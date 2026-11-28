"""Toolforge Bastion, scheduled jobs, directory, and ToolsDB diagnostic probes."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import shutil
import subprocess  # noqa: S404
import tempfile
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from django.core.management.base import CommandError
from dotenv import dotenv_values

from proxycheck.settings import (
    build_databases_config,
    resolve_dotenv_path,
)

from ..core.sanitization import sanitize_error_message
from ..offline.updaters import _ALL_CANONICAL_SOURCES, _SOURCE_ALIASES
from .env_specs import (
    _ENV_NAME_RE,
    _FAILED_JOB_STATUS_TOKENS,
    _GRANT_STMT_RE,
    _MYSQL_PROBE_ERRORS,
    _SEPARATOR_LINE_RE,
    _WIKI_REPLICA_READONLY_PRIVS,
    DEFAULT_TOOLFORGE_IMAGE,
    ENV_MODES,
    ENV_SPEC_BY_NAME,
    ENV_SPECS,
    BastionJobCheck,
    DirectoryStatus,
    EnvLoadResult,
    JobSpec,
    RegisteredJob,
    ToolsDbCheckResult,
    is_public_toolsdb_name,
    pymysql,
)


def _run_toolforge_command(
    toolforge_bin: str,
    args: Sequence[str],
    *,
    input_text: Optional[str] = None,
    timeout: float = 30.0,
) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(  # noqa: S603
            [toolforge_bin, *args],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return 1, "", f"Failed to execute toolforge CLI: {exc}"
    except subprocess.TimeoutExpired:
        return 1, "", f"Timed out executing: toolforge {' '.join(args)}"
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def _parse_envvars_list_output(raw_output: str, *, with_values: bool) -> Tuple[Dict[str, str], set[str]]:
    stripped = raw_output.strip()
    if not stripped:
        return {}, set()

    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(stripped)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            values = {str(k): str(v) for k, v in payload.items() if _ENV_NAME_RE.match(str(k))}
            return values, set(values.keys())
        if isinstance(payload, list):
            values = {}
            names: set[str] = set()
            for entry in payload:
                if isinstance(entry, dict) and entry.get("name"):
                    key = str(entry["name"]).strip()
                    names.add(key)
                    if entry.get("value") is not None:
                        values[key] = str(entry["value"])
                elif isinstance(entry, str) and _ENV_NAME_RE.match(entry.strip()):
                    names.add(entry.strip())
            return values, names

    values_out: Dict[str, str] = {}
    names_out: set[str] = set()
    for line in raw_output.splitlines():
        candidate = line.strip()
        if not candidate or _SEPARATOR_LINE_RE.match(candidate):
            continue
        first_token = candidate.split(None, 1)[0]
        parts = [part.strip() for part in candidate.split("=", 1)] if "=" in first_token else candidate.split(None, 1)
        head = parts[0].strip().rstrip(":")
        if head.lower() in ("name", "key", "envvar", "variable") and (
            len(parts) == 1 or parts[1].strip().lower() in ("value", "values")
        ):
            continue
        if not _ENV_NAME_RE.match(head):
            continue
        names_out.add(head)
        if with_values and len(parts) == 2:
            values_out[head] = parts[1].strip()
    return values_out, names_out


def _detect_runtime_environment(requested_mode: str) -> Tuple[str, Optional[str], Optional[str]]:
    normalised_mode = requested_mode.strip().lower()
    if normalised_mode not in ENV_MODES:
        raise CommandError(f"Unsupported --env mode '{requested_mode}'. Choose from: {', '.join(ENV_MODES)}.")

    env = os.environ
    toolforge_bin = shutil.which("toolforge")

    tool_account: Optional[str] = None
    for user_var in ("USER", "LOGNAME"):
        raw_user = str(env.get(user_var) or "").strip()
        for prefix in ("tools.", "toolsbeta."):
            if raw_user.startswith(prefix) and len(raw_user) > len(prefix):
                tool_account = raw_user[len(prefix) :]
                break
        if tool_account:
            break
    if not tool_account:
        for candidate in (str(env.get(k) or "") for k in ("TOOL_DATA_DIR", "HOME") if env.get(k)):
            match = re.match(r"^/data/project/([^/]+)(?:/|$)", candidate.strip())
            if match:
                tool_account = match.group(1)
                break

    if normalised_mode == "bastion":
        if not toolforge_bin:
            raise CommandError("Cannot run in bastion mode: 'toolforge' CLI was not found on PATH.")
        return "bastion", toolforge_bin, tool_account

    if normalised_mode == "local":
        return "local", toolforge_bin, tool_account

    # Auto mode requires both the toolforge CLI and a WMCS host marker outside buildpack containers.
    raw_user = str(env.get("USER") or env.get("LOGNAME") or "").strip()
    raw_home = str(env.get("HOME") or "").strip()
    is_container = bool(env.get("CNB_STACK_ID") or env.get("TOOL_TOOLFORGE_API_URL") or Path("/.dockerenv").exists())
    has_bastion_marker = (
        Path("/etc/wmcs-project").exists()
        or raw_user.startswith(("tools.", "toolsbeta."))
        or raw_home.startswith("/data/project/")
    )
    if toolforge_bin and has_bastion_marker and not is_container:
        return "bastion", toolforge_bin, tool_account
    return "local", toolforge_bin, tool_account


def _load_bastion_envvars(toolforge_bin: str, base_dir: Path) -> EnvLoadResult:
    values: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    hidden_keys: set[str] = set()

    rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("envvars", "list", "--show-values"))
    if rc == 0:
        parsed_vals, parsed_names = _parse_envvars_list_output(stdout, with_values=True)
        for key in parsed_names:
            val = parsed_vals.get(key, "")
            if val:
                values[key] = val
                sources[key] = "toolforge envvars"
        return EnvLoadResult(values=values, sources=sources, hidden_keys=frozenset(), dotenv_path=base_dir / ".env")

    rc_list, stdout_list, stderr_list = _run_toolforge_command(toolforge_bin, ("envvars", "list"))
    if rc_list != 0:
        err_detail = (stderr_list or stderr or stdout_list or stdout).strip()
        raise CommandError(f"Failed to query Toolforge envvars: {err_detail or f'exit code {rc_list}'}")

    _, listed_names = _parse_envvars_list_output(stdout_list, with_values=False)
    for key in sorted(listed_names):
        if key not in ENV_SPEC_BY_NAME:
            continue
        rc_show, stdout_show, _ = _run_toolforge_command(toolforge_bin, ("envvars", "show", key))
        shown_val: Optional[str] = None
        if rc_show == 0:
            filtered = [
                line.rstrip("\r\n")
                for line in stdout_show.splitlines()
                if line.strip() and not _SEPARATOR_LINE_RE.match(line.strip())
            ]
            for line in filtered:
                stripped = line.strip()
                parts = stripped.split(None, 1)
                if len(parts) == 2 and parts[0].lower() in ("name", "key") and parts[1].strip().lower() == "value":
                    continue
                if len(parts) == 2 and parts[0] == key:
                    val = parts[1].strip()
                    shown_val = None if set(val) == {"*"} else val
                    break
                if stripped.startswith((f"{key}:", f"{key}=")):
                    val = stripped[len(key) + 1 :].strip()
                    shown_val = None if set(val) == {"*"} else val
                    break
            else:
                if len(filtered) == 1:
                    single = filtered[0].strip()
                    if single != key and set(single) != {"*"}:
                        shown_val = single
        values[key] = shown_val or ""
        sources[key] = "toolforge envvars"
        if not shown_val:
            hidden_keys.add(key)

    return EnvLoadResult(
        values=values,
        sources=sources,
        hidden_keys=frozenset(hidden_keys),
        dotenv_path=base_dir / ".env",
    )


def _load_local_envvars(base_dir: Path) -> EnvLoadResult:
    env = os.environ
    warnings: List[str] = []

    raw_tool_dir = str(env.get("TOOL_DATA_DIR") or "").strip()
    resolved_dotenv = resolve_dotenv_path(base_dir, raw_tool_dir)
    read_dotenv_path = resolved_dotenv if resolved_dotenv is not None else (base_dir / ".env")
    write_dotenv_path = base_dir / ".env"
    dotenv_label = read_dotenv_path.name if read_dotenv_path == write_dotenv_path else str(read_dotenv_path)

    dotenv_map: Dict[str, str] = {}
    if read_dotenv_path.is_file():
        try:
            raw_dotenv = dotenv_values(read_dotenv_path, encoding="utf-8-sig")
            dotenv_map = {str(k): ("" if v is None else str(v)) for k, v in raw_dotenv.items() if k}
        except (OSError, UnicodeDecodeError) as exc:
            warnings.append(f"Unable to read {read_dotenv_path}: {exc}")

    values: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    for spec in ENV_SPECS:
        name = spec.name
        env_val = env.get(name)
        dotenv_val = dotenv_map.get(name)
        if env_val is not None and env_val.strip():
            values[name] = env_val.strip()
            sources[name] = (
                dotenv_label if (dotenv_val is not None and dotenv_val.strip() == env_val.strip()) else "process env"
            )
        elif dotenv_val is not None and dotenv_val.strip():
            values[name] = dotenv_val.strip()
            sources[name] = dotenv_label

    return EnvLoadResult(
        values=values,
        sources=sources,
        hidden_keys=frozenset(),
        dotenv_path=write_dotenv_path,
        warnings=tuple(warnings),
    )


def _inspect_directory(
    label: str,
    path: Path,
    *,
    required: bool,
    persistent: bool,
    mounts: Sequence[Tuple[str, str, str]],
) -> DirectoryStatus:
    mount_summary = "local filesystem"
    is_ephemeral = False
    if mounts:
        try:
            probe = path.resolve()
        except OSError:
            probe = path
        probe_str = probe.as_posix()
        best_match: Optional[Tuple[str, str, str]] = None
        for mount_point, fs_type, options in mounts:
            normalised_mp = mount_point.rstrip("/") or "/"
            is_match = normalised_mp == "/" or probe_str == normalised_mp or probe_str.startswith(f"{normalised_mp}/")
            if is_match and (best_match is None or len(normalised_mp) > len(best_match[0].rstrip("/") or "/")):
                best_match = (mount_point, fs_type, options)
        if best_match is not None:
            mount_point, fs_type, options = best_match
            rw_flag = "ro" if "ro" in options.split(",") else "rw"
            kind = "NFS" if fs_type.startswith("nfs") else fs_type
            mount_summary = f"{kind} ({fs_type}, {rw_flag}) at {mount_point}"
            is_ephemeral = fs_type in ("overlay", "tmpfs", "ramfs")

    if not path.exists():
        return DirectoryStatus(
            label=label,
            path=path,
            required=required,
            persistent=persistent,
            exists=False,
            is_dir=False,
            readable=False,
            writable=False,
            mount_summary=mount_summary,
            is_ephemeral_mount=is_ephemeral,
        )

    if not path.is_dir():
        return DirectoryStatus(
            label=label,
            path=path,
            required=required,
            persistent=persistent,
            exists=True,
            is_dir=False,
            readable=False,
            writable=False,
            mount_summary=mount_summary,
            is_ephemeral_mount=is_ephemeral,
            error="path exists but is not a directory",
        )

    readable = os.access(path, os.R_OK | os.X_OK)
    read_err = ""
    if readable:
        try:
            with os.scandir(path):
                pass
        except OSError as exc:
            readable = False
            read_err = str(exc)
    else:
        read_err = "read permission denied"

    writable = False
    write_err = ""
    if persistent:
        try:
            with tempfile.NamedTemporaryFile(dir=path, prefix=".check_setup_", delete=True):
                writable = True
        except OSError as exc:
            write_err = str(exc)
    else:
        writable = os.access(path, os.W_OK)

    return DirectoryStatus(
        label=label,
        path=path,
        required=required,
        persistent=persistent,
        exists=True,
        is_dir=True,
        readable=readable,
        writable=writable,
        mount_summary=mount_summary,
        is_ephemeral_mount=is_ephemeral,
        error="; ".join(msg for msg in (read_err, write_err) if msg),
    )


def _extract_update_offline_sources(command: str) -> set[str]:
    if not command or "update_offline_dbs" not in command:
        return set()
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    if len(tokens) >= 3 and Path(tokens[0]).name in ("sh", "bash") and tokens[1] in ("-c", "-lc"):
        try:
            tokens = shlex.split(tokens[2])
        except ValueError:
            tokens = tokens[2].split()

    cmd_idx = next((idx for idx, tok in enumerate(tokens) if tok == "update_offline_dbs"), None)
    if cmd_idx is None:
        return set()

    source_tokens: List[str] = []
    idx = cmd_idx + 1
    while idx < len(tokens):
        tok = tokens[idx]
        if tok == "--sources":
            idx += 1
            while idx < len(tokens) and not tokens[idx].startswith("-"):
                source_tokens.extend(part.strip().lower() for part in tokens[idx].split(",") if part.strip())
                idx += 1
            continue
        if tok.startswith("--sources="):
            raw_val = tok.split("=", 1)[1]
            source_tokens.extend(part.strip().lower() for part in raw_val.split(",") if part.strip())
        idx += 1

    if not source_tokens or "all" in source_tokens:
        return set(_ALL_CANONICAL_SOURCES)
    return {_SOURCE_ALIASES[tok] for tok in source_tokens if tok in _SOURCE_ALIASES}


def _schedule_matches_expected(expected_schedule: str, actual_job_type: str) -> bool:
    lowered_type = actual_job_type.strip().lower()
    if "scheduled" not in lowered_type:
        return False
    actual_cron = " ".join((lowered_type.split(":", 1)[1] if ":" in lowered_type else lowered_type).split())
    norm_expected = " ".join(expected_schedule.strip().lower().split())
    if not norm_expected or norm_expected == actual_cron:
        return True
    hourly_re = r"\d{1,2}\s+\*\s+\*\s+\*\s+\*"
    daily_re = r"\d{1,2}\s+\d{1,2}\s+\*\s+\*\s+\*"
    if norm_expected == "@hourly":
        return bool(re.fullmatch(hourly_re, actual_cron))
    if actual_cron == "@hourly":
        return bool(re.fullmatch(hourly_re, norm_expected))
    if norm_expected == "@daily":
        return bool(re.fullmatch(daily_re, actual_cron))
    if actual_cron == "@daily":
        return bool(re.fullmatch(daily_re, norm_expected))
    return False


def _validate_registered_job(
    spec: JobSpec,
    reg: RegisteredJob,
    *,
    adapted_image: str,
    tool_account: Optional[str],
    covered_by: str = "",
) -> BastionJobCheck:
    job_warnings: List[str] = []
    covered_sources = _extract_update_offline_sources(reg.command)
    is_combined_coverage = bool(covered_by) and len(covered_sources) > 1
    schedule_ok = _schedule_matches_expected(spec.schedule, reg.job_type)
    if not schedule_ok and is_combined_coverage and spec.schedule.strip().lower() == "@daily":
        schedule_ok = _schedule_matches_expected("@hourly", reg.job_type)
    if spec.schedule and not schedule_ok:
        job_warnings.append(f"schedule mismatch (expected '{spec.schedule}', got '{reg.job_type or 'unknown'}')")

    if reg.mount.strip() and spec.mount.lower() not in reg.mount.strip().lower():
        job_warnings.append(f"mount is '{reg.mount}' (expected '{spec.mount}')")
    if tool_account and reg.image and reg.image != adapted_image:
        job_warnings.append(f"image is '{reg.image}' (expected '{adapted_image}')")
    if reg.command and not covered_by:
        expects_offline_updater = "update_offline_dbs" in spec.command
        command_mismatch = (
            ("update_offline_dbs" not in reg.command)
            if expects_offline_updater
            else (spec.command.strip() not in reg.command)
        )
        if command_mismatch:
            job_warnings.append(f"command is '{reg.command}' (expected '{spec.command}')")
    if any(token in reg.status.lower() for token in _FAILED_JOB_STATUS_TOKENS):
        job_warnings.append(f"unhealthy job status '{reg.status}'")

    return BastionJobCheck(
        expected=spec,
        registered=True,
        job_type=reg.job_type,
        status=reg.status or "Registered",
        warnings=tuple(job_warnings),
        adapted_image=adapted_image,
        covered_by=covered_by,
    )


def _parse_toolforge_jobs_list(raw_output: str) -> Dict[str, RegisteredJob]:
    stripped = raw_output.strip()
    if not stripped or "no jobs found" in stripped.lower():
        return {}

    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(stripped)
        except ValueError:
            payload = None
        if isinstance(payload, list):
            return {
                str(entry["name"]).strip(): RegisteredJob(
                    name=str(entry["name"]).strip(),
                    command=str(entry.get("command") or ""),
                    job_type=str(entry.get("type") or entry.get("job_type") or ""),
                    image=str(entry.get("image") or ""),
                    mount=str(entry.get("mount") or entry.get("mounts") or ""),
                    status=str(entry.get("status") or ""),
                )
                for entry in payload
                if isinstance(entry, dict) and entry.get("name")
            }

    if any(line.strip().startswith("|") and line.strip().endswith("|") for line in raw_output.splitlines()):
        plus_positions: Optional[List[int]] = None
        headers: Optional[List[str]] = None
        bordered: Dict[str, RegisteredJob] = {}
        for line in (ln.rstrip("\r\n") for ln in raw_output.splitlines() if ln.strip()):
            line_stripped = line.strip()
            if line_stripped.startswith("+") and "+" in line_stripped[1:] and set(line_stripped) <= {"+", "-", "="}:
                candidate_positions = [idx for idx, ch in enumerate(line) if ch == "+"]
                if len(candidate_positions) >= 2:
                    plus_positions = candidate_positions
                continue
            if not (line_stripped.startswith("|") and line_stripped.endswith("|")):
                continue
            if plus_positions and len(plus_positions) >= 2 and len(line) >= plus_positions[-1] + 1:
                cells = [
                    line[plus_positions[idx] + 1 : plus_positions[idx + 1]].strip()
                    for idx in range(len(plus_positions) - 1)
                ]
            else:
                cells = [cell.strip() for cell in line_stripped.strip("|").split("|")]
            if headers is None:
                headers = [cell.rstrip(":").strip().lower() for cell in cells]
                continue
            row_map = {header: cells[idx] for idx, header in enumerate(headers) if idx < len(cells)}
            name = row_map.get("job name") or row_map.get("name") or ""
            if name:
                bordered[name] = RegisteredJob(
                    name=name,
                    command=row_map.get("command", ""),
                    job_type=row_map.get("job type") or row_map.get("type") or "",
                    image=row_map.get("image", ""),
                    mount=row_map.get("mounts") or row_map.get("mount") or "",
                    status=row_map.get("status", ""),
                )
        if bordered:
            return bordered

    jobs: Dict[str, RegisteredJob] = {}
    col_bounds: Optional[List[Tuple[int, int]]] = None
    for line in (ln.rstrip("\r\n") for ln in raw_output.splitlines() if ln.strip()):
        if line.strip().lower().startswith("job name"):
            continue
        if _SEPARATOR_LINE_RE.match(line.strip()):
            spans = [m.span() for m in re.finditer(r"-+", line)]
            if len(spans) >= 2:
                col_bounds = spans
            continue
        if col_bounds and len(col_bounds) >= 3:
            name = line[col_bounds[0][0] : col_bounds[1][0]].strip()
            job_type = line[col_bounds[1][0] : col_bounds[2][0]].strip()
            status = line[col_bounds[2][0] :].strip()
        else:
            parts = line.split(None, 2)
            if not parts:
                continue
            name = parts[0].strip()
            job_type = parts[1].strip() if len(parts) > 1 else ""
            status = parts[2].strip() if len(parts) > 2 else ""
        if name and not name.endswith(":"):
            jobs[name] = RegisteredJob(name=name, job_type=job_type, status=status)
    return jobs


def _check_bastion_jobs(
    toolforge_bin: str,
    base_dir: Path,
    tool_account: Optional[str],
) -> Tuple[List[BastionJobCheck], Optional[str]]:
    jobs_path = base_dir / "jobs.yaml"
    expected_jobs: List[JobSpec] = []
    if jobs_path.is_file():
        raw_items: List[Dict[str, str]] = []
        current: Optional[Dict[str, str]] = None
        for raw_line in jobs_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line == "---":
                continue
            if line.startswith("- "):
                if current:
                    raw_items.append(current)
                current = {}
                line = line[2:].strip()
            if current is None or ":" not in line:
                continue
            key, val = line.split(":", 1)
            cleaned_val = val.strip()
            if len(cleaned_val) >= 2 and cleaned_val[0] == cleaned_val[-1] and cleaned_val[0] in ("'", '"'):
                cleaned_val = cleaned_val[1:-1]
            current[key.strip()] = cleaned_val
        if current:
            raw_items.append(current)
        expected_jobs = [
            JobSpec(
                name=item["name"].strip(),
                command=item.get("command", "").strip(),
                image=item.get("image", DEFAULT_TOOLFORGE_IMAGE).strip(),
                schedule=item.get("schedule", "").strip(),
                mount=item.get("mount", "all").strip(),
            )
            for item in raw_items
            if item.get("name", "").strip()
        ]
    if not expected_jobs:
        return [], f"No scheduled jobs found in {jobs_path}"

    used_long_output = True
    rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("jobs", "list", "--output", "long"))
    if rc != 0:
        used_long_output = False
        rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("jobs", "list"))
    if rc != 0:
        detail = (stderr or stdout).strip()
        return [], f"Unable to query toolforge jobs list: {detail or f'exit code {rc}'}"

    active_jobs = _parse_toolforge_jobs_list(stdout)
    if not used_long_output:
        expected_names = {spec.name for spec in expected_jobs}
        for job_name, reg in list(active_jobs.items()):
            if (
                job_name not in expected_names
                and "update" not in job_name
                and "db" not in job_name
                and "purge" not in job_name
            ):
                continue
            if reg.command and reg.image and reg.mount:
                continue
            rc_show, show_stdout, _ = _run_toolforge_command(toolforge_bin, ("jobs", "show", job_name))
            if rc_show == 0:
                details: Dict[str, str] = {}
                for show_line in show_stdout.splitlines():
                    if ":" in show_line:
                        k, v = show_line.split(":", 1)
                        cleaned_k = k.strip().lower()
                        if cleaned_k:
                            details[cleaned_k] = v.strip()
                active_jobs[job_name] = RegisteredJob(
                    name=job_name,
                    command=details.get("command", reg.command),
                    job_type=reg.job_type or details.get("job type") or details.get("type") or "",
                    image=details.get("image", reg.image),
                    mount=details.get("mounts") or details.get("mount") or reg.mount,
                    status=reg.status or details.get("status", ""),
                )

    results: List[BastionJobCheck] = []
    for spec in expected_jobs:
        adapted_image = f"tool-{tool_account}/tool-{tool_account}:latest" if tool_account else spec.image
        if spec.name in active_jobs:
            results.append(
                _validate_registered_job(
                    spec,
                    active_jobs[spec.name],
                    adapted_image=adapted_image,
                    tool_account=tool_account,
                )
            )
            continue

        needed_sources = _extract_update_offline_sources(spec.command)
        candidates = (
            [reg for reg in active_jobs.values() if needed_sources <= _extract_update_offline_sources(reg.command)]
            if needed_sources
            else []
        )
        if candidates:
            covering_job = next((cand for cand in candidates if "scheduled" in cand.job_type.lower()), candidates[0])
            results.append(
                _validate_registered_job(
                    spec,
                    covering_job,
                    adapted_image=adapted_image,
                    tool_account=tool_account,
                    covered_by=covering_job.name,
                )
            )
            continue

        warnings = (
            (
                f"jobs.yaml specifies template image '{spec.image}', whereas active account '{tool_account}' "
                f"requires '{adapted_image}'",
            )
            if (tool_account and spec.image != adapted_image)
            else ()
        )
        results.append(
            BastionJobCheck(
                expected=spec,
                registered=False,
                job_type="",
                status="Missing",
                warnings=warnings,
                adapted_image=adapted_image,
            )
        )
    return results, None


def _check_toolsdb_status(
    base_dir: Path,
    env_values: Mapping[str, str],
    *,
    hidden_keys: frozenset[str] = frozenset(),
) -> ToolsDbCheckResult:
    raw_db_name = str(env_values.get("TOOLSDB_NAME") or env_values.get("TOOL_TOOLSDB_NAME") or "").strip()
    if is_public_toolsdb_name(raw_db_name):
        return ToolsDbCheckResult(
            status="error",
            db_name=raw_db_name,
            is_public_name_hazard=True,
            message=(
                f"Database name '{raw_db_name}' ends with '_p', which exposes tables publicly across "
                "Toolforge and Quarry."
            ),
        )

    enable_raw = str(env_values.get("ENABLE_L2_TOOLSDB_CACHE") or "").strip().lower()
    if enable_raw in ("0", "false", "no", "off"):
        return ToolsDbCheckResult(
            status="disabled",
            db_name=raw_db_name,
            message="ToolsDB L2 cache is disabled via ENABLE_L2_TOOLSDB_CACHE.",
        )

    default_cfg = build_databases_config(
        env=env_values,
        base_dir=base_dir,
        is_test_run=False,
        home_dir=Path.home(),
    )["default"]
    if default_cfg.get("ENGINE") != "django.db.backends.mysql":
        if raw_db_name:
            if "TOOLSDB_PASSWORD" in hidden_keys or "TOOL_TOOLSDB_PASSWORD" in hidden_keys:
                return ToolsDbCheckResult(
                    status="ok",
                    db_name=raw_db_name,
                    message=f"Schema '{raw_db_name}' configured in Toolforge envvars (credentials hidden by CLI).",
                )
            return ToolsDbCheckResult(
                status="warning",
                db_name=raw_db_name,
                message=f"Schema '{raw_db_name}' is set without ToolsDB credentials; falling back to local SQLite.",
            )
        return ToolsDbCheckResult(
            status="unconfigured",
            message="ToolsDB not configured; using local SQLite fallback.",
        )

    resolved_db_name = str(default_cfg.get("NAME") or "").strip()
    resolved_host = str(default_cfg.get("HOST") or "")
    resolved_port = int(default_cfg.get("PORT") or 3306)
    resolved_user = str(default_cfg.get("USER") or "")
    if is_public_toolsdb_name(resolved_db_name):
        return ToolsDbCheckResult(
            status="error",
            db_name=resolved_db_name,
            host=resolved_host,
            port=resolved_port,
            user=resolved_user,
            is_public_name_hazard=True,
            message=(
                f"Database name '{resolved_db_name}' ends with '_p', which exposes tables publicly across "
                "Toolforge and Quarry."
            ),
        )

    conn = None
    try:
        if pymysql is None:
            raise ImportError("PyMySQL is not installed in the active Python environment.")
        options = default_cfg.get("OPTIONS") if isinstance(default_cfg.get("OPTIONS"), Mapping) else {}
        conn = pymysql.connect(
            host=resolved_host or "tools.db.svc.wikimedia.cloud",
            port=resolved_port,
            user=resolved_user,
            password=str(default_cfg.get("PASSWORD") or ""),
            database=resolved_db_name,
            connect_timeout=int(options.get("connect_timeout") or 3),
            read_timeout=int(options.get("read_timeout") or 5),
            write_timeout=int(options.get("write_timeout") or 5),
            charset=str(options.get("charset") or "utf8mb4"),
        )
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.execute("SHOW GRANTS")
            grant_rows = list(cursor.fetchall() or ())
    except _MYSQL_PROBE_ERRORS as exc:
        return ToolsDbCheckResult(
            status="error",
            db_name=resolved_db_name,
            host=resolved_host,
            port=resolved_port,
            user=resolved_user,
            message=f"ToolsDB connection check failed: {sanitize_error_message(str(exc))}",
        )
    finally:
        close_fn = getattr(conn, "close", None)
        if callable(close_fn):
            with contextlib.suppress(*_MYSQL_PROBE_ERRORS):
                close_fn()

    unsafe: List[str] = []
    if resolved_db_name and is_public_toolsdb_name(resolved_db_name):
        unsafe.append(f"PUBLIC_SCHEMA_NAME:{resolved_db_name}")
    for row in grant_rows:
        if isinstance(row, str):
            stmt = row.strip()
        elif isinstance(row, Sequence) and row:
            stmt = str(row[0]).strip()
        else:
            continue
        match = _GRANT_STMT_RE.match(stmt) if stmt else None
        if not match:
            continue
        privs_raw, target_raw, grantee_raw = match.groups()
        privs_upper = " ".join(privs_raw.upper().split())
        trimmed_grantee = re.split(
            r"\s+(?:IDENTIFIED|WITH|REQUIRE)\b", grantee_raw.strip(), maxsplit=1, flags=re.IGNORECASE
        )[0].strip()
        if trimmed_grantee.upper() == "PUBLIC" or trimmed_grantee.upper().startswith("PUBLIC "):
            unsafe.append(stmt)
            continue
        if "@" not in trimmed_grantee:
            grantee_user = trimmed_grantee.strip("`'\"")
            is_public_grantee = grantee_user.upper() == "PUBLIC"
        else:
            grantee_user = trimmed_grantee.rsplit("@", 1)[0].strip().strip("`'\"")
            is_public_grantee = grantee_user == "" or "%" in grantee_user or grantee_user.lower() == "public"
        if is_public_grantee or (resolved_user and grantee_user and grantee_user != resolved_user.strip()):
            unsafe.append(stmt)
            continue

        normalised_schema = target_raw.strip().split(".", 1)[0].strip().strip("`'\"").replace("\\_", "_")
        # Toolforge grants every tool read-only access to Wiki Replicas (`%_p`); this is expected.
        privs_set = {part.strip() for part in privs_upper.split(",") if part.strip()}
        if normalised_schema == "%_p" and privs_set and privs_set <= _WIKI_REPLICA_READONLY_PRIVS:
            continue
        if is_public_toolsdb_name(normalised_schema) or (normalised_schema in ("*", "%") and privs_upper != "USAGE"):
            unsafe.append(stmt)

    if unsafe:
        return ToolsDbCheckResult(
            status="error",
            db_name=resolved_db_name,
            host=resolved_host,
            port=resolved_port,
            user=resolved_user,
            unsafe_grants=tuple(unsafe),
            message=f"Unsafe wildcard or public MariaDB grants detected ({len(unsafe)} statement(s)).",
        )
    return ToolsDbCheckResult(
        status="ok",
        db_name=resolved_db_name,
        host=resolved_host,
        port=resolved_port,
        user=resolved_user,
        message=f"Connected to {resolved_host}:{resolved_port} schema '{resolved_db_name}' as '{resolved_user}'.",
    )
