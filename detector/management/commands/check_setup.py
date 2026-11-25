"""Interactive environment diagnostic and initialisation command for Proxycheck."""

from __future__ import annotations

import contextlib
import getpass
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.crypto import get_random_string
from dotenv import set_key

from detector.offline import collect_offline_databases_status
from detector.setup_diag.env_specs import (
    _LOCAL_HOSTS,
    _SECRET_KEY_CHARS,
    DEFAULT_JOB_SPEC,
    DEFAULT_PRODUCTION_REDIRECT_URI,
    DEFAULT_TOOLFORGE_ALLOWED_HOSTS,
    DEFAULT_TOOLFORGE_REDIS_URL,
    ENV_MODES,
    ENV_SPECS,
    INSECURE_DEV_SECRET_KEY,
    BastionJobCheck,
    DirectoryStatus,
    EnvLoadResult,
    EnvVarSpec,
    ToolsDbCheckResult,
    _is_weak_secret_key,
    format_display_value,
    mask_secret,
)
from detector.setup_diag.probes import (
    _check_bastion_jobs,
    _check_toolsdb_status,
    _detect_runtime_environment,
    _inspect_directory,
    _load_bastion_envvars,
    _load_local_envvars,
    _run_toolforge_command,
)
from proxycheck.settings import (
    expand_configured_path,
    resolve_tool_data_subdir,
)


class Command(BaseCommand):
    help = "Audits and interactively initialises Proxycheck environment configuration."
    requires_system_checks = []
    requires_migrations_checks = False

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--no-input",
            "--noinput",
            action="store_true",
            dest="no_input",
            help="Run in non-interactive mode without prompting for missing settings or directories.",
        )
        parser.add_argument(
            "--env",
            choices=ENV_MODES,
            default="auto",
            dest="env_mode",
            help="Target runtime environment mode: auto, bastion, or local (default: auto).",
        )
        parser.add_argument(
            "--all-options",
            action="store_true",
            dest="all_options",
            help="Display all low-level tuning and quota limit variables and include them in interactive prompts.",
        )
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Exit with non-zero status if any required variable, directory, offline database, or job is missing.",
        )

    def _prompt_text(self, prompt: str, *, sensitive: bool = False) -> Optional[str]:
        try:
            raw = getpass.getpass(prompt) if sensitive else input(prompt)
        except EOFError, KeyboardInterrupt:
            self.stdout.write("")
            return None
        return raw.strip()

    def _prompt_yes_no(self, prompt: str) -> bool:
        response = self._prompt_text(prompt, sensitive=False)
        return bool(response and response.lower() in ("y", "yes"))

    def _save_env_value(
        self,
        *,
        mode: str,
        toolforge_bin: Optional[str],
        base_dir: Path,
        env_result: EnvLoadResult,
        key: str,
        value: str,
    ) -> None:
        if mode == "bastion":
            if not toolforge_bin:
                raise CommandError("Cannot write Toolforge envvars without 'toolforge' CLI.")
            rc, stdout, stderr = _run_toolforge_command(toolforge_bin, ("envvars", "create", key), input_text=value)
            if rc != 0:
                detail = (stderr or stdout).strip()
                raise CommandError(f"Failed to set Toolforge envvar {key}: {detail or f'exit code {rc}'}")
            env_result.values[key] = value
            env_result.sources[key] = "toolforge envvars"
            return

        gitignore_path = base_dir / ".gitignore"
        gitignore_note: Optional[str] = None
        if gitignore_path.is_file():
            existing = gitignore_path.read_text(encoding="utf-8")
            if not any(line.split("#", 1)[0].strip() in (".env", "/.env", "*.env") for line in existing.splitlines()):
                prefix = "\n" if existing and not existing.endswith("\n") else ""
                gitignore_path.write_text(f"{existing}{prefix}.env\n", encoding="utf-8")
                gitignore_note = f"appended '.env' to {gitignore_path}"
        else:
            gitignore_path.write_text(".env\n", encoding="utf-8")
            gitignore_note = f"created {gitignore_path} with '.env'"

        dotenv_path = env_result.dotenv_path
        created_new = not dotenv_path.exists()
        dotenv_path.parent.mkdir(parents=True, exist_ok=True)
        set_key(dotenv_path, key, value, quote_mode="always", encoding="utf-8")
        if created_new:
            with contextlib.suppress(OSError):
                os.chmod(dotenv_path, 0o600)
        os.environ[key] = value

        if gitignore_note:
            self.stdout.write(self.style.WARNING(f"  Git safety: {gitignore_note}"))
        env_result.values[key] = value
        env_result.sources[key] = dotenv_path.name

    def _print_env_section(
        self,
        env_result: EnvLoadResult,
        *,
        mode: str,
        tool_account: Optional[str],
        show_all_options: bool,
    ) -> Tuple[List[EnvVarSpec], List[EnvVarSpec], List[EnvVarSpec], List[EnvVarSpec]]:
        self.stdout.write("\n[1/4] Environment Variables")
        values, sources, hidden_keys = env_result.values, env_result.sources, env_result.hidden_keys

        missing_required: List[EnvVarSpec] = []
        attention_recommended: List[EnvVarSpec] = []
        missing_providers: List[EnvVarSpec] = []
        missing_optional_all: List[EnvVarSpec] = []

        sections = (
            ("required", "Required Configuration", "[REQUIRED]"),
            ("recommended", "Production / Toolforge Recommended", "[RECOMMENDED]"),
            ("provider", "Upstream IP Intelligence Providers (Optional)", "[OPTIONAL]"),
            ("optional", "Runtime, Paths & Build Metadata (Optional)", "[OPTIONAL]"),
        )
        for tier, heading, tag in sections:
            self.stdout.write(f"\n  {heading}:")
            for spec in (s for s in ENV_SPECS if s.tier == tier):
                if spec.name in hidden_keys:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  - {tag} {spec.name}: CONFIGURED (hidden by CLI, {sources.get(spec.name, '')})"
                        )
                    )
                    continue
                val = values.get(spec.name, "")
                if not val:
                    if spec.tier == "required":
                        missing_required.append(spec)
                        self.stdout.write(self.style.ERROR(f"  - {tag} {spec.name}: MISSING ({spec.description})"))
                    elif spec.tier == "recommended":
                        attention_recommended.append(spec)
                        self.stdout.write(
                            self.style.WARNING(f"  - {tag} {spec.name}: MISSING (default: {spec.default_display})")
                        )
                    elif spec.tier == "provider":
                        missing_providers.append(spec)
                        self.stdout.write(f"  - {tag} {spec.name}: MISSING (provider skipped)")
                    else:
                        missing_optional_all.append(spec)
                        self.stdout.write(f"  - {tag} {spec.name}: USING DEFAULT ({spec.default_display})")
                    continue

                source_label = sources.get(spec.name, "configured")
                if spec.name == "DJANGO_SECRET_KEY" and val == INSECURE_DEV_SECRET_KEY:
                    missing_required.append(spec)
                    self.stdout.write(self.style.ERROR(f"  - {tag} {spec.name}: INSECURE DEFAULT ({source_label})"))
                    continue
                if spec.name == "DJANGO_SECRET_KEY":
                    is_placeholder, weak_reason = _is_weak_secret_key(val)
                    if weak_reason:
                        if is_placeholder:
                            missing_required.append(spec)
                        shown_val = format_display_value(spec, val)
                        self.stdout.write(
                            self.style.WARNING(
                                f"  - {tag} {spec.name}: WEAK / PLACEHOLDER = {shown_val} ({weak_reason}; {source_label})"
                            )
                        )
                        continue

                review_reason: Optional[str] = None
                if spec.tier == "recommended":
                    cleaned_val = val.strip()
                    if spec.name == "DJANGO_ALLOWED_HOSTS" and mode == "bastion":
                        hosts = [entry.strip().lower() for entry in cleaned_val.split(",") if entry.strip()]
                        if hosts and all(host in _LOCAL_HOSTS for host in hosts):
                            review_reason = "contains only local hosts for a Toolforge environment"
                    elif (
                        spec.name == "REDIS_URL"
                        and mode == "bastion"
                        and ("127.0.0.1" in cleaned_val.lower() or "localhost" in cleaned_val.lower())
                    ):
                        review_reason = "points to localhost Redis inside Toolforge"
                    elif (
                        spec.name == "WIKIMEDIA_REDIRECT_URI"
                        and tool_account == "proxycheck-dev"
                        and "proxycheck.toolforge.org" in cleaned_val
                        and "proxycheck-dev.toolforge.org" not in cleaned_val
                    ):
                        review_reason = "points to production callback URL while active tool is proxycheck-dev"

                shown_val = format_display_value(spec, val)
                if review_reason:
                    attention_recommended.append(spec)
                    self.stdout.write(
                        self.style.WARNING(
                            f"  - {tag} {spec.name}: NEEDS REVIEW = {shown_val} ({review_reason}; {source_label})"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(f"  - {tag} {spec.name}: CONFIGURED = {shown_val} ({source_label})")
                    )

        if values.get("ENABLE_TEST_AUTH") == "1" and (
            mode == "bastion" or values.get("DJANGO_DEBUG", "").lower() not in ("1", "true", "yes")
        ):
            self.stdout.write(
                self.style.WARNING(
                    "  ! Security notice: ENABLE_TEST_AUTH=1 should only be enabled alongside DJANGO_DEBUG=True locally."
                )
            )

        tuning_specs = [spec for spec in ENV_SPECS if spec.tier == "tuning"]
        custom_tuning = [spec for spec in tuning_specs if values.get(spec.name, "")]
        if show_all_options:
            self.stdout.write("\n  Tuning & Quota Limits (Optional):")
            for spec in tuning_specs:
                val = values.get(spec.name, "")
                if val:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"  - [OPTIONAL] {spec.name}: CUSTOMISED = {val} ({sources.get(spec.name, '')})"
                        )
                    )
                else:
                    missing_optional_all.append(spec)
                    self.stdout.write(f"  - [OPTIONAL] {spec.name}: USING DEFAULT ({spec.default_display})")
        else:
            self.stdout.write(f"\n  Tuning & Quota Limits ({len(tuning_specs)} optional vars):")
            if custom_tuning:
                custom_summary = ", ".join(f"{spec.name}={values[spec.name]}" for spec in custom_tuning)
                self.stdout.write(f"  - Customised ({len(custom_tuning)}): {custom_summary}")
            self.stdout.write(
                f"  - Using built-in defaults ({len(tuning_specs) - len(custom_tuning)} vars); "
                "pass --all-options to inspect or edit individually."
            )

        return missing_required, attention_recommended, missing_providers, missing_optional_all

    def _run_interactive_env_prompts(
        self,
        *,
        mode: str,
        toolforge_bin: Optional[str],
        tool_account: Optional[str],
        base_dir: Path,
        env_result: EnvLoadResult,
        missing_required: List[EnvVarSpec],
        attention_recommended: List[EnvVarSpec],
        missing_providers: List[EnvVarSpec],
        missing_optional_all: List[EnvVarSpec],
        show_all_options: bool,
    ) -> int:
        updated_count = 0

        def _prompt_and_store(spec: EnvVarSpec, *, hint: str = "") -> None:
            nonlocal updated_count
            if spec.name == "DJANGO_SECRET_KEY":
                prompt = (
                    f"  Enter {spec.name} (hidden; type 'gen' to auto-generate a 50-char secret, "
                    "or press Enter to skip): "
                )
            else:
                hidden_note = " (hidden)" if spec.sensitive else ""
                hint_note = f" [suggested: {hint}]" if hint else ""
                prompt = f"  Enter {spec.name}{hidden_note}{hint_note} (press Enter to skip): "

            entered = self._prompt_text(prompt, sensitive=spec.sensitive)
            if not entered:
                return

            final_val = (
                get_random_string(50, _SECRET_KEY_CHARS)
                if spec.name == "DJANGO_SECRET_KEY" and entered.lower() == "gen"
                else entered
            )
            self._save_env_value(
                mode=mode,
                toolforge_bin=toolforge_bin,
                base_dir=base_dir,
                env_result=env_result,
                key=spec.name,
                value=final_val,
            )
            updated_count += 1
            self.stdout.write(self.style.SUCCESS(f"    Saved {spec.name} = {format_display_value(spec, final_val)}"))

        if missing_required:
            self.stdout.write("\n  Interactive Setup: Required Variables")
            for spec in missing_required:
                _prompt_and_store(spec)

        if attention_recommended:
            self.stdout.write("\n  Interactive Setup: Recommended Variables")
            for spec in attention_recommended:
                hint = ""
                if spec.name == "DJANGO_ALLOWED_HOSTS" and mode == "bastion":
                    hint = DEFAULT_TOOLFORGE_ALLOWED_HOSTS
                elif spec.name == "WIKIMEDIA_REDIRECT_URI":
                    if tool_account:
                        hint = f"https://{tool_account}.toolforge.org/oauth/callback"
                    else:
                        hint = (
                            "http://127.0.0.1:8000/oauth/callback"
                            if mode == "local"
                            else DEFAULT_PRODUCTION_REDIRECT_URI
                        )
                elif spec.name == "REDIS_URL" and mode == "bastion":
                    hint = DEFAULT_TOOLFORGE_REDIS_URL
                elif spec.name == "TOOL_DATA_DIR" and mode == "bastion" and tool_account:
                    hint = f"/data/project/{tool_account}"
                _prompt_and_store(spec, hint=hint)

        if missing_providers:
            self.stdout.write("")
            if self._prompt_yes_no(
                f"  Configure {len(missing_providers)} missing third-party IP intelligence API keys now? [y/N]: "
            ):
                for spec in missing_providers:
                    _prompt_and_store(spec)

        if show_all_options and missing_optional_all:
            self.stdout.write("")
            if self._prompt_yes_no(
                f"  Configure {len(missing_optional_all)} optional runtime and tuning variables now? [y/N]: "
            ):
                for spec in missing_optional_all:
                    _prompt_and_store(spec, hint=spec.default_display)

        return updated_count

    def _print_directory_section(
        self,
        *,
        base_dir: Path,
        env_values: Mapping[str, str],
        mode: str,
        no_input: bool,
    ) -> List[DirectoryStatus]:
        self.stdout.write("\n[2/4] Persistent Directories & Mount Status")

        mounts: List[Tuple[str, str, str]] = []
        mounts_path = Path("/proc/mounts")
        if mounts_path.is_file():
            with contextlib.suppress(OSError):
                for line in mounts_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        mounts.append((parts[1].replace("\\040", " "), parts[2], parts[3]))

        raw_targets: List[Tuple[str, Path, bool, bool]] = []
        tool_data_dir = expand_configured_path(env_values.get("TOOL_DATA_DIR", ""))
        if tool_data_dir:
            raw_targets.append(
                ("Persistent data directory (TOOL_DATA_DIR)", resolve_tool_data_subdir(tool_data_dir), True, True)
            )
        elif mode == "bastion" or base_dir.parent == Path(base_dir.anchor):
            raw_targets.append(("Persistent data directory (~/data)", Path.home() / "data", True, True))
        else:
            local_candidates = (base_dir.parent / "data", base_dir / "data", Path.home() / "data")
            chosen_local = next((cand for cand in local_candidates if cand.is_dir()), base_dir.parent / "data")
            raw_targets.append(("Default offline data directory", chosen_local, True, True))
        raw_targets.append(("Frontend build assets (dist/assets)", base_dir / "dist" / "assets", False, False))
        raw_targets.append(("Collected static directory (staticfiles)", base_dir / "staticfiles", False, False))

        statuses: List[DirectoryStatus] = []
        for label, path, required, persistent in raw_targets:
            status = _inspect_directory(label, path, required=required, persistent=persistent, mounts=mounts)
            tag = "[REQUIRED]" if required else "[OPTIONAL]"
            if not status.exists:
                if not persistent and mode == "bastion":
                    self.stdout.write(
                        f"  - [INFO] {label}: NOT ON BASTION NFS "
                        "(built inside Toolforge Build Service image during 'toolforge build start')"
                    )
                    statuses.append(status)
                    continue
                msg = f"  - {tag} {label}: MISSING -> {path} ({status.mount_summary})"
                self.stdout.write(self.style.ERROR(msg) if required else self.style.WARNING(msg))
                if persistent and not no_input and self._prompt_yes_no(f"    Create directory '{path}'? [y/N]: "):
                    try:
                        path.mkdir(parents=True, exist_ok=True)
                        status = _inspect_directory(
                            label, path, required=required, persistent=persistent, mounts=mounts
                        )
                        self.stdout.write(self.style.SUCCESS(f"    Created {path}"))
                    except OSError as exc:
                        status = DirectoryStatus(
                            label=label,
                            path=path,
                            required=required,
                            persistent=persistent,
                            exists=False,
                            is_dir=False,
                            readable=False,
                            writable=False,
                            mount_summary=status.mount_summary,
                            is_ephemeral_mount=status.is_ephemeral_mount,
                            error=str(exc),
                        )
                        self.stdout.write(self.style.ERROR(f"    Failed to create {path}: {exc}"))
            elif not status.is_dir or not status.readable or (persistent and not status.writable):
                self.stdout.write(
                    self.style.ERROR(
                        f"  - {tag} {label}: PERMISSION / PATH ERROR -> {path} ({status.error}; {status.mount_summary})"
                    )
                )
            else:
                perm_label = "read/write" if status.writable else "read-only"
                line = f"  - {tag} {label}: OK ({perm_label}; {status.mount_summary}) -> {path}"
                if persistent and status.is_ephemeral_mount:
                    self.stdout.write(
                        self.style.WARNING(f"{line} [WARNING: ephemeral mount; ensure --mount=all on Toolforge]")
                    )
                else:
                    self.stdout.write(self.style.SUCCESS(line))
            statuses.append(status)

        return statuses

    def _print_offline_db_and_storage_section(
        self,
        *,
        base_dir: Path,
        env_result: EnvLoadResult,
    ) -> Tuple[List[Dict[str, Any]], Tuple[str, str], ToolsDbCheckResult]:
        self.stdout.write("\n[3/4] Offline Databases & Rule Files")
        entries = collect_offline_databases_status(
            env_overrides=env_result.values,
            base_dir=base_dir,
            include_resolved_path=True,
        )

        for entry in entries:
            tag = "[OPTIONAL]" if entry["optional"] else "[REQUIRED]"
            name, filename, status, resolved_path = (
                entry["name"],
                entry["filename"],
                entry["status"],
                entry["resolvedPath"],
            )
            if status in ("healthy", "stale"):
                size_bytes = entry["sizeBytes"]
                if size_bytes is None:
                    size_str = "-"
                elif size_bytes < 1024:
                    size_str = f"{size_bytes} B"
                elif size_bytes < 1024 * 1024:
                    size_str = f"{size_bytes / 1024:.1f} KiB"
                else:
                    size_str = f"{size_bytes / (1024 * 1024):.1f} MiB"

                age_seconds = entry["ageSeconds"]
                if age_seconds is None:
                    age_str = "-"
                elif age_seconds < 60:
                    age_str = f"{age_seconds}s"
                elif age_seconds < 3600:
                    age_str = f"{age_seconds // 60}m"
                elif age_seconds < 86400:
                    age_str = f"{age_seconds // 3600}h"
                else:
                    age_str = f"{age_seconds // 86400}d"

                style_fn = self.style.SUCCESS if status == "healthy" else self.style.WARNING
                self.stdout.write(
                    style_fn(
                        f"  - {tag} {name} ({filename}): {status.upper()} ({size_str}, age {age_str}) -> {resolved_path}"
                    )
                )
            elif entry["optional"] and entry["key"] == "hosting_asn_rules":
                self.stdout.write(f"  - {tag} {name} ({filename}): BUILT-IN FALLBACK (no override file found)")
            elif entry["optional"]:
                self.stdout.write(f"  - {tag} {name} ({filename}): MISSING (optional)")
            else:
                self.stdout.write(self.style.ERROR(f"  - {tag} {name} ({filename}): MISSING"))

        self.stdout.write("\n  Cache Isolation & ToolsDB Storage:")
        if "REDIS_KEY_SECRET" in env_result.hidden_keys:
            redis_status, redis_note = "ok", "configured in Toolforge envvars (hidden by CLI)"
        else:
            raw_secret = str(env_result.values.get("REDIS_KEY_SECRET") or "").strip()
            if not raw_secret:
                redis_status, redis_note = (
                    "warning",
                    "unset; falling back to DJANGO_SECRET_KEY for Redis namespace HMAC isolation",
                )
            else:
                is_placeholder, weak_reason = _is_weak_secret_key(raw_secret)
                if is_placeholder:
                    redis_status, redis_note = "error", f"{mask_secret(raw_secret)} ({weak_reason})"
                elif weak_reason:
                    redis_status, redis_note = "warning", f"{mask_secret(raw_secret)} ({weak_reason})"
                else:
                    redis_status, redis_note = "ok", f"configured = {mask_secret(raw_secret)}"

        if redis_status == "ok":
            self.stdout.write(self.style.SUCCESS(f"  - REDIS_KEY_SECRET: OK ({redis_note})"))
        elif redis_status == "warning":
            self.stdout.write(self.style.WARNING(f"  - REDIS_KEY_SECRET: WARNING ({redis_note})"))
        else:
            self.stdout.write(self.style.ERROR(f"  - REDIS_KEY_SECRET: ERROR ({redis_note})"))

        toolsdb_result = _check_toolsdb_status(
            base_dir,
            env_result.values,
            hidden_keys=env_result.hidden_keys,
        )
        if toolsdb_result.status == "ok":
            self.stdout.write(self.style.SUCCESS(f"  - ToolsDB L2: OK ({toolsdb_result.message})"))
        elif toolsdb_result.status == "warning":
            self.stdout.write(self.style.WARNING(f"  - ToolsDB L2: WARNING ({toolsdb_result.message})"))
        elif toolsdb_result.status == "error":
            self.stdout.write(self.style.ERROR(f"  - ToolsDB L2: ERROR ({toolsdb_result.message})"))
            for bad_grant in toolsdb_result.unsafe_grants:
                self.stdout.write(self.style.ERROR(f"    Unsafe grant: {bad_grant}"))
        else:
            self.stdout.write(f"  - ToolsDB L2: {toolsdb_result.status.upper()} ({toolsdb_result.message})")

        return entries, (redis_status, redis_note), toolsdb_result

    def _print_jobs_section(
        self,
        *,
        mode: str,
        toolforge_bin: Optional[str],
        tool_account: Optional[str],
        base_dir: Path,
    ) -> Tuple[List[BastionJobCheck], Optional[str]]:
        self.stdout.write("\n[4/4] Toolforge Scheduled Jobs")
        if mode != "bastion":
            self.stdout.write("  - [SKIPPED] Toolforge jobs check only runs in Toolforge Bastion mode.")
            return [], None

        if not toolforge_bin:
            err = "toolforge CLI unavailable"
            self.stdout.write(self.style.ERROR(f"  - [ERROR] {err}"))
            return [], err

        checks, err = _check_bastion_jobs(toolforge_bin, base_dir, tool_account)
        if err:
            self.stdout.write(self.style.ERROR(f"  - [ERROR] {err}"))
            return [], err

        for check in checks:
            spec = check.expected
            coverage_note = f", covered by '{check.covered_by}'" if check.covered_by else ""
            if not check.registered:
                self.stdout.write(
                    self.style.ERROR(
                        f"  - [REQUIRED] {spec.name}: MISSING (expected schedule '{spec.schedule}', command '{spec.command}')"
                    )
                )
                for warning in check.warnings:
                    self.stdout.write(self.style.WARNING(f"    Note: {warning}"))
            elif check.warnings:
                detail = "; ".join(check.warnings)
                self.stdout.write(
                    self.style.WARNING(
                        f"  - [REQUIRED] {spec.name}: REGISTERED WITH WARNINGS ({check.status}{coverage_note}; {detail})"
                    )
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  - [REQUIRED] {spec.name}: OK ({check.job_type or spec.schedule}; {check.status}{coverage_note})"
                    )
                )
        return checks, None

    def _print_remediation_and_summary(
        self,
        *,
        mode: str,
        tool_account: Optional[str],
        env_result: EnvLoadResult,
        dir_statuses: Sequence[DirectoryStatus],
        offline_entries: Sequence[Dict[str, Any]],
        redis_secret_check: Tuple[str, str],
        toolsdb_check: ToolsDbCheckResult,
        job_checks: Sequence[BastionJobCheck],
        jobs_error: Optional[str],
        updated_env_count: int,
        strict: bool,
    ) -> None:
        self.stdout.write("\nSummary & Next Steps")

        values, hidden = env_result.values, env_result.hidden_keys
        unresolved_required_env = [
            spec.name
            for spec in ENV_SPECS
            if spec.tier == "required"
            and spec.name not in hidden
            and (
                not values.get(spec.name)
                or (
                    spec.name == "DJANGO_SECRET_KEY"
                    and (values[spec.name] == INSECURE_DEV_SECRET_KEY or _is_weak_secret_key(values[spec.name])[0])
                )
            )
        ]
        missing_dirs = [d for d in dir_statuses if d.required and not d.exists]
        broken_dirs = [
            d
            for d in dir_statuses
            if d.required and d.exists and (not d.is_dir or not d.readable or (d.persistent and not d.writable))
        ]
        missing_or_stale_core_dbs = [e for e in offline_entries if not e["optional"] and e["status"] != "healthy"]
        missing_or_warn_jobs = [j for j in job_checks if not j.registered or j.warnings]

        commands_to_run: List[str] = []
        if mode == "bastion" and updated_env_count > 0:
            commands_to_run.append("toolforge webservice buildservice restart --mount=all")
        commands_to_run.extend(f"mkdir -p {d.path}" for d in missing_dirs)

        if missing_or_stale_core_dbs:
            missing_sfs_dbs = [e for e in missing_or_stale_core_dbs if e["source"] == "StopForumSpam"]
            missing_maxmind_dbs = [e for e in missing_or_stale_core_dbs if e["source"] == "MaxMind"]
            has_maxmind_creds = bool(
                (values.get("MAXMIND_ACCOUNT_ID") or "MAXMIND_ACCOUNT_ID" in hidden)
                and (values.get("MAXMIND_LICENSE_KEY") or "MAXMIND_LICENSE_KEY" in hidden)
            )
            if mode == "bastion":
                target_image = (
                    f"tool-{tool_account}/tool-{tool_account}:latest" if tool_account else DEFAULT_JOB_SPEC.image
                )
                if missing_maxmind_dbs and not has_maxmind_creds:
                    self.stdout.write(
                        self.style.WARNING(
                            "  - MaxMind credentials (MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY) are not configured; "
                            "configure them first or upload GeoLite2-*.mmdb manually into ~/data."
                        )
                    )
                commands_to_run.append(
                    f"toolforge jobs run update-offline-dbs-init --image {target_image} "
                    '--mount=all --wait --command "python manage.py update_offline_dbs"'
                )
            elif missing_sfs_dbs and not missing_maxmind_dbs:
                commands_to_run.append("python manage.py update_offline_dbs --sources stopforumspam")
            else:
                if missing_maxmind_dbs and not has_maxmind_creds:
                    self.stdout.write(
                        self.style.WARNING(
                            "  - MaxMind credentials (MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY) are not configured; "
                            "StopForumSpam can still update via '--sources stopforumspam'."
                        )
                    )
                    if missing_sfs_dbs:
                        commands_to_run.append("python manage.py update_offline_dbs --sources stopforumspam")
                commands_to_run.append("python manage.py update_offline_dbs")

        if missing_or_warn_jobs:
            commands_to_run.extend(
                f'toolforge jobs run {job.covered_by or job.expected.name} --command "{job.expected.command}" '
                f'--image {job.adapted_image} --schedule "{job.expected.schedule}" --mount={job.expected.mount}'
                for job in missing_or_warn_jobs
            )
            if any(job.expected.image != job.adapted_image for job in missing_or_warn_jobs):
                template_img = missing_or_warn_jobs[0].expected.image
                adapted_img = missing_or_warn_jobs[0].adapted_image
                commands_to_run.append(
                    f"tmp_jobs=$(mktemp) && sed 's|{template_img}|{adapted_img}|g' jobs.yaml > \"$tmp_jobs\" "
                    '&& toolforge jobs load "$tmp_jobs" && rm -f "$tmp_jobs"'
                )
            else:
                commands_to_run.append("toolforge jobs load jobs.yaml")

        if unresolved_required_env:
            self.stdout.write(
                self.style.ERROR(f"  - Required envvars still missing/invalid: {', '.join(unresolved_required_env)}")
            )
        else:
            self.stdout.write(self.style.SUCCESS("  - All required environment variables are configured."))

        if broken_dirs:
            self.stdout.write(
                self.style.ERROR("  - Directory permission/path issues: " + ", ".join(str(d.path) for d in broken_dirs))
            )
        if missing_dirs:
            self.stdout.write(
                self.style.WARNING("  - Missing required directories: " + ", ".join(str(d.path) for d in missing_dirs))
            )
        if not missing_dirs and not broken_dirs:
            self.stdout.write(self.style.SUCCESS("  - All required persistent directories are ready."))

        if missing_or_stale_core_dbs:
            self.stdout.write(
                self.style.WARNING(
                    f"  - Core offline databases needing attention: {len(missing_or_stale_core_dbs)} "
                    f"({', '.join(e['filename'] for e in missing_or_stale_core_dbs)})"
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS("  - All core offline databases are present and up to date."))

        if mode == "bastion":
            if jobs_error:
                self.stdout.write(self.style.ERROR(f"  - Scheduled jobs check error: {jobs_error}"))
            elif missing_or_warn_jobs:
                self.stdout.write(
                    self.style.WARNING(
                        "  - Scheduled jobs needing setup/review: "
                        + ", ".join(j.expected.name for j in missing_or_warn_jobs)
                    )
                )
            else:
                self.stdout.write(self.style.SUCCESS("  - Toolforge scheduled jobs match jobs.yaml."))

        if redis_secret_check[0] == "error":
            self.stdout.write(self.style.ERROR(f"  - Invalid REDIS_KEY_SECRET: {redis_secret_check[1]}"))
        if toolsdb_check.status == "error":
            self.stdout.write(self.style.ERROR(f"  - ToolsDB L2 error: {toolsdb_check.message}"))

        if commands_to_run:
            self.stdout.write("\n  Recommended commands:")
            for cmd in commands_to_run:
                self.stdout.write(f"    {cmd}")

        has_required_failures = bool(
            unresolved_required_env
            or missing_dirs
            or broken_dirs
            or missing_or_stale_core_dbs
            or redis_secret_check[0] == "error"
            or toolsdb_check.status == "error"
            or jobs_error
            or (mode == "bastion" and any(not j.registered for j in job_checks))
        )
        if strict and has_required_failures:
            raise CommandError("Setup check failed under --strict because required items are missing or unhealthy.")

    def handle(self, *args, **options) -> None:
        base_dir = Path(str(getattr(settings, "BASE_DIR", Path(__file__).resolve().parent.parent.parent.parent)))
        requested_mode = str(options.get("env_mode") or "auto")
        no_input = bool(options.get("no_input"))
        show_all_options = bool(options.get("all_options"))
        strict = bool(options.get("strict"))

        mode, toolforge_bin, tool_account = _detect_runtime_environment(requested_mode)
        mode_desc = (
            f"Toolforge Bastion (account: {tool_account})"
            if mode == "bastion" and tool_account
            else ("Toolforge Bastion (account undetected)" if mode == "bastion" else "Local / Buildpack Container")
        )
        self.stdout.write(f"Proxycheck Environment Check ({mode_desc})")
        if mode == "bastion" and not tool_account:
            self.stdout.write(
                self.style.WARNING(
                    "  Warning: Could not detect a 'tools.<name>' account. Run 'become proxycheck' or "
                    "'become proxycheck-dev' before managing toolforge envvars or jobs."
                )
            )

        env_result = (
            _load_bastion_envvars(toolforge_bin, base_dir)
            if mode == "bastion" and toolforge_bin
            else _load_local_envvars(base_dir)
        )
        for warning in env_result.warnings:
            self.stdout.write(self.style.WARNING(f"  Warning: {warning}"))

        missing_required, attention_recommended, missing_providers, missing_optional_all = self._print_env_section(
            env_result,
            mode=mode,
            tool_account=tool_account,
            show_all_options=show_all_options,
        )

        updated_env_count = 0
        if not no_input:
            updated_env_count = self._run_interactive_env_prompts(
                mode=mode,
                toolforge_bin=toolforge_bin,
                tool_account=tool_account,
                base_dir=base_dir,
                env_result=env_result,
                missing_required=missing_required,
                attention_recommended=attention_recommended,
                missing_providers=missing_providers,
                missing_optional_all=missing_optional_all,
                show_all_options=show_all_options,
            )

        dir_statuses = self._print_directory_section(
            base_dir=base_dir,
            env_values=env_result.values,
            mode=mode,
            no_input=no_input,
        )
        offline_entries, redis_secret_check, toolsdb_check = self._print_offline_db_and_storage_section(
            base_dir=base_dir,
            env_result=env_result,
        )
        job_checks, jobs_error = self._print_jobs_section(
            mode=mode,
            toolforge_bin=toolforge_bin,
            tool_account=tool_account,
            base_dir=base_dir,
        )

        self._print_remediation_and_summary(
            mode=mode,
            tool_account=tool_account,
            env_result=env_result,
            dir_statuses=dir_statuses,
            offline_entries=offline_entries,
            redis_secret_check=redis_secret_check,
            toolsdb_check=toolsdb_check,
            job_checks=job_checks,
            jobs_error=jobs_error,
            updated_env_count=updated_env_count,
            strict=strict,
        )
