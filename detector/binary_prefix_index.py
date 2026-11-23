"""Compact memory-mapped binary prefix index for fast IPv4 and IPv6 longest prefix matching."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import mmap
import os
import shutil
import socket
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

MAGIC_HEADER = b"PCBI\x00\x01\x00\x00"
_HEADER_STRUCT = struct.Struct(">8s13Q")
_V4_SEG_STRUCT = struct.Struct(">II")
_V4_RULE_STRUCT = struct.Struct(">IB3xI")
_V6_SEG_STRUCT = struct.Struct(">16sI")
_V6_RULE_STRUCT = struct.Struct(">16sB3xI")
_PAYLOAD_INDEX_STRUCT = struct.Struct(">QQB7x")
_U32_STRUCT = struct.Struct(">I")

_KIND_NONE = 0
_KIND_INT = 1
_KIND_STR = 2
_KIND_JSON = 3

_IPV4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"
_MAX_V4_INT = (1 << 32) - 1
_MAX_V6_INT = (1 << 128) - 1


class BinaryPrefixFormatError(ValueError):
    """Raised when a binary prefix index file has an invalid header or truncated section."""


def _atomic_replace_retry(src_path: Path, dst_path: Path) -> None:
    for attempt in range(6):
        try:
            os.replace(src_path, dst_path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (attempt + 1))


def parse_cidr_to_int_prefix(raw_cidr: str) -> Optional[Tuple[int, int, int]]:
    """Normalises an IPv4 or IPv6 CIDR or host address into version, masked network integer, and prefix length."""
    if not isinstance(raw_cidr, str):
        return None
    cleaned = raw_cidr.strip()
    if not cleaned:
        return None

    prefix_len: Optional[int]
    if "/" in cleaned:
        addr_part, prefix_part = cleaned.split("/", 1)
        addr_part = addr_part.strip()
        prefix_part = prefix_part.strip()
        prefix_len = int(prefix_part) if prefix_part.isdigit() else None
    else:
        addr_part = cleaned
        prefix_len = 128 if ":" in addr_part else 32

    if prefix_len is not None:
        if ":" not in addr_part:
            if not (0 <= prefix_len <= 32):
                return None
            with contextlib.suppress(OSError):
                packed = socket.inet_pton(socket.AF_INET, addr_part)
                mask = ((_MAX_V4_INT << (32 - prefix_len)) & _MAX_V4_INT) if prefix_len > 0 else 0
                return 4, int.from_bytes(packed, "big") & mask, prefix_len
        else:
            if "%" in addr_part:
                addr_part = addr_part.split("%", 1)[0]
            if not (0 <= prefix_len <= 128):
                return None
            with contextlib.suppress(OSError):
                packed6 = socket.inet_pton(socket.AF_INET6, addr_part)
                mask6 = (_MAX_V6_INT ^ ((1 << (128 - prefix_len)) - 1)) if prefix_len > 0 else 0
                return 6, int.from_bytes(packed6, "big") & mask6, prefix_len

    try:
        net = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        return None
    return net.version, int(net.network_address), net.prefixlen


def _flatten_dyadic_rules(
    sorted_rules: List[Tuple[int, int, int]],
    width: int,
) -> List[Tuple[int, int]]:
    """Converts nested dyadic CIDR intervals sorted by start and prefix length into disjoint LPM segments."""
    if not sorted_rules:
        return []

    max_addr = (1 << width) - 1
    segments: List[Tuple[int, int]] = []
    stack: List[Tuple[int, int]] = []
    cursor = 0

    def append_segment(seg_start: int, rule_id: int) -> None:
        if not segments or segments[-1][1] != rule_id:
            segments.append((seg_start, rule_id))

    for rule_idx, (net_start, prefix_len, _payload_idx) in enumerate(sorted_rules, start=1):
        host_bits = width - prefix_len
        net_end = net_start + ((1 << host_bits) - 1)

        while stack and stack[-1][0] < net_start:
            top_end, top_rule = stack.pop()
            if cursor <= top_end:
                append_segment(cursor, top_rule)
                cursor = top_end + 1

        if cursor < net_start:
            append_segment(cursor, stack[-1][1] if stack else 0)
            cursor = net_start

        stack.append((net_end, rule_idx))

    while stack:
        top_end, top_rule = stack.pop()
        if cursor <= top_end:
            append_segment(cursor, top_rule)
            cursor = top_end + 1

    if cursor <= max_addr:
        append_segment(cursor, 0)

    return segments


def _intern_rule_payloads(
    rule_map: Dict[Tuple[int, int], Any],
    payload_pool: Dict[Tuple[int, bytes], int],
    payload_entries: List[Tuple[int, bytes]],
) -> List[Tuple[int, int, int]]:
    rules: List[Tuple[int, int, int]] = []
    for key in sorted(rule_map.keys()):
        value = rule_map[key]
        if value is None:
            encoded = (_KIND_NONE, b"")
        elif isinstance(value, int) and not isinstance(value, bool):
            encoded = (_KIND_INT, str(value).encode("ascii"))
        elif isinstance(value, str):
            encoded = (_KIND_STR, value.encode("utf-8"))
        else:
            encoded = (_KIND_JSON, json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))

        payload_idx = payload_pool.get(encoded)
        if payload_idx is None:
            payload_idx = len(payload_entries)
            payload_pool[encoded] = payload_idx
            payload_entries.append(encoded)
        rules.append((key[0], key[1], payload_idx))
    return rules


def compile_binary_prefix_index(
    entries: Iterable[Tuple[str, Any]],
    target_path: Path | str,
    *,
    merge_payloads: Optional[Callable[[Any, Any], Any]] = None,
) -> int:
    """Compiles IPv4 and IPv6 CIDRs with tagged metadata into an atomic memory-mappable binary file."""
    dst = Path(target_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    v4_map: Dict[Tuple[int, int], Any] = {}
    v6_map: Dict[Tuple[int, int], Any] = {}
    for raw_cidr, payload in entries:
        parsed = parse_cidr_to_int_prefix(raw_cidr)
        if parsed is None:
            continue
        version, net_int, prefix_len = parsed
        target = v4_map if version == 4 else v6_map
        key = (net_int, prefix_len)
        if merge_payloads is not None and key in target:
            target[key] = merge_payloads(target[key], payload)
        else:
            target[key] = payload

    payload_pool: Dict[Tuple[int, bytes], int] = {}
    payload_entries: List[Tuple[int, bytes]] = []
    v4_rules = _intern_rule_payloads(v4_map, payload_pool, payload_entries)
    v6_rules = _intern_rule_payloads(v6_map, payload_pool, payload_entries)
    v4_segments = _flatten_dyadic_rules(v4_rules, 32)
    v6_segments = _flatten_dyadic_rules(v6_rules, 128)

    v4_seg_offset = _HEADER_STRUCT.size
    v4_rule_offset = v4_seg_offset + len(v4_segments) * _V4_SEG_STRUCT.size
    v6_seg_offset = v4_rule_offset + len(v4_rules) * _V4_RULE_STRUCT.size
    v6_rule_offset = v6_seg_offset + len(v6_segments) * _V6_SEG_STRUCT.size
    payload_index_offset = v6_rule_offset + len(v6_rules) * _V6_RULE_STRUCT.size
    payload_blob_offset = payload_index_offset + len(payload_entries) * _PAYLOAD_INDEX_STRUCT.size
    payload_blob_size = sum(len(data) for _kind, data in payload_entries)
    total_file_size = payload_blob_offset + payload_blob_size

    header_bytes = _HEADER_STRUCT.pack(
        MAGIC_HEADER,
        v4_seg_offset,
        len(v4_segments),
        v4_rule_offset,
        len(v4_rules),
        v6_seg_offset,
        len(v6_segments),
        v6_rule_offset,
        len(v6_rules),
        payload_index_offset,
        len(payload_entries),
        payload_blob_offset,
        payload_blob_size,
        total_file_size,
    )

    fd, tmp_name = tempfile.mkstemp(prefix=f".{dst.name}.tmp.", dir=str(dst.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        with tmp_path.open("wb") as handle:
            handle.write(header_bytes)
            for seg_start, rule_id in v4_segments:
                handle.write(_V4_SEG_STRUCT.pack(seg_start, rule_id))
            for net_int, prefix_len, payload_idx in v4_rules:
                handle.write(_V4_RULE_STRUCT.pack(net_int, prefix_len, payload_idx))
            for seg_start6, rule_id6 in v6_segments:
                handle.write(_V6_SEG_STRUCT.pack(seg_start6.to_bytes(16, "big"), rule_id6))
            for net_int6, prefix_len6, payload_idx6 in v6_rules:
                handle.write(_V6_RULE_STRUCT.pack(net_int6.to_bytes(16, "big"), prefix_len6, payload_idx6))

            running_offset = 0
            for kind, raw_blob in payload_entries:
                handle.write(_PAYLOAD_INDEX_STRUCT.pack(running_offset, len(raw_blob), kind))
                running_offset += len(raw_blob)
            for _kind, raw_blob in payload_entries:
                if raw_blob:
                    handle.write(raw_blob)

        with contextlib.suppress(OSError):
            os.chmod(tmp_path, 0o644)
        _atomic_replace_retry(tmp_path, dst)
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()

    return len(v4_rules) + len(v6_rules)


def sync_file_to_ephemeral_cache(
    source_path: Path,
    ephemeral_dir: Path,
    *,
    stat_sig: Optional[Tuple[int, int]] = None,
) -> Path:
    """Sequentially copies an offline file to local ephemeral storage when its stat signature changes."""
    if stat_sig is None:
        st = os.stat(source_path)
        stat_sig = (st.st_mtime_ns, st.st_size)

    with contextlib.suppress(OSError):
        if source_path.parent.resolve() == ephemeral_dir.resolve():
            return source_path

    sig_token = f"{source_path}:{stat_sig[0]}:{stat_sig[1]}".encode("utf-8")
    digest = hashlib.sha256(sig_token).hexdigest()[:12]
    local_name = f"{source_path.stem}_{digest}{source_path.suffix}"
    local_target = ephemeral_dir / local_name

    try:
        ephemeral_dir.mkdir(parents=True, exist_ok=True)
        if local_target.is_file() and local_target.stat().st_size == stat_sig[1]:
            return local_target

        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{local_name}.{os.getpid()}.tmp.",
            dir=str(ephemeral_dir),
        )
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            with source_path.open("rb") as src_handle, tmp_path.open("wb") as dst_handle:
                shutil.copyfileobj(src_handle, dst_handle, length=262144)
            with contextlib.suppress(OSError):
                os.chmod(tmp_path, 0o644)
            _atomic_replace_retry(tmp_path, local_target)
        finally:
            if tmp_path.exists():
                with contextlib.suppress(OSError):
                    tmp_path.unlink()

        prefix_glob = f"{source_path.stem}_*{source_path.suffix}"
        for sibling in ephemeral_dir.glob(prefix_glob):
            if sibling != local_target:
                with contextlib.suppress(OSError):
                    sibling.unlink()
        return local_target
    except OSError:
        return source_path


class BinaryPrefixIndexReader:
    """Read-only memory-mapped longest prefix match reader for compiled binary prefix files."""

    def __init__(self, file_path: Path | str) -> None:
        self.file_path = Path(file_path)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        fd = os.open(self.file_path, flags)
        try:
            file_size = os.fstat(fd).st_size
            if file_size < _HEADER_STRUCT.size:
                raise BinaryPrefixFormatError(f"Binary prefix file is truncated: {self.file_path}")
            mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        finally:
            os.close(fd)

        self._mmap: Optional[mmap.mmap] = mm
        self._scalar_cache: Dict[int, Any] = {}
        try:
            (
                magic,
                self._v4_seg_offset,
                self._v4_seg_count,
                self._v4_rule_offset,
                self._v4_rule_count,
                self._v6_seg_offset,
                self._v6_seg_count,
                self._v6_rule_offset,
                self._v6_rule_count,
                self._payload_index_offset,
                self._payload_count,
                self._payload_blob_offset,
                self._payload_blob_size,
                recorded_total_size,
            ) = _HEADER_STRUCT.unpack_from(mm, 0)

            if magic != MAGIC_HEADER:
                raise BinaryPrefixFormatError(f"Invalid magic header in binary prefix index: {self.file_path}")
            if recorded_total_size != file_size:
                raise BinaryPrefixFormatError(f"Binary prefix index size mismatch in {self.file_path}")

            sections = (
                (self._v4_seg_offset, self._v4_seg_count * _V4_SEG_STRUCT.size),
                (self._v4_rule_offset, self._v4_rule_count * _V4_RULE_STRUCT.size),
                (self._v6_seg_offset, self._v6_seg_count * _V6_SEG_STRUCT.size),
                (self._v6_rule_offset, self._v6_rule_count * _V6_RULE_STRUCT.size),
                (self._payload_index_offset, self._payload_count * _PAYLOAD_INDEX_STRUCT.size),
                (self._payload_blob_offset, self._payload_blob_size),
            )
            for offset, length in sections:
                if offset < _HEADER_STRUCT.size or offset + length > file_size:
                    raise BinaryPrefixFormatError(f"Corrupt section bounds in binary prefix index: {self.file_path}")
        except Exception:
            self.close()
            raise

    @classmethod
    def open_from_source(
        cls,
        source_path: Path,
        ephemeral_dir: Path,
        *,
        stat_sig: Optional[Tuple[int, int]] = None,
    ) -> BinaryPrefixIndexReader:
        local_path = sync_file_to_ephemeral_cache(source_path, ephemeral_dir, stat_sig=stat_sig)
        return cls(local_path)

    @property
    def closed(self) -> bool:
        return self._mmap is None or self._mmap.closed

    def close(self) -> None:
        mm = self._mmap
        self._mmap = None
        self._scalar_cache.clear()
        if mm is not None and not mm.closed:
            with contextlib.suppress(BufferError, OSError, ValueError):
                mm.close()

    def __enter__(self) -> BinaryPrefixIndexReader:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _decode_payload_at(self, mm: mmap.mmap, payload_idx: int) -> Any:
        if payload_idx >= self._payload_count:
            raise BinaryPrefixFormatError("Payload index out of range in binary prefix index.")
        if payload_idx in self._scalar_cache:
            return self._scalar_cache[payload_idx]

        idx_pos = self._payload_index_offset + payload_idx * _PAYLOAD_INDEX_STRUCT.size
        rel_offset, blob_len, kind = _PAYLOAD_INDEX_STRUCT.unpack_from(mm, idx_pos)
        start = self._payload_blob_offset + rel_offset
        end = start + blob_len
        if end > self._payload_blob_offset + self._payload_blob_size:
            raise BinaryPrefixFormatError("Payload slice exceeds blob section bounds.")
        raw = mm[start:end]

        if kind == _KIND_NONE:
            val: Any = None
        elif kind == _KIND_INT:
            val = int(raw.decode("ascii"))
        elif kind == _KIND_STR:
            val = raw.decode("utf-8")
        elif kind == _KIND_JSON:
            return json.loads(raw.decode("utf-8"))
        else:
            raise BinaryPrefixFormatError(f"Unsupported payload kind {kind} in binary prefix index.")

        if len(self._scalar_cache) < 8192:
            self._scalar_cache[payload_idx] = val
        return val

    def _lookup_v4_u32(self, mm: mmap.mmap, addr_u32: int) -> Optional[Tuple[str, int, Any]]:
        count = self._v4_seg_count
        if count == 0:
            return None

        base = self._v4_seg_offset
        lo = 0
        hi = count - 1
        while lo <= hi:
            mid = (lo + hi) >> 1
            seg_start = _U32_STRUCT.unpack_from(mm, base + (mid << 3))[0]
            if seg_start <= addr_u32:
                lo = mid + 1
            else:
                hi = mid - 1

        if hi < 0:
            return None
        rule_id = _U32_STRUCT.unpack_from(mm, base + (hi << 3) + 4)[0]
        if rule_id == 0 or rule_id > self._v4_rule_count:
            return None

        rule_pos = self._v4_rule_offset + (rule_id - 1) * _V4_RULE_STRUCT.size
        net_u32, prefix_len, payload_idx = _V4_RULE_STRUCT.unpack_from(mm, rule_pos)
        cidr_str = f"{socket.inet_ntop(socket.AF_INET, net_u32.to_bytes(4, 'big'))}/{prefix_len}"
        return cidr_str, prefix_len, self._decode_payload_at(mm, payload_idx)

    def lookup_with_prefix_len(self, ip: Optional[str]) -> Optional[Tuple[str, int, Any]]:
        """Matches an IPv4 or IPv6 address against the longest prefix and returns CIDR, prefix length, and payload."""
        mm = self._mmap
        if mm is None or mm.closed or not ip or not isinstance(ip, str):
            return None
        cleaned = ip.strip()
        if not cleaned:
            return None

        if ":" not in cleaned:
            try:
                packed4 = socket.inet_pton(socket.AF_INET, cleaned)
            except OSError:
                return None
            return self._lookup_v4_u32(mm, _U32_STRUCT.unpack(packed4)[0])

        if "%" in cleaned:
            cleaned = cleaned.split("%", 1)[0]
        try:
            packed6 = socket.inet_pton(socket.AF_INET6, cleaned)
        except OSError:
            try:
                addr = ipaddress.ip_address(cleaned)
            except ValueError:
                return None
            if addr.version == 4:
                return self._lookup_v4_u32(mm, int(addr))
            packed6 = addr.packed

        if self._v6_seg_count > 0:
            base = self._v6_seg_offset
            lo = 0
            hi = self._v6_seg_count - 1
            while lo <= hi:
                mid = (lo + hi) >> 1
                pos = base + mid * _V6_SEG_STRUCT.size
                if mm[pos : pos + 16] <= packed6:
                    lo = mid + 1
                else:
                    hi = mid - 1

            if hi >= 0:
                rule_id = _U32_STRUCT.unpack_from(mm, base + hi * _V6_SEG_STRUCT.size + 16)[0]
                if 0 < rule_id <= self._v6_rule_count:
                    rule_pos = self._v6_rule_offset + (rule_id - 1) * _V6_RULE_STRUCT.size
                    net_bytes, prefix_len, payload_idx = _V6_RULE_STRUCT.unpack_from(mm, rule_pos)
                    cidr_str = f"{ipaddress.IPv6Address(net_bytes).compressed}/{prefix_len}"
                    return cidr_str, prefix_len, self._decode_payload_at(mm, payload_idx)

        if packed6[:12] == _IPV4_MAPPED_PREFIX:
            return self._lookup_v4_u32(mm, _U32_STRUCT.unpack_from(packed6, 12)[0])
        return None

    def lookup(self, ip: Optional[str]) -> Optional[Tuple[str, Any]]:
        """Matches an IPv4 or IPv6 address against the longest prefix and returns matched CIDR and payload."""
        hit = self.lookup_with_prefix_len(ip)
        if hit is None:
            return None
        return hit[0], hit[2]
