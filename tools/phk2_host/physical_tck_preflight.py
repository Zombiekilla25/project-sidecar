#!/usr/bin/env python3
"""Fail-closed, local-only preflight for a future PHK2 physical TCK test.

The live mode reads files, /proc, `ps`, and `ss`; it never opens a transport,
enumerates USB, connects to XVC, or sends JTAG traffic. Synthetic unit tests
exercise its checks without inspecting the current host.
"""
from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
from typing import Any, Iterable


PINNED_REVIEWED_BRIDGE_SHA256 = "8c7230f0bf586e9297dc0e568bd19278aeeb7cff8dbb3dde150811f11393218a"
PINNED_REVIEWED_BUILD_ID = "b0562d538761373e2f1025c8bc8d8188ff8a0c40"
HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
SERVER_WORDS = ("sqrl_bridge", "sqrlbridge", "xvcserver")
CLIENT_WORDS = ("xvc", "jtag", "openocd", "hw_server", "vivado_lab", "libftdi", "ftdi")


class Refusal(RuntimeError):
    """An evidence or ownership gate failed; physical use must stop."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hash_text(value: Any, name: str, length: int = 64) -> str:
    pattern = HEX40 if length == 40 else HEX64
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise Refusal(f"{name} must be a {length}-character hexadecimal digest")
    return value.lower()


def _require_file(path_value: Any, label: str) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise Refusal(f"{label} path is missing")
    path = Path(path_value)
    if not path.is_absolute():
        raise Refusal(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise Refusal(f"{label} is not a regular file")
        return resolved
    except OSError as exc:
        raise Refusal(f"{label} is unavailable: {exc}") from exc


def _package_file(root: Path, item: Any, label: str) -> tuple[Path, str]:
    if not isinstance(item, dict):
        raise Refusal(f"{label} reference is missing")
    relative = item.get("path")
    expected = _hash_text(item.get("sha256"), f"{label}.sha256")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise Refusal(f"{label}.path must be package-relative")
    path = root / relative
    try:
        # Resolve only after rejecting symlink components. A resolved target
        # inside the package is still not acceptable if the supplied evidence
        # path itself traversed a symlink.
        cursor = root
        for component in Path(relative).parts:
            if component in ("", ".", ".."):
                if component == "..":
                    raise Refusal(f"{label}.path must not traverse parent directories")
                continue
            cursor = cursor / component
            if cursor.is_symlink():
                raise Refusal(f"{label}.path must not traverse symlinks")
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except Refusal:
        raise
    except (OSError, ValueError) as exc:
        raise Refusal(f"{label} escapes or is missing from the qualification package") from exc
    if not resolved.is_file():
        raise Refusal(f"{label} must be a regular package file")
    actual = _sha256(resolved)
    if actual != expected:
        raise Refusal(f"{label} hash mismatch")
    return resolved, actual


def _finite_number(value: Any, label: str, *, positive: bool = True) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise Refusal(f"{label} must be a finite number")
    result = float(value)
    if positive and result <= 0:
        raise Refusal(f"{label} must be positive")
    return result


def validate_qualification_manifest(path: str | Path) -> dict[str, Any]:
    """Verify a package-relative source, routed, constraint, timing, promotion set."""
    manifest_path = _require_file(str(path), "qualification manifest")
    try:
        data = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"qualification manifest is unreadable JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != "PHK2-QUALIFICATION-MANIFEST-v1":
        raise Refusal("unsupported qualification manifest schema")
    root = manifest_path.parent.resolve()

    source_commit = _hash_text(data.get("SOURCE_COMMIT"), "SOURCE_COMMIT", 40)
    source_tree_hash = _hash_text(data.get("SOURCE_TREE_HASH"), "SOURCE_TREE_HASH")
    source_archive, actual_tree_hash = _package_file(root, data.get("SOURCE_TREE_ARCHIVE"), "SOURCE_TREE_ARCHIVE")
    if actual_tree_hash != source_tree_hash:
        raise Refusal("SOURCE_TREE_HASH does not match the source tree archive")

    routed_hash = _hash_text(data.get("ROUTED_DCP_HASH"), "ROUTED_DCP_HASH")
    _, actual_routed_hash = _package_file(root, data.get("ROUTED_DCP"), "ROUTED_DCP")
    if routed_hash != actual_routed_hash:
        raise Refusal("ROUTED_DCP_HASH does not match the routed checkpoint")

    constraints = data.get("CONSTRAINT_MODEL")
    if not isinstance(constraints, dict) or not isinstance(constraints.get("name"), str) or not constraints["name"]:
        raise Refusal("CONSTRAINT_MODEL identity is missing")
    constraint_hash = _hash_text(constraints.get("sha256"), "CONSTRAINT_MODEL.sha256")
    _, actual_constraint_hash = _package_file(root, constraints, "CONSTRAINT_MODEL")
    if constraint_hash != actual_constraint_hash:
        raise Refusal("CONSTRAINT_MODEL hash mismatch")

    target_part = data.get("TARGET_PART")
    if not isinstance(target_part, str) or not target_part.strip():
        raise Refusal("TARGET_PART is missing")
    envelope = data.get("TCK_ANALYSIS_ENVELOPE")
    if not isinstance(envelope, dict) or envelope.get("qualified") is not True:
        raise Refusal("TCK_ANALYSIS_ENVELOPE is absent or not qualified")
    for field in ("minimum_tck_hz", "maximum_tck_hz", "minimum_high_ns", "minimum_low_ns",
                  "minimum_duty_cycle_percent", "maximum_duty_cycle_percent",
                  "maximum_period_jitter_p2p_ns", "maximum_period_jitter_rms_ns"):
        _finite_number(envelope.get(field), f"TCK_ANALYSIS_ENVELOPE.{field}")
    if envelope["minimum_tck_hz"] > envelope["maximum_tck_hz"]:
        raise Refusal("TCK analysis frequency interval is inverted")
    if envelope["minimum_duty_cycle_percent"] >= envelope["maximum_duty_cycle_percent"] or envelope["maximum_duty_cycle_percent"] >= 100:
        raise Refusal("TCK analysis duty-cycle interval is invalid")
    _, timing_hash = _package_file(root, envelope.get("timing_report"), "TCK_ANALYSIS_ENVELOPE.timing_report")

    if data.get("QUALIFICATION_STATUS") != "QUALIFIED":
        raise Refusal("QUALIFICATION_STATUS is not QUALIFIED")
    promotion = data.get("INDEPENDENT_PROMOTION")
    if not isinstance(promotion, dict) or promotion.get("status") != "COMPLETE" or promotion.get("result") != "PASS":
        raise Refusal("independent promotion is incomplete or not passing")
    if not isinstance(promotion.get("approval_id"), str) or not promotion["approval_id"].strip():
        raise Refusal("independent promotion approval_id is missing")
    promotion_path, _ = _package_file(root, promotion.get("evidence"), "INDEPENDENT_PROMOTION.evidence")
    try:
        promotion_evidence = json.loads(promotion_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"independent promotion evidence is unreadable: {exc}") from exc
    link_values = {
        "SOURCE_COMMIT": source_commit,
        "SOURCE_TREE_HASH": source_tree_hash,
        "ROUTED_DCP_HASH": routed_hash,
        "CONSTRAINT_MODEL_HASH": constraint_hash,
        "TARGET_PART": target_part,
    }
    if not isinstance(promotion_evidence, dict) or promotion_evidence.get("status") != "PASS":
        raise Refusal("independent promotion evidence does not report PASS")
    for key, value in link_values.items():
        if promotion.get(key) != value or promotion_evidence.get(key) != value:
            raise Refusal(f"independent promotion does not bind {key}")

    return {
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "SOURCE_COMMIT": source_commit,
        "SOURCE_TREE_HASH": source_tree_hash,
        "SOURCE_TREE_ARCHIVE_PATH": str(source_archive),
        "ROUTED_DCP_HASH": routed_hash,
        "CONSTRAINT_MODEL": constraints["name"],
        "CONSTRAINT_MODEL_HASH": constraint_hash,
        "TARGET_PART": target_part,
        "TCK_ANALYSIS_ENVELOPE": dict(envelope),
        "TCK_TIMING_REPORT_HASH": timing_hash,
        "QUALIFICATION_STATUS": "QUALIFIED",
        "INDEPENDENT_PROMOTION_STATUS": "COMPLETE",
        "INDEPENDENT_PROMOTION_APPROVAL_ID": promotion["approval_id"],
    }


def validate_target_lock(path: str | Path) -> dict[str, Any]:
    lock_path = _require_file(str(path), "target lock")
    try:
        data = json.loads(lock_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"target lock is unreadable JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != "PHK2-PHYSICAL-TCK-TARGET-LOCK-v1" or data.get("status") != "PASS":
        raise Refusal("target lock schema/status is not a passing PHK2 TCK lock")
    if data.get("match_count") != 1:
        raise Refusal("target lock does not uniquely identify one adapter")
    try:
        expiry = datetime.fromisoformat(str(data["expires_utc"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise Refusal("target lock expiry is missing or invalid") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise Refusal("target lock is expired or has no timezone")
    adapter, target, xvc = data.get("adapter"), data.get("target"), data.get("xvc")
    if not isinstance(adapter, dict) or not isinstance(target, dict) or not isinstance(xvc, dict):
        raise Refusal("target lock adapter/target/xvc identity is incomplete")
    for field in ("usb_path", "ftdi_serial", "vid", "pid", "interface"):
        if not isinstance(adapter.get(field), str) or not adapter[field].strip():
            raise Refusal(f"target lock adapter.{field} is missing")
    for field in ("board_id", "target_part", "idcode", "current_image_sha256", "expected_chain_topology"):
        if not isinstance(target.get(field), str) or not target[field].strip():
            raise Refusal(f"target lock target.{field} is missing")
    _hash_text(target["current_image_sha256"], "target.current_image_sha256")
    if not isinstance(xvc.get("host"), str) or not xvc["host"].strip() or isinstance(xvc.get("port"), bool) or not isinstance(xvc.get("port"), int) or not 1 <= xvc["port"] <= 65535:
        raise Refusal("target lock XVC endpoint is invalid")
    return {
        "path": str(lock_path), "sha256": _sha256(lock_path),
        "adapter": dict(adapter), "target": dict(target), "xvc": dict(xvc),
        "lock_key": hashlib.sha256(json.dumps({"adapter": adapter, "target": target, "xvc": xvc}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }


def validate_bridge_policy(path: str | Path, target_lock: dict[str, Any]) -> dict[str, Any]:
    policy_path = _require_file(str(path), "bridge policy")
    try:
        policy = json.loads(policy_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"bridge policy is unreadable JSON: {exc}") from exc
    if not isinstance(policy, dict) or policy.get("schema") != "PHK2-SQRL-XVC-BRIDGE-POLICY-v1":
        raise Refusal("unsupported bridge policy schema")
    bridge_path = policy.get("BRIDGE_PATH")
    if not isinstance(bridge_path, str) or not Path(bridge_path).is_absolute():
        raise Refusal("BRIDGE_PATH must be the expected absolute deployed path")
    bridge_hash = _hash_text(policy.get("BRIDGE_SHA256"), "BRIDGE_SHA256")
    build_id = _hash_text(policy.get("BUILD_ID"), "BUILD_ID", 40)
    if bridge_hash != PINNED_REVIEWED_BRIDGE_SHA256 or build_id != PINNED_REVIEWED_BUILD_ID:
        raise Refusal("bridge policy does not name the statically reviewed SQRL ELF")
    unit = policy.get("SERVICE_UNIT")
    config_path = policy.get("SERVICE_CONFIG_PATH")
    config_hash = _hash_text(policy.get("SERVICE_CONFIG_HASH"), "SERVICE_CONFIG_HASH")
    if not isinstance(unit, str) or not unit.endswith(".service") or not unit.strip():
        raise Refusal("SERVICE_UNIT is missing or invalid")
    if not isinstance(config_path, str) or not Path(config_path).is_absolute():
        raise Refusal("SERVICE_CONFIG_PATH must be an absolute path")
    config_file = _require_file(config_path, "service config")
    actual_config_hash = _sha256(config_file)
    if actual_config_hash != config_hash:
        raise Refusal("SERVICE_CONFIG_HASH does not match the service config")
    exec_tokens = policy.get("SERVICE_EXEC_TOKENS")
    if not isinstance(exec_tokens, list) or not exec_tokens or any(not isinstance(v, str) or not v for v in exec_tokens):
        raise Refusal("SERVICE_EXEC_TOKENS must bind the expected bridge command")
    config_text = config_file.read_text(errors="replace")
    if any(token not in config_text for token in exec_tokens):
        raise Refusal("service config does not contain the expected bridge command tokens")
    port = policy.get("XVC_PORT")
    serial = policy.get("FTDI_SERIAL")
    if isinstance(port, bool) or not isinstance(port, int) or port != target_lock["xvc"]["port"]:
        raise Refusal("bridge XVC_PORT does not match the target lock")
    if not isinstance(serial, str) or serial != target_lock["adapter"]["ftdi_serial"]:
        raise Refusal("bridge FTDI_SERIAL does not match the target lock")
    argv_tokens = policy.get("ARGV_CONTAINS")
    required = ("-j", str(port), "-s", "," + serial)
    if not isinstance(argv_tokens, list) or any(token not in argv_tokens for token in required):
        raise Refusal("ARGV_CONTAINS must bind XVC port and exact FTDI serial")
    return {
        "policy_path": str(policy_path), "policy_sha256": _sha256(policy_path),
        "BRIDGE_PATH": bridge_path, "BRIDGE_SHA256": bridge_hash, "BUILD_ID": build_id,
        "SERVICE_UNIT": unit, "SERVICE_CONFIG_PATH": str(config_file),
        "SERVICE_CONFIG_HASH": actual_config_hash, "XVC_PORT": port,
        "FTDI_SERIAL": serial, "ARGV_CONTAINS": argv_tokens,
        "target_part": policy.get("TARGET_PART"),
    }


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    argv: tuple[str, ...]
    exe_path: str
    sha256: str
    build_id: str
    cgroup: str


@dataclass(frozen=True)
class SocketRecord:
    state: str
    local: str
    peer: str
    owner_pids: tuple[int, ...]


@dataclass(frozen=True)
class RuntimeSnapshot:
    processes: tuple[ProcessRecord, ...]
    listeners: tuple[SocketRecord, ...]
    established: tuple[SocketRecord, ...]
    complete: bool = True


def _host_port(address: str) -> tuple[str, int] | None:
    match = re.match(r"^(.*):(\d+)$", address)
    if not match:
        return None
    return match.group(1).strip("[]"), int(match.group(2))


def _is_competing(argv: Iterable[str], exe_path: str) -> bool:
    text = (exe_path + " " + " ".join(argv)).lower()
    return any(word in text for word in SERVER_WORDS + CLIENT_WORDS)


def evaluate_runtime(policy: dict[str, Any], target_lock: dict[str, Any], snapshot: RuntimeSnapshot) -> dict[str, Any]:
    if not snapshot.complete:
        raise Refusal("process/socket inspection is incomplete; refusing")
    expected_path = policy["BRIDGE_PATH"]
    expected_pid_records = [p for p in snapshot.processes if p.exe_path.removesuffix(" (deleted)") == expected_path]
    if len(expected_pid_records) != 1:
        raise Refusal("expected SQRL/XVC server process is missing or duplicated")
    server = expected_pid_records[0]
    if _hash_text(server.sha256, "running bridge SHA256") != policy["BRIDGE_SHA256"]:
        raise Refusal("running SQRL/XVC executable differs from statically reviewed binary")
    if _hash_text(server.build_id, "running bridge BUILD_ID", 40) != policy["BUILD_ID"]:
        raise Refusal("running SQRL/XVC BUILD_ID differs from reviewed bridge")
    if not re.search(r"(?:^|/)" + re.escape(policy["SERVICE_UNIT"]) + r"(?:$|/)", server.cgroup):
        raise Refusal("SQRL/XVC process is not owned by the expected service unit")
    if any(token not in server.argv for token in policy["ARGV_CONTAINS"]):
        raise Refusal("running SQRL/XVC command line does not match service/target policy")

    competitors = [p for p in snapshot.processes if p.pid != server.pid and _is_competing(p.argv, p.exe_path)]
    if competitors:
        raise Refusal("unexpected competing SQRL/XVC/JTAG client or server process detected")

    port = policy["XVC_PORT"]
    port_listeners = [s for s in snapshot.listeners if _host_port(s.local) and _host_port(s.local)[1] == port]
    if len(port_listeners) != 1 or port_listeners[0].owner_pids != (server.pid,):
        raise Refusal("XVC listener is absent, duplicated, or owned by another process")
    active = []
    for sock in snapshot.established:
        local, peer = _host_port(sock.local), _host_port(sock.peer)
        if (local and local[1] == port) or (peer and peer[1] == port):
            active.append(sock)
    if active:
        raise Refusal("an existing XVC client connection is active")
    if target_lock["target"]["target_part"] != policy.get("target_part"):
        raise Refusal("bridge policy target part differs from the locked physical target")
    return {
        "ready": True, "server_pid": server.pid,
        "BRIDGE_PATH": server.exe_path, "BRIDGE_SHA256": server.sha256.lower(),
        "BUILD_ID": server.build_id.lower(), "SERVICE_UNIT": policy["SERVICE_UNIT"],
        "SERVICE_CONFIG_HASH": policy["SERVICE_CONFIG_HASH"],
        "listener_owner_pid": server.pid, "existing_client_connections": 0,
        "competing_processes": 0, "usb_enumeration": 0, "xvc_connections": 0,
        "jtag_transactions": 0,
    }


def _parse_ss(text: str) -> tuple[SocketRecord, ...]:
    records: list[SocketRecord] = []
    for line in text.splitlines():
        columns = line.split()
        if len(columns) < 5:
            continue
        owners = tuple(sorted({int(x) for x in re.findall(r"pid=(\d+)", line)}))
        records.append(SocketRecord(columns[0].upper(), columns[3], columns[4], owners))
    return tuple(records)


def _read_build_id(path: Path) -> str:
    if shutil.which("readelf") is None:
        raise Refusal("readelf is required for read-only running ELF identity inspection")
    result = subprocess.run(("readelf", "-n", str(path)), check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    match = re.search(r"Build ID: ([0-9a-fA-F]+)", result.stdout)
    if not match:
        raise Refusal("running executable has no readable ELF Build ID")
    return match.group(1).lower()


def capture_local_runtime() -> RuntimeSnapshot:
    """Inspect process/socket metadata only. Never calls connect(), USB, or XVC."""
    try:
        ps = subprocess.run(("ps", "-eo", "pid=,comm=,args="), check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        listeners = subprocess.run(("ss", "-Hltpn"), check=True, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        established = subprocess.run(("ss", "-Htnp", "state", "established"), check=True, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refusal(f"read-only process/socket snapshot failed: {exc}") from exc
    processes: list[ProcessRecord] = []
    complete = True
    for line in ps.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        pid = int(fields[0])
        comm = fields[1]
        argv = tuple(shlex.split(fields[2] if len(fields) > 2 else comm))
        if not _is_competing(argv, comm):
            continue
        proc = Path("/proc") / str(pid)
        try:
            exe_path = os.readlink(proc / "exe")
            with (proc / "exe").open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            argv_raw = (proc / "cmdline").read_bytes()
            actual_argv = tuple(v.decode(errors="replace") for v in argv_raw.split(b"\0") if v)
            cgroup = (proc / "cgroup").read_text()
            build_id = _read_build_id(proc / "exe")
        except (OSError, subprocess.CalledProcessError, Refusal):
            complete = False
            continue
        processes.append(ProcessRecord(pid, actual_argv or argv, exe_path, digest, build_id, cgroup))
    return RuntimeSnapshot(tuple(processes), _parse_ss(listeners), _parse_ss(established), complete)


class ExclusiveTestLock(AbstractContextManager["ExclusiveTestLock"]):
    """Advisory flock is authoritative; stale PIDs are never treated as owners."""
    def __init__(self, path: str | Path, lock_key: str):
        self.path = Path(path)
        self.lock_key = _hash_text(lock_key, "lock key")
        self.fd: int | None = None
        self.stale_metadata_replaced = False
        self._metadata: dict[str, Any] = {}

    def acquire(self) -> "ExclusiveTestLock":
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            parent = self.path.parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise Refusal(f"cannot inspect lock directory: {exc}") from exc
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            raise Refusal("lock directory must be a private, non-writable-by-others directory owned by this user")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                os.close(fd)
                raise Refusal("lock file must be a singly-linked regular file owned by this user")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refusal("live foreign lock is held; refusing") from exc
        except OSError as exc:
            raise Refusal(f"cannot safely acquire exclusive lock: {exc}") from exc
        self.fd = fd
        try:
            raw = os.read(fd, max(1, info.st_size))
            if raw:
                try:
                    previous = json.loads(raw.decode())
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise Refusal("existing lock metadata is malformed; refusing recovery") from exc
                if not isinstance(previous, dict) or previous.get("schema") != "PHK2-PHYSICAL-TCK-OS-LOCK-v1" or previous.get("state") not in ("held", "released"):
                    raise Refusal("existing lock metadata schema/state is invalid; refusing recovery")
                if previous.get("lock_key") != self.lock_key:
                    raise Refusal("existing lock metadata belongs to another target identity")
                self.stale_metadata_replaced = previous.get("state") == "held"
            self._metadata = {
                "schema": "PHK2-PHYSICAL-TCK-OS-LOCK-v1", "state": "held",
                "lock_key": self.lock_key, "pid": os.getpid(),
                "created_utc": datetime.now(timezone.utc).isoformat(),
                "stale_metadata_replaced": self.stale_metadata_replaced,
            }
            self._write_metadata()
            return self
        except Exception:
            self.release(mark_clean=False)
            raise

    def _write_metadata(self) -> None:
        assert self.fd is not None
        blob = (json.dumps(self._metadata, sort_keys=True) + "\n").encode()
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.ftruncate(self.fd, 0)
        view = memoryview(blob)
        while view:
            written = os.write(self.fd, view)
            view = view[written:]
        os.fsync(self.fd)

    def release(self, *, mark_clean: bool = True) -> None:
        if self.fd is None:
            return
        try:
            if mark_clean:
                self._metadata["state"] = "released"
                self._metadata["released_utc"] = datetime.now(timezone.utc).isoformat()
                self._write_metadata()
        finally:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None

    def __enter__(self) -> "ExclusiveTestLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release(mark_clean=exc_type is None)


def default_lock_path(lock_dir: str | Path, lock_key: str) -> Path:
    return Path(lock_dir) / f"phk2-physical-tck-{_hash_text(lock_key, 'lock key')}.lock"


def run_live_preflight(target_lock_path: str, bridge_policy_path: str,
                       qualification_manifest_path: str, lock_dir: str,
                       *, input_stream=None, output_stream=None) -> dict[str, Any]:
    target = validate_target_lock(target_lock_path)
    policy = validate_bridge_policy(bridge_policy_path, target)
    qualification = validate_qualification_manifest(qualification_manifest_path)
    if qualification["TARGET_PART"] != target["target"]["target_part"]:
        raise Refusal("qualification target part differs from target lock")
    if policy.get("target_part") != target["target"]["target_part"]:
        raise Refusal("bridge policy target part differs from target lock")
    lock = ExclusiveTestLock(default_lock_path(lock_dir, target["lock_key"]), target["lock_key"])
    with lock:
        snapshot = capture_local_runtime()
        runtime = evaluate_runtime(policy, target, snapshot)
        result = {"exclusive_preflight_ready": True,
                  "stale_lock_metadata_replaced": lock.stale_metadata_replaced,
                  "target_lock_sha256": target["sha256"], **runtime,
                  "qualification": qualification,
                  "physical_authorization_required": True,
                  "live_execution_authorized": False}
        out = output_stream or sys.stdout
        print(json.dumps(result, indent=2), file=out, flush=True)
        inp = input_stream or sys.stdin
        print("OS lock held. No transport has been opened. Press Enter to release after the separately authorized test/handoff.", file=out, flush=True)
        inp.readline()
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target-lock", required=True, help="authorized PHK2 physical TCK target lock JSON")
    ap.add_argument("--bridge-policy", required=True, help="expected deployed bridge/service identity JSON")
    ap.add_argument("--qualification-manifest", required=True, help="qualified source/route/timing/promotion package manifest")
    ap.add_argument("--lock-dir", required=True, help="trusted local directory for the persistent flock file")
    args = ap.parse_args(argv)
    try:
        run_live_preflight(args.target_lock, args.bridge_policy, args.qualification_manifest, args.lock_dir)
    except Refusal as exc:
        print(json.dumps({"exclusive_preflight_ready": False, "refusal": str(exc),
                          "live_execution_authorized": False,
                          "usb_enumeration": 0, "xvc_connections": 0, "jtag_transactions": 0}, indent=2), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
