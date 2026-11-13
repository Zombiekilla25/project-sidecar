"""Remote-side durable one-shot process receipts and read-only status checks.

This helper performs filesystem/process bookkeeping only. It has no FTDI or
JTAG imports and cannot launch, signal, or restart an acquisition.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any

import fk0957_remote_cleanup_protocol as protocol

DEFAULT_RECEIPT_ROOT = Path.home() / ".local/state/sidecar/fk0957/operation-receipts"
MAX_RECEIPT_BYTES = 16 * 1024


def _safe_directory(path: Path, *, create: bool) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("receipt directory path rejected")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        for index, part in enumerate(path.parts[1:]):
            final = index == len(path.parts[1:]) - 1
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700 if final else 0o755, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            info = os.fstat(child)
            mode = stat.S_IMODE(info.st_mode)
            allowed_owner = info.st_uid in (0, os.getuid())
            # A root-owned sticky parent such as /tmp is safe for traversal;
            # receipt files themselves are never stored directly there.
            sticky_root = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
            allowed_mode = (mode & 0o022) == 0 or sticky_root
            if final:
                allowed_owner = info.st_uid == os.getuid()
                allowed_mode = mode == 0o700
            if not stat.S_ISDIR(info.st_mode) or not allowed_owner or not allowed_mode:
                os.close(child)
                raise ValueError("receipt parent directory unsafe")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(directory_fd: int, name: str) -> tuple[bytes, tuple[int, int]]:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_size < 1 or before.st_size > MAX_RECEIPT_BYTES):
            raise ValueError("receipt file unsafe")
        chunks = bytearray()
        while len(chunks) <= MAX_RECEIPT_BYTES:
            block = os.read(fd, min(4096, MAX_RECEIPT_BYTES + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        after = os.fstat(fd)
        if (len(chunks) > MAX_RECEIPT_BYTES or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("receipt changed during read")
        return bytes(chunks), (before.st_dev, before.st_ino)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        if count <= 0:
            raise OSError("receipt write made no progress")
        offset += count


class ProcessInspectionFailure(OSError):
    """Process metadata could not be inspected; this is not proof of exit."""


def process_start_identity(pid: int) -> str | None:
    """Return start ticks, None only for ENOENT, and raise for inspection errors."""
    if type(pid) is not int or pid <= 1:
        raise ProcessInspectionFailure("invalid process identifier")
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="ascii") as handle:
            raw = handle.read(8192)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProcessInspectionFailure("process metadata inspection failed") from exc
    except UnicodeError as exc:
        raise ProcessInspectionFailure("process metadata encoding invalid") from exc
    close = raw.rfind(")")
    if close < 0:
        raise ProcessInspectionFailure("process metadata malformed")
    fields = raw[close + 2:].split()  # starts at field 3 (state)
    try:
        value = fields[19]  # field 22, process start time
    except IndexError as exc:
        raise ProcessInspectionFailure("process metadata truncated") from exc
    if (not value.isdecimal() or len(value) > 20 or int(value) <= 0):
        raise ProcessInspectionFailure("process start identity malformed")
    return value


def process_directory_absent(pid: int) -> bool:
    """Confirm a PID is absent; any other procfs result is inconclusive."""
    if type(pid) is not int or pid <= 1:
        raise ProcessInspectionFailure("invalid process identifier")
    try:
        info = os.stat(f"/proc/{pid}", follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise ProcessInspectionFailure("process directory inspection failed") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise ProcessInspectionFailure("process directory identity malformed")
    return False


def process_identity(operation_id: str, *, pid: int | None = None) -> dict[str, Any]:
    if type(operation_id) is not str or not protocol.OP_ID.fullmatch(operation_id):
        raise ValueError("operation ID invalid")
    process_id = os.getpid() if pid is None else pid
    start = process_start_identity(process_id)
    if start is None:
        raise ValueError("process start identity unavailable")
    executable = os.path.realpath(f"/proc/{process_id}/exe")
    executable_bytes = Path(executable).read_bytes()
    argv_raw = Path(f"/proc/{process_id}/cmdline").read_bytes()
    argv = [part.decode("utf-8", "strict") for part in argv_raw.rstrip(b"\0").split(b"\0")]
    if operation_id not in argv:
        raise ValueError("operation ID is absent from process argv")
    cwd = os.path.realpath(f"/proc/{process_id}/cwd")
    return {
        "pid": process_id, "start_identity": start, "uid": os.stat(f"/proc/{process_id}").st_uid,
        "executable": executable, "executable_sha256": hashlib.sha256(executable_bytes).hexdigest(),
        "argv_sha256": hashlib.sha256(argv_raw).hexdigest(), "cwd": cwd,
        "operation_id_argument": operation_id,
    }


def _validate_receipt_payload(payload: Any) -> None:
    """Reject incomplete or contradictory local receipt state before writing."""
    if type(payload) is not dict or set(payload) != protocol.RECEIPT_KEYS:
        raise ValueError("receipt payload fields invalid")
    if (payload.get("schema") != protocol.RECEIPT_SCHEMA or
            type(payload.get("operation_id")) is not str or
            not protocol.OP_ID.fullmatch(payload["operation_id"]) or
            type(payload.get("receipt_id")) is not str or
            not protocol.RECEIPT_ID.fullmatch(payload["receipt_id"]) or
            payload.get("target_selector") != "FK0957" or
            payload.get("usb_descriptor_serial") != "153300000957" or
            payload.get("adapter_serial") != "153300000957A" or
            payload.get("one_shot") is not True or payload.get("state") != "PREPARED" or
            payload.get("process") is not None or payload.get("exit_code") is not None):
        raise ValueError("receipt initial state invalid")
    for key in ("release_authorization_sha256", "expected_executable_sha256",
                "release_manifest_sha256"):
        if type(payload.get(key)) is not str or not protocol.HEX64.fullmatch(payload[key]):
            raise ValueError("receipt digest invalid")
    for key in ("release_authorization_id", "remote_host", "remote_user",
                "expected_executable", "source_commit"):
        if type(payload.get(key)) is not str or not payload[key]:
            raise ValueError("receipt identity invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", payload["source_commit"]):
        raise ValueError("receipt source commit invalid")
    if payload.get("created_utc") != payload.get("updated_utc"):
        raise ValueError("new receipt timestamps disagree")
    if type(payload.get("created_utc")) is not str:
        raise ValueError("receipt timestamp invalid")
    for key in ("operation_id", "release_authorization_id", "release_authorization_sha256",
                "target_selector", "usb_descriptor_serial", "adapter_serial",
                "expected_executable", "expected_executable_sha256", "release_manifest_sha256",
                "source_commit", "release_authorization_expires_utc", "remote_host", "remote_user",
                "receipt_id", "created_utc", "updated_utc", "state"):
        if type(payload.get(key)) is not str:
            raise ValueError("receipt field type invalid")


class ReceiptStore:
    """Atomic receipt storage under a private per-operation directory."""
    def __init__(self, root: Path = DEFAULT_RECEIPT_ROOT):
        self.root = root

    def _operation_dir(self, operation_id: str, *, create: bool = False) -> int:
        if type(operation_id) is not str or not protocol.OP_ID.fullmatch(operation_id):
            raise ValueError("operation ID invalid")
        root_fd = _safe_directory(self.root, create=create)
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
            if create:
                try:
                    os.mkdir(operation_id, 0o700, dir_fd=root_fd)
                except FileExistsError:
                    pass
            op_fd = os.open(operation_id, flags, dir_fd=root_fd)
            info = os.fstat(op_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o700):
                os.close(op_fd)
                raise ValueError("operation receipt directory unsafe")
            return op_fd
        finally:
            os.close(root_fd)

    def create(self, payload: dict[str, Any]) -> None:
        _validate_receipt_payload(payload)
        operation_id = payload.get("operation_id")
        op_fd = self._operation_dir(operation_id, create=True)
        try:
            fd = os.open("receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=op_fd)
            try:
                _write_all(fd, protocol.canonical(payload))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(op_fd)
        finally:
            os.close(op_fd)

    def read(self, operation_id: str) -> tuple[dict[str, Any], tuple[int, int]]:
        op_fd = self._operation_dir(operation_id)
        try:
            raw, identity = _read_at(op_fd, "receipt.json")
        finally:
            os.close(op_fd)
        value = protocol._parse_canonical(raw, MAX_RECEIPT_BYTES)
        if value.get("operation_id") != operation_id:
            raise ValueError("receipt operation mismatch")
        return value, identity

    def transition(self, operation_id: str, state: str, *, process: dict[str, Any] | None,
                   exit_code: int | None) -> dict[str, Any]:
        op_fd = self._operation_dir(operation_id)
        try:
            lock_fd = os.open(".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                              0o600, dir_fd=op_fd)
            try:
                lock_info = os.fstat(lock_fd)
                if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid() or
                        lock_info.st_nlink != 1 or stat.S_IMODE(lock_info.st_mode) != 0o600):
                    raise ValueError("receipt lock file unsafe")
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                raw, _ = _read_at(op_fd, "receipt.json")
                row = protocol._parse_canonical(raw, MAX_RECEIPT_BYTES)
                if not protocol.receipt_transition_allowed(row["state"], state):
                    raise ValueError("receipt transition refused")
                if state == "RUNNING" and process is None:
                    raise ValueError("RUNNING receipt requires process identity")
                if state == "RUNNING" and (type(process) is not dict or
                        set(process) != protocol.PROCESS_KEYS or
                        process.get("operation_id_argument") != operation_id or
                        process_start_identity(process.get("pid", -1)) != process.get("start_identity")):
                    raise ValueError("RUNNING process identity is not current")
                if state.startswith("EXITED_") and (process is None or type(exit_code) is not int):
                    raise ValueError("terminal receipt requires process and exit code")
                row["state"] = state
                row["process"] = process
                row["exit_code"] = exit_code
                row["updated_utc"] = datetime.now(timezone.utc).isoformat()
                data = protocol.canonical(row)
                if len(data) > MAX_RECEIPT_BYTES:
                    raise ValueError("receipt exceeds size bound")
                prior_raw, prior_identity = _read_at(op_fd, "receipt.json")
                if prior_raw != raw:
                    raise ValueError("receipt changed before replacement")
                temp_name = ".receipt-" + secrets.token_hex(16)
                try:
                    fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=op_fd)
                    try:
                        _write_all(fd, data)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    check_raw, check_identity = _read_at(op_fd, "receipt.json")
                    if check_raw != raw or check_identity != prior_identity:
                        raise ValueError("receipt identity changed before replacement")
                    os.replace(temp_name, "receipt.json", src_dir_fd=op_fd, dst_dir_fd=op_fd)
                finally:
                    try:
                        os.unlink(temp_name, dir_fd=op_fd)
                    except FileNotFoundError:
                        pass
                os.fsync(op_fd)
                return row
            finally:
                os.close(lock_fd)
        finally:
            os.close(op_fd)

    def status(self, *, operation_id: str, query_nonce: str,
               launch_closed: bool = False) -> dict[str, Any]:
        if (type(query_nonce) is not str or not protocol.HEX64.fullmatch(query_nonce) or
                type(launch_closed) is not bool):
            raise ValueError("status challenge invalid")
        row, _identity = self.read(operation_id)
        claimed = row["state"]
        process = row["process"]
        observed_state = protocol.UNKNOWN
        if claimed == "PREPARED" and launch_closed:
            observed_state = protocol.NOT_STARTED
        elif claimed == "RUNNING" and type(process) is dict:
            try:
                actual_start = process_start_identity(process.get("pid", -1))
            except ProcessInspectionFailure:
                observed_state = protocol.STATUS_INSPECTION_FAILED
            else:
                if actual_start is None:
                    # Confirm the PID directory itself is absent. A missing or
                    # unreadable stat entry under a live /proc/<pid> is an
                    # inspection failure, never evidence of process exit.
                    try:
                        absent = process_directory_absent(process.get("pid", -1))
                    except ProcessInspectionFailure:
                        observed_state = protocol.STATUS_INSPECTION_FAILED
                    else:
                        observed_state = protocol.UNKNOWN if absent else protocol.STATUS_INSPECTION_FAILED
                elif actual_start != process.get("start_identity"):
                    observed_state = protocol.IDENTITY_MISMATCH
                else:
                    observed_state = protocol.RUNNING_EXPECTED_PROCESS
        elif claimed in {"EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE"}:
            try:
                actual_start = process_start_identity(process.get("pid", -1)) if type(process) is dict else -1
            except ProcessInspectionFailure:
                observed_state = protocol.STATUS_INSPECTION_FAILED
            else:
                if actual_start is None:
                    try:
                        absent = process_directory_absent(process.get("pid", -1))
                    except ProcessInspectionFailure:
                        observed_state = protocol.STATUS_INSPECTION_FAILED
                    else:
                        if absent and launch_closed:
                            observed_state = {
                                "EXITED_SUCCESS": protocol.EXITED_SUCCESS,
                                "EXITED_REFUSAL": protocol.EXITED_REFUSAL,
                                "EXITED_FAILURE": protocol.EXITED_FAILURE,
                            }[claimed]
                        else:
                            observed_state = protocol.UNKNOWN if absent else protocol.STATUS_INSPECTION_FAILED
                elif actual_start == process.get("start_identity"):
                    observed_state = protocol.RUNNING_EXPECTED_PROCESS
                else:
                    observed_state = protocol.IDENTITY_MISMATCH
        result = {
            "schema": protocol.STATUS_SCHEMA, "operation_id": operation_id,
            "query_nonce": query_nonce,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "release_authorization_id": row["release_authorization_id"],
            "release_authorization_sha256": row["release_authorization_sha256"],
            "target_selector": row["target_selector"],
            "release_manifest_sha256": row["release_manifest_sha256"],
            "remote_host": row["remote_host"], "remote_user": row["remote_user"],
            "launch_closed": launch_closed, "status": observed_state,
            "receipt_sha256": hashlib.sha256(protocol.canonical(row)).hexdigest(),
            "receipt": row, "process_identity": process,
        }
        return result
