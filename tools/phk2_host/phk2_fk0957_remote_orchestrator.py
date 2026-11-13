#!/usr/bin/env python3
"""Local-only validation and Ed25519 signing for remote unsigned FK0957 evidence."""
from __future__ import annotations

import argparse
import base64
import stat
from datetime import datetime, timezone, timedelta
import hmac
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import types
from typing import Callable

import phk2_fk0957_identity_observer as observer

_AUTHORIZED_SSH_DESTINATION = "rmann@192.168.1.173"
_AUTHORIZED_SSH_IP = "192.168.1.173"
# Public aliases retained for audit/tests; execution uses the authorized constants above.
SSH_DESTINATION = _AUTHORIZED_SSH_DESTINATION
SSH_IP = _AUTHORIZED_SSH_IP
SSH_BINARY = "/usr/bin/ssh"
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
COLLECTOR = HERE / "phk2_fk0957_remote_collector.py"
BACKEND = HERE / "phk2_fk0957_readonly_backend.py"
EXPECTED_FIELDS = {
    "schema", "version", "target_selector", "collector_source_sha256", "backend_source_sha256",
    "session_nonce",
    "source_commit", "remote_hostname", "acquisition_timestamp", "ftdi_vid", "ftdi_pid",
    "manufacturer", "product", "interface", "usb_path", "adapter_serial",
    "usb_descriptor_serial", "fk0957_mapping",
    "WRITE_COUNT", "RESET_COUNT", "PROGRAM_COUNT", "JTAG_OPERATIONS",
}
ZERO_FIELDS = ("WRITE_COUNT", "RESET_COUNT", "PROGRAM_COUNT", "JTAG_OPERATIONS")
SOURCE_COMMIT_PIN = "e2feedcfde44563854a3cf41fe4526c231ed385b"
OBSERVER_PIN = "49651502745163b2d69d2641b319f7d88b602a60ba4d91ee042afe81e354fd7e"
BUNDLE_BUILDER_PIN = "a60d4bb57fea4e9441bf9a89476e286da16e12d4b9bd9cf7c7df8178a41c3438"
BUNDLE_RUNNER_PIN = "8e3aaf2422199072551c9be495c0335df61e3d7abaf1c4fc9f6cfd015a351813"


def _load_pinned_bundle_builder():
    path = HERE / "phk2_fk0957_ephemeral_bundle.py"
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != BUNDLE_BUILDER_PIN:
        raise RuntimeError("ephemeral bundle builder source pin mismatch")
    name = "_fk0957_reviewed_ephemeral_bundle"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


_bundle_builder = _load_pinned_bundle_builder()
deterministic_bundle = _bundle_builder.deterministic_bundle
inspect_bundle = _bundle_builder.inspect_bundle
ephemeral_remote_command = _bundle_builder.remote_command


class Refusal(RuntimeError):
    pass


_REMOTE_DIAG_PREFIX = "FK0957_DIAG "
COLLECTOR_REFUSAL_CODES = frozenset({
    "NO_MATCHING_TARGET", "MULTIPLE_MATCHING_TARGETS", "INCOMPLETE_DESCRIPTOR_METADATA",
    "EXPECTED_SERIAL_NOT_FOUND", "UNEXPECTED_PEER_DEVICE", "BACKEND_PIN_MISMATCH",
    "TARGET_MAPPING_MISSING", "TARGET_MAPPING_AMBIGUOUS", "SOURCE_PROVENANCE_MISMATCH",
    "DESCRIPTOR_READ_FAILED", "INTERNAL_REFUSAL",
})
_REMOTE_DIAG_KEYS = {
    "REMOTE_RUNNER_STARTED", "BUNDLE_RECEIVED", "BUNDLE_HASH_VERIFIED",
    "MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED",
    "COLLECTOR_STARTED", "COLLECTOR_RETURNED", "STDOUT_RECORD_RECEIVED",
    "COLLECTOR_REFUSAL_CODE", "REMOTE_PHASE", "SSH_ERROR_CLASS",
}
_REMOTE_PHASES = {
    "REMOTE_RUNNER_STARTED", "BUNDLE_RECEIVED", "BUNDLE_HASH_VERIFIED", "MANIFEST_VERIFIED",
    "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED", "COLLECTOR_STARTED",
    "COLLECTOR_RETURNED", "STDOUT_RECORD_RECEIVED", "RUNNER_FAILED", "SSH_TRANSPORT",
    "REMOTE_PYTHON_STARTUP",
}
_REMOTE_ERROR_CLASSES = {
    "HOST_KEY_REJECTED", "SSH_AUTH_FAILED", "REMOTE_PYTHON_FAILED", "BUNDLE_FRAMING_FAILED",
    "BUNDLE_HASH_FAILED", "RUNNER_FAILED", "COLLECTOR_REFUSED", "JSON_PARSE_FAILED",
    "UNEXPECTED_REMOTE_EXIT",
}
_REMOTE_PROGRESS = (
    "REMOTE_RUNNER_STARTED", "BUNDLE_RECEIVED", "BUNDLE_HASH_VERIFIED",
    "MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED",
    "COLLECTOR_STARTED", "COLLECTOR_RETURNED", "STDOUT_RECORD_RECEIVED",
)


def _parse_remote_diagnostics(stderr) -> tuple[dict[str, str], bool]:
    """Accept only bounded ordered diagnostic records; raw stderr is never returned."""
    if not stderr:
        return {}, True
    if isinstance(stderr, str):
        raw = stderr.encode("utf-8", "replace")
    elif isinstance(stderr, bytes):
        raw = stderr
    else:
        return {}, False
    if len(raw) > 4096:
        return {}, False
    records = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return {}, False
    for line in lines:
        if not line.startswith(_REMOTE_DIAG_PREFIX):
            return {}, False
        item = line[len(_REMOTE_DIAG_PREFIX):]
        key, sep, value = item.partition("=")
        if not sep or key not in _REMOTE_DIAG_KEYS or key in records:
            return {}, False
        if key == "COLLECTOR_REFUSAL_CODE":
            allowed = value in COLLECTOR_REFUSAL_CODES
        elif key == "REMOTE_PHASE":
            allowed = value in _REMOTE_PHASES
        elif key == "SSH_ERROR_CLASS":
            allowed = value in _REMOTE_ERROR_CLASSES
        else:
            allowed = value == "YES"
        if not allowed:
            return {}, False
        records[key] = value
    progress = [key for key in _REMOTE_PROGRESS if records.get(key) == "YES"]
    if any(records.get(key) != "YES" for key in records if key in _REMOTE_PROGRESS):
        return {}, False
    if progress != list(_REMOTE_PROGRESS[:len(progress)]):
        return {}, False
    progress_in_stream = [key for key in records if key in _REMOTE_PROGRESS]
    if progress_in_stream != progress:
        return {}, False
    refusal_code = records.get("COLLECTOR_REFUSAL_CODE")
    terminal = [key for key in records if key in ("REMOTE_PHASE", "SSH_ERROR_CLASS")]
    if terminal:
        expected = list(progress)
        if refusal_code is not None:
            expected.append("COLLECTOR_REFUSAL_CODE")
        expected.extend(("REMOTE_PHASE", "SSH_ERROR_CLASS"))
        if list(records) != expected or terminal != ["REMOTE_PHASE", "SSH_ERROR_CLASS"]:
            return {}, False
        phase = records["REMOTE_PHASE"]
        last_progress = progress[-1] if progress else None
        if phase == "RUNNER_FAILED":
            if last_progress not in _REMOTE_PROGRESS[5:]:
                return {}, False
        elif phase in ("SSH_TRANSPORT", "REMOTE_PYTHON_STARTUP"):
            if progress:
                return {}, False
        elif phase != last_progress:
            return {}, False
        is_collector_refusal = records["SSH_ERROR_CLASS"] == "COLLECTOR_REFUSED"
        if (is_collector_refusal != (refusal_code is not None) or
                (refusal_code is not None and
                 (phase != "COLLECTOR_RETURNED" or last_progress != "COLLECTOR_RETURNED"))):
            return {}, False
    elif refusal_code is not None or list(records) != progress:
        return {}, False
    return records, True


def _parse_collector_failure_envelope(stdout, *, returncode: int) -> dict | None:
    """Strictly validate a refusal envelope only on a nonzero process exit."""
    if returncode == 0 or not isinstance(stdout, bytes) or not stdout or len(stdout) > 4096:
        return None
    if not stdout.endswith(b"\n") or stdout.count(b"\n") != 1:
        return None
    try:
        value = json.loads(stdout.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (UnicodeError, ValueError):
        return None
    fields = {"status", "phase", "refusal_code", "cards_opened", "second_card_opened",
              "write_count", "reset_count", "program_count", "jtag_operations"}
    if not isinstance(value, dict) or set(value) != fields or canonical(value) + b"\n" != stdout:
        return None
    if (value["status"] != "REFUSED" or value["phase"] != "COLLECTOR" or
            not isinstance(value["refusal_code"], str) or
            value["refusal_code"] not in COLLECTOR_REFUSAL_CODES or
            type(value["cards_opened"]) is not int or value["cards_opened"] != 0 or
            type(value["second_card_opened"]) is not bool or value["second_card_opened"] is not False or
            any(type(value[key]) is not int or value[key] != 0
                for key in ("write_count", "reset_count", "program_count", "jtag_operations"))):
        return None
    return value


def _classify_ssh_error(stderr) -> str:
    raw = stderr if isinstance(stderr, bytes) else str(stderr or "").encode("utf-8", "replace")
    lowered = raw[:4096].lower()
    if b"host key verification failed" in lowered or b"remote host identification has changed" in lowered:
        return "HOST_KEY_REJECTED"
    if b"permission denied" in lowered or b"too many authentication failures" in lowered:
        return "SSH_AUTH_FAILED"
    return "UNEXPECTED_REMOTE_EXIT"


def _remote_failure_message(returncode, stderr, stdout=b"") -> str:
    records, clean = _parse_remote_diagnostics(stderr)
    error_class = records.get("SSH_ERROR_CLASS") or _classify_ssh_error(stderr)
    if not clean:
        records = {}
        error_class = _classify_ssh_error(stderr)
    failure = _parse_collector_failure_envelope(stdout, returncode=returncode)
    if stdout:
        if (failure is None or not clean or
                records.get("SSH_ERROR_CLASS") != "COLLECTOR_REFUSED" or
                records.get("REMOTE_PHASE") != "COLLECTOR_RETURNED" or
                records.get("COLLECTOR_REFUSAL_CODE") != failure["refusal_code"]):
            records = {}
            failure = None
            error_class = "UNEXPECTED_REMOTE_EXIT"
    elif records.get("COLLECTOR_REFUSAL_CODE") is not None:
        records = {}
        error_class = "UNEXPECTED_REMOTE_EXIT"
    phase = records.get("REMOTE_PHASE")
    if phase is None:
        phase = next((name for name in (
            "STDOUT_RECORD_RECEIVED", "COLLECTOR_RETURNED", "COLLECTOR_STARTED",
            "BACKEND_SOURCE_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "MANIFEST_VERIFIED",
            "BUNDLE_HASH_VERIFIED", "BUNDLE_RECEIVED", "REMOTE_RUNNER_STARTED")
            if records.get(name) == "YES"),
            "SSH_TRANSPORT" if returncode == 255 else "REMOTE_PYTHON_STARTUP")
    summary = [f"SSH_RETURN_CODE={returncode}", f"SSH_ERROR_CLASS={error_class}",
               f"REMOTE_PHASE={phase}"]
    if failure is not None:
        summary.append("COLLECTOR_REFUSAL_CODE=" + failure["refusal_code"])
    for key in ("REMOTE_RUNNER_STARTED", "BUNDLE_RECEIVED", "BUNDLE_HASH_VERIFIED",
                "MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED",
                "COLLECTOR_STARTED", "COLLECTOR_RETURNED", "STDOUT_RECORD_RECEIVED"):
        if key in records:
            summary.append(f"{key}={records[key]}")
    return "remote unsigned acquisition failed (" + " ".join(summary) + ")"

def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _open_path_parent(path: Path) -> tuple[int, str]:
    """Walk a path's parent without following any symlink component."""
    path = Path(path)
    if not path.name or path.name in (".", "..") or ".." in path.parts:
        raise Refusal("path must not contain parent-directory traversal")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow_flags = directory_flags | getattr(os, "O_NOFOLLOW", 0)
    absolute = path.is_absolute()
    fd = os.open("/" if absolute else ".", directory_flags)
    try:
        for part in path.parent.parts:
            if part in ("", "/", "."):
                continue
            next_fd = os.open(part, nofollow_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _validated_local_ssh_auth_sock() -> tuple[str, tuple[int, int]]:
    """Validate the RGB-local agent endpoint; it is never forwarded remotely."""
    raw = os.environ.get("SSH_AUTH_SOCK")
    if not isinstance(raw, str) or not raw or len(raw) > 107 or "\x00" in raw:
        raise Refusal("local SSH agent socket is unavailable or malformed")
    path = Path(raw)
    if not path.is_absolute() or ".." in path.parts:
        raise Refusal("local SSH agent socket path is unsafe")
    parent_fd, name = _open_path_parent(path)
    try:
        parent = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent.st_mode) or
                (parent.st_uid == os.geteuid() and parent.st_mode & 0o022) or
                (parent.st_uid != os.geteuid() and
                 not (parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX))):
            raise Refusal("local SSH agent socket parent is not protected")
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_mode & 0o077):
            raise Refusal("local SSH_AUTH_SOCK is not an owner-only Unix socket")
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino)
        if identity != (after.st_dev, after.st_ino):
            raise Refusal("local SSH_AUTH_SOCK changed during validation")
        return str(path), identity
    except OSError as exc:
        raise Refusal("local SSH_AUTH_SOCK cannot be validated") from exc
    finally:
        os.close(parent_fd)


def _revalidate_local_ssh_auth_sock(path: str, identity: tuple[int, int]) -> None:
    if os.environ.get("SSH_AUTH_SOCK") != path:
        raise Refusal("local SSH_AUTH_SOCK changed before SSH invocation")
    current_path, current_identity = _validated_local_ssh_auth_sock()
    if current_path != path or current_identity != identity:
        raise Refusal("local SSH_AUTH_SOCK identity changed before SSH invocation")


def _read_signing_key(path: Path) -> bytes:
    """Read a private key only from a regular, single-link, non-symlink file."""
    parent_fd, name = _open_path_parent(path)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Refusal("signing key must be a regular file with one link")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def write_evidence_atomic(path: Path, data: bytes) -> None:
    """Replace the named output atomically without following its final symlink."""
    path = Path(path)
    dir_fd, output_name = _open_path_parent(path)
    temp_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    temp_created = False
    try:
        try:
            existing = os.stat(output_name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and stat.S_ISLNK(existing.st_mode):
            raise Refusal("evidence output must not be a symlink")
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise Refusal("evidence output must be a regular file")
        initial_identity = None if existing is None else (existing.st_dev, existing.st_ino)
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o600, dir_fd=dir_fd)
        temp_created = True
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            raise
        check_dir_fd, _ = _open_path_parent(path)
        try:
            original_dir, current_dir = os.fstat(dir_fd), os.fstat(check_dir_fd)
            if (original_dir.st_dev, original_dir.st_ino) != (current_dir.st_dev, current_dir.st_ino):
                raise Refusal("evidence output parent changed during write")
        finally:
            os.close(check_dir_fd)
        try:
            current = os.stat(output_name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None and stat.S_ISLNK(current.st_mode):
            raise Refusal("evidence output became a symlink during write")
        current_identity = None if current is None else (current.st_dev, current.st_ino)
        if current_identity != initial_identity:
            raise Refusal("evidence output changed during write")
        os.replace(temp_name, output_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp_created = False
    finally:
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)


def validate_unsigned(raw: bytes, *, collector_hash: str, backend_hash: str,
                      expected_hostname: str, session_nonce: str, now: datetime | None = None) -> dict:
    if not isinstance(raw, bytes) or len(raw) > 16384:
        raise Refusal("remote evidence is oversized or not bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite number")))
    except (UnicodeError, ValueError) as exc:
        raise Refusal("remote evidence is malformed JSON") from exc
    if not isinstance(value, dict) or set(value) != EXPECTED_FIELDS:
        raise Refusal("remote evidence fields are incomplete or unapproved")
    if canonical(value) + b"\n" != raw:
        raise Refusal("remote evidence is not canonical JSON")
    if type(value["version"]) is not int or any(type(value[name]) is not int for name in ZERO_FIELDS):
        raise Refusal("numeric fields must use canonical integer types")
    fixed = {"schema": "fk0957-unsigned-descriptor-evidence", "version": 1,
             "target_selector": "FK0957", "collector_source_sha256": collector_hash,
             "session_nonce": session_nonce,
             "backend_source_sha256": backend_hash, "ftdi_vid": "0403", "ftdi_pid": "6010",
             "manufacturer": "Xilinx", "product": "SQRL FK", "interface": "A",
             "adapter_serial": "153300000957A", "usb_descriptor_serial": "153300000957",
             "fk0957_mapping": "153300000957",
             **{name: 0 for name in ZERO_FIELDS}}
    if any(value.get(k) != v for k, v in fixed.items()):
        raise Refusal("target identity, source pin, or zero-operation counter mismatch")
    if not isinstance(expected_hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", expected_hostname):
        raise Refusal("hostname is malformed")
    if value["remote_hostname"] != expected_hostname:
        raise Refusal("collector self-reported hostname differs from expected informational hostname")
    if not isinstance(value["usb_path"], str) or not re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", value["usb_path"]):
        raise Refusal("USB path is missing or malformed")
    if value["source_commit"] != SOURCE_COMMIT_PIN:
        raise Refusal("source commit differs from reviewed provenance pin")
    if not isinstance(value["session_nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["session_nonce"]):
        raise Refusal("session nonce is malformed")
    try:
        stamp = datetime.fromisoformat(value["acquisition_timestamp"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise Refusal("acquisition timestamp is malformed") from exc
    reference = now or datetime.now(timezone.utc)
    if stamp.tzinfo is None or stamp > reference + timedelta(minutes=2) or reference - stamp > timedelta(minutes=10):
        raise Refusal("acquisition evidence is stale or future dated")
    if stamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z") != value["acquisition_timestamp"]:
        raise Refusal("timestamp is not canonical UTC")
    return value


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_pinned_known_hosts(path: Path) -> tuple[int, bytes, dict]:
    """Read and validate the private temporary known_hosts file."""
    path = Path(path)
    parent_fd, name = _open_path_parent(path)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600):
            raise Refusal("pinned known_hosts must be owner-only, singly linked, and owned by this user")
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or
                    (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino) or
                    opened.st_uid != os.getuid() or opened.st_nlink != 1 or
                    stat.S_IMODE(opened.st_mode) != 0o600):
                raise Refusal("pinned known_hosts changed during validation")
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1024 * 1024:
                    raise Refusal("pinned known_hosts is oversized")
                chunks.append(chunk)
            material = b"".join(chunks)
            identity = _parse_pinned_host_key(material)
            os.lseek(fd, 0, os.SEEK_SET)
            return fd, material, identity
        except Exception:
            os.close(fd)
            raise
    except OSError as exc:
        raise Refusal("pinned known_hosts cannot be opened safely") from exc
    finally:
        os.close(parent_fd)


def _read_pinned_source(path: Path) -> tuple[bytes, dict, tuple[int, int]]:
    """Read the designated pin without following any path component."""
    path = Path(path)
    parent_fd, name = _open_path_parent(path)
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.getuid() or before.st_mode & 0o177 or
                not before.st_mode & 0o400):
            raise Refusal("pinned source known_hosts must be owner-only, regular, and singly linked")
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            inode = (opened.st_dev, opened.st_ino)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                    opened.st_uid != os.getuid() or opened.st_mode & 0o177 or
                    not opened.st_mode & 0o400 or inode != (before.st_dev, before.st_ino) or
                    inode != (after.st_dev, after.st_ino)):
                raise Refusal("pinned source known_hosts changed during validation")
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1024 * 1024:
                    raise Refusal("pinned known_hosts is oversized")
                chunks.append(chunk)
            material = b"".join(chunks)
            return material, _parse_pinned_host_key(material), inode
        finally:
            os.close(fd)
    except OSError as exc:
        raise Refusal("pinned source known_hosts cannot be opened safely") from exc
    finally:
        os.close(parent_fd)


def _open_private_pin_dir(path: Path) -> tuple[int, tuple[int, int]]:
    path = Path(path)
    if not path.is_absolute() or path.parent != Path("/tmp") or not path.name.startswith("fk0957-known-hosts-"):
        raise Refusal("temporary known_hosts directory path is unsafe")
    parent = Path("/tmp").lstat()
    if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode) or
            parent.st_uid not in (0, os.getuid()) or not parent.st_mode & stat.S_ISVTX):
        raise Refusal("temporary known_hosts parent is not a protected sticky directory")
    before = path.lstat()
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or
            before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o700):
        raise Refusal("temporary known_hosts directory is not private and owner-controlled")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    opened = os.fstat(fd)
    inode = (opened.st_dev, opened.st_ino)
    if (inode != (before.st_dev, before.st_ino) or opened.st_uid != os.getuid() or
            stat.S_IMODE(opened.st_mode) != 0o700):
        os.close(fd)
        raise Refusal("temporary known_hosts directory changed during validation")
    return fd, inode


def _write_private_pin(dir_fd: int, material: bytes) -> tuple[int, int]:
    fd = os.open("known_hosts", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                 0o600, dir_fd=dir_fd)
    try:
        offset = 0
        while offset < len(material):
            offset += os.write(fd, material[offset:])
        os.fsync(fd)
        info = os.fstat(fd)
        path_info = os.stat("known_hosts", dir_fd=dir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or
                (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise Refusal("temporary known_hosts copy is not private and singly linked")
        os.fsync(dir_fd)
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def _validate_private_pin(path: Path, material: bytes, host_identity: dict,
                          dir_identity: tuple[int, int], file_identity: tuple[int, int]) -> None:
    dir_fd, current_dir_identity = _open_private_pin_dir(Path(path).parent)
    try:
        if current_dir_identity != dir_identity:
            raise Refusal("temporary known_hosts directory changed")
        pin_fd, current, identity = _read_pinned_known_hosts(path)
        try:
            info = os.fstat(pin_fd)
            if (current != material or identity != host_identity or
                    (info.st_dev, info.st_ino) != file_identity):
                raise Refusal("temporary known_hosts copy changed before SSH")
        finally:
            os.close(pin_fd)
    finally:
        os.close(dir_fd)


def _ssh_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ValueError("truncated SSH key blob")
    length = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4
    if length > len(data) - offset:
        raise ValueError("truncated SSH key field")
    return data[offset:offset + length], offset + length


def _parse_pinned_host_key(material: bytes) -> dict:
    matches = []
    try:
        text = material.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Refusal("pinned known_hosts is not ASCII") from exc
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        marker = ""
        if fields[0].startswith("@"):
            marker, fields = fields[0], fields[1:]
            if marker not in ("@revoked", "@cert-authority"):
                raise Refusal(f"malformed known_hosts marker on line {line_no}")
        if len(fields) < 3:
            raise Refusal(f"malformed known_hosts line {line_no}")
        hosts, algorithm, encoded = fields[:3]
        if not re.fullmatch(r"[A-Za-z0-9@._+:-]+", algorithm):
            raise Refusal(f"malformed host-key algorithm on line {line_no}")
        try:
            blob = base64.b64decode(encoded, validate=True)
            key_type, offset = _ssh_string(blob, 0)
        except (ValueError, base64.binascii.Error) as exc:
            raise Refusal(f"malformed host-key material on line {line_no}") from exc
        try:
            decoded_type = key_type.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise Refusal(f"malformed host-key type on line {line_no}") from exc
        if decoded_type != algorithm or offset >= len(blob):
            raise Refusal(f"host-key algorithm/blob mismatch on line {line_no}")
        if marker:
            continue
        for host in hosts.split(","):
            applies = False
            if host.startswith("|1|"):
                pieces = host.split("|")
                if len(pieces) != 4 or not pieces[2] or not pieces[3]:
                    raise Refusal(f"malformed hashed host entry on line {line_no}")
                try:
                    salt, digest = base64.b64decode(pieces[2], validate=True), base64.b64decode(pieces[3], validate=True)
                except base64.binascii.Error as exc:
                    raise Refusal(f"malformed hashed host entry on line {line_no}") from exc
                applies = hmac.compare_digest(hmac.new(salt, _AUTHORIZED_SSH_IP.encode("ascii"), hashlib.sha1).digest(), digest)
            elif any(c in host for c in "*!?"):
                # Wildcards and negations make the approved identity set ambiguous.
                if SSH_IP in host:
                    raise Refusal("ambiguous wildcard/negated host entry for authorized SSH IP")
            else:
                applies = host == _AUTHORIZED_SSH_IP
            if applies:
                matches.append({"algorithm": algorithm,
                                "fingerprint": "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")})
    if len(matches) != 1:
        raise Refusal("pinned known_hosts must contain exactly one applicable approved host key")
    return matches[0]


def acquire_and_sign(key_path: Path, *, known_hosts_path: Path, runner: Callable = subprocess.run,
                     expected_hostname: str, remote_repo: str | None = None,
                     ephemeral: bool = False) -> dict:
    if not isinstance(expected_hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", expected_hostname):
        raise Refusal("expected informational hostname is malformed")
    collector_bytes = COLLECTOR.read_bytes()
    collector_hash = sha(collector_bytes)
    backend_bytes = BACKEND.read_bytes()
    backend_hash = sha(backend_bytes)
    if sha(observer.OBSERVER_PATH.read_bytes()) != OBSERVER_PIN:
        raise Refusal("local observer source pin mismatch")
    # The existing observer allowlist is the reviewed local backend source pin.
    spec = "phk2_fk0957_readonly_backend:create_backend"
    if observer.REVIEWED_BACKENDS.get(spec) != backend_hash:
        raise Refusal("local backend source pin mismatch")
    if collector_hash != COLLECTOR_PIN:
        raise Refusal("collector source pin mismatch")
    nonce = secrets.token_hex(32)
    bundle_hash = None
    execution_source_commit = None
    if ephemeral:
        if remote_repo is not None:
            raise Refusal("choose one acquisition mode")
        try:
            execution_source_commit = subprocess.run(
                ["git", "-C", str(REPO), "rev-parse", "HEAD"], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                     "GIT_CONFIG_SYSTEM": "/dev/null"}).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise Refusal("local execution source commit unavailable") from exc
        runner_bytes = (HERE / "phk2_fk0957_ephemeral_runner.py").read_bytes()
        if sha(runner_bytes) != BUNDLE_RUNNER_PIN:
            raise Refusal("ephemeral remote runner source pin mismatch")
        try:
            bundle, bundle_metadata = deterministic_bundle(
                source_commit=execution_source_commit, session_nonce=nonce, source_root=REPO,
                collector_pin=collector_hash, backend_pin=backend_hash, observer_pin=OBSERVER_PIN,
                runner_bytes=runner_bytes)
            bundle_hash = bundle_metadata["bundle_sha256"]
            inspect_bundle(bundle, expected_bundle_sha256=bundle_hash,
                           expected_source_commit=execution_source_commit,
                           expected_collector_sha256=collector_hash,
                           expected_backend_sha256=backend_hash, expected_nonce=nonce)
        except Exception as exc:
            raise Refusal("ephemeral execution bundle failed local validation") from exc
        stdin_data = bundle
        remote_command = ephemeral_remote_command(
            bundle_sha256=bundle_hash, source_commit=execution_source_commit,
            collector_sha256=collector_hash, backend_sha256=backend_hash, session_nonce=nonce)
        execution_mode = "EPHEMERAL_REVIEWED_BUNDLE"
    else:
        if not isinstance(remote_repo, str) or not remote_repo or "\x00" in remote_repo:
            raise Refusal("remote repository path is required unless ephemeral mode is selected")
        stdin_data = collector_bytes
        remote_command = (f"cd -- {shlex.quote(remote_repo)} && "
                          f"FK0957_TARGET=FK0957 python3 - {collector_hash} {nonce}")
        execution_mode = "REMOTE_CHECKOUT"
    known_hosts_bytes, host_identity, source_identity = _read_pinned_source(known_hosts_path)
    pinned_hash = sha(known_hosts_bytes)
    agent_path, agent_identity = _validated_local_ssh_auth_sock()
    safe_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                "LC_ALL": "C", "LANG": "C", "SSH_AUTH_SOCK": agent_path}
    with tempfile.TemporaryDirectory(prefix="fk0957-known-hosts-", dir="/tmp") as pin_dir_name:
        pin_dir = Path(pin_dir_name)
        pin_dir_fd, pin_dir_identity = _open_private_pin_dir(pin_dir)
        try:
            pin_file_identity = _write_private_pin(pin_dir_fd, known_hosts_bytes)
        finally:
            os.close(pin_dir_fd)
        temporary_pin = pin_dir / "known_hosts"
        _validate_private_pin(temporary_pin, known_hosts_bytes, host_identity,
                              pin_dir_identity, pin_file_identity)
        cmd = [SSH_BINARY, "-F", "/dev/null", "-T",
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={temporary_pin}",
               "-o", "GlobalKnownHostsFile=/dev/null", "-o", "CheckHostIP=yes",
               "-o", "UpdateHostKeys=no", "-o", "KnownHostsCommand=none",
               "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
               "-o", "PermitLocalCommand=no", _AUTHORIZED_SSH_DESTINATION, remote_command]
        # Check both source and private copy immediately before OpenSSH opens the path.
        check_bytes, check_identity, check_source_inode = _read_pinned_source(known_hosts_path)
        if (check_bytes != known_hosts_bytes or check_identity != host_identity or
                check_source_inode != source_identity or sha(check_bytes) != pinned_hash):
            raise Refusal("pinned known_hosts changed between validation and SSH invocation")
        _validate_private_pin(temporary_pin, known_hosts_bytes, host_identity,
                              pin_dir_identity, pin_file_identity)
        _revalidate_local_ssh_auth_sock(agent_path, agent_identity)
        result = runner(cmd, input=stdin_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        check=False, timeout=30, env=safe_env)
    returncode = getattr(result, "returncode", 1)
    stderr = getattr(result, "stderr", b"")
    diagnostics, clean_diagnostics = _parse_remote_diagnostics(stderr)
    if returncode != 0:
        remote_stdout = getattr(result, "stdout", b"")
        if isinstance(remote_stdout, str):
            remote_stdout = remote_stdout.encode("utf-8", "replace")
        raise Refusal(_remote_failure_message(returncode, stderr, remote_stdout))
    if not clean_diagnostics or diagnostics.get("SSH_ERROR_CLASS") or diagnostics.get("REMOTE_PHASE"):
        raise Refusal(_remote_failure_message(returncode, stderr))
    raw = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode()
    try:
        unsigned = validate_unsigned(raw, collector_hash=collector_hash, backend_hash=backend_hash,
                                      expected_hostname=expected_hostname, session_nonce=nonce)
    except Refusal as exc:
        received = "YES" if raw else "NO"
        raise Refusal(f"unsigned evidence rejected (SSH_RETURN_CODE=0 STDOUT_RECORD_RECEIVED={received} "
                      "SSH_ERROR_CLASS=JSON_PARSE_FAILED REMOTE_PHASE=STDOUT_RECORD_RECEIVED)") from exc
    payload = {"schema": "fk0957-signed-identity-evidence", "version": 1,
               "unsigned_evidence": unsigned,
               "provenance": {"ssh_destination": _AUTHORIZED_SSH_DESTINATION,
                              "ssh_host_key_algorithm": host_identity["algorithm"],
                              "ssh_host_key_sha256": host_identity["fingerprint"],
                              "pinned_known_hosts_sha256": pinned_hash,
                              "collector_reported_hostname_SELF_REPORTED": unsigned["remote_hostname"],
                              "collector_source_sha256": collector_hash, "backend_source_sha256": backend_hash,
                              "execution_mode": execution_mode,
                              "execution_source_commit": execution_source_commit,
                              "execution_bundle_sha256": bundle_hash,
                              "source_commit": unsigned["source_commit"],
                              "acquisition_timestamp": unsigned["acquisition_timestamp"],
                              "session_nonce": nonce, "raw_unsigned_sha256": sha(raw)}}
    encoded = canonical(payload)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(_read_signing_key(key_path), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("not Ed25519")
        signature = key.sign(encoded)
        verify_signed({"payload": payload, "payload_sha256": sha(encoded), "signature_algorithm": "Ed25519",
                       "signature_hex": signature.hex()}, key.public_key())
    except Exception as exc:
        raise Refusal("local Ed25519 signing or verification failed") from exc
    return {"payload": payload, "payload_sha256": sha(encoded), "signature_algorithm": "Ed25519",
            "signature_hex": signature.hex()}


def verify_signed(evidence: dict, public_key) -> bool:
    if not isinstance(evidence, dict) or set(evidence) != {"payload", "payload_sha256", "signature_algorithm", "signature_hex"}:
        raise Refusal("signed evidence envelope malformed")
    encoded = canonical(evidence["payload"])
    payload = evidence["payload"]
    if not isinstance(payload, dict) or set(payload) != {"schema", "version", "unsigned_evidence", "provenance"}:
        raise Refusal("signed payload schema malformed")
    unsigned = payload["unsigned_evidence"]
    provenance = payload["provenance"]
    provenance_fields = {"ssh_destination", "ssh_host_key_algorithm", "ssh_host_key_sha256",
                         "pinned_known_hosts_sha256", "collector_reported_hostname_SELF_REPORTED",
                         "collector_source_sha256", "backend_source_sha256", "execution_mode",
                         "execution_source_commit", "execution_bundle_sha256",
                         "source_commit", "acquisition_timestamp", "session_nonce", "raw_unsigned_sha256"}
    if (payload["schema"] != "fk0957-signed-identity-evidence" or payload["version"] != 1 or
            not isinstance(unsigned, dict) or set(unsigned) != EXPECTED_FIELDS or
            not isinstance(provenance, dict) or set(provenance) != provenance_fields):
        raise Refusal("signed payload fields malformed")
    expected_provenance = {"ssh_destination": _AUTHORIZED_SSH_DESTINATION,
                           "ssh_host_key_algorithm": provenance.get("ssh_host_key_algorithm"),
                           "ssh_host_key_sha256": provenance.get("ssh_host_key_sha256"),
                           "pinned_known_hosts_sha256": provenance.get("pinned_known_hosts_sha256"),
                           "collector_reported_hostname_SELF_REPORTED": unsigned.get("remote_hostname"),
                           "collector_source_sha256": unsigned.get("collector_source_sha256"),
                           "backend_source_sha256": unsigned.get("backend_source_sha256"),
                           "execution_mode": provenance.get("execution_mode"),
                           "execution_source_commit": provenance.get("execution_source_commit"),
                           "execution_bundle_sha256": provenance.get("execution_bundle_sha256"),
                           "source_commit": unsigned.get("source_commit"),
                           "acquisition_timestamp": unsigned.get("acquisition_timestamp"),
                           "session_nonce": unsigned.get("session_nonce"),
                           "raw_unsigned_sha256": sha(canonical(unsigned) + b"\n")}
    if provenance != expected_provenance:
        raise Refusal("signed provenance binding mismatch")
    if (not isinstance(provenance["ssh_host_key_algorithm"], str) or
            not isinstance(provenance["ssh_host_key_sha256"], str) or
            not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", provenance["ssh_host_key_sha256"]) or
            not re.fullmatch(r"[0-9a-f]{64}", provenance["pinned_known_hosts_sha256"])):
        raise Refusal("signed SSH host-key provenance malformed")
    if provenance["execution_mode"] == "EPHEMERAL_REVIEWED_BUNDLE":
        if (not isinstance(provenance["execution_source_commit"], str) or
                not re.fullmatch(r"[0-9a-f]{40}", provenance["execution_source_commit"]) or
                not isinstance(provenance["execution_bundle_sha256"], str) or
                not re.fullmatch(r"[0-9a-f]{64}", provenance["execution_bundle_sha256"])):
            raise Refusal("ephemeral bundle provenance malformed")
    elif provenance["execution_mode"] != "REMOTE_CHECKOUT" or provenance["execution_bundle_sha256"] is not None:
        raise Refusal("execution mode provenance malformed")
    if evidence["signature_algorithm"] != "Ed25519" or evidence["payload_sha256"] != sha(encoded):
        raise Refusal("signed evidence digest or algorithm mismatch")
    try:
        public_key.verify(bytes.fromhex(evidence["signature_hex"]), encoded)
    except Exception as exc:
        raise Refusal("signed evidence verification failed") from exc
    return True


# Updated to the reviewed collector bytes after implementation; prevents a
# mutable collector replacement from being sent to the authorized host.
COLLECTOR_PIN = "d944db4b592bba442431ca24a8f0ce2d8600e9f744d8e96c50bf27119f2f60b4"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-key", required=True, type=Path, help="local Ed25519 PEM key")
    parser.add_argument("--known-hosts", required=True, type=Path,
                        help="owner-only pinned known_hosts file dedicated to the authorized testbench")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-hostname", required=True,
                        help="pre-established hostname expected from the authorized SSH destination")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ephemeral", action="store_true",
                      help="execute the deterministic reviewed bundle from SSH stdin; no remote checkout needed")
    mode.add_argument("--remote-repo",
                      help="legacy checkout mode: testbench checkout containing pinned observer/backend")
    args = parser.parse_args(argv)
    try:
        evidence = acquire_and_sign(args.signing_key, known_hosts_path=args.known_hosts,
                                    expected_hostname=args.expected_hostname,
                                    remote_repo=args.remote_repo, ephemeral=args.ephemeral)
        write_evidence_atomic(args.output, canonical(evidence) + b"\n")
    except (Refusal, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
