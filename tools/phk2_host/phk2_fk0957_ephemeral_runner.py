#!/usr/bin/env python3
"""Isolated remote runner embedded in the reviewed FK0957 stdin bundle."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

_DIAG_PREFIX = "FK0957_DIAG "
COLLECTOR_REFUSAL_CODES = frozenset({
    "NO_MATCHING_TARGET", "MULTIPLE_MATCHING_TARGETS", "INCOMPLETE_DESCRIPTOR_METADATA",
    "EXPECTED_SERIAL_NOT_FOUND", "UNEXPECTED_PEER_DEVICE", "BACKEND_PIN_MISMATCH",
    "TARGET_MAPPING_MISSING", "TARGET_MAPPING_AMBIGUOUS", "SOURCE_PROVENANCE_MISMATCH",
    "DESCRIPTOR_READ_FAILED", "INTERNAL_REFUSAL",
})
COLLECTOR_FAILURE_FIELDS = frozenset({
    "status", "phase", "refusal_code", "cards_opened", "second_card_opened",
    "write_count", "reset_count", "program_count", "jtag_operations",
})


def _diag(name: str, value: str = "YES") -> None:
    print(f"{_DIAG_PREFIX}{name}={value}", file=sys.stderr, flush=True)


class RemoteDiagnosticError(RuntimeError):
    def __init__(self, phase: str, error_class: str, *, refusal_code: str | None = None,
                 failure_envelope: bytes | None = None):
        self.phase = phase
        self.error_class = error_class
        self.refusal_code = refusal_code
        self.failure_envelope = failure_envelope
        super().__init__(error_class)


def parse_collector_failure_envelope(raw: bytes, *, returncode: int, stderr: bytes = b"") -> dict | None:
    """Accept only one canonical refusal record on a nonzero, silent child exit."""
    if returncode == 0 or stderr or not isinstance(raw, bytes) or not raw or len(raw) > 4096:
        return None
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        return None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (UnicodeError, ValueError):
        return None
    if not isinstance(value, dict) or set(value) != COLLECTOR_FAILURE_FIELDS:
        return None
    if _canonical(value) + b"\n" != raw:
        return None
    if (value["status"] != "REFUSED" or value["phase"] != "COLLECTOR" or
            not isinstance(value["refusal_code"], str) or
            value["refusal_code"] not in COLLECTOR_REFUSAL_CODES or
            type(value["cards_opened"]) is not int or value["cards_opened"] != 0 or
            type(value["second_card_opened"]) is not bool or value["second_card_opened"] is not False or
            any(type(value[name]) is not int or value[name] != 0
                for name in ("write_count", "reset_count", "program_count", "jtag_operations"))):
        return None
    return value



def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _write_member(root: Path, relative: str, data: bytes) -> None:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in ("", ".", "..") for p in parts):
        raise RuntimeError("unsafe bundle member path")
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(root, flags_dir)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, flags_dir, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        out_fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
        with os.fdopen(out_fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def run_payload(manifest: dict, members: dict[str, bytes], *, expected_commit: str,
                collector_hash: str, backend_hash: str, session_nonce: str,
                temp_factory=tempfile.TemporaryDirectory, process_runner=subprocess.run,
                stdout=None) -> bytes:
    required = set(manifest.get("files", {}))
    if set(members) != required or len(members) != len(required):
        raise RuntimeError("bundle files are incomplete or unexpected")
    if (manifest.get("source_commit") != expected_commit or
            manifest.get("collector_source_sha256") != collector_hash or
            manifest.get("backend_source_sha256") != backend_hash or
            manifest.get("session_nonce") != session_nonce):
        raise RuntimeError("bundle provenance or nonce mismatch")
    for name, content in members.items():
        if hashlib.sha256(content).hexdigest() != manifest["files"].get(name):
            raise RuntimeError("bundle member hash mismatch")
    reference = Path("tools/phk2_host/phk2_fk0957_readonly_backend.py")
    collector_rel = "tools/phk2_host/phk2_fk0957_remote_collector.py"
    if manifest["files"].get(collector_rel) != collector_hash or manifest["files"].get(str(reference)) != backend_hash:
        raise RuntimeError("collector/backend bytes do not match local reviewed pins")

    temp = temp_factory(prefix="fk0957-ephemeral-", dir="/tmp")
    raw = None
    failure = None
    root = Path(temp.name)
    try:
        st = root.lstat()
        parent = root.parent.lstat()
        if (not root.is_absolute() or root.parent != Path("/tmp") or
                stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or
                st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700 or
                stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode) or
                parent.st_uid not in (0, os.getuid()) or not parent.st_mode & stat.S_ISVTX or
                any(root.iterdir())):
            raise RuntimeError("ephemeral directory is unsafe, shared, or not empty")
        for name in sorted(members):
            _write_member(root, name, members[name])
        collector_bytes = members[collector_rel]
        # Execute the same in-memory bytes whose digest was checked above.
        # Running a temporary pathname here would reopen a replaceable file
        # after verification and permit a temp-file TOCTOU substitution.
        bootstrap = "import sys; exec(compile(sys.stdin.buffer.read(), '<fk0957-verified-collector>', 'exec'))"
        env = {"FK0957_TARGET": "FK0957", "FK0957_BUNDLE_ROOT": str(root)}
        _diag("COLLECTOR_STARTED")
        try:
            result = process_runner([sys.executable, "-I", "-S", "-c", bootstrap,
                                     collector_hash, session_nonce], cwd=str(root), env=env,
                                    input=collector_bytes, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, check=False, timeout=20)
        except Exception as exc:
            raise RemoteDiagnosticError("COLLECTOR_STARTED", "REMOTE_PYTHON_FAILED") from exc
        _diag("COLLECTOR_RETURNED")
        if result.returncode != 0:
            failure = parse_collector_failure_envelope(
                result.stdout, returncode=result.returncode, stderr=result.stderr)
            if failure is None:
                raise RemoteDiagnosticError("COLLECTOR_RETURNED", "REMOTE_PYTHON_FAILED")
            raise RemoteDiagnosticError("COLLECTOR_RETURNED", "COLLECTOR_REFUSED",
                                        refusal_code=failure["refusal_code"],
                                        failure_envelope=result.stdout)
        if result.stderr:
            raise RemoteDiagnosticError("COLLECTOR_RETURNED", "RUNNER_FAILED")
        raw = result.stdout
        if not isinstance(raw, bytes) or len(raw) > 16384 or not raw.endswith(b"\n"):
            raise RemoteDiagnosticError("COLLECTOR_RETURNED", "JSON_PARSE_FAILED")
        _diag("STDOUT_RECORD_RECEIVED")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
            if _canonical(value) + b"\n" != raw:
                raise ValueError("noncanonical JSON")
        except Exception as exc:
            raise RemoteDiagnosticError("STDOUT_RECORD_RECEIVED", "JSON_PARSE_FAILED") from exc
        if isinstance(value, dict) and value.get("status") == "REFUSED":
            raise RemoteDiagnosticError("STDOUT_RECORD_RECEIVED", "JSON_PARSE_FAILED")
    except Exception as exc:
        failure = exc
    try:
        temp.cleanup()
    except Exception as exc:
        failure = failure or RuntimeError("ephemeral directory cleanup failed")
    if root.exists() or root.is_symlink():
        failure = failure or RuntimeError("ephemeral directory remains after cleanup")
    if failure:
        if isinstance(failure, RemoteDiagnosticError):
            raise failure
        raise RuntimeError(str(failure)) from failure
    if stdout is not None:
        stdout.write(raw)
    return raw


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def main():
    # The isolated bootstrap has already emitted its verified phase markers.
    run_payload(BUNDLE_MANIFEST, BUNDLE_MEMBERS, expected_commit=EXPECTED_COMMIT,
                collector_hash=EXPECTED_COLLECTOR_SHA256, backend_hash=EXPECTED_BACKEND_SHA256,
                session_nonce=EXPECTED_SESSION_NONCE, stdout=sys.stdout.buffer)


if __name__ == "__main__":
    try:
        main()
    except RemoteDiagnosticError as exc:
        if exc.refusal_code is not None:
            _diag("COLLECTOR_REFUSAL_CODE", exc.refusal_code)
        _diag("REMOTE_PHASE", exc.phase)
        _diag("SSH_ERROR_CLASS", exc.error_class)
        if exc.failure_envelope is not None:
            sys.stdout.buffer.write(exc.failure_envelope)
        raise SystemExit(2)
    except Exception as exc:
        _diag("REMOTE_PHASE", "RUNNER_FAILED")
        _diag("SSH_ERROR_CLASS", "RUNNER_FAILED")
        raise SystemExit(2)
