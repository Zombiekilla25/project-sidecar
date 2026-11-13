#!/usr/bin/python3
"""Protected FK0957 one-shot process supervisor.

Deployment model: run this daemon as root from the supplied systemd unit.  The
ordinary acquisition account talks to its Unix socket; it has no write access
to the state directory.  The daemon validates the signed endpoint request,
then launches exactly one fixed endpoint command and owns waitpid() for that
child.  This module deliberately has no USB/JTAG imports and cannot choose a
transaction.  It is not operational until an administrator provisions trust
pins and installs the root-owned package.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from typing import Any

import phk2_fk0957_remote_topology_endpoint as endpoint

SOCKET_PATH = "/run/sidecar/fk0957-supervisor.sock"
STATE_ROOT = "/var/lib/sidecar/fk0957/supervisor"
LAUNCHER = "/usr/local/sbin/fk0957-safe-launcher"
ENDPOINT_MODE = "--supervisor-remote-endpoint"
MAX_MESSAGE = 600 * 1024
MAX_OUTPUT = 600 * 1024
OP_ID = re.compile(r"[0-9a-f]{32}\Z")
RUN_KEYS = {"schema", "command", "operation_id", "request_b64"}
STATUS_KEYS = {"schema", "command", "operation_id"}
REQUEST_SCHEMA = "fk0957-supervisor-ipc-v1"
RESPONSE_SCHEMA = "fk0957-supervisor-status-v1"
TERMINAL = {"EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE"}
ALLOWED_TRANSITIONS = {
    "REGISTERED": {"LAUNCHING"},
    "LAUNCHING": {"RUNNING", "UNKNOWN"},
    "RUNNING": TERMINAL | {"UNKNOWN"},
}
_RUN_LOCK = threading.Lock()


def transition_allowed(prior: str | None, current: Any) -> bool:
    if prior is None:
        return current == "REGISTERED"
    return prior in ALLOWED_TRANSITIONS and current in ALLOWED_TRANSITIONS[prior]


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def parse_message(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_MESSAGE:
        raise ValueError("message size invalid")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    if type(value) is not dict or canonical(value) != raw:
        raise ValueError("message is not canonical")
    return value


def validate_request(value: Any) -> tuple[str, bytes, dict[str, Any], bytes, str]:
    if (type(value) is not dict or set(value) != RUN_KEYS or
            value.get("schema") != REQUEST_SCHEMA or
            value.get("command") != "run" or
            type(value.get("operation_id")) is not str or
            not OP_ID.fullmatch(value["operation_id"]) or
            type(value.get("request_b64")) is not str or
            len(value["request_b64"]) > MAX_MESSAGE * 2):
        raise ValueError("IPC request rejected")
    try:
        raw = base64.b64decode(value["request_b64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("IPC request encoding rejected") from None
    if not raw or len(raw) > endpoint.MAX_REQUEST_BYTES:
        raise ValueError("endpoint request size rejected")
    # Verify identity and signature/handoff/manifest before creating a child.
    issuers = endpoint._load_trust_config()
    context, auth_bytes, auth_id = endpoint._validate_request(raw, issuers)
    if context["operation_id"] != value["operation_id"]:
        raise ValueError("IPC/authorization operation mismatch")
    return value["operation_id"], raw, context, auth_bytes, auth_id, issuers


def _ensure_root_state() -> int:
    """Open the fixed root-owned state directory without following links."""
    if os.geteuid() != 0:
        raise PermissionError("supervisor must run as root service")
    path = Path(STATE_ROOT)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        components = path.parts[1:]
        for index, component in enumerate(components):
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=fd)
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
            info = os.fstat(child)
            final = index == len(components) - 1
            mode = stat.S_IMODE(info.st_mode)
            unsafe_mode = mode != 0o700 if final else bool(mode & 0o022)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or unsafe_mode:
                os.close(child)
                raise PermissionError("supervisor state directory is not private root storage")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _append_state(root_fd: int, operation_id: str, record: dict[str, Any], *, first: bool) -> None:
    """Append-only journal in a private operation directory; terminal rows never replace."""
    try:
        os.mkdir(operation_id, 0o700, dir_fd=root_fd)
        created = True
    except FileExistsError:
        created = False
    if first != created:
        raise ValueError("operation already registered or missing")
    if created:
        os.fsync(root_fd)
    op_fd = os.open(operation_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_fd)
    try:
        info = os.fstat(op_fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError("operation storage ownership rejected")
        lock_fd = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                          0o600, dir_fd=op_fd)
        try:
            lock_info = os.fstat(lock_fd)
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0 or
                    lock_info.st_nlink != 1 or stat.S_IMODE(lock_info.st_mode) != 0o600):
                raise PermissionError("operation lock identity rejected")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                try:
                    journal_fd = os.open("journal.jsonl", os.O_RDONLY | os.O_NOFOLLOW,
                                         dir_fd=op_fd)
                except FileNotFoundError:
                    prior = None
                else:
                    try:
                        previous = bytearray()
                        while len(previous) <= 1024 * 1024:
                            part = os.read(journal_fd, min(65536, 1024 * 1024 + 1 - len(previous)))
                            if not part:
                                break
                            previous.extend(part)
                        if len(previous) > 1024 * 1024:
                            raise ValueError("journal oversized")
                    finally:
                        os.close(journal_fd)
                    lines = previous.splitlines()
                    if not lines:
                        raise ValueError("empty operation journal")
                    prior = parse_message(lines[-1] + b"\n").get("state")
                current = record.get("state")
                if (prior is None and not first) or not transition_allowed(prior, current):
                    raise ValueError("non-monotonic or terminal state transition")
                flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                fd = os.open("journal.jsonl", flags, 0o600, dir_fd=op_fd)
                try:
                    fstat = os.fstat(fd)
                    if (not stat.S_ISREG(fstat.st_mode) or fstat.st_uid != 0 or
                            fstat.st_nlink != 1 or stat.S_IMODE(fstat.st_mode) != 0o600):
                        raise PermissionError("journal identity rejected")
                    data = canonical(record)
                    offset = 0
                    while offset < len(data):
                        n = os.write(fd, data[offset:])
                        if n <= 0:
                            raise OSError("journal write incomplete")
                        offset += n
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
        os.fsync(op_fd)
    finally:
        os.close(op_fd)


def _peer_uid(client: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise OSError("kernel peer credentials unavailable")
    raw = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _pid, uid, _gid = __import__("struct").unpack("3i", raw)
    return uid


def _service_accounts() -> tuple[int, int, int]:
    """Require dedicated non-login runner and private device-group membership."""
    caller = pwd.getpwnam("sidecar-acquire")
    runner = pwd.getpwnam("sidecar-fk0957-runner")
    device_group = grp.getgrnam("fk0957-device")
    if (caller.pw_uid <= 0 or runner.pw_uid <= 0 or
            runner.pw_uid in {0, caller.pw_uid} or
            Path(runner.pw_shell).name not in {"nologin", "false"} or
            runner.pw_dir not in {"/nonexistent", "/var/empty"}):
        raise PermissionError("dedicated acquisition accounts are not provisioned safely")
    named = set(device_group.gr_mem)
    primary = {row.pw_name for row in pwd.getpwall() if row.pw_gid == device_group.gr_gid}
    if named - {runner.pw_name} or primary - {runner.pw_name}:
        raise PermissionError("FK0957 device group has unrelated users")
    return caller.pw_uid, runner.pw_uid, device_group.gr_gid


def _read_status(root_fd: int, operation_id: str) -> bytes:
    if not OP_ID.fullmatch(operation_id):
        raise ValueError("operation ID invalid")
    op_fd = os.open(operation_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_fd)
    try:
        directory_info = os.fstat(op_fd)
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0 or
                stat.S_IMODE(directory_info.st_mode) != 0o700):
            raise PermissionError("operation directory identity invalid")
        fd = os.open("journal.jsonl", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=op_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                    info.st_size > 1024 * 1024):
                raise PermissionError("journal identity invalid")
            raw = bytearray()
            while len(raw) <= 1024 * 1024:
                part = os.read(fd, min(65536, 1024 * 1024 + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            after = os.fstat(fd)
            if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError("journal changed while read")
        finally:
            os.close(fd)
    finally:
        os.close(op_fd)
    rows = [parse_message(line + b"\n") for line in bytes(raw).splitlines()]
    if not rows or any(row.get("operation_id") != operation_id for row in rows):
        raise ValueError("journal has no consistent operation state")
    states = [row.get("state") for row in rows]
    for index, state in enumerate(states):
        prior = None if index == 0 else states[index - 1]
        if not transition_allowed(prior, state):
            raise ValueError("journal contains impossible state history")
    last = rows[-1]
    if last.get("state") not in {
            "REGISTERED", "LAUNCHING", "RUNNING", "EXITED_SUCCESS",
            "EXITED_REFUSAL", "EXITED_FAILURE", "UNKNOWN"}:
        raise ValueError("journal state invalid")
    return canonical(last)


def _child_identity(pid: int, operation_id: str, authorization_id: str) -> dict[str, Any]:
    """Bind supervisor's Popen child PID to start time, parent and executable bytes."""
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as handle:
        raw_stat = handle.read(8192)
    close = raw_stat.rfind(")")
    fields = raw_stat[close + 2:].split()
    if len(fields) < 20 or fields[19].isdecimal() is False or int(fields[19]) <= 0:
        raise OSError("child start identity unavailable")
    # In fields beginning with state (proc field 3), ppid is index 1.
    if int(fields[1]) != os.getpid():
        raise OSError("child parent identity mismatch")
    executable = os.path.realpath(f"/proc/{pid}/exe")
    executable_bytes = Path(executable).read_bytes()
    argv_raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    argv = argv_raw.rstrip(b"\0").split(b"\0")
    if not argv or argv[0].decode("utf-8", "strict") != LAUNCHER or \
            ENDPOINT_MODE.encode("ascii") not in argv:
        raise OSError("child executable/arguments mismatch")
    return {"pid": pid, "start_identity": fields[19], "parent_pid": os.getpid(),
            "operation_id": operation_id, "authorization_id": authorization_id,
            "executable": executable,
            "executable_sha256": hashlib.sha256(executable_bytes).hexdigest(),
            "argv_sha256": hashlib.sha256(argv_raw).hexdigest()}


def serve_one(client: socket.socket, *, allowed_uid: int,
              launcher: str = LAUNCHER, state_fd: int | None = None) -> bytes:
    """Handle one authenticated local IPC request, supervising and reaping child."""
    if _peer_uid(client) != allowed_uid:
        raise PermissionError("IPC principal rejected")
    raw = bytearray()
    while len(raw) <= MAX_MESSAGE:
        part = client.recv(min(65536, MAX_MESSAGE + 1 - len(raw)))
        if not part or b"\n" in part:
            if part:
                raw.extend(part)
            break
        raw.extend(part)
    request = parse_message(bytes(raw))
    root_fd = _ensure_root_state() if state_fd is None else state_fd
    owns_fd = state_fd is None
    if request.get("schema") != REQUEST_SCHEMA:
        if owns_fd:
            os.close(root_fd)
        raise ValueError("IPC schema rejected")
    if request.get("command") == "status":
        if set(request) != STATUS_KEYS:
            raise ValueError("status query fields rejected")
        try:
            return _read_status(root_fd, request.get("operation_id"))
        finally:
            if owns_fd:
                os.close(root_fd)
    if request.get("command") != "run":
        if owns_fd:
            os.close(root_fd)
        raise ValueError("unsupported IPC command")
    try:
        operation_id, endpoint_request, context, auth_bytes, auth_id, issuers = validate_request(request)
    except BaseException:
        if owns_fd:
            os.close(root_fd)
        raise
    if not _RUN_LOCK.acquire(blocking=False):
        if owns_fd:
            os.close(root_fd)
        raise RuntimeError("another FK0957 operation is active")
    now = time.time_ns()
    child = None
    terminal_written = False
    try:
        base = {"schema": RESPONSE_SCHEMA, "operation_id": operation_id,
                "authorization_id": auth_id,
                "authorization_sha256": context["authorization_sha256"],
                "handoff_sha256": context["handoff_sha256"],
                "manifest_sha256": context["manifest_sha256"],
                "production_head": context["production_head"],
                "transaction_profile_sha256": context["transaction_profile_sha256"],
                "target": "FK0957", "one_shot": True,
                "registered_ns": now, "state": "REGISTERED"}
        _append_state(root_fd, operation_id, base, first=True)
        # Consume from the protected authority ledger before child launch.
        # The inherited root-peer capability tells only this child that the
        # supervisor has completed this operation-bound consume step.
        endpoint._consume_authorization(auth_id, auth_bytes)
        # The trusted static launcher selects only the endpoint mode. It
        # receives the signed request on stdin; no argv carries key material.
        command = [launcher, ENDPOINT_MODE]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        parent_capability, child_capability = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child_capability.set_inheritable(True)
        issuer_frame = canonical({name: base64.b64encode(issuers[name]).decode("ascii")
                                  for name in ("release", "handoff")})
        parent_capability.sendall(len(issuer_frame).to_bytes(4, "big") + issuer_frame)
        parent_capability.shutdown(socket.SHUT_WR)
        def map_capability_to_fd3() -> None:
            if child_capability.fileno() != 3:
                os.dup2(child_capability.fileno(), 3)
        _append_state(root_fd, operation_id,
                      {**base, "state": "LAUNCHING", "launch_ns": time.time_ns()}, first=False)
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=env, close_fds=True,
                                 start_new_session=True, pass_fds=(child_capability.fileno(),),
                                 preexec_fn=map_capability_to_fd3,
                                 user=pwd.getpwnam("sidecar-fk0957-runner").pw_uid,
                                 group=pwd.getpwnam("sidecar-fk0957-runner").pw_gid,
                                 extra_groups=[grp.getgrnam("fk0957-device").gr_gid])
        child_capability.close()
        process = _child_identity(child.pid, operation_id, auth_id)
        _append_state(root_fd, operation_id,
                      {**base, "state": "RUNNING", "process": process}, first=False)
        output, _ = child.communicate(endpoint_request, timeout=900)
        exit_code = child.wait()  # exact Popen child reaped by this supervisor
        # The endpoint contract is one process. If any child remains in its
        # private process group, do not report a clean operation lifecycle.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            pass
        else:
            _append_state(root_fd, operation_id,
                          {**base, "state": "UNKNOWN", "reason": "CHILD_PROCESS_GROUP_REMAINS"},
                          first=False)
            raise RuntimeError("unexpected child process survived endpoint")
        if len(output) > MAX_OUTPUT:
            output = b""
            terminal = "EXITED_FAILURE"
        else:
            terminal = "EXITED_SUCCESS" if exit_code == 0 else (
                "EXITED_REFUSAL" if exit_code == 2 else "EXITED_FAILURE")
        final = {**base, "state": terminal, "process": process,
                 "exit_code": exit_code, "reaped_ns": time.time_ns(),
                 "result_b64": base64.b64encode(output).decode("ascii")}
        _append_state(root_fd, operation_id, final, first=False)
        terminal_written = True
        parent_capability.close()
        return canonical(final)
    except subprocess.TimeoutExpired:
        # A timeout is not exit proof. Kill the process group, then require
        # successful wait/reap; otherwise persist UNKNOWN and fail closed.
        try:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            deadline = time.monotonic() + 0.5
            while True:
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("endpoint process group still exists")
                time.sleep(0.01)
        except BaseException:
            _append_state(root_fd, operation_id,
                          {"schema": RESPONSE_SCHEMA, "operation_id": operation_id,
                           "state": "UNKNOWN", "reason": "SUPERVISION_TIMEOUT"}, first=False)
            raise
        _append_state(root_fd, operation_id,
                      {"schema": RESPONSE_SCHEMA, "operation_id": operation_id,
                       "state": "EXITED_FAILURE", "exit_code": child.returncode,
                       "reaped_ns": time.time_ns()}, first=False)
        terminal_written = True
        raise
    except BaseException:
        # Unexpected parent-side errors cannot orphan the exact acquisition
        # child. Kill/reap it if possible, then persist UNKNOWN (never infer a
        # successful/failed endpoint result from supervisor-side uncertainty).
        if child is not None and not terminal_written:
            try:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=5)
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise RuntimeError("process group remains")
            except BaseException:
                pass
            try:
                _append_state(root_fd, operation_id,
                              {"schema": RESPONSE_SCHEMA, "operation_id": operation_id,
                               "state": "UNKNOWN", "reason": "SUPERVISOR_INTERNAL_FAILURE"},
                              first=False)
            except BaseException:
                pass
        raise
    finally:
        for sock_name in ("parent_capability", "child_capability"):
            sock = locals().get(sock_name)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if owns_fd:
            os.close(root_fd)
        _RUN_LOCK.release()


def endpoint_process_start(pid: int) -> str:
    """Capture Linux start ticks to bind the PID to this exact child instance."""
    with open(f"/proc/{pid}/stat", "r", encoding="ascii") as handle:
        value = handle.read(8192)
    close = value.rfind(")")
    fields = value[close + 2:].split()
    start = fields[19]
    if not start.isdecimal() or int(start) <= 0:
        raise OSError("child start identity unavailable")
    return start


def main() -> int:
    if os.geteuid() != 0:
        return 126
    # Socket directory is provisioned by the unit as root:sidecar-acquire
    # 0750. Existing paths are refused; no unlink/rebind race is tolerated.
    try:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o660)
        os.chown(SOCKET_PATH, 0, grp.getgrnam("sidecar-acquire").gr_gid,
                 follow_symlinks=False)
        server.listen(8)
        server.settimeout(1.0)
        state_fd = _ensure_root_state()
    except BaseException:
        return 126
    try:
        allowed_uid, _runner_uid, _device_gid = _service_accounts()
    except (KeyError, PermissionError):
        return 126
    try:
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="fk0957-ipc") as pool:
            while True:
                try:
                    client, _ = server.accept()
                except TimeoutError:
                    continue
                pool.submit(_serve_client, client, allowed_uid, state_fd)
    finally:
        os.close(state_fd)
        server.close()
    return 0


def _serve_client(client: socket.socket, allowed_uid: int, state_fd: int) -> None:
    with client:
        try:
            result = serve_one(client, allowed_uid=allowed_uid, state_fd=state_fd)
            client.sendall(result)
        except BaseException:
            try:
                client.sendall(canonical({"schema": RESPONSE_SCHEMA,
                                          "state": "UNKNOWN",
                                          "code": "SUPERVISION_FAILED"}))
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
