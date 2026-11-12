#!/usr/bin/env python3
"""Read-only diagnostic for FK0957 ephemeral bundle transport and verification.

The remote bootstrap verifies the exact bundle and its pinned source bytes, then
exits before importing or executing any bundle member.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import types

import phk2_fk0957_remote_orchestrator as orchestrator

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SSH_DESTINATION = "rmann@192.168.1.173"
SSH_IP = "192.168.1.173"
MAX_BUNDLE_BYTES = 4 * 1024 * 1024


REMOTE_DIAGNOSTIC_BODY = r'''import hashlib,io,json,sys,zipfile
MAX=4*1024*1024
NAMES=__EXPECTED_NAMES__
def say(k,v="YES"):
 print(k+"="+v,flush=True)
def fail(phase):
 print("FAILURE_PHASE="+phase,flush=True)
 raise SystemExit(3)
say("REMOTE_RUNNER_STARTED")
if len(sys.argv)!=8 or sys.argv[1]!="FK0957-DIAGNOSTIC": fail("REMOTE_RUNNER_STARTED")
bundle_sha,source_commit,collector_sha,backend_sha,observer_sha,nonce=sys.argv[2:]
raw=sys.stdin.buffer.read(MAX+1)
if len(raw)>MAX: fail("REMOTE_BUNDLE_RECEIVED")
say("REMOTE_BUNDLE_RECEIVED")
phase="REMOTE_BUNDLE_HASH_VERIFIED"
if hashlib.sha256(raw).hexdigest()!=bundle_sha:
 say(phase,"NO")
 fail(phase)
say(phase)
try:
 z=zipfile.ZipFile(io.BytesIO(raw),"r")
 infos=z.infolist(); names=[i.filename for i in infos]
 if names!=NAMES or len(names)!=len(set(names)): fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 if any(i.is_dir() or ((i.external_attr>>16)&0o170000)!=0o100000 or i.file_size>MAX for i in infos): fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 raw_manifest=z.read("manifest.json")
 def pairs(items):
  d={}
  for k,v in items:
   if k in d: raise ValueError("duplicate key")
   d[k]=v
  return d
 m=json.loads(raw_manifest.decode("utf-8"),object_pairs_hook=pairs)
 if json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False).encode()!=raw_manifest: fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 expected={"schema","version","source_commit","session_nonce","collector_source_sha256","backend_source_sha256","observer_source_sha256","runner_source_sha256","files"}
 if set(m)!=expected or m["schema"]!="fk0957-ephemeral-execution-bundle" or m["version"]!=1: fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 if (m["source_commit"]!=source_commit or m["session_nonce"]!=nonce or
     m["collector_source_sha256"]!=collector_sha or m["backend_source_sha256"]!=backend_sha or
     m["observer_source_sha256"]!=observer_sha): fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 members={n:z.read(n) for n in names if n not in ("manifest.json","runner.py")}
 runner=z.read("runner.py")
 if set(members)!=set(m["files"]): fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 if any(hashlib.sha256(b).hexdigest()!=m["files"].get(n) for n,b in members.items()): fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
 if hashlib.sha256(runner).hexdigest()!=m["runner_source_sha256"]: fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
except SystemExit:
 raise
except Exception:
 fail("REMOTE_BUNDLE_MANIFEST_VERIFIED")
say("REMOTE_BUNDLE_MANIFEST_VERIFIED")
say("COLLECTOR_SOURCE_VERIFIED","YES" if hashlib.sha256(members["tools/phk2_host/phk2_fk0957_remote_collector.py"]).hexdigest()==collector_sha else "NO")
if hashlib.sha256(members["tools/phk2_host/phk2_fk0957_remote_collector.py"]).hexdigest()!=collector_sha: fail("COLLECTOR_SOURCE_VERIFIED")
say("BACKEND_SOURCE_VERIFIED","YES" if hashlib.sha256(members["tools/phk2_host/phk2_fk0957_readonly_backend.py"]).hexdigest()==backend_sha else "NO")
if hashlib.sha256(members["tools/phk2_host/phk2_fk0957_readonly_backend.py"]).hexdigest()!=backend_sha: fail("BACKEND_SOURCE_VERIFIED")
say("OBSERVER_SOURCE_VERIFIED","YES" if hashlib.sha256(members["tools/phk2_host/phk2_fk0957_identity_observer.py"]).hexdigest()==observer_sha else "NO")
if hashlib.sha256(members["tools/phk2_host/phk2_fk0957_identity_observer.py"]).hexdigest()!=observer_sha: fail("OBSERVER_SOURCE_VERIFIED")
say("RUNNER_SOURCE_VERIFIED")
say("COLLECTOR_INVOKED","NO")
say("USB_ACCESS","NO")
say("HARDWARE_ACCESS","NO")
'''

REMOTE_PHASES = (
    "REMOTE_RUNNER_STARTED", "REMOTE_BUNDLE_RECEIVED", "REMOTE_BUNDLE_HASH_VERIFIED",
    "REMOTE_BUNDLE_MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED", "OBSERVER_SOURCE_VERIFIED",
    "RUNNER_SOURCE_VERIFIED", "COLLECTOR_INVOKED", "USB_ACCESS", "HARDWARE_ACCESS",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_source_pin(path: Path) -> tuple[bytes, dict]:
    fd, data, identity = orchestrator._read_pinned_known_hosts(Path(path))
    try:
        info = os.fstat(fd)
        return data, {**identity, "device": info.st_dev, "inode": info.st_ino}
    finally:
        os.close(fd)


def _open_private_temp_dir(path: Path) -> tuple[int, tuple[int, int]]:
    path = Path(path)
    if not path.is_absolute() or path.parent != Path("/tmp") or not path.name.startswith("fk0957-stage-pin-"):
        raise RuntimeError("temporary pin directory has an unsafe path")
    parent = Path("/tmp").lstat()
    if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode) or
            parent.st_uid not in (0, os.getuid()) or not parent.st_mode & stat.S_ISVTX):
        raise RuntimeError("temporary pin parent is not a protected sticky directory")
    before = path.lstat()
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode) or
            before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o700):
        raise RuntimeError("temporary pin directory is not private and owner-controlled")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    opened = os.fstat(fd)
    identity = (opened.st_dev, opened.st_ino)
    if (identity != (before.st_dev, before.st_ino) or opened.st_uid != os.getuid() or
            stat.S_IMODE(opened.st_mode) != 0o700):
        os.close(fd)
        raise RuntimeError("temporary pin directory changed during validation")
    return fd, identity


def _write_private_pin(dir_fd: int, data: bytes) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("known_hosts", flags, 0o600, dir_fd=dir_fd)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        info = os.fstat(fd)
        path_info = os.stat("known_hosts", dir_fd=dir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or
                (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise RuntimeError("temporary known_hosts copy is not a private single-link file")
        return info.st_dev, info.st_ino
    finally:
        os.close(fd)


def remote_command(*, bundle_sha256: str, source_commit: str, collector_sha256: str,
                   backend_sha256: str, observer_sha256: str, session_nonce: str) -> str:
    pins = ((bundle_sha256, 64), (source_commit, 40), (collector_sha256, 64),
            (backend_sha256, 64), (observer_sha256, 64), (session_nonce, 64))
    if any(len(v) != n or re.fullmatch(r"[0-9a-f]+", v) is None for v, n in pins):
        raise ValueError("diagnostic pin or nonce is malformed")
    names = sorted(("manifest.json", "runner.py",
                    "tools/phk2_host/phk2_fk0957_remote_collector.py",
                    "tools/phk2_host/phk2_fk0957_readonly_backend.py",
                    "tools/phk2_host/phk2_fk0957_identity_observer.py"))
    body = REMOTE_DIAGNOSTIC_BODY.replace("__EXPECTED_NAMES__", repr(names))
    return ("FK0957_TARGET=FK0957 /usr/bin/python3 -I -S -c " + shlex.quote(body) +
            " FK0957-DIAGNOSTIC " + " ".join(v for v, _ in pins))


def _git_source_commit() -> str:
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null"}
    result = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, check=True, env=env)
    return result.stdout.strip()


def _bundle() -> tuple[bytes, dict]:
    collector = orchestrator.COLLECTOR.read_bytes()
    backend = orchestrator.BACKEND.read_bytes()
    observer = orchestrator.observer.OBSERVER_PATH.read_bytes()
    runner = (HERE / "phk2_fk0957_ephemeral_runner.py").read_bytes()
    if _sha(runner) != orchestrator.BUNDLE_RUNNER_PIN:
        raise RuntimeError("ephemeral runner source pin mismatch")
    bundle, metadata = orchestrator.deterministic_bundle(
        source_commit=_git_source_commit(), session_nonce=secrets.token_hex(32),
        source_root=REPO, collector_pin=orchestrator.COLLECTOR_PIN,
        backend_pin=orchestrator.observer.REVIEWED_BACKENDS[
            "phk2_fk0957_readonly_backend:create_backend"],
        observer_pin=orchestrator.OBSERVER_PIN, runner_bytes=runner)
    orchestrator.inspect_bundle(
        bundle, expected_bundle_sha256=metadata["bundle_sha256"],
        expected_source_commit=metadata["source_commit"],
        expected_collector_sha256=orchestrator.COLLECTOR_PIN,
        expected_backend_sha256=orchestrator.observer.REVIEWED_BACKENDS[
            "phk2_fk0957_readonly_backend:create_backend"],
        expected_nonce=metadata["session_nonce"])
    return bundle, metadata


def _sanitize(text: bytes) -> str:
    decoded = text.decode("utf-8", "replace").replace("\r", " ").replace("\n", " ")
    return re.sub(r"[^A-Za-z0-9 ._:/@=-]", "?", decoded)[:240]


def run_diagnostic(known_hosts_path: Path, *, runner=subprocess.run, output=None,
                   temp_factory=tempfile.TemporaryDirectory) -> dict:
    emit = print if output is None else lambda value: print(value, file=output)
    emit("COLLECTOR_INVOKED=NO")
    emit("USB_ACCESS=NO")
    emit("HARDWARE_ACCESS=NO")
    try:
        bundle, metadata = _bundle()
    except Exception:
        emit("BUNDLE_CONSTRUCTED=NO")
        emit("SSH_STDIN_SENT=NO")
        emit("REMOTE_RUNNER_STARTED=NO")
        emit("REMOTE_BUNDLE_RECEIVED=NO")
        emit("REMOTE_BUNDLE_HASH_VERIFIED=NO")
        emit("REMOTE_BUNDLE_MANIFEST_VERIFIED=NO")
        emit("COLLECTOR_SOURCE_VERIFIED=NO")
        emit("BACKEND_SOURCE_VERIFIED=NO")
        emit("COLLECTOR_INVOKED=NO")
        emit("USB_ACCESS=NO")
        emit("HARDWARE_ACCESS=NO")
        emit("FAILURE_PHASE=LOCAL_BUNDLE_CONSTRUCTION")
        return {"failure_phase": "LOCAL_BUNDLE_CONSTRUCTION", "ssh_rc": None}
    emit("BUNDLE_CONSTRUCTED=YES")
    emit("BUNDLE_SHA256=" + metadata["bundle_sha256"])
    source_bytes, source_identity = _safe_source_pin(Path(known_hosts_path))
    temp = temp_factory(prefix="fk0957-stage-pin-", dir="/tmp")
    successful_result = None
    try:
        temp_fd, temp_dir_identity = _open_private_temp_dir(Path(temp.name))
        safe_path = Path(temp.name) / "known_hosts"
        try:
            copy_identity = _write_private_pin(temp_fd, source_bytes)
        finally:
            os.close(temp_fd)
        check_fd, copied, identity = orchestrator._read_pinned_known_hosts(safe_path)
        try:
            check_info = os.fstat(check_fd)
            if (copied != source_bytes or identity != {k: v for k, v in source_identity.items()
                                                       if k not in ("device", "inode")} or
                    (check_info.st_dev, check_info.st_ino) != copy_identity):
                raise RuntimeError("protected host-key copy differs from the supplied pin")
        finally:
            os.close(check_fd)
        remote = remote_command(
            bundle_sha256=metadata["bundle_sha256"],
            source_commit=metadata["source_commit"],
            collector_sha256=metadata["collector_source_sha256"],
            backend_sha256=metadata["backend_source_sha256"],
            observer_sha256=metadata["observer_source_sha256"],
            session_nonce=metadata["session_nonce"])
        cmd = [orchestrator.SSH_BINARY, "-F", "/dev/null", "-T",
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={safe_path}",
               "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "CheckHostIP=yes", "-o", "UpdateHostKeys=no",
               "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
               "-o", "PermitLocalCommand=no", SSH_DESTINATION, remote]
        source_check, current_identity = _safe_source_pin(Path(known_hosts_path))
        if source_check != source_bytes or current_identity != source_identity:
            raise RuntimeError("supplied known_hosts changed before diagnostic SSH")
        temp_check_fd, current_temp_dir_identity = _open_private_temp_dir(Path(temp.name))
        try:
            check_fd, copied, identity = orchestrator._read_pinned_known_hosts(safe_path)
            try:
                check_info = os.fstat(check_fd)
                if (current_temp_dir_identity != temp_dir_identity or copied != source_bytes or
                        identity != {k: v for k, v in source_identity.items() if k not in ("device", "inode")} or
                        (check_info.st_dev, check_info.st_ino) != copy_identity):
                    raise RuntimeError("protected host-key copy changed before diagnostic SSH")
            finally:
                os.close(check_fd)
        finally:
            os.close(temp_check_fd)
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "LANG": "C"}
        try:
            result = runner(cmd, input=bundle, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=30, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            emit("SSH_RC=unavailable")
            emit("SSH_STDERR=" + _sanitize(str(exc).encode()))
            emit("SSH_STDIN_SENT=NO")
            emit("REMOTE_RUNNER_STARTED=NO")
            emit("REMOTE_BUNDLE_RECEIVED=NO")
            emit("REMOTE_BUNDLE_HASH_VERIFIED=NO")
            emit("REMOTE_BUNDLE_MANIFEST_VERIFIED=NO")
            emit("COLLECTOR_SOURCE_VERIFIED=NO")
            emit("BACKEND_SOURCE_VERIFIED=NO")
            emit("COLLECTOR_INVOKED=NO")
            emit("USB_ACCESS=NO")
            emit("HARDWARE_ACCESS=NO")
            emit("FAILURE_PHASE=SSH_TRANSPORT")
            return {"failure_phase": "SSH_TRANSPORT", "ssh_rc": None,
                    "bundle_sha256": metadata["bundle_sha256"]}
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        phases = {}
        failure_phase = None
        malformed = False
        for line in lines:
            if line.startswith("FAILURE_PHASE="):
                failure_phase = line.split("=", 1)[1]
            elif "=" in line:
                k, v = line.split("=", 1)
                if k not in (*REMOTE_PHASES, "BUNDLE_SHA256") or k in phases:
                    malformed = True
                phases[k] = v
            else:
                malformed = True
        stdin_sent = phases.get("REMOTE_BUNDLE_RECEIVED") == "YES"
        emit("SSH_STDIN_SENT=" + ("YES" if stdin_sent else "NO"))
        for name in REMOTE_PHASES:
            if name in phases:
                emit(name + "=" + phases[name])
            elif name not in ("COLLECTOR_INVOKED", "USB_ACCESS", "HARDWARE_ACCESS"):
                emit(name + "=NO")
        emit("SSH_RC=" + str(result.returncode))
        if result.stderr:
            emit("SSH_STDERR=" + _sanitize(result.stderr))
        expected = set(REMOTE_PHASES)
        success = (result.returncode == 0 and not malformed and failure_phase is None and
                   all(phases.get(k) == ("NO" if k in ("COLLECTOR_INVOKED", "USB_ACCESS", "HARDWARE_ACCESS") else "YES")
                       for k in expected))
        if success:
            successful_result = {"failure_phase": "none", "ssh_rc": result.returncode,
                                 "bundle_sha256": metadata["bundle_sha256"], "phases": phases}
        else:
            if failure_phase is None and result.returncode != 0 and phases.get("REMOTE_RUNNER_STARTED") != "YES":
                failure_phase = "SSH_TRANSPORT"
            if failure_phase is None:
                sequence = ("REMOTE_RUNNER_STARTED", "REMOTE_BUNDLE_RECEIVED",
                            "REMOTE_BUNDLE_HASH_VERIFIED", "REMOTE_BUNDLE_MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED",
                            "BACKEND_SOURCE_VERIFIED", "OBSERVER_SOURCE_VERIFIED", "RUNNER_SOURCE_VERIFIED")
                failure_phase = next((n for n in sequence if phases.get(n) != "YES"),
                                     "REMOTE_DIAGNOSTIC_RESPONSE")
            emit("FAILURE_PHASE=" + failure_phase)
            return {"failure_phase": failure_phase, "ssh_rc": result.returncode,
                    "bundle_sha256": metadata["bundle_sha256"], "phases": phases}
    finally:
        temp.cleanup()
    emit("FAILURE_PHASE=none")
    return successful_result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--known-hosts", required=True, type=Path)
    args = parser.parse_args(argv)
    result = run_diagnostic(args.known_hosts)
    return 0 if result["failure_phase"] == "none" else 1


if __name__ == "__main__":
    raise SystemExit(main())
