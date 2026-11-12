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
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or
            before.st_uid != os.getuid() or before.st_nlink != 1 or
            before.st_mode & 0o177 or not before.st_mode & 0o400):
        raise RuntimeError("known_hosts must be owner-only, regular, and singly linked")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError("known_hosts changed during diagnostic validation")
        chunks = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
            if sum(map(len, chunks)) > 1024 * 1024:
                raise RuntimeError("known_hosts is oversized")
        data = b"".join(chunks)
    finally:
        os.close(fd)
    return data, orchestrator._parse_pinned_host_key(data)


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


def run_diagnostic(known_hosts_path: Path, *, runner=subprocess.run, output=None) -> dict:
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
    temp = tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-", dir="/tmp")
    try:
        os.chmod(temp.name, 0o700)
        safe_path = Path(temp.name) / "known_hosts"
        safe_path.write_bytes(source_bytes)
        os.chmod(safe_path, 0o600)
        check_fd, copied, identity = orchestrator._read_pinned_known_hosts(safe_path)
        os.close(check_fd)
        if copied != source_bytes or identity != source_identity:
            raise RuntimeError("protected host-key copy differs from the supplied pin")
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
            emit("FAILURE_PHASE=none")
            return {"failure_phase": "none", "ssh_rc": result.returncode,
                    "bundle_sha256": metadata["bundle_sha256"], "phases": phases}
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--known-hosts", required=True, type=Path)
    args = parser.parse_args(argv)
    result = run_diagnostic(args.known_hosts)
    return 0 if result["failure_phase"] == "none" else 1


if __name__ == "__main__":
    raise SystemExit(main())
