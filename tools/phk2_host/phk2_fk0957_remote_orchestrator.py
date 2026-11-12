#!/usr/bin/env python3
"""Local-only validation and Ed25519 signing for remote unsigned FK0957 evidence."""
from __future__ import annotations

import argparse
import base64
import stat
from datetime import datetime, timezone, timedelta
import fcntl
import hmac
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
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
    "manufacturer", "product", "interface", "usb_path", "adapter_serial", "fk0957_mapping",
    "WRITE_COUNT", "RESET_COUNT", "PROGRAM_COUNT", "JTAG_OPERATIONS",
}
ZERO_FIELDS = ("WRITE_COUNT", "RESET_COUNT", "PROGRAM_COUNT", "JTAG_OPERATIONS")
SOURCE_COMMIT_PIN = "e2feedcfde44563854a3cf41fe4526c231ed385b"
OBSERVER_PIN = "c73d6a8112e5d125c88cb43455ecdcffa07dd47f129c2539f571aa27b27fff25"


class Refusal(RuntimeError):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_signing_key(path: Path) -> bytes:
    """Read a private key only from a regular, single-link, non-symlink file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refusal("signing key must be a regular file with one link")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def write_evidence_atomic(path: Path, data: bytes) -> None:
    """Replace the named output atomically without following its final symlink."""
    path = Path(path)
    parent = path.parent
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    dir_fd = os.open(parent, flags)
    temp_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    try:
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o600, dir_fd=dir_fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                os.unlink(temp_name, dir_fd=dir_fd)
            except OSError:
                pass
            raise
        os.replace(temp_name, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    finally:
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
             "adapter_serial": "153300000957A", "fk0957_mapping": "153300000957",
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
    """Open one owner-only pinned known_hosts inode and identify exactly one key for SSH_IP."""
    path = Path(path)
    if not path.is_absolute():
        raise Refusal("pinned known_hosts path must be absolute")
    # Refuse symlinks and writable/foreign parent directories so the validated path
    # cannot be replaced by another local user before OpenSSH opens it.
    parts = (path, *path.parents)
    for item in reversed(parts[1:]):
        try:
            parent_st = item.lstat()
        except OSError as exc:
            raise Refusal("pinned known_hosts parent is unavailable") from exc
        if not stat.S_ISDIR(parent_st.st_mode) or stat.S_ISLNK(parent_st.st_mode):
            raise Refusal("pinned known_hosts path has a symlink or non-directory parent")
        sticky_tmp = bool(parent_st.st_mode & stat.S_ISVTX)
        if parent_st.st_uid not in (0, os.getuid()) or (parent_st.st_mode & 0o022 and not sticky_tmp):
            raise Refusal("pinned known_hosts parent is not owned and protected by this user")
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise Refusal("pinned known_hosts must be a regular non-symlink file")
        if (before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_mode & 0o177 or
                not before.st_mode & 0o400):
            raise Refusal("pinned known_hosts must be owner-only, singly linked, and owned by this user")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except Refusal:
        raise
    except OSError as exc:
        raise Refusal("pinned known_hosts cannot be opened safely") from exc
    try:
        opened = os.fstat(fd)
        after = path.lstat()
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino or
                after.st_dev != opened.st_dev or after.st_ino != opened.st_ino or opened.st_uid != os.getuid() or
                opened.st_nlink != 1 or opened.st_mode & 0o177 or not opened.st_mode & 0o400):
            raise Refusal("pinned known_hosts changed during validation")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 1024 * 1024:
                raise Refusal("pinned known_hosts is oversized")
        material = b"".join(chunks)
        identity = _parse_pinned_host_key(material)
        # OpenSSH will use this already-validated inode through the inherited FD.
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, material, identity
    except Exception:
        os.close(fd)
        raise


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


def _sealed_known_hosts_fd(material: bytes) -> int:
    """Give OpenSSH immutable bytes from the validated pinned file, not a replaceable path."""
    if not hasattr(os, "memfd_create") or not hasattr(fcntl, "F_ADD_SEALS"):
        raise Refusal("immutable known_hosts descriptor support is required")
    flags = getattr(os, "MFD_ALLOW_SEALING", 0) | getattr(os, "MFD_CLOEXEC", 0)
    fd = os.memfd_create("fk0957-pinned-known-hosts", flags)
    try:
        offset = 0
        while offset < len(material):
            offset += os.write(fd, material[offset:])
        seals = (getattr(fcntl, "F_SEAL_SEAL", 0) | getattr(fcntl, "F_SEAL_SHRINK", 0) |
                 getattr(fcntl, "F_SEAL_GROW", 0) | getattr(fcntl, "F_SEAL_WRITE", 0))
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise Refusal("could not seal validated known_hosts material")


def acquire_and_sign(key_path: Path, *, known_hosts_path: Path, runner: Callable = subprocess.run,
                     expected_hostname: str, remote_repo: str) -> dict:
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
    if not isinstance(remote_repo, str) or not remote_repo or "\x00" in remote_repo:
        raise Refusal("remote repository path is missing or malformed")
    source_fd, known_hosts_bytes, host_identity = _read_pinned_known_hosts(known_hosts_path)
    os.close(source_fd)
    pinned_hash = sha(known_hosts_bytes)
    known_hosts_fd = _sealed_known_hosts_fd(known_hosts_bytes)
    remote_command = (f"cd -- {shlex.quote(remote_repo)} && "
                     f"FK0957_TARGET=FK0957 python3 - {collector_hash} {nonce}")
    fd_known_hosts = f"/proc/self/fd/{known_hosts_fd}"
    cmd = [SSH_BINARY, "-F", "/dev/null", "-T",
           "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={fd_known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
           "-o", f"HostKeyAlias={_AUTHORIZED_SSH_IP}", "-o", "CheckHostIP=yes", "-o", "UpdateHostKeys=no",
           "-o", "KnownHostsCommand=none", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
           "-o", "PermitLocalCommand=no", _AUTHORIZED_SSH_DESTINATION, remote_command]
    safe_env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                "LC_ALL": "C", "LANG": "C"}
    try:
        # Re-read and verify the named path immediately before invocation. OpenSSH
        # consumes the inherited descriptor, so a later rename/symlink swap cannot alter the pin.
        check_fd, check_bytes, check_identity = _read_pinned_known_hosts(known_hosts_path)
        os.close(check_fd)
        if check_bytes != known_hosts_bytes or check_identity != host_identity or sha(check_bytes) != pinned_hash:
            raise Refusal("pinned known_hosts changed between validation and SSH invocation")
        result = runner(cmd, input=collector_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        check=False, timeout=30, env=safe_env, pass_fds=(known_hosts_fd,))
    finally:
        os.close(known_hosts_fd)
    if getattr(result, "returncode", 1) != 0:
        raise Refusal("remote unsigned acquisition failed")
    raw = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode()
    unsigned = validate_unsigned(raw, collector_hash=collector_hash, backend_hash=backend_hash,
                                  expected_hostname=expected_hostname, session_nonce=nonce)
    payload = {"schema": "fk0957-signed-identity-evidence", "version": 1,
               "unsigned_evidence": unsigned,
               "provenance": {"ssh_destination": _AUTHORIZED_SSH_DESTINATION,
                              "ssh_host_key_algorithm": host_identity["algorithm"],
                              "ssh_host_key_sha256": host_identity["fingerprint"],
                              "pinned_known_hosts_sha256": pinned_hash,
                              "collector_reported_hostname_SELF_REPORTED": unsigned["remote_hostname"],
                              "collector_source_sha256": collector_hash, "backend_source_sha256": backend_hash,
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
                         "collector_source_sha256", "backend_source_sha256",
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
    if evidence["signature_algorithm"] != "Ed25519" or evidence["payload_sha256"] != sha(encoded):
        raise Refusal("signed evidence digest or algorithm mismatch")
    try:
        public_key.verify(bytes.fromhex(evidence["signature_hex"]), encoded)
    except Exception as exc:
        raise Refusal("signed evidence verification failed") from exc
    return True


# Updated to the reviewed collector bytes after implementation; prevents a
# mutable collector replacement from being sent to the authorized host.
COLLECTOR_PIN = "4ce9604d4ea6986282b6fc468c0dda60383aebe49eed40d8f13d4e0ef7644240"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signing-key", required=True, type=Path, help="local Ed25519 PEM key")
    parser.add_argument("--known-hosts", required=True, type=Path,
                        help="owner-only pinned known_hosts file dedicated to the authorized testbench")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-hostname", required=True,
                        help="pre-established hostname expected from the authorized SSH destination")
    parser.add_argument("--remote-repo", required=True,
                        help="testbench checkout containing the pinned observer and backend")
    args = parser.parse_args(argv)
    try:
        evidence = acquire_and_sign(args.signing_key, known_hosts_path=args.known_hosts,
                                    expected_hostname=args.expected_hostname,
                                    remote_repo=args.remote_repo)
        write_evidence_atomic(args.output, canonical(evidence) + b"\n")
    except (Refusal, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
