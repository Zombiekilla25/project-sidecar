#!/usr/bin/env python3
"""Local-only validation and Ed25519 signing for remote unsigned FK0957 evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
from typing import Callable

import phk2_fk0957_identity_observer as observer

HOST = "rmann@192.168.1.173"
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
    if value["remote_hostname"] != expected_hostname:
        raise Refusal("remote hostname mismatch")
    if not isinstance(expected_hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", expected_hostname):
        raise Refusal("hostname is malformed")
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


def acquire_and_sign(key_path: Path, *, runner: Callable = subprocess.run,
                     expected_hostname: str, remote_repo: str) -> dict:
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
    remote_command = (f"cd -- {shlex.quote(remote_repo)} && "
                     f"FK0957_TARGET=FK0957 python3 - {collector_hash} {nonce}")
    cmd = ["ssh", "-T", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
           "-o", "PermitLocalCommand=no", HOST, remote_command]
    safe_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "")}
    result = runner(cmd, input=collector_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30, env=safe_env)
    if getattr(result, "returncode", 1) != 0:
        raise Refusal("remote unsigned acquisition failed")
    raw = result.stdout if isinstance(result.stdout, bytes) else str(result.stdout).encode()
    unsigned = validate_unsigned(raw, collector_hash=collector_hash, backend_hash=backend_hash,
                                  expected_hostname=expected_hostname, session_nonce=nonce)
    payload = {"schema": "fk0957-signed-identity-evidence", "version": 1,
               "unsigned_evidence": unsigned,
               "provenance": {"ssh_target": HOST, "remote_hostname": unsigned["remote_hostname"],
                              "collector_source_sha256": collector_hash, "backend_source_sha256": backend_hash,
                              "source_commit": unsigned["source_commit"],
                              "acquisition_timestamp": unsigned["acquisition_timestamp"],
                              "session_nonce": nonce, "raw_unsigned_sha256": sha(raw)}}
    encoded = canonical(payload)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
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
    provenance_fields = {"ssh_target", "remote_hostname", "collector_source_sha256", "backend_source_sha256",
                         "source_commit", "acquisition_timestamp", "session_nonce", "raw_unsigned_sha256"}
    if (payload["schema"] != "fk0957-signed-identity-evidence" or payload["version"] != 1 or
            not isinstance(unsigned, dict) or set(unsigned) != EXPECTED_FIELDS or
            not isinstance(provenance, dict) or set(provenance) != provenance_fields):
        raise Refusal("signed payload fields malformed")
    expected_provenance = {"ssh_target": HOST, "remote_hostname": unsigned.get("remote_hostname"),
                           "collector_source_sha256": unsigned.get("collector_source_sha256"),
                           "backend_source_sha256": unsigned.get("backend_source_sha256"),
                           "source_commit": unsigned.get("source_commit"),
                           "acquisition_timestamp": unsigned.get("acquisition_timestamp"),
                           "session_nonce": unsigned.get("session_nonce"),
                           "raw_unsigned_sha256": sha(canonical(unsigned) + b"\n")}
    if provenance != expected_provenance:
        raise Refusal("signed provenance binding mismatch")
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
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-hostname", required=True,
                        help="pre-established hostname expected from the authorized SSH destination")
    parser.add_argument("--remote-repo", required=True,
                        help="testbench checkout containing the pinned observer and backend")
    args = parser.parse_args(argv)
    try:
        evidence = acquire_and_sign(args.signing_key, expected_hostname=args.expected_hostname,
                                    remote_repo=args.remote_repo)
        args.output.write_bytes(canonical(evidence) + b"\n")
    except (Refusal, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
