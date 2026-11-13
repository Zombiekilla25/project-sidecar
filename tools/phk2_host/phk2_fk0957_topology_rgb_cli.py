"""RGB-only entrypoint for a remote unsigned FK0957 topology acquisition.

This command accepts a canonical, pre-authorized request artifact.  It does
not accept scan vectors, a host override, or a transport/backend selector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as canonical_json
import phk2_fk0957_topology_live_cli as evidence_cli
import phk2_fk0957_topology_rgb_orchestrator as rgb

MAX_REQUEST_BYTES = 512 * 1024


def _read_request(path: Path) -> bytes:
    parent_fd, name = canonical_json._open_path_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_size < 1 or before.st_size > MAX_REQUEST_BYTES):
                raise ValueError("request file rejected")
            chunks = bytearray()
            while len(chunks) <= MAX_REQUEST_BYTES:
                block = os.read(fd, min(65536, MAX_REQUEST_BYTES + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            after = os.fstat(fd)
            if (len(chunks) > MAX_REQUEST_BYTES or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError("request file changed while reading")
            return bytes(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _verify_signed_remote_result(document: object) -> dict:
    if (type(document) is not dict or set(document) != {
            "payload", "payload_sha256", "signature_algorithm", "signature_hex", "signer_fingerprint"} or
            document.get("signature_algorithm") != "Ed25519" or
            document.get("signer_fingerprint") != identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256):
        raise ValueError("signed result envelope rejected")
    payload = document["payload"]
    if type(payload) is not dict or set(payload) != {
            "schema", "version", "unsigned_acquisition", "unsigned_acquisition_sha256", "ssh_provenance"} or \
            payload.get("schema") != "fk0957-signed-topology-evidence-v1" or \
            type(payload.get("version")) is not int or payload["version"] != 1:
        raise ValueError("signed result payload rejected")
    encoded = canonical_json.canonical(payload)
    if hashlib.sha256(encoded).hexdigest() != document.get("payload_sha256"):
        raise ValueError("signed result digest rejected")
    signature_hex = document.get("signature_hex")
    if type(signature_hex) is not str or len(signature_hex) != 128:
        raise ValueError("signed result signature rejected")
    try:
        identity_gate._trusted_signer().verify(bytes.fromhex(signature_hex), encoded)
    except Exception:
        raise ValueError("signed result signature rejected") from None
    unsigned = payload["unsigned_acquisition"]
    if type(unsigned) is not dict:
        raise ValueError("unsigned acquisition schema rejected")
    unsigned_bytes = canonical_json.canonical(unsigned)
    if hashlib.sha256(unsigned_bytes).hexdigest() != payload["unsigned_acquisition_sha256"]:
        raise ValueError("unsigned acquisition digest rejected")
    provenance = payload["ssh_provenance"]
    if (type(provenance) is not dict or set(provenance) != {
            "ssh_destination", "ssh_host_key_algorithm", "ssh_host_key_sha256",
            "pinned_known_hosts_sha256", "local_agent_available_to_ssh_client",
            "remote_agent_forwarding", "remote_process_state"} or
            provenance.get("remote_agent_forwarding") is not False or
            provenance.get("local_agent_available_to_ssh_client") is not True or
            provenance.get("remote_process_state") != "REMOTE_PROCESS_CONFIRMED_EXITED" or
            provenance.get("ssh_destination") != "rmann@192.168.1.173"):
        raise ValueError("SSH provenance rejected")
    return unsigned


def run_once(request_path: Path, evidence_path: Path) -> tuple[bytes, int, bool]:
    try:
        request = _read_request(request_path)
        signed = rgb.acquire_validate_sign_once(request)
        unsigned = _verify_signed_remote_result(signed)
        evidence = canonical_json.canonical(signed)
        summary = evidence_cli._success_summary(unsigned, evidence_path,
                                                hashlib.sha256(evidence).hexdigest())
        summary_bytes = canonical_json.canonical(summary)
        published = ["SIGNED_STAGED"]
        evidence_cli._publish_evidence_atomic(evidence_path, evidence, published)
        return summary_bytes, 0, True
    except BaseException:
        # A published record is a committed acquisition and can never become
        # REFUSED due to subsequent status formatting or pipe failures.
        if "published" in locals() and published[0] == "EVIDENCE_PUBLISHED":
            return b"FK0957_POST_SUCCESS_REPORTING_FAULT=YES EVIDENCE_PUBLISHED=YES\n", 3, True
        return b"FK0957_STATUS=REFUSED CODE=REMOTE_RGB_FLOW_FAILED EVIDENCE_PATH=none SIGNATURE_VERIFIED=NO\n", 2, False


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ValueError("invalid arguments")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(prog="fk0957_topology_rgb_one_shot")
    parser.add_argument("--authorization-request", required=True)
    parser.add_argument("--output", required=True)
    try:
        args = parser.parse_args(argv)
    except BaseException:
        report, status, published = (b"FK0957_STATUS=REFUSED CODE=INVALID_ARGUMENTS EVIDENCE_PATH=none SIGNATURE_VERIFIED=NO\n", 2, False)
    else:
        report, status, published = run_once(Path(args.authorization_request), Path(args.output))
    try:
        sys.stdout.buffer.write(report)
        sys.stdout.buffer.flush()
    except BaseException:
        if published:
            return 3
    return status


if __name__ == "__main__":
    raise SystemExit(main())
