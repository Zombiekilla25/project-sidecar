"""RGB-only Ed25519 signer for independently validated remote acquisitions.

This module has no import or API for the physical FTDI transport. The testbench
deployment must omit this module and the RGB signing key.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator

LOCAL_SIGNING_KEY_PATH = Path(
    "/home/rmann/.local/share/sidecar/operator-keys/phk2-fk0957-evidence-20261111/"
    "phk2_fk0957_physical_evidence_ed25519_private.pem")


class Refusal(ValueError):
    pass


def perform_fk0957_topology_discovery_once(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Legacy API retained only to fail closed for stale callers."""
    raise Refusal("combined local acquisition and signing is disabled")


def sign_local_discovery_record(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Legacy API retained only to fail closed for stale callers."""
    raise Refusal("local physical-observation signing is disabled")


def _read_local_private_key(path: Path = LOCAL_SIGNING_KEY_PATH) -> bytes:
    parent_fd, name = orchestrator._open_path_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16 * 1024):
                raise Refusal("local signing key file rejected")
            raw = bytearray()
            while len(raw) <= 16 * 1024:
                block = os.read(fd, min(4096, 16 * 1024 + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(fd)
            if (len(raw) > 16 * 1024 or
                    (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise Refusal("local signing key changed during read")
            return bytes(raw)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _sign_validated_remote_record(record: dict[str, Any],
                                  ssh_provenance: dict[str, Any]) -> dict[str, Any]:
    """Internal signer. The only production caller is the RGB validator."""
    required_provenance = {
        "ssh_destination", "ssh_host_key_algorithm", "ssh_host_key_sha256",
        "pinned_known_hosts_sha256", "local_agent_available_to_ssh_client",
        "remote_agent_forwarding", "remote_process_state",
    }
    if (type(record) is not dict or
            record.get("schema") != "fk0957-unsigned-topology-acquisition-v1" or
            record.get("status") != "ACQUIRED" or
            any(type(record.get(k)) is not int or record[k] != 0
                for k in ("write_count", "reset_count", "program_count")) or
            type(record.get("jtag_operation_count")) is not int or record["jtag_operation_count"] != 1 or
            record.get("idcode_qualification_pass") is not False or
            record.get("card_id") != "FK0957" or
            record.get("adapter_serial") != "153300000957A" or
            record.get("usb_descriptor_serial") != "153300000957" or
            (record.get("scan_a_tck_count"), record.get("scan_b_tck_count"),
             record.get("total_tck_count")) != (591, 586, 1177) or
            type(ssh_provenance) is not dict or set(ssh_provenance) != required_provenance or
            ssh_provenance.get("ssh_destination") != "rmann@192.168.1.173" or
            ssh_provenance.get("local_agent_available_to_ssh_client") is not True or
            ssh_provenance.get("remote_agent_forwarding") is not False or
            ssh_provenance.get("remote_process_state") != "REMOTE_PROCESS_CONFIRMED_EXITED" or
            type(ssh_provenance.get("ssh_host_key_algorithm")) is not str or
            type(ssh_provenance.get("ssh_host_key_sha256")) is not str or
            not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", ssh_provenance["ssh_host_key_sha256"]) or
            type(ssh_provenance.get("pinned_known_hosts_sha256")) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", ssh_provenance["pinned_known_hosts_sha256"])):
        raise Refusal("remote acquisition record was not validated")
    raw_key = _read_local_private_key()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(raw_key, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError
        public_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        fingerprint = hashlib.sha256(public_der).hexdigest()
        if record.get("trusted_signer_fingerprint") != fingerprint:
            raise Refusal("RGB signing key does not match descriptor trust identity")
        unsigned_bytes = orchestrator.canonical(record)
        payload = {
            "schema": "fk0957-signed-topology-evidence-v1", "version": 1,
            "unsigned_acquisition": record,
            "unsigned_acquisition_sha256": hashlib.sha256(unsigned_bytes).hexdigest(),
            "ssh_provenance": ssh_provenance,
        }
        payload_bytes = orchestrator.canonical(payload)
        signature = key.sign(payload_bytes)
        identity_gate._trusted_signer().verify(signature, payload_bytes)
        return {"payload": payload, "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                "signature_algorithm": "Ed25519", "signature_hex": signature.hex(),
                "signer_fingerprint": fingerprint}
    except Refusal:
        raise
    except Exception:
        raise Refusal("RGB local signing failed") from None
