"""Narrow one-shot local CLI for FK0957 topology discovery.

The command accepts only signed descriptor evidence and a local evidence
destination. Physical selection and both fixed scans remain internal to the
reviewed transport module. This module has no remote command or scan options.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Sequence

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator
import phk2_fk0957_topology_transport as transport

MAX_DESCRIPTOR_BYTES = 1024 * 1024
_ENVELOPE_KEYS = frozenset({
    "status", "phase", "code", "evidence_path", "signature_verified",
    "return_code", "target_candidates", "device_opened", "scan_a_started",
    "scan_a_tck_emitted", "scan_b_started", "scan_b_tck_emitted",
    "transport_closed", "permit_consumed",
})


def _read_descriptor(path: Path) -> bytes:
    parent_fd, name = orchestrator._open_path_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_size < 1 or info.st_size > MAX_DESCRIPTOR_BYTES):
                raise ValueError("descriptor evidence file rejected")
            chunks = bytearray()
            while len(chunks) <= MAX_DESCRIPTOR_BYTES:
                block = os.read(fd, min(65536, MAX_DESCRIPTOR_BYTES + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if not chunks or len(chunks) > MAX_DESCRIPTOR_BYTES:
                raise ValueError("descriptor evidence size rejected")
            after = os.fstat(fd)
            if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError("descriptor evidence changed while reading")
            return bytes(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _fallback_refusal(phase: str, code: str) -> bytes:
    trace = transport._AttemptTrace()
    trace.phase = phase
    trace.permit_consumed = 0 if phase in ("PRELIVE_VALIDATION", "PERMIT_VALIDATION") else "unknown"
    return trace.refuse(code=code, phase=phase).canonical_envelope()


def _bounded_envelope(value: Any) -> bool:
    if (not isinstance(value, dict) or set(value) != _ENVELOPE_KEYS or
            value.get("status") != "REFUSED" or
            value.get("phase") not in transport.REFUSAL_PHASES or
            value.get("code") not in transport.REFUSAL_CODES or
            value.get("evidence_path") != "none" or
            value.get("signature_verified") is not False):
        return False
    rc = value.get("return_code")
    if rc is not None and (type(rc) is not int or not -255 <= rc <= 255):
        return False
    candidates = value.get("target_candidates")
    if candidates != "unknown" and (type(candidates) is not int or not 0 <= candidates <= 1177):
        return False
    opened = value.get("device_opened")
    consumed = value.get("permit_consumed")
    if ((opened != "unknown" and (type(opened) is not int or opened not in (0, 1))) or
            (consumed != "unknown" and (type(consumed) is not int or consumed not in (0, 1)))):
        return False
    for key in ("scan_a_started", "scan_b_started", "transport_closed"):
        if type(value.get(key)) is not int or value[key] not in (0, 1):
            return False
    for key, limit in (("scan_a_tck_emitted", 591), ("scan_b_tck_emitted", 586)):
        item = value.get(key)
        if item != "unknown" and (type(item) is not int or not 0 <= item <= limit):
            return False
    if (value["scan_b_started"] and not value["scan_a_started"] or
            not value["scan_a_started"] and value["scan_a_tck_emitted"] not in (0, "unknown") or
            not value["scan_b_started"] and value["scan_b_tck_emitted"] not in (0, "unknown") or
            opened == 0 and (value["scan_a_started"] or value["scan_b_started"])):
        return False
    return True


def _safe_refusal(exc: BaseException) -> bytes:
    """Forward only a strictly validated canonical envelope; suppress all text."""
    if isinstance(exc, transport.Refusal):
        try:
            raw = exc.canonical_envelope()
            value = json.loads(raw)
            if not _bounded_envelope(value):
                raise ValueError("invalid refusal schema")
            return orchestrator.canonical(value)
        except Exception:
            pass
    return _fallback_refusal("INTERNAL_REFUSAL", "INTERNAL_REFUSAL")


def _verify_signed_record(document: Any) -> dict[str, Any]:
    if (not isinstance(document, dict) or
            set(document) != {"payload", "payload_sha256", "signature_algorithm",
                              "signature_hex", "signer_fingerprint"} or
            document.get("signature_algorithm") != "Ed25519" or
            document.get("signer_fingerprint") != identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256):
        raise ValueError("signed record envelope rejected")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("signed record payload rejected")
    payload_bytes = orchestrator.canonical(payload)
    if hashlib.sha256(payload_bytes).hexdigest() != document.get("payload_sha256"):
        raise ValueError("signed record digest rejected")
    signature_hex = document.get("signature_hex")
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        raise ValueError("signed record signature encoding rejected")
    try:
        signature = bytes.fromhex(signature_hex)
        identity_gate._trusted_signer().verify(signature, payload_bytes)
    except Exception as exc:
        raise ValueError("signed record signature rejected") from exc
    required = {
        "topology_discovery_only": True,
        "idcode_qualification_pass": False,
        "fpga_dna_observed": False,
        "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
        "card_id": "FK0957",
        "adapter_serial": "153300000957A",
        "usb_descriptor_serial": "153300000957",
        "scan_a_tck_count": 591,
        "scan_b_tck_count": 586,
        "total_tck_count": 1177,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
    }
    if any(payload.get(key) != value for key, value in required.items()):
        raise ValueError("signed record policy fields rejected")
    return payload


def _success_summary(payload: dict[str, Any], evidence_path: Path,
                     evidence_sha256: str) -> dict[str, Any]:
    try:
        raw_a = bytes.fromhex(payload["scan_a_raw_tdo_hex"])
        raw_b = bytes.fromhex(payload["scan_b_raw_tdo_hex"])
        scan_a_tx = payload["scan_a_transaction_sha256"]
        scan_b_tx = payload["scan_b_transaction_sha256"]
        for digest in (scan_a_tx, scan_b_tx):
            if (not isinstance(digest, str) or len(digest) != 64 or
                    any(ch not in "0123456789abcdef" for ch in digest)):
                raise ValueError
    except Exception as exc:
        raise ValueError("signed record observation fields rejected") from exc
    parsed = payload.get("aggregate_dr_length") is not None and isinstance(
        payload.get("observed_taps_tdo_to_tdi"), list)
    return {
        "status": "SIGNED",
        "target": "FK0957",
        "scan_a_tck_count": 591,
        "scan_b_tck_count": 586,
        "total_tck_count": 1177,
        "scan_a_transaction_sha256": scan_a_tx,
        "scan_b_transaction_sha256": scan_b_tx,
        "scan_a_raw_tdo_bytes": len(raw_a),
        "scan_a_raw_tdo_sha256": hashlib.sha256(raw_a).hexdigest(),
        "scan_b_raw_tdo_bytes": len(raw_b),
        "scan_b_raw_tdo_sha256": hashlib.sha256(raw_b).hexdigest(),
        "parse_status": "PASS" if parsed else "INCONCLUSIVE",
        "evidence_path": str(evidence_path),
        "evidence_sha256": evidence_sha256,
        "signature_verified": True,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
        "jtag_operation_count": 1,
    }


def run_once(descriptor_path: Path, output_path: Path) -> tuple[bytes, int]:
    try:
        descriptor = _read_descriptor(descriptor_path)
        descriptor_sha256 = hashlib.sha256(descriptor).hexdigest()
    except Exception:
        return _fallback_refusal("PRELIVE_VALIDATION", "INTERNAL_REFUSAL") + b"\n", 2

    try:
        signed = transport.perform_fk0957_topology_discovery_once(
            descriptor, descriptor_sha256)
    except BaseException as exc:
        return _safe_refusal(exc) + b"\n", 2

    try:
        payload = _verify_signed_record(signed)
        evidence_bytes = orchestrator.canonical(signed) + b"\n"
        orchestrator.write_evidence_atomic(output_path, evidence_bytes)
        summary = _success_summary(payload, output_path, hashlib.sha256(evidence_bytes).hexdigest())
        return orchestrator.canonical(summary) + b"\n", 0
    except BaseException:
        return _fallback_refusal("LOCAL_VALIDATION", "LOCAL_VALIDATION_FAILED") + b"\n", 2


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: D401 - suppress argparse internals
        raise ValueError("invalid operator arguments")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _ArgumentParser(prog="fk0957_topology_live_one_shot")
    parser.add_argument("--descriptor-evidence", required=True,
                        help="path to fresh signed FK0957 descriptor evidence")
    parser.add_argument("--output", required=True,
                        help="local path for the signed topology-discovery record")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    except Exception:
        sys.stdout.buffer.write(_fallback_refusal("PRELIVE_VALIDATION", "INTERNAL_REFUSAL") + b"\n")
        return 2
    output, status = run_once(Path(args.descriptor_evidence), Path(args.output))
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
