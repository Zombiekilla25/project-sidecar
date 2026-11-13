"""RGB-only Ed25519 signing for FK0957 topology observations.

This module is deliberately separate from the testbench physical transport.
Remote deployment bundles must omit it and the RGB private signing key.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
from typing import Any

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator
import phk2_fk0957_topology_discovery as topology
import phk2_fk0957_topology_transport as transport
from phk2_fk0957_topology_transport import (
    Refusal, TransportObservation, _AttemptTrace, _RESULT_LOCK, _SIGNED_PERMITS,
    _diagnostic_refusal, _permit_consumption_state, _trace_from_sealed_result,
)

LOCAL_SIGNING_KEY_PATH = Path(
    "/home/rmann/.local/share/sidecar/operator-keys/phk2-fk0957-evidence-20261111/"
    "phk2_fk0957_physical_evidence_ed25519_private.pem")

def _read_local_private_key(path: Path) -> bytes:
    parent_fd, name = orchestrator._open_path_parent(path)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
                raise Refusal("local signing key must be regular, mode 0600, and single-link")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(16 * 1024 + 1)
                if len(raw) > 16 * 1024:
                    raise Refusal("local signing key file exceeds the bounded PEM size")
                return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _sign_local_discovery_record(permit: topology.DiscoveryPermit,
                                 result: TransportObservation,
                                 trace: _AttemptTrace | None = None) -> dict[str, Any]:
    """Validate the complete raw observation, then sign locally on RGB only."""
    parsed = transport.validate_transport_observation(permit, result)
    if trace is not None:
        trace.advance("LOCAL_VALIDATED")
    with _RESULT_LOCK:
        if permit._token in _SIGNED_PERMITS:
            raise Refusal("local topology record already signed for this permit")
        _SIGNED_PERMITS.add(permit._token)
    record = {
        "schema": "fk0957-topology-discovery-record-v1",
        "topology_discovery_only": True,
        "idcode_qualification_pass": False,
        "fpga_dna_observed": False,
        "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
        "card_id": result.card_id,
        "adapter_serial": result.adapter_serial,
        "usb_descriptor_serial": result.usb_descriptor_serial,
        "physical_interface": result.physical_interface,
        "descriptor_evidence_sha256": result.descriptor_evidence_sha256,
        "permit_nonce": result.permit_nonce,
        "permit_issued_at": permit.issued_at,
        "permit_expires_at": permit.expires_at,
        "observation_timestamp": datetime.now(timezone.utc).isoformat(),
        "usb_path": result.usb_path,
        "ftdi_vid": result.ftdi_vid,
        "ftdi_pid": result.ftdi_pid,
        "manufacturer": result.manufacturer,
        "product": result.product,
        "trusted_signer_fingerprint": permit.trusted_signer_fingerprint,
        "transport_source_sha256": result.transport_source_sha256,
        "production_git_head": result.production_git_head,
        "worktree_clean": result.worktree_clean,
        "runtime_library_provenance": [
            {"logical_name": row[0], "approved_path": row[1], "expected_sha256": row[2],
             "expected_build_id": row[3], "soname": row[4], "preload_stat": row[5],
             "postload_stat": row[6], "loaded_object_realpath": row[7]}
            for row in result.runtime_library_provenance],
        "scan_a_transaction_sha256": result.scan_a_transaction_sha256,
        "scan_a_tck_count": result.scan_a_tck_count,
        "scan_a_raw_tdo_hex": result.scan_a_raw_tdo.hex(),
        "scan_b_transaction_sha256": result.scan_b_transaction_sha256,
        "scan_b_tck_count": result.scan_b_tck_count,
        "scan_b_raw_tdo_hex": result.scan_b_raw_tdo.hex(),
        "total_tck_count": result.total_tck_count,
        "matched_device_count": result.matched_device_count,
        "opened_device_count": result.opened_device_count,
        "second_device_opened": result.second_device_opened,
        "aggregate_dr_length": parsed.aggregate_dr_length,
        "observed_taps_tdo_to_tdi": parsed.taps_tdo_to_tdi,
        "raw_tdo_scan_a_bits_lsb_first": parsed.raw_tdo_scan_a_bits,
        "raw_tdo_scan_b_bits_lsb_first": parsed.raw_tdo_scan_b_bits,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
    }
    raw_key = _read_local_private_key(LOCAL_SIGNING_KEY_PATH)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(raw_key, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("not Ed25519")
        public_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        signer_fingerprint = hashlib.sha256(public_der).hexdigest()
        if signer_fingerprint != permit.trusted_signer_fingerprint:
            raise Refusal("local key does not match trusted descriptor signer")
        payload_bytes = orchestrator.canonical(record)
        signature = key.sign(payload_bytes)
        identity_gate._trusted_signer().verify(signature, payload_bytes)
        if trace is not None:
            trace.advance("SIGNED_STAGED")
    except Refusal:
        raise
    except Exception as exc:
        raise Refusal("local topology record signing or verification failed") from exc
    return {"payload": record, "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "signature_algorithm": "Ed25519", "signature_hex": signature.hex(),
            "signer_fingerprint": permit.trusted_signer_fingerprint}


def sign_local_discovery_record(permit: topology.DiscoveryPermit,
                                result: TransportObservation) -> dict[str, Any]:
    trace = _AttemptTrace()
    trace.phase = "LOCAL_SIGNING"
    trace.permit_consumed = _permit_consumption_state(permit)
    _trace_from_sealed_result(trace, result)
    try:
        return _sign_local_discovery_record(permit, result, trace)
    except BaseException as exc:
        if isinstance(exc, Refusal) and exc.envelope is not None:
            raise
        if trace.operation_state == "TRANSPORT_CLOSED":
            trace.phase = "LOCAL_VALIDATION"
        raise _diagnostic_refusal(exc, trace) from None


def perform_fk0957_topology_discovery_once(descriptor_evidence: bytes,
                                            expected_sha256: str) -> dict[str, Any]:
    """One-shot local workflow: authorize, acquire, validate, then sign; never writes a file."""
    trace = _AttemptTrace()
    trace.phase = "PERMIT_VALIDATION"
    trace.permit_consumed = 0
    try:
        permit = transport.issue_fk0957_topology_permit(descriptor_evidence, expected_sha256)
        trace.phase = "PERMIT_VALIDATION"
        trace.advance("PERMIT_VALIDATED")
        result = transport.run_fk0957_topology_discovery(permit)
        trace.permit_consumed = 1
        _trace_from_sealed_result(trace, result)
        trace.phase = "LOCAL_VALIDATION"
        transport.validate_transport_observation(permit, result)
        trace.advance("LOCAL_VALIDATED")
        trace.phase = "LOCAL_SIGNING"
        signed = sign_local_discovery_record(permit, result)
        trace.advance("SIGNED_STAGED")
        return signed
    except BaseException as exc:
        trace.permit_consumed = _permit_consumption_state(locals().get("permit"))
        raise _diagnostic_refusal(exc, trace) from None

