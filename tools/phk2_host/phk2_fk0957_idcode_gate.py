"""Offline policy and fixed transaction definition for future FK0957 IDCODE work.

There is deliberately no USB/JTAG transport, result ingestion API, signer for
physical observations, or command-line entry point in this module.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
from typing import Any, Mapping

import phk2_fk0957_remote_orchestrator as orchestrator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CARD_ID = "FK0957"
ADAPTER_SERIAL = "153300000957A"
USB_DESCRIPTOR_SERIAL = "153300000957"
EXPECTED_IDCODE = 0x04B69093
EXPECTED_IDCODE_TEXT = "04b69093"
EXPECTED_PART_FAMILY = "xcvu33p"
MAX_DESCRIPTOR_AGE_SECONDS = 600
FUTURE_CLOCK_SKEW_SECONDS = 30
TAP_RESET_TMS = (1, 1, 1, 1, 1, 0)
IDCODE_IR_OPCODE = 0x09
IDCODE_IR_BITS = 6
IDCODE_DR_BITS = 64
IDCODE_TCK_CYCLES = 87
# RFC 8410 SubjectPublicKeyInfo DER for the operator evidence signer. Pin both
# the public bytes and their digest here; no API accepts a replacement key.
TRUSTED_SIGNER_PUBLIC_DER_B64 = "MCowBQYDK2VwAyEAxB3T0C+ueYu4OpGHL7sQ11FXeanbOySr2zFBZKJikCo="
TRUSTED_SIGNER_FINGERPRINT_SHA256 = "8bc668e59192ed62070138bb70be70073b9757943697f039c9db9bd27b9ab9f9"
CAPTURE_EDGE = "BLOCKED: MPSSE TDO sample edge is not specified by retained reviewed source"
# Authorization is process-local and one-shot. A transport failure consumes
# the permit too; a new scan requires a fresh descriptor authorization call.
_AUTHORIZED_TOKENS: set[object] = set()
_CONSUMED_TOKENS: set[object] = set()


class Refusal(ValueError):
    """Descriptor binding or fixed IDCODE result failed validation."""


@dataclass(frozen=True)
class ReadPermit:
    descriptor_evidence_sha256: str
    card_id: str
    adapter_serial: str
    usb_descriptor_serial: str
    usb_path: str
    vid: str
    pid: str
    manufacturer: str
    product: str
    interface: str
    permit_nonce: str
    operation: str = "ONE_FIXED_IDCODE_READ"
    tap_reset_tms: tuple[int, ...] = TAP_RESET_TMS
    ir_opcode: int = IDCODE_IR_OPCODE
    ir_bits: int = IDCODE_IR_BITS
    dr_bits: int = IDCODE_DR_BITS
    tck_cycle_limit: int = IDCODE_TCK_CYCLES
    _token: Any = field(default=None, init=False, repr=False, compare=False)


@dataclass(frozen=True)
class FixedTransaction:
    tms_bits: tuple[int, ...]
    tdi_bits: tuple[int, ...]
    initial_tap_state: str = "UNKNOWN"
    ir_value: int = IDCODE_IR_OPCODE
    ir_length: int = IDCODE_IR_BITS
    dr_length: int = IDCODE_DR_BITS
    bit_order: str = "LSB_FIRST"
    capture_edge: str = CAPTURE_EDGE
    final_tap_state: str = "RUN_TEST_IDLE"
    expected_tck_count: int = IDCODE_TCK_CYCLES


def fixed_transaction() -> FixedTransaction:
    """Construct the sole allowed semantic transaction; accepts no vectors."""
    tms = ((1, 1, 1, 1, 1, 0) + (1, 1, 0, 0) + (0, 0, 0, 0, 0, 1) +
           (1, 0) + (1, 0, 0) + (0,) * 63 + (1,) + (1, 0))
    # Six-bit 0x09 is shifted LSB first: 1,0,0,1,0,0. All other TDI clocks are zero.
    tdi = (0,) * 6 + (0,) * 4 + (1, 0, 0, 1, 0, 0) + (0,) * (2 + 3 + 64 + 2)
    if len(tms) != IDCODE_TCK_CYCLES or len(tdi) != IDCODE_TCK_CYCLES:
        raise AssertionError("internal fixed IDCODE vector length mismatch")
    return FixedTransaction(tms, tdi)


def transaction_definition_sha256() -> str:
    txn = fixed_transaction()
    material = ("tms=" + "".join(map(str, txn.tms_bits)) + "\n" +
                "tdi=" + "".join(map(str, txn.tdi_bits)) + "\n" +
                f"ir={txn.ir_value}/{txn.ir_length};dr={txn.dr_length};" +
                f"order={txn.bit_order};capture={txn.capture_edge};" +
                f"cycles={txn.expected_tck_count};initial={txn.initial_tap_state};" +
                f"final={txn.final_tap_state};expected_idcode={EXPECTED_IDCODE_TEXT}\n")
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def _trusted_signer() -> Ed25519PublicKey:
    der = base64.b64decode(TRUSTED_SIGNER_PUBLIC_DER_B64, validate=True)
    if hashlib.sha256(der).hexdigest() != TRUSTED_SIGNER_FINGERPRINT_SHA256:
        raise Refusal("pinned descriptor signer identity is internally inconsistent")
    key = serialization.load_der_public_key(der)
    if not isinstance(key, Ed25519PublicKey):
        raise Refusal("pinned descriptor signer is not Ed25519")
    return key


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise Refusal("descriptor timestamp malformed")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal("descriptor timestamp malformed") from exc
    if stamp.tzinfo is None:
        raise Refusal("descriptor timestamp must include timezone")
    return stamp.astimezone(timezone.utc)


def _validate_descriptor_payload(evidence: Mapping[str, Any], provenance: Mapping[str, Any]) -> str:
    if (evidence["target_selector"] != CARD_ID or evidence["adapter_serial"] != ADAPTER_SERIAL or
            evidence["usb_descriptor_serial"] != USB_DESCRIPTOR_SERIAL or
            evidence["fk0957_mapping"] != "153300000957" or evidence["ftdi_vid"] != "0403" or
            evidence["ftdi_pid"] != "6010" or evidence["manufacturer"] != "Xilinx" or
            evidence["product"] != "SQRL FK" or evidence["interface"] != "A"):
        raise Refusal("descriptor identity does not bind exact FK0957 adapter")
    if any(type(evidence[name]) is not int or evidence[name] != 0
           for name in orchestrator.ZERO_FIELDS):
        raise Refusal("descriptor evidence mutation counters are nonzero or malformed")
    if (provenance["ssh_destination"] != "rmann@192.168.1.173" or
            provenance["execution_mode"] != "EPHEMERAL_REVIEWED_BUNDLE"):
        raise Refusal("descriptor provenance does not match authorized acquisition")
    stamp = _timestamp(evidence["acquisition_timestamp"])
    current = datetime.now(timezone.utc)
    age = (current - stamp).total_seconds()
    if age < -FUTURE_CLOCK_SKEW_SECONDS or age > MAX_DESCRIPTOR_AGE_SECONDS:
        raise Refusal("descriptor evidence is stale or future-dated")
    path = evidence["usb_path"]
    if not isinstance(path, str) or not re.fullmatch(r"[0-9]+(?:-[0-9]+(?:\.[0-9]+)*)", path):
        raise Refusal("descriptor USB path malformed")
    return path


def authorize_descriptor(raw_evidence: bytes, *, expected_sha256: str) -> ReadPermit:
    """Verify exact-hash, trusted-signer, fresh FK0957 evidence; accept no key argument."""
    if not isinstance(raw_evidence, bytes) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise Refusal("descriptor evidence binding malformed")
    actual_sha = hashlib.sha256(raw_evidence).hexdigest()
    if actual_sha != expected_sha256:
        raise Refusal("descriptor evidence SHA256 mismatch")
    try:
        document = json.loads(raw_evidence)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("descriptor evidence JSON malformed") from exc
    try:
        orchestrator.verify_signed(document, _trusted_signer())
    except Exception as exc:
        raise Refusal("descriptor signature invalid") from exc
    if not isinstance(document.get("payload"), dict):
        raise Refusal("descriptor payload malformed")
    payload = document["payload"]
    evidence = payload.get("unsigned_evidence")
    provenance = payload.get("provenance")
    if not isinstance(evidence, dict) or not isinstance(provenance, dict):
        raise Refusal("descriptor payload fields malformed")
    path = _validate_descriptor_payload(evidence, provenance)
    permit = ReadPermit(actual_sha, CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL,
                        path, "0403", "6010", "Xilinx", "SQRL FK", "A",
                        secrets.token_hex(32))
    token = object()
    object.__setattr__(permit, "_token", token)
    _AUTHORIZED_TOKENS.add(token)
    return permit


def _consume_permit(permit: ReadPermit) -> None:
    """One-shot claim for a future in-process adapter, before any transport call."""
    if (not isinstance(permit, ReadPermit) or permit._token not in _AUTHORIZED_TOKENS or
            permit._token in _CONSUMED_TOKENS or
            not re.fullmatch(r"[0-9a-f]{64}", permit.permit_nonce) or
            permit.card_id != CARD_ID or permit.adapter_serial != ADAPTER_SERIAL or
            permit.usb_descriptor_serial != USB_DESCRIPTOR_SERIAL or permit.vid != "0403" or
            permit.pid != "6010" or permit.manufacturer != "Xilinx" or
            permit.product != "SQRL FK" or permit.interface != "A" or
            permit.operation != "ONE_FIXED_IDCODE_READ" or permit.tap_reset_tms != TAP_RESET_TMS or
            permit.ir_opcode != IDCODE_IR_OPCODE or permit.ir_bits != IDCODE_IR_BITS or
            permit.dr_bits != IDCODE_DR_BITS or permit.tck_cycle_limit != IDCODE_TCK_CYCLES):
        raise Refusal("invalid, altered, or replayed fixed IDCODE permit")
    _CONSUMED_TOKENS.add(permit._token)
