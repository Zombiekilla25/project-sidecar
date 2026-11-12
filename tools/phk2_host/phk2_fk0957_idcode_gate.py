"""Mockable policy gate for a single FK0957 IDCODE-only qualification.

This module contains no USB/JTAG transport and no command-line entry point.
It validates signed descriptor evidence and passes a fixed, immutable permit
to an injected transport. A live transport requires separate review/pinning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Protocol

import phk2_fk0957_remote_orchestrator as orchestrator

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
EXPECTED_CHAIN_WORDS = (EXPECTED_IDCODE, 0)
_AUTHORIZATION_TOKEN = object()


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
    operation: str = "ONE_FIXED_IDCODE_READ"
    tap_reset_tms: tuple[int, ...] = TAP_RESET_TMS
    ir_opcode: int = IDCODE_IR_OPCODE
    ir_bits: int = IDCODE_IR_BITS
    dr_bits: int = IDCODE_DR_BITS
    tck_cycle_limit: int = IDCODE_TCK_CYCLES
    _token: Any = field(default=None, init=False, repr=False, compare=False)


class FixedIdcodeTransport(Protocol):
    def read_fk0957_idcode_once(self, permit: ReadPermit) -> Mapping[str, Any]: ...


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


def authorize_descriptor(raw_evidence: bytes, *, expected_sha256: str,
                         public_key: Any, now: datetime | None = None) -> ReadPermit:
    """Verify signed, fresh FK0957 descriptor evidence and create fixed permit."""
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
        orchestrator.verify_signed(document, public_key)
    except Exception as exc:
        raise Refusal("descriptor signature invalid") from exc

    payload = document["payload"]
    evidence = payload["unsigned_evidence"]
    provenance = payload["provenance"]
    if (evidence["target_selector"] != CARD_ID or evidence["adapter_serial"] != ADAPTER_SERIAL or
            evidence["usb_descriptor_serial"] != USB_DESCRIPTOR_SERIAL or
            evidence["fk0957_mapping"] != "153300000957" or evidence["ftdi_vid"] != "0403" or
            evidence["ftdi_pid"] != "6010" or evidence["interface"] != "A"):
        raise Refusal("descriptor identity does not bind exact FK0957 adapter")
    if any(type(evidence[name]) is not int or evidence[name] != 0
           for name in orchestrator.ZERO_FIELDS):
        raise Refusal("descriptor evidence mutation counters are nonzero or malformed")
    if (provenance["ssh_destination"] != "rmann@192.168.1.173" or
            provenance["execution_mode"] != "EPHEMERAL_REVIEWED_BUNDLE"):
        raise Refusal("descriptor provenance does not match authorized acquisition")
    stamp = _timestamp(evidence["acquisition_timestamp"])
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise Refusal("current time must include timezone")
    age = (current.astimezone(timezone.utc) - stamp).total_seconds()
    if age < -FUTURE_CLOCK_SKEW_SECONDS or age > MAX_DESCRIPTOR_AGE_SECONDS:
        raise Refusal("descriptor evidence is stale or future-dated")
    path = evidence["usb_path"]
    if not isinstance(path, str) or not re.fullmatch(r"[0-9]+(?:-[0-9]+(?:\.[0-9]+)*)", path):
        raise Refusal("descriptor USB path malformed")
    permit = ReadPermit(actual_sha, CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL,
                        path, "0403", "6010")
    object.__setattr__(permit, "_token", _AUTHORIZATION_TOKEN)
    return permit


_RESULT_FIELDS = {
    "schema", "descriptor_evidence_sha256", "operation", "card_id", "adapter_serial",
    "usb_descriptor_serial", "usb_path", "before_identity", "after_identity",
    "candidate_count", "device_handles_opened", "second_card_opened", "tap_reset_tms",
    "ir_opcode", "ir_bits", "dr_bits", "tck_cycles", "tap_state_after", "chain_words",
    "idcode", "target_part_family", "write_count", "reset_count", "program_count",
    "jtag_operations",
}
def validate_observation(permit: ReadPermit, result: Mapping[str, Any]) -> dict[str, Any]:
    """Strictly validate a fixed IDCODE-only result; never interpret DNA/image identity."""
    if not isinstance(result, Mapping) or set(result) != _RESULT_FIELDS:
        raise Refusal("IDCODE result schema malformed")
    expected_identity = {"card_id": permit.card_id, "adapter_serial": permit.adapter_serial,
                         "usb_descriptor_serial": permit.usb_descriptor_serial,
                         "usb_path": permit.usb_path}
    if (result["schema"] != "fk0957-fixed-idcode-observation-v1" or
            result["descriptor_evidence_sha256"] != permit.descriptor_evidence_sha256 or
            result["operation"] != permit.operation or
            result["before_identity"] != expected_identity or result["after_identity"] != expected_identity or
            any(result[name] != value for name, value in expected_identity.items())):
        raise Refusal("IDCODE result identity/evidence binding mismatch")
    if (type(result["candidate_count"]) is not int or result["candidate_count"] != 1 or
            type(result["device_handles_opened"]) is not int or result["device_handles_opened"] != 1 or
            result["second_card_opened"] is not False):
        raise Refusal("IDCODE result target-count/handle invariant failed")
    if (not isinstance(result["tap_reset_tms"], list) or
            any(type(bit) is not int for bit in result["tap_reset_tms"]) or
            tuple(result["tap_reset_tms"]) != TAP_RESET_TMS or
            any(type(result[name]) is not int for name in ("ir_opcode", "ir_bits", "dr_bits", "tck_cycles")) or
            result["ir_opcode"] != IDCODE_IR_OPCODE or
            result["ir_bits"] != IDCODE_IR_BITS or result["dr_bits"] != IDCODE_DR_BITS or
            result["tck_cycles"] != IDCODE_TCK_CYCLES or result["tap_state_after"] != "RUN_TEST_IDLE"):
        raise Refusal("IDCODE result is not the fixed 87-cycle TAP sequence")
    if (not isinstance(result["chain_words"], list) or
            any(type(word) is not int for word in result["chain_words"]) or
            result["chain_words"] != list(EXPECTED_CHAIN_WORDS) or
            result["idcode"] != EXPECTED_IDCODE_TEXT or
            result["target_part_family"] != EXPECTED_PART_FAMILY):
        raise Refusal("unexpected chain topology, IDCODE, or part family")
    if any(type(result[name]) is not int or result[name] != 0
           for name in ("write_count", "reset_count", "program_count", "jtag_operations")):
        raise Refusal("IDCODE result mutation or operation counters invalid")
    return dict(result)


def read_once(permit: ReadPermit, transport: FixedIdcodeTransport) -> dict[str, Any]:
    """Invoke one fixed read through an injected transport, then validate it."""
    if (not isinstance(permit, ReadPermit) or permit._token is not _AUTHORIZATION_TOKEN or
            permit.card_id != CARD_ID or permit.adapter_serial != ADAPTER_SERIAL or
            permit.usb_descriptor_serial != USB_DESCRIPTOR_SERIAL or
            permit.vid != "0403" or permit.pid != "6010" or
            permit.operation != "ONE_FIXED_IDCODE_READ" or
            permit.tap_reset_tms != TAP_RESET_TMS or permit.ir_opcode != IDCODE_IR_OPCODE or
            permit.ir_bits != IDCODE_IR_BITS or permit.dr_bits != IDCODE_DR_BITS or
            permit.tck_cycle_limit != IDCODE_TCK_CYCLES or
            not re.fullmatch(r"[0-9a-f]{64}", permit.descriptor_evidence_sha256) or
            not re.fullmatch(r"[0-9]+(?:-[0-9]+(?:\.[0-9]+)*)", permit.usb_path)):
        raise Refusal("invalid fixed IDCODE permit")
    result = transport.read_fk0957_idcode_once(permit)
    return validate_observation(permit, result)
