"""Fail-closed representation and validation for a future approved Case-B method.

This module supplies no TAP vectors, BSCAN opcode, expected response, or defaults.
An owner-signed method is usable only when its method hash/schema/response are
also pinned into the immutable Case-B qualification binding.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any

from physical_tck_preflight import Refusal

METHOD_SCHEMA = "PHK2-FK0957-CASE-B-METHOD-v1"
APPROVED_RECORD_SCHEMA = "PHK2-FK0957-CASE-B-APPROVED-METHOD-v1"
TAP_TRACE_SCHEMA = "PHK2-BSCAN-TAP-TRACE-v1"
PLACEHOLDERS = {"", "*", "tbd", "todo", "unknown", "unset", "placeholder", "experimental",
                "idcode_only", "default", "any", "all", "n/a", "none"}
TAP_STATES = {
    "TEST_LOGIC_RESET", "RUN_TEST_IDLE", "SELECT_DR_SCAN", "CAPTURE_DR", "SHIFT_DR",
    "EXIT1_DR", "PAUSE_DR", "EXIT2_DR", "UPDATE_DR", "SELECT_IR_SCAN", "CAPTURE_IR",
    "SHIFT_IR", "EXIT1_IR", "PAUSE_IR", "EXIT2_IR", "UPDATE_IR",
}
TAP_NEXT = {
    "TEST_LOGIC_RESET": ("RUN_TEST_IDLE", "TEST_LOGIC_RESET"),
    "RUN_TEST_IDLE": ("RUN_TEST_IDLE", "SELECT_DR_SCAN"),
    "SELECT_DR_SCAN": ("CAPTURE_DR", "SELECT_IR_SCAN"),
    "CAPTURE_DR": ("SHIFT_DR", "EXIT1_DR"),
    "SHIFT_DR": ("SHIFT_DR", "EXIT1_DR"),
    "EXIT1_DR": ("PAUSE_DR", "UPDATE_DR"),
    "PAUSE_DR": ("PAUSE_DR", "EXIT2_DR"),
    "EXIT2_DR": ("SHIFT_DR", "UPDATE_DR"),
    "UPDATE_DR": ("RUN_TEST_IDLE", "SELECT_DR_SCAN"),
    "SELECT_IR_SCAN": ("CAPTURE_IR", "TEST_LOGIC_RESET"),
    "CAPTURE_IR": ("SHIFT_IR", "EXIT1_IR"),
    "SHIFT_IR": ("SHIFT_IR", "EXIT1_IR"),
    "EXIT1_IR": ("PAUSE_IR", "UPDATE_IR"),
    "PAUSE_IR": ("PAUSE_IR", "EXIT2_IR"),
    "EXIT2_IR": ("SHIFT_IR", "UPDATE_IR"),
    "UPDATE_IR": ("RUN_TEST_IDLE", "SELECT_DR_SCAN"),
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Refusal("Case-B method contains non-canonical data") from exc


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _method_digest(method: dict[str, Any]) -> str:
    """Hash method content while avoiding a self-referential auth hash field."""
    material = json.loads(_canonical(method))
    material.get("authorization_binding", {}).pop("method_sha256", None)
    return _sha(_canonical(material))


def _exact_text(value: Any, label: str) -> str:
    if (not isinstance(value, str) or value.strip() != value or value.casefold() in PLACEHOLDERS or
            "*" in value or "?" in value):
        raise Refusal(f"Case-B authoritative field missing or placeholder: {label}")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise Refusal(f"Case-B {label} must be a lowercase SHA256")
    return value


def _bits(value: Any, label: str, *, exact_length: int | None = None) -> list[int]:
    if not isinstance(value, list) or not value:
        raise Refusal(f"Case-B {label} must be a complete nonempty bit vector")
    if any(isinstance(bit, bool) or bit not in (0, 1) for bit in value):
        raise Refusal(f"Case-B {label} contains a non-binary or wildcard value")
    if exact_length is not None and len(value) != exact_length:
        raise Refusal(f"Case-B {label} length does not equal the approved cycle/register length")
    return value


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Refusal(f"Case-B {label} is missing or malformed")
    return value


def _required(obj: dict[str, Any], names: tuple[str, ...], label: str) -> None:
    missing = [name for name in names if name not in obj]
    if missing:
        raise Refusal(f"Case-B {label} missing required fields: {', '.join(missing)}")


def _valid_window(issued_value: Any, expires_value: Any, now: datetime | None, label: str) -> None:
    try:
        issued = datetime.fromisoformat(_exact_text(issued_value, f"{label}.issued_utc").replace("Z", "+00:00"))
        expires = datetime.fromisoformat(_exact_text(expires_value, f"{label}.expires_utc").replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal(f"Case-B {label} validity window is malformed") from exc
    current = now or datetime.now(timezone.utc)
    if issued.tzinfo is None or expires.tzinfo is None or issued > current or expires <= current or expires <= issued:
        raise Refusal(f"Case-B {label} validity window is stale or invalid")


def validate_case_b_method_payload(payload: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Validate the complete method shape, without granting approval or authority."""
    _mapping(payload, "approved method record")
    _required(payload, ("schema", "provenance", "synthetic_fixture", "approval_status", "case_id",
                       "qualification_record_sha256", "method_sha256", "approved_utc", "expires_utc", "method"),
              "approved method record")
    if (payload["schema"] != APPROVED_RECORD_SCHEMA or payload["provenance"] != "QUALIFICATION_OWNER_APPROVED" or
            payload["synthetic_fixture"] is not False or payload["approval_status"] != "APPROVED" or
            payload["case_id"] != "33"):
        raise Refusal("Case-B method is not an authentic approved Case-B record")
    _digest(payload["qualification_record_sha256"], "qualification record hash")
    _digest(payload["method_sha256"], "method hash")
    _valid_window(payload["approved_utc"], payload["expires_utc"], now, "method")

    method = _mapping(payload["method"], "method")
    _required(method, ("schema", "case_id", "qualification_record_sha256", "source_commit", "source_tree_hash",
                       "routed_dcp_sha256", "loaded_image_sha256", "target_part", "target_identity", "tap",
                       "read_only", "read_only_proof", "physical_tck_correlation", "acquisition_provenance",
                       "authorization_binding", "validity", "evidence_contract"), "method")
    if method["schema"] != METHOD_SCHEMA or method["case_id"] != "33":
        raise Refusal("Case-B method schema/case binding mismatch; IDCODE-only or experimental method refused")
    for key in ("qualification_record_sha256", "routed_dcp_sha256", "loaded_image_sha256"):
        _digest(method[key], f"method.{key}")
    for key in ("source_commit", "source_tree_hash"):
        value = _exact_text(method[key], f"method.{key}")
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise Refusal(f"Case-B method.{key} is malformed")
    _exact_text(method["target_part"], "method.target_part")

    target = _mapping(method["target_identity"], "target_identity")
    _required(target, ("card_id", "adapter_id", "fpga_dna", "idcode", "target_part",
                       "jtag_chain_topology", "loaded_image_sha256"), "target_identity")
    for key, value in target.items():
        if key == "loaded_image_sha256":
            _digest(value, f"target_identity.{key}")
        else:
            _exact_text(value, f"target_identity.{key}")
    if target["loaded_image_sha256"] != method["loaded_image_sha256"]:
        raise Refusal("Case-B method target identity and loaded-image hashes differ")

    tap = _mapping(method["tap"], "tap")
    _required(tap, ("initial_state", "reset_procedure", "selection", "tms_vector", "tdi_vector",
                    "cycle_count", "expected_transitions", "final_state", "expected_response"), "tap")
    if (not isinstance(tap["initial_state"], str) or tap["initial_state"] not in TAP_STATES or
            not isinstance(tap["final_state"], str) or tap["final_state"] not in TAP_STATES):
        raise Refusal("Case-B TAP initial/final state is not exact")
    reset = _mapping(tap["reset_procedure"], "tap.reset_procedure")
    _required(reset, ("description", "tms_vector", "tdi_vector", "cycle_count", "expected_transitions", "final_state"), "tap.reset_procedure")
    _exact_text(reset["description"], "tap.reset_procedure.description")
    reset_tms = _bits(reset["tms_vector"], "reset TMS vector")
    reset_tdi = _bits(reset["tdi_vector"], "reset TDI vector", exact_length=len(reset_tms))
    if isinstance(reset["cycle_count"], bool) or reset["cycle_count"] != len(reset_tms):
        raise Refusal("Case-B TAP reset cycle count/vector mismatch")
    if not isinstance(reset["final_state"], str) or reset["final_state"] not in TAP_STATES:
        raise Refusal("Case-B TAP reset final state missing")

    selection = _mapping(tap["selection"], "tap.selection")
    _required(selection, ("bscan_chain", "instruction_name", "ir_width_bits", "ir_opcode_bits_lsb_first", "data_register_name"), "tap.selection")
    chain = selection["bscan_chain"]
    if isinstance(chain, str):
        _exact_text(chain, "tap.selection.bscan_chain")
    elif isinstance(chain, bool) or not isinstance(chain, int) or chain <= 0:
        raise Refusal("Case-B BSCAN chain selection is invalid")
    instruction = _exact_text(selection["instruction_name"], "tap.selection.instruction_name")
    register = _exact_text(selection["data_register_name"], "tap.selection.data_register_name")
    if instruction.upper() == "IDCODE" or register.upper() == "IDCODE":
        raise Refusal("IDCODE-only evidence cannot satisfy Case B")
    width = selection["ir_width_bits"]
    if isinstance(width, bool) or not isinstance(width, int) or width < 1:
        raise Refusal("Case-B instruction register width missing")
    _bits(selection["ir_opcode_bits_lsb_first"], "instruction opcode", exact_length=width)

    tms = _bits(tap["tms_vector"], "complete TMS vector")
    tdi = _bits(tap["tdi_vector"], "complete TDI vector", exact_length=len(tms))
    count = tap["cycle_count"]
    transitions = tap["expected_transitions"]
    if isinstance(count, bool) or not isinstance(count, int) or count != len(tms) or not isinstance(transitions, list) or len(transitions) != count:
        raise Refusal("Case-B complete vectors, transitions, and exact cycle count disagree")
    if tms[:len(reset_tms)] != reset_tms or tdi[:len(reset_tdi)] != reset_tdi:
        raise Refusal("Case-B reset procedure is not the exact prefix of the complete TAP vector")
    state = tap["initial_state"]
    for index, row in enumerate(transitions):
        row = _mapping(row, f"expected_transitions[{index}]")
        _required(row, ("from", "tms", "to"), f"expected_transitions[{index}]")
        if (row["from"] != state or isinstance(row["tms"], bool) or
                row["tms"] != tms[index] or row["tms"] not in (0, 1)):
            raise Refusal("Case-B expected TAP transition does not match the approved vector/state")
        state = TAP_NEXT[state][row["tms"]]
        if row["to"] != state:
            raise Refusal("Case-B expected TAP transition table is inconsistent with the TAP FSM")
        if index < len(reset_tms):
            reset_row = reset["expected_transitions"]
            if not isinstance(reset_row, list) or len(reset_row) != len(reset_tms) or row != reset_row[index]:
                raise Refusal("Case-B reset transition table differs from the full sequence")
    reset_transitions = reset["expected_transitions"]
    if (not isinstance(reset_transitions, list) or not reset_transitions or
            state != tap["final_state"] or not isinstance(reset_transitions[-1], dict) or
            reset_transitions[-1].get("to") != reset["final_state"]):
        raise Refusal("Case-B declared final/reset TAP state is inconsistent")

    response = _mapping(tap["expected_response"], "tap.expected_response")
    _required(response, ("tdo_bits", "mask_bits", "bit_order", "sample_edge", "permitted_variation"), "tap.expected_response")
    expected_bits = _bits(response["tdo_bits"], "expected TDO response", exact_length=count)
    mask = _bits(response["mask_bits"], "approved TDO mask", exact_length=count)
    _exact_text(response["bit_order"], "expected response bit order")
    _exact_text(response["sample_edge"], "expected response sample edge")
    if not any(mask):
        raise Refusal("Case-B expected TDO response cannot be entirely wildcarded")
    if not all(mask):
        variation = _mapping(response["permitted_variation"], "permitted_variation")
        _required(variation, ("approved", "reason", "approval_id", "approval_sha256"), "permitted_variation")
        if variation["approved"] is not True:
            raise Refusal("Case-B response mask lacks explicit owner approval")
        _exact_text(variation["reason"], "permitted variation reason")
        _exact_text(variation["approval_id"], "permitted variation approval id")
        _digest(variation["approval_sha256"], "permitted variation approval hash")

    if method["read_only"] is not True:
        raise Refusal("Case-B method is not explicitly read-only")
    proof = _mapping(method["read_only_proof"], "read_only_proof")
    _required(proof, ("reference", "sha256", "approval_id"), "read_only_proof")
    for key in ("reference", "approval_id"):
        _exact_text(proof[key], f"read_only_proof.{key}")
    _digest(proof["sha256"], "read-only proof hash")

    correlation = _mapping(method["physical_tck_correlation"], "physical_tck_correlation")
    _required(correlation, ("method", "tck_measurement_point", "bscan_observation_point", "shared_capture_timebase",
                            "capture_window", "acceptance_criteria"), "physical_tck_correlation")
    for key in ("method", "tck_measurement_point", "bscan_observation_point", "shared_capture_timebase", "capture_window"):
        _exact_text(correlation[key], f"physical_tck_correlation.{key}")
    criteria = _mapping(correlation["acceptance_criteria"], "correlation acceptance criteria")
    if not criteria:
        raise Refusal("Case-B physical TCK correlation acceptance criteria are absent")

    acquisition = _mapping(method["acquisition_provenance"], "acquisition_provenance")
    _required(acquisition, ("capture_backend_sha256", "capture_software_identity", "instrument_identity",
                            "calibration_identity", "native_capture_format", "signing_role"), "acquisition_provenance")
    _digest(acquisition["capture_backend_sha256"], "capture backend hash")
    for key in ("capture_software_identity", "instrument_identity", "calibration_identity", "native_capture_format"):
        _exact_text(acquisition[key], f"acquisition_provenance.{key}")
    if acquisition["signing_role"] != "capture":
        raise Refusal("Case-B acquisition provenance must use the capture signing role")

    auth = _mapping(method["authorization_binding"], "authorization_binding")
    _required(auth, ("operation", "card_scope", "case_id", "qualification_record_sha256", "loaded_image_sha256",
                     "bridge_sha256", "method_sha256", "trust_root_sha256"), "authorization_binding")
    if (auth["operation"] != "PHK2_PHYSICAL_TCK_CLOSURE_CASE_B" or
            type(auth["card_scope"]) is not int or auth["card_scope"] != 1 or auth["case_id"] != "33"):
        raise Refusal("Case-B authorization binding has wrong operation/case/card scope")
    for key in ("qualification_record_sha256", "loaded_image_sha256", "bridge_sha256", "method_sha256", "trust_root_sha256"):
        _digest(auth[key], f"authorization_binding.{key}")
    if (auth["qualification_record_sha256"] != method["qualification_record_sha256"] or
            auth["loaded_image_sha256"] != method["loaded_image_sha256"]):
        raise Refusal("Case-B authorization binding differs from method qualification/image")

    validity = _mapping(method["validity"], "validity")
    _required(validity, ("issued_utc", "expires_utc", "target_session_nonce"), "validity")
    _valid_window(validity["issued_utc"], validity["expires_utc"], now, "method")
    _exact_text(validity["target_session_nonce"], "target session nonce")
    evidence = _mapping(method["evidence_contract"], "evidence_contract")
    _required(evidence, ("raw_tap_sha256", "raw_tck_capture_sha256", "raw_bscan_observation_sha256",
                         "correlation_artifact_sha256", "journal_sha256", "journal_entry_sha256"), "evidence_contract")
    for key, value in evidence.items():
        _digest(value, f"evidence_contract.{key}")

    calculated_hash = _method_digest(method)
    if payload["method_sha256"] != calculated_hash:
        raise Refusal("Case-B method canonical hash mismatch")
    return {"payload": payload, "method": method, "method_sha256": calculated_hash}


def validate_approved_case_b_method_record(record: Any, *, binding: Any, trusted_keys: dict[str, Any],
                                           expected_target_identity: dict[str, Any],
                                           authorization_payload: dict[str, Any], session_nonce: str,
                                           now: datetime | None = None) -> dict[str, Any]:
    """Verify owner signature and immutable qualification pin; absent pin always refuses."""
    case = getattr(binding, "case_b", None)
    if (not isinstance(case, dict) or not case.get("approved_bscan_observation_schema") or
            not case.get("approved_expected_observation") or not case.get("approved_bscan_method_sha256")):
        raise Refusal("no immutable matrix-approved BSCAN observation method is pinned for Case B")
    if not isinstance(record, dict):
        raise Refusal("approved Case-B method record is missing")
    from phk2_physical_close_guard import verify_signed_document
    payload = verify_signed_document(record, trusted_keys, "qualification_owner", now=now)
    validated = validate_case_b_method_payload(payload, now=now)
    method = validated["method"]
    trust_root_sha256 = getattr(trusted_keys, "verified_sha256", None)
    if not isinstance(trust_root_sha256, str) or method["authorization_binding"]["trust_root_sha256"] != trust_root_sha256:
        raise Refusal("Case-B method authorization trust root is not the verified pinned key store")
    if method["authorization_binding"]["method_sha256"] != validated["method_sha256"]:
        raise Refusal("Case-B authorization binding method hash mismatch")
    if validated["method_sha256"] != case["approved_bscan_method_sha256"]:
        raise Refusal("Case-B method hash differs from immutable qualification binding")
    if payload.get("qualification_record_sha256") != binding.qualification_record_sha256 or method.get("qualification_record_sha256") != binding.qualification_record_sha256:
        raise Refusal("Case-B method is bound to another qualification record")
    for key, expected in (("source_commit", binding.source_commit), ("source_tree_hash", binding.source_tree_hash),
                          ("routed_dcp_sha256", binding.routed_dcp_sha256)):
        if method.get(key) != expected:
            raise Refusal(f"Case-B method design identity mismatch: {key}")
    validate_case_b_session_binding(method, authorization_payload, expected_target_identity,
                                    validated["method_sha256"], session_nonce, now=now)
    if method["tap"]["expected_response"] != case["approved_expected_observation"]:
        raise Refusal("Case-B response differs from immutable qualification approval")
    return validated


def validate_case_b_session_binding(method: dict[str, Any], authorization_payload: dict[str, Any],
                                    expected_target_identity: dict[str, Any], method_sha256: str,
                                    session_nonce: str, *, now: datetime | None = None) -> None:
    """Check the target, signed authorization claims, and one-session freshness."""
    if not isinstance(method, dict) or method.get("target_identity") != expected_target_identity:
        raise Refusal("Case-B method FK0957 identity/image differs from fresh observed identity")
    if not isinstance(session_nonce, str) or not session_nonce or len(session_nonce) > 256:
        raise Refusal("Case-B session nonce is missing or malformed")
    validity = _mapping(method.get("validity"), "validity")
    if validity.get("target_session_nonce") != session_nonce:
        raise Refusal("Case-B method is stale or replayed into another session")
    auth = authorization_payload if isinstance(authorization_payload, dict) else {}
    case_ids = auth.get("case_ids")
    _valid_window(auth.get("issued_utc"), auth.get("expires_utc"), now, "authorization")
    if (auth.get("case_b_method_sha256") != method_sha256 or auth.get("session_nonce") != session_nonce or
            not isinstance(case_ids, list) or "33" not in case_ids or
            auth.get("authorized_operation") != "PHK2_PHYSICAL_TCK_CLOSURE" or
            type(auth.get("card_scope")) is not int or auth.get("card_scope") != 1 or
            auth.get("qualification_record_sha256") != method.get("qualification_record_sha256") or
            auth.get("card_id") != expected_target_identity.get("card_id") or
            auth.get("bridge_sha256") != method["authorization_binding"].get("bridge_sha256") or
            auth.get("loaded_image_sha256") != expected_target_identity.get("loaded_image_sha256")):
        raise Refusal("Case-B authorization is not bound to the approved method/target/session")


def parse_case_b_transcript(raw: bytes, capture_payload: dict[str, Any], validated_method: dict[str, Any],
                            *, session_nonce: str) -> dict[str, Any]:
    """Parse a signed raw Case-B trace against the owner-pinned exact method."""
    if (not isinstance(validated_method, dict) or not isinstance(validated_method.get("method"), dict) or
            not isinstance(validated_method.get("payload"), dict) or
            not isinstance(validated_method.get("method_sha256"), str) or
            not HEX64.fullmatch(validated_method["method_sha256"])):
        raise Refusal("Case-B transcript parser requires a validated owner-approved method")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("Case-B BSCAN transcript is malformed JSON") from exc
    method = validated_method["method"]
    digest = validated_method["method_sha256"]
    if not isinstance(capture_payload, dict):
        raise Refusal("Case-B signed capture payload is malformed")
    if (not isinstance(doc, dict) or doc.get("schema") != TAP_TRACE_SCHEMA or
            doc.get("case_id") != "33" or doc.get("method_sha256") != digest or
            doc.get("session_nonce") != session_nonce):
        raise Refusal("Case-B transcript schema/method/session binding mismatch")
    tap = method["tap"]
    records = doc.get("records")
    if not isinstance(records, list) or len(records) != tap["cycle_count"]:
        raise Refusal("Case-B transcript cycle count differs from approved method")
    state = tap["initial_state"]
    previous_time = float("-inf")
    expected = tap["expected_response"]
    for index, row in enumerate(records):
        if (not isinstance(row, dict) or isinstance(row.get("seq"), bool) or
                row.get("seq") != index):
            raise Refusal("Case-B transcript record order is malformed")
        timestamp = row.get("timestamp_ns")
        if (isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or
                not math.isfinite(timestamp) or timestamp <= previous_time):
            raise Refusal("Case-B transcript timestamps are malformed/non-monotonic")
        previous_time = timestamp
        tms, tdi = tap["tms_vector"][index], tap["tdi_vector"][index]
        if (isinstance(row.get("tms"), bool) or isinstance(row.get("tdi"), bool) or
                row.get("tms") != tms or row.get("tdi") != tdi or row.get("state_before") != state):
            raise Refusal("Case-B observed TAP vector/state differs from owner-approved method")
        state_after = TAP_NEXT[state][tms]
        if row.get("state_after") != state_after:
            raise Refusal("Case-B observed TAP transition differs from TAP state machine")
        observed_tdo = row.get("tdo")
        if isinstance(observed_tdo, bool) or not isinstance(observed_tdo, int) or observed_tdo not in (0, 1):
            raise Refusal("Case-B observed TDO value is malformed")
        if expected["mask_bits"][index] and observed_tdo != expected["tdo_bits"][index]:
            raise Refusal("Case-B TDO response differs from owner-approved expectation")
        state = state_after
    if state != tap["final_state"] or doc.get("final_state") != tap["final_state"]:
        raise Refusal("Case-B final TAP state differs from owner-approved state")
    if capture_payload.get("correlation_timebase_id") != method["physical_tck_correlation"]["shared_capture_timebase"]:
        raise Refusal("Case-B physical TCK correlation uses a different capture timebase")
    for b64_key, sha_key, contract_key in (
        ("raw_tck_capture_b64", "raw_tck_capture_sha256", "raw_tck_capture_sha256"),
        ("raw_bscan_observation_b64", "raw_bscan_observation_sha256", "raw_bscan_observation_sha256"),
        ("physical_clock_correlation_b64", "physical_clock_correlation_sha256", "correlation_artifact_sha256"),
    ):
        try:
            artifact = base64.b64decode(capture_payload[b64_key], validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise Refusal(f"Case-B raw acquisition artifact missing/malformed: {b64_key}") from exc
        digest_value = _sha(artifact)
        if not artifact or capture_payload.get(sha_key) != digest_value or method["evidence_contract"][contract_key] != digest_value:
            raise Refusal(f"Case-B raw acquisition hash mismatch: {b64_key}")
    if capture_payload.get("raw_capture_sha256") != _sha(raw) or method["evidence_contract"]["raw_tap_sha256"] != _sha(raw):
        raise Refusal("Case-B TAP transcript hash/journal contract mismatch")
    if (capture_payload.get("journal_sha256") != method["evidence_contract"]["journal_sha256"] or
            capture_payload.get("journal_entry_sha256") != method["evidence_contract"]["journal_entry_sha256"]):
        raise Refusal("Case-B evidence journal linkage mismatch")
    acquisition = method["acquisition_provenance"]
    if (capture_payload.get("synthetic_fixture") is not False or any(
            capture_payload.get(field) != acquisition[method_field]
            for field, method_field in (
                ("capture_backend_sha256", "capture_backend_sha256"),
                ("capture_software_identity", "capture_software_identity"),
                ("instrument_identity", "instrument_identity"),
                ("calibration_identity", "calibration_identity"),
                ("native_capture_format", "native_capture_format")))):
        raise Refusal("Case-B acquisition provenance is synthetic or from another backend")
    return {"tap_cycles": tap["cycle_count"], "final_state": state,
            "method_sha256": digest, "transcript_sha256": _sha(raw)}
