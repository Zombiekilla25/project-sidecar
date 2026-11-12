"""Offline fail-closed checks for future owner-approved Case-B method records.

No test fixture in this file contains a TAP vector or an expected TDO value.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from physical_tck_preflight import Refusal
from phk2_case_b_method import (
    APPROVED_RECORD_SCHEMA,
    METHOD_SCHEMA,
    parse_case_b_transcript,
    validate_approved_case_b_method_record,
    validate_case_b_method_payload,
    validate_case_b_session_binding,
    _exact_text,
)
from phk2_physical_close_guard import verify_immutable_v51


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "ops/phk2/PHK2_FK0957_CASE_B_METHOD_SCHEMA.json"


class CaseBMethodFailClosedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binding = verify_immutable_v51(ROOT)

    def test_schema_requires_authoritative_method_fields_without_defaults(self):
        schema = json.loads(SCHEMA_PATH.read_text())
        self.assertEqual(schema["$id"], "urn:phk2:fk0957:case-b:approved-method:v1")
        self.assertEqual(schema["$defs"]["method"]["properties"]["schema"]["const"], METHOD_SCHEMA)
        method_required = set(schema["$defs"]["method"]["required"])
        self.assertTrue({"qualification_record_sha256", "routed_dcp_sha256", "loaded_image_sha256",
                         "target_identity", "tap", "read_only_proof", "physical_tck_correlation",
                         "acquisition_provenance", "authorization_binding", "validity",
                         "evidence_contract"}.issubset(method_required))
        tap = schema["$defs"]["method"]["properties"]["tap"]
        self.assertTrue({"initial_state", "reset_procedure", "selection", "tms_vector", "tdi_vector",
                         "cycle_count", "expected_transitions", "final_state", "expected_response"}
                        .issubset(set(tap["required"])))
        def has_default(value):
            if isinstance(value, dict):
                return "default" in value or any(has_default(item) for item in value.values())
            if isinstance(value, list):
                return any(has_default(item) for item in value)
            return False
        self.assertFalse(has_default(schema))

    def test_wildcard_and_default_identifiers_refuse(self):
        for value in ("*", "FK*", "any", "default", "experimental", "IDCODE_ONLY"):
            with self.subTest(value=value), self.assertRaises(Refusal):
                _exact_text(value, "fixture")

    def test_specification_contains_no_authoritative_tap_or_response_values(self):
        spec_path = ROOT / "ops/phk2/PHK2_FK0957_CASE_B_QUALIFICATION_SPEC.json"
        spec = json.loads(spec_path.read_text())
        procedure = spec["tap_procedure"]
        self.assertIsNone(procedure["initial_tap_state"]["value"])
        for value in procedure["initialization_or_reset_sequence"].values():
            if value != "REQUIRES_QUALIFICATION_OWNER_APPROVAL":
                self.assertIsNone(value)
        for value in procedure["instruction_and_register_selection"].values():
            if value != "REQUIRES_QUALIFICATION_OWNER_APPROVAL":
                self.assertIsNone(value)
        for value in procedure["complete_sequence"].values():
            if value != "REQUIRES_QUALIFICATION_OWNER_APPROVAL":
                self.assertIsNone(value)
        for key, value in procedure["expected_response"].items():
            if key not in ("classification", "note"):
                self.assertIsNone(value)

    def test_immutable_v51_record_has_no_method_pin_and_refuses(self):
        self.assertFalse(self.binding.case_b.get("approved_bscan_observation_schema"))
        self.assertFalse(self.binding.case_b.get("approved_expected_observation"))
        self.assertFalse(self.binding.case_b.get("approved_bscan_method_sha256"))
        with self.assertRaisesRegex(Refusal, "no immutable matrix-approved"):
            validate_approved_case_b_method_record(
                {}, binding=self.binding, trusted_keys={}, expected_target_identity={},
                authorization_payload={}, session_nonce="offline-only")

    def test_missing_or_unapproved_authoritative_record_refuses(self):
        cases = [
            None,
            {},
            {"schema": APPROVED_RECORD_SCHEMA},
            {"schema": APPROVED_RECORD_SCHEMA, "provenance": "EXPERIMENTAL"},
            {"schema": APPROVED_RECORD_SCHEMA, "provenance": "QUALIFICATION_OWNER_APPROVED",
             "synthetic_fixture": True, "approval_status": "APPROVED", "case_id": "33"},
            {"schema": APPROVED_RECORD_SCHEMA, "provenance": "QUALIFICATION_OWNER_APPROVED",
             "synthetic_fixture": False, "approval_status": "APPROVED", "case_id": "*"},
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(Refusal):
                validate_case_b_method_payload(payload)

    def test_idcode_only_and_placeholder_records_cannot_be_used(self):
        # The immutable binding check runs before parsing any purported method.
        # This blocks old IDCODE-only captures and unapproved historical experiments.
        for record in ({"tap": {"selection": {"instruction_name": "IDCODE"}}},
                       {"experimental_sequence": "historical"},
                       {"expected_response": "*"}):
            with self.subTest(record=record), self.assertRaisesRegex(Refusal, "no immutable matrix-approved"):
                validate_approved_case_b_method_record(
                    record, binding=self.binding, trusted_keys={}, expected_target_identity={},
                    authorization_payload={}, session_nonce="offline-only")

    def test_session_binding_rejects_target_image_nonce_auth_and_expiry_mismatch(self):
        now = datetime.now(timezone.utc)
        future = (now + timedelta(minutes=5)).isoformat()
        past = (now - timedelta(minutes=5)).isoformat()
        target = {"card_id": "expected-card", "loaded_image_sha256": "a" * 64}
        method = {
            "target_identity": target, "qualification_record_sha256": "f" * 64,
            "validity": {"issued_utc": past, "expires_utc": future, "target_session_nonce": "nonce-1"},
            "authorization_binding": {"bridge_sha256": "b" * 64},
        }
        auth = {"issued_utc": past, "expires_utc": future, "case_ids": ["33"],
                "authorized_operation": "PHK2_PHYSICAL_TCK_CLOSURE", "card_scope": 1,
                "qualification_record_sha256": "f" * 64,
                "case_b_method_sha256": "c" * 64, "session_nonce": "nonce-1",
                "card_id": "expected-card", "bridge_sha256": "b" * 64,
                "loaded_image_sha256": "a" * 64}
        validate_case_b_session_binding(method, auth, target, "c" * 64, "nonce-1", now=now)
        attacks = [
            (method, auth, {**target, "card_id": "wrong-card"}, "nonce-1", future),
            (method, auth, {**target, "loaded_image_sha256": "d" * 64}, "nonce-1", future),
            (method, auth, target, "copied-or-replayed", future),
            (method, {**auth, "case_b_method_sha256": "e" * 64}, target, "nonce-1", future),
            (method, {**auth, "expires_utc": past}, target, "nonce-1", past),
            (method, {**auth, "card_scope": True}, target, "nonce-1", future),
            (method, {**auth, "card_scope": 1.0}, target, "nonce-1", future),
            (method, {"authorized": True}, target, "nonce-1", future),
            (method, {**auth, "case_ids": ["40"]}, target, "nonce-1", future),
        ]
        for candidate, authorization, observed, nonce, expires in attacks:
            with self.subTest(authorization=authorization, observed=observed, nonce=nonce), self.assertRaises(Refusal):
                validate_case_b_session_binding(candidate, authorization, observed,
                                                "c" * 64, nonce, now=now)

    def test_transcript_cannot_parse_without_validated_owner_method(self):
        for validated in (None, {}, {"method": {}}, {"method_sha256": "0" * 64}):
            with self.subTest(validated=validated), self.assertRaises(Refusal):
                parse_case_b_transcript(b"{}", {}, validated, session_nonce="offline-only")


if __name__ == "__main__":
    unittest.main()
