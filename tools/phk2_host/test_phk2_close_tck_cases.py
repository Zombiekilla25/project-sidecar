"""Fail-closed regressions for the operator-facing promotion command."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from physical_tck_preflight import Refusal
from phk2_close_tck_cases import (validate_manifest, _verify_authorization, package_file,
                                  _validate_promotion_session, _promotion_card_expectation)
import phk2_close_tck_cases as close_runner
from phk2_physical_close_guard import verify_immutable_v51, CASE_A_ID, CASE_A_NAME, CASE_B_ID, CASE_B_NAME


class CloseRunnerRejectsUnboundInputs(unittest.TestCase):
    def setUp(self):
        self.repo = Path(__file__).resolve().parents[2]
        self.binding = verify_immutable_v51(self.repo)

    def test_exact_case_definitions_come_from_immutable_record(self):
        self.assertEqual((CASE_A_ID, self.binding.case_a["case"]), ("40", CASE_A_NAME))
        self.assertEqual((CASE_B_ID, self.binding.case_b["case"]), ("33", CASE_B_NAME))

    def test_arbitrary_synthetic_manifest_refuses(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "manifest.json"
            path.write_text(json.dumps({"schema": "PHK2-TCK-CLOSURE-MANIFEST-v1",
                "synthetic_fixture": False, "TCK_INDEPENDENT_PASS": 38,
                "TCK_INDEPENDENT_FAIL": 0, "tck_dependent_cases": [
                    {"case_id": "SYNTH-A", "kind": "PHYSICAL_TCK_WAVEFORM"},
                    {"case_id": "SYNTH-B", "kind": "BSCAN_CLOCK_INTERACTION"}]}))
            with self.assertRaises(Refusal): validate_manifest(path)

    def test_v5_1_record_has_no_physical_envelope_so_runner_stays_closed(self):
        self.assertFalse(self.binding.qualified_physical_envelope_available)
        self.assertEqual(self.binding.tck_envelope["physical_waveform_limits"], None)
        self.assertFalse(self.binding.tck_envelope["physical_tck_contract_qualified"])

    def test_route_json_pass_claim_cannot_override_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / "routed.dcp").write_bytes(b"actual wrong route bytes")
            b = self.binding
            manifest = {"schema": "PHK2-TCK-CLOSURE-MANIFEST-v1", "synthetic_fixture": False,
                "TCK_INDEPENDENT_PASS": 38, "TCK_INDEPENDENT_FAIL": 0,
                "v5_1_identity": {"source_commit": b.source_commit, "source_tree_hash": b.source_tree_hash,
                    "routed_dcp_sha256": b.routed_dcp_sha256,
                    "qualification_record_sha256": b.qualification_record_sha256,
                    "matrix_sha256": b.matrix_sha256, "evidence_commit": b.evidence_commit},
                "qualification_matrix": {"sha256": b.matrix_sha256,
                    "commit": "6ad11b72fc62a452195245984b69f236d4d3b315",
                    "path": "results/phk2-v3-post-route-intake-20261110/qualification.json"},
                "tck_dependent_cases": [
                    {"case_id": "40", "case": "host_TCK_frequency_contract", "kind": "PHYSICAL_TCK_WAVEFORM",
                     "matrix_detail": "Physical host maximum TCK frequency/duty contract not qualified"},
                    {"case_id": "33", "case": "clock_interaction_no_unsafe", "kind": "BSCAN_CLOCK_INTERACTION",
                     "matrix_detail": b.case_b["detail"]}],
                "TCK_ENVELOPE_SHA256": b.tck_envelope_sha256,
                "TCK_ANALYSIS_REFERENCE": b.tck_envelope,
                "artifacts": {"routed_dcp": {"path": "routed.dcp", "sha256": b.routed_dcp_sha256}}}
            path = root / "manifest.json"; path.write_text(json.dumps(manifest))
            with self.assertRaises(Refusal): validate_manifest(path)
            fake_pass_ref = {"path": "routed.dcp", "sha256": "0" * 64}
            with self.assertRaises(Refusal): package_file(root, fake_pass_ref, "routed DCP")

    def test_boolean_authorization_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "auth.json"
            path.write_text(json.dumps({"AUTHORIZED": True, "signature_verified": True}))
            with self.assertRaises(Refusal):
                _verify_authorization(path, {}, {}, expected_card_id=self.binding.expected_card_id,
                                      session_nonce="fixture", service_config_sha256="0" * 64,
                                      peer_expectation_sha256="0" * 64)

    def test_promotion_session_requires_fresh_matching_nonce(self):
        now = datetime.now(timezone.utc)
        auth = {"session_nonce": "session-current", "issued_utc": now.isoformat(),
                "expires_utc": (now + timedelta(minutes=5)).isoformat()}
        self.assertEqual(_validate_promotion_session(auth, "session-current"), "session-current")
        with self.assertRaises(Refusal):
            _validate_promotion_session(None, "session-current")
        for nonce in (None, "", " session-current", "session-current\n", "x" * 257, 7):
            with self.subTest(nonce=repr(nonce)), self.assertRaises(Refusal):
                _validate_promotion_session(auth, nonce)
        with self.assertRaisesRegex(Refusal, "nonce mismatch"):
            _validate_promotion_session(auth, "different-session")
        stale = {**auth, "issued_utc": (now - timedelta(days=2)).isoformat()}
        with self.assertRaises(Refusal):
            _validate_promotion_session(stale, "session-current")
        expired = {**auth, "expires_utc": (now - timedelta(seconds=1)).isoformat()}
        with self.assertRaises(Refusal):
            _validate_promotion_session(expired, "session-current")
        malformed = {**auth, "expires_utc": "not-a-time"}
        with self.assertRaises(Refusal):
            _validate_promotion_session(malformed, "session-current")

    def test_promotion_card_expectation_binds_exact_fpga_identity(self):
        expected = _promotion_card_expectation(self.binding, "a" * 64)
        self.assertEqual(expected["expected_fpga_dna"], self.binding.expected_fpga_dna)
        self.assertEqual(expected["expected_target_part"], self.binding.expected_target_part)
        self.assertEqual(expected["bridge_sha256"], "a" * 64)
        malformed_bridge_hashes = (None, "short", "g" * 64)
        for digest in malformed_bridge_hashes:
            with self.subTest(digest=digest), self.assertRaises(Refusal):
                _promotion_card_expectation(self.binding, digest)
        incomplete = type("IncompleteBinding", (), {
            "expected_card_id": self.binding.expected_card_id,
            "expected_adapter_id": self.binding.expected_adapter_id,
            "expected_idcode": self.binding.expected_idcode,
            "expected_fpga_dna": "",
            "expected_target_part": self.binding.expected_target_part,
        })()
        with self.assertRaises(Refusal):
            _promotion_card_expectation(incomplete, "a" * 64)

    def test_validate_evidence_passes_session_nonce_and_full_target_expectation(self):
        now = datetime.now(timezone.utc)
        nonce = "wire-session-1"
        auth = {"session_nonce": nonce, "issued_utc": now.isoformat(),
                "expires_utc": (now + timedelta(minutes=5)).isoformat()}
        bridge_hash = "a" * 64
        with tempfile.TemporaryDirectory() as td:
            evidence_path = Path(td) / "evidence.json"
            evidence_path.write_text(json.dumps({"schema": "PHK2-TCK-CLOSURE-EVIDENCE-v1"}))
            stop = Refusal("stop after target expectation captured")
            with mock.patch.object(close_runner, "validate_physical_capture_package", return_value={}) as capture, \
                 mock.patch.object(close_runner, "verify_signed_document", side_effect=[{}, {"session_nonce": nonce}]), \
                 mock.patch.object(close_runner, "validate_peer_proof", return_value="b" * 64), \
                 mock.patch.object(close_runner, "validate_card_identity", side_effect=stop) as card_check:
                with self.assertRaisesRegex(Refusal, "stop after target"):
                    close_runner.validate_evidence(
                        evidence_path, {}, {"BRIDGE_SHA256": bridge_hash}, auth,
                        trusted_keys={}, peer_expectation={}, session_nonce=nonce)
            self.assertEqual(capture.call_args.kwargs["expected_session_nonce"], nonce)
            expected = card_check.call_args.args[1]
            self.assertEqual(expected["expected_fpga_dna"], self.binding.expected_fpga_dna)
            self.assertEqual(expected["expected_target_part"], self.binding.expected_target_part)


if __name__ == "__main__":
    unittest.main()
