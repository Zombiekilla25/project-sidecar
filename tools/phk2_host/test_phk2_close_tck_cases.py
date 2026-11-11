"""Fail-closed regressions for the operator-facing promotion command."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from physical_tck_preflight import Refusal
from phk2_close_tck_cases import validate_manifest, _verify_authorization, package_file
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


if __name__ == "__main__":
    unittest.main()
