"""Synthetic-only negative coverage for the final TCK closure verifier."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from phk2_close_tck_cases import (
    _measurement_in_envelope,
    _verify_authorization,
    _verify_bridge,
    validate_evidence,
    validate_manifest,
)
from physical_tck_preflight import PINNED_REVIEWED_BRIDGE_SHA256, PINNED_REVIEWED_BUILD_ID, Refusal


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc(delta=timedelta(0)):
    return (datetime.now(timezone.utc) + delta).isoformat()


class TckClosureDryRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="phk2-close-tck-")
        self.root = Path(self.tmp.name)
        self.package = self.root / "qualified-v4"
        self.package.mkdir()
        self._artifact("routed.dcp", b"synthetic routed v4")
        self._artifact("image.bit", b"synthetic v4 image")
        self._artifact("matrix.json", b'{"fixture":true,"cases":["SYNTH-A","SYNTH-B"]}')
        self.manifest_path = self.package / "closure-manifest.json"
        self.manifest_path.write_text(json.dumps(self._manifest(), sort_keys=True))
        self.manifest = json.loads(self.manifest_path.read_text())
        self.bridge_path = self.root / "bridge.json"
        self.bridge = {"BRIDGE_SHA256": PINNED_REVIEWED_BRIDGE_SHA256,
                       "BUILD_ID": PINNED_REVIEWED_BUILD_ID, "TARGET_PART": "xcvu33p-fsvh2104-2-e",
                       "verified": True, "verified_utc": utc()}
        self.bridge_path.write_text(json.dumps(self.bridge))
        self.auth_path = self.root / "auth.json"
        self.auth = {"status": "AUTHORIZED", "signature_verified": True, "one_card_scope": True,
                     "target_part": self.manifest["TARGET_PART"], "routed_dcp_hash": self.manifest["ROUTED_DCP_HASH"],
                     "image_hash": self.manifest["IMAGE_HASH"], "peer_exclusion": "PASS",
                     "workload_preservation": "PASS", "rollback_readiness": "PASS",
                     "issued_utc": utc(), "expires_utc": utc(timedelta(hours=2))}
        self.auth_path.write_text(json.dumps(self.auth))
        self.bridge_verified = _verify_bridge(self.bridge_path, self.manifest["TARGET_PART"])
        self.auth_verified = _verify_authorization(self.auth_path, self.manifest)
        self.evidence_path = self.root / "capture" / "evidence.json"
        self.evidence_path.parent.mkdir()
        for name, data in (("wave.csv", b"time,tck\n"), ("tap.jsonl", b"{}\n"),
                           ("correlation.csv", b"time,bscane2\n"), ("preflight.json", b"{}\n"),
                           ("adapter.json", b"{}\n"), ("peers.json", b"{}\n")):
            (self.evidence_path.parent / name).write_bytes(data)
        self.evidence = self._evidence()
        self._save_evidence()

    def tearDown(self):
        self.tmp.cleanup()

    def _artifact(self, name, content):
        path = self.package / name
        path.write_bytes(content)
        return {"path": name, "sha256": digest(path)}

    def _manifest(self):
        route = {"path": "routed.dcp", "sha256": digest(self.package / "routed.dcp")}
        image = {"path": "image.bit", "sha256": digest(self.package / "image.bit")}
        matrix = {"path": "matrix.json", "sha256": digest(self.package / "matrix.json")}
        cases = [
            {"case_id": "SYNTH-A", "kind": "PHYSICAL_TCK_WAVEFORM", "purpose": "fixture waveform case",
             "required_inputs": ["scope trace"], "required_measurement": ["TCK frequency and pulse widths"],
             "pass_criteria": ["within envelope"], "fail_criteria": ["outside envelope"], "evidence_output": ["waveform.csv"]},
            {"case_id": "SYNTH-B", "kind": "BSCAN_CLOCK_INTERACTION", "purpose": "fixture BSCAN case",
             "required_inputs": ["TAP trace"], "required_measurement": ["clock correlation"],
             "pass_criteria": ["source-derived correlation"], "fail_criteria": ["interaction mismatch"], "evidence_output": ["tap.jsonl"]},
        ]
        return {"schema": "PHK2-TCK-CLOSURE-MANIFEST-v1", "synthetic_fixture": False,
                "TCK_INDEPENDENT_PASS": 38, "TCK_INDEPENDENT_FAIL": 0,
                "independent_qualification": {"result": "PASS"}, "TARGET_PART": "xcvu33p-fsvh2104-2-e",
                "artifacts": {"routed_dcp": route, "image": image}, "ROUTED_DCP_HASH": route["sha256"],
                "IMAGE_HASH": image["sha256"], "route_qualification": {"status": "QUALIFIED"},
                "TCK_ANALYSIS_ENVELOPE": {"qualified": True, "minimum_tck_hz": 1e6, "maximum_tck_hz": 50e6,
                    "minimum_high_ns": 8, "minimum_low_ns": 8, "minimum_duty_cycle_percent": 40,
                    "maximum_duty_cycle_percent": 60, "maximum_period_jitter_p2p_ns": 1,
                    "maximum_period_jitter_rms_ns": 0.25},
                "qualification_matrix": {"status": "AUTHENTICATED", "source": matrix}, "tck_dependent_cases": cases}

    def _ref(self, name):
        p = self.evidence_path.parent / name
        return {"path": name, "sha256": digest(p)}

    def _evidence(self):
        manifest = json.loads(self.manifest_path.read_text())
        return {"schema": "PHK2-TCK-CLOSURE-EVIDENCE-v1", "evidence_class": "MOCK_CAPTURE",
            "synthetic_fixture": True, "production_evidence": True, "captured_utc": utc(),
            "manifest_sha256": digest(self.manifest_path), "routed_dcp_hash": manifest["ROUTED_DCP_HASH"],
            "image_hash": manifest["IMAGE_HASH"], "bridge_sha256": self.bridge["BRIDGE_SHA256"],
            "authorization_sha256": digest(self.auth_path), "peer_exclusion": "PASS", "one_card_scope": True,
            "workload_unchanged": True, "preflight": self._ref("preflight.json"),
            "adapter_identity": self._ref("adapter.json"), "peer_exclusion_proof": self._ref("peers.json"),
            "case_a": {"case_id": "SYNTH-A", "status": "PASS", "MEASURED_TCK_HZ": 30e6,
                "MEASURED_PERIOD_NS": 33.33, "MEASURED_HIGH_NS": 16.66, "MEASURED_LOW_NS": 16.67,
                "MEASURED_DUTY_CYCLE": 50, "MEASURED_JITTER_P2P_NS": .2, "MEASURED_JITTER_RMS_NS": .05,
                "raw_waveform": self._ref("wave.csv"), "settck_used_as_measurement": False},
            "case_b": {"case_id": "SYNTH-B", "status": "PASS", "before_state": "IDLE_CONFIRMED",
                "after_state": "IDLE_CONFIRMED", "tap_cycles": 87, "fpga_programming": False,
                "workload_changed": False, "transcript": self._ref("tap.jsonl"),
                "physical_clock_correlation": self._ref("correlation.csv"), "settck_used_as_measurement": False},
            "final_case_statuses": {"SYNTH-A": "PASS", "SYNTH-B": "PASS"},
            "close": {"transport_closed": True, "tap_idle": True, "peer_count_after": 0}}

    def _save_evidence(self):
        self.evidence_path.write_text(json.dumps(self.evidence, sort_keys=True))

    def _allow_downstream_gate_test(self):
        # Unit-test-only marker lets this synthetic fixture reach later checks;
        # the separate mock-production test proves these flags are rejected.
        self.evidence["synthetic_fixture"] = False
        self.evidence["evidence_class"] = "PHYSICAL_CAPTURE"

    def test_manifest_with_38_zero_and_two_source_cases_passes_static_gate(self):
        _, data = validate_manifest(self.manifest_path)
        self.assertEqual([x["case_id"] for x in data["tck_dependent_cases"]], ["SYNTH-A", "SYNTH-B"])

    def test_only_37_independent_pass_refuses(self):
        self.manifest["TCK_INDEPENDENT_PASS"] = 37
        self.manifest_path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(Refusal, "exactly 38 pass"):
            validate_manifest(self.manifest_path)

    def test_missing_v4_manifest_refuses(self):
        with self.assertRaisesRegex(Refusal, "unavailable"):
            validate_manifest(self.root / "missing-v4.json")

    def test_wrong_route_hash_refuses(self):
        self.manifest["ROUTED_DCP_HASH"] = "0" * 64
        self.manifest_path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(Refusal, "identity/hash mismatch"):
            validate_manifest(self.manifest_path)

    def test_bridge_mismatch_refuses(self):
        self.bridge["BRIDGE_SHA256"] = "0" * 64
        self.bridge_path.write_text(json.dumps(self.bridge))
        with self.assertRaisesRegex(Refusal, "differs"):
            _verify_bridge(self.bridge_path, self.manifest["TARGET_PART"])

    def test_peer_exclusion_failure_refuses(self):
        self.auth["peer_exclusion"] = "FAIL"
        self.auth_path.write_text(json.dumps(self.auth))
        with self.assertRaisesRegex(Refusal, "peer exclusion"):
            _verify_authorization(self.auth_path, self.manifest)

    def test_missing_authorization_refuses(self):
        with self.assertRaisesRegex(Refusal, "unavailable"):
            _verify_authorization(self.root / "missing-auth.json", self.manifest)

    def test_tck_above_envelope_refuses(self):
        value = dict(self.evidence["case_a"])
        value["MEASURED_TCK_HZ"] = 51e6
        value["MEASURED_PERIOD_NS"] = 1e9 / 51e6
        value["MEASURED_HIGH_NS"] = value["MEASURED_PERIOD_NS"] / 2
        value["MEASURED_LOW_NS"] = value["MEASURED_PERIOD_NS"] / 2
        with self.assertRaisesRegex(Refusal, "outside qualified envelope"):
            _measurement_in_envelope(value, self.manifest["TCK_ANALYSIS_ENVELOPE"])

    def test_duty_outside_envelope_refuses(self):
        value = dict(self.evidence["case_a"])
        value["MEASURED_DUTY_CYCLE"] = 65
        with self.assertRaisesRegex(Refusal, "duty cycle"):
            _measurement_in_envelope(value, self.manifest["TCK_ANALYSIS_ENVELOPE"])

    def test_missing_waveform_evidence_refuses(self):
        self._allow_downstream_gate_test()
        self.evidence["case_a"] = {"status": "NOT_RUN"}
        self._save_evidence()
        manifest = json.loads(self.manifest_path.read_text()); manifest["_path"] = str(self.manifest_path)
        with self.assertRaisesRegex(Refusal, "waveform case incomplete"):
            validate_evidence(self.evidence_path, manifest, self.bridge_verified, self.auth_verified)

    def test_missing_bscan_evidence_refuses(self):
        self._allow_downstream_gate_test()
        self.evidence["case_b"] = {"status": "NOT_RUN"}
        self._save_evidence()
        manifest = json.loads(self.manifest_path.read_text()); manifest["_path"] = str(self.manifest_path)
        with self.assertRaisesRegex(Refusal, "BSCAN clock-interaction case incomplete"):
            validate_evidence(self.evidence_path, manifest, self.bridge_verified, self.auth_verified)

    def test_partial_case_completion_refuses(self):
        self.evidence["final_case_statuses"] = {"SYNTH-A": "PASS"}
        self._save_evidence()
        manifest = json.loads(self.manifest_path.read_text()); manifest["_path"] = str(self.manifest_path)
        with self.assertRaisesRegex(Refusal, "mock/synthetic"):
            validate_evidence(self.evidence_path, manifest, self.bridge_verified, self.auth_verified)

    def test_mock_evidence_marked_production_refuses(self):
        manifest = json.loads(self.manifest_path.read_text()); manifest["_path"] = str(self.manifest_path)
        with self.assertRaisesRegex(Refusal, "mock/synthetic"):
            validate_evidence(self.evidence_path, manifest, self.bridge_verified, self.auth_verified)

    def test_stale_evidence_refuses(self):
        self.evidence["synthetic_fixture"] = False
        self.evidence["evidence_class"] = "PHYSICAL_CAPTURE"
        self.evidence["captured_utc"] = utc(timedelta(days=-2))
        self._save_evidence()
        manifest = json.loads(self.manifest_path.read_text()); manifest["_path"] = str(self.manifest_path)
        with self.assertRaisesRegex(Refusal, "stale"):
            validate_evidence(self.evidence_path, manifest, self.bridge_verified, self.auth_verified)


if __name__ == "__main__":
    unittest.main()
