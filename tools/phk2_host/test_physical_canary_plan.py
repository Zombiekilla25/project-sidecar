"""Offline-only tests for the FK0957 physical-canary preparation plan."""
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_physical_canary_plan as plan


class PhysicalCanaryPlanTests(unittest.TestCase):
    def test_plan_is_exactly_bound_to_v5_1_envelope_and_one_canary(self):
        result = plan.build_plan(ROOT, verify_all=False)
        env = result["immutable_tck_envelope"]
        self.assertEqual(env["commit"], "a01a735fb1e1d0e9b918a2d20c0733ba244b4ee0")
        self.assertEqual(env["limits"]["tck_min_hz"], 5_000_000)
        self.assertEqual(env["limits"]["tck_max_hz"], 40_000_000)
        self.assertEqual(env["limits"]["period_min_ns"], 25.0)
        self.assertEqual(env["limits"]["period_max_ns"], 200.0)
        self.assertEqual(env["limits"]["high_ns_min"], 10.0)
        self.assertEqual(env["limits"]["low_ns_min"], 10.0)
        self.assertEqual(env["limits"]["duty_cycle_min_percent"], 40.0)
        self.assertEqual(env["limits"]["duty_cycle_max_percent"], 60.0)
        self.assertEqual(result["one_card_scope"]["authorized_card_count"], 1)
        self.assertEqual(result["one_card_scope"]["name"], "FK0957")

    def test_physical_cases_jitter_and_readiness_stay_fail_closed(self):
        result = plan.build_plan(ROOT, verify_all=False)
        self.assertEqual(result["qualification"]["offline_pass"], "38/40")
        self.assertEqual(result["qualification"]["case_a"]["status"], "UNQUALIFIED")
        self.assertEqual(result["qualification"]["case_b"]["status"], "UNQUALIFIED")
        self.assertIsNone(result["immutable_tck_envelope"]["limits"]["jitter_numeric_limit_ns"])
        self.assertEqual(result["immutable_tck_envelope"]["limits"]["jitter_status"], "NOT_QUALIFIED")
        self.assertEqual(result["physical_canary_readiness"], "FAIL")
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(result["physical_evidence_passes"], {"40": False, "33": False})

    def test_conservative_start_rate_is_plan_only_and_never_trusts_settck(self):
        result = plan.build_plan(ROOT, verify_all=False)
        first = result["first_requested_tck"]
        self.assertEqual(first["target_hz"], 5_000_000)
        self.assertEqual(first["period_ns"], 200.0)
        self.assertEqual(first["target_high_ns"] + first["target_low_ns"], first["period_ns"])
        self.assertEqual(first["status"], "PLAN_ONLY_EFFECTIVE_RATE_UNPROVEN")
        self.assertFalse(result["case_a_measurement"]["settck_echo_is_measurement"])

    def test_case_b_does_not_guess_user_instruction(self):
        result = plan.build_plan(ROOT, verify_all=False)
        case_b = result["case_b_sequence"]
        self.assertIn("87", case_b["approved_baseline_sequence"])
        self.assertIn("do not guess", case_b["internal_observation"])
        self.assertFalse(case_b["user_instructions_authorized"])
        self.assertFalse(case_b["fpga_programming"])
        self.assertFalse(case_b["workload_change"])

    def test_wrong_envelope_hash_refuses(self):
        with mock.patch.object(plan, "ENVELOPE_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "JSON identity mismatch"):
                plan.verify_envelope(ROOT, verify_all=False)

    def test_source_is_offline_only(self):
        text = Path(plan.__file__).read_text()
        self.assertNotIn("socket.connect", text)
        self.assertNotIn("usb.core", text.lower())
        self.assertNotIn("--execute-physical", text)
        self.assertIn("[\"git\", \"-C\", str(repo), *args]", text)


if __name__ == "__main__":
    unittest.main()
