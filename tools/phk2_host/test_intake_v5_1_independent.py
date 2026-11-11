from pathlib import Path
import unittest

from intake_v5_1_independent import analyze


class V51IndependentIntakeTest(unittest.TestCase):
    def test_immutable_identity_timing_and_topology(self):
        result = analyze(Path(__file__).resolve().parents[2])
        self.assertTrue(result["MANIFEST_AND_SHA256SUMS_VALID"])
        self.assertTrue(result["RTL_XDC_UNCHANGED_FROM_FAILED_V5"])
        self.assertEqual(result["COMMON_RESET_RELEASE_SYNCHRONIZERS"], 1)
        self.assertEqual(result["INDEPENDENT_ASYNC_RELEASE_CHAINS"], 0)
        self.assertEqual(result["CDC11_FINAL_ROWS"], 3)
        self.assertTrue(result["CDC11_STRUCTURALLY_SAFE"])
        self.assertEqual(result["WNS_NS"], 0.0)
        self.assertEqual(result["TNS_NS"], 0.0)
        self.assertEqual(result["RESET_RELEASE_WORST_RECOVERY_REMOVAL_SLACK_NS"], 0.074)

    def test_physical_only_closure_and_gray_constraints(self):
        result = analyze(Path(__file__).resolve().parents[2])
        self.assertTrue(result["PHYSICAL_ONLY_FIX_SUCCEEDED"])
        self.assertFalse(result["SYNC_DISTRIBUTION_STAGE_REQUIRED"])
        self.assertEqual(result["PHYS_OPT_ADDED_CELLS"], 0)
        self.assertEqual(result["PHYS_OPT_OPTIMIZED_CELLS_OR_NETS"], 14)
        self.assertEqual(result["GRAY_MAX_DELAY_ACTIVE_COUNT"], 4)
        self.assertEqual(result["GRAY_BUS_SKEW_ACTIVE_COUNT"], 4)
        self.assertEqual(result["GRAY_FINITE_TIMING_COUNT"], 4)
        self.assertEqual(result["TCK_INDEPENDENT_PASS"], 38)
        self.assertEqual(result["TCK_INDEPENDENT_FAIL"], 0)
        self.assertFalse(result["PHYSICAL_HOST_TCK_CONTRACT_PROVEN"])


if __name__ == "__main__":
    unittest.main()
