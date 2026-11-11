from pathlib import Path
import unittest

from review_v5_common_reset_timing import analyze


class V5CommonResetTimingTest(unittest.TestCase):
    def test_hash_bound_four_bscan_failures_and_global_tns_breakdown(self):
        result = analyze(Path(__file__).resolve().parents[2])
        self.assertTrue(result["MANIFEST_AND_SHA256SUMS_VALID"])
        self.assertEqual(result["FAILED_PATHS"], 4)
        self.assertEqual(result["BSCAN_CLOCK_SETUP_FAILING_ENDPOINTS"], 4)
        self.assertEqual(result["GLOBAL_SETUP_FAILING_ENDPOINTS"], 15)
        self.assertAlmostEqual(result["GLOBAL_TNS_NS"], -0.750)
        self.assertAlmostEqual(result["BSCAN_CLOCK_TNS_NS"], -0.652)
        self.assertEqual(result["NON_BSCAN_SETUP_FAILING_ENDPOINTS"], 11)
        self.assertAlmostEqual(result["NON_BSCAN_TNS_NS"], -0.098)

    def test_route_and_branch_skew_dominate_reset_paths(self):
        result = analyze(Path(__file__).resolve().parents[2])
        paths = result["PATH_DETAILS"]
        self.assertEqual([p["SLACK_NS"] for p in paths], [-0.272, -0.217, -0.102, -0.062])
        self.assertEqual([p["CLOCK_SKEW_NS"] for p in paths[:3]], [-5.708, -5.714, -5.714])
        self.assertTrue(all(p["ROUTE_FRACTION"] > 0.95 for p in paths))
        self.assertTrue(all(p["COMMON_RESET_NET_FANOUT"] == 213 for p in paths[:3]))
        self.assertTrue(result["COMMON_RESET_ARCHITECTURE_VALID"])
        self.assertTrue(result["SYNC_DISTRIBUTION_STAGE_LIKELY_REQUIRED"])
        self.assertFalse(result["PHYSICAL_ONLY_FIX_LIKELY"])


if __name__ == "__main__":
    unittest.main()
