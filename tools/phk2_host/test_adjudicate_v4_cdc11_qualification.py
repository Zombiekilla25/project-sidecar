from pathlib import Path
import unittest

from adjudicate_v4_cdc11_qualification import audit


class V4Cdc11CrossQualificationAuditTest(unittest.TestCase):
    def test_rejects_unsupported_three_domain_premise(self):
        result = audit(Path(__file__).resolve().parents[2])
        self.assertFalse(result["RIGHT_ACCEPTANCE_PREMISE_VALID"])
        self.assertFalse(result["RIGHT_CODE_CHECKS_DISTINCT_DOMAIN_CLOCK_OBJECTS"])
        self.assertEqual(result["BSCAN_LOGICAL_CLOCK_DOMAINS"], 1)
        self.assertEqual(result["BSCAN_PHYSICAL_CLOCK_BRANCHES"], 3)
        self.assertEqual(result["INDEPENDENT_RELEASE_CHAINS"], 3)

    def test_reset_divergence_invalidates_qualification_promotion(self):
        result = audit(Path(__file__).resolve().parents[2])
        self.assertTrue(result["DIVERGENT_RELEASE_EDGE_POSSIBLE"])
        self.assertFalse(result["DIVERGENT_RELEASE_ARCHITECTURALLY_SAFE"])
        self.assertFalse(result["CDC11_ACCEPTANCE_PASS"])
        self.assertFalse(result["RIGHT_38_OF_38_RESULT_VALID"])
        self.assertTrue(result["RTL_FIX_REQUIRED"])
        self.assertEqual(result["FAILING_RESET_ROW_IDS"], [3, 4, 5])
        self.assertTrue(result["RIGHT_COMPONENT_CASE_EXECUTION_COUNTS_RETAINED"])


if __name__ == "__main__":
    unittest.main()
