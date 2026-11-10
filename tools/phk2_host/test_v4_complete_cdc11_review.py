"""Checks the immutable complete v4 CDC-11 package review."""
from pathlib import Path
import unittest

from v4_complete_cdc11_review import review


class CompleteV4ReviewTest(unittest.TestCase):
    def test_hash_bound_complete_package_and_topology(self):
        result = review(Path(__file__).resolve().parents[2])
        self.assertTrue(result["MANIFEST_VALID"])
        self.assertTrue(result["SHA256SUMS_VALID"])
        self.assertEqual(result["CDC11_ROWS_ACCOUNTED"], 5)
        self.assertEqual(result["RESET_ROWS"], 3)
        self.assertEqual(result["FIFO_HANDSHAKE_ROWS"], 2)
        self.assertEqual(result["DISTINCT_RESET_DOMAINS"], 1)
        self.assertEqual(result["SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS"], 2)
        self.assertEqual(result["FAILING_ROW_IDS"], [3, 4, 5])
        self.assertTrue(result["CDC11_REAL_UNSAFE"])
        self.assertTrue(result["RTL_FIX_REQUIRED"])
        self.assertFalse(result["CDC11_ACCEPTANCE_PASS"])

    def test_bscan_object_collapse_and_reset_paths(self):
        result = review(Path(__file__).resolve().parents[2])
        self.assertEqual(result["BSCAN_TCK_PINS"], 3)
        self.assertEqual(result["UNIQUE_TCK_CLOCK_OBJECTS"], 1)
        self.assertEqual(result["UNIQUE_TCK_CLOCK_ROOTS"], 3)
        self.assertFalse(result["BSCAN_CLOCK_COLLAPSE_SAFE"])
        self.assertTrue(all(row["RECOVERY_REMOVAL_PASS"] for row in result["RESET_ROW_PROOFS"]))
        self.assertTrue(all(row["CDC9_MATCH"] for row in result["RESET_ROW_PROOFS"]))


if __name__ == "__main__":
    unittest.main()
