#!/usr/bin/env python3
"""Dry-run checks for strict immutable v4 CDC-11 intake."""
from pathlib import Path
import unittest

from v4_cdc11_five_row_gate import analyze, infer


class V4FiveRowGateDryRun(unittest.TestCase):
    def test_exact_immutable_bundle_is_accounted_but_not_overaccepted(self):
        root = Path(__file__).resolve().parents[2]
        result = analyze(root)
        self.assertTrue(result["V4_IDENTITY_VERIFIED"])
        self.assertEqual(result["CDC11_ROWS_EXPECTED"], 5)
        self.assertEqual(result["CDC11_ROWS_ACCOUNTED"], 5)
        self.assertEqual(result["RESET_ROWS"], 3)
        self.assertEqual(result["FIFO_HANDSHAKE_ROWS"], 2)
        self.assertEqual(result["CONTROL_ROWS"], 0)
        self.assertEqual(result["DATA_ROWS"], 0)
        self.assertEqual(result["OTHER_ROWS"], 0)
        self.assertFalse(result["CDC11_ACCEPTANCE_PASS"])
        self.assertTrue(result["CDC11_INDETERMINATE"])
        self.assertEqual(result["FAILING_OR_INDETERMINATE_ROWS"], [1, 2, 3, 4, 5])

    def test_category_comes_from_endpoint_not_lane_label(self):
        self.assertEqual(infer({"DESTINATION": "input_fifo/rd_up_w1_reg/D",
                                "TOPOLOGY": "CONTROL"}), "FIFO_LOCAL_UP_HANDSHAKE")
        self.assertEqual(infer({"DESTINATION": "scan2_reset_release/release_pipe_reg[0]/PRE",
                                "TOPOLOGY": "DATA"}), "RESET_RELEASE")
        self.assertEqual(infer({"DESTINATION": "mystery_reg/D",
                                "TOPOLOGY": "ASYNC_ASSERT_SYNC_RELEASE_RESET"}), "OTHER")


if __name__ == "__main__":
    unittest.main()
