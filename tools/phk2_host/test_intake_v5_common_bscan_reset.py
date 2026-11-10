from pathlib import Path
import unittest

from intake_v5_common_bscan_reset import V4_SOURCE, Blocked, discover, source_audit


class V5CommonResetIntakeTest(unittest.TestCase):
    def test_old_v4_source_cannot_be_mistaken_for_v5(self):
        repo = Path(__file__).resolve().parents[2]
        with self.assertRaisesRegex(Blocked, "not v5"):
            source_audit(repo, V4_SOURCE)

    def test_no_current_v5_evidence_fails_closed(self):
        repo = Path(__file__).resolve().parents[2]
        result = discover(repo)
        self.assertFalse(result["CDC11_ACCEPTANCE_PASS"])
        self.assertFalse(result["EVIDENCE_READY"])
        self.assertIsNotNone(result["BLOCKER"])


if __name__ == "__main__":
    unittest.main()
