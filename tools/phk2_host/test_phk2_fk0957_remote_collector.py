from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_remote_collector as collector


class CollectorRefusalEnvelopeTests(unittest.TestCase):
    def test_every_refusal_code_emits_only_the_canonical_bounded_envelope(self):
        expected_fields = {
            "status", "phase", "refusal_code", "cards_opened", "second_card_opened",
            "write_count", "reset_count", "program_count", "jtag_operations",
        }
        for code in sorted(collector.REFUSAL_CODES):
            with self.subTest(code=code):
                envelope = collector.refusal_envelope(code)
                self.assertEqual(set(envelope), expected_fields)
                self.assertEqual(envelope["status"], "REFUSED")
                self.assertEqual(envelope["phase"], "COLLECTOR")
                self.assertEqual(envelope["refusal_code"], code)
                self.assertEqual(envelope["cards_opened"], 0)
                self.assertIs(envelope["second_card_opened"], False)
                self.assertEqual([envelope[k] for k in
                    ("write_count", "reset_count", "program_count", "jtag_operations")], [0, 0, 0, 0])
                raw = collector.canonical(envelope)
                self.assertLessEqual(len(raw), 4096)
                self.assertNotIn(b"exception", raw.lower())

    def test_unknown_internal_exception_code_collapses_to_enumerated_internal_code(self):
        self.assertEqual(collector._backend_refusal_code(RuntimeError("secret text")), "INTERNAL_REFUSAL")
        self.assertEqual(collector.refusal_envelope("NOT_A_CODE")["refusal_code"], "INTERNAL_REFUSAL")


if __name__ == "__main__":
    unittest.main()
