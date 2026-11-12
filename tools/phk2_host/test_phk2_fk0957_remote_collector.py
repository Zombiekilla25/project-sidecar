from __future__ import annotations

from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

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

    def collect_fixture(self, *, usb_serial="153300000957", adapter_serial="153300000957A"):
        observation = {
            "adapter_identity": {"vid": "0403", "pid": "6010", "manufacturer": "Xilinx",
                                 "product": "SQRL FK", "interface": "A", "usb_path": "1-9.3"},
            "adapter_serial": adapter_serial, "usb_descriptor_serial": usb_serial,
            "card_id": "153300000957", "accessed_card_ids": ["153300000957"],
        }

        class Transport:
            def observe(self): return observation
            def close(self): pass

        class Backend:
            BACKEND_IDENTITY = {"source_commit": "e2feedcfde44563854a3cf41fe4526c231ed385b"}
            def select_exact(self, selector): return SimpleNamespace(card_id="153300000957")
            def open_selected(self, selection): return Transport()

        observer_module = SimpleNamespace(TargetSelector=lambda: object())
        backend_module = SimpleNamespace(FK0957ReadOnlyBackend=Backend)
        with mock.patch.object(collector, "_load_reviewed_backend",
                               return_value=(Path("/tmp/mock-bundle"), "b" * 64,
                                             observer_module, backend_module)), \
             mock.patch.dict("os.environ", {"FK0957_TARGET": "FK0957", "FK0957_BUNDLE_ROOT": "/tmp/mock-bundle"}):
            return collector.collect("a" * 64, "c" * 64)

    def test_success_evidence_keeps_adapter_and_usb_serial_distinct(self):
        evidence = self.collect_fixture()
        self.assertEqual(evidence["target_selector"], "FK0957")
        self.assertEqual(evidence["adapter_serial"], "153300000957A")
        self.assertEqual(evidence["usb_descriptor_serial"], "153300000957")
        self.assertEqual(evidence["fk0957_mapping"], "153300000957")
        self.assertNotIn("fpga_dna", evidence)
        self.assertNotIn("idcode", evidence)
        self.assertNotIn("target_part", evidence)

    def test_usb_serial_does_not_alias_adapter_serial_and_wrong_values_refuse(self):
        for serial in ("153300000957A", "153300000958", "0957", "15330000095", "153300000957-extra"):
            with self.subTest(serial=serial), self.assertRaises(collector.CollectorRefusal) as caught:
                self.collect_fixture(usb_serial=serial)
            self.assertEqual(caught.exception.refusal_code, "EXPECTED_SERIAL_NOT_FOUND")

    def test_missing_usb_serial_or_adapter_mapping_refuses(self):
        with self.assertRaises(collector.CollectorRefusal) as caught:
            self.collect_fixture(usb_serial=None)
        self.assertEqual(caught.exception.refusal_code, "INCOMPLETE_DESCRIPTOR_METADATA")
        with self.assertRaises(collector.CollectorRefusal) as caught:
            self.collect_fixture(adapter_serial="")
        self.assertEqual(caught.exception.refusal_code, "INCOMPLETE_DESCRIPTOR_METADATA")


if __name__ == "__main__":
    unittest.main()
