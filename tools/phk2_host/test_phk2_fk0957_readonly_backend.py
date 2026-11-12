from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from phk2_fk0957_identity_observer import Refusal, TargetSelector
import phk2_fk0957_identity_observer as observer
from phk2_fk0957_readonly_backend import (
    Device, FK0957ReadOnlyBackend, SUPPORTED_TARGET_SELECTOR,
    SysfsCatalog,
)


def target(**kw):
    data = dict(vid="0403", pid="6010", serial="153300000957A",
                manufacturer="Xilinx", product="SQRL FK", usb_path="1-2.3",
                interface_number="00", interface_name="A", sysfs_path="/mock/1-2")
    data.update(kw)
    return Device(**data)


class FakeCatalog:
    def __init__(self, devices):
        self.devices = list(devices)
        self.enumerations = 0
        self.open_calls = []
        self.open_selected_calls = []

    def enumerate_fk(self):
        self.enumerations += 1
        return list(self.devices)


class BackendTests(unittest.TestCase):
    def backend(self, *devices):
        return FK0957ReadOnlyBackend(FakeCatalog(devices))

    def test_fk0957_exact_match(self):
        backend = self.backend(target())
        selected = backend.select_exact(TargetSelector())
        self.assertEqual(selected.matching_devices, 1)
        self.assertTrue(selected.serial_scoped_before_open)
        self.assertEqual(selected.adapter_serial, "153300000957A")

    def test_no_match_refuses(self):
        with self.assertRaises(Refusal):
            self.backend().select_exact(TargetSelector())

    def test_wrong_serial_refuses(self):
        with self.assertRaises(Refusal):
            self.backend(target(serial="153300000958A")).select_exact(TargetSelector())

    def test_missing_serial_refuses(self):
        with self.assertRaises(Refusal):
            self.backend(target(serial="")).select_exact(TargetSelector())

    def test_unreadable_high_bus_usb_candidate_refuses_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "9-1").mkdir()
            with self.assertRaisesRegex(Refusal, "metadata incomplete: 9-1"):
                SysfsCatalog(root).enumerate_fk()

    def test_duplicate_match_refuses(self):
        with self.assertRaises(Refusal):
            self.backend(target(), target()).select_exact(TargetSelector())

    def test_fk0957_plus_another_fk_refuses_as_ambiguous(self):
        with self.assertRaises(Refusal):
            self.backend(target(), target(serial="153300000711A", usb_path="1-4.2")).select_exact(TargetSelector())

    def test_wrong_ftdi_interface_refuses(self):
        with self.assertRaises(Refusal):
            self.backend(target(interface_name="B", interface_number="01")).select_exact(TargetSelector())

    def test_serial_change_after_resolution_refuses_before_open(self):
        catalog = FakeCatalog([target()])
        backend = FK0957ReadOnlyBackend(catalog)
        selected = backend.select_exact(TargetSelector())
        catalog.devices[:] = [replace(target(), serial="153300000958A")]
        with self.assertRaises(Refusal):
            backend.open_selected(selected)
        self.assertEqual(catalog.open_calls, [])

    def test_backend_hash_is_computed_and_source_pins_present(self):
        backend = self.backend(target())
        self.assertEqual(len(backend.BACKEND_IDENTITY["sha256"]), 64)
        self.assertEqual(len(backend.BACKEND_IDENTITY["source_commit"]), 40)
        self.assertIn("usb_selection.cpp", backend.BACKEND_IDENTITY["source_file_hashes"])
        self.assertEqual(backend.BACKEND_IDENTITY["supported_target_selector"],
                         __import__("json").dumps(SUPPORTED_TARGET_SELECTOR, sort_keys=True, separators=(",", ":")))

    def test_backend_hash_mismatch_refuses(self):
        with self.assertRaises(Refusal):
            observer._load_reviewed_backend(
                "phk2_fk0957_readonly_backend:create_backend", "0" * 64)

    def test_exact_source_pinned_backend_loads_without_discovery(self):
        spec = "phk2_fk0957_readonly_backend:create_backend"
        backend = observer._load_reviewed_backend(spec, observer.REVIEWED_BACKENDS[spec])
        self.assertEqual(backend.BACKEND_IDENTITY["name"], "phk2_fk0957_sysfs_readonly")

    def test_stale_reference_source_pin_refuses(self):
        spec = "phk2_fk0957_readonly_backend:create_backend"
        stale = {"source_commit": "f" * 40, "source_file_hashes": {}}
        with mock.patch.dict(observer.REVIEWED_BACKEND_SOURCE_PINS, {spec: stale}):
            with self.assertRaises(Refusal):
                observer._load_reviewed_backend(spec, observer.REVIEWED_BACKENDS[spec])

    def test_altered_backend_is_refused_before_any_module_code_executes(self):
        spec = "phk2_fk0957_readonly_backend:create_backend"
        pinned = observer.REVIEWED_BACKENDS[spec]
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "module-executed"
            altered = Path(temp) / "altered_backend.py"
            altered.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
                "def create_backend(): return object()\n"
            )
            with mock.patch.dict(observer.REVIEWED_BACKEND_PATHS, {spec: str(altered)}):
                with self.assertRaises(Refusal):
                    observer._load_reviewed_backend(spec, pinned)
            self.assertFalse(marker.exists(), "altered source executed before hash refusal")

    def test_attempted_forbidden_methods_are_not_exposed(self):
        backend = self.backend(target())
        for name in ("write", "write_exact", "program", "reset", "reconfigure",
                     "tap_update", "shift_ir", "shift_dr", "mpsse", "send_command"):
            self.assertFalse(callable(getattr(backend, name, None)), name)
        transport = backend.open_selected(backend.select_exact(TargetSelector()))
        for name in ("write", "write_exact", "program", "reset", "shift_ir", "shift_dr", "mpsse"):
            self.assertFalse(callable(getattr(transport, name, None)), name)

    def test_second_device_open_is_impossible_and_peer_refuses(self):
        catalog = FakeCatalog([target(), target(serial="153300000711A", usb_path="1-5")])
        backend = FK0957ReadOnlyBackend(catalog)
        with self.assertRaises(Refusal):
            backend.select_exact(TargetSelector())
        self.assertEqual(catalog.open_calls, [])
        self.assertEqual(catalog.open_selected_calls, [])

    def test_hidden_initialization_write_absent(self):
        source = Path(__file__).with_name("phk2_fk0957_readonly_backend.py").read_text()
        self.assertNotIn("ftdi_write_data", source)
        self.assertNotIn("ftdi_set_bitmode", source)
        self.assertNotIn("libusb_claim_interface", source)
        catalog = FakeCatalog([target()])
        backend = FK0957ReadOnlyBackend(catalog)
        selection = backend.select_exact(TargetSelector())
        transport = backend.open_selected(selection)
        self.assertEqual(transport.observe()["adapter_serial"], "153300000957A")
        self.assertEqual(catalog.open_calls, [])
        self.assertEqual(catalog.open_selected_calls, [])

    def test_readable_identity_scope_and_unavailable_jtag_data(self):
        backend = self.backend(target())
        selection = backend.select_exact(TargetSelector())
        obs = backend.open_selected(selection).observe()
        self.assertEqual(obs["adapter_serial"], "153300000957A")
        self.assertEqual(obs["card_id"], "153300000957")
        self.assertNotIn("idcode", obs)
        self.assertNotIn("fpga_dna", obs)
        self.assertNotIn("target_part", obs)
        self.assertEqual(backend.BACKEND_IDENTITY["jtag_or_fpga_observation"],
                         "UNAVAILABLE_READ_ONLY_BACKEND_DOES_NOT_OPEN_TRANSPORT")


if __name__ == "__main__":
    unittest.main()
