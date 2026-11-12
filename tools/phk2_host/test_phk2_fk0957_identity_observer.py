from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phk2_fk0957_identity_observer import (
    EXPECTED_ADAPTER_SERIAL, EXPECTED_USB_SERIAL, EXPECTED_CARD_ID, Refusal, Selection,
    TargetSelector, observe,
)


class FakeTransport:
    METHOD_ACCESS = {"observe": "READ_ONLY", "close": "READ_ONLY"}

    def __init__(self, observations=None, *, program=False, reset=False):
        self.observations = observations or {
            "adapter_identity": "FTDI adapter",
            "adapter_serial": EXPECTED_ADAPTER_SERIAL,
            "usb_descriptor_serial": EXPECTED_USB_SERIAL,
            "card_id": EXPECTED_CARD_ID,
            "fpga_dna": "4000000001295d813c80a445",
            "idcode": "04b69093",
            "target_part": "xcvu33p-fsvh2104-2-e",
            "jtag_chain": ["04b69093"],
            "loaded_image_identity": None,
            "bridge_identity": {"name": "mock", "version": "1"},
            "accessed_card_ids": [EXPECTED_CARD_ID],
        }
        self.closed = False
        if program:
            self.program = lambda: None
        if reset:
            self.reset = lambda: None

    def observe(self):
        return self.observations

    def close(self):
        self.closed = True


class FakeBackend:
    METHOD_ACCESS = {"select_exact": "READ_ONLY", "open_selected": "READ_ONLY",
                     "observe": "READ_ONLY", "close": "READ_ONLY"}
    BACKEND_IDENTITY = {"name": "fake-reviewed", "version": "1", "sha256": "a" * 64,
                        "source_commit": "b" * 40, "source_file_hashes": "{}"}
    SINGLE_DEVICE_SERIAL_SCOPE = True

    def __init__(self, *, serial=EXPECTED_USB_SERIAL, adapter=EXPECTED_ADAPTER_SERIAL, card=EXPECTED_CARD_ID,
                 matches=1, scoped=True, requires_write=False, observations=None,
                 program=False, reset=False):
        self.serial, self.adapter, self.card = serial, adapter, card
        self.matches, self.scoped, self.requires_write = matches, scoped, requires_write
        self.transport = FakeTransport(observations, program=program, reset=reset)
        self.open_count = 0
        self.selection_count = 0
        self.method_access = dict(self.METHOD_ACCESS)

    def select_exact(self, selector):
        self.selection_count += 1
        return Selection(adapter_serial=self.adapter, usb_descriptor_serial=self.serial,
                         card_id=self.card, serial_suffix=selector.serial_suffix,
                         matching_devices=self.matches, serial_scoped_before_open=self.scoped,
                         requires_write=self.requires_write, endpoint_token="opaque-selected-token")

    def open_selected(self, selection):
        assert self.selection_count == 1, "transport opened before target selection gate"
        self.open_count += 1
        return self.transport


class IdentityObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "signer.pem"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.repo = Path(__file__).resolve().parents[2]

    def tearDown(self):
        self.temp.cleanup()

    def call(self, backend, selector=None):
        return observe(backend, selector or TargetSelector(), repo=self.repo,
                       signing_key_path=self.key_path)

    def assert_refused_before_open(self, backend, selector=None):
        with self.assertRaises(Refusal):
            self.call(backend, selector)
        self.assertEqual(backend.open_count, 0)

    def test_success_is_signed_hash_bound_and_explicitly_read_only(self):
        backend = FakeBackend()
        evidence = self.call(backend)
        payload = evidence["payload"]
        self.assertEqual(payload["write_count"], 0)
        self.assertEqual(payload["program_count"], 0)
        self.assertEqual(payload["reset_count"], 0)
        self.assertEqual(payload["observations"]["adapter_serial"], "153300000957A")
        self.assertEqual(payload["observations"]["usb_descriptor_serial"], "153300000957")
        canonical = __import__("json").dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertEqual(evidence["payload_sha256"], hashlib.sha256(canonical).hexdigest())
        self.key.public_key().verify(bytes.fromhex(evidence["signature_hex"]), canonical)
        self.assertEqual(backend.open_count, 1)
        self.assertTrue(backend.transport.closed)

    def test_wrong_serial_refuses_before_open(self):
        self.assert_refused_before_open(FakeBackend(serial="153300000958"))

    def test_no_serial_refuses_before_open(self):
        self.assert_refused_before_open(FakeBackend(serial=""))

    def test_multiple_matches_refuse_before_open(self):
        self.assert_refused_before_open(FakeBackend(matches=2))

    def test_ambiguous_backend_refuses_before_open(self):
        backend = FakeBackend(scoped=False)
        backend.SINGLE_DEVICE_SERIAL_SCOPE = False
        self.assert_refused_before_open(backend)

    def test_backend_requiring_write_refuses_before_open(self):
        self.assert_refused_before_open(FakeBackend(requires_write=True))

    def test_backend_with_program_capability_refuses_before_open(self):
        backend = FakeBackend()
        backend.program = lambda: None
        self.assert_refused_before_open(backend)

    def test_transport_with_program_capability_refuses_without_calling_it(self):
        backend = FakeBackend(program=True)
        with self.assertRaises(Refusal):
            self.call(backend)
        self.assertEqual(backend.open_count, 1)

    def test_transport_with_reset_capability_refuses_without_calling_it(self):
        backend = FakeBackend(reset=True)
        with self.assertRaises(Refusal):
            self.call(backend)
        self.assertEqual(backend.open_count, 1)

    def test_identity_change_during_observation_refuses(self):
        data = FakeTransport().observations
        data["usb_descriptor_serial"] = "153300000958"
        backend = FakeBackend(observations=data)
        with self.assertRaises(Refusal):
            self.call(backend)
        self.assertEqual(backend.selection_count, 1)
        self.assertEqual(backend.open_count, 1)

    def test_second_card_access_refuses(self):
        data = FakeTransport().observations
        data["accessed_card_ids"] = [EXPECTED_CARD_ID, "153300000958"]
        backend = FakeBackend(observations=data)
        with self.assertRaises(Refusal):
            self.call(backend)
        self.assertEqual(backend.open_count, 1)

    def test_wrong_selector_refuses_before_backend_selection_or_open(self):
        backend = FakeBackend()
        selector = TargetSelector(adapter_serial="153300000958A", card_id="153300000958",
                                  serial_suffix="0958")
        self.assert_refused_before_open(backend, selector)
        self.assertEqual(backend.selection_count, 0)

    def test_backend_method_manifest_must_be_exact_and_read_only(self):
        backend = FakeBackend()
        backend.METHOD_ACCESS = {**backend.METHOD_ACCESS, "program": "WRITE"}
        self.assert_refused_before_open(backend)


if __name__ == "__main__":
    unittest.main()
