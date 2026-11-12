from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_idcode_gate as gate
import phk2_fk0957_remote_orchestrator as remote

DESCRIPTOR = Path("/home/rmann/.local/share/sidecar/fk0957-descriptor-identity-20261112.json")


class IdcodeGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = DESCRIPTOR.read_bytes()
        cls.digest = hashlib.sha256(cls.raw).hexdigest()
        cls.document = json.loads(cls.raw)
        cls.stamp = gate._timestamp(cls.document["payload"]["unsigned_evidence"]["acquisition_timestamp"])

    def at_descriptor_time(self, value):
        class TestClock:
            @staticmethod
            def now(tz=timezone.utc):
                return value

            fromisoformat = staticmethod(datetime.fromisoformat)
        return mock.patch.object(gate, "datetime", TestClock)

    def authorized(self):
        with self.at_descriptor_time(self.stamp + timedelta(seconds=1)):
            return gate.authorize_descriptor(self.raw, expected_sha256=self.digest)

    def test_trusted_signer_is_pinned_and_not_a_caller_argument(self):
        self.assertEqual(gate.TRUSTED_SIGNER_FINGERPRINT_SHA256,
                         "8bc668e59192ed62070138bb70be70073b9757943697f039c9db9bd27b9ab9f9")
        self.assertEqual(hashlib.sha256(gate.base64.b64decode(
            gate.TRUSTED_SIGNER_PUBLIC_DER_B64, validate=True)).hexdigest(),
            gate.TRUSTED_SIGNER_FINGERPRINT_SHA256)
        self.assertTrue(remote.verify_signed(self.document, gate._trusted_signer()))
        self.assertNotIn("public_key", inspect.signature(gate.authorize_descriptor).parameters)

    def test_evidence_sha_signature_and_freshness_fail_closed(self):
        with self.at_descriptor_time(self.stamp + timedelta(seconds=1)):
            permit = gate.authorize_descriptor(self.raw, expected_sha256=self.digest)
            with self.assertRaises(gate.Refusal):
                gate.authorize_descriptor(self.raw, expected_sha256="0" * 64)
            altered = dict(self.document)
            altered["payload"] = dict(altered["payload"])
            altered["payload"]["unsigned_evidence"] = dict(altered["payload"]["unsigned_evidence"])
            altered["payload"]["unsigned_evidence"]["usb_descriptor_serial"] = "153300000957A"
            tampered = remote.canonical(altered)
            with self.assertRaises(gate.Refusal):
                gate.authorize_descriptor(tampered, expected_sha256=hashlib.sha256(tampered).hexdigest())
        self.assertEqual(permit.descriptor_evidence_sha256, self.digest)
        with self.at_descriptor_time(self.stamp + timedelta(seconds=gate.MAX_DESCRIPTOR_AGE_SECONDS + 1)):
            with self.assertRaisesRegex(gate.Refusal, "stale"):
                gate.authorize_descriptor(self.raw, expected_sha256=self.digest)

    def test_all_descriptor_identity_pins_are_exact(self):
        evidence = self.document["payload"]["unsigned_evidence"]
        provenance = self.document["payload"]["provenance"]
        with self.at_descriptor_time(self.stamp + timedelta(seconds=1)):
            gate._validate_descriptor_payload(evidence, provenance)
            for field, value in (("target_selector", "FK0958"),
                                 ("adapter_serial", "153300000957"),
                                 ("usb_descriptor_serial", "153300000957A"),
                                 ("ftdi_vid", "0404"), ("ftdi_pid", "6011"),
                                 ("manufacturer", "Other"), ("product", "Other"),
                                 ("interface", "B")):
                altered = dict(evidence, **{field: value})
                with self.subTest(field=field), self.assertRaises(gate.Refusal):
                    gate._validate_descriptor_payload(altered, provenance)

    def test_fixed_transaction_bits_match_canonical_87_tck_sequence(self):
        txn = gate.fixed_transaction()
        expected_tms = ("111110" "1100" "000001" "10" "100" + "0" * 63 + "1" "10")
        expected_tdi = ("0" * 6 + "0" * 4 + "100100" + "0" * (2 + 3 + 64 + 2))
        self.assertEqual(len(expected_tms), 87)
        self.assertEqual(len(expected_tdi), 87)
        self.assertEqual("".join(map(str, txn.tms_bits)), expected_tms)
        self.assertEqual("".join(map(str, txn.tdi_bits)), expected_tdi)
        self.assertEqual(txn.ir_value, 0x09)
        self.assertEqual(txn.ir_length, 6)
        self.assertEqual(txn.dr_length, 64)
        self.assertEqual(txn.bit_order, "LSB_FIRST")
        self.assertEqual(txn.initial_tap_state, "UNKNOWN")
        self.assertEqual(txn.expected_tck_count, 87)
        self.assertEqual(txn.final_tap_state, "RUN_TEST_IDLE")
        self.assertIn("BLOCKED", txn.capture_edge)
        self.assertEqual(gate.transaction_definition_sha256(),
                         "bcc12df9f88baa27ca65ed4c03156a4132c5005760cc5fdfa61d56083b9323c0")

    def test_authorized_permit_nonce_is_random_and_single_use(self):
        with self.at_descriptor_time(self.stamp + timedelta(seconds=1)):
            first = gate.authorize_descriptor(self.raw, expected_sha256=self.digest)
            second = gate.authorize_descriptor(self.raw, expected_sha256=self.digest)
        self.assertNotEqual(first.permit_nonce, second.permit_nonce)
        gate._consume_permit(first)
        with self.assertRaisesRegex(gate.Refusal, "replayed"):
            gate._consume_permit(first)

    def test_gate_exposes_no_transport_or_generic_scan_entrypoint(self):
        self.assertFalse(hasattr(gate, "read_once"))
        self.assertFalse(hasattr(gate, "FixedIdcodeTransport"))
        self.assertFalse(hasattr(gate, "_validate_adapter_observation"))
        self.assertFalse(hasattr(gate, "shift_ir"))
        self.assertFalse(hasattr(gate, "shift_dr"))
        self.assertFalse(hasattr(gate, "execute_scan"))


if __name__ == "__main__":
    unittest.main()
