from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator
import phk2_fk0957_topology_transport as transport
import phk2_fk0957_topology_live_cli as cli

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class _BinaryStdout:
    def __init__(self):
        self.buffer = io.BytesIO()


@contextmanager
def captured_main(argv):
    stdout = _BinaryStdout()
    with mock.patch.object(sys, "stdout", stdout):
        result = cli.main(argv)
    yield result, stdout.buffer.getvalue()


def signed_fake_record(signer):
    raw_a = bytes.fromhex("01 02 03")
    raw_b = bytes.fromhex("04 05 06")
    payload = {
        "schema": "fk0957-topology-discovery-record-v1",
        "topology_discovery_only": True,
        "idcode_qualification_pass": False,
        "fpga_dna_observed": False,
        "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
        "card_id": "FK0957",
        "adapter_serial": "153300000957A",
        "usb_descriptor_serial": "153300000957",
        "scan_a_tck_count": 591,
        "scan_b_tck_count": 586,
        "total_tck_count": 1177,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
        "jtag_operation_count": 1,
        "scan_a_transaction_sha256": "a" * 64,
        "scan_b_transaction_sha256": "b" * 64,
        "scan_a_raw_tdo_hex": raw_a.hex(),
        "scan_b_raw_tdo_hex": raw_b.hex(),
        "aggregate_dr_length": 33,
        "observed_taps_tdo_to_tdi": [{"idcode": "04b69093"}],
    }
    encoded = orchestrator.canonical(payload)
    public_der = signer.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(public_der).hexdigest()
    return {
        "payload": payload,
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
        "signature_algorithm": "Ed25519",
        "signature_hex": signer.sign(encoded).hex(),
        "signer_fingerprint": fingerprint,
    }, fingerprint


class LiveCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.descriptor = self.root / "descriptor.json"
        self.descriptor.write_bytes(b"signed descriptor fixture")
        self.output = self.root / "topology.json"

    def tearDown(self):
        self.temp.cleanup()

    def test_actual_cli_forwards_canonical_refusal_for_every_phase(self):
        phases = sorted(transport.REFUSAL_PHASES)
        for phase in phases:
            expected_code = transport._DEFAULT_REFUSAL_CODE.get(phase, "INTERNAL_REFUSAL")
            envelope = transport.RefusalEnvelope(
                phase, expected_code, -7, "unknown", 0, 0, 0, 0, 0, 1, 1)
            refusal = transport.Refusal("must never be printed secret=/private/key", envelope=envelope)
            with self.subTest(phase=phase), \
                 mock.patch.object(transport, "perform_fk0957_topology_discovery_once",
                                   side_effect=refusal) as operation, \
                 mock.patch.object(transport, "issue_fk0957_topology_permit",
                                   side_effect=AssertionError("CLI must use the single workflow")):
                with captured_main(["--descriptor-evidence", str(self.descriptor),
                                    "--output", str(self.output)]) as (rc, output):
                    self.assertEqual(rc, 2)
                value = json.loads(output)
                self.assertEqual(value["phase"], phase)
                self.assertEqual(value["code"], expected_code)
                self.assertEqual(value["status"], "REFUSED")
                self.assertEqual(value["permit_consumed"], 1)
                self.assertEqual(output, orchestrator.canonical(envelope.as_dict()) + b"\n")
                self.assertNotIn(b"must never", output)
                self.assertNotIn(b"secret", output)
                self.assertNotIn(b"/private", output)
                self.assertFalse(self.output.exists())
                operation.assert_called_once()

    def test_actual_cli_fake_success_verifies_and_atomically_writes_record(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(transport, "perform_fk0957_topology_discovery_once",
                               return_value=document) as operation:
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 0)
        operation.assert_called_once_with(
            self.descriptor.read_bytes(), hashlib.sha256(self.descriptor.read_bytes()).hexdigest())
        summary = json.loads(output)
        self.assertEqual(summary["status"], "SIGNED")
        self.assertEqual((summary["scan_a_tck_count"], summary["scan_b_tck_count"],
                          summary["total_tck_count"]), (591, 586, 1177))
        self.assertEqual(summary["scan_a_raw_tdo_sha256"],
                         hashlib.sha256(bytes.fromhex(document["payload"]["scan_a_raw_tdo_hex"])).hexdigest())
        self.assertEqual(summary["scan_b_raw_tdo_sha256"],
                         hashlib.sha256(bytes.fromhex(document["payload"]["scan_b_raw_tdo_hex"])).hexdigest())
        self.assertTrue(summary["signature_verified"])
        self.assertEqual(summary["parse_status"], "PASS")
        written = json.loads(self.output.read_bytes())
        self.assertEqual(written, document)
        self.assertEqual(summary["evidence_sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual((summary["write_count"], summary["reset_count"],
                          summary["program_count"]), (0, 0, 0))

    def test_argument_surface_rejects_transport_controls(self):
        with captured_main(["--descriptor-evidence", str(self.descriptor),
                            "--output", str(self.output), "--tms", "111"]
                           ) as (rc, output):
            self.assertEqual(rc, 2)
        value = json.loads(output)
        self.assertEqual(value["phase"], "PRELIVE_VALIDATION")
        self.assertEqual(value["code"], "INTERNAL_REFUSAL")
        self.assertFalse(self.output.exists())

    def test_missing_descriptor_is_bounded_prelive_refusal(self):
        with captured_main(["--descriptor-evidence", str(self.root / "absent"),
                            "--output", str(self.output)]) as (rc, output):
            self.assertEqual(rc, 2)
        value = json.loads(output)
        self.assertEqual(value["phase"], "PRELIVE_VALIDATION")
        self.assertEqual(value["permit_consumed"], 0)
        self.assertNotIn(str(self.root), output.decode())

    def test_malformed_or_unbounded_refusal_becomes_internal_envelope(self):
        refusal = transport.Refusal("SECRET raw exception")
        stderr = io.StringIO()
        with mock.patch.object(transport, "perform_fk0957_topology_discovery_once",
                               side_effect=refusal), mock.patch.object(sys, "stderr", stderr):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 2)
        value = json.loads(output)
        self.assertEqual((value["phase"], value["code"]),
                         ("INTERNAL_REFUSAL", "INTERNAL_REFUSAL"))
        self.assertNotIn(b"SECRET", output)
        self.assertEqual(stderr.getvalue(), "")

    def test_contradictory_refusal_progress_is_discarded(self):
        envelope = transport.RefusalEnvelope(
            "DEVICE_OPEN", "DEVICE_OPEN_FAILED", None, 1, 0, 1, 8, 0, 0, 1, 1)
        refusal = transport.Refusal("secret contradiction", envelope=envelope)
        with mock.patch.object(transport, "perform_fk0957_topology_discovery_once",
                               side_effect=refusal):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 2)
        value = json.loads(output)
        self.assertEqual((value["phase"], value["code"]),
                         ("INTERNAL_REFUSAL", "INTERNAL_REFUSAL"))
        self.assertEqual(value["device_opened"], 0)
        self.assertEqual(value["scan_a_started"], 0)
        self.assertNotIn(b"secret", output)


if __name__ == "__main__":
    unittest.main()
