from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator
import phk2_fk0957_topology_transport as transport
import phk2_fk0957_topology_signing as signing
import phk2_fk0957_topology_live_cli as cli

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class _BinaryStdout:
    def __init__(self):
        self.buffer = io.BytesIO()


class _FailingWriteStream:
    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        os.close(self.fd)

    def write(self, _data):
        raise OSError("synthetic staging write failure")

    def flush(self):
        return None

    def fileno(self):
        return self.fd


class _FailingBinaryOutput:
    def write(self, _data):
        raise OSError("synthetic final report failure")

    def flush(self):
        return None


class _FailingStdout:
    def __init__(self):
        self.buffer = _FailingBinaryOutput()


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
        "production_git_head": "c" * 40,
        "worktree_clean": True,
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


def refusal_progress(phase):
    values = dict(target_candidates=0, device_opened=0,
                  scan_a_started=0, scan_a_tck_emitted=0,
                  scan_b_started=0, scan_b_tck_emitted=0,
                  transport_closed=0, permit_consumed=1,
                  operation_state="PRELIVE", close_from_state=None,
                  publication_state="NOT_STARTED")
    states = {
        "PRELIVE_VALIDATION": "PRELIVE", "PERMIT_VALIDATION": "PRELIVE",
        "LIBRARY_PROVENANCE": "PERMIT_VALIDATED", "FTDI_CONTEXT_CREATE": "RUNTIME_READY",
        "REMOTE_BOOTSTRAP": "RUNTIME_READY", "DEVICE_ENUMERATION": "ENUMERATING",
        "DEVICE_SELECTION": "ENUMERATING", "DEVICE_OPEN": "DEVICE_SELECTED",
        "MPSSE_INIT": "DEVICE_OPENED", "SCAN_A_WRITE": "SCAN_A_NAV_WRITE",
        "SCAN_A_READ": "SCAN_A_BULK_READ", "SCAN_B_WRITE": "SCAN_B_NAV_WRITE",
        "SCAN_B_READ": "SCAN_B_BULK_READ", "TRANSPORT_CLOSE": "TRANSPORT_CLOSING",
        "LOCAL_VALIDATION": "TRANSPORT_CLOSED", "LOCAL_SIGNING": "LOCAL_VALIDATED",
        "INTERNAL_REFUSAL": "PRELIVE",
    }
    values["operation_state"] = states[phase]
    if phase in {"PRELIVE_VALIDATION", "PERMIT_VALIDATION", "INTERNAL_REFUSAL"}:
        values["permit_consumed"] = 0
    if phase in {"DEVICE_SELECTION", "DEVICE_OPEN", "MPSSE_INIT", "SCAN_A_WRITE",
                 "SCAN_A_READ", "SCAN_B_WRITE", "SCAN_B_READ", "TRANSPORT_CLOSE",
                 "LOCAL_VALIDATION", "LOCAL_SIGNING"}:
        values["target_candidates"] = 1
    if phase in {"MPSSE_INIT", "SCAN_A_WRITE", "SCAN_A_READ", "SCAN_B_WRITE",
                 "SCAN_B_READ", "TRANSPORT_CLOSE", "LOCAL_VALIDATION", "LOCAL_SIGNING"}:
        values["device_opened"] = 1
    if phase in {"SCAN_A_WRITE", "SCAN_A_READ", "SCAN_B_WRITE", "SCAN_B_READ",
                 "TRANSPORT_CLOSE", "LOCAL_VALIDATION", "LOCAL_SIGNING"}:
        values["scan_a_started"] = 1
    if phase in {"SCAN_B_WRITE", "SCAN_B_READ", "TRANSPORT_CLOSE",
                 "LOCAL_VALIDATION", "LOCAL_SIGNING"}:
        values["scan_a_tck_emitted"] = 591
        values["scan_b_started"] = 1
    if phase == "SCAN_A_READ":
        values["scan_a_tck_emitted"] = 585
    if phase == "SCAN_B_READ":
        values["scan_b_tck_emitted"] = 580
    if phase == "TRANSPORT_CLOSE":
        values.update(scan_b_tck_emitted=586, transport_closed=0,
                      close_from_state="SCAN_B_COMPLETE")
    if phase in {"LOCAL_VALIDATION", "LOCAL_SIGNING"}:
        values.update(scan_b_tck_emitted=586, transport_closed=1,
                      close_from_state="SCAN_B_COMPLETE")
    if phase == "LOCAL_SIGNING":
        values["publication_state"] = "SIGNED_STAGED"
        values["operation_state"] = "SIGNED_STAGED"
    return values


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
            envelope = transport.RefusalEnvelope(phase, expected_code, -7,
                                                 **refusal_progress(phase))
            refusal = transport.Refusal("must never be printed secret=/private/key", envelope=envelope)
            with self.subTest(phase=phase), \
                 mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
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
                self.assertEqual(value["permit_consumed"], 1 if phase not in {
                    "PRELIVE_VALIDATION", "PERMIT_VALIDATION", "INTERNAL_REFUSAL"} else 0)
                self.assertEqual(output, orchestrator.canonical(envelope.as_dict()) + b"\n")
                self.assertNotIn(b"must never", output)
                self.assertNotIn(b"secret", output)
                self.assertNotIn(b"/private", output)
                self.assertFalse(self.output.exists())
                self.assertEqual({path.name for path in self.root.iterdir()}, {"descriptor.json"})
                operation.assert_called_once()

    def test_actual_cli_fake_success_verifies_and_atomically_writes_record(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
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
        self.assertEqual({path.name for path in self.root.iterdir()}, {"descriptor.json", "topology.json"})
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_summary_validation_failure_happens_before_evidence_publish(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                               return_value=document), \
             mock.patch.object(cli, "_success_summary", side_effect=ValueError("bad final summary")):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 2)
        refused = json.loads(output)
        self.assertEqual((refused["status"], refused["phase"], refused["code"]),
                         ("REFUSED", "INTERNAL_REFUSAL", "INTERNAL_REFUSAL"))
        self.assertFalse(self.output.exists())
        self.assertEqual({path.name for path in self.root.iterdir()}, {"descriptor.json"})

    def test_atomic_publish_failure_removes_private_staging_artifacts(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                               return_value=document), \
             mock.patch.object(cli.os, "link", side_effect=OSError("publish failed")):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 2)
        self.assertEqual(json.loads(output)["status"], "REFUSED")
        self.assertFalse(self.output.exists())
        self.assertEqual({path.name for path in self.root.iterdir()}, {"descriptor.json"})

    def test_failure_before_and_during_temp_write_leaves_no_staging_artifact(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        real_open = os.open

        def fail_staging_open(path, *args, **kwargs):
            if path == "record.tmp":
                raise OSError("synthetic failure before temp write")
            return real_open(path, *args, **kwargs)

        for failing_operation in ("open", "write"):
            with self.subTest(operation=failing_operation), \
                 mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
                 mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
                 mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                                   return_value=document):
                if failing_operation == "open":
                    patcher = mock.patch.object(cli.os, "open", side_effect=fail_staging_open)
                else:
                    patcher = mock.patch.object(cli.os, "fdopen", side_effect=lambda fd, *_a, **_k:
                                                _FailingWriteStream(fd))
                with patcher:
                    with captured_main(["--descriptor-evidence", str(self.descriptor),
                                        "--output", str(self.output)]) as (rc, output):
                        self.assertEqual(rc, 2)
                self.assertEqual(json.loads(output)["status"], "REFUSED")
                self.assertFalse(self.output.exists())
                self.assertEqual({path.name for path in self.root.iterdir()}, {"descriptor.json"})

    def test_ambiguous_post_link_error_is_resolved_as_published_success(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        real_link = os.link

        def link_then_raise(*args, **kwargs):
            real_link(*args, **kwargs)
            raise OSError("synthetic error after atomic no-replace publish")

        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                               return_value=document), \
             mock.patch.object(cli.os, "link", side_effect=link_then_raise):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output)["status"], "SIGNED")
        self.assertEqual(json.loads(self.output.read_bytes()), document)
        self.assertEqual({path.name for path in self.root.iterdir()},
                         {"descriptor.json", "topology.json"})

    def test_preexisting_hardlink_destination_is_refused_and_preserved(self):
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"preexisting")
        os.link(sentinel, self.output)
        with self.assertRaises(ValueError):
            cli._publish_evidence_atomic(self.output, b"signed-record")
        self.assertEqual(self.output.read_bytes(), b"preexisting")
        self.assertEqual(sentinel.stat().st_ino, self.output.stat().st_ino)
        self.assertEqual(self.output.stat().st_nlink, 2)

    def test_concurrent_output_creation_is_not_replaced_at_publish(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        real_link = os.link
        sentinel = b"concurrent non-evidence output"

        def create_destination_then_link(*args, **kwargs):
            self.output.write_bytes(sentinel)
            return real_link(*args, **kwargs)

        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                               return_value=document), \
             mock.patch.object(cli.os, "link", side_effect=create_destination_then_link):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 2)
        self.assertEqual(json.loads(output)["status"], "REFUSED")
        self.assertEqual(self.output.read_bytes(), sentinel)
        self.assertEqual({path.name for path in self.root.iterdir()},
                         {"descriptor.json", "topology.json"})

    def test_parent_rename_during_publish_rolls_back_original_dirfd_link(self):
        parent = self.root / "evidence-parent"
        moved = self.root / "evidence-parent-moved"
        parent.mkdir()
        output = parent / "record.json"
        real_link = os.link

        def link_then_move_parent(*args, **kwargs):
            real_link(*args, **kwargs)
            parent.rename(moved)
            parent.mkdir()

        with mock.patch.object(cli.os, "link", side_effect=link_then_move_parent):
            with self.assertRaises(ValueError):
                cli._publish_evidence_atomic(output, b"signed-record")
        self.assertFalse((moved / "record.json").exists())
        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [])

    def test_parent_symlink_or_replacement_during_publish_fails_closed(self):
        parent = self.root / "bound-parent"
        moved = self.root / "bound-parent-moved"
        replacement = self.root / "replacement-parent"
        parent.mkdir(); replacement.mkdir()
        output = parent / "record.json"
        real_link = os.link

        def link_then_replace_parent(*args, **kwargs):
            real_link(*args, **kwargs)
            parent.rename(moved)
            parent.symlink_to(replacement, target_is_directory=True)

        with mock.patch.object(cli.os, "link", side_effect=link_then_replace_parent):
            with self.assertRaises(ValueError):
                cli._publish_evidence_atomic(output, b"signed-record")
        self.assertFalse((moved / "record.json").exists())
        self.assertEqual(list(replacement.iterdir()), [])
        self.assertTrue(parent.is_symlink())

    def test_parent_replaced_before_publish_does_not_redirect_output(self):
        parent = self.root / "parent-before-link"
        moved = self.root / "parent-before-link-moved"
        replacement = self.root / "parent-before-link-new"
        parent.mkdir(); replacement.mkdir()
        output = parent / "record.json"
        real_link = os.link

        def replace_before_link(*args, **kwargs):
            parent.rename(moved)
            parent.symlink_to(replacement, target_is_directory=True)
            return real_link(*args, **kwargs)

        with mock.patch.object(cli.os, "link", side_effect=replace_before_link):
            with self.assertRaises((ValueError, OSError)):
                cli._publish_evidence_atomic(output, b"signed-record")
        self.assertFalse((moved / "record.json").exists())
        self.assertEqual(list(replacement.iterdir()), [])

    def test_final_stdout_failure_after_publish_is_not_downgraded_to_refusal(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        stdout = _FailingStdout()
        stderr = _BinaryStdout()
        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                               return_value=document), \
             mock.patch.object(sys, "stdout", stdout), \
             mock.patch.object(sys, "stderr", stderr):
            rc = cli.main(["--descriptor-evidence", str(self.descriptor),
                           "--output", str(self.output)])
        self.assertEqual(rc, 3)
        self.assertTrue(self.output.exists())
        self.assertEqual(json.loads(self.output.read_bytes()), document)
        self.assertEqual(stderr.buffer.getvalue(),
                         b"FK0957_POST_SUCCESS_REPORTING_FAULT=YES EVIDENCE_PUBLISHED=YES\n")
        self.assertNotIn(b"REFUSED", stderr.buffer.getvalue())

    def test_failure_immediately_after_publish_is_classified_post_success(self):
        signer = Ed25519PrivateKey.generate()
        document, fingerprint = signed_fake_record(signer)
        real_publish = cli._publish_evidence_atomic

        def publish_then_raise(path, data, state):
            real_publish(path, data, state)
            raise OSError("synthetic interruption immediately after publish")

        with mock.patch.object(identity_gate, "TRUSTED_SIGNER_FINGERPRINT_SHA256", fingerprint), \
             mock.patch.object(identity_gate, "_trusted_signer", return_value=signer.public_key()), \
             mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                               return_value=document), \
             mock.patch.object(cli, "_publish_evidence_atomic", side_effect=publish_then_raise):
            with captured_main(["--descriptor-evidence", str(self.descriptor),
                                "--output", str(self.output)]) as (rc, output):
                self.assertEqual(rc, 3)
        self.assertEqual(output,
                         b"FK0957_POST_SUCCESS_REPORTING_FAULT=YES EVIDENCE_PUBLISHED=YES\n")
        self.assertNotIn(b"REFUSED", output)
        self.assertEqual(json.loads(self.output.read_bytes()), document)

    def test_argument_surface_rejects_transport_controls(self):
        with captured_main(["--descriptor-evidence", str(self.descriptor),
                            "--output", str(self.output), "--tms", "111"]
                           ) as (rc, output):
            self.assertEqual(rc, 2)
        value = json.loads(output)
        self.assertEqual(value["phase"], "PRELIVE_VALIDATION")
        self.assertEqual(value["code"], "INTERNAL_REFUSAL")
        self.assertFalse(self.output.exists())

    def test_prelive_output_write_failure_has_no_traceback_or_exception_text(self):
        stderr = _BinaryStdout()
        with mock.patch.object(sys, "stdout", _FailingStdout()), \
             mock.patch.object(sys, "stderr", stderr):
            rc = cli.main(["--invalid-operator-option"])
        self.assertEqual(rc, 2)
        self.assertEqual(stderr.buffer.getvalue(), b"")
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
        with mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
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
        with mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
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

    def test_phase_counter_state_machine_rejects_impossible_progress(self):
        cases = (
            ("PRELIVE_VALIDATION", dict(device_opened=1)),
            ("PRELIVE_VALIDATION", dict(scan_a_started=1)),
            ("DEVICE_ENUMERATION", dict(device_opened=1)),
            ("DEVICE_OPEN", dict(scan_a_started=1)),
            ("DEVICE_OPEN", dict(permit_consumed=0)),
            ("SCAN_A_WRITE", dict(scan_b_started=1)),
            ("SCAN_A_READ", dict(scan_b_started=1)),
            ("SCAN_B_WRITE", dict(scan_a_tck_emitted=590, scan_b_started=1)),
            ("LOCAL_VALIDATION", dict(scan_b_tck_emitted=585)),
            ("LOCAL_SIGNING", dict(transport_closed=0)),
            ("SCAN_A_WRITE", dict(scan_a_tck_emitted=592)),
            ("SCAN_B_READ", dict(scan_b_tck_emitted=587)),
            ("TRANSPORT_CLOSE", dict(scan_b_tck_emitted=585)),
            ("TRANSPORT_CLOSE", dict(scan_b_started=0, scan_b_tck_emitted=0)),
            ("TRANSPORT_CLOSE", dict(transport_closed=1)),
            ("TRANSPORT_CLOSE", dict(close_from_state="MPSSE_READY",
                                      scan_a_started=1, scan_a_tck_emitted=591)),
            ("DEVICE_SELECTION", dict(target_candidates=0)),
            ("DEVICE_OPEN", dict(target_candidates=2)),
            ("TRANSPORT_CLOSE", dict(scan_b_tck_emitted=585)),
        )
        for phase, changes in cases:
            values = refusal_progress(phase)
            values.update(changes)
            envelope = transport.RefusalEnvelope(
                phase, transport._DEFAULT_REFUSAL_CODE.get(phase, "INTERNAL_REFUSAL"),
                None, **values)
            with self.subTest(phase=phase, changes=changes):
                self.assertFalse(cli._bounded_envelope(envelope.as_dict()))

    def test_unhashable_envelope_fields_are_rejected_without_internal_exception(self):
        valid = json.loads(cli._fallback_refusal("PRELIVE_VALIDATION", "TRANSACTION_PIN_MISMATCH"))
        malformed = (
            {"phase": []}, {"phase": {}}, {"phase": None},
            {"code": []}, {"code": {}}, {"code": None},
            {"operation_state": []}, {"operation_state": {}},
            {"close_from_state": []}, {"close_from_state": {}},
        )
        for change in malformed:
            candidate = dict(valid, **change)
            with self.subTest(change=change):
                self.assertFalse(cli._bounded_envelope(candidate))

    def test_every_impossible_progress_envelope_is_scrubbed_at_live_cli(self):
        cases = (
            ("PRELIVE_VALIDATION", dict(device_opened=1)),
            ("PRELIVE_VALIDATION", dict(scan_a_started=1)),
            ("DEVICE_ENUMERATION", dict(device_opened=1)),
            ("DEVICE_OPEN", dict(scan_a_started=1)),
            ("SCAN_A_WRITE", dict(scan_b_started=1)),
            ("SCAN_A_READ", dict(scan_b_started=1)),
            ("SCAN_B_WRITE", dict(scan_a_tck_emitted=590, scan_b_started=1)),
            ("LOCAL_VALIDATION", dict(scan_b_tck_emitted=585)),
            ("LOCAL_SIGNING", dict(transport_closed=0)),
            ("SCAN_A_WRITE", dict(scan_a_tck_emitted=592)),
            ("SCAN_B_READ", dict(scan_b_tck_emitted=587)),
        )
        for phase, changes in cases:
            values = refusal_progress(phase)
            values.update(changes)
            envelope = transport.RefusalEnvelope(
                phase, transport._DEFAULT_REFUSAL_CODE.get(phase, "INTERNAL_REFUSAL"),
                None, **values)
            refusal = transport.Refusal("hidden contradictory details", envelope=envelope)
            with self.subTest(phase=phase, changes=changes), \
                 mock.patch.object(signing, "perform_fk0957_topology_discovery_once",
                                   side_effect=refusal):
                with captured_main(["--descriptor-evidence", str(self.descriptor),
                                    "--output", str(self.output)]) as (rc, output):
                    self.assertEqual(rc, 2)
                reported = json.loads(output)
                self.assertEqual((reported["phase"], reported["code"]),
                                 ("INTERNAL_REFUSAL", "INTERNAL_REFUSAL"))
                self.assertEqual((reported["device_opened"], reported["scan_a_started"],
                                  reported["scan_a_tck_emitted"], reported["scan_b_started"],
                                  reported["scan_b_tck_emitted"]), (0, 0, 0, 0, 0))
                self.assertNotIn(b"hidden contradictory details", output)
                self.assertFalse(self.output.exists())

    def test_valid_progress_state_is_accepted_for_each_refusal_phase(self):
        for phase in transport.REFUSAL_PHASES:
            values = refusal_progress(phase)
            envelope = transport.RefusalEnvelope(
                phase, transport._DEFAULT_REFUSAL_CODE.get(phase, "INTERNAL_REFUSAL"),
                None, **values)
            with self.subTest(phase=phase):
                self.assertTrue(cli._bounded_envelope(envelope.as_dict()))

    def test_publication_state_preserves_signing_stage_boundary(self):
        staged = refusal_progress("LOCAL_SIGNING")
        staged.update(operation_state="LOCAL_VALIDATED", publication_state="NOT_STARTED")
        self.assertTrue(cli._bounded_envelope(transport.RefusalEnvelope(
            "LOCAL_SIGNING", "LOCAL_SIGNING_FAILED", None, **staged).as_dict()))

        signed_staged = refusal_progress("LOCAL_SIGNING")
        self.assertTrue(cli._bounded_envelope(transport.RefusalEnvelope(
            "LOCAL_SIGNING", "LOCAL_SIGNING_FAILED", None, **signed_staged).as_dict()))

        publishing = dict(signed_staged, publication_state="PUBLISHING")
        self.assertTrue(cli._bounded_envelope(transport.RefusalEnvelope(
            "LOCAL_SIGNING", "LOCAL_SIGNING_FAILED", None, **publishing).as_dict()))

        unsigned_publish = dict(staged, publication_state="PUBLISHING")
        self.assertFalse(cli._bounded_envelope(transport.RefusalEnvelope(
            "LOCAL_SIGNING", "LOCAL_SIGNING_FAILED", None, **unsigned_publish).as_dict()))

        impossible_published_refusal = dict(signed_staged, publication_state="PUBLISHED")
        self.assertFalse(cli._bounded_envelope(transport.RefusalEnvelope(
            "LOCAL_SIGNING", "LOCAL_SIGNING_FAILED", None,
            **impossible_published_refusal).as_dict()))
        missing = transport.RefusalEnvelope(
            "LOCAL_SIGNING", "LOCAL_SIGNING_FAILED", None, **signed_staged).as_dict()
        missing.pop("publication_state")
        self.assertFalse(cli._bounded_envelope(missing))

    def test_unknown_candidate_count_is_allowed_only_before_selection(self):
        permit = refusal_progress("PERMIT_VALIDATION")
        permit.update(target_candidates="unknown", permit_consumed=0)
        self.assertTrue(cli._bounded_envelope(transport.RefusalEnvelope(
            "PERMIT_VALIDATION", "PERMIT_INVALID", None, **permit).as_dict()))
        enumerating = refusal_progress("DEVICE_ENUMERATION")
        enumerating.update(target_candidates="unknown")
        self.assertTrue(cli._bounded_envelope(transport.RefusalEnvelope(
            "DEVICE_ENUMERATION", "ENUMERATION_FAILED", None, **enumerating).as_dict()))
        selected = refusal_progress("DEVICE_SELECTION")
        selected.update(target_candidates="unknown")
        self.assertFalse(cli._bounded_envelope(transport.RefusalEnvelope(
            "DEVICE_SELECTION", "CANDIDATE_IDENTITY_MISMATCH", None, **selected).as_dict()))

    def test_legitimate_partial_write_boundaries_and_large_candidate_count(self):
        for phase, counter, values in (
                ("SCAN_A_WRITE", "scan_a_tck_emitted", (0, 1, 590, 591)),
                ("SCAN_A_READ", "scan_a_tck_emitted", (585, 586)),
                ("SCAN_B_WRITE", "scan_b_tck_emitted", (0, 1, 585, 586)),
                ("SCAN_B_READ", "scan_b_tck_emitted", (580, 581))):
            for count in values:
                fields = refusal_progress(phase)
                fields[counter] = count
                if phase == "SCAN_A_WRITE":
                    fields["operation_state"] = (
                        "SCAN_A_NAV_WRITE" if count <= 9 else
                        "SCAN_A_BULK_WRITE" if count <= 585 else
                        "SCAN_A_FINAL_WRITE" if count == 586 else "SCAN_A_EXIT_WRITE")
                elif phase == "SCAN_B_WRITE":
                    fields["operation_state"] = (
                        "SCAN_B_NAV_WRITE" if count <= 4 else
                        "SCAN_B_BULK_WRITE" if count <= 580 else
                        "SCAN_B_FINAL_WRITE" if count == 581 else "SCAN_B_EXIT_WRITE")
                if phase == "SCAN_A_READ":
                    fields["operation_state"] = (
                        "SCAN_A_BULK_READ" if count == 585 else "SCAN_A_FINAL_READ")
                elif phase == "SCAN_B_READ":
                    fields["operation_state"] = (
                        "SCAN_B_BULK_READ" if count == 580 else "SCAN_B_FINAL_READ")
                envelope = transport.RefusalEnvelope(
                    phase, transport._DEFAULT_REFUSAL_CODE[phase], None, **fields)
                with self.subTest(phase=phase, tcks=count):
                    self.assertTrue(cli._bounded_envelope(envelope.as_dict()))
        fields = refusal_progress("DEVICE_SELECTION")
        fields["target_candidates"] = 256
        too_many = transport.RefusalEnvelope(
            "DEVICE_SELECTION", "MULTIPLE_TARGET_CANDIDATES", None, **fields)
        self.assertTrue(cli._bounded_envelope(too_many.as_dict()))
        fields["target_candidates"] = 257
        out_of_schema = transport.RefusalEnvelope(
            "DEVICE_SELECTION", "MULTIPLE_TARGET_CANDIDATES", None, **fields)
        self.assertFalse(cli._bounded_envelope(out_of_schema.as_dict()))

    def test_phase_boundaries_bind_candidate_count_open_and_command_substage(self):
        self.assertEqual(transport._bounded_candidate_count(256), 256)
        self.assertEqual(transport._bounded_candidate_count(300), 256)
        self.assertEqual(transport._bounded_candidate_count(-1), "unknown")
        self.assertEqual(transport._bounded_candidate_count(True), "unknown")
        for count in (0, 1, 2, 255, 256):
            fields = refusal_progress("DEVICE_ENUMERATION")
            fields["target_candidates"] = count
            envelope = transport.RefusalEnvelope(
                "DEVICE_ENUMERATION", "ENUMERATION_FAILED", None, **fields)
            with self.subTest(phase="DEVICE_ENUMERATION", count=count):
                self.assertTrue(cli._bounded_envelope(envelope.as_dict()))

        selected = refusal_progress("DEVICE_SELECTION")
        selected.update(target_candidates=256)
        multiple = transport.RefusalEnvelope(
            "DEVICE_SELECTION", "MULTIPLE_TARGET_CANDIDATES", None, **selected)
        self.assertTrue(cli._bounded_envelope(multiple.as_dict()))
        selected["target_candidates"] = 300
        over_bound = transport.RefusalEnvelope(
            "DEVICE_SELECTION", "MULTIPLE_TARGET_CANDIDATES", None, **selected)
        self.assertFalse(cli._bounded_envelope(over_bound.as_dict()))

        opened = refusal_progress("DEVICE_OPEN")
        opened.update(device_opened=1, operation_state="DEVICE_OPENED")
        open_completed = transport.RefusalEnvelope(
            "DEVICE_OPEN", "DEVICE_OPEN_FAILED", None, **opened)
        self.assertFalse(cli._bounded_envelope(open_completed.as_dict()))

        impossible = dict(opened, scan_a_started=1, scan_a_tck_emitted=591,
                          operation_state="DEVICE_OPENED")
        rejected = transport.RefusalEnvelope(
            "DEVICE_OPEN", "DEVICE_OPEN_FAILED", None, **impossible)
        self.assertFalse(cli._bounded_envelope(rejected.as_dict()))

        invalid_write_points = (
            ("SCAN_A_WRITE", "SCAN_A_NAV_WRITE", "scan_a_tck_emitted", 10),
            ("SCAN_A_WRITE", "SCAN_A_BULK_WRITE", "scan_a_tck_emitted", 8),
            ("SCAN_A_WRITE", "SCAN_A_FINAL_WRITE", "scan_a_tck_emitted", 587),
            ("SCAN_A_WRITE", "SCAN_A_EXIT_WRITE", "scan_a_tck_emitted", 585),
            ("SCAN_B_WRITE", "SCAN_B_NAV_WRITE", "scan_b_tck_emitted", 5),
            ("SCAN_B_WRITE", "SCAN_B_BULK_WRITE", "scan_b_tck_emitted", 3),
            ("SCAN_B_WRITE", "SCAN_B_FINAL_WRITE", "scan_b_tck_emitted", 582),
            ("SCAN_B_WRITE", "SCAN_B_EXIT_WRITE", "scan_b_tck_emitted", 580),
        )
        for phase, operation_state, counter, value in invalid_write_points:
            fields = refusal_progress(phase)
            fields.update(operation_state=operation_state)
            fields[counter] = value
            bad = transport.RefusalEnvelope(
                phase, transport._DEFAULT_REFUSAL_CODE[phase], None, **fields)
            with self.subTest(phase=phase, operation_state=operation_state, value=value):
                self.assertFalse(cli._bounded_envelope(bad.as_dict()))

    def test_close_history_allows_cleanup_but_not_fabricated_later_progress(self):
        valid = dict(target_candidates=1, device_opened=1, scan_a_started=1,
                     scan_a_tck_emitted=591, scan_b_started=0,
                     scan_b_tck_emitted=0, transport_closed=1,
                     permit_consumed=1, operation_state="TRANSPORT_CLOSED",
                     close_from_state="SCAN_A_COMPLETE")
        envelope = transport.RefusalEnvelope(
            "TRANSPORT_CLOSE", "TRANSPORT_CLOSE_FAILED", None, **valid)
        self.assertTrue(cli._bounded_envelope(envelope.as_dict()))
        forged = dict(valid, scan_b_started=1, scan_b_tck_emitted=586)
        impossible = transport.RefusalEnvelope(
            "TRANSPORT_CLOSE", "TRANSPORT_CLOSE_FAILED", None, **forged)
        self.assertFalse(cli._bounded_envelope(impossible.as_dict()))

    def test_transport_close_preserves_each_legal_prior_state(self):
        scenarios = (
            ("DEVICE_SELECTED", 0, 0, 0, 0, 0),
            ("DEVICE_OPENED", 1, 0, 0, 0, 0),
            ("MPSSE_READY", 1, 0, 0, 0, 0),
            ("SCAN_A_BULK_WRITE", 1, 1, 23, 0, 0),
            ("SCAN_A_COMPLETE", 1, 1, 591, 0, 0),
            ("SCAN_B_BULK_WRITE", 1, 1, 591, 1, 17),
            ("SCAN_B_COMPLETE", 1, 1, 591, 1, 586),
        )
        for prior, opened, a_started, a_tcks, b_started, b_tcks in scenarios:
            fields = dict(target_candidates=1, device_opened=opened,
                          scan_a_started=a_started, scan_a_tck_emitted=a_tcks,
                          scan_b_started=b_started, scan_b_tck_emitted=b_tcks,
                          transport_closed=0, permit_consumed=1,
                          operation_state="TRANSPORT_CLOSING", close_from_state=prior)
            envelope = transport.RefusalEnvelope(
                "TRANSPORT_CLOSE", "TRANSPORT_CLOSE_FAILED", None, **fields)
            with self.subTest(prior=prior):
                self.assertTrue(cli._bounded_envelope(envelope.as_dict()))


if __name__ == "__main__":
    unittest.main()
