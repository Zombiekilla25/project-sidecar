from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from io import StringIO
import tempfile
import unittest
from unittest import mock

import fk0957_remote_cleanup_protocol as protocol
import fk0957_remote_receipts as receipts


class RemoteReceiptStoreTests(unittest.TestCase):
    def setUp(self):
        self.parent = Path(tempfile.mkdtemp(prefix="fk0957-receipt-test-", dir=str(Path.home())))
        os.chmod(self.parent, 0o700)
        self.root = self.parent / "receipt-root"
        self.store = receipts.ReceiptStore(self.root)
        self.operation_id = "a" * 32
        now = datetime.now(timezone.utc).isoformat()
        self.payload = {
            "schema": protocol.RECEIPT_SCHEMA,
            "operation_id": self.operation_id,
            "release_authorization_id": "auth-123",
            "release_authorization_sha256": "1" * 64,
            "target_selector": "FK0957",
            "usb_descriptor_serial": "153300000957",
            "adapter_serial": "153300000957A",
            "expected_executable": "/usr/local/lib/sidecar/fk0957/endpoint",
            "expected_executable_sha256": "2" * 64,
            "release_manifest_sha256": "3" * 64,
            "source_commit": "4" * 40,
            "release_authorization_expires_utc": "2026-11-14T12:00:00+00:00",
            "remote_host": "testbench.example.invalid",
            "remote_user": "acquire",
            "receipt_id": "b" * 32,
            "created_utc": now,
            "updated_utc": now,
            "one_shot": True,
            "state": "PREPARED",
            "process": None,
            "exit_code": None,
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.parent, ignore_errors=True)

    def test_legacy_store_never_claims_launch_closed_or_not_started(self):
        self.store.create(self.payload)
        with self.assertRaises(FileExistsError):
            self.store.create(self.payload)
        nonce = "c" * 64
        self.assertEqual(self.store.status(operation_id=self.operation_id,
                                           query_nonce=nonce)["status"], protocol.UNKNOWN)
        with self.assertRaises(TypeError):
            self.store.status(operation_id=self.operation_id,
                              query_nonce=nonce, launch_closed=True)
        self.assertNotIn("launch_closed", self.store.status(
            operation_id=self.operation_id, query_nonce=nonce))
        self.assertFalse(protocol.restore_allowed(protocol.NOT_STARTED))

    def test_invalid_nonce_and_removed_launch_closed_argument_fail_closed(self):
        self.store.create(self.payload)
        with self.assertRaises(ValueError):
            self.store.status(operation_id=self.operation_id, query_nonce="x")
        with self.assertRaises(TypeError):
            self.store.status(operation_id=self.operation_id, query_nonce="c" * 64,
                              launch_closed=True)
        self.assertFalse(protocol.restore_allowed(
            self.store.status(operation_id=self.operation_id,
                              query_nonce="c" * 64)["status"]))

    def test_claimed_and_running_states_never_authorize_restore(self):
        self.store.create(self.payload)
        self.store.transition(self.operation_id, "CLAIMED", process=None, exit_code=None)
        self.assertEqual(self.store.status(operation_id=self.operation_id,
                                           query_nonce="c" * 64)["status"], protocol.UNKNOWN)
        process = {
            "pid": os.getpid(), "start_identity": "123", "uid": os.getuid(),
            "executable": "/usr/bin/python3", "executable_sha256": "5" * 64,
            "argv_sha256": "6" * 64, "cwd": "/", "operation_id_argument": self.operation_id,
        }
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            self.store.transition(self.operation_id, "RUNNING", process=process, exit_code=None)
            status = self.store.status(operation_id=self.operation_id,
                                       query_nonce="c" * 64)["status"]
        self.assertEqual(status, protocol.RUNNING_EXPECTED_PROCESS)
        self.assertFalse(protocol.restore_allowed(status))

    def test_missing_running_pid_does_not_synthesize_remote_exit(self):
        self.store.create(self.payload)
        self.store.transition(self.operation_id, "CLAIMED", process=None, exit_code=None)
        process = {
            "pid": 99999999, "start_identity": "123", "uid": os.getuid(),
            "executable": "/usr/bin/python3", "executable_sha256": "5" * 64,
            "argv_sha256": "6" * 64, "cwd": "/", "operation_id_argument": self.operation_id,
        }
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            self.store.transition(self.operation_id, "RUNNING", process=process, exit_code=None)
        with mock.patch.object(receipts, "process_start_identity", return_value=None):
            status = self.store.status(operation_id=self.operation_id,
                                       query_nonce="c" * 64)["status"]
        self.assertEqual(status, protocol.UNKNOWN)
        self.assertFalse(protocol.restore_allowed(status))
        row, _ = self.store.read(self.operation_id)
        self.assertEqual(row["state"], "RUNNING")

    def test_proc_enoent_is_distinct_from_inspection_error(self):
        self.assertIsNotNone(receipts.process_start_identity(os.getpid()))
        with mock.patch("builtins.open", side_effect=FileNotFoundError):
            self.assertIsNone(receipts.process_start_identity(99999999))
        with mock.patch("builtins.open", side_effect=PermissionError):
            with self.assertRaises(receipts.ProcessInspectionFailure):
                receipts.process_start_identity(os.getpid())
        with mock.patch("builtins.open", return_value=StringIO("bad proc stat\n")):
            with self.assertRaises(receipts.ProcessInspectionFailure):
                receipts.process_start_identity(os.getpid())

    def test_live_pid_inspection_failure_cannot_authorize_restore(self):
        self.store.create(self.payload)
        self.store.transition(self.operation_id, "CLAIMED", process=None, exit_code=None)
        process = {
            "pid": os.getpid(), "start_identity": "123", "uid": os.getuid(),
            "executable": "/usr/bin/python3", "executable_sha256": "5" * 64,
            "argv_sha256": "6" * 64, "cwd": "/", "operation_id_argument": self.operation_id,
        }
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            self.store.transition(self.operation_id, "RUNNING", process=process, exit_code=None)
            with self.assertRaisesRegex(ValueError, "receipt transition refused"):
                self.store.transition(self.operation_id, "EXITED_SUCCESS", process=process, exit_code=0)
        self.assertTrue(Path(f"/proc/{os.getpid()}/stat").exists())
        with mock.patch.object(receipts, "process_start_identity",
                               side_effect=receipts.ProcessInspectionFailure("permission denied")):
            state = self.store.status(operation_id=self.operation_id,
                                      query_nonce="c" * 64)["status"]
        self.assertEqual(state, protocol.STATUS_INSPECTION_FAILED)
        self.assertFalse(protocol.restore_allowed(state))
        with mock.patch.object(receipts, "process_start_identity", return_value=None):
            state = self.store.status(operation_id=self.operation_id,
                                      query_nonce="c" * 64)["status"]
        self.assertEqual(state, protocol.STATUS_INSPECTION_FAILED)
        self.assertFalse(protocol.restore_allowed(state))

    def test_fabricated_terminal_receipt_and_pid_absence_remain_unknown(self):
        self.store.create(self.payload)
        self.store.transition(self.operation_id, "CLAIMED", process=None, exit_code=None)
        process = {
            "pid": 99999999, "start_identity": "123", "uid": os.getuid(),
            "executable": "/usr/bin/python3", "executable_sha256": "5" * 64,
            "argv_sha256": "6" * 64, "cwd": "/", "operation_id_argument": self.operation_id,
        }
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            self.store.transition(self.operation_id, "RUNNING", process=process, exit_code=None)
        row, _ = self.store.read(self.operation_id)
        row.update(state="EXITED_SUCCESS", process=process, exit_code=0)
        op_dir = self.root / self.operation_id
        (op_dir / "receipt.json").write_bytes(protocol.canonical(row))
        status = self.store.status(operation_id=self.operation_id, query_nonce="c" * 64)
        self.assertEqual(status["status"], protocol.UNKNOWN)
        self.assertFalse(protocol.restore_allowed(status["status"]))

    def test_malformed_state_and_transition_arguments_are_bounded(self):
        self.store.create(self.payload)
        row, _ = self.store.read(self.operation_id)
        row["state"] = []
        with self.assertRaises(ValueError):
            protocol.validate_receipt(
                protocol.canonical(row), operation_id=self.operation_id,
                release_authorization_id=self.payload["release_authorization_id"],
                release_authorization_sha256=self.payload["release_authorization_sha256"],
                release_manifest_sha256=self.payload["release_manifest_sha256"],
                source_commit=self.payload["source_commit"],
                release_authorization_expires_utc=self.payload["release_authorization_expires_utc"],
                expected_receipt_id=self.payload["receipt_id"],
                expected_host=self.payload["remote_host"], expected_user=self.payload["remote_user"],
                expected_uid=os.getuid(), expected_executable=self.payload["expected_executable"],
                expected_executable_sha256=self.payload["expected_executable_sha256"],
                expected_argv_sha256="6" * 64,
                now=datetime.now(timezone.utc))
        self.assertFalse(protocol.receipt_transition_allowed([], "RUNNING"))
        self.assertFalse(protocol.receipt_transition_allowed("RUNNING", []))
        self.assertFalse(protocol.one_shot_claim_allowed([], claimed=False))
        self.assertFalse(protocol.one_shot_claim_allowed("PREPARED", claimed=0))

    def test_receipt_symlink_is_rejected(self):
        self.store.create(self.payload)
        op_dir = self.root / self.operation_id
        (op_dir / "receipt.json").unlink()
        (op_dir / "receipt.json").symlink_to(self.parent / "missing")
        with self.assertRaises(OSError):
            self.store.read(self.operation_id)

    def test_contradictory_initial_receipt_is_rejected(self):
        self.payload["state"] = "RUNNING"
        with self.assertRaises(ValueError):
            self.store.create(self.payload)


if __name__ == "__main__":
    unittest.main()
