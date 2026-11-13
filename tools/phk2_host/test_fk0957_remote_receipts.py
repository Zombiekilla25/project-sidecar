from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
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

    def test_create_is_exclusive_and_status_requires_explicit_launcher_closure(self):
        self.store.create(self.payload)
        with self.assertRaises(FileExistsError):
            self.store.create(self.payload)
        nonce = "c" * 64
        self.assertEqual(self.store.status(operation_id=self.operation_id,
                                           query_nonce=nonce)["status"], protocol.UNKNOWN)
        response = self.store.status(operation_id=self.operation_id,
                                     query_nonce=nonce, launch_closed=True)
        self.assertEqual(response["status"], protocol.NOT_STARTED)
        self.assertTrue(protocol.restore_allowed(response["status"]))

    def test_invalid_status_nonce_and_default_launch_state_fail_closed(self):
        self.store.create(self.payload)
        with self.assertRaises(ValueError):
            self.store.status(operation_id=self.operation_id, query_nonce="x", launch_closed=True)
        self.assertFalse(protocol.restore_allowed(
            self.store.status(operation_id=self.operation_id,
                              query_nonce="c" * 64)["status"]))

    def test_claimed_and_running_states_never_authorize_restore(self):
        self.store.create(self.payload)
        self.store.transition(self.operation_id, "CLAIMED", process=None, exit_code=None)
        self.assertEqual(self.store.status(operation_id=self.operation_id,
                                           query_nonce="c" * 64,
                                           launch_closed=True)["status"], protocol.UNKNOWN)
        process = {
            "pid": os.getpid(), "start_identity": "123", "uid": os.getuid(),
            "executable": "/usr/bin/python3", "executable_sha256": "5" * 64,
            "argv_sha256": "6" * 64, "cwd": "/", "operation_id_argument": self.operation_id,
        }
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            self.store.transition(self.operation_id, "RUNNING", process=process, exit_code=None)
            status = self.store.status(operation_id=self.operation_id,
                                       query_nonce="c" * 64, launch_closed=True)["status"]
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
                                       query_nonce="c" * 64,
                                       launch_closed=True)["status"]
        self.assertEqual(status, protocol.UNKNOWN)
        self.assertFalse(protocol.restore_allowed(status))
        row, _ = self.store.read(self.operation_id)
        self.assertEqual(row["state"], "RUNNING")

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
