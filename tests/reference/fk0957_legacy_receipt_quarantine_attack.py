#!/usr/bin/env python3
"""Independent attacks on the quarantined legacy FK0957 receipt path."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock


def run(candidate: Path) -> dict:
    candidate = candidate.resolve()
    sys.path.insert(0, str(candidate / "tools/phk2_host"))
    import fk0957_remote_cleanup_protocol as protocol
    import fk0957_remote_receipts as receipts
    import test_fk0957_remote_receipts as fixtures

    attacks = {}
    setup = fixtures.RemoteReceiptStoreTests()
    setup.setUp()
    try:
        setup.store.create(setup.payload)
        setup.store.transition(setup.operation_id, "CLAIMED", process=None, exit_code=None)
        proc = {"pid": 99999999, "start_identity": "123", "uid": os.getuid(),
                "executable": setup.payload["expected_executable"],
                "executable_sha256": setup.payload["expected_executable_sha256"],
                "argv_sha256": "6" * 64, "cwd": "/",
                "operation_id_argument": setup.operation_id}
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            setup.store.transition(setup.operation_id, "RUNNING", process=proc, exit_code=None)
        # Model the same-UID caller's direct write to its legacy receipt file.
        forged = dict(setup.store.read(setup.operation_id)[0])
        forged.update(state="EXITED_SUCCESS", process=proc, exit_code=0,
                      updated_utc=datetime.now(timezone.utc).isoformat())
        path = setup.store.root / setup.operation_id / "receipt.json"
        path.write_bytes(protocol.canonical(forged))
        os.chmod(path, 0o600)
        pid_absent = not Path(f"/proc/{proc['pid']}").exists()
        try:
            setup.store.status(operation_id=setup.operation_id,
                               query_nonce="a" * 64, launch_closed=True)
            legacy_launch_claim = "ACCEPTED"
        except TypeError:
            legacy_launch_claim = "REJECTED"
        except ValueError:
            legacy_launch_claim = "REJECTED"
        status = setup.store.status(operation_id=setup.operation_id,
                                    query_nonce="a" * 64)
        kwargs = {
            "operation_id": setup.operation_id, "query_nonce": "a" * 64,
            "release_authorization_id": forged["release_authorization_id"],
            "release_authorization_sha256": forged["release_authorization_sha256"],
            "release_manifest_sha256": forged["release_manifest_sha256"],
            "expected_receipt_id": forged["receipt_id"],
            "source_commit": forged["source_commit"],
            "release_authorization_expires_utc": forged["release_authorization_expires_utc"],
            "expected_host": forged["remote_host"], "expected_user": forged["remote_user"],
            "expected_uid": os.getuid(), "expected_executable": forged["expected_executable"],
            "expected_executable_sha256": forged["expected_executable_sha256"],
            "expected_argv_sha256": "6" * 64, "expected_cwd": "/",
            "now": datetime.now(timezone.utc),
        }
        classified = protocol.classify_status_query(
            transport_return_code=0, response_bytes=protocol.canonical(status),
            validator_kwargs=kwargs)
        attacks["forged_terminal_absent_pid"] = {
            "pid_absent": pid_absent,
            "raw_status": status["status"],
            "validated_status": classified,
            "restore_allowed": protocol.restore_allowed(classified),
        }
        stale = dict(status)
        stale["observed_utc"] = (datetime.now(timezone.utc) -
                                  timedelta(minutes=1)).isoformat()
        attacks["stale_status"] = protocol.validate_status(
            protocol.canonical(stale), **kwargs)
        replay_kwargs = dict(kwargs, operation_id="b" * 32)
        attacks["old_operation_replay"] = protocol.validate_status(
            protocol.canonical(status), **replay_kwargs)
        attacks["restore_allowed_exit_success"] = protocol.restore_allowed(
            protocol.EXITED_SUCCESS)
        attacks["legacy_status_schema"] = protocol.STATUS_SCHEMA
        attacks["legacy_launch_closed_parameter"] = legacy_launch_claim
    finally:
        setup.doCleanups()

    terminal = fixtures.RemoteReceiptStoreTests()
    terminal.setUp()
    try:
        terminal.store.create(terminal.payload)
        terminal.store.transition(terminal.operation_id, "CLAIMED", process=None, exit_code=None)
        proc = {"pid": os.getpid(), "start_identity": "123", "uid": os.getuid(),
                "executable": "/usr/bin/python3", "executable_sha256": "5" * 64,
                "argv_sha256": "6" * 64, "cwd": "/",
                "operation_id_argument": terminal.operation_id}
        with mock.patch.object(receipts, "process_start_identity", return_value="123"):
            terminal.store.transition(terminal.operation_id, "RUNNING", process=proc, exit_code=None)
        try:
            terminal.store.transition(terminal.operation_id, "EXITED_SUCCESS",
                                      process=proc, exit_code=0)
            attacks["terminal_writer_transition"] = "ACCEPTED"
        except ValueError:
            attacks["terminal_writer_transition"] = "REJECTED"
    finally:
        terminal.doCleanups()

    attacks["candidate_head"] = subprocess.check_output(
        ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip()
    attacks["legacy_receipt_authority_pass"] = (
        attacks["forged_terminal_absent_pid"]["validated_status"] == protocol.UNKNOWN and
        attacks["forged_terminal_absent_pid"]["restore_allowed"] is False and
        attacks["stale_status"] == protocol.UNKNOWN and
        attacks["old_operation_replay"] == protocol.UNKNOWN and
        attacks["restore_allowed_exit_success"] is False and
        attacks["legacy_launch_closed_parameter"] == "REJECTED" and
        attacks["terminal_writer_transition"] == "REJECTED")
    attacks["hardware_access"] = False
    attacks["network_access"] = False
    return attacks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.candidate), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
