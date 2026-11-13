#!/usr/bin/env python3
"""Independent deterministic adversarial sweep for FK0957 remote cleanup state."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
from unittest import mock
from pathlib import Path


def run(candidate: Path) -> dict:
    sys.path.insert(0, str(candidate / "tools/phk2_host"))
    import fk0957_remote_cleanup_protocol as protocol
    import test_fk0957_remote_cleanup_protocol as fixtures

    case = fixtures.RemoteCleanupContractTests()
    case.setUp()
    bad_types = [None, True, False, 0, -1, "", "UNKNOWN", [], ["RUNNING"], {}, {"x": 1}]
    escaped_receipt = []
    receipt_cases = 0
    receipt_args = {k: v for k, v in case.expected.items() if k != "query_nonce"}
    for key in sorted(protocol.RECEIPT_KEYS):
        for value in bad_types:
            row = case.receipt()
            row[key] = value
            receipt_cases += 1
            try:
                protocol.validate_receipt(protocol.canonical(row), **receipt_args)
            except ValueError:
                pass
            except BaseException as exc:
                escaped_receipt.append((key, type(value).__name__, type(exc).__name__))

    escaped_status = []
    status_cases = 0
    for key in sorted(protocol.STATUS_KEYS):
        for value in bad_types:
            row = json.loads(case.status(protocol.NOT_STARTED))
            row[key] = value
            status_cases += 1
            result = protocol.validate_status(protocol.canonical(row), **case.expected)
            if result != protocol.UNKNOWN:
                escaped_status.append((key, type(value).__name__, "accepted:" + str(result)))

    # Mutate every nested receipt field and recompute its outer digest. This
    # ensures the validator sees semantically malformed, canonical records.
    nested_cases = 0
    nested_bad = []
    for key in sorted(protocol.RECEIPT_KEYS):
        for value in bad_types:
            receipt = case.receipt()
            receipt[key] = value
            row = json.loads(case.status(protocol.NOT_STARTED))
            row["receipt"] = receipt
            row["receipt_sha256"] = hashlib.sha256(protocol.canonical(receipt)).hexdigest()
            nested_cases += 1
            result = protocol.validate_status(protocol.canonical(row), **case.expected)
            if result != protocol.UNKNOWN:
                nested_bad.append((key, type(value).__name__, result))

    utility_exceptions = {}
    for label, invoke in (
        ("restore_allowed_unhashable", lambda: protocol.restore_allowed([])),
        ("transition_old_state_unhashable", lambda: protocol.receipt_transition_allowed([], "RUNNING")),
        ("transition_new_state_unhashable", lambda: protocol.receipt_transition_allowed("RUNNING", [])),
    ):
        try:
            utility_exceptions[label] = repr(invoke())
        except BaseException as exc:
            utility_exceptions[label] = type(exc).__name__

    receipt_writer_attacks = {"implemented": False}
    if (candidate / "tools/phk2_host/fk0957_remote_receipts.py").is_file():
        import fk0957_remote_receipts as receipts
        import test_fk0957_remote_receipts as receipt_fixtures
        fixture = receipt_fixtures.RemoteReceiptStoreTests()
        fixture.setUp()
        try:
            fixture.store.create(fixture.payload)
            fixture.store.transition(fixture.operation_id, "CLAIMED", process=None, exit_code=None)
            fake_process = {
                "pid": __import__("os").getpid(), "start_identity": "123",
                "uid": __import__("os").getuid(), "executable": "/usr/bin/python3",
                "executable_sha256": "5" * 64, "argv_sha256": "6" * 64,
                "cwd": "/", "operation_id_argument": fixture.operation_id,
            }
            with mock.patch.object(receipts, "process_start_identity", return_value="123"):
                fixture.store.transition(fixture.operation_id, "RUNNING",
                                         process=fake_process, exit_code=None)
                fixture.store.transition(fixture.operation_id, "EXITED_SUCCESS",
                                         process=fake_process, exit_code=0)
            # The PID is this still-live audit process. Simulate /proc stat
            # becoming unreadable (process_start_identity conflates all errors
            # with absence) while status caller asserts launch_closed.
            with mock.patch.object(receipts, "process_start_identity", return_value=None):
                observed = fixture.store.status(operation_id=fixture.operation_id,
                                                query_nonce="c" * 64,
                                                launch_closed=True)["status"]
            receipt_writer_attacks = {
                "implemented": True,
                "live_pid_still_exists": __import__("os").path.exists(
                    f"/proc/{__import__('os').getpid()}"),
                "inaccessible_proc_stat_status": observed,
                "inaccessible_proc_stat_restorable": protocol.restore_allowed(observed),
            }
        finally:
            fixture.doCleanups()
        race = receipt_fixtures.RemoteReceiptStoreTests()
        race.setUp()
        try:
            race.store.create(race.payload)
            original_replace = receipts.os.replace
            injected = []

            def replace_after_destination_substitution(src, dst, **kwargs):
                row, _ = race.store.read(race.operation_id)
                row["release_manifest_sha256"] = "9" * 64
                replacement = protocol.canonical(row)
                fd = __import__("os").open(dst, __import__("os").O_WRONLY |
                    __import__("os").O_TRUNC | getattr(__import__("os"), "O_NOFOLLOW", 0),
                    dir_fd=kwargs["dst_dir_fd"])
                try:
                    __import__("os").write(fd, replacement)
                finally:
                    __import__("os").close(fd)
                injected.append(True)
                return original_replace(src, dst, **kwargs)

            with mock.patch.object(receipts.os, "replace",
                                   side_effect=replace_after_destination_substitution):
                race.store.transition(race.operation_id, "CLAIMED", process=None, exit_code=None)
            final_row, _ = race.store.read(race.operation_id)
            receipt_writer_attacks["destination_replacement_injected"] = bool(injected)
            receipt_writer_attacks["destination_replacement_detected"] = False
            receipt_writer_attacks["replacement_overwritten_by_transition"] = (
                final_row["release_manifest_sha256"] != "9" * 64 and final_row["state"] == "CLAIMED")
        finally:
            race.doCleanups()
        before_fsync = receipt_fixtures.RemoteReceiptStoreTests()
        before_fsync.setUp()
        try:
            before_fsync.store.create(before_fsync.payload)
            with mock.patch.object(receipts.os, "fsync", side_effect=OSError("audit pre-rename fsync")):
                try:
                    before_fsync.store.transition(before_fsync.operation_id, "CLAIMED",
                                                  process=None, exit_code=None)
                except OSError:
                    pass
            row, _ = before_fsync.store.read(before_fsync.operation_id)
            receipt_writer_attacks["pre_rename_fsync_failure_state"] = row["state"]
        finally:
            before_fsync.doCleanups()
        after_rename = receipt_fixtures.RemoteReceiptStoreTests()
        after_rename.setUp()
        try:
            after_rename.store.create(after_rename.payload)
            real_replace = receipts.os.replace

            def replace_then_fail(src, dst, **kwargs):
                real_replace(src, dst, **kwargs)
                raise OSError("audit post-rename failure")

            with mock.patch.object(receipts.os, "replace", side_effect=replace_then_fail):
                try:
                    after_rename.store.transition(after_rename.operation_id, "CLAIMED",
                                                  process=None, exit_code=None)
                except OSError:
                    pass
            row, _ = after_rename.store.read(after_rename.operation_id)
            receipt_writer_attacks["post_rename_failure_state"] = row["state"]
            receipt_writer_attacks["post_rename_failure_restorable"] = protocol.restore_allowed(
                after_rename.store.status(operation_id=after_rename.operation_id,
                    query_nonce="c" * 64, launch_closed=True)["status"])
        finally:
            after_rename.doCleanups()

    # Deterministic type/value fuzzing for challenge-bound status. Every case
    # starts from a valid canonical NOT_STARTED status; the mutator changes at
    # least one field to a value outside that field's valid baseline value.
    rng = random.Random(0x0957_2026)
    seeds = [None, True, False, 0, -1, 1 << 80, "", "forged", "UNKNOWN",
             [], ["NOT_STARTED"], {}, {"x": 1}]
    fuzz_count = 50_000
    unsafe_restorable = []
    safe_outcomes = {protocol.UNKNOWN: 0, protocol.IDENTITY_MISMATCH: 0,
                     protocol.NOT_STARTED: 0, "OTHER": 0}
    for index in range(fuzz_count):
        row = json.loads(case.status(protocol.NOT_STARTED))
        if index % 4 == 0:
            raw = rng.choice([b"", b"{", b"[]\n", b"null\n", b"{}\n"])
            result = protocol.validate_status(raw, **case.expected)
        elif index % 4 == 1:
            field = rng.choice(sorted(protocol.STATUS_KEYS))
            choices = [v for v in seeds if v != row[field]]
            row[field] = rng.choice(choices)
            result = protocol.validate_status(protocol.canonical(row), **case.expected)
        elif index % 4 == 2:
            receipt = row["receipt"]
            field = rng.choice(sorted(protocol.RECEIPT_KEYS))
            choices = [v for v in seeds if v != receipt[field]]
            receipt[field] = rng.choice(choices)
            row["receipt_sha256"] = hashlib.sha256(protocol.canonical(receipt)).hexdigest()
            result = protocol.validate_status(protocol.canonical(row), **case.expected)
        else:
            # Stale/wrong challenge and receipt digest mutations target replay
            # and stale-status acceptance without relying on parser errors.
            field = rng.choice(("query_nonce", "receipt_sha256", "observed_utc", "launch_closed"))
            row[field] = {"query_nonce": "0" * 64,
                          "receipt_sha256": "0" * 64,
                          "observed_utc": "2026-11-13T11:59:00Z",
                          "launch_closed": False}[field]
            result = protocol.validate_status(protocol.canonical(row), **case.expected)
        safe_outcomes[result if result in safe_outcomes else "OTHER"] += 1
        if protocol.restore_allowed(result) and result != protocol.UNKNOWN:
            unsafe_restorable.append(index)

    return {
        "candidate_head": subprocess.check_output(
            ["git", "-C", str(candidate), "rev-parse", "HEAD"], text=True).strip(),
        "receipt_field_type_cases": receipt_cases,
        "receipt_unexpected_exceptions": escaped_receipt,
        "status_field_type_cases": status_cases,
        "status_non_unknown_results": escaped_status,
        "nested_receipt_type_cases": nested_cases,
        "nested_receipt_non_unknown_results": nested_bad,
        "utility_malformed_input_results": utility_exceptions,
        "receipt_writer_attacks": receipt_writer_attacks,
        "deterministic_fuzz_seed": "0x09572026",
        "deterministic_fuzz_cases": fuzz_count,
        "deterministic_fuzz_outcomes": safe_outcomes,
        "malformed_case_restorable_results": unsafe_restorable[:20],
        "malformed_case_restorable_count": len(unsafe_restorable),
        "unknown_restore_allowed": protocol.restore_allowed(protocol.UNKNOWN),
        "running_restore_allowed": protocol.restore_allowed(protocol.RUNNING_EXPECTED_PROCESS),
        "hardware_access": False,
        "ssh_access": False,
        "usb_jtag_access": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    result = run(args.candidate.resolve())
    rendered = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
