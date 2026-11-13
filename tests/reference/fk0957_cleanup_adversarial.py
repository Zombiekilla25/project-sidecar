#!/usr/bin/env python3
"""Independent deterministic adversarial sweep for FK0957 remote cleanup state."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
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
