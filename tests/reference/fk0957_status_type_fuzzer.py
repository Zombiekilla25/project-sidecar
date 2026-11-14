#!/usr/bin/env python3
"""Fuzz bounded supervisor refusal-result types without hardware or SSH."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import random
import sys
import time


EXPECTED = {"operation_id": "a" * 32, "authorization_id": "9" * 64,
            "authorization_sha256": "b" * 64, "handoff_sha256": "c" * 64,
            "manifest_sha256": "d" * 64, "production_head": "e" * 40,
            "transaction_profile_sha256": "f" * 64}
FIELDS = ("phase", "code", "publication_state", "operation_state", "close_from_state",
          "target_candidates", "device_opened", "permit_consumed", "scan_a_tck_emitted",
          "scan_b_tck_emitted")
VALUES = (None, False, True, 0, -1, "", [], {}, ["LOCAL_SIGNING"], {"x": 1})


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--cases", type=int, default=100_000)
    parser.add_argument("--seed", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.cases <= 1_000_000:
        parser.error("--cases must be between 1 and 1000000")
    sys.path.insert(0, str(args.candidate_root.resolve() / "tools/phk2_host"))
    import fk0957_supervisor_status_contract as contract

    result = {"status": "REFUSED", "phase": "LOCAL_SIGNING", "code": "LOCAL_SIGNING_FAILED",
              "evidence_path": "none", "signature_verified": False, "return_code": None,
              "target_candidates": 1, "device_opened": 1, "scan_a_started": 1,
              "scan_a_tck_emitted": 591, "scan_b_started": 1, "scan_b_tck_emitted": 586,
              "transport_closed": 1, "permit_consumed": 1,
              "operation_state": "SIGNED_STAGED", "close_from_state": "SCAN_B_COMPLETE",
              "publication_state": "SIGNED_STAGED"}
    child = {"pid": 4321, "start_identity": "123456", "parent_pid": 4100,
             "operation_id": EXPECTED["operation_id"], "authorization_id": EXPECTED["authorization_id"],
             "launcher": "/usr/local/bin/fk0957-safe-launcher", "launcher_sha256": "1" * 64,
             "executable": "/usr/bin/python3.12", "executable_sha256": "2" * 64,
             "argv_sha256": "3" * 64}
    record = {"schema": contract.SCHEMA, "operation_id": EXPECTED["operation_id"],
              "state": contract.EXITED_REFUSAL, "terminal": True, "restore_eligible": True,
              **EXPECTED, "target": "FK0957", "one_shot": True, "registered_ns": 100,
              "child_identity": child, "exit_code": 2, "reaped_ns": 200,
              "result_b64": base64.b64encode(canonical(result)).decode("ascii")}
    rng = random.Random(args.seed)
    raw_exceptions = accepted = 0
    exception_types: dict[str, int] = {}
    start = time.monotonic()
    for _ in range(args.cases):
        changed = dict(result)
        for _mutation in range(1 + int(rng.random() < 0.15)):
            changed[rng.choice(FIELDS)] = rng.choice(VALUES)
        candidate = dict(record)
        candidate["result_b64"] = base64.b64encode(canonical(changed)).decode("ascii")
        try:
            observed = contract.classify_supervisor_status(canonical(candidate), expected=EXPECTED)
            if observed != contract.UNKNOWN:
                accepted += 1
        except Exception as exc:
            raw_exceptions += 1
            key = type(exc).__name__
            exception_types[key] = exception_types.get(key, 0) + 1
    output = {"schema": "fk0957-independent-supervisor-status-fuzz-v1", "seed": args.seed,
              "cases": args.cases, "fields_mutated": list(FIELDS),
              "raw_exception_count": raw_exceptions, "unsafe_terminal_state_count": accepted,
              "exception_types": exception_types,
              "elapsed_seconds": round(time.monotonic() - start, 3),
              "hardware_access": False, "network_access": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, sort_keys=True))
    return 0 if raw_exceptions == 0 and accepted == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
