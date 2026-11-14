#!/usr/bin/env python3
"""Minimize malformed publication/status records that escape as TypeError."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", type=Path, required=True)
    ap.add_argument("--expected-commit", required=True)
    args = ap.parse_args()
    root = args.candidate_root.resolve(strict=True)
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                            capture_output=True, check=True, timeout=10).stdout.strip()
    if actual != args.expected_commit:
        raise SystemExit("candidate SHA mismatch")
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import fk0957_publication_report_contract as publication
    import fk0957_supervisor_status_contract as status_contract

    report = {"status": "REFUSED", "code": "REMOTE_RGB_FLOW_FAILED",
              "operation_id": "a" * 32, "authorization_id": "b" * 64,
              "local_state": "PRELIVE", "supervisor_state": "UNKNOWN",
              "publication_state": "NOT_STARTED", "evidence_sha256": None,
              "evidence_path": "none"}
    report_failures = []
    for field in ("local_state", "publication_state", "supervisor_state"):
        value = dict(report); value[field] = []
        try:
            publication.refusal_diagnostic(canonical(value), operation_id="a" * 32)
        except publication.PublicationReportError:
            continue
        except Exception as exc:
            report_failures.append({"field": field, "exception": type(exc).__name__})
        else:
            report_failures.append({"field": field, "exception": "ACCEPTED"})

    expected = {"operation_id": "a" * 32, "authorization_id": "9" * 64,
                "authorization_sha256": "b" * 64, "handoff_sha256": "c" * 64,
                "manifest_sha256": "d" * 64, "production_head": "e" * 40,
                "transaction_profile_sha256": "f" * 64}
    good_result = {"status": "REFUSED", "phase": "LOCAL_SIGNING",
                   "code": "LOCAL_SIGNING_FAILED", "evidence_path": "none",
                   "signature_verified": False, "return_code": None,
                   "target_candidates": 1, "device_opened": 1,
                   "scan_a_started": 1, "scan_a_tck_emitted": 591,
                   "scan_b_started": 1, "scan_b_tck_emitted": 586,
                   "transport_closed": 1, "permit_consumed": 1,
                   "operation_state": "SIGNED_STAGED",
                   "close_from_state": "SCAN_B_COMPLETE",
                   "publication_state": "SIGNED_STAGED"}
    child = {"pid": 4321, "start_identity": "123456", "parent_pid": 4100,
             "operation_id": expected["operation_id"],
             "authorization_id": expected["authorization_id"],
             "launcher": "/usr/local/bin/fk0957-safe-launcher",
             "launcher_sha256": "1" * 64, "executable": "/usr/bin/python3.12",
             "executable_sha256": "2" * 64, "argv_sha256": "3" * 64}
    record = {"schema": status_contract.SCHEMA,
              "operation_id": expected["operation_id"],
              "state": status_contract.EXITED_REFUSAL,
              "terminal": True, "restore_eligible": True, **expected,
              "target": "FK0957", "one_shot": True, "registered_ns": 100,
              "child_identity": child, "exit_code": 2, "reaped_ns": 200,
              "result_b64": base64.b64encode(canonical(good_result)).decode("ascii")}
    if status_contract.classify_supervisor_status(canonical(record), expected=expected) != status_contract.EXITED_REFUSAL:
        raise SystemExit("baseline terminal fixture was not accepted as the expected valid state")
    status_outcomes = {}
    for field in ("phase", "code", "publication_state", "operation_state", "close_from_state"):
        changed = dict(good_result); changed[field] = []
        candidate = dict(record)
        candidate["result_b64"] = base64.b64encode(canonical(changed)).decode("ascii")
        try:
            observed = status_contract.classify_supervisor_status(canonical(candidate), expected=expected)
        except Exception as exc:
            status_outcomes[field] = type(exc).__name__
        else:
            status_outcomes[field] = "REFUSED_UNKNOWN" if observed == status_contract.UNKNOWN else "ACCEPTED"

    print(json.dumps({"candidate_commit": actual,
                      "publication_raw_exception_fields": report_failures,
                      "supervisor_status_outcomes": status_outcomes,
                      "hardware_access": False, "network_access": False},
                     sort_keys=True))
    raw_status = {field for field, outcome in status_outcomes.items() if outcome == "TypeError"}
    expected_raw = {"code", "publication_state", "operation_state", "close_from_state"}
    return 0 if len(report_failures) == 3 and raw_status == expected_raw and \
        status_outcomes.get("phase") == "REFUSED_UNKNOWN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
