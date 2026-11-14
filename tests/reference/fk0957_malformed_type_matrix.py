#!/usr/bin/env python3
"""Exhaust deterministic JSON type, omission, and duplicate-key cases offline."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import time


VALUES = (None, False, True, 0, 1, -1, 2**31, 591, 592, "", "REFUSED",
          "LOCAL_SIGNING", [], {}, ["LOCAL_SIGNING"], {"x": 1})


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", required=True, type=Path)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--output", required=True, type=Path)
    a = ap.parse_args(); root = a.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          text=True, capture_output=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, check=True, text=True, capture_output=True,
                           timeout=10).stdout
    if head != a.expected_commit or dirty:
        raise SystemExit("candidate identity or cleanliness mismatch")
    started = time.monotonic()
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import fk0957_publication_report_contract as pub
    import fk0957_supervisor_status_contract as sup

    report = {"status":"REFUSED", "code":"REMOTE_RGB_FLOW_FAILED",
              "operation_id":"a"*32, "authorization_id":"b"*64,
              "local_state":"PRELIVE", "supervisor_state":"UNKNOWN",
              "publication_state":"NOT_STARTED", "evidence_sha256":None,
              "evidence_path":"none"}
    release_fields = ("local_state", "supervisor_state", "publication_state")
    type_errors = []; unexpected_accepts = []; total = 0
    for field in release_fields:
        for item in VALUES:
            changed = dict(report); changed[field] = item; total += 1
            try: pub.refusal_diagnostic(canonical(changed), operation_id="a"*32)
            except pub.PublicationReportError: pass
            except Exception as exc: type_errors.append({"parser":"publication","field":field,"type":type(item).__name__,"exception":type(exc).__name__})
            else: unexpected_accepts.append({"parser":"publication","field":field,"value_type":type(item).__name__})
        changed = dict(report); changed.pop(field); total += 1
        try: pub.refusal_diagnostic(canonical(changed), operation_id="a"*32)
        except pub.PublicationReportError: pass
        except Exception as exc: type_errors.append({"parser":"publication","field":field,"type":"MISSING","exception":type(exc).__name__})
        else: unexpected_accepts.append({"parser":"publication","field":field,"value_type":"MISSING"})

    expected = {"operation_id":"a"*32,"authorization_id":"9"*64,
                "authorization_sha256":"b"*64,"handoff_sha256":"c"*64,
                "manifest_sha256":"d"*64,"production_head":"e"*40,
                "transaction_profile_sha256":"f"*64}
    result = {"status":"REFUSED","phase":"LOCAL_SIGNING","code":"LOCAL_SIGNING_FAILED",
              "evidence_path":"none","signature_verified":False,"return_code":None,
              "target_candidates":1,"device_opened":1,"scan_a_started":1,
              "scan_a_tck_emitted":591,"scan_b_started":1,"scan_b_tck_emitted":586,
              "transport_closed":1,"permit_consumed":1,"operation_state":"SIGNED_STAGED",
              "close_from_state":"SCAN_B_COMPLETE","publication_state":"SIGNED_STAGED"}
    child = {"pid":4321,"start_identity":"123456","parent_pid":4100,
             "operation_id":expected["operation_id"],"authorization_id":expected["authorization_id"],
             "launcher":"/usr/local/bin/fk0957-safe-launcher","launcher_sha256":"1"*64,
             "executable":"/usr/bin/python3.12","executable_sha256":"2"*64,"argv_sha256":"3"*64}
    record = {"schema":sup.SCHEMA,"operation_id":expected["operation_id"],
              "state":sup.EXITED_REFUSAL,"terminal":True,"restore_eligible":True,**expected,
              "target":"FK0957","one_shot":True,"registered_ns":100,
              "child_identity":child,"exit_code":2,"reaped_ns":200,
              "result_b64":base64.b64encode(canonical(result)).decode("ascii")}
    if sup.classify_supervisor_status(canonical(record), expected=expected) != sup.EXITED_REFUSAL:
        raise SystemExit("known-valid supervisor control record rejected")
    status_fields = ("phase","code","publication_state","operation_state","close_from_state",
                     "target_candidates","device_opened","permit_consumed","scan_a_tck_emitted","scan_b_tck_emitted")
    for field in status_fields:
        candidates = VALUES + ("unknown", "SCAN_B_COMPLETE")
        for item in candidates:
            if type(item) is type(result[field]) and item == result[field]:
                continue
            mutated = dict(result); mutated[field] = item
            outer = dict(record); outer["result_b64"] = base64.b64encode(canonical(mutated)).decode("ascii")
            total += 1
            try:
                observed = sup.classify_supervisor_status(canonical(outer), expected=expected)
            except Exception as exc: type_errors.append({"parser":"supervisor","field":field,"type":type(item).__name__,"exception":type(exc).__name__})
            else:
                if observed != sup.UNKNOWN: unexpected_accepts.append({"parser":"supervisor","field":field,"value_type":type(item).__name__})
        mutated = dict(result); mutated.pop(field)
        outer = dict(record); outer["result_b64"] = base64.b64encode(canonical(mutated)).decode("ascii")
        total += 1
        try:
            observed = sup.classify_supervisor_status(canonical(outer), expected=expected)
        except Exception as exc: type_errors.append({"parser":"supervisor","field":field,"type":"MISSING","exception":type(exc).__name__})
        else:
            if observed != sup.UNKNOWN: unexpected_accepts.append({"parser":"supervisor","field":field,"value_type":"MISSING"})

    # Duplicate semantic keys must be rejected in outer and nested canonical records.
    duplicate_outer = canonical(record).replace(b'"terminal":true', b'"terminal":true,"terminal":true')
    duplicate_result = b'{"code":"A","code":"B"}\n'
    duplicate_nested = dict(record); duplicate_nested["result_b64"] = base64.b64encode(duplicate_result).decode("ascii")
    duplicate_cases = []
    for raw in (duplicate_outer, canonical(duplicate_nested)):
        total += 1
        try: observed = sup.classify_supervisor_status(raw, expected=expected)
        except Exception as exc: duplicate_cases.append(type(exc).__name__)
        else: duplicate_cases.append("UNKNOWN" if observed == sup.UNKNOWN else "ACCEPTED")
    output = {"schema":"fk0957-independent-malformed-type-matrix-v1","candidate_commit":head,
              "cases":total,"raw_exceptions":type_errors,"raw_exception_count":len(type_errors),
              "elapsed_seconds":round(time.monotonic()-started,3),
              "unexpected_accepts":unexpected_accepts,"unexpected_accept_count":len(unexpected_accepts),
              "duplicate_key_outcomes":duplicate_cases,"hardware_access":False,"network_access":False}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(output,sort_keys=True,indent=2)+"\n")
    print(json.dumps(output,sort_keys=True))
    return 0 if not type_errors and not unexpected_accepts and duplicate_cases == ["UNKNOWN","UNKNOWN"] else 1


if __name__ == "__main__": raise SystemExit(main())
