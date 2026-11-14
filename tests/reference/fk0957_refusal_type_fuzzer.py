#!/usr/bin/env python3
"""Deterministic malformed-state fuzzing for the candidate refusal parser."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys
import time


VALUES = (None, False, True, 0, 1, -1, "", "REFUSED", [], {}, [1], {"x": 1},
          ["NOT_STARTED"], {"status": "NOT_STARTED"})
FIELDS = ("local_state", "supervisor_state", "publication_state")


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
    from fk0957_publication_report_contract import PublicationReportError, refusal_diagnostic

    base = {"status": "REFUSED", "code": "REMOTE_RGB_FLOW_FAILED", "operation_id": "a" * 32,
            "authorization_id": "b" * 64, "local_state": "SUPERVISOR_TERMINAL",
            "supervisor_state": "EXITED_REFUSAL", "publication_state": "SIGNED_STAGED",
            "evidence_sha256": None, "evidence_path": "none"}
    rng = random.Random(args.seed)
    raw_exception_count = 0
    accepted_count = 0
    exception_types: dict[str, int] = {}
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    started = time.monotonic()
    for _ in range(args.cases):
        value = dict(base)
        mutation_count = 1 + int(rng.random() < 0.15)
        for _mutation in range(mutation_count):
            value[rng.choice(FIELDS)] = rng.choice(VALUES)
        wire = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        try:
            refusal_diagnostic(wire, operation_id="a" * 32)
        except PublicationReportError:
            pass
        except Exception as exc:
            raw_exception_count += 1
            name = type(exc).__name__
            exception_types[name] = exception_types.get(name, 0) + 1
        else:
            accepted_count += 1
    result = {
        "schema": "fk0957-independent-refusal-fuzz-v1",
        "seed": args.seed,
        "cases": args.cases,
        "fields_mutated": list(FIELDS),
        "raw_exception_count": raw_exception_count,
        "unexpected_accepted_count": accepted_count,
        "exception_types": exception_types,
        "started_utc": started_utc,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "hardware_access": False,
        "network_access": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if raw_exception_count == 0 and accepted_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
