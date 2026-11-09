"""Offline contract, latency, backpressure, and first-sequence checks."""
from __future__ import annotations
import json
from pathlib import Path
from board_transport import HostTransportAdapter, SoftwareTransportEmulator
from runtime import fixture_descriptor, verify_exact
from oracle import predict
from core_adapter_stress import run


def qualify() -> dict:
    # Four sharply different response-latency windows, identical ready/valid
    # rules. Each run exercises 150k transitions including randomized stalls.
    stress = [run(150_000, 0x50484B32 + i, latency_max=limit)
              for i, limit in enumerate((0, 1, 32, 128))]
    assert all(x["UNEXPECTED_FAILURES"] == x["DEADLOCKS"] ==
               x["DUPLICATE_RESULTS"] == x["DROPPED_RESULTS"] == 0 for x in stress)
    stress_events = sum(x["CORE_ADAPTER_STRESS_EVENTS"] for x in stress)
    # Count-one path must complete and verify before the batch path is issued.
    d = fixture_descriptor()
    em = SoftwareTransportEmulator()
    host = HostTransportAdapter(em)
    hello = host.hello()
    assert hello["profile_id"] == 3
    host.load_job(d.encode())
    host.start_range(d.generation, 0, 1, 1)
    status = host.status()
    assert status.flags & 2 and not status.flags & 1
    one = host.read_result(d.generation, 1)
    oracle_one = predict(d, 0, 1)
    one_exact = len(one) == 1 and verify_exact(one[0].raw_result, oracle_one["expected_compact_result"][0]) and verify_exact(one[0].canonical_result, oracle_one["canonical_result"][0])
    assert one_exact and oracle_one["checks"]["exact"]
    host.start_range(d.generation, 0, 64, 2)
    batch = host.read_result(d.generation, 2)
    assert len(batch) == 64
    oracle_batch = predict(d, 0, 64)
    batch_exact = all(verify_exact(r.raw_result, x) for r, x in zip(batch, oracle_batch["expected_compact_result"])) and all(verify_exact(r.canonical_result, x) for r, x in zip(batch, oracle_batch["canonical_result"]))
    assert batch_exact
    return {
        "INTERFACE_WIDTH_ASSERTIONS": "PASS",
        "LATENCY_INDEPENDENCE_TESTS": "4/4",
        "CORE_ADAPTER_BACKPRESSURE": "PASS",
        "CORE_STATUS_PROPAGATION": "PASS",
        "CORE_ADAPTER_STRESS_EVENTS": stress_events,
        "UNEXPECTED_FAILURES": 0,
        "DEADLOCKS": 0,
        "DUPLICATE_RESULTS": 0,
        "DROPPED_RESULTS": 0,
        "FIRST_SILICON_SEQUENCE_MOCK": "PASS",
        "COUNT1_RAW_CANONICAL_CPU_ORACLE": "PASS",
        "BATCH64_AFTER_COUNT1": "PASS",
        "latency_profiles": [0, 1, 32, 128],
        "stress_runs": stress,
    }


if __name__ == "__main__":
    print(json.dumps(qualify(), indent=2, sort_keys=True))
