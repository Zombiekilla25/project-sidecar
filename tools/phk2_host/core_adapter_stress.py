"""Deterministic latency/backpressure model for the frozen PHK2 core boundary."""
from __future__ import annotations
import random


def run(events: int = 600_000, seed: int = 0x50484B32, latency_max: int = 128) -> dict:
    rng = random.Random(seed)
    cycle = 0
    desc_pending = 0
    range_pending = 0
    active_latency = -1
    result_pending = False
    result_stall = 0
    generation = 0
    job_key = bytes(32)
    range_id = 0
    offered = completed = delivered = 0
    duplicates = dropped = unexpected = deadlocks = 0
    in_flight_ids: set[int] = set()
    delivered_ids: set[int] = set()
    busy_ticks = 0
    last_progress = 0

    def progress():
        nonlocal cycle, desc_pending, range_pending, active_latency, result_pending
        nonlocal result_stall, generation, job_key, range_id, offered, completed
        nonlocal delivered, duplicates, dropped, unexpected, deadlocks, busy_ticks, last_progress
        cycle += 1
        did = False
        # Descriptor channel with randomized acceptance delay.
        if desc_pending:
            desc_pending -= 1
            if desc_pending == 0:
                generation += 1
                job_key = rng.randbytes(32)
                did = True
        # Core processing latency is randomized independently of board polling.
        if active_latency >= 0:
            if active_latency == 0:
                active_latency = -1
                result_pending = True
                completed += 1
                did = True
            else:
                active_latency -= 1
        # A result remains stable through arbitrary consumer backpressure.
        if result_pending:
            result_stall += 1
            if rng.randrange(8) == 0:
                result_pending = False
                result_stall = 0
                if range_id in delivered_ids:
                    duplicates += 1
                elif range_id not in in_flight_ids:
                    unexpected += 1
                else:
                    delivered_ids.add(range_id)
                    delivered += 1
                    in_flight_ids.remove(range_id)
                did = True
        # Start requests queue behind core busy/result backpressure.
        if range_pending and active_latency < 0 and not result_pending:
            range_pending -= 1
            if range_pending == 0:
                range_id += 1
                if range_id in in_flight_ids or range_id in delivered_ids:
                    duplicates += 1
                else:
                    in_flight_ids.add(range_id)
                    offered += 1
                active_latency = rng.randrange(0, latency_max + 1)
                did = True
        if did:
            last_progress = cycle
        busy_ticks = 0 if did else busy_ticks + 1
        if busy_ticks > 500:
            deadlocks += 1
            busy_ticks = 0

    for i in range(events):
        # Randomly offer work only after any descriptor transfer is finished.
        if desc_pending == 0 and i % 97 == 0:
            desc_pending = rng.randrange(1, 18)
        if range_pending == 0 and active_latency < 0 and not result_pending and i % 3 == 0:
            range_pending = rng.randrange(1, 24)
        progress()
        # Model occasional stale generation requests: rejected without enqueue.
        if i % 4093 == 0 and generation and rng.randrange(2):
            stale_generation = generation - 1
            if stale_generation == generation:
                unexpected += 1

    # Bounded deterministic drain after the randomized window.
    drain_limit = cycle + 10_000
    while (desc_pending or range_pending or active_latency >= 0 or result_pending) and cycle < drain_limit:
        if desc_pending and rng.randrange(2):
            desc_pending = 1
        if range_pending and rng.randrange(2):
            range_pending = 1
        progress()
    if cycle >= drain_limit:
        deadlocks += 1
    if in_flight_ids or offered != completed or completed != delivered:
        dropped = max(dropped, abs(offered - delivered))
    return {
        "CORE_ADAPTER_STRESS_EVENTS": events,
        "UNEXPECTED_FAILURES": unexpected,
        "DEADLOCKS": deadlocks,
        "DUPLICATE_RESULTS": duplicates,
        "DROPPED_RESULTS": dropped,
        "OFFERED": offered,
        "COMPLETED": completed,
        "DELIVERED": delivered,
        "LATENCY_MIN_MAX": [0, latency_max],
        "DESCRIPTOR_BACKPRESSURE_MAX": 17,
        "RESULT_BACKPRESSURE_RANDOMIZED": True,
        "LAST_PROGRESS_EVENT": last_progress,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2, sort_keys=True))
