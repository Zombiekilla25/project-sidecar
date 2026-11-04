# FK33 fleet orchestration test report

This report covers the deterministic offline fleet model. Every accelerator
and lifecycle operation in these cases is mocked; no physical card, USB, JTAG,
pool, CUDA context, or GPU workload is used.

## Exercised rollout sizes

| Stage | Active cards expected | Tested behavior |
| --- | ---: | --- |
| `CANARY_1` | 1 | Select exactly `fk0`; no peer receives work |
| `EXPAND_2` | 2 | Advance only after each active card meets the configured health gate |
| `EXPAND_4` | 4 | Preserve prior stage evidence and expand to exactly four |
| `FULL_8` | 8 | Expand to eight and schedule across all logical cards |

The model also constructs configurations containing each fleet size from one
through eight. A mock run assigned and CPU-verified 10,000 unique work items
across eight active cards with zero duplicate, stale, unqualified-activation,
or image-mismatch counters.

## Failure and recovery cases

- A local timeout or bad result rolls back the affected card and leaves peers
  schedulable. A replacement must pass qualification again, and stage health
  history is retained while the cohort is repaired.
- Repeated failures quarantine a card. Rejoin is limited by a configured retry
  count and requires qualification, unique binding, rollback identity, health
  check, and verified limited canary.
- A matching incorrect raw/canonical signature from two cards aborts the stage
  and rolls back the stage cohort as a systemic concern.
- Wrong bitstream/runner/protocol qualification, unknown rollback image,
  duplicate target binding, wrong programmed image, and target binding
  mismatch all fail closed. A target binding mismatch stops at the selected
  card and does not try a peer.
- A new job invalidates queued old-generation work. Late results are dropped;
  they cannot alter peer state or become share eligible.
- A full queue rejects an oversized enqueue atomically, without partially
  assigning the requested batch.
- Controller restart treats prior active assertions as `UNKNOWN`. Explicit
  qualification and state revalidation are required before a card returns to
  `READY`.

## Scheduling and observability

Round-robin balances equal cards, least-busy balances outstanding assignments,
and measured-throughput weighting favors cards with supplied measured rates.
Unknown measured timing fields stay `null`; the test does not synthesize
hardware compute time or PearlHash throughput. Status is machine-readable,
public-safe, and contains logical IDs rather than physical binding strings.

## Regression command and scope

Run with the isolated project Python environment:

```sh
python -m unittest tests.test_fleet -v
```

The fleet test module covers model/state transitions, qualification and image
gates, scheduling policies, result verification, stage progression, rollback,
quarantine/rejoin, safe persistence, CLI commands, release packaging, and the
10,000-assignment mock soak. Passing these tests validates orchestration logic
only. PHK1 physical qualification remains a separate prerequisite; no actual
multi-card speedup, transport stability, or production rollout is claimed.
