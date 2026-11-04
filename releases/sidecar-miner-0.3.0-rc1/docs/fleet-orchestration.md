# Offline FK33 fleet orchestration

The fleet controller is a policy and lifecycle layer above the existing miner
backend contracts. It exposes `fk0` through `fk7` as independent logical
resources, consumes the existing PHK1 qualification artifact loader, verifies
every result through the existing raw/canonical and CPU-reference gates, and
uses an injected lifecycle adapter. This checkout accepts only the deterministic
mock adapter; it has no live USB, FTDI, JTAG, FPGA, pool, or CUDA fleet actions.

## Rollout stages

```text
CANARY_1 (1 active)
    | configured health gate: sample count, error rates, observation time
EXPAND_2 (2 active)
    | same gate
EXPAND_4 (4 active)
    | same gate
FULL_8 (8 active)
```

Every new controller starts at `CANARY_1`; persisted state cannot assert that a
card is active. A stage can advance only when the active count matches its
target, enough verified transactions have completed, the observation period has
elapsed, timeout/transport rates are within configured bounds, and no incorrect
result occurred. The gate parameters are explicit inputs; no production
thresholds are guessed here. A local card failure is rolled back and can be
replaced through a new plan while preserving the stage's accumulated evidence.
Identity/protocol mismatch, scheduler failure, shared transport corruption, or
the same bad result signature on multiple cards aborts the stage cohort.

## Qualification and image identity

Each card must have a unique abstract physical binding, a valid imported PHK1
artifact matching its expected bitstream, runner, backend, and protocol hashes,
and a known rollback image hash. Missing or ambiguous bindings fail closed.
Configuration examples deliberately use `null` binding placeholders and do not
contain serial numbers, DNA, USB paths, wallets, or credentials. A future
hardware adapter must resolve one logical card through the hardware project's
authoritative target lock and must return the exact bound identity; a mismatch
aborts before programming and does not fall through to a peer.

## Work distribution and result gate

The controller projects active resources to the scheduler as logical backend
IDs only. It supports deterministic `round_robin`, `least_busy`, and
`measured_throughput_weighted` assignment. Throughput weighting uses supplied
measured jobs/second values; unknown values default to equal weights. Work IDs
are unique within a job generation, queue capacity is bounded, and a new job
marks queued prior-generation work stale. A late result remains isolated to its
assigned card. Before success, a result must match backend, batch, job, and
generation; its raw/canonical identities must agree; and the CPU reference must
accept it. No fleet result can bypass the miner share-verification path.

## Health, quarantine, and recovery

Per-card telemetry tracks assignments/completions, raw and verified results,
bad results, timeouts, transport errors, stale results, latency summaries,
throughput estimate, uptime, restarts, and rollback count. Health score uses an
explicit weighted failure formula exposed in status output. Failure threshold
quarantines one card. Rejoin is bounded and requires fresh qualification,
unique binding, rollback identity, health check, and limited verified canary.
The status endpoint aggregates active/qualified counts, verification/failure
rates, queue depth, stale work, recent failure categories, and measured
throughput. Unknown silicon timing remains `null`; effective PearlHash rate is
reported as `UNKNOWN` until the workload-to-silicon relationship is measured.

## Rollback policy

| Trigger | Card action | Stage action |
| --- | --- | --- |
| Wrong raw/canonical result or CPU mismatch | Roll back and quarantine after configured repeated failures | Abort if the same bad signature appears on multiple cards |
| Timeout, missing heartbeat, process crash | Roll back that card; count timeout/restart | Continue healthy peers unless a stage gate fails |
| Qualification, bitstream, or protocol mismatch | Fail closed and roll back any already staged card | Abort the stage |
| Shared transport corruption or scheduler failure | Roll back affected stage participants | Abort the stage |
| Stale result | Discard, count stale, do not submit | No peer action |
| Target binding mismatch | Stop before programming; no peer fallback | Abort the stage |

Rollback is represented as `XBT rollback -> production restore -> release` in
the adapter contract. Only mock actions are executable in this package.

## Commands

Use a config with one through eight logical card entries:

```sh
sidecar-miner fleet status --fleet fixtures/fleet/eight-fk-offline.json --json
sidecar-miner fleet plan --fleet fixtures/fleet/eight-fk-offline.json
sidecar-miner fleet rollout --fleet fixtures/fleet/eight-fk-offline.json --dry-run
sidecar-miner fleet watch --fleet fixtures/fleet/eight-fk-offline.json --iterations 3
sidecar-miner fleet disable --fleet local-fleet.json --card fk3
sidecar-miner fleet enable --fleet local-fleet.json --card fk3
```

`rollout` requires `--dry-run`. Status, plan, and watch are read-only. Disable
and enable modify only the supplied in-memory model and optionally its
public-safe state file; none of these commands accesses hardware. A restored
process reports enabled cards as `UNKNOWN` and requires explicit revalidation.

## Verification and performance evidence

The test suite covers fleet sizes 1 through 8, gated 1/2/4/8 expansion,
qualification/image/rollback gates, target mismatch, per-card containment,
systemic failures, stale work, duplicate assignment, scheduling fairness,
heterogeneous weights, bounded queues, restart ambiguity, recovery, status/CLI,
and 10,000 mock work assignments over eight cards. The observed test inventory
is recorded in [the fleet orchestration test report](fleet-orchestration-test-report.md).
These are software model results only. They are not physical-card stability or
performance claims.

The PHK1 physical protocol remains pending separate qualification, real CUDA
remains unqualified, and Kryptex live mining remains unauthorized. Once the
external PHK1 process produces the public-safe qualification artifact, the
operator must still provide verified image/runner identities and per-card
physical bindings before the mock lifecycle adapter can be replaced under a
separate reviewed hardware integration change.
