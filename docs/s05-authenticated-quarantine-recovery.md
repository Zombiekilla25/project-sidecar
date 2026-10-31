# S05 Authenticated Persistent-Quarantine Recovery

_Date: 2026-10-31_

Status: **OFFLINE QUALIFIED**

## Milestone

L02 S05 software closure now includes an explicit authenticated recovery path for persistent lifecycle quarantine.

The qualified behavior is intentionally fail-closed:

1. Running-service loss can place the lifecycle into persistent quarantine.
2. A process restart alone does not release quarantine.
3. Registry/object recovery alone does not release lifecycle quarantine.
4. Immediate reconstruction without authorized recovery remains rejected.
5. Recovery requires an explicit authenticated lifecycle transition.
6. Only after successful authenticated recovery may normal restart proceed.

Persistent quarantine was not weakened or bypassed.

## Qualification

The final retained offline qualification completed with:

- **1,253 / 1,253 tests PASS**
- **0 failures**
- **0 errors**
- **44 / 44 authenticated-recovery tests PASS**
- running-loss recovery path: **PASS**
- persistent-quarantine negative coverage: **PASS**
- authenticated FD3 clean-EOF behavior: **preserved**
- real supervisor-to-broker path: **preserved**
- software-closure / VM dry-run path: **preserved**

The retained suite increased from 1,209 to 1,253 tests because 44 dedicated authenticated-recovery tests were added.

## Security properties retained

The recovery design preserves fail-closed checks around the existing lifecycle identity and authorization model, including stale or mismatched recovery contexts.

Recovery is not authorized merely by:

- restarting a process
- recovering registry/publication state
- deleting quarantine state
- using stale pre-quarantine state
- suppressing the persistent-quarantine rejection

## Safety boundary

This qualification was offline software work only.

During this milestone:

- no FPGA was programmed
- no JTAG transaction was performed
- no hardware was accessed
- no mining configuration was changed
- no production service was changed
- no protected target installation was performed
- no supervised hardware canary was executed

Private runtime evidence, machine-local paths, and local qualification artifacts remain outside this public repository.

## Next gate

S05 is closed offline.

The next milestone is controlled installation/readiness qualification against the protected target boundary. The installed candidate must be independently verified before any hardware access.

A one-card FK0957 live canary remains separately gated and requires explicit owner authorization, submission-disabled operation, and authenticated rollback/recovery readiness.
