# Qualification Progress

_Last updated: 2026-11-01_

## Current milestone

The FK33 PRL safety/qualification stack has reached a major checkpoint:

- Immutable V7 soak: **109/109 PASS**
- H0 regression: **67/67 PASS**
- Single-owner security regression: **51/51 PASS**
- Repeated H0 stress: **50/50 PASS**
- Read-only physical USB stability soak: **360/360 PASS**
- USB disappearances: **0**
- USB state changes: **0**
- Serious kernel USB errors during soak: **0**
- Programmer/tool provenance checks: **PASS**
- Serial qualification: **12/12 selected runs satisfy their declared oracle**
- Deterministic repeat pairs in the serial qualification set: **6/6**
- Parallel qualification: **cleared the ordered gate**
- Full qualification campaign: **started successfully**
- Current full-campaign progress at the first stop: **68 qualified case-runs, 1 unqualified case-run**
- Full qualification catalog audit: **322/322 unique cases**
- Qualification families represented: **24**
- H0-site union represented by the full catalog: **114/114**
- Cases without detected oracle fields in the catalog audit: **0**
- Final read-only canary readiness: **PASS** for candidate authentication, rollback authentication, programmer authentication, USB identity, and submission-disabled latch state.
- V4.1 integrated host candidate: **fixture-qualified** with 5/5 known bypass paths closed in the fixture model and no placeholder success paths remaining.
- V4.1 integrated regression groups: **35/35, 16/16, 644/644, 37/37, and 44/44 PASS**, plus 105 D01 checks, 23 prestart checks, 17 refusal checks, and the new integrated failure-injection group passing.
- Protected host installation: **PASS** with **6,278 candidate files verified**, static native admission installed, and direct unprivileged candidate/native execution denied.
- L02 S05 authenticated persistent-quarantine recovery: **OFFLINE QUALIFIED** with **1,253/1,253 retained tests PASS**, **44/44 dedicated recovery tests PASS**, 0 failures, and 0 errors.
- S05 target userspace compatibility: **1,253/1,253 PASS** locally and on target.
- Initial Project Sidecar production deployment: **COMPLETE**.
- Guarded production transaction: **60/60 planned mutations**, **0 unexpected mutations**, transaction committed.
- Installed-file verification: **40/40 PASS** for hash, ownership/group, and mode checks.
- Supervisor/worker runtime handoff and privilege separation: **PASS**.
- Production rollback path: **qualified**; no rollback was required by the successful deployment.
- Post-install read-only production soak: **15 minutes PASS** with stable service health and unchanged restart counters.
- Shared-ancestor mutation count during the successful deployment/verification path: **0**.
- Protected workloads remained stable across deployment and soak.
- One-card FK0957 hardware canary: **not authorized and not executed**.

No FPGA programming, real JTAG transaction, USB reset, mining configuration change, or pool-submission change was performed by the production deployment qualification or the read-only production soak.

## Qualification semantics

The qualification harness distinguishes between:

1. **Raw harness result**
2. **Qualification/oracle satisfaction**

Some negative containment tests intentionally fail closed. A raw FAIL can therefore still represent a successfully qualified safety branch when the authenticated case oracle explicitly requires that behavior.

For the full qualification campaign, the target remains:

- **644/644 case-runs satisfy their authenticated oracle**
- **322/322 deterministic repeat pairs**
- **114/114 H0-site union coverage on repeat 1**
- **114/114 H0-site union coverage on repeat 2**

Raw PASS/FAIL counts are reported separately and are not substituted for oracle satisfaction.

## Current validation notes

The ordered validation pipeline has now progressed through:

1. authenticated input/immutability gates
2. H0 regression
3. single-owner security regression
4. fixture/aggregation/static gates
5. T01 rootns smoke
6. serial qualification
7. parallel qualification
8. entry into the full 322-case campaign
9. protected-host installation and boundary qualification
10. S05 authenticated recovery and target-userspace compatibility
11. guarded production transaction qualification
12. real production installation
13. post-install read-only production soak

The first full-campaign stop occurred after 68 qualified case-runs when one case-run failed qualification. Immutable inputs remained authenticated and unchanged. That campaign gap remains separate from the now-complete initial production deployment milestone.

A previous heavy parallel qualification farm also established:

- 322/322 unique cases in the catalog
- 24 qualification families
- 114/114 H0-site union in the catalog
- final read-only canary readiness PASS
- four-worker rootns stress at 47/48 under deliberately heavy simultaneous host load, with the single miss being a T01 timeout

## V4.1 protected-host checkpoint

The V4.1 host-authority work converged from separate forensic/design lanes into one integrated candidate. The qualified fixture path covers static native admission, clean environment enrollment, hash-bound candidate/interpreter identity, D01 target-policy enforcement, three-principal authority binding, two-inventory regeneration, publication ordering, rollback, simulated SIGKILL next-start recovery, and recovery idempotence.

A protected release was installed on the development host and independently carried forward into the production Sidecar qualification path. Public-safe verification established:

- 6,278 candidate files verified after protected-boundary installation
- static native admission present
- protected ownership/mode boundary present
- direct unprivileged candidate access denied
- direct unprivileged native execution denied
- live source unchanged
- rollback/recovery prerequisites retained

This checkpoint did **not** authorize the FK0957 one-card hardware canary.

See [V4.1 protected host boundary milestone](v41-protected-host-boundary.md) for the focused checkpoint.

## S05 authenticated-recovery checkpoint

The L02 S05 offline software gate is closed.

The running-loss blocker was resolved by implementing an explicit authenticated lifecycle recovery transition rather than weakening persistent quarantine. The final retained suite passed 1,253/1,253 tests with zero failures and zero errors. Forty-four dedicated authenticated-recovery tests were added and all passed.

The qualified contract preserves persistent quarantine across ordinary reconstruction. Registry/object recovery alone is insufficient to release lifecycle quarantine; an explicit authorized recovery transition is required before normal restart may resume.

See [S05 authenticated persistent-quarantine recovery](s05-authenticated-quarantine-recovery.md).

## Initial production deployment checkpoint

The initial Sidecar production installation is complete.

Public-safe results from the final production path:

- production transaction committed successfully;
- **60/60** planned mutations applied;
- **0** unexpected production mutations;
- **40/40** installed-file integrity/ownership/mode checks passed;
- supervisor/worker startup and privilege separation passed;
- the runtime handoff/READY path passed;
- the authenticated rollback path remained available;
- no shared-ancestor metadata mutation was observed;
- protected workloads remained unchanged;
- the post-install service state remained stable for a **15-minute read-only soak** with unchanged restart counters.

This closes the initial deployment phase. The installed production runtime is now the known-good baseline for subsequent observability and acceleration work.

See [initial production deployment milestone](production-deployment-milestone.md).

## Remaining gates

The production-deployment phase is complete. Remaining work is now split between long-running validation and the project’s actual acceleration objective:

- Maintain lightweight read-only production monitoring and preserve the known-good deployment baseline.
- Resolve or formally disposition any remaining full-campaign qualification gaps that are still applicable.
- Qualify the next safe GPU↔FK33 transport/data-path step.
- Measure host-to-FPGA DMA latency and bandwidth on real hardware when separately authorized.
- Demonstrate a real GPU-produced PearlHash intermediate offloaded to FK33.
- Measure end-to-end throughput including transfer, synchronization, scheduling, FPGA processing, and return-path overhead.
- Obtain separate explicit owner authorization before any one-card FK0957 hardware canary or other newly gated hardware action.

## Repository hygiene

This public repository intentionally excludes:

- FPGA bitstreams
- proprietary/vendor binaries
- credentials
- machine-specific secrets
- private runtime evidence
- local host paths and identifiers
- private authority material

Only public-safe source, documentation, architecture notes, and summarized qualification progress should be committed here.
