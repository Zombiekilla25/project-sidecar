# Qualification Progress

_Last updated: 2026-10-31_

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
- One-card FK0957 canary: **not authorized and not executed**; protected-boundary qualification is the current gate.
- L02 S05 authenticated persistent-quarantine recovery: **OFFLINE QUALIFIED** with **1,253/1,253 retained tests PASS**, **44/44 dedicated recovery tests PASS**, 0 failures, and 0 errors. Persistent quarantine remains fail-closed; registry recovery alone does not release lifecycle quarantine.

No FPGA programming, real JTAG transaction, USB reset, service change, or pool submission was performed by the read-only physical stability or canary-readiness checks.

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

The first full-campaign stop occurred after 68 qualified case-runs when one case-run failed qualification. Immutable inputs remained authenticated and unchanged. The next task is to isolate that exact case and determine whether it is a true runtime/oracle defect or a timing/fixture issue before resuming the full campaign.

A previous heavy parallel qualification farm also established:

- 322/322 unique cases in the catalog
- 24 qualification families
- 114/114 H0-site union in the catalog
- final read-only canary readiness PASS
- four-worker rootns stress at 47/48 under deliberately heavy simultaneous host load, with the single miss being a T01 timeout

## V4.1 protected-host checkpoint

The V4.1 host-authority work has converged from separate forensic/design lanes into one integrated candidate. The qualified fixture path now covers static native admission, clean environment enrollment, hash-bound candidate/interpreter identity, D01 target-policy enforcement, three-principal authority binding, two-inventory regeneration, publication ordering, rollback, simulated SIGKILL next-start recovery, and recovery idempotence.

A protected release has now been installed on the development host. Public-safe install verification established:

- 6,278 candidate files verified after installation
- static native admission present
- protected ownership/mode boundary present
- direct unprivileged candidate access denied
- direct unprivileged native execution denied
- live source unchanged
- no service restart, network action, FPGA programming, JTAG access, hardware access, or mining change

This installation does **not** authorize a hardware canary. The next step is independent qualification of the installed production boundary against the fixture-qualified contract. A separate explicit owner authorization remains required before any one-card FK0957 hardware execution.

See [V4.1 protected host boundary milestone](v41-protected-host-boundary.md) for the focused checkpoint.


## S05 authenticated-recovery checkpoint

The L02 S05 offline software gate is now closed.

The remaining running-loss blocker was resolved by implementing an explicit authenticated lifecycle recovery transition rather than weakening persistent quarantine. The final retained suite passed 1,253/1,253 tests with zero failures and zero errors. Forty-four dedicated authenticated-recovery tests were added and all passed.

The qualified contract preserves persistent quarantine across ordinary reconstruction. Registry/object recovery alone is insufficient to release lifecycle quarantine; an explicit authorized recovery transition is required before normal restart may resume.

No hardware, FPGA, JTAG, mining, production-service, or protected-target installation action was part of this checkpoint.

See [S05 authenticated persistent-quarantine recovery](s05-authenticated-quarantine-recovery.md).

## Remaining gates

Before the next supervised hardware canary:

- Independently qualify the installed V4.1 protected production boundary.
- Confirm the installed release identity and protected ownership/mode contract.
- Confirm direct invocation remains denied outside the admitted path.
- Re-authenticate rollback/recovery prerequisites at the installed boundary.
- Resolve or formally disposition any remaining full-campaign qualification gaps that are still applicable to the final canary contract.
- Obtain separate explicit owner authorization for the one-card canary.
- Run one final supervised single-card FK0957 hardware canary with submission disabled and mandatory rollback.

## Repository hygiene

This public repository intentionally excludes:

- FPGA bitstreams
- proprietary/vendor binaries
- credentials
- machine-specific secrets
- private runtime evidence
- local host paths and identifiers

Only public-safe source, documentation, architecture notes, and summarized qualification progress should be committed here.

## S05 target userspace compatibility checkpoint

Full retained qualification passed locally and on target: **1,253/1,253**, zero failures and errors. Exact descriptor inventory and authenticated recovery semantics remain unchanged. No protected installation or hardware action occurred. See [target userspace compatibility](s05-target-userspace-compatibility.md).
