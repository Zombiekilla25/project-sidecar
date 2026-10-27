# Qualification Progress

_Last updated: 2026-10-27_

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
- Current serial qualification: **12/12 selected runs satisfy their declared oracle**
- Deterministic repeat pairs in the serial qualification set: **6/6**
- Full qualification catalog audit: **322/322 unique cases**
- Qualification families represented: **24**
- H0-site union represented by the full catalog: **114/114**
- Cases without detected oracle fields in the catalog audit: **0**
- Final read-only canary readiness: **PASS** for candidate authentication, rollback authentication, programmer authentication, USB identity, and submission-disabled latch state.
- Four-worker rootns stress observation: **47/48 qualified**, with one T01 timeout under simultaneous heavy host load. This is being treated as a concurrency/timing investigation, not as a qualified PASS.

No FPGA programming, real JTAG transaction, USB reset, service change, or pool submission was performed by the read-only physical stability or canary-readiness checks.

## Qualification semantics

The qualification harness now distinguishes between:

1. **Raw harness result**
2. **Qualification/oracle satisfaction**

That distinction matters because some negative containment tests are intentionally required to fail closed. A raw FAIL can therefore still represent a successfully qualified safety branch when the authenticated case oracle explicitly requires that behavior.

For the full qualification campaign, the target is:

- **644/644 case-runs satisfy their authenticated oracle**
- **322/322 deterministic repeat pairs**
- **114/114 H0-site union coverage on repeat 1**
- **114/114 H0-site union coverage on repeat 2**

Raw PASS/FAIL counts are reported separately and are not substituted for oracle satisfaction.

## Current validation notes

A heavy parallel qualification farm was used to stress the validation environment. It produced several useful findings:

- The 322-case catalog/oracle structural audit passed.
- A determinism-fuzz lane failed before exercising the normalizer because its disposable snapshot omitted a local dependency; that result is a farm setup defect, not a qualification failure.
- A high-concurrency H0 stress lane returned 120/120 failures and is under setup/path-forensics review before being interpreted.
- A four-worker rootns stress lane qualified 47/48 runs; the single miss was a T01 timeout while the host was simultaneously running multiple heavy lanes.
- Integrity checks found zero Python syntax failures, zero Bash syntax failures, zero broken symlinks, and zero world-writable input files. Extra generated Python cache files are treated as non-source contamination and are being kept out of authenticated inputs.

## Remaining gates

Before the next supervised hardware canary:

- Pass the parallel 6-case × 2-repeat qualification set.
- Pass the full 322-case × 2-repeat campaign.
- Confirm both repeats reach 114/114 H0-site coverage.
- Confirm 322/322 deterministic repeat pairs.
- Isolate the single rootns timeout observed under heavy parallel host load.
- Re-authenticate the final candidate, rollback image, external tools, and recovery path.
- Run one final supervised single-card hardware canary with submission disabled and mandatory rollback.

## Repository hygiene

This public repository intentionally excludes:

- FPGA bitstreams
- proprietary/vendor binaries
- credentials
- machine-specific secrets
- private runtime evidence
- local host paths and identifiers

Only public-safe source, documentation, architecture notes, and summarized qualification progress should be committed here.
