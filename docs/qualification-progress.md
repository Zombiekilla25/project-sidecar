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

## Remaining gates

Before the next supervised hardware canary:

- Resolve the first full-campaign unqualified case.
- Resume and complete the full 322-case × 2-repeat campaign.
- Confirm both repeats reach 114/114 H0-site coverage.
- Confirm 322/322 deterministic repeat pairs.
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
