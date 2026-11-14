# Independent FK0957 final software audit: de06a944

Audited exact stable remote HEAD `de06a94450c8cd4623aa3c123fa289e2533a7167`
in a fresh detached worktree. The remote and local hardening ref matched that
SHA at final refresh. Watcher PID 1170327 remained active on
`origin/hardening/fk0957-production-20261113`. Candidate worktree was clean.
No production tree, hardware, testbench, USB, or JTAG was accessed.

## Original documentation defect: closed

Searched docs, handoff, and ops material for transport-source-hash claims. The
remaining `transport_source_sha256 is null` statement is explicitly scoped to
the pure parser/mock record, which has no physical transport provenance. The
same passage says the supervised production endpoint computes the non-null
hash over clean exact HEAD, full source closure, and pinned native runtime.
That matches code. The historical handoff snapshot was relabeled historical.
`TRANSPORT_HASH_DOCUMENTATION_PASS=YES`.

## State distinction: partially implemented, not secure end-to-end

Commit `a072d9e` adds `publication_state` (`NOT_STARTED`, `SIGNED_STAGED`,
`PUBLISHING`) to refusal records and the schema. The validator enforces
reasonable combinations: a truthful `ATOMIC_PUBLISH` record marked
`PUBLISHING` without signed staging is refused. The 28/249,572 corpus, adapted
without changing the pinned reference model to project the new field, reports
zero rejected valid states and zero accepted invalid states.

However, unsigned stage substitution still recreates the original collision:

- Valid `SIGNING_STAGING`: `operation_state=LOCAL_VALIDATED`,
  `publication_state=NOT_STARTED`.
- Invalid `ATOMIC_PUBLISH`: same operation state, but the truthful field is
  `publication_state=PUBLISHING`; the validator rejects this record.
- Change only that unsigned field to `NOT_STARTED`: the candidate accepts it,
  and the projected record becomes byte-identical to the valid signing-stage
  record. The refusal has no signature or operation ID to bind the stage.

The publication field is also not wired through the real CLI failure path.
`_publish_evidence_atomic` updates a local `publish_state` list, but `run_once`
throws that state away on failure and emits `_fallback_refusal` with
`operation_state=PRELIVE`, `publication_state=NOT_STARTED`. An injected
publish fault after entering `PUBLISHING` reproduced that refusal projection.
The `_AttemptTrace.begin_evidence_publish` / `mark_evidence_published` methods
are only called by tests, not by production code. Thus `publication_state` is
not authoritative end-to-end for the operation it purports to describe.

`VALIDATOR_WEAKENED=NO`; the added consistency checks reject truthful
impossible combinations. But `STATE_COLLISION_CLOSED=NO`,
`NEW_FIELD_AUTHORITATIVE=NO`, and the overall `ORACLE_MATCH=NO` because one
additional invalid state is accepted after unsigned mutation.

## Provenance and authority

- `RELEASE_SOURCE_PATHS`: 31 entries, all present, including CLI, transport,
  supervisor, launcher, schemas, and verifier.
- Runtime inventory: 10 objects (Python 3.12, loader, libc, libcap, expat,
  libftdi, libm, libudev, libusb, zlib). All ten launcher SHA256/build-ID pins
  matched the installed bytes.
- Signed exact-HEAD manifest, tamper rejection, trust binding, and source/runtime
  checks passed in test-only signed fixtures. Production authority remains
  unprovisioned: trust-template hash matches its source pin, but release and
  handoff key-hash fields are empty, and production key/config files are absent.
- Release/handoff verifier suites pass test-only wrong-key, wrong-token,
  wrong-target, wrong-operation, wrong-HEAD/manifest, replay, duplicate-use,
  expiry, and stale-handoff cases. This establishes software mechanics only.
- Machine-readable supervisor ownership model passes package tests; no real
  root installation was verified.

## Reconfirmed closures

- Permit identity: end-to-end fake result retained authorization ID, operation
  ID, descriptor SHA, and nonce. Mismatch tests refuse before consumption and
  backend; replay/parallel use refuse.
- Legacy receipt authority: forged absent-PID receipt projected UNKNOWN and did
  not authorize restore; replay and caller terminal assertions refused.
- Startup: unsupported direct Python/bootstrap paths failed to obtain operation
  authority. Harmless sentinels still ran in some unsupported interpreter and
  environment routes before refusal; installed launcher deployment remains
  pending.
- Focused candidate suites: 107 tests passed.
- Corrected standard corpus: 28 valid / 249,572 invalid; 0 valid rejected / 0
  invalid accepted after adapting only the external envelope projection for
  `publication_state`.
- Additional adversarial stage cases: one invalid state accepted by changing
  unsigned `publication_state`; injected publish-fault state was lost in CLI
  refusal output.
- Physical transaction: unchanged, 591 / 586 / 1177 TCK; golden transaction
  tests passed.
- `git diff --check` passed.

## Scoreboard and disposition

`ORIGINAL_SOFTWARE_DEFECTS_CLOSED=8/8` (the stale documentation defect is now
closed; the other original software categories remain closed). Production
issuer keys and root installation are deployment gates, not counted as
software defects.

`SOFTWARE_RELEASE_BLOCKERS`: publication stage is not bound to the refusal
record; unsigned `PUBLISHING` → `NOT_STARTED` substitution is accepted; actual
CLI publish failure discards progress and reports PRELIVE.

`DEPLOYMENT_BLOCKERS`: provision independently approved release/handoff keys
and manifest; perform and verify the root-owned supervisor installation.

`FINAL_SOFTWARE_HARDENING_AUDIT_PASS=NO`
`READY_FOR_ADMIN_INSTALL=NO` (state/refusal reporting defect remains)
`REAL_DEPLOYMENT_VERIFIED=NO`
`READY_FOR_LIVE=NO`.

Next blocker: make publication stage an operation-bound authoritative value,
carry actual publish progress into refusal/reporting, and reject unsigned stage
substitution. Then rerun the independent state corpus and field attacks.
