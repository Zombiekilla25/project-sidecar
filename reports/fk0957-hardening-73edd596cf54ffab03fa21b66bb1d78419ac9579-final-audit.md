# Independent FK0957 hardening audit: 73edd596

Audited exact committed HEAD `73edd596cf54ffab03fa21b66bb1d78419ac9579` in a
fresh detached worktree. A read-only refresh confirmed it is the remote HEAD on
`origin/hardening/fk0957-production-20261113`; watcher PID 1170327 is still
running on that ref. The candidate worktree remained clean. No production
checkout was modified and no hardware, testbench, USB, or JTAG was accessed.

## State projection collision: reproduced

The corrected reference model's standard generated corpus still reports 28
valid / 249,572 invalid, with zero mismatches. Its generator does not vary
`local_validation_passed` or `signing_staged`, so it misses this independent
pair:

- Valid: `SIGNING_STAGING`, one target, consumed permit, device open, both
  scans complete, transport closed, local validation passed, signing not yet
  staged, no final evidence.
- Invalid: same fields at `ATOMIC_PUBLISH`; that phase requires signing to be
  staged, but `signing_staged=false`.

The independent projection produces the exact same canonical refusal record
for both: `phase=LOCAL_SIGNING`, `code=LOCAL_SIGNING_FAILED`,
`operation_state=LOCAL_VALIDATED`, `close_from_state=SCAN_B_COMPLETE`, and the
same counters/other fields. The candidate `_bounded_envelope` accepts both.
This is one invalid accepted state in the new adversarial pair. The commit
changes no state-envelope/projection code and introduces no authoritative phase
field. It therefore does not fix the collision.

`VALIDATOR_WEAKENED=NO`; `ORACLE_CLASSIFICATION_WEAKENED=NO`;
`NEW_FIELD_AUTHORITATIVE=NO`.

## 73edd changes

The commit adds machine-readable deployment ownership policy and sysusers,
installer checks, trust-config key-file paths/hashes, and launcher pins for
Python's previously unpinned dynamic dependencies. It does not modify the
phase/progress validator or its projection.

- All 30 `RELEASE_SOURCE_PATHS` entries exist in the candidate.
- The canonical trust-template bytes hash to the source-pinned
  `TRUST_CONFIG_SHA256` (`64ced3c5dafb6d585d3ffa10c022599722dd85e2313bb68bb4bcae6f57a22dc1`).
- Both key SHA fields in that template are empty; `/etc/sidecar/fk0957/remote-trust.json`,
  `release-issuer.pub`, and `handoff-issuer.pub` are absent in this environment.
  Loading the template refuses with `ISSUER_KEYS_NOT_PROVISIONED`.
- The supervisor deployment ownership model is internally checked against the
  installer policy: root-owned 0700 state and ledger, root:sidecar-acquire
  0750 IPC directory, root:sidecar-acquire 0660 socket, distinct runner and
  device groups. This is a package/model pass, not a real installation.
- The launcher has ten ELF pins: Python, loader, libc, libm, libz, expat,
  libudev, libcap, libftdi, and libusb. Every installed candidate file matched
  its configured SHA256 and ELF build ID. Python's direct DT_NEEDED set
  (`libm.so.6`, `libz.so.1`, `libexpat.so.1`, `libc.so.6`) is covered.
- The offline topology document still says the transport source hash remains
  null until a production adapter exists. This is stale: the candidate has the
  reviewed adapter and computes that hash.

## Verification

- Corrected standard oracle against exact candidate: 28 valid, 249,572 invalid;
  zero rejected valid states and zero accepted invalid states in that corpus.
- Additional collision pair: one invalid state accepted because it has the
  same serialized projection as a valid state.
- Candidate-focused suite: 67 tests passed through the corrected-oracle
  harness. Expanded release/endpoint/live-CLI/transport/supervisor suites: 104
  tests passed.
- Independent malformed boundary acceptance: 20,000 generated cases; zero
  escaped exceptions, exception-text leaks, or unsafe/noncanonical outputs.
- Permit reconstruction: end-to-end authorized fake route preserved
  authorization ID, operation ID, descriptor SHA, and nonce; unauthorised
  internal route refused before fake open. Endpoint tests verify mismatch
  before consumption/backend, replay, and parallel single-use behavior.
- Signed manifest and handoff verifier tests pass with generated test keys.
  Production release and handoff trust remain unprovisioned, so production
  issuer authority is not established.
- Scan transactions remain at 591 / 586 / 1177 TCK with reviewed golden hashes.
- `git diff --check` passed.

## Software scoreboard

`ORIGINAL_SOFTWARE_DEFECTS_CLOSED=7/8`:

1. Startup authority bypass: CLOSED in software; unsupported routes do not
   acquire supervisor authority. Some deliberately unsupported Python routes
   still execute harmless startup sentinels before refusing.
2. Acquisition/signing separation: CLOSED.
3. Bridge ownership binding: CLOSED as a verifier and deployment-policy model
   (generated-key attacks refuse before fake transport).
4. Runtime/source provenance: CLOSED as an implementation: 30 source paths,
   signed-manifest verifier, Git/HEAD/cleanliness checks, and ten native pins
   are present and tested. Production trust-root provisioning remains a
   deployment gate.
5. Synthetic backend/signing seam: CLOSED.
6. Evidence path identity/race: CLOSED in prior independent attack corpus.
7. Native runtime pinning: CLOSED for the audited installed bytes; all ten
   configured hashes/build IDs matched.
8. Launch/documentation consistency: OPEN; stale transport-hash documentation
   remains.

The newly reproduced state-projection collision is an additional unresolved
state-machine defect, outside the original eight categories.

`TRUSTED_RELEASE_AUTHORITY_PASS=NO` and `TRUSTED_HANDOFF_AUTHORITY_PASS=NO` for
the current production environment because key hashes are empty and key files
are absent; generated-key verifier tests pass. `FULL_PROVENANCE_PASS=YES` for
the implemented signed-manifest/source/runtime verification path in tests, but
no production authority is installed. `REAL_DEPLOYMENT_VERIFIED=NO`.

`FINAL_SOFTWARE_HARDENING_AUDIT_PASS=NO`
`READY_FOR_ADMIN_INSTALL=NO` until the collision is fixed and stale
documentation is corrected.
`READY_FOR_LIVE=NO`.

Next blockers: add authoritative stage/progress information (without weakening
the oracle) so SIGNING_STAGING and ATOMIC_PUBLISH cannot alias; correct the
stale transport-hash documentation; then independently provision/review the
release and handoff keys and verify real installation.
