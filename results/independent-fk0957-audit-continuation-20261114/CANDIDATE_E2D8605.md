# Independent audit: `e2d860584cbdcf74f58f4cf582214b8531528871`

## Verdict

**FAIL for release qualification; deployment remains blocked.** The two prior software defects have different results on this commit: malformed field types are now rejected safely, and manifest hashes now match this release candidate. Parent-path replacement can still cause the installer to return success while the requested installation path is absent or redirected.

## Exact identity and provenance

- Candidate: `release/fk0957-candidate-20261115`
- HEAD: `e2d860584cbdcf74f58f4cf582214b8531528871`
- Parent: `fcb4626364b977a3101abb014c83750be1db528a`
- Relevant commits in ancestry: `93fdf68041d06a593c5539522bce9f45d2f1ad02` (installer recovery), `4135afc78319ff988a6eb8bcb37c618082e38ae7` (malformed-status fix), followed by release evidence refresh.
- Manifest SHA-256: see `manifest-e2d8605.json`; sidecar matches.
- Manifest's source revision: `4135afc78319ff988a6eb8bcb37c618082e38ae7`, an ancestor of this candidate.
- Independent source/runtime checks: **31/31 source hashes match; 10/10 runtime hashes and build IDs match**. Transaction profile and trust-template hashes match; Scan A/Scan B remain 591/586 TCK, total 1177.
- Manifest remains **unsigned**, production authorization is unavailable, and production trust keys are not provisioned.

## Results

### Malformed refusal/status fields: fixed in this candidate

The independent 237-case type/omission/duplicate-key matrix produced **0 uncaught exceptions and 0 unexpected accepts**. Duplicate semantic keys in both outer and nested records resolve to `UNKNOWN`. The corresponding earlier malformed-field finding is closed for `e2d8605`.

### Parent path identity: still open

The same independent 36-case matrix (first install/upgrade; seven checkpoints; fresh directory / symlink to original / symlink to decoy) produced **22 success returns after parent substitution**.

Minimal reproducible case: during first install, at `after_installed_verify`, rename the parent directory and create a fresh empty directory at the requested parent pathname. The installer returns success although `<requested-parent>/release` is absent; the verified package exists under the renamed parent. Replacing the requested parent with a decoy symlink also returns success. The recovery locator preserves and recovers the original directory, but the final success result does not establish that the requested path still names the directory whose package was verified.

### Exact-candidate test results

- FK0957-focused host tests: **482 passed**, 122.506 s.
- Complete `tools/phk2_host` suite in the existing isolated blake3 venv: **586 passed**, 140.948 s.
- Operations acceptance campaign: **871 passed** (52 targeted + 3 × 273 broad), 101.2 s.
- Independent corrected oracle: **28 valid / 249,572 invalid**, 0 valid rejected / 0 invalid accepted; 70 focused oracle tests passed.
- Malformed type matrix: **237 cases**, 0 uncaught exceptions, 0 unexpected accepts.
- Parent identity matrix: **36 cases**, 22 success-after-substitution cases.
- Independent manifest check: **31/31 source**, **10/10 runtime**, integrity checks pass; authentication still absent.
- Candidate worktree is detached and clean; `git diff --check` passes.

No hardware, SSH to a production host, USB/JTAG, privileged installation, production keys, or live services were accessed.

## Remaining blockers

1. Before success, bind the result to and revalidate the requested parent and target identity after all replaceable checkpoints. If it changes, return a distinct relocated outcome or fail closed; do not report success for an absent requested path.
2. Production authorization remains unavailable: unsigned manifest and unprovisioned production trust keys. No live/deployment readiness can be claimed.

Minimal deterministic reproducer: `tests/reference/fk0957_parent_path_postverify_repro.py`. Artifacts: `parent-matrix-e2d8605.json`, `type-matrix-e2d8605.json`, `manifest-e2d8605.json`, `oracle-e2d8605.json`, `ops-acceptance-e2d8605.json`, `candidate-e2d8605.json`.
