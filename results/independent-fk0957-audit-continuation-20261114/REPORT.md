# FK0957 independent audit continuation

**Verdict: FAIL for the current candidate branches; BLOCKED for release/deployment.**

## Candidate identity

- Current release ref: `release/fk0957-candidate-20261115` at `684770dd9657d070c982ce98fe84c839016456a6`.
- Left operations integration commit audited in a fresh detached worktree: `5eb007c92ec4b193ee4d0b08d51019fde711640a`, a descendant of 684770 but not advanced onto the release ref.
- Current Middle installer rollback branch tip inspected: `abe81bc2791b52b546985fdab9db986063a1e721`.
- Runtime source head in the release manifest and qualification result: `50fe500558495273501f643e0a0024443e23e210`. The 684770 source manifest's 31 file hashes, 10 runtime hashes/build IDs, trust-template hash, and transaction-profile hash independently matched the 5eb tree. The manifest is unsigned; production release/handoff keys remain absent. The newer Left commit adds operations/test tooling, not the manifest's installed runtime closure. No signed/authenticated final release package exists.
- Production main remained `3226bfc1474d6afa873fce7327ded6dac548baae`; no production or candidate files were changed.

## Tests collected and run

- Exact Left 5eb FK0957 host suite: **502 tests passed**, 126.912 seconds.
- Exact 5eb operations acceptance campaign: **960 tests passed** (75 targeted plus three 295-test broad runs), 105.994 seconds total.
- Corrected independent oracle on 5eb: **28 valid / 249,572 invalid**, zero valid rejected, zero invalid accepted; 70 focused reference tests passed.
- Malformed type matrix on both 684 and 5eb: 237 cases each; **28 uncaught TypeErrors**, zero unexpected accepts, duplicate-key cases return UNKNOWN. This reproduces the known refusal/status parsing defect on the newer Left integration commit.
- Parent identity race matrix on 684 and 5eb: **36 cases each**, with directory, symlink-to-original, and symlink-to-decoy substitutions at publication/cleanup checkpoints. Each run reports 22 cases where the installer returns SUCCESS after the requested parent path was substituted. The candidate may leave the valid package under the moved parent, expose it through a new symlink, or leave the requested path absent.
- Middle installer branch `abe81`: package tests **12 passed** in 7.276 seconds, while the parent identity matrix found **4 success-after-substitution cases out of 12**. This branch is not an ancestor of the current release candidate.
- Three additional exact-5eb deterministic scenario runs (15 seconds each; seeds 659918, 721077, 12648430): **285,435 scenarios / 856,305 validator checks**, zero unsafe outcomes.
- Existing background integration campaign completed: **24,024,072 scenarios**, zero unsafe, seeds 987479, 307021102, 365662174. Its recorded operations source head is `d29065046b7920ecfe7194ea198850cf715aa865`, so it is supplemental historical evidence, not proof for 5eb.
- The existing watcher remains healthy and has recorded hardening HEAD `89853ae15f435ae2069a6f6b2d627e5a14cecd18`. On that separate branch its oracle run reported 28 valid rejected, zero invalid accepted, and the specific legal-state checks failed. It is not an ancestor of release 684770 and is not treated as the release candidate.

## Confirmed defects

1. **Malformed envelope TypeErrors remain open.** On 684 and 5eb, list/dict values in publication state fields and supervisor `code`, `publication_state`, `operation_state`, or `close_from_state` escape as `TypeError`. The maintenance caller catches `ValueError` around the publication parser, not `TypeError`; the supervisor refusal checker likewise performs set/dict membership before type validation. The matrix reproduced 28 exceptions among 237 one-field/missing/duplicate cases; larger seeded fuzz previously found 59,063 TypeErrors in 200,000 mutations. No unsafe acceptance occurred, but the bounded validation contract is violated. See [Left finding](LEFT_FINDING.md).

2. **Installer can return success for a replaced destination parent.** On 684 and 5eb, after commit/install verification, renaming the parent and replacing it with a directory or symlink can still produce `SUCCESS`. Across the 36-case matrix, 22 cases per candidate returned success after parent substitution. In the minimal directory case, `stage_package` returns success, `deploy/release` is absent, and the valid package exists under `deploy-moved/release`. With symlink-to-original, the requested parent becomes a symlink and the call still returns success. The ordinary acquisition user is not intended to own the root install parent, but this breaks installer path identity and recovery guarantees for an owner/admin/filesystem race. A hard kill during pre-commit parent replacement also leaves stage+owner-marker siblings in the renamed original parent, recoverable only when that original path is supplied. See [Middle finding](MIDDLE_FINDING.md).

## Worker and campaign status

The audit worker state for 684770 is `COMPLETE` with four successful bounded tasks and journaled logs. The one-hour integration campaign and three-seed 5eb scenario campaign have completed. The long-running hardening watcher remains running; it was not restarted. Candidate and detached test worktrees remained clean after tests.

## Disposition

Neither defect is fixed in the checked release ref or Left 5eb integration branch, so this remains **FAIL**. Keep production authorization, privileged installation, and live acquisition blocked. The 684770 release evidence is integrity-checked but unsigned, and production issuer keys are not provisioned. Rerun both independent matrices and the full oracle/host suites against one exact integrated candidate after Left/Middle land fixes.
