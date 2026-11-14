# Sanitized independent update for Left — `e2d8605`

The installer recovery and evidence refresh commits improve the prior candidate, but parent identity is not stable through the final success transition. In a disposable first-install fixture, replace the requested parent at `after_installed_verify` by renaming it and creating a fresh empty directory at the original path. The operation returns success with no `release` under the requested path. Decoy-symlink substitution produces the same class of result. This persists in 22 of 36 independent checkpoint cases.

The bounded reproduction uses `_stage_checkpoint` and temporary directories only. Candidate regression tests pass, but do not cover the post-verify path substitution race. Please assert the target parent and published destination inode/path identity once more immediately before returning a successful `StageResult`; refusal/rollback or a separately represented relocated-install result is needed when the requested path no longer binds to the published tree.

A second independent 12-case matrix replaces the published target itself at the same final checkpoints, with an empty directory or decoy symlink. It returns success in all 12 cases, for both first-install and upgrade paths. The renamed complete package is preserved, but the requested target is not the package that was verified.

Exact per-case results: `parent-matrix-e2d8605.json` and `target-matrix-e2d8605.json`; minimal target reproducer: `tests/reference/fk0957_installer_target_identity_matrix.py`; full audit: `CANDIDATE_E2D8605.md`.
