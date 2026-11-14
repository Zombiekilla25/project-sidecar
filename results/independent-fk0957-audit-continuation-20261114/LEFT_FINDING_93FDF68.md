# Sanitized independent finding for Left — candidate `93fdf68`

The installer recovery change fixes the earlier hard-kill orphan-stage scenario through a parent-anchored recovery locator. Its installer tests pass (22/22). An independent adversarial checkpoint matrix still reproduces a terminal path-identity defect:

1. Create a disposable first-install target beneath a private parent.
2. At the existing `after_installed_verify` checkpoint, rename the parent and create a new empty directory at the requested parent path.
3. Allow the operation to return normally.
4. `stage_package()` returns success, although `<requested-parent>/release` is absent. The package exists only under the renamed parent.

This also reproduces with a decoy symlink substituted at the requested parent. Across 36 offline cases, 22 return success after parent substitution. Please revalidate the requested parent inode/path after the final checkpoint and before success. The test only uses temporary directories and candidate checkpoints; it does not install anything on the host.

Reproducer and per-case data: `parent-matrix-93fdf68.json`; full exact-candidate audit: `CANDIDATE_93FDF68.md`.
