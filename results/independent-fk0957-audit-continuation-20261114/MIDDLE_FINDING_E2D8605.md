# Sanitized independent update for Middle — `e2d8605`

The newer candidate closes the malformed refusal/status type issue: independent 237-case matrix, zero uncaught exceptions and zero unexpected accepts. The evidence refresh also fixes source completeness for this exact tree: all 31 source paths and 10 native runtime objects match their recorded hashes/build IDs.

One installer correctness defect remains. The independent 36-case parent identity matrix still finds 22 success returns after parent substitution. Minimal case: first install; at `after_installed_verify`, rename the target parent and create a new empty directory at its old pathname. `stage_package()` returns normally, but the requested `<parent>/release` is absent. A decoy parent symlink also returns success. The commit's recovery locator recovers the old directory after interruption; the remaining issue is the terminal success/path contract after path replacement.

On exact `e2d8605`: focused suite 482/482, complete host suite 586/586 in the existing isolated blake3 environment, operations acceptance 871/871, independent corrected oracle 28/249572 with zero mismatches. The manifest is integrity-consistent but still unsigned and has no provisioned production trust key, so release authorization remains blocked.

Reproducer/report artifacts are in `parent-matrix-e2d8605.json` and `CANDIDATE_E2D8605.md` on the independent audit branch.
