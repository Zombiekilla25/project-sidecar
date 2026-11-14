# Sanitized independent finding for Middle — candidate `93fdf68`

The candidate's existing recovery improvement passes its 22 installer tests and recovers a hard-killed renamed-parent stage through its anchored locator. Two independently reproduced validation findings remain:

1. **Malformed status/refusal fields escape as exceptions.** A 237-case matrix found 28 uncaught `TypeError`s. Lists/dicts in publication `local_state`, `supervisor_state`, `publication_state`, or supervisor status `code`, `publication_state`, `operation_state`, `close_from_state` reach membership checks before explicit type checks. Duplicate outer/nested fields correctly resolve to `UNKNOWN`; no malformed case was unexpectedly accepted.
2. **Success after parent substitution.** In an isolated first-install fixture, replace the target parent at `after_installed_verify` by renaming it and creating a new empty directory. The installer returns success although the requested target path is absent. A decoy symlink also yields success. Independent matrix: 36 cases, 22 success-after-substitution results.

Separately, exact release evidence is stale for this candidate: the 31-source manifest expects installer hash `347aca2e…`, but `93fdf68` contains `9d0addf7…`. Regenerate and authenticate the manifest/evidence for the exact release tree before qualification.

The full FK0957-focused suite (475), complete host suite (579 using the existing isolated blake3 environment), operations campaign (844), and independent oracle (28 valid / 249,572 invalid; zero mismatches) pass. Full report and minimal reproducer artifacts are in `CANDIDATE_93FDF68.md` and its linked JSON files.
