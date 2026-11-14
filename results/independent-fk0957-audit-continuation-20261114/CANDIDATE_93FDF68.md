# Independent audit: `93fdf68041d06a593c5539522bce9f45d2f1ad02`

## Verdict

**FAIL for release qualification; the offline test evidence is otherwise green.** The commit improves crash recovery and its own tests pass, but independent testing still finds post-verification success after the requested install parent is replaced. The malformed refusal/status parser exceptions also remain. The release source manifest does not hash the installer bytes at this commit.

## Exact source and evidence identities

- Candidate branch: `release/fk0957-candidate-20261115`
- Candidate HEAD: `93fdf68041d06a593c5539522bce9f45d2f1ad02`
- Parent: `684770dd9657d070c982ce98fe84c839016456a6`
- Candidate source revision asserted by evidence: `50fe500558495273501f643e0a0024443e23e210`
- Manifest: `results/fk0957-release-candidate-source-manifest.json`
- Manifest SHA-256: `a3f4b8afc516213128faea59c5bdeac44226d3692d20423f0de505b33b7b6d16` (sidecar matches)
- Qualification evidence source: `results/fk0957-release-qualification-20261114.json`; its sidecar matches.
- Manifest authentication: unsigned; production authorization and trust keys are absent.

Independent manifest verification: **30/31 source hashes match, 10/10 native runtime hashes/build IDs match**, transaction counts and transaction-profile hash match. The mismatch is `tools/phk2_host/install_fk0957_supervisor.py`: manifest expects `347aca2ed29d8ac68ac29c9363dce5131ebad5425b827594051c45d2bfdf9f70`; candidate bytes hash to `9d0addf77e8dfba83404e4b6e5511326b43f65b7f9d52803912909a415a7763b`. Thus evidence and manifest do not describe the exact candidate tree.

## Reproduced defects

### Parent-path replacement false success

Independent checkpoint matrix: **36 cases**, across first install/upgrade, seven publication checkpoints, and new-directory / symlink-to-original / symlink-to-decoy replacement. It found **22 success returns after parent substitution**.

Minimal case: first install; at `after_installed_verify`, rename the requested parent, create a fresh directory at the original path, and let the operation continue. `stage_package()` returns `SUCCESS`; the fully verified release exists under the renamed parent, while the requested path has no `release` entry. This is post-publication path-identity drift after the verification checkpoint, so the caller is told installation succeeded at a path that is not installed. A symlink-to-decoy at the same checkpoint also returns success with the requested target absent.

The implementation does correctly recover the interrupted renamed-parent stage through its anchored locator. This finding concerns the terminal success contract after the requested path changes, not the locator recovery improvement.

### Malformed refusal/status types

Independent type/omission/duplicate-key matrix: **237 cases**, **28 uncaught `TypeError` exceptions**, zero unexpected accepts; duplicate outer and nested keys both classify as `UNKNOWN`.

- Publication parser: list/dict values in `local_state`, `supervisor_state`, or `publication_state` reach membership operations before type rejection.
- Supervisor status parser: list/dict values in `code`, `publication_state`, `operation_state`, or `close_from_state` escape as `TypeError`.

Malformed data must resolve to the bounded refusal/unknown result instead of leaking an implementation exception through the validation boundary.

## Test results on exact candidate

- Installer package suite: **22 passed**, 19.403 s.
- FK0957 focused suite, `python3 -m unittest discover -s tools/phk2_host -p 'test*fk0957*.py'`: **475 passed**, 129.552 s.
- Complete `tools/phk2_host` suite using existing isolated `/tmp/fk0957-audit-venv-20261114`: **579 passed**, 144.568 s. System-Python first attempt had the known optional `blake3` import error; rerun in the existing isolated venv passed without system package changes.
- Operations acceptance: **844 passed** (46 targeted + 3 × 266 broad), 102.5 s.
- Independent corrected oracle: **28 valid / 249,572 invalid**, 0 valid rejected / 0 invalid accepted; 70 oracle tests passed.
- Independent type matrix: **237 cases**, 28 raw exceptions, 0 unexpected accepts.
- Independent parent replacement matrix: **36 cases**, 22 false-success cases.
- `git diff --check` on the candidate commit: pass; detached candidate worktree clean.

No hardware, SSH, USB/JTAG, privileged install, production keys, or live services were used.

## Blocking actions

1. Revalidate the requested parent directory identity after the last publication checkpoint and before reporting success; refusal/rollback or an explicitly distinct relocated-install result must be returned when identity changed.
2. Type-check all status/refusal fields before membership or comparison operations and translate malformed input to the documented bounded result.
3. Regenerate the release manifest/evidence for the exact installer bytes and exact candidate HEAD; authenticate it with provisioned production trust before treating it as authorization.

Audit artifacts: `parent-matrix-93fdf68.json`, `type-matrix-93fdf68.json`, `manifest-93fdf68.json`, `oracle-93fdf68.json`, `ops-acceptance-93fdf68.json`.
