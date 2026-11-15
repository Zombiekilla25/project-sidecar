# Independent audit: source `be33af695079847cfab6a1dd6310a27cc31a4ca9`, evidence `6f0c27da54de098c9de43fe8d0311d9889f0efbf`

## Verdict

**PASS for the previously identified parent-path and target-inode substitution defects; BLOCKED for production release authorization/deployment.** The exact candidate refuses every independently generated invalid parent/target substitution in the expanded matrices. No production trust key is provisioned and the release manifest is unsigned, so no production or live readiness is implied.

## Watcher and worker state

- Existing hardening watcher PID `1170327` was inspected and left running; it still tracks `origin/hardening/fk0957-production-20261113` with two stable polls.
- Existing worker checkpoint `/tmp/fk0957-audit-worker-state-684770/{state.json,journal.jsonl}` remains completed and unchanged.
- No integration campaign was running when inspected. Prior completed campaign output was preserved; it belongs to older source `d290650` and was not used as evidence for this candidate.

## Identity and manifest

- Source HEAD: `be33af695079847cfab6a1dd6310a27cc31a4ca9` (subject: “Recheck publish identity on installer cleanup failures”).
- Evidence HEAD: `6f0c27da54de098c9de43fe8d0311d9889f0efbf`, direct child of source HEAD.
- Manifest `production_head` and qualification `candidate_source_commit` both equal the exact source HEAD.
- Manifest SHA-256: `41aee5f94f4b355ba29afbb61378199ee8337c2e95e4520debefa3713fa1b4fe`; sidecar matches.
- Independent integrity checks: **31/31 source hashes**, **10/10 native runtime hashes/build IDs**, trust-template/profile digests, and transaction counts all match.
- Authentication is explicitly `UNSIGNED; integrity evidence only, not production authentication`; production authorization and trust keys are absent. Handoff evidence reports `ready_for_live=false`.

## Substitution and recovery findings

- Original independent parent matrix: **36 cases; zero false-success outcomes**.
- Strict parent identity matrix: **42 cases; all 42 refused**, zero unsafe outcomes. It includes the original parent replacement cases plus six additional `after_stage_verify` checkpoints. It records first-install and upgrade paths, recreated parent directories, symlink-to-original and symlink-to-decoy replacements.
- Original independent target matrix: **12 cases; zero false-success outcomes**.
- Expanded strict target matrix: **18 cases; all 18 refused**, zero unsafe outcomes. It covers first install and upgrade at post-verification/finalize checkpoints, upgrade cleanup checkpoints, and replacement with an empty directory, decoy symlink, or absent target.
- Minimal prior failure reproducer now returns `ValueError` for the changed parent and reports no successful install at the absent requested path.
- Preservation: 24 parent-upgrade cases and all 18 target-substitution cases retained a complete verified release. Candidate package tests also verify old-release rollback, idempotent recovery, and neighbor preservation.

## Input and regression suites

- Malformed refusal/status matrix: **237 cases**, zero uncaught exceptions, zero unexpected accepts; duplicate keys classify as `UNKNOWN`.
- Installer package tests: **24 passed**, 32.067 s. This includes the 36-case parent matrix and a cleanup-error parent-substitution regression.
- FK0957-focused host suite: **484 passed**, 141.950 s.
- Complete host suite using existing isolated blake3 venv: **588 passed**, 164.675 s.
- Operations acceptance: **871 passed** (52 targeted + 3 × 273 broad), 108.045 s.
- Corrected independent state oracle: **28 valid / 249,572 invalid**, 0 valid rejected / 0 invalid accepted; 70 focused oracle tests passed.
- Compileall and commit `git diff --check`: pass.

No hardware, testbench/production host, USB/JTAG, privileged installation, signing-key provisioning, or live service was accessed.

## Remaining blocker

Production authorization remains unavailable: manifest unsigned and production trust keys absent. This is a deployment/release gate, not a failure of the tested substitution fix.

Artifacts: `minimal-parent-be33af6.json`, `parent-matrix-be33af6.json`, `parent-strict-be33af6.json`, `target-matrix-be33af6.json`, `target-strict-be33af6.json`, `type-matrix-be33af6.json`, `manifest-6f0c27d.json`, `oracle-be33af6.json`, `ops-acceptance-be33af6.json`, `candidate-be33af6.json`. Reproducers: `tests/reference/fk0957_parent_path_postverify_repro.py`, `tests/reference/fk0957_installer_parent_identity_strict_matrix.py`, `tests/reference/fk0957_installer_target_identity_strict_matrix.py`.
