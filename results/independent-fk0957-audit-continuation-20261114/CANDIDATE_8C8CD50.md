# Exact release branch audit: `8c8cd5022e799b13eb998795196c6c73b845f94d`

## Verdict

**PASS for the targeted parent-path and target-inode substitution defects; BLOCKED for production release authorization and deployment.** The exact release branch HEAD is a test-only commit; its runtime source revision remains `be33af695079847cfab6a1dd6310a27cc31a4ca9`. Evidence revision remains `6f0c27da54de098c9de43fe8d0311d9889f0efbf`.

## Identity and source closure

- Exact release branch HEAD: `8c8cd5022e799b13eb998795196c6c73b845f94d`.
- Parent: `6f0c27da54de098c9de43fe8d0311d9889f0efbf`; commit adds installer target-identity regression tests only.
- Audited production source HEAD: `be33af695079847cfab6a1dd6310a27cc31a4ca9`.
- Evidence revision: `6f0c27da54de098c9de43fe8d0311d9889f0efbf`, direct child of be33.
- Manifest SHA-256: `41aee5f94f4b355ba29afbb61378199ee8337c2e95e4520debefa3713fa1b4fe`; manifest `production_head` and qualification `candidate_source_commit` both equal be33.
- Independent verifier: **31/31 source hashes**, **10/10 native hashes/build IDs**, trust-template/profile digests and transaction invariants match.
- Manifest is unsigned; production authorization and trust keys are absent. Handoff evidence sets `ready_for_live=false`.

## Parent and target identity substitution

- Original **36-case** parent-substitution matrix on exact 8c: **zero false successes**.
- Strict parent matrix: **42/42 refused**, no unsafe outcomes. This adds post-stage-verification injection and records every result. It covers first-install and upgrade, recreated parent directories, symlink-to-original and symlink-to-decoy. All 24 upgrade cases preserve a complete verified prior release.
- Original **12-case** target-inode matrix on exact 8c: **zero false successes**.
- Strict target matrix: **18/18 refused**, no unsafe outcomes. It covers first install and upgrade with target absent, empty-directory substitution, and decoy-symlink substitution at final verification and cleanup checkpoints. A complete verified displaced release remains available in all 18 cases.
- The former minimal parent-path reproducer now gets `ValueError` after replacing the parent at `after_installed_verify`; it does not report a successful install at the absent requested path.
- Candidate package tests include independent parent and target matrix regressions, rollback, interrupted publication/recovery, old-release preservation, and neighbor preservation.

## Exact-8c test results

- Installer package suite: **25 passed**, 35.862 s.
- FK0957-focused host suite: **485 passed**, 143.775 s.
- Complete host suite in existing isolated blake3 venv: **589 passed**, 165.773 s.
- Operations acceptance: **871 passed** (52 targeted + three × 273 broad), 107.943 s.
- Malformed refusal/status campaign: **237 cases**, zero exceptions and zero unexpected accepts.
- Independent corrected oracle: **28 valid / 249,572 invalid**, zero valid rejected / zero invalid accepted; 70 focused oracle tests passed.
- `compileall` and exact-commit `git diff --check`: pass.

No hardware, production systems, USB/JTAG, privileged installation, signing keys, or live operations were accessed.

## Remaining release gate

Targeted software defects are independently resolved on this release lineage. Production release readiness remains **BLOCKED** because the manifest is unsigned, production trust keys/authorization are absent, and no privileged deployment verification exists.

Artifacts: `candidate-8c8cd50.json`, `manifest-6f0c27d.json`, `oracle-8c8cd50.json`, `ops-acceptance-8c8cd50.json`, `type-matrix-8c8cd50.json`, `parent-matrix-8c8cd50.json`, `parent-strict-8c8cd50.json`, `target-matrix-8c8cd50.json`, `target-strict-8c8cd50.json`, `minimal-parent-8c8cd50.json`.
