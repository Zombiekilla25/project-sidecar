# FK0957 overnight independent audit checkpoint — c56b0edf

Date: 2026-11-15 (America/New_York). Scope: local committed source and artifact inspection only. No candidate module was imported or invoked.

## Source and evidence identity

- Audited candidate: `c56b0edf7ea5087db7b6823580b2b7b613778bc8` (`codex/fk0957-overnight-contract-20261115`, exact local committed tip at audit start).
- Manifest source HEAD: `39d8e07657f7200963fdf5850008091c87a08ec8`, an ancestor of c56.
- Evidence revision: `3883381edb8c09a2b610ebca40686bb9f36e2837`; c56 adds the final blocker note.
- Operations integration commit: `e4779d18cfe14fc3fb94d7a517e593779dd851cb`, followed by `39d8e076...`. This imports the Left operations guards, but Left's exact `bb7fa295...` SHA is not in the candidate ancestry.
- Manifest SHA256: `9ae4f9dc0c900e82ce492ed93102c563dd460476d86f5f020e38cab26635784b`.
- Source inventory: 38 entries, all present with matching Git-blob SHA256; source hash map and inventory agree, no duplicate or extra paths. Ten native runtime objects are declared. Their identities were not checked against a deployed installation in this audit.
- Existing reproducible archive `/tmp/fk0957-release-fresh-3883381/results/fk0957-release-package.tar.gz` recomputes to `cd98852066efcb3c43f7877e12852144162ac10878aad2bec77489a01abfd5dd`, matching its prior recorded digest. It is the 388/39d source package, not a fresh build of a later candidate.

## Independent static route and trust review

The worker parsed 12 production Python modules (227 functions), without imports. It also checked C launcher source text and ran two in-memory source mutation checks. Results are retained in `sha-reports/c56b0edf7ea5087db7b6823580b2b7b613778bc8.json`.

- Maintenance controller `main(--live)` refuses before `_precheck`; direct `_live()` begins with the unconditional `require_pre_release_authorization_api()` refusal. Hidden guardian and retired guardian paths refuse. This is a source-derived pass for the controller path.
- The controller still does not route through the candidate RGB one-shot CLI. Its live route remains explicitly blocked, which is safer than falling back to the legacy orchestrator but leaves the intended release integration incomplete.
- `validate_pre_release_status()` requires the exact `NOT_STARTED` status and returns `query_mutates_authorization=NO` and `authorizes_release=NO`. This projection is diagnostic, not authorization.
- `phk2_fk0957_topology_rgb_orchestrator._pinned_ssh()` has a real `subprocess.run` default and calls it without first validating/consuming the local authorization. Those checks occur in its normal caller. The helper itself is directly callable; direct invocation can reach SSH without the caller-side gate. It was not invoked.
- RGB `main()` and `run_once()` do not enforce the trusted-launcher marker themselves. The official bootstrap/launcher has a separate trust path, but direct script/import invocation can bypass that pre-start verification. The current empty trust template blocks valid production authorization today; it does not close the alternate route once provisioned.
- `_sign_validated_remote_record()` calls the local key's `sign()` operation and has no unforgeable validated-operation capability parameter. It checks selected record fields and provenance shape, but a direct caller is not forced through the full RGB acquisition validator first. The private key was not accessed. This is an import-level synthetic-signing risk.
- `fk0957_test_support/legacy_remote_orchestrator.py` is outside the manifest and has no production import reference. Its public wrapper refuses, but `_acquire_and_sign_for_test()` retains a real `subprocess.run` default and local signing path. It is not in the declared 38-file package, but remains hazardous if called from a repository checkout. No such function was invoked.
- The direct `phk2_fk0957_topology_live_cli.main()` also lacks a launcher check, but the current `perform_fk0957_topology_discovery_once()` implementation is an unconditional refusal stub. No physical transport route was reached or invoked.
- Static C launcher review found runtime hash/build-ID checks, protected bootstrap/manifest/trust opens, isolated `-I -S`, and `execve`. The worker's `clean_environment=false` is a checker false negative: C passes an explicit `clean_env` array containing only `PATH=/usr/bin:/bin`, `LANG=C.UTF-8`, and `FK0957_TRUSTED_LAUNCHER=1`; it does not call `clearenv()`. This was verified by reading the C source, not executing it.

## Pure offline checks and dynamic test limits

- Standard-library-only JSON checks: both trust template key hash slots are empty; the runtime manifest has no signature/issuer envelope; transaction profile is exactly 591 / 586 / 1177 and hashes to `695870565b971d3b4ac49d69a6196e600629e5b2604af4e063ea0cf1d763cd00`.
- Source-route mutation checks: removing the controller `_live()` guard is detected; inserting a required local auth check into `_pinned_ssh()` is detected. These mutate in-memory source text only.
- No candidate host/controller/operations/oracle suite was executed. The required network-isolated `bwrap` setup previously failed with `RTM_NEWADDR: Operation not permitted`; no weaker isolation or repeated attempt was used. Dynamic tests are **BLOCKED**. Prior suite counts in the handoff remain supplied evidence, not independently reproduced here.
- No SSH, network fetch, production path, key, signing, bridge release, remote process, USB/JTAG, hardware, or live service was accessed.

## Verdict

**AUDIT_VERDICT=FAIL / BLOCKED.** The controller route itself is fail-closed and status preflight is non-authorizing, but callable SSH and signing helpers bypass those caller-side trust boundaries; direct RGB entry also lacks launcher enforcement. Production issuer keys and authenticated manifest are absent, so production authorization/deployment remain blocked. Do not mark the candidate ready for live use.

Required software follow-up: make the SSH primitive require an unforgeable validated-operation capability; make the signer accept only a sealed validated result or move signing behind an inaccessible closure; enforce launcher authorization in every callable CLI entry; retire or fake-runner-gate the test support live helper. Then independently rerun dynamic negative tests only under verified isolation.
