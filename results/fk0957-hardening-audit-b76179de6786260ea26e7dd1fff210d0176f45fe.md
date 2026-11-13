# Independent FK0957 hardening audit — `b76179de6786260ea26e7dd1fff210d0176f45fe`

Audit date: 2026-11-13. All work used a fresh detached worktree. No production files were changed; no SSH, network, USB, or hardware access occurred.

## Results

- Corrected independent state oracle: **PASS** — 28 valid and 249,572 invalid states; 0 valid states rejected; 0 invalid states accepted. Its 49 focused tests passed, and the oracle does not use the production validator.
- Additional malformed-envelope campaign: 20,000 cases, no validator exceptions, no raw exception text, no unsafe/noncanonical output.
- Long-run adversarial campaign: passed after correcting the audit's parent-move race expectation to accept the candidate's fail-closed `NotADirectoryError`/`ValueError`. It included 10,000 malformed variants, 120 target-order permutations, 120 duplicate-target permutations, publication races, path attacks, and transaction hashes.
- Candidate focused native/CLI/orchestrator suites: 128 tests passed. Independent native-library requalification: 187 candidate tests passed; runtime/native pins matched and no FTDI context or USB enumeration was invoked.
- `git diff --check`: passed.
- Fixed transactions remain byte-identical: Scan A 591 TCK, Scan B 586 TCK, total 1,177. Hashes: A `81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2`; B `08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a`.

## Defects and gates

1. **Startup injection — OPEN.** Harmless sentinels executed via `PYTHONPATH`, `sitecustomize`, `usercustomize`, `LD_PRELOAD`, `PATH`, and replacement of a documented interpreter path. More specifically, direct invocation of `fk0957_safe_bootstrap.py` with caller-set `FK0957_TRUSTED_LAUNCHER=1` still ran an `LD_PRELOAD` constructor before bootstrap refusal. The static launcher source is present, but no protected launcher binary is deployed. The environment marker does not authenticate the launcher.
2. **Remote acquisition / RGB signing split — OPEN.** The topology CLI performs local FTDI acquisition and local signing. There is no unsigned remote topology result boundary or operation-ID binding. No key transmission or remote signing code was found.
3. **Bridge ownership / handoff authority — OPEN.** No signed owner handoff validation or cross-process exclusive lock gates this live acquisition path. The seven missing/stale/wrong/competing-owner fixture cases all reached the acquisition boundary. The runbook itself says this remains required.
4. **Complete runtime/Git provenance — OPEN.** One-byte changes to all listed runtime sources and manifest changed the self-computed source hash; clean Git state and HEAD are sampled. However, no immutable expected release HEAD or trusted signed source-manifest pin is enforced. A clean different commit can self-hash and proceed.
5. **Synthetic backend seam — CLOSED at the explicit API boundary.** The production public function takes only `authorized_permit`, the transport factory is hard-coded to `_NativeLibFtdi`, and there is no caller-supplied backend argument. The fake signing flow found is test-only. This does not close startup injection, which can run code before the trusted boundary.
6. **Evidence path identity/race — CLOSED for tested cases.** Symlink, hardlink, parent replacement, temp collision, competing writer, and publish races failed closed; no replacement path received evidence.
7. **Native runtime pins — OPEN.** The integrated libc/libftdi/libusb bytes matched the locally reviewed pins and native tests passed. The ELF loader is inventoried but not pinned/enforced before Python starts, and the direct-bootstrap test demonstrates execution before its post-start environment check.
8. **Launch/documentation consistency — OPEN.** `docs/phk2-fk0957-topology-discovery-offline.md` still says the transport source hash is null until a production adapter exists, although the integrated transport now computes one. The handoff snapshot names `fe94ef45...` while the audited branch is at `b76179de...`; its own metadata describes it as a snapshot, but it is not a current release authorization. The documentation correctly states that the launcher is undeployed and the operation is not live-ready.

## New defect reproduced

`phk2_fk0957_topology_transport._run_consumed_permit()` is production-importable and starts `_NativeLibFtdi` without validating or consuming the permit. Its downstream `validate_candidates()` checks only candidate count and identity. A mock-only call using a manually constructed, unregistered permit returned two sealed observations on two calls, with two simulated device opens, while the token remained absent from both `_ACTIVE` and `_CONSUMED`. This path bypasses permit issuance, signer binding, expiry validation, and single-use enforcement before transport. No real device was opened. The internal function must not be directly capable of physical acquisition without an unforgeable consumed-permit capability or equivalent gate.

## Per-SHA status

`DEFECT_1_STARTUP_INJECTION=OPEN`
`DEFECT_2_ACQUISITION_SIGNING=OPEN`
`DEFECT_3_BRIDGE_OWNERSHIP=OPEN`
`DEFECT_4_RUNTIME_PROVENANCE=OPEN`
`DEFECT_5_SYNTHETIC_SIGNING=CLOSED`
`DEFECT_6_EVIDENCE_PATH_RACE=CLOSED`
`DEFECT_7_NATIVE_LIBRARY_PIN=OPEN`
`DEFECT_8_LAUNCH_DOCUMENTATION=OPEN`

`NEW_DEFECTS=unconsumed private transport entrypoint permits repeated scans`
`VALID_STATE_REJECTED=0`
`INVALID_STATE_ACCEPTED=0`
`TRANSACTION_INVARIANTS=PASS`
`READY_FOR_LIVE=NO`

The independent watcher should continue against new committed hardening HEADs. The active hardening worktree was observed with uncommitted edits; they were not audited or modified.
