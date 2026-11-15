# FK0957 independent integration audit — 2026-11-15

## Verdict

**SOFTWARE_INTEGRATION: FAIL / BLOCKED.** The exact release source `d8f4fe665cbb181faa0f1b07176925896cde4271` has passing offline tests and artifact checks, but still contains direct-import/legacy acquisition routes outside the public CLI gate. The reviewed Left implementation is not in the source lineage, does not apply cleanly to d8, and itself retains two callable import-level seams. **PRODUCTION_DEPLOYMENT: BLOCKED.** Production trust keys and authorization are absent; no installation or live operation is authorized.

## Immutable identities

- Last reviewed source baseline: `9ce7bb2435c2a942f7baf6c1668e09a081597c82`.
- Middle source candidate audited: `d8f4fe665cbb181faa0f1b07176925896cde4271` (parent `72c137bd5f0cbdaacc4abb674cc5a2418de376f4`).
- Evidence/package state audited: `66636104b5410d36332b6bb65230b462b8035734` (descends from source candidate; contains the final report/package pin updates).
- Package archive: SHA256 `4b6b7069734c78b6bad0c809a1a93484d52bc53cf97d75ef309212b745558ec4`, source commit recorded as `98ad42a4fecfe22bc104f7db417fe4e1ae242ab3`.
- Evidence-tree source manifest SHA256 `88d034cf6c102fce97c6fe8a325d70a9ca33e83c319d58e1f43062e1e26c768f`; independent verification: 38/38 source hashes and 10/10 runtime object hashes/build IDs match; transaction profile and sidecar match. Manifest is unsigned and test-only trust template is not production authority.
- Left implementation: `bb7fa2958a6d4808cfbef73812f83a9ab9060a44`, parent `89bdba831a981d510fc03f0823444ef2e69c5ad7`; handoff/package commit `6ed7479a91acd2b926068f77bbf4ca5bc243db82`.
- Left commit is not an ancestor of d8. The portable patch SHA256 is `4994e562317924af3495d7404640a97d0ffc9de08636f602e671f5d8899a06a2`. Applying it to its declared parent recreates bb7's exact tree `3c874ad43239066057359b6c3cae94d01bf76f14`; applying it to d8 fails at controller, RGB contract, orchestrator, and test contexts.
- Production checkout was clean at `3226bfc1474d6afa873fce7327ded6dac548baae`; it was not modified.

## Independently derived routing results

`tests/reference/audit_fk0957_entrypoint_routes.py` derives routes from source AST and verifies the argv producer consumed by `run_operation_once`; it does not accept caller-supplied route booleans. A dead call to the candidate RGB helper leaves the derived route classified as legacy.

On d8:

- Public maintenance `main(--live)` returns refusal before `_precheck`.
- Direct `_live()` has no first-action pre-release guard, constructs argv via `build_operation_argv`, and passes it to `run_operation_once`.
- Legacy orchestrator `main()` calls `acquire_and_sign()`; the public imported API has no pre-release guard.
- The candidate RGB CLI's empty authorization preflight returned canonical `REFUSED`, `AUTHORIZATION_PREFLIGHT_FAILED`, `transport_started=false`, `authorization_consumed=false`, rc 2.

On bb7:

- `_live()`, hidden guardian CLI, legacy CLI, and the public `acquire_and_sign()` API have fail-closed guards.
- However `guardian_main()` remains import-callable, takes a caller-supplied `--self-sha256`, and dispatches to `_guardian_main()` without an independent trusted-runner identity.
- `_acquire_and_sign_for_test()` remains import-callable and unguarded, defaults `runner` to real `subprocess.run`, reaches SSH/validation/signing code, and its fake-runner test demonstrates local signing from synthetic acquisition output. Renaming it “for_test” does not make it unreachable from production imports.
- The handoff itself says the authenticated non-consuming supervisor idle/status API is missing and its candidate compatibility audit is BLOCKED. The preflight report is diagnostic/non-authorizing, as required, but it does not complete the controller lifecycle.

Thus the latest Left handoff is useful but is not a complete safe integration. It must remove or hard-guard every import-level side-effect path and supply the independently authenticated supervisor preflight contract before it can be integrated.

## Test results

Exact candidate d8 / evidence package checks:

- FK0957 focused suite: **542 passed** (150.839 s).
- Complete host suite in isolated venv with `blake3 1.0.11`: **646 passed** (163.743 s). System Python without blake3 had one import error; rerunning in the existing isolated venv resolved it.
- Independent state oracle: **28 valid, 249572 invalid; 0 valid rejected, 0 invalid accepted**; 70 focused oracle checks passed; 591/586/1177 transaction invariants and hashes match.
- Malformed status/refusal matrix: **237 cases**, zero uncaught exceptions and zero unexpected accepts.
- Deterministic integration scenario campaign, seed `2026111401`: **11763 scenarios / 35289 validator checks / 0 unsafe**.
- Installer identity matrices: **36 parent-path cases + 12 target-inode cases**, zero violations.
- Independent manifest verification: **38/38 sources, 10/10 runtime objects**, no source/runtime hash or build-ID errors; manifest unauthenticated and production keys unprovisioned.
- Left bb7 focused controller/RGB CLI/orchestrator suite: **133 passed**; all Left FK0957 discovery tests: **318 passed**.
- d8 invalid empty authorization request: refusal before transport, rc 2.
- d8 public maintenance `--live`: refuses before precheck, rc 1.
- Source-to-evidence ancestry verified; no live tests were run.

## Safety incident disclosure

One dynamic route probe accidentally reused the d8 Python module object while switching to the Left checkout and called d8's unguarded `_live()` directly. It printed an operation ID and created an empty local operation directory plus a consumed marker under the local maintenance state root. The invocation terminated locally; no USB or hardware path was invoked and no evidence was written. Because `_live()` calls `_precheck()`, an SSH precheck may have been reached; the exact boundary cannot be recovered from surviving output. No SSH process remains. I stopped all execution-path probing and made no cleanup to the consumed marker/state, to avoid altering operation state. This is a test-harness error and must be included in any review of this audit. No additional SSH/network/hardware actions were performed.

## Watchers and preserved prior worker results

- Existing hardening watcher PID `1170327` remains running with the same remote branch configuration; it was not restarted or duplicated.
- The old bounded test queue at `/tmp/fk0957-offline-queue-4463` is complete with status FAILED, not a healthy running worker. Its prior failure (`rotating-integration-campaign`, seeds `2026111401`, `659918`, `6229397`) is retained; it was tied to evidence revision `4463a4b6` and was not substituted for this d8 qualification.

## Remaining blockers

1. Integrate the exact operations changes into a new immutable candidate and regenerate its authenticated source/runtime manifest.
2. Close import-level guardian and test-helper execution routes; add source-derived regression tests that call no external service.
3. Provide the authenticated, non-consuming supervisor idle/status API bound to operation, authorization, target, HEAD, source/runtime/profile hashes, freshness, and supervisor identity.
4. Provision genuine production issuer/trust roots and verify authorization/handoff externally.
5. Independently verify an authorized installation before any live readiness claim.

Offline software tests are strong but do not authorize production installation or a live operation.
