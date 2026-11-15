# FK0957 independent integration audit — 2026-11-15

## Verdict

**FAIL for software integration; BLOCKED for production deployment.** The new controller's public `--live` CLI refuses before remote precheck, and request preflight is non-consuming. The source/runtime manifest is materially more complete and verifies independently. The candidate still does not integrate its candidate RGB CLI into the actual controller route: `_live()` builds and launches the legacy orchestrator, although the public command currently blocks before reaching it. That internal helper remains import-callable, so the public guard is not a complete route boundary. Production trust is an empty-key template and remains unavailable. A candidate scenario campaign also still false-accepts its legacy-route fault fixture.

## Exact identities and provenance

- Source candidate: `9ce7bb2435c2a942f7baf6c1668e09a081597c82` (`fix: fail closed on legacy FK0957 live route`).
- Evidence revision: `3e31c44ccd1454b59f49f4d01279e2cdfd53ab81`, parent `8bdcb6b224c0abe3b13e49a9c8b4bd578c2a600e`. Source 9ce is an ancestor of evidence 3e31; candidate worktree is clean.
- Independent manifest verification: 38/38 source files, 10/10 runtime hashes/build IDs, sidecar, and transaction profile all match. Manifest SHA-256 `4f68ea22a06fe2f5fc2722af7874f64f3dda5de3744cf53037ceb9f1f9da1d65`. Covered sources now include the controller, publication and supervisor-status contracts, RGB contract, release endpoint/authorization contracts, supervisor, launcher, operations policy, and transaction profile.
- Manifest signature/production authorization: **unavailable**. The pinned trust config digest is the canonical empty-key nonproduction template (`64ced3c5…`); issuer slots are empty, and signed runtime-manifest verification returned `RUNTIME_MANIFEST=REFUSED`, exit 2. No test key was treated as production authority.
- Independent package rebuild at source commit `8bdcb6b224c0abe3b13e49a9c8b4bd578c2a600e` exactly matched the reported 169,907-byte package SHA-256 `e803e5ec8031ad4decde037bfca05cd38063f478f318fa37e252f456754ba20f`; archive verification passed.
- The compatibility CLI, run with source HEAD 9ce and evidence HEAD 3e31, confirmed all manifest-source/runtime/profile pins but refused: the controller route is legacy, the manifest is unsigned, and evidence revision `3e31` includes `docs/fk0957-read-only-pre-live-verification.md`, outside its evidence-only path allowlist. The tool correctly records evidence ancestry and exact source separately.

## Controller and authorization findings

- Direct source/data-flow inspection: `_live()` assigns `argv` from `build_operation_argv()` and passes that variable to `run_operation_once()`. That builder launches `phk2_fk0957_remote_orchestrator.py`. `build_candidate_rgb_cli_argv()` is not in that data flow.
- The public `fk0957_maintenance_controller.py --live` invocation returned exit 1 with `HANDOFF_GO=NO` and `NEXT_BLOCKER=CANDIDATE_RGB_AUTHORIZATION_AND_LIFECYCLE_NOT_READY`; the code returns before `_precheck()`.
- The candidate RGB CLI preflight on an invalid request returned bounded `AUTHORIZATION_PREFLIGHT_FAILED`, exit 2, `authorization_consumed=false`, `transport_started=false`, and empty stderr. The endpoint loads the fixed protected trust configuration and verifies its hash; no test-only key or caller-supplied issuer reaches this public path.
- Remaining route risk: `_live()` itself is an import-callable function with no authorization argument/validation guard; it creates a random local permit digest and proceeds through the legacy orchestrator workflow if called directly and its other production checks pass. The package qualification explicitly records `legacy_internal_live_helper_reachable=true`. This is an internal direct-call bypass of the public `--live` refusal and blocks a complete route-boundary pass.

## Independent fixture and checker findings

- The candidate scenario campaign still fails at deterministic case 6 (`fault=6`). It mutates `controller.operation_entrypoint` to the legacy orchestrator, then calls `audit_candidate()` without an observed route result; the default `controller_live_uses_candidate_cli=True` makes the malformed fixture compatible. The source-derived independent fixture instead derives the route from `_live()` argv data flow and passes that result explicitly; it refuses the legacy route.
- An additional mutation exposed a compatibility-checker false positive: adding an unused `build_candidate_rgb_cli_argv(...)` call inside `_live()` makes the checker’s call-presence heuristic say the candidate CLI is integrated, even while `argv` still comes from `build_operation_argv()` and is consumed by `run_operation_once()`. This is not present in the actual 9ce source (which the CLI correctly rejects); it is a checker robustness defect for future route mutations.
- The independent route auditor and deterministic fixtures are in `tests/reference/audit_fk0957_controller_route.py`. Prior b821 reproducer remains preserved separately.

## Test results on exact evidence checkout 3e31

- FK0957-focused host suite: **539 passed**, 148.317 s.
- Complete host suite: **643 passed**, 169.343 s.
- Corrected independent oracle: **28 valid / 249,572 invalid**, 0 valid rejected, 0 invalid accepted; 70 oracle tests passed.
- Malformed status/refusal matrix: **237 cases**, zero uncaught exceptions and zero unexpected accepts.
- Installer identity matrices: parent **36 + 42** and target **12 + 18** cases; zero violations/unsafe outcomes. Timings: 11.045 s, 12.875 s, 3.858 s, 5.967 s.
- Transaction profile and golden scan hashes unchanged: 591 / 586 / 1177; Scan A `81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2`; Scan B `08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a`.
- Candidate rotating integration campaign: **FAIL**, exit 1 at case 6, seed `2026111401`.
- Manifest signed verifier: expected fail-closed result, exit 2. Public live CLI and invalid RGB preflight both refused without transport or authorization consumption.
- Measured test time was approximately **5m52s**, excluding setup/review.

## Disposition

The installer path-identity behavior remains independently passing, and manifest coverage/integrity improved. Software integration is not complete: public live acquisition is disabled rather than routed through the candidate RGB one-shot lifecycle; direct invocation of the legacy internal helper remains reachable; the route compatibility heuristic and candidate campaign fixture have false-accept gaps; and the evidence checker rejects this evidence revision because of a non-handoff documentation change. Production deployment remains blocked pending an integrated trusted lifecycle, genuinely provisioned production issuer keys and signed manifest/authorization, and independent privileged deployment verification. No hardware, USB/JTAG, production host, privileged installation, service, or signing key was accessed.
