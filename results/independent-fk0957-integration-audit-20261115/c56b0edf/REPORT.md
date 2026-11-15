# FK0957 independent integration audit — c56b0edf

Date: 2026-11-15 (local development environment)
Mode: offline, source-only inspection. No candidate module was imported or invoked.

## Candidate identity and preserved workers

- Audited commit: `c56b0edf7ea5087db7b6823580b2b7b613778bc8`
- Candidate worktree: `/tmp/fk0957-source-audit-c56b0edf` (detached, clean)
- Manifest source HEAD: `39d8e07657f7200963fdf5850008091c87a08ec8`
- Evidence/documentation revision: `3883381edb8c09a2b610ebca40686bb9f36e2837`; c56 adds the final blocker note.
- Operations import: `e4779d18cfe14fc3fb94d7a517e593779dd851cb`; it imports the reviewed Left operations behavior, but is not the exact `bb7fa295...` commit.
- Watcher PID 1170327 remains alive (state `Ss`, command watches `hardening/fk0957-production-20261113`). It was not restarted.
- Existing failed audit/campaign files were preserved. No other active test worker was found.
- Production main was not modified.

## Source and manifest integrity

Independent byte hashing of all 38 `source_inventory` entries against the c56 worktree found 38/38 present and matching, no duplicate paths, and exact equality between `source_inventory` and `source_hashes`. The manifest source HEAD is an ancestor of c56. The manifest sidecar and recomputed SHA256 both equal:

`9ae4f9dc0c900e82ce492ed93102c563dd460476d86f5f020e38cab26635784b`

The inventory includes controller, candidate RGB CLI, publication/status contracts, supervisor, launcher, endpoint, transport, backend/collector, transaction profile, and deployment config. It declares 10 native runtime objects. This audit did not inspect a privileged installed runtime or independently validate those binaries against a deployed machine.

The manifest is unsigned. Its trust-config digest matches the checked-in non-production template, whose issuer key hash slots are empty. The provisioning document explicitly says the template does not authenticate issuers and that the populated trust config, signing authorities, and signed manifest are administrator actions still outstanding.

## Controller and route analysis

Static source trace:

- `fk0957_maintenance_controller.main(--live)` returns refusal before `_precheck`, remote status probing, state creation, bridge release, or child launch.
- Direct `_live()` begins with `require_pre_release_authorization_api()`, which unconditionally raises. The hidden guardian mode also refuses; `guardian_main()` is retired and refuses.
- The controller does not invoke the candidate RGB CLI. Candidate CLI argv/report adapters exist, but comments and the compatibility handoff state they are not integrated into the live controller lifecycle. This is a fail-closed integration blocker, not a fallback authorization.
- RGB `preflight_request()` validates signatures/bindings and reports `transport_started=false`, `authorization_consumed=false`; it does not itself authorize release.
- `validate_pre_release_status()` accepts only the exact bound `NOT_STARTED` projection and explicitly returns `authorizes_release=NO`. The controller's live gate still refuses; the projection is not used as release authority.
- RGB `run_once()` is itself a live-capable CLI route: it calls `acquire_validate_sign_once()`, which validates the signed request, consumes a local one-shot ledger entry, then calls `_pinned_ssh()` and local signing after response validation. It is not wired through the maintenance controller's release/status lifecycle.

### Static alternate-entrypoint findings

1. `phk2_fk0957_topology_rgb_orchestrator._pinned_ssh(request_raw, runner=None, ...)` defaults to `subprocess.run`. It validates the pinned host key and local SSH-agent socket, but it does not itself call `_validated_local_context()` or `_consume_local_auth()` before invoking SSH. The normal `acquire_validate_sign_once()` caller does those checks first, but the helper is directly import-callable. Thus a direct helper call can reach the SSH endpoint without the RGB-side request-validation/consumption boundary. The remote supervisor should reject an invalid request before acquisition, but that does not make the local network invocation guarded. This was established by source inspection only; it was not called.
2. `tools/phk2_host/fk0957_test_support/legacy_remote_orchestrator.py` is excluded from the 38-file release manifest and has no production-source import references. Its public `acquire_and_sign()` refuses, but its `_acquire_and_sign_for_test()` function has a default real `subprocess.run`, executes the acquisition path, and signs a result. This is test-support code, not part of the declared release package; it remains a callable live-capable seam in the repository checkout and must not be run. Tests currently call it with fake runners. This is a test-harness isolation risk, not proof that the manifest package contains the file.

No unsafe function above was invoked. The transport's internal consumed-permit path statically requires a protected supervisor capability, signed request validation, permit/request tuple equality, and the original active permit before native backend construction.

## Left operations / authorization

The imported controller guard closes the previously reported direct `_live()` path, and the ordinary CLI `--live` route refuses before side effects. The status projection is non-consuming and non-authorizing. However, the controller-to-candidate-CLI release route remains intentionally unavailable. The remote trust template is unprovisioned, and there is no production issuer trust/config or authenticated release manifest. No production authorization is established.

## Dynamic tests and isolation

No candidate dynamic tests were run. A read-only, network-namespace-isolated `bwrap` attempt for the pure supervisor-status unit test failed before Python startup with `Failed RTM_NEWADDR: Operation not permitted`. Because the required isolation could not be established, the test remains blocked; no retry with weaker isolation was made. Test counts in the prior handoff (179 targeted, 555 FK tests, oracle 28/249572) are recorded as supplied evidence only and were not independently reproduced on c56 in this audit.

## Verdict

**FAIL for the requested no-unguarded-alternate-entrypoint criterion; BLOCKED for release qualification.** The controller's supported `--live` path is fail-closed, but the RGB helper exposes direct SSH before its caller-side authorization boundary, and test-support code retains a directly callable real subprocess/signing seam. The candidate CLI/controller integration is expressly absent, and production issuer keys, authenticated trust configuration/manifest, and installed-runtime verification are not available. Do not authorize live use or installation based on this audit.

Recommended remediation for the next candidate: make the SSH primitive require an unforgeable operation capability produced only after request validation/one-shot consumption (or move it behind a closed private closure/API); make test support fail closed unless a fake runner is explicitly supplied and enforce that it cannot access real SSH or signing; then source-derived mutation tests should prove those constraints. Separately integrate the candidate CLI only after authenticated non-consuming preflight is available.

Safety: no SSH, network, production filesystem, signing key, hardware, USB/JTAG, bridge release, or transport action was accessed. Candidate source was not modified.
