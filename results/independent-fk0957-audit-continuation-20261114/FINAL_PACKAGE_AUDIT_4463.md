# FK0957 independent integration audit — 2026-11-15

## Verdict

**FAIL for integrated software release; BLOCKED for production deployment.** The exact package source hashes and runtime inventory verify, and the installer identity matrices pass. The active maintenance controller still routes `_live()` to the legacy remote orchestrator; it does not use the candidate RGB one-shot CLI. The package manifest omits the controller and publication/supervisor-status contracts. Production authorization remains unavailable and unsigned. An independent rotating integration fixture also has a false-accept defect for its legacy-entrypoint mutation.

## Immutable identities

- Source candidate: `b821b273d7113a5ce44607fa3dfee599b7fdaa58`.
- Evidence/package qualification commit: `4463a4b6c826cc3211f75aef83ed4089e85488b7` (parent `404626467d794a6157f8b9d011ac763f7f9bdf62`); detached audit worktree clean.
- Source manifest: `results/fk0957-release-candidate-source-manifest.json`, SHA-256 `38b0538c2ca05be20ad0818bcef0452108bfc289751f1e4f21ccd19ade907b04`; checksum sidecar agrees. Manifest source head is b821; the evidence tree at 4463 contains that source plus later report/package commits.
- Candidate source integrity: all 31/31 listed files match. Runtime inventory: all 10/10 pinned objects/hash/build-id rows match. The manifest is unsigned; no production trust root/keys are provisioned.
- Manifest omits runtime-relevant `tools/phk2_host/fk0957_maintenance_controller.py` (SHA-256 `03bace19991318510d64aae1f61aa4c84ad7eb36d2a5d3f05994089de1db76e5`), `fk0957_publication_report_contract.py` (`6b4558e2b5c4bd19c8d8d09a67289594cb53e8c68eb1edceaddb63edcc30bffd`), and `fk0957_supervisor_status_contract.py` (`25e1df2c6a197e8d7e596a5a3b24fa7950d1514c0eb24d302af75e2652e75bb4`). Thus the listed hashes are internally correct but source closure is incomplete.
- Latest handoff `4dddb8e9527dad782ff7aab56ac12a3c06ceee24` is not an ancestor of b821. Candidate qualification also records the latest handoff snapshot as not imported.

## Integration findings

- `fk0957_maintenance_controller.py::_live()` calls `build_operation_argv()`. That constructs an inline Python runner for `phk2_fk0957_remote_orchestrator.py` with `--ephemeral`.
- `build_candidate_rgb_cli_argv()` exists, but is described as an offline adapter and `_live()` does not call it. The controller therefore bypasses the expected candidate RGB one-shot CLI.
- The production-facing compatibility CLI independently detects this route: `controller_live_path_uses_candidate_rgb_cli=false`, `controller_entrypoint=phk2_fk0957_remote_orchestrator.py`, and exits 2 (refusal). It also reports missing production signature/trust-root, profile/source pin mismatches, and mismatched profile digest. Candidate-source hashes and runtime rows themselves match.
- The compatibility tool sets `candidate_head` from the checked-out Git HEAD when `--candidate-root` is supplied. This makes a source manifest naming b821 report `reviewed_head_exact=false` on the later evidence commit 4463, despite the 31 file hashes matching. The source/evidence revision distinction should be made explicit in the checker contract or the release package should be built from a checkout at the manifest's exact candidate source SHA.

## Independent campaign defect

The exact-candidate rotating campaign fails deterministically at case 6 (fault 6): it changes `controller.operation_entrypoint` to `phk2_fk0957_remote_orchestrator.py`, then calls `audit_candidate()` without passing `controller_live_uses_candidate_cli=False`. That function defaults this check to `True`, so the legacy entrypoint is accepted as compatible. Minimal reproduction output: fault 6, legacy entrypoint, check `True`, `compatible=True`, while expected result is refusal. This is a false acceptance in the campaign fixture/API call; the actual compatibility CLI does pass an AST-derived boolean and correctly refuses the checked candidate. The fixture must provide or derive the live-route check before its campaign claim can be trusted.

## Independent test record

- Full host suite: 630 passed, 159.676 s; log `/tmp/fk0957-host-4463.log`.
- Focused integration/admin suite: 93 passed, 0.325 s.
- Operations campaign: three broad runs, 314 tests each, zero unsafe outcomes; 34.106 s, 34.531 s, 35.023 s.
- Corrected independent state oracle: 28 valid + 249,572 invalid states; 0 valid rejected, 0 invalid accepted; 70 oracle tests passed.
- Malformed supervisor/refusal campaign: 237 cases, 0 uncaught exceptions, 0 unexpected accepts.
- Enumeration permutations: deterministic seed `2026111501`, 5,000 permutations; target selection stable; expected refusals 2; no device open.
- Installer identity matrices: parent 36 cases and expanded 42 cases, zero violations; target 12 cases and expanded 18 cases, zero unsafe outcomes. Timings: 11.204 s, 3.915 s, 12.709 s, 5.891 s.
- Package reproducibility: builder commit `13bdcb01104aaec6298f737b861abb3dec09131f` independently produced and verified SHA-256 `e291f2fbcdb45426f5af9bbba14aa61f6445dc3e69871aefa1dc7c4ec61e410e` (124,685 bytes; 31 source files), matching the qualification report.
- Rotating integration campaign expected seeds `[2026111401, 659918, 6229397]`; failed at first case in 0.045 s with exit 1. Log SHA-256 `a16487d2248a3bdc3a9b80c35eba1f7fa50d6da4794701793be5a2754e5d14c4`.
- Compatibility audit exited 2 as expected for blocked release; log SHA-256 `177a38ed05ab2e377751489ef1dd893111ca2b765a3a44b84c3a609609d4f322`.
- Preserved queue state and logs: `/tmp/fk0957-offline-queue-4463/`. Watcher PID 1170327 remained healthy and running; no restart/duplicate.

## Disposition

Installer path-identity behavior passes on this candidate. Software release integration does not pass because the live controller route is still legacy, the manifest omits active integration contracts, the latest handoff is absent, compatibility/profile pins disagree, and the integration campaign false-accepts its legacy-route mutation. Production authorization and privileged installation remain separately blocked. No hardware, production host, privileged installation, signing-key provisioning, or live service was accessed.
