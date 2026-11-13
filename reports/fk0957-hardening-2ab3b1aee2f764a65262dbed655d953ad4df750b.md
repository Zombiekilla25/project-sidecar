# FK0957 independent audit: `2ab3b1aee2f764a65262dbed655d953ad4df750b`

## Candidate and scope

The refreshed hardening remote resolves to `2ab3b1aee2f764a65262dbed655d953ad4df750b`, parent `57ff20b93a93b186c7b3dc7467772f663c587cd4`, subject `Separate FK0957 cleanup failures from exit proof`. The watcher had already created a clean detached worktree at this exact commit. Changes are limited to cleanup protocol, receipt helper, related tests, and handoff documentation. No hardware, testbench SSH, USB, or JTAG was accessed.

## Cleanup retest

- `/proc` inspection failure for a live PID now reports `STATUS_INSPECTION_FAILED`; `restore_allowed()` is false. The helper distinguishes `ENOENT` from other inspection errors and checks the process directory before treating absence as proof.
- SSH return code 255 with otherwise valid status bytes classifies as `TRANSPORT_FAILED`; restoration is false.
- A PID start-identity mismatch reports `PROCESS_IDENTITY_MISMATCH`; restoration is false.
- Malformed state inputs no longer escape from the transition/restore helpers as `TypeError`.
- The cleanup protocol and receipt-store unittest modules pass: 24 tests.
- The watcher’s independent state oracle reports 28 valid and 249,572 invalid states with zero mismatches. Its broad acceptance, campaign, native-runtime, and diff-check suites exited 0.

These are real improvements to process/status classification.

## Remaining receipt and supervisor defects

Independent fixture attacks still reproduce:

1. **Terminal receipt replacement race:** replacement immediately before `os.replace` is not detected; the writer overwrites the competing terminal record and returns success.
2. **Operation-directory replacement:** replacing the operation directory during the transition causes the held-FD write to finish in the displaced directory, while a later path-based read sees an attacker-created terminal refusal receipt with a different authorization hash.
3. **Same-UID terminal forgery:** writing a canonical `EXITED_SUCCESS` receipt into the caller-owned mode-0700 directory, naming an absent PID, and setting caller-controlled `launch_closed=True` yields `CONFIRMED_EXITED_SUCCESS`; the RGB classifier accepts it and `restore_allowed()` returns true.
4. **Caller-supplied launch closure:** a fresh PREPARED receipt plus `launch_closed=True` yields `CONFIRMED_NOT_STARTED` and is restorable. The boolean is not authenticated by a protected supervisor in this implementation.

The `/proc` false-exit defect from 57ff is fixed for inspection failure, but false confirmed exit remains possible through forged local receipt/closure assertions. The helper is not wired to a trusted supervisor or integrated into the endpoint/RGB cleanup route, so the required trust boundary is still absent.

The independent cleanup campaign ran 50,000 deterministic malformed/stale/replay cases (seed `0x09572026`), 231 receipt type cases, 165 status field type cases, and 231 nested receipt cases. It found zero malformed cases becoming restorable, while the explicit receipt-writer attacks above remained reproducible.

## Other acceptance findings

The watcher’s independent acceptance run still finds:

- Startup injection: sentinels execute through `PYTHONPATH`, `sitecustomize`, `usercustomize`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, PATH substitution, and the documented venv executable route; direct bootstrap accepts a forged launcher marker in a self-test.
- Release/handoff authority: production issuer pin remains unprovisioned; wrong signed bridge hash, clients, and lanes are accepted as assertions; immutable release authorization and bridge handoff gates are absent from the live CLI/transport path.
- Provenance: the release manifest lists 12 sources, but the independent one-byte tamper fixture shows multiple runtime-relevant files do not affect the runtime hash; the transport hash covers only a subset.
- Signing separation: remote private-key transmission and remote signing code are absent, but startup bypass and local synthetic signer reachability findings remain open from earlier acceptance results.
- Native runtime pins match the installed candidate environment.

Transaction constants remain unchanged: Scan A 591, Scan B 586, total 1177. The watcher’s transaction-invariant check passes.

## Verdict

`2ab3b1a` closes the specific `/proc` inspection-error and SSH-255 classification defects. It does **not** close the receipt race or supervisor trust boundary. The candidate is not a complete hardening candidate and is not ready for a live topology read.

Audit artifacts: `results/candidate-2ab3b1aee2f764a65262dbed655d953ad4df750b/cleanup-adversarial.json` plus watcher-generated per-SHA outputs. Production files were not modified.
