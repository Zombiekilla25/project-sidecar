# FK0957 independent hardening audit: f84dc8d

Audit mode: offline source/test review only. No testbench SSH, USB, JTAG, or hardware access. Production was not modified.

## Candidate and watcher

- Audited hardening commit: `f84dc8dafb94e634f20644475e3e1def410d62b7`
- Parent: `2364e9b55c5ef289937894b77eb6990352fdda83`
- Subject: `Enforce one transport use per FK0957 authorization`
- `origin/hardening/fk0957-production-20261113` and the hardening checkout HEAD both resolved to f84 at audit time.
- The configured watcher process remained running and tracked that remote/branch with two stable polls.
- No `COMPLETE_HARDENED_CANDIDATE` declaration was present for f84.

## Permit identity and ordering

The new endpoint/transport flow preserves one authorization identity across request validation, permit creation, transport authorization, the internally sealed transport result, and the unsigned result record. The transport gate revalidates the signed request and binds descriptor SHA, nonce, and authorization ID before attaching the permit. It checks the permit against the original active token, rejects an already attached/consumed token or authorization ID, and the endpoint passes that same permit into transport and result validation.

The independent fake-transport reconstruction attack reached the endpoint's simulated acquisition path and confirmed the result's authorization ID, operation ID, descriptor evidence SHA, and permit nonce all equal the validated request. A request/permit nonce or authorization-ID mismatch refused before backend reach. A second permit token for the same authorization, replay, and parallel duplicate invocation were refused or constrained to one backend execution.

Focused tests passed: 49 transport, endpoint, and supervisor-package tests. The independent corrected oracle passed all 28 valid and 249,572 invalid states with zero mismatches; its report also covered 1,015 additional adversarial cases. The independently recomputed transaction hashes remained Scan A `81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2` (591 TCK), Scan B `08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a` (586 TCK), total 1,177.

## Receipt and cleanup

Legacy caller-writable receipt probes remained non-authoritative: fabricated success with absent PID, stale response, wrong-operation replay, caller `launch_closed`, and direct terminal transition did not establish success or restore eligibility. The independent receipt result remains PASS.

## Remaining deployment and trust blockers

- **Release authority: not established.** The endpoint has `TRUST_CONFIG_SHA256 = ""`; it refuses when issuer pins are absent. The supervisor-provided issuer handoff is protected in the code path, but this does not establish a deployed trusted issuer configuration.
- **Handoff authority: not established operationally.** Endpoint tests exercise signed handoff validation, but the root supervisor/package is not installed in the audited environment.
- **Supervisor deployment boundary: open.** `install_fk0957_supervisor.py --verify` failed because the expected `/usr/local`, `/etc`, `/run`, and `/var/lib` package/state artifacts are missing. Source code alone is not proof that ordinary users cannot alter authoritative state.
- **Startup trust: open.** Independent harmless-fixture campaign reproduced PYTHONPATH/ctypes and sitecustomize injection, plus an LD_PRELOAD constructor before trusted bootstrap.
- **Complete provenance: open.** The campaign reports `transport_hash_omits_cli_source=true`; source/provenance closure is incomplete.
- **Acceptance harness limitation:** the broad independent acceptance harness exited 1 because its older bridge fixture directly calls the endpoint without the newly required root-supervisor kernel capability. This is an audit-fixture incompatibility, not a passing bridge-authorization test.

The candidate campaign also passed malformed-input tests (10,000 generated cases; zero validator exceptions/unsafe fallbacks), enumeration permutation tests (120 unique target orders selected and 120 duplicate target orders refused), and evidence path/publish race checks. Those results do not close the startup, deployed authority, or full provenance blockers above.

## Assessment

- Permit identity continuity: **PASS for the exercised simulated endpoint/transport path**.
- Mismatch reaches transport/backend: **NO in focused tests**.
- Duplicate consumption/replay: **NO in focused tests**.
- Legacy receipt authority: **PASS**.
- Trusted release authority: **NO; trust pin is empty and deployment absent**.
- Trusted handoff authority: **NO operational proof; supervisor package absent**.
- Full provenance: **NO**.
- Startup trust: **NO**.
- Supervisor package trust boundary: **NO; required installed artifacts absent**.
- Scoreboard remains **3/8**; this commit closes the exercised permit continuity defect but does not warrant increasing the overall closed-class count while the trust/deployment boundary remains unprovisioned.
- No live or physical operation was attempted.
