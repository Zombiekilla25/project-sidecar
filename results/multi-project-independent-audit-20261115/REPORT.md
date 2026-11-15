# Project Sidecar multi-project independent audit

Date: 2026-11-15. Scope: local committed source and retained evidence, plus documented pure/offline tests. No production operation, SSH, network-to-hardware, signing, acquisition, guardian, controller live route, transport, USB, or JTAG function was invoked.

## Worker and checkpoint status

- Existing FK0957 hardening watcher PID 1170327 is alive and was preserved. It watches the hardening branch and is not a multi-project test runner.
- The prior static worker PID 3192414 is no longer running; its tmux session has ended. Its state has all 7 tasks completed, the journal records `STOPPED_BY_FLAG`, and a STOP file is present. It was not restarted or duplicated.
- The prior worker stopped at candidate `c56b0edf7ea5087db7b6823580b2b7b613778bc8`; its dynamic tests were blocked because its required `bwrap` network namespace setup was denied. That result is historical, not substituted for current-candidate testing.

## Project 1 — FK0957

- Release/evidence tree: `eb534fff681e23fb24bd821e1d09a21a1b15a1a3`, clean.
- Manifest source identity: `8c8cd5022e799b13eb998795196c6c73b845f94d`.
- Manifest SHA256: `416c96afddce7926a77209720c0a505f5057295ed1cd707b55f4a9f209bcbce6`.
- Source inventory: 31/31 paths present, exact path set and independently recomputed bytes agree with manifest hashes. Native object manifest rows agree with local installed-file bytes; this is not a deployed-host or loaded-object qualification.
- Authorization behavior: unsigned manifest refusal is source-derived and fail-closed. The checked-in trust template has empty release/handoff key pins, and no authenticated production manifest or provisioned production issuer key is present. Production authorization therefore remains unavailable.
- Integration result: FAIL/BLOCKED. Source-derived routing shows the maintenance controller is not integrated with the candidate RGB one-shot CLI/release lifecycle. The RGB one-shot route and internal helpers remain callable from Python without all trust gates at every helper boundary; these routes were inspected statically only and were never executed. The controller also carries a stale production-head/repository binding relative to the manifest source HEAD. The controller, publication-report, supervisor-status, and handoff-preflight contracts are not in the 31-file package manifest, leaving the end-to-end controller path outside that provenance set.
- No FK host tests or dynamic entrypoint tests were run: live-capable test paths lack independently verified isolation, and prior network isolation setup was unavailable. This is a blocker, not a pass.

## Project 2 — PHK1 evidence/attestation

- Candidate: `ee8345ae079a658323dbb3589a14e63fa377db16`, clean.
- Pure offline tests: evidence tests 29/29; target-lock/recovery tests 7/7 (including the suite's 10,000 deterministic cases); fixture-preflight tests 9/9. The preflight selection excluded a test that imports and invokes a live-capable runner. Total selected tests: 45 passed.
- Independent negative-path findings:
  1. `integration/candidate/tools/phk1_raw_bscan/fixture_preflight.py::validate_physical_hello` filters non-dictionary rows from `ir_sequence`; an otherwise valid decoded object with an appended `None` is accepted. The pinned fixture loader rejects altered on-disk bytes by SHA256, but direct validator callers do not get strict row typing.
  2. `tools/phk1_evidence_v2.py` validators can leak ordinary Python exceptions for malformed types (`AttributeError`/`TypeError`) in `validate_attempt`, `validate_events`, `validate_user3`, `validate_input_accounting`, `validate_command`, and `validate_usb_call`. Boolean values are accepted as integers by some counters (`bool` subclasses `int`). A pure mock probe reproduced these conditions; no device functions were called.
  3. `integration/AUTHORITATIVE_SOURCES.json` records upstream `mpsse_backend.cpp` digest `59a9f042…`, while current checked-in source hashes to `5926bc62…`; the isolated instrumented copy has a separate digest. This is a provenance/handoff reconciliation item.
- PHK1 verdict: FAIL for strict malformed-type behavior and source-handoff consistency; physical acquisition claims remain untested.

## Project 3 — PHK2 RTL/model

- RTL candidate: `96f719903646977020570e5d7674bbbd60b39dde`, clean.
- Source manifest SHA256 `6d032f6c6a03cd5a59f4b0eb8f9dfd1542497860e21e94caf7aa8aac11699357`; independently checked source rows: 9/9 match.
- Pure model tests: 13/13 pass (0.001 s reported by unittest; 0.05 s wall).
- Additional deterministic model campaign: seed `985431`; 100 schedulers × 250 operations = 25,000 operations, checking four queue/active/outstanding/association/response-capacity invariants; pass (about 0.2 s).
- Static RTL concern: in `rtl/phk2_batch64_controller.sv`, the `abort` assignment block precedes the independent `start` block. With `abort=1`, `start=1`, and matching generations on the same rising edge, later nonblocking assignments set `active=1` and clear `stale`, so `start` wins. If abort is specified to dominate simultaneous start, this is a correctness defect. The standalone controller is not instantiated in `phk2_core_synth_top` in this tree, limiting current integrated impact. No RTL simulator was run because process isolation for broader candidate tests was not independently established.
- Retained production replay evidence is present (13 capture bundles and the recorded randomized/model campaigns), but it was inspected rather than re-executed. Autonomous work-generation/pool-proof serialization remains explicitly unproven in the evidence.
- PHK2 verdict: model PASS; RTL dynamic verification BLOCKED; simultaneous abort/start requires contract clarification and likely a directed RTL test.

## Project 4 — Quantus feasibility

- Quantus workspace has no Git metadata. `synthesis_and_packing.json` SHA256: `cec0346cefe1c16180b1081d21b55bc096dbe929d038612840e73d62ed4097bf`.
- Retained hashes verified: top-level checksum list 6/6, synthesis artifacts 76/76, deliverables 48/48.
- The study explicitly lacks placed/routed timing, bitstream, device, JTAG/USB, pool, HBM, power/thermal, and host transport validation. Resource counts are OOC synthesis and mathematical packing estimates.
- Recomputed conditional throughput: 94.832 MHz / 214 cycles ≈443.14 kperm/s per core; four cores ≈1.77255 Mperm/s. At two permutations per nonce this projects ≈0.88628 Mnonce/s; three per nonce ≈0.59085 Mnonce/s. These are conditional upper projections, not measured rates or guaranteed lower bounds. The 94.832 MHz planning point is 80% of an unplaced synthesis ceiling, not routed Fmax. Four throughput cores use 295,712 LUT against a 327,744-LUT core budget after the stated front-end reserve, leaving 32,032 LUT; the front end itself is not synthesized.
- Quantus verdict: feasibility evidence internally hashed and arithmetic is consistent; implementation performance/resource claims remain provisional pending placement, routing, full-system integration, and hardware measurements.

## Cross-project quality

- FK0957 evidence tree HEAD `eb534…` is documentation/result-only beyond source HEAD `8c8cd…`; this distinction is explicit in the manifest and handoff. The production trust template remains unprovisioned.
- PHK1 source-history manifest is not synchronized with current upstream MPSSE source bytes, as described above.
- PHK2 manifest is synchronized with the nine listed sources; the Quantus workspace is hash-checked but lacks commit ancestry.
- GitHub issue #3 was reviewed. The audit branch was refreshed from GitHub to `ffc6061dd91200c55ab25f762d8c66817e42de2f`; local audit-only history is five commits ahead. No production branch was changed.

## Test record and verdict

- Current independently executed pure tests: 45 PHK1 tests, 13 PHK2 model tests, and 25,000 additional deterministic PHK2 model operations. PHK1 test runtime was about 2.2 s total; PHK2 tests/campaign about 0.25 s. Static inventory/hash work was performed in this audit session; end-to-end wall duration was not instrumented, so no precise aggregate duration is claimed.
- The prior static worker's seven-task checkpoint is preserved; its 14-minute run is recorded in its state file. It did not continue after its STOP flag.
- Overall software audit: **FAIL/BLOCKED**. Concrete PHK1 malformed-input and manifest-digest issues remain; FK0957 release routing/production authority remains blocked; PHK2 simultaneous abort/start precedence is unresolved; Quantus is analytical/OOC only.
- Deployment/live readiness: **NO**. No production issuer authorization, deployed supervisor verification, RTL hardware validation, or device operation was performed.

Safety: no production host, key, live endpoint, SSH, controller execution, signing, transport, bridge operation, USB/JTAG, FPGA, or service state was accessed or modified.
