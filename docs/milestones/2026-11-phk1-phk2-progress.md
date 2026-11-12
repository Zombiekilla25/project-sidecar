# Project Sidecar milestones — November 2026

This milestone summarizes verified PHK1 and PHK2 progress since the November 3 public update. It is a status record, not a release announcement. Qualification boundaries are stated for each result.

## PHK1 diagnostic control path

### Proven in offline and target-host software checks

- A candidate-aware live-capable diagnostic launcher was built around distinct current, candidate, and rollback image roles.
- The target-host diagnostic runtime was deployed and bound to its launcher. The runtime combines Evidence-v2 capture, split USER3 decoding for the diagnostic candidate, and the qualified bounded RAW_BSCAN transport backend.
- The runner preserves raw status before decoding and reports combined, `rx_overflow_direct`, and `core_error_direct` status where the diagnostic image exposes those fields.
- Target and peer identity gates fail closed, cap candidate programming at one device, and keep peer programming disallowed.
- Mocked rollback and recovery paths cover failures before and after modeled programming. The deterministic no-hardware canary path includes the persistent HELLO-to-Vector session and result checks.

These results qualify software and fixture behavior. They do not establish the live behavior of the candidate on silicon.

### 72-hour reliability campaign

The isolated offline campaign ran for 259,200 seconds and completed:

- 2,815,825,360 modeled PHK1 attempts;
- 72 of 72 deterministic regression checkpoints, each passing 16 runtime and 23 launcher tests;
- zero recorded product defects, safety-invariant violations, evidence losses, manifest errors, provenance errors, peer-program violations, duplicate program/HELLO/Vector violations, or recovery failures;
- zero testbench SSH, USB, JTAG, FPGA programming, pool, and miner-change activity.

The campaign recorded one harness-only defect. A generic mocked program failure was used for a peer-selection refusal, so the harness miscounted a target program attempt while checking for a peer program. The campaign-local mock was corrected to represent a peer refusal with zero operation counts. The failure artifact and unexpected-failure counter were retained; 71 later hourly regressions, including the final checkpoint, passed. No product runtime, RTL, or active testbench source was changed by this correction.

Worker RSS and file-descriptor time series were not retained, so the campaign did not certify long-run leak stability. This instrumentation limit is separate from its passing safety and correctness counts.

### Current PHK1 boundary and blocker

PHK1 physical protocol qualification remains **incomplete**. A previous silicon diagnostic observed a tile-0 error, but the retained combined status did not identify whether `rx_overflow` or `core_error` was the underlying source. Offline replay did not reproduce that error, so no root cause is claimed.

The current live-canary blocker is an identify-phase diagnostic evidence/attestation integration mismatch found by fail-closed preflight. It was detected before FPGA programming. The launcher has continued to block attempts when identity or evidence requirements are incomplete. The next step is to correct and revalidate that integration, followed by a separately authorized one-card diagnostic canary. No successful PearlHash silicon acceleration is claimed.

## PHK2 production evidence and work generation

The PHK2 work recovered retained production capture bundles and established a production-backed CPU golden model. The offline proof covers the captured production 4×5 tile slice and 13 retained capture bundles, with byte-exact operand replay and CPU transcript/digest checks. It also checks 100,000 randomized Philox samples and 100,000 randomized operand positions without mismatch.

The compact production descriptor work established the fields needed to regenerate tested operands: setup seed and both setup-produced noise seeds, plus job identity and a generation fence. A job key and setup seed alone were not established as sufficient arithmetic inputs. The descriptor findings model the retained production setup semantics; they do not claim pool/share submission or live job execution.

## PHK2 offline core RTL qualification

The current PHK2 core report records `PHK2_CORE_RTL_QUALIFIED=true` for its documented scope. Results include exact production operand bytes, 13/13 authoritative capture RTL tile checks, a 1,000/1,000 keyed-BLAKE3 CPU differential, 10,000 full work-generation random checks with zero mismatches, and an end-to-end batch-64 flow over 64 tile coordinates. The verification also exercises abort, reset, backpressure, stale-generation rejection, and held/stale result handling.

This is an offline RTL functional result for the tested 4×8 production tile and batch-64 model. It does not qualify the full 16×16 production region, physical interfaces, CDC, resource fit, routed timing, silicon behavior, or mining performance.

The 72-hour campaign's PHK2 snapshot predates this core qualification. It recorded 3,983,740,000 randomized Philox primitive cases with no mismatch and zero duplicate work, dropped work, stale-result accepts, and deadlocks. It rechecked capture manifests but did not run new authoritative capture replays because its Python BLAKE3 dependency was unavailable. Its evidence applies to earlier Philox, descriptor, batch-control, and tile-adapter sub-blocks, not the later production operand/BLAKE3/full-core additions.

## Initial VU33P synthesis baseline

Vivado synthesis of the initial fully combinational autonomous-work-generation architecture completed for a Virtex UltraScale+ VU33P target. The **initial synthesis baseline** was approximately:

| Resource | Result | Device utilization |
|---|---:|---:|
| LUT | 327,854 | 74.57% |
| DSP | 1,372 | 47.64% |
| Flip-flop | 2,202 | 0.25% |
| BRAM | 0 | 0% |
| URAM | 0 | 0% |

This unoptimized architecture used 26 parallel keyed-BLAKE3 blocks and 12 Philox instances in its production operand generator. The synthesis run did not produce a completed timing report. Its measurement wrapper exposed an unrealistic, over-wide top-level interface, so placement and routing were not run and the numbers do not show physical timing, route quality, or silicon performance.

The resource result motivated a sequential, time-multiplexed keyed-BLAKE3/work-generation design with cached job-scoped factors. This is an architectural direction, not a qualified implementation. The 200 MHz value remains a target basis only.

## PHK2 pre-live first-silicon control path

Since the earlier November PHK2 synthesis milestone, the first-silicon software path has been hardened around a deliberately fail-closed physical-qualification boundary.

### Offline software closure and physical gates

The PHK2 physical-close logic now distinguishes software readiness from physical execution readiness. Offline host, guard, plan, evidence, and deterministic-regeneration tests progressed while physical Case A and Case B remained unqualified. Case A now has an explicit physical measurement contract and owner-decision workflow; Case B has a fail-closed schema/validator and a candidate read-only status-observation method derived from RTL/test evidence. Candidate values remain unapproved and are not treated as physical qualification.

The measurement side also gained deterministic period/jitter metric support for the qualified capture shape. Numeric physical jitter limits, measurement-uncertainty/guardband rules, calibrated instrument requirements, and final physical acceptance remain owner-controlled inputs rather than software defaults.

### Single-target identity and provenance path

A dedicated descriptor-only identity path was built for the first authorized physical canary. Its reviewed backend is intentionally narrower than a general JTAG/MPSSE interface: it performs descriptor identity observation only and does not expose programming, reset, arbitrary IR/DR, or JTAG operations. Target selection and ambiguity checks are designed to fail closed before deeper access, and independent audits added regression coverage for source/hash verification, incomplete metadata, peer-device ambiguity, and path/provenance handling.

Evidence acquisition and signing were separated so the hardware-side process returns unsigned canonical observations while validation and Ed25519 signing remain local to the trusted host. Additional hardening requires pinned SSH host authentication, binds host-key provenance into evidence, treats the remote hostname as self-reported metadata, rejects replay/stale evidence, refuses unsafe signing-key/output paths, and uses atomic evidence output.

### Live preflight and no-checkout execution

The first descriptor-only live preflight authenticated the remote host but correctly stopped before collector or device access because no suitable pinned PHK2 checkout was available remotely. No card was opened and no programming, reset, or JTAG operation occurred.

Rather than make the remote checkout a new trust dependency, a no-checkout ephemeral collector/bundle mode was implemented. The design transmits only the reviewed acquisition payload, binds source/bundle hashes and session provenance before execution, returns unsigned canonical evidence, and preserves local validation/signing. Offline targeted and broad regressions passed aside from the previously documented optional BLAKE3 test-environment limitation. Independent adversarial audit of the ephemeral mode is currently in progress.

This milestone therefore establishes a hardened path toward the first signed descriptor identity observation; it does **not** establish PHK2 JTAG/BSCAN qualification, FPGA programming success, physical timing/jitter qualification, silicon correctness, or acceleration performance.

## Roadmap

1. **PHK1:** resolve the identify-phase evidence/attestation mismatch; then complete the one-card diagnostic silicon test, capture direct error sources, and restore through the qualified rollback path. Keep physical qualification false until the complete correctness criteria pass.
2. **PHK2 pre-live qualification:** complete the independent audit of the no-checkout descriptor-acquisition path, then perform the separately authorized single-card descriptor identity observation. Preserve the boundary between descriptor evidence and deeper JTAG/BSCAN qualification.
3. **PHK2 physical qualification:** finalize owner-approved measurement limits, calibrated capture requirements, and the authoritative read-only BSCAN method before deeper physical testing.
4. **PHK2 implementation:** continue the sequential work-generation architecture and physical design behind a realistic interface; run routing, timing, and design-rule checks before any performance claim.
5. **Qualification and scaling:** consider broader silicon testing or scaling only after measured correctness, timing, recovery, and end-to-end results.

## Evidence boundary

| Label | Meaning in this milestone |
|---|---|
| **Offline qualified** | Software/RTL behavior passed the documented deterministic fixtures and golden-model comparisons. |
| **Synthesized** | Logic synthesis completed and resource counts were reported; no timing or routing conclusion follows. |
| **Not yet silicon qualified** | No claim of correct PHK1/PHK2 operation on physical silicon or of end-to-end acceleration. |

This public summary intentionally excludes private machine identities, lock data, raw traces, capture payloads, local filesystem locations, bitstreams, and private runtime binaries.
