<p align="center">
  <img src="assets/project-sidecar-logo.png" alt="Project Sidecar" width="512">
</p>

# Project Sidecar

GPU + FPGA cooperative compute research for PearlHash/PRL using NVIDIA RTX GPUs and SQRL FK33 accelerators.

## Current status — November 2026

Project Sidecar is testing whether an FK33 pod can accelerate selected PearlHash stages alongside a GPU. The project evaluates end-to-end work, including transfer, synchronization, scheduling, FPGA processing, and host verification.

### PHK1 diagnostic path

The PHK1 work now has a candidate-aware diagnostic launcher, a versioned evidence capture flow, split USER3 error reporting, and a bounded RAW_BSCAN transport backend. Target/peer checks fail closed, and the control path has modeled rollback and recovery behavior. The candidate runtime has passed target-host no-hardware fixtures and deployment-binding checks.

The 72-hour offline reliability campaign completed 2,815,825,360 modeled attempts and 72 of 72 deterministic regression checkpoints passed. It found no product defects or safety-invariant violations. One mock-harness defect was corrected during the campaign; its failure record was retained, and subsequent regressions passed. No hardware activity occurred during the campaign.

PHK1 physical protocol qualification is **not complete**. A prior silicon diagnostic observed a tile-0 error whose internal source remains unresolved. The latest fail-closed preflight also found an identify-phase diagnostic evidence/attestation integration mismatch before FPGA programming. The launcher continues to block attempts when identity or evidence prerequisites are incomplete. No correct PearlHash silicon result or acceleration claim is made.

### PHK2 autonomous work generation

Retained production captures were recovered and replayed against a production-backed CPU oracle. Production operand generation and the PHK2 core now have offline RTL qualification, including exact production operands, CPU/RTL differential checks, batch-64 exactness, and abort, reset, backpressure, and stale-generation tests. This establishes functional equivalence within the tested profiles and fixtures; it does not establish physical implementation or mining performance.

### PHK2 synthesis findings

An **initial synthesis baseline** for the first fully combinational work-generation design completed for the VU33P family. It used approximately 327,854 LUTs (74.57%), 1,372 DSPs (47.64%), 2,202 flip-flops, and no BRAM or URAM. This is a resource measurement for an unoptimized architecture, not a routed design. Timing analysis did not complete, and the measurement wrapper was unsuitable for placement and routing. The result motivated a sequential, time-multiplexed keyed-BLAKE3/work-generation architecture.

### PHK2 pre-live physical-qualification hardening

The PHK2 first-silicon control path has advanced from general offline closure into a fail-closed pre-live qualification flow. The current software separates offline qualification from physical evidence, requires explicit owner-approved physical limits and methods, and keeps unqualified physical cases blocked.

A single-target descriptor identity path was added for the first physical canary. It is designed to refuse ambiguous or peer-device access, exposes no programming/reset/JTAG capability in the descriptor-only backend, and keeps evidence signing local to the trusted host. Remote acquisition was split from local validation/signing so private signing material is never required on the hardware host. SSH host authentication, source/hash pinning, replay protection, symlink/hardlink refusal, and atomic evidence output have been independently exercised in offline tests.

The first live descriptor attempt correctly stopped before device access when the remote environment did not contain the expected checkout. A no-checkout ephemeral collector/bundle mode has since been implemented so the reviewed acquisition payload can be transmitted and executed without trusting a remote repository. Independent adversarial audit of that new mode is in progress. No PHK2 JTAG, BSCAN qualification, FPGA programming, reset, or silicon-performance claim follows from this work.

### Next steps

1. Complete the independent audit of the PHK2 no-checkout ephemeral descriptor-acquisition path, then perform the separately authorized single-card descriptor-only identity observation.
2. Finish owner approval of PHK2 physical measurement limits/methods and the authoritative read-only BSCAN observation contract before any deeper physical qualification.
3. Continue the resource-efficient sequential PHK2 work-generator path and physical-design work behind a realistic interface before making any silicon-performance or scaling claim.
4. Resolve the remaining PHK1 identify-phase evidence/attestation preflight mismatch before its separately authorized one-card diagnostic canary.

## Qualification boundaries

The evidence types above are distinct: software and RTL results are offline-qualified; the PHK2 resource figures are synthesis-only; neither establishes silicon correctness, timing, or end-to-end speedup. PHK1 physical qualification remains open. PHK2 routing and silicon qualification have not been demonstrated.

The project license has not yet been selected. Do not assume permission to redistribute third-party RTL, vendor IP, bitstreams, or external source code.

## Project logs

GitHub contains public-safe milestone summaries, not raw machine/runtime evidence. See [logging and evidence policy](docs/logging.md) and the [November 2026 PHK1/PHK2 milestone](docs/milestones/2026-11-phk1-phk2-progress.md).
