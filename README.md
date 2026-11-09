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

### Next steps

1. Resolve the PHK1 identify-phase evidence/attestation preflight mismatch, then separately authorize and run the one-card diagnostic silicon canary.
2. Develop and verify the resource-efficient sequential PHK2 work generator against the CPU golden model.
3. Synthesize PHK2 behind a realistic interface, then measure routing and timing before any silicon qualification or scaling decision.

## Qualification boundaries

The evidence types above are distinct: software and RTL results are offline-qualified; the PHK2 resource figures are synthesis-only; neither establishes silicon correctness, timing, or end-to-end speedup. PHK1 physical qualification remains open. PHK2 routing and silicon qualification have not been demonstrated.

The project license has not yet been selected. Do not assume permission to redistribute third-party RTL, vendor IP, bitstreams, or external source code.

## Project logs

GitHub contains public-safe milestone summaries, not raw machine/runtime evidence. See [logging and evidence policy](docs/logging.md) and the [November 2026 PHK1/PHK2 milestone](docs/milestones/2026-11-phk1-phk2-progress.md).
