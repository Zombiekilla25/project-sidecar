<p align="center">
  <img src="assets/project-sidecar-logo.png" alt="Project Sidecar" width="512">
</p>

# Project Sidecar

Project Sidecar explores cooperative PearlHash/PRL computation across NVIDIA GPUs and SQRL FK33 accelerators. The 0.3.0-rc1 software release candidate provides the miner and fleet control needed to evaluate that design offline.

## Sidecar miner 0.3.0-rc1

This candidate combines the PRL miner frontend and CPU verifier, supervisor with a one-share canary limit, backend qualification artifacts, offline FK33 fleet orchestration, and first-silicon benchmark/scaling analysis. The full offline suite passes **244/244** tests; the deterministic mock fleet completed **10,000** assignments. No live pool connection was used for this milestone.

Real CUDA and PHK1 physical backends remain unqualified. Live pool access remains disabled. The patched PHK1 candidate passed offline simulation, synthesis, implementation, timing, and DRC checks, but VU33P bitstream generation is blocked because the available Vivado license does not permit `write_bitstream` for that target.

See the [release-candidate source](releases/sidecar-miner-0.3.0-rc1/README.md), [software milestone](docs/run-logs/2026-11-03-sidecar-miner-0.3.0-rc1.md), and [changelog](releases/sidecar-miner-0.3.0-rc1/CHANGELOG.md).

## Architecture and rollout

The miner keeps pool decoding, job scheduling, accelerator backends, CPU result verification, target checks, and share encoding behind defined interfaces. Its fleet controller models **1 → 2 → 4 → 8** FK33 rollout stages with qualification gates, per-card health, quarantine, recovery, and rollback. The benchmark subsystem accepts measured timing artifacts and reports bottlenecks and scaling; synthetic fixtures are labeled as models and do not represent hardware measurements.

## Current qualification status

| Component | Status |
| --- | --- |
| PRL frontend, CPU verifier, scheduler, and share safety gates | Implemented and offline tested |
| Fleet orchestration and benchmark/scaling subsystem | Implemented and mock tested |
| Real CUDA PearlHash backend | Not qualified |
| PHK1 physical RAW_BSCAN backend | Not qualified |
| Live Kryptex mining | Not authorized |

The first hardware milestone remains a separately controlled one-card PHK1 qualification. A successful qualification artifact and measured timing must be imported before the staged fleet rollout can advance.
