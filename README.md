<p align="center">
  <img src="assets/project-sidecar-logo.png" alt="Project Sidecar" width="512">
</p>

# Project Sidecar

GPU + FPGA cooperative compute research for PearlHash/PRL using NVIDIA RTX GPUs and SQRL FK33 accelerators.

## Current status

The PHK1 control design uses a v2 candidate/current/rollback lock architecture for controlled canary work. It binds candidate use to a current-image baseline, keeps a distinct rollback image available, and checks peer identity to protect peer devices from candidate programming. A single-card canary and rollback path is being prepared around these locks.

A PHK1 candidate has been routed at 200 MHz, and the software can generate a patched bitstream candidate. These are experimental FPGA results. First-silicon correctness is still under qualification; no claim of PHK1 physical correctness or production readiness is made.

The bounded RAW_BSCAN transport path is qualified at the software/transport level. Production service restoration to the eight-worker baseline after controlled tests has been completed. See the [PHK1 milestone draft](docs/phk1-public-milestone-draft.md) for the concise status and remaining limits.

## Goal

Project Sidecar tests whether an FK33 pod can accelerate selected PearlHash stages alongside a GPU instead of operating only as independent miners. A sidecar is a win only if end-to-end throughput improves after transfer, synchronization, scheduling, FPGA processing, and return-path overhead are included.

## Qualification state and limitations

Routing, software-generated patched images, transport qualification, and lock/recovery rehearsal do not establish that PHK1 computes correctly on physical silicon. That remains an open qualification gate. Experimental FPGA use remains isolated from production, bounded to a single-card canary, and paired with a rollback path. Public submission and broad deployment are outside the current qualification scope.

The project license has not yet been selected. Do not assume permission to redistribute third-party RTL, vendor IP, bitstreams, or external source code.

## Future work

Complete first-silicon correctness qualification, review the public-safe lock and rollback implementation, and only then consider a separately authorized canary. Measure end-to-end GPU/FPGA performance after correctness is established. See [qualification progress](docs/qualification-progress.md) for the broader project validation record.

## Project logs

GitHub is used for public-safe milestone summaries, not raw machine/runtime evidence. See [logging and evidence policy](docs/logging.md).
