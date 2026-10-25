# Architecture

## Objective

Project Sidecar explores a cooperative GPU+FPGA PearlHash pipeline where one or more FK33 cards accelerate selected work from an NVIDIA GPU.

## Current compute path

The current PearlHash structure is:

1. Generate noised integer matrices A and B.
2. Process K in noise-rank tiles.
3. Accumulate int32 GEMM output.
4. Fold cumulative tile state into a 16-word transcript.
5. Compute keyed BLAKE3 over the transcript.
6. Compare the digest against the target.

The GPU Redux work showed that transcript-fold dependency cost matters: replacing the earlier shuffle-heavy reduction path produced a meaningful GPU speedup.

## Sidecar transport

Initial FPGA transport target:

- SQRL FK33 / Xilinx VU33P
- PCIe Gen3 x4
- Xilinx XDMA
- BRAM/FIFO staging for the first hardware version
- no HBM dependency in the first sidecar experiment
- BSCAN/JTAG retained independently for recovery and diagnostics

The PCIe frontend is intended to feed the existing resident V5.3 loader/bank/compute boundary rather than replacing the qualified PRL core.

## Candidate experiments

### A. Transport-only benchmark

Measure:
- host-to-FPGA DMA latency
- FPGA-to-host return latency
- sustained throughput
- small-message overhead
- pinned-buffer behavior

### B. Transcript offload

Send GPU-produced transcript data to FK33 for downstream processing. This is primarily a pipeline validation experiment and may not improve performance by itself.

### C. Partial-reduction offload

Move a larger dependency-heavy reduction stage to the FPGA so the GPU removes real serialized work instead of merely relocating BLAKE3.

### D. Eight-FK pod

Partition sidecar work across the eight-card FK pod and compare:
- one card
- paired cards
- full pod

## Success criterion

A kernel microbenchmark is not sufficient.

Project Sidecar counts as successful only when measured end-to-end GPU throughput improves after including PCIe transfer, buffering, synchronization, FPGA processing, and result return.
