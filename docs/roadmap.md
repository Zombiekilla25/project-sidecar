# Roadmap

## Phase 1 — Stable FK33 runtime

Status: PASS

- V5.3 PearlHash compute qualification
- resident fast reload
- authenticated rollback
- coordinated multi-card pod
- V7 same-generation job renewal
- controlled coordinator-loss recovery
- L02 S05 authenticated persistent-quarantine recovery qualified offline (1,253/1,253 retained tests)

## Phase 2 — PCIe hardware bring-up

Status: READY

- Gen3 x4 XDMA design implemented offline
- routing/timing/DRC complete
- release bitstream packaged
- host tools prepared

Next:
- guarded one-card hardware canary
- enumerate endpoint
- verify build identity
- validate DMA reads/writes
- preserve JTAG/BSCAN recovery path

## Phase 3 — Transport benchmark

Status: NOT STARTED

Measure:
- round-trip latency
- bulk bandwidth
- transfer-size crossover points
- CPU overhead
- pipeline overlap

## Phase 4 — First GPU→FPGA work item

Status: NOT STARTED

Send a real GPU-produced PearlHash intermediate through the FPGA and verify the returned result against the GPU reference.

Initial goal is correctness and measured transport cost, not a speedup claim.

## Phase 5 — Useful offload

Status: EXPERIMENTAL

Evaluate larger work units that can remove dependency-heavy GPU work.

Candidates include:
- transcript/fold work
- compact partial reductions
- hash-side work
- shared invariant/noise setup

## Phase 6 — Eight-card sidecar pod

Status: EXPERIMENTAL

Scale the winning offload across all eight FK33s with coordinated dispatch and work partitioning.

## Phase 7 — Integrated miner

Status: FUTURE

Integrate the sidecar path into a production miner only after:
- deterministic correctness
- positive end-to-end speedup
- recovery testing
- long-duration soak
- pool validation
