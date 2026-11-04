# Integrated Project Sidecar miner architecture

This worktree combines the PRL-aware frontend with the timing scheduler. The PRL frontend, scheduler, and CPU verifier are implemented offline; the CUDA adapter is runtime-test-ready but no GPU ran during this FK integration. PHK1 host framing and Vector001 logic are integrated behind `RawBscanFk33Backend` with a mock transport. Physical RAW_BSCAN is unqualified and live FK initialization fails closed. Dry-run Stratum binds only to loopback.

```text
PRL / Kryptex
      |
 sidecar-miner (Stratum transport)
      |
  Job Manager (canonical fingerprint + generation)
      |
    Scheduler <--- matched GPU timing + PHK1 result timing
      |                         |
     RTX                       FK33 fleet (1 / 2 / 4 / 8 modeled)
      \                         /
        raw/canonical result gates
                  |
       CPU PearlHash verification
                  |
      target + current-generation gates
                  |
         PRL share encoder
                  |
          Stratum submit
```

## Modes

- **`gpu-only`**: GPU backend runs; FK is never dispatched.
- **`sidecar`**: operator-selected mode requires at least one healthy FK backend. If an FK execution fails or returns a bad/stale result, that backend is marked unhealthy and the complete GPU candidate is used as fallback.
- **`auto`**: the scheduler requires measured GPU and FK end-to-end records with matching job fingerprint and batch size. It selects Sidecar only if FK end-to-end time is lower. Missing, synthetic, mismatched, or unhealthy inputs select GPU-only.

The FK backend currently accepts only the fixed `operand-vector-001` PHK1 protocol diagnostic. Its result validates protocol frames and frozen raw/canonical fixture identities; it is not the PRL mining candidate. The offline FK fixture E2E gates the independently generated PRL candidate through the existing CPU verifier and share encoder. No arbitrary candidate-to-PHK1 work mapping is claimed.

Run a complete local fixture session with `sidecar-miner --dry-run --mode gpu-only`, `--mode sidecar`, or `--mode auto`. `--pool`, `--wallet`, and `--worker` are config inputs for later use; the CLI never opens those endpoints. `--gpu-timing gpu.json --fk-timing FIFTH_PHK1_CANARY_RESULT.json` loads measured timing in auto mode.

## Batch execution and safety

`StratumClient` validates `mining.notify` into a canonical `MiningJob`. Its job listener advances scheduler generation and clears queued and active batches on replacement. A GPU result must match that job/generation/batch. Sidecar batches are assigned to high-level FK backend IDs according to the scheduler policy; no physical adapter identity is exposed. FK raw/canonical identity, expected batch/backend identity, health, and job generation must pass before the CPU PearlHash verifier runs. The sealed `Verification` then gates target eligibility and the PRL share encoder. `StratumClient.submit` checks the latest job identity again.

The bounded GPU→FK and FK→verification queues reject excess enqueue work. Timeout, disconnect, wrong result, slow response, or stale result marks the FK unhealthy and falls back to the associated GPU candidate. If no FK remains, auto mode chooses GPU-only. The modeled fleet supports 1, 2, 4, and 8 FKs; physical parallelism is not claimed.

## Telemetry and timing

The shared telemetry includes pool state, job generation, selected mode/decision, GPU/FK batches, accepted/rejected/stale shares and results, GPU and FK elapsed time, transfer and FPGA compute when provided, verification time, end-to-end time, fallback count, and backend health. Unknown FPGA compute remains null. Scheduler stage accounting is documented separately in `sidecar-scheduler-architecture.md` and accepts the canary result schema without code edits to its parser.

The actual CUDA backend and physical PHK1 protocol are not qualified; live Stratum remains disabled in this build. The native RAW_BSCAN binding is integrated behind a lazy, qualification-gated boundary. `--dry-run` uses CPU-generated proofs and mock GPU/transport paths with the official CPU verifier; it validates software wiring, not accelerator performance.

# Qualification and release status

The public-safe versioned PHK1 and CUDA artifact schemas are consumed through one loader and an explicit local qualification store. Use `sidecar-miner qualification import`, `list`, and `show`, plus `sidecar-miner status`. The store accepts only explicitly imported files and binds PHK1 to current runner/backend source hashes and the configured bitstream.

Live mode rejects offline fixture adapters. GPU and FK qualification must match runtime identity; auto mode also requires matched measured timing and the GPU fallback. The guarded canary still has a fixed maximum of one submitted share. Both real backend qualification states remain false, and the current canary launcher blocks before network activity.

The operator configuration template is `sidecar-miner.kryptex.example.json`. Run `python tools/package_miner.py` to make a local deployment directory and a manifest containing the source revision. Packaging performs no device or network activity.

## Offline FK33 fleet controller

The `sidecar_miner.fleet` lifecycle model now supports up to eight logical FK33
resources with gated `CANARY_1 → EXPAND_2 → EXPAND_4 → FULL_8` progression.
It uses the shared qualification loader, per-card image/rollback identity,
bounded queue and deterministic distribution policies, raw/canonical plus CPU
result verification, quarantine/rejoin, and fail-closed state restoration.
`sidecar-miner fleet status|plan|rollout --dry-run|watch` operate on the fleet
model only. See [fleet orchestration](fleet-orchestration.md). Mock fleet tests
do not claim physical timing or multi-card hardware qualification.

## FK33 native binding status (2026-11-02)

- PRL frontend, scheduler, and CPU verifier: implemented offline.
- CUDA adapter: runtime-test-ready; no GPU execution in this FK binding work.
- Native RAW_BSCAN ABI and `LiveRawBscanTransport`: source integrated and mock-boundary tested; native binary build pending development headers.
- PHK1 physical protocol: pending separate qualification; the qualification gate defaults false and has no production bypass.
- Kryptex live mining: not authorized.
# CUDA integration status (2026-11-02)

The qualified upstream CUDA PearlHash implementation has been inventoried in
[cuda-pearlhash-source-inventory.md](cuda-pearlhash-source-inventory.md). It is
now has a lazy, disabled-by-default low-level adapter behind the Sidecar backend
module, but it is not a qualified share-producing `GpuBackend`: the upstream execution API creates
miner-selected matrices, commitments and noise before scanning tile digests, then
constructs a proof for a winning tile. Its low-level C API also targets logical
CUDA device 0. `--gpu-id` / `SIDECAR_GPU_ID` are now accepted as explicit config,
but the mock backend remains active until a bounded CUDA worker API can honor
device selection safely. No GPU vector test was run because available cards were
busy. See [CUDA backend details](cuda-backend.md).
