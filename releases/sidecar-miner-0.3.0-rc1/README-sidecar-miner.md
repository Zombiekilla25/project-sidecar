# Project Sidecar miner integration

The integration worktree combines the PRL frontend with the GPU/FK scheduler. `sidecar-miner --dry-run --mode gpu-only|sidecar|auto` runs a complete loopback-only fixture session through job parsing, backend scheduling, official CPU PearlHash verification, target checks, PRL share encoding, and mock Stratum submission. It never connects to a mining pool.

Modes are `gpu-only`, `sidecar` (requires a healthy mock/adapter FK), and `auto` (uses only matched measured GPU/FK end-to-end timing; otherwise it selects GPU-only). `--fk-count` accepts modeled fleet sizes 1, 2, 4, and 8. `--gpu-timing` and `--fk-timing` accept the scheduler timing records and PHK1 canary result format.

Pool, wallet, worker, and GPU selection remain external configuration via `SIDECAR_POOL`, `SIDECAR_WALLET`, `SIDECAR_WORKER`, `SIDECAR_GPU`, and `SIDECAR_MODE`; no real wallet is embedded. Local config filenames are gitignored. `--show-config` redacts pool and wallet values.

Install `requirements.txt` (the CPU verifier uses official `py-pearl-mining`) and run `python3 -m unittest discover -v`. See [integrated architecture](docs/sidecar-miner-integrated-architecture.md), [scheduler architecture](docs/sidecar-scheduler-architecture.md), [source inventory](docs/prl-protocol-source-inventory.md), and [live miner roadmap](docs/live-miner-roadmap.md).

The native RAW_BSCAN adapter source is integrated and compiled behind a qualification gate, but physical PHK1 remains unqualified. CUDA execution and live pool operation also remain unqualified/unauthorized.

Offline supervision and one-share canary simulation are available with `sidecar-miner --dry-run --canary-shares 1`; the status views are `--status` and `--status-json`. The `--live` flag is currently fail-closed and does not connect.

The operator-facing `bin/sidecar-canary` launcher previews by default and writes a public-safe `CANARY_EXECUTION_PLAN.json`. Use `--check` to validate selected qualification artifacts without connecting, or `--dry-run` for a loopback mock canary. Its share-attempt limit is fixed at one. `--live` requires valid artifact identities and explicit config, but this build still blocks before DNS/socket activity.

Import and inspect public-safe backend qualifications with `sidecar-miner qualification import|list|show`; use `sidecar-miner status` for offline backend/configuration status. See [qualification lifecycle](docs/backend-qualification.md). `python tools/package_miner.py` assembles a local RGB-ready release directory without installing services or touching devices.


## Release candidate status

This tree prepares `sidecar-miner 0.3.0-rc1`: supervisor/canary control, explicit qualification artifact handling, offline FK33 fleet orchestration, and first-silicon benchmark/scaling analysis. Real CUDA and PHK1 physical backends remain unqualified and live pool operation remains disabled. The patched PHK1 candidate is offline implementation-qualified, while bitstream generation for the VU33P requires a suitable Vivado device license. See `CHANGELOG.md` and `docs/first-silicon-benchmark.md`.
