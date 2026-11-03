# sidecar-miner scaffold

Offline-first Project Sidecar pool frontend. Run `./sidecar-miner --show-config` to inspect non-secret settings, or `python -m sidecar_miner.cli`. No live connection is enabled. Set local configuration with `SIDECAR_POOL`, `SIDECAR_WALLET`, `SIDECAR_WORKER`, and `SIDECAR_MODE` (`gpu-only` or `sidecar`). See [architecture](docs/sidecar-miner-architecture.md).

Run offline tests from this directory with `python -m pytest -q`.
