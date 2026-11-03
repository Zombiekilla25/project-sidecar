# sidecar-miner scaffold

Offline-first Project Sidecar PRL frontend. The CLI does not connect to a pool. Configure local values with `SIDECAR_POOL`, `SIDECAR_WALLET`, `SIDECAR_WORKER`, `SIDECAR_GPU`, and `SIDECAR_MODE` (`gpu-only` or `sidecar`); unprefixed `POOL`, `WALLET`, `WORKER`, `GPU`, and `MODE` are accepted as fallbacks. `sidecar-miner.local.json`, `.sidecar-miner.json`, `config.local.json`, and `.env` are ignored by Git.

Install `requirements.txt` (the CPU verifier uses official `py-pearl-mining`) and run `python3 -m unittest discover -v` for offline tests. See [architecture](docs/sidecar-miner-architecture.md) and [PRL source inventory](docs/prl-protocol-source-inventory.md). The live Kryptex protobuf envelope has not been qualified; no live pool path is enabled.
