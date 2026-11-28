# Sidecar FP8 compatibility matrix

| Target | What is known | What remains unqualified |
|---|---|---|
| RTX 3080 | A specific source-pinned internal configuration ran a local CUDA-to-peer fixture. | Current public release, public shares, and broad device/driver support. |
| RTX 3060 | SM86 code path may be compile-compatible. | Real-device runtime and mining qualification. |
| RTX 3060 Ti | SM86 code path may be compile-compatible. | Real-device runtime and mining qualification. |
| RTX 3070 | SM86 code path may be compile-compatible. | Real-device runtime and mining qualification. |
| RTX 3090 | No release qualification. | Real-device runtime and mining qualification. |
| Ubuntu | Offline metadata and isolated Python checks. | Live install, driver/runtime floor, and rollback. |
| HiveOS | OS label can be recognized. | Installer and supervisor/driver integration. |
| RabidOS | OS label can be recognized. | Installer and supervisor/driver integration. |

A successful compile does not qualify a GPU. Internal search benchmark attempts are not accepted shares, sustained miner hashrate, or profitability. Public Testnet2 share and canonical block acceptance remain unverified.
