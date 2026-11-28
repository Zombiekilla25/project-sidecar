# Sidecar FP8 compatibility matrix

| Target | What is known | What remains unqualified |
|---|---|---|
| RTX 3080 | Separate GPU-B runtime passed ABI-v2 CUDA parity on both cards; local fixture verified 24 certificates, 20 local ACKs and four intentional rejects. A 20-pair legacy search screen measured 816.60 attempts/s at 2,400 shards vs 790.33 at 1,200 (+3.32%; paired interval +24.75 to +27.82). | RC5/MIDDLE R1 integration, public shares, and broad device/driver support. |
| RTX 3060 | SM86 code path may be compile-compatible. | Real-device runtime and mining qualification. |
| RTX 3060 Ti | SM86 code path may be compile-compatible. | Real-device runtime and mining qualification. |
| RTX 3070 | SM86 code path may be compile-compatible. | Real-device runtime and mining qualification. |
| RTX 3090 | No release qualification. | Real-device runtime and mining qualification. |
| Ubuntu | Offline metadata and isolated Python checks. | Live install, driver/runtime floor, and rollback. |
| HiveOS | OS label can be recognized. | Installer and supervisor/driver integration. |
| RabidOS | OS label can be recognized. | Installer and supervisor/driver integration. |

A successful compile does not qualify a GPU. The 2,400-shard result applies only to the legacy search CLI. These internal attempts and local receipts are not public shares, public miner hashrate, or profitability. GPU-B's 69be runtime and MIDDLE R1 have different source maps; combined runtime qualification remains open. Public Testnet2 share and canonical block acceptance remain unverified.
