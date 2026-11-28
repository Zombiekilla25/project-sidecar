# FP8 miner readiness and installation prerequisites

**No supported public installation is available.** Sidecar's current FP8 packages are internal engineering candidates. Their pool start gate is disabled; no binary is published by this documentation PR.

## What has been tested

The pinned internal R6 runtime has source-locked local RTX 3080 CUDA-to-peer evidence. That does not establish public Testnet2 acceptance. A separate GPU-B rank-32 noise-LUT search comparison measured 729.93 attempts/s against 674.49 attempts/s for a matched dual packed-warp control in a bounded run. The optimized search binary has not been integrated into the release runtime; it is not a certificate rate or pool hashrate.

The internal balanced proof profile uses four threads and remains the rollback control. Two threads is a low-memory comparison. Eight threads requires explicit opt-in and remains unqualified; the entrypoint smoke had no jobs and zero CUDA attempts.

## Requirements known so far

- Linux x86-64 has offline development tests; supported live distro installation is not qualified.
- Internal validation uses Python 3.12.3 and the pinned direct Python dependencies listed in the release engineering source.
- The native search worker dynamically requires `libcudart.so.12`, `libstdc++.so.6`, `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, and `ld-linux-x86-64.so.2`. These host libraries are not bundled.
- A minimum supported NVIDIA driver version has not been established.
- RTX 3060/3060 Ti/3070/3090 runtime qualification remains incomplete.
- HiveOS and RabidOS service, filesystem, driver, update, and rollback behavior is unverified.

These are development observations, not a host compatibility promise. Do not copy CUDA libraries from another miner or change drivers to run an internal candidate.

## Safe user guidance

Wait for a release announcement before installing or connecting to a pool. Never overwrite another miner's files, launch a service from this branch, put wallet/password data in URLs or command lines, or change payout settings based on a local test.

The internal setup wizard previews private configuration and has no public support contract. Its device list is metadata only; it does not create a CUDA context. Local peer receipts and RegressionNet successes are not public shares.

## Release gates

Public pool acceptance; source-matched runtime integration; per-device hardware qualification; reproducible build and dependency lock; complete notices; written native-binary redistribution rights; supported install/rollback on target operating systems.
