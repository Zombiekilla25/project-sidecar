# Project Sidecar

Project Sidecar explores Pearl (PRL) mining software for NVIDIA RTX GPUs and possible FPGA co-processing with SQRL FK33 cards.

## Current status: FP8 miner is experimental

There is no supported public FP8 miner release or downloadable binary. The current internal candidate is inactive; its start gate remains closed. Do not install it over another miner, enable services, change pool/payout settings, or treat local tests as network mining.

The internal work now has source-pinned local RTX 3080 computation and receipt evidence. A separate GPU-B dual-RTX-3080 candidate passed ABI-v2 CUDA parity on both cards and a local fixture verified 24 certificates (20 local ACKs, four intentional rejects). Its 8x1 local proof fixture measured 0.03772 certificates/s versus 0.03590 for 4x2. A 20-pair sustained legacy-search test measured 816.60 attempts/s at 2,400-attempt shards versus 790.33 at 1,200 (+3.32%; paired 95% interval +24.75 to +27.82; 1.44M attempts per layout). That shard result applies only to the legacy fixture CLI, not the authenticated ABI-v2 worker. These are local results, not public pool acceptance, block acceptance, or profitability.

Four proof threads remain the RC6 internal default and rollback control. Two threads is comparative; eight threads is explicit and unqualified in that package. Proof threads are separate from search settings: ABI-v2 remains at four search threads per GPU and 32-attempt authenticated leases. The 2,400-attempt result is only for the legacy fixture CLI. A separate GPU-B runtime recorded 8x1 local proof fixtures, but it is not the RC6/MIDDLE R1 packaged runtime. The newest MIDDLE R1 admission manifest (`c8e832db…`) passes source and dual-device admission preflight, but integrated CUDA-to-peer testing remains pending. Its nested runtime still differs from the GPU-B runtime in the supervisor and scheduler (48 common files, two differing files, plus a MIDDLE-only CPU policy file). The common ABI-v2 worker hash does not qualify the surrounding runtime. Keep the existing rollback until an exact combined source pin and Gateway/R1 receipt-recovery regression pass.

## Supported hardware and operating systems

“Compile-compatible” and “hardware-qualified” are different claims.

| Target | Current status |
|---|---|
| RTX 3080 | Exact internal local-test configuration evidence; public mining is not qualified. |
| RTX 3060 / 3060 Ti / 3070 / 3090 | Not runtime-qualified. |
| Ubuntu | Offline development checks only; no supported live installation. |
| HiveOS / RabidOS | Unverified. |

The minimum NVIDIA driver and full deployment matrix are still being established. The internal worker requires a host-provided CUDA runtime; no driver or CUDA library is bundled.

## Installation

There is no supported installation command yet. Internal RC6 adds a read-only OS/GPU doctor and clearer setup/profile previews, but these tools and service templates are not a public installer. Device detection reads `nvidia-smi` metadata only and does not qualify a GPU. Do not run a miner from a development branch or copy internal executables to another system. A release will be announced here only after public acceptance, rollback, dependency, licensing, and device qualification gates are satisfied.

The project uses placeholder values in examples. Never put real wallets or passwords in URLs, command lines, logs, or GitHub issues.

## FPGA work

FK33 work includes PearlHash arithmetic, candidate computation, and transport prototypes. Routed or simulated results are not a deployable bitstream unless the same complete design has passed timing, CDC, board-interface, silicon-compatibility, and rollback checks. No current report claims fleet deployment.

## More information

- [Current FP8 miner readiness and prerequisites](docs/fp8-miner-readiness-2026-11-27.md)
- [Hardware and OS compatibility](docs/fp8-miner-compatibility-2026-11-27.md)
- [Project progress and blockers](https://github.com/Zombiekilla25/project-sidecar/issues/3)
- [Draft user-documentation PR](https://github.com/Zombiekilla25/project-sidecar/pull/5)

Performance numbers are scoped to their exact benchmark and source revision; they are not a hashrate or profitability promise.
