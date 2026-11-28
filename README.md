# Project Sidecar

Project Sidecar explores Pearl (PRL) mining software for NVIDIA RTX GPUs and possible FPGA co-processing with SQRL FK33 cards.

## Current status: FP8 miner is experimental

There is no supported public FP8 miner release or downloadable binary. The current internal candidate is inactive; its start gate remains closed. Do not install it over another miner, enable services, change pool/payout settings, or treat local tests as network mining.

The internal work now has source-pinned local RTX 3080 computation and receipt evidence. A separate GPU-B dual-RTX-3080 candidate passed ABI-v2 CUDA parity on both cards and a local fixture verified 24 certificates (20 local ACKs, four intentional rejects). Its 8x1 local proof fixture measured 0.03772 certificates/s versus 0.03590 for 4x2. A 20-pair sustained legacy-search test measured 816.60 attempts/s at 2,400-attempt shards versus 790.33 at 1,200 (+3.32%; paired 95% interval +24.75 to +27.82; 1.44M attempts per layout). That shard result applies only to the legacy fixture CLI, not the authenticated ABI-v2 worker. These are local results, not public pool acceptance, block acceptance, or profitability.

Four proof threads remain the RC5/R6 default. A separate GPU-B runtime recorded 8x1 local proof fixtures, but its source manifest differs from MIDDLE R1 (11 shared-path hash differences and two unique paths per side). The runtime is not integrated into RC5 or MIDDLE R1; a combined source lock and Gateway/runtime regression are still required before integration.

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

There is no supported installation command yet. Setup tools and service templates in internal candidates are not a public installer. Do not run a miner from a development branch or copy internal executables to another system. A release will be announced here only after public acceptance, rollback, dependency, licensing, and device qualification gates are satisfied.

The project uses placeholder values in examples. Never put real wallets or passwords in URLs, command lines, logs, or GitHub issues.

## FPGA work

FK33 work includes PearlHash arithmetic, candidate computation, and transport prototypes. Routed or simulated results are not a deployable bitstream unless the same complete design has passed timing, CDC, board-interface, silicon-compatibility, and rollback checks. No current report claims fleet deployment.

## More information

- [Current FP8 miner readiness and prerequisites](docs/fp8-miner-readiness-2026-11-27.md)
- [Hardware and OS compatibility](docs/fp8-miner-compatibility-2026-11-27.md)
- [Project progress and blockers](https://github.com/Zombiekilla25/project-sidecar/issues/3)
- [Draft user-documentation PR](https://github.com/Zombiekilla25/project-sidecar/pull/5)

Performance numbers are scoped to their exact benchmark and source revision; they are not a hashrate or profitability promise.
