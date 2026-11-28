# Project Sidecar

Project Sidecar explores Pearl (PRL) mining software for NVIDIA RTX GPUs and possible FPGA co-processing with SQRL FK33 cards.

## Current status: FP8 miner is experimental

There is no supported public FP8 miner release or downloadable binary. The current internal candidate is inactive; its start gate remains closed. Do not install it over another miner, enable services, change pool/payout settings, or treat local tests as network mining.

The internal work has source-pinned local RTX 3080 computation and receipt evidence. A separate two-RTX-3080 search experiment reported 729.93 attempts/s versus 674.49 for its matched packed-warp control in a bounded benchmark. That search binary is not integrated into the miner runtime. Neither result demonstrates a public pool share, accepted block, sustained end-to-end rate, or profitability.

Four proof threads remain the default in the internal candidate. Two threads are a lower-memory comparison. Eight threads is an opt-in experiment and is not hardware-qualified.

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
