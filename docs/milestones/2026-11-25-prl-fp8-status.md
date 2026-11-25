# Project Sidecar — PRL FP8 (V4) engineering milestone

**Report date:** 2026-11-25  
**Status:** Experimental GPU/FPGA research; **not** a production mining release.

This public-safe milestone summarizes the November 24–25 workstream reports. The numeric benchmarks below originate from local bounded experiments reported by the five engineering terminals. The current public repository does **not** contain the complete referenced private runtime evidence or all executable handoff artifacts. No public Testnet2 success or FPGA mining result is claimed.

## Priorities

1. Preserve/extend useful Pearl mining on NVIDIA RTX 30-series GPUs through the proposed FP8/V4 change.
2. Achieve a **measured end-to-end** GPU performance benefit from SQRL FK33 VU33P co-processing, if transport and arithmetic permit.
3. Consider standalone FK33 mining only after those priorities.

## GPU-A — mining job/consensus integration

- Authentic Testnet2 job acquisition and source-locked job/result/cancellation ABI were exercised in bounded offline tests.
- Versioned adapter tests passed (reported 16/16) with source checksums and stale-job controls.
- An RTX 3080-generated, H100-profile V4 candidate **previously passed unchanged local full-block validation** at an intentionally easy local-only target, including negative controls. **This is not public Testnet2 acceptance.**
- The latest isolated GPU-A integration reproduced a GPU candidate through unchanged **local proof verification**, while the full **v1.3 GPU-search → certificate → local block** qualification remains incomplete. A fresh source-matched local chain template and a safe exclusive RTX 3080 test window are still needed.
- A recovered real Testnet2 job expired; bounded handling/cancellation tests did not search or submit public work.

## GPU-B — real RTX 3080 CUDA FP8 search

- **B200-profile v1.3.0:** five matched 200-candidate runs measured **182.95 candidate attempts/s GPU** versus **132.61 attempts/s matched CPU**, a **37.96%** median gain in the reported campaign.
- The older **H100-profile** fused lookup-table experiment reported **288.70 candidate attempts/s** in a **different benchmark and profile**. These rates are **not directly comparable**.
- Source-locked job-bound executable, canonical input/output ABI, cancellation/stale-work checks, reference fixtures, and negative/error tests are included in the local handoff.
- GPU/CPU candidate/proof comparisons passed unchanged local verifier checks in bounded tests; no public network acceptance or complete deployed miner throughput has been established.
- The selected RTX 3080 was returned to its existing miner, with pool connection, positive hashrate and an accepted ordinary mining share reported after testing. This is **not** proof of V4 acceptance.

## MIDDLE — independent CPU and policy optimization

- Source-locked jackpot-policy and pipeline optimization patches and independent regression evidence were preserved.
- Reported CPU candidate search/target-check gains are **not** verified as gains in the fully integrated CUDA miner, GPU proof throughput, or accepted network work.
- Merged qualification is pending matching executable/source manifests and resource-isolated before/after benchmarks.

## LEFT — RTX 30-series miner packaging

- Offline package **v1.2.0** was staged and archived; **21 offline checks** were reported passed, including packaging, dry-run staging and rollback paths.
- Reproducible SM86 build/package tests exist, but source rebuild reproducibility does not imply byte-identical host ELF builds.
- RTX 3060/3060 Ti/3070/3080 CUDA capability compatibility is **not** equivalent to per-device runtime qualification.
- No CUDA miner/pool workload or real deployment test was performed during the package qualification.
- Third-party transitive licensing review, individual GPU/VRAM testing, active gateway worker, and Octominer management access remain incomplete. Service templates remain disabled.

## RIGHT — FK33 high-bandwidth readiness

- Offline PCIe/XDMA identity, capture-validation, integrity and performance-harness tests reported **18/18 PASS**, with a checksum-verified source/image inventory.
- An archived XDMA implementation is **not** evidence that a physically usable V4-compatible DMA endpoint is present; no matching endpoint was established on the inspected host, which may not host the relevant card.
- BSCAN was previously ruled out for the large-transfer offload tested. No measured FK33 V4 physical throughput, DMA, new RTL qualification or FPGA bitstream deployment.
- A separate authorized FK0957 single-card test is gated on host/card identity, image provenance and reuse rights, nonproduction isolation, recovery planning, and **read-only enumeration before any state-changing DMA/programming**.

## What is proven, and what is not

**Demonstrated:** real RTX 3080 FP8-emulation arithmetic; local proof checks; previous local full-block acceptance of an SM86-produced H100-profile candidate; bounded B200-profile search speedup; source-locked offline integration/packaging/regression evidence.

**Not demonstrated:** deployed public Testnet2 accepting an RTX 30-series-produced V4 block/share; full newest v1.3 GPU-to-block validation in one run; competitive steady-state network mining profitability; qualification of every RTX 30-series model; profitable FK33 GPU acceleration; any production-ready miner or developer-fee product.

Do not infer a mainnet FP8 activation date from an open proposal or development PR. Do not confuse candidate attempts/sec with network-accepted mining shares or final certificate throughput.

## Next gated milestones

1. **GPU-A + GPU-B:** align the same immutable B200 v1.3 executable, job/result ABI and source-manifest identity. Complete a bounded GPU search → proof → unchanged local full-block-validation test.
2. **GPU-A:** establish exact deployed public Testnet2 validator eligibility and a legitimate fresh job/payout configuration before considering real submission.
3. **MIDDLE:** qualify CPU patches against the merged source with fair matched workloads and no contention from GPU-B.
4. **LEFT:** assemble updated integration package and independently qualify each GPU model; resolve third-party redistribution rights before distribution.
5. **RIGHT:** perform non-invasive FK0957 endpoint identification where authorized, then propose separately approved physical transfer tests only if actual hardware capabilities and end-to-end break-even justify them.

**Safety:** preserve existing production mining, do not change payout addresses, drivers or firmware, and do not flash FPGAs or launch unbounded public-difficulty searches.
