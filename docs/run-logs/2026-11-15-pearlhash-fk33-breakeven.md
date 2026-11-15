# PearlHash RTX 3080 / FK33 break-even analysis

## Decision summary

The best retained apples-to-apples CUDA full-grid result is **75.454830
Tera-work/s**, where the benchmark's `TH/s` is mathematically a count of
int8 multiply-accumulate (MAC) work, not SHA hashes/s or floating-point
operations/s. One complete work unit is 131,072 × 131,072 outputs at K=4,096:
70,368,744,177,664 MACs across 1,024 regions. The matched offline grid took
about **0.932594 s**.

A separate short live-miner record logged **81.246667 TH/s** over 12 no-hit
grids, but the source report says that its timing scope differs from offline
`FULL_TH` and the sample is too short to establish sustained throughput. Treat
that as a second, stricter planning hurdle, not as the matched denominator.

At 250 MHz, matching the offline result allows about **233.15 million FPGA
cycles per full grid** (227,684 cycles per region); matching the short live
logged rate allows about **216.53 million cycles** (211,453 per region).
With a 10% speed margin the offline target falls to about **211.95 million
cycles**. These are end-to-end cycle budgets, including setup, transfer,
synchronization, return, and any software handling.

The local Stage-8 profitability record gives a current one-card ideal
arithmetic ceiling of **1.100080 TMAC/s at assumed 200 MHz**, and **8.800638
TMAC/s for eight cards**, before transport and full-path costs. This is about
68.6× below the matched CUDA result for one card and 8.6× below for eight.
It implies roughly 63.97 s/card or 8.00 s/eight cards per GPU-sized work unit
under ideal linear scaling. It is a design arithmetic ceiling, not measured
pool throughput or a guarantee that this distinct FPGA profile executes the
same complete work unit. The current evidence does not support an FK33 speedup
claim.

## Evidence and metric reconciliation

| Evidence | Result | Scope |
|---|---:|---|
| Matched GA102 CUDA Redux full-grid comparison | 62.30 → 70.11 TH/s, +12.53% | Matched offline work, K4096/R256; sole retained code change replaces five XOR shuffles with `__reduce_xor_sync`. |
| RH-U8 matched RTX 3080 qualification | 75.454830 TH/s | 24 timed complete grids across two matched blocks; full setup/prep, all 1,024 regions, synchronization/readback. Prep 20.353 ms; search 912.242 ms; total 932.594 ms. |
| RH-U8 bounded live miner sample | 81.246667 TH/s mean, 77.84–82.25 | 12 no-hit grids, separate logging scope; one bounded live canary, not sustained qualification. |
| Local active device check | GPU 1 at 100% utilization, SRBMiner PearlHash process present | Read-only observation. No benchmark was started and no workload was interrupted. |
| CPU reference stage timings | unavailable | Existing CPU correctness reference vectors are not timing records. No new CPU load benchmark was run. |

The CUDA full-grid benchmark uses M=N=131,072, K=4,096, rank R=256, 4,096
square regions, 16×16 hash tiles, 1,024 regions, and a 64-result polling
batch. Its work metric is derived as `outputs × K`, i.e. MACs. It is **not**
equivalent to a pool share rate or to FLOP/s (which counts a multiply and an
add as two operations).

The retained `fullgrid_offline_v3.py` harness is a standalone no-pool CUDA
benchmark with deterministic seeds and the production-shaped full grid. Its
hardest-target mode checks that every found flag remains zero. Separate V3
integration gates cover host/GPU seed equality and a positive verified proof;
the benchmark itself is not a per-output golden-vector comparator. The
existing correctness gates plus the full-grid no-hit check are the retained
output verification. Neither was re-run during this analysis because the GPU
was busy.

GPU stage records do not provide CPU-only timings for operand generation,
NoisyGEMM, transcript folding, or final hashing. The reported 20.353 ms prep
is a GPU full-grid setup/noise interval, not a CPU measurement. Search's
912.242 ms combines region compute and fused transcript/hash work; it is not
split into a standalone NoisyGEMM time. A separate root/hash diagnostic is
6.056 ms on the GPU, which is not the per-candidate final-hash cost.

## PCIe Gen3 x4 model

Theoretical one-direction bandwidth after 128b/130b encoding is **3.938
GB/s**. The calculator uses **3.15 GB/s** as an explicit 80%-of-theoretical
planning assumption; 2.5–3.5 GB/s should be swept until actual XDMA timings
exist. DMA startup, launch, and synchronization costs are separate inputs.
These are estimates, not measured FK33 transport results.

At 3.15 GB/s, transferring the two 512 MiB int8 matrices (1 GiB total) takes
about **0.341 s**, before command and synchronization overhead—36.5% of the
offline GPU deadline. Against the short live rate it leaves about 0.525 s for
FPGA compute, requiring roughly **134 TMAC/s** FPGA compute, or about **536,000
MAC/cycle at 250 MHz**. If the FPGA can regenerate operands/noise from compact
job seeds, this matrix transfer can disappear; that requires exact algorithm
and commitment compatibility.

Returning the full int32 product for only one complete output grid would be
64 GiB and take about **21.8 s** at the assumed link rate. Returning 64-byte
transcripts for all 16×16 output tiles would be 4 GiB and take about **1.36 s**,
already longer than either GPU reference. DMA per tile or per region is
therefore ruled out. Keep candidate checking beside the compute or aggregate
results into a small bounded record.

For work split into independent batches, double buffering can hide transfer
behind compute only when buffers and DMA are asynchronous and work is
independent. The steady-state batch interval is then bounded by the slowest
stage (`max(prep, transfer, compute, return)`); first-work latency remains
additive. The calculator reports additive latency and does not assume overlap.
Batch 64 is the production-backed polling size. Future tests should compare
64/128/256-region batches and separately report fill/drain latency.

## Ranked offload options

1. **Full compact-work-unit search (compute + transcript + hash + compare on
   FPGA).** This is the only option with a path to avoid huge PCIe inputs and
   outputs: provide compact seed/job state, return compact candidate records.
   First run a cycle/resource feasibility gate, then a small 64-region
   correctness/latency batch. Current candidate ceiling is far below break
   even, so do not invest in a full-grid implementation without a radically
   higher compute budget or many more cards.
2. **Partial NoisyGEMM with fold/hash kept adjacent to the FPGA.** It avoids
   returning 64 GiB, but only works if the interface can carry the required
   source operands efficiently and preserve deterministic region reuse. A
   1 GiB matrix upload consumes roughly a third of the time budget and pushes
   compute needs above 118–134 TMAC/s, depending on baseline and link rate.
3. **Operand/noise generation offload.** GPU prep is only 20.353 ms in the
   matched run. Returning 1 GiB of generated operands would cost about 341 ms;
   this loses. Compact seed generation could be a correctness experiment, but
   it is not a meaningful performance target by itself.
4. **Transcript reduction offload after GPU compute.** A direct 64-byte
   transcript per 16×16 tile is about 4 GiB per complete grid, exceeding the
   grid deadline. The current CUDA Redux already reduced the shuffle-heavy
   fold and improved full-grid throughput 12.53%; extra transfer is unlikely
   to win.
5. **Final keyed BLAKE3 only.** The measured setup/root hashing diagnostic is
   6.056 ms, under 0.7% of the 932.594 ms grid. Moving transcript bytes across
   PCIe costs far more than that. Do not test standalone final-hash offload as
   a speedup candidate.

## Required future measurements

Before a performance claim, collect same-work GPU and GPU+FPGA full-grid
timings, CPU-only stage timings, FPGA cycles at measured clock, DMA payload
bytes and throughput, queue/launch/sync/readback time, batch size, warm-up,
duration, correctness, and output equivalence. Report the metrics using the
same MAC definition and include prep, fill, steady state, drain, and result
return. Use `tools/pearlhash_breakeven.py` to enter measured FPGA cycles and
transport parameters. It is stdlib-only and never launches a benchmark.

## Safety and status

No CUDA benchmark ran because an active PearlHash workload occupied an RTX
3080. No miner was paused, stopped, or changed. No pool, remote system, FPGA,
PCIe endpoint, or hardware was accessed. A future GPU benchmark requires a
separate maintenance/idle window and explicit authorization.
