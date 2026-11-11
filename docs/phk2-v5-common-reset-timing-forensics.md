# PHK2 v5 common-reset routed timing forensics

## Immutable evidence

This review reads only commit `ce9cc2dd9e6334d6b24c6f7d3a0cbcc8619af00e`.
Its manifest and every SHA256SUMS entry validate. The exact source identity is
`42b6a724df771906ee7e565034724edd345081a8`, tree
`6423092d516f964f4ea745fdec49463db4337d19`; routed DCP SHA256 is
`17ee11c07cdf74d2d27d2205ead0c11909809eac5b5c045f9b0e1f0a224130aa`.

The four paths below are the four failing `bscan_tck -> bscan_tck` endpoints
from the routed timing summary. The full design summary has **15** setup
failures, not four: four on BSCAN TCK (`TNS=-0.652 ns`) and eleven in
`pll_core_unbuf` (`TNS=-0.098 ns`), giving global `TNS=-0.750 ns`. The extra
eleven are small response-payload core paths (slack -0.019 ns through
-0.001 ns) and are separate from the reset distribution diagnosis. Hold
passes (`WHS=+0.008 ns`, `THS=0`).

## Four BSCAN setup failures

All clocks are the single logical `bscan_tck`, period 20 ns, rise at 0 ns and
fall at 10 ns. Clock roots and branches below come directly from the launch
and capture clock paths in `route/setup_max.rpt`.

| Path | Startpoint → endpoint | Roots / branches | Data / route / logic (ns) | Clock skew (ns) | High fanout | Slack (ns) | Classification |
|---:|---|---|---:|---:|---:|---:|---|
| 1 | `bscan_reset_release/release_pipe_reg[1]/C` → `result_fifo/rbin_reg[8]/D` | X6Y1 USER2 → X7Y1 USER1 | 14.553 / 13.974 / 0.579 | -5.708 | common reset net 213 loads, 5.174 ns | -0.272 | routing dominated; severe skew and fanout contribute |
| 2 | `bscan_reset_release/release_pipe_reg[1]/C` → `result_fifo/rbin_reg[3]/D` | X6Y1 USER2 → X7Y1 USER1 | 14.492 / 13.872 / 0.620 | -5.714 | common reset net 213 loads, 5.174 ns | -0.217 | routing dominated; severe skew and fanout contribute |
| 3 | `bscan_reset_release/release_pipe_reg[1]/C` → `result_fifo/rgray_reg[3]/D` | X6Y1 USER2 → X7Y1 USER1 | 14.377 / 13.733 / 0.644 | -5.714 | common reset net 213 loads, 5.174 ns | -0.102 | routing dominated; severe skew and fanout contribute |
| 4 | `result_fifo/rbin_reg[3]/C` → `tx_shift_reg[4]/D` | X7Y1 USER1 → X7Y1 USER1 | 19.759 / 19.282 / 0.477 | -0.293 | read-address net 69 loads | -0.062 | routing dominated; FIFO distributed-RAM read path |

For paths 1–3, 96% of data delay is route delay. The reset-release Q net
alone has fanout 213 and 5.174 ns delay. The USER2 launch clock arrives at
9.759 ns while the next USER1 capture clock arrives at 24.051 ns (relative
to its nominal 20 ns edge), producing roughly -5.7 ns setup skew. Those are
the principal contributors; the logic delay is under 0.65 ns. Path 4 is a
separate result-FIFO memory/read-data route, with 97.6% route delay and modest
clock skew.

The routed clock interaction shows `bscan_tck -> bscan_tck` as `Partial Common
Node` and labels its exception interaction `Partial False Path (unsafe)`.
However, the four failing endpoints remain explicitly timed in `setup_max`;
the XDC and exception inventory do not cut these paths. That warning does not
explain their negative slack, so `CONSTRAINT_DEFECT=false` for these paths.

## Architecture and remedy ranking

The reset architecture itself is valid: one common two-stage asynchronous-
assert/synchronous-release chain resolves metastability once. Its final
release signal then drives a high-fanout physical distribution network across
separate BSCAN clock branches. The failures are in that synchronous
distribution and in a separate FIFO data route, not evidence that the single
common resolver is wrong.

| Candidate | Rank | Assessment |
|---|---|---|
| A. Physical optimization only | **Acceptable** | Run a bounded placement/physical-optimization/routing improvement first if desired. It can improve the high-fanout net, path routing, the FIFO RAM path, and the eleven small core paths. It cannot remove the measured BSCANE2 branch insertion difference by placement alone; physical-only closure is unlikely. |
| B. Buffer/replicate only after the common synchronizer | **Acceptable** | A buffered post-resolver tree can reduce the 213-load net delay. Keep all metastability resolution in the one common chain; check branch reset release timing and skew after buffering. This alone does not add cycle margin for the -5.7 ns USER2-to-USER1 skew or fix the FIFO read path. |
| C. Deterministic synchronous branch-local distribution stage after the common synchronizer | **Preferred** | Localize high-fanout reset loads after the common resolver and give the cross-branch transfer a full synchronous cycle. The stage must be timed from the common resolver, preserve asynchronous assertion and stopped-clock-safe reassertion, and must not independently sample/deassert raw asynchronous reset. No new `ASYNC_REG` reset chain per branch. |
| D. Change the architectural reset scheme | **Reject** | The common resolving chain is the correct architecture. Reverting to independent async deassert synchronizers would recreate the known CDC-11 failure. |

Option C is likely needed for reset-distribution closure. Option A or B may
still be enough for path 4 and the additional small core paths; those are
separate timing work. No what-if implementation was run for this review.

## Result

```text
FAILED_PATHS=4 (BSCAN clock group)
ROUTING_DOMINATED=4
CLOCK_SKEW_DOMINATED=3 significant contributors
FANOUT_DOMINATED=0 primary; FANOUT_CONTRIBUTOR_PATHS=3
LOGIC_DOMINATED=0
CONSTRAINT_DEFECT=false

COMMON_RESET_ARCHITECTURE_VALID=true
PHYSICAL_ONLY_FIX_LIKELY=false
SYNC_DISTRIBUTION_STAGE_LIKELY_REQUIRED=true

GLOBAL_SETUP_FAILING_ENDPOINTS=15 (4 BSCAN + 11 core)
GLOBAL_TNS=-0.750 ns (BSCAN -0.652 ns; core -0.098 ns)
RECOMMENDED_FIX=C, with physical routing optimization; separately close FIFO read and core paths
```

Machine-readable path detail is in
[`phk2-v5-common-reset-timing-forensics.json`](../results/phk2-v5-common-reset-timing-forensics.json).
