# PHK2 v4 complete-package CDC-11 methodology review

## Immutable package verification

This review reads only Git objects from evidence commit
`221002426f26dd7a3705ba5ec58d40a2ea4c2674`; it does not use mutable routed
worktree files or check out the candidate implementation. The immutable
source is `5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a`, tree
`18139976ecd88843c93a43d3f8bb08659049307b`.

The manifest and SHA256SUMS coverage and content hashes validate. The package
binds these checkpoint hashes:

```text
SYNTH_DCP_SHA256=d2ee37bc487359dc1599e04e02cfbc530791d5ceeb10c3317c9c19b1f44a23a0
PLACED_DCP_SHA256=c4a396a84f663c9d108e6a48fc793932fc2f5a91d93d9a8a701da3fe18308ca6
ROUTED_DCP_SHA256=853af691b7ab1d8e8ac8b108e5a13fba6c2c5a4e357171caf99c2154ad45d400
```

The raw routed `report_cdc -all_checks_per_endpoint -details` report is
hash-bound in the manifest. It contains exactly five CDC-11 rows and three
CDC-9 reset rows. The endpoint table and CDC-9 correlation table are checked
against that raw report. Reset paths, exceptions, clock interaction, and the
immutable source RTL are also read from the exact commit.

## Row review

| Local row | Vivado row | Exact destination | Clock object | Routed clock path | Class | Result |
|---:|---:|---|---|---|---|---|
| 1 | 5 | `input_fifo/rd_up_w1_reg/D` | `bscan_tck` | `tck2` / X7Y0 | FIFO local-up handshake | structurally coherent |
| 2 | 11 | `result_fifo/wr_up_r1_reg/D` | `bscan_tck` | `tck1` / X7Y1 | FIFO local-up handshake | structurally coherent |
| 3 | 13 | `scan1_reset_release/release_pipe_reg[0]/PRE` | `bscan_tck` | `tck1` / X7Y1 | reset release | duplicate same-domain release |
| 4 | 15 | `scan2_reset_release/release_pipe_reg[0]/PRE` | `bscan_tck` | `tck2` / X7Y0 | reset release | duplicate same-domain release |
| 5 | 17 | `scan3_reset_release/release_pipe_reg[0]/PRE` | `bscan_tck` | direct routed branch; no BUFG root token | reset release | duplicate same-domain release |

All rows have source `clockgen/reset_release/release_pipe_reg[3]/C`, source
clock `pll_core_unbuf`, destination clock `bscan_tck`, `ASYNC_REG=true`, and
reported depth 2. The three reset rows correlate to CDC-9 report rows 12, 14,
and 16 respectively. Each routed reset timing report passes its recovery or
removal check with positive slack: 0.070 ns, 0.170 ns, and 0.364 ns. The
immutable reset RTL confirms asynchronous assertion and clocked synchronous
deassertion; a stopped clock leaves the pipe asserted until destination edges
occur.

CDC-9 describes the recognized destination synchronizer. It does not waive
CDC-11's launch-flop fanout. The routed CDC report names the same logical
destination clock object (`bscan_tck`) for all three reset chains. Thus the
reported topology contains one logical destination domain with three
independent release synchronizers: two duplicate chains beyond one coherent
chain. Their different routed branches do not make them independent clock
domains when all are timed and reported under the same clock object. The
captured reports provide no architectural waiver establishing safe independent
release for these same-domain consumers.

### FIFO handshake rows

The two local-up crossings are levels, not pulses. Immutable RTL shows a
two-stage `ASYNC_REG` synchronizer for each FIFO's remote-side-up indication.
Each synchronized value gates only its owning FIFO's readiness, empty/full,
and pointer activity. The two rows carry separate FIFO status indications;
they are not duplicate copies of one signal feeding divergent consumers.
Pointer state is held at zero and data acceptance is blocked until both sides
of each FIFO report up. No unsafe FIFO handshake row was found in this review.

## BSCAN TCK clock-object review

All three pins are assigned to the same `bscan_tck` object at 20.000 ns. Routed
reset paths show distinct physical branch nets and roots:

| BSCAN instance | TCK pin | Clock object | Routed clock root/path | Physical net segment |
|---|---|---|---|---|
| `u_user1` | `u_user1/INTERNAL_TCK` | `bscan_tck` | X7Y1 via `tck1_BUFG_inst/O` | `tck1` |
| `u_user2` | `u_user2/INTERNAL_TCK` | `bscan_tck` | X7Y0 via `tck2_BUFG_inst/O` | `tck2` |
| `u_user3` | `u_user3/INTERNAL_TCK` | `bscan_tck` | direct routed path, no BUFG clock-root token | `scan3_reset_release/clk` |

The evidence establishes **one logical clock object and three separate
physical clock paths**. These are not one shared routed net from the three
BSCANE2 pins. The constraints collapse the distinct paths into one clock
object, so `BSCAN_CLOCK_COLLAPSE_SAFE=false` for this qualification: clock
object identity cannot be used to claim independent destination domains, and
the path-specific insertion/skew must not be hidden by that logical alias.

## Decision

```text
V4_IDENTITY_VERIFIED=true
MANIFEST_VALID=true
SHA256SUMS_VALID=true
CDC11_ROWS_ACCOUNTED=5
RESET_ROWS=3
FIFO_HANDSHAKE_ROWS=2
DISTINCT_RESET_DOMAINS=1
SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS=2
CDC11_STRUCTURALLY_SAFE=false
CDC11_REAL_UNSAFE=true
CDC11_INDETERMINATE=false
FIFO_HANDSHAKE_UNSAFE_ROWS=[]
BSCAN_CLOCK_COLLAPSE_SAFE=false
CDC11_ACCEPTANCE_PASS=false
RTL_FIX_REQUIRED=true
FAILING_ROW_IDS=[3,4,5]
```

This supersedes the earlier incomplete-package result. The exact machine
review is [`phk2-v4-complete-cdc11-review.json`](../results/phk2-v4-complete-cdc11-review.json).
The immutable source and constraints were not modified.
