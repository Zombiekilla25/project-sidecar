# PHK2 v4 CDC-11 cross-qualification adjudication

## Immutable inputs

This audit reads only Git objects from:

- Complete v4 evidence commit `221002426f26dd7a3705ba5ec58d40a2ea4c2674`.
- Independent qualification result commit
  `7893357612d9d8bc671badde63525e8925668dff`.
- V4 source commit `5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a`.

The independent result reports CDC-11 5/5 accepted and 38/38 TCK-independent
cases passed. Its component test counts remain valid as recorded executions.
The qualification promotion derived from that acceptance does not.

## What made the other lane pass

In `tools/phk2_cdc_qualification/intake_v4_immutable_bundle.py`,
`check_cdc11`:

1. Classifies rows 1–2 by FIFO topology, verifies matching two-stage CDC-3
   entries and checks the FIFO local-up RTL gates.
2. Classifies rows 3–5 as domain reset releases, correlates each endpoint to a
   two-stage CDC-9 row, checks `ASYNC_REG`, and consumes positive
   recovery/removal results.
3. Verifies three source instances named `scan1/2/3_reset_release` clocked by
   RTL nets `tck1/tck2/tck3`, plus a testbench that independently starts and
   stops three simulated clocks.
4. Sets `same_domain_consumers_share_release` and
   `same_domain_release_edge_coherent` from those per-instance structural and
   test results, then marks all five rows safe.

The function never compares each routed row's `destination_clock` or
`CLOCK_ROOT`, and it never checks whether `tck1/tck2/tck3` represent
independent clock sources. Its “three domains” premise is inferred from RTL
signal/instance names and a simulation model that drives three independent
clocks. CDC-9 and recovery/removal prove each reset chain is recognized and
locally timed; neither proves three distinct domains or coherent release
across one domain.

## Routed clock facts

The raw routed CDC report puts every CDC-11 row in the same clock pair:
`pll_core_unbuf` to `bscan_tck`. The committed XDC assigns one `bscan_tck`
clock to the collection of all three BSCANE2 `INTERNAL_TCK` pins. Routed reset
timing paths show three distinct physical branches, all at a 20 ns period and
rise@0/fall@10 waveform:

| BSCAN pin | Logical clock object | Physical branch | Routed root/path |
|---|---|---|---|
| `u_user1/INTERNAL_TCK` | `bscan_tck` | `tck1` | X7Y1 through `tck1_BUFG_inst` |
| `u_user2/INTERNAL_TCK` | `bscan_tck` | `tck2` | X7Y0 through `tck2_BUFG_inst` |
| `u_user3/INTERNAL_TCK` | `bscan_tck` | `scan3_reset_release/clk` | direct routed branch; no BUFG root token |

The immutable RTL itself says the BSCANE2 clock outputs are separate leaves
“even though the physical TAP TCK is shared.” Thus the evidence supports one
logical TCK domain with three physical clock branches, not three independent
TCK sources. The names `tck1/tck2/tck3` and their separate roots do not change
the common source or establish asynchronous independence.

## Reset edge divergence and circuit consequences

All three release pipes receive the same asynchronous `core_rst` deassertion.
The destination edges derive from the same TCK source but reach the three
branches with different insertion delays. If reset deasserts near an edge,
each first stage has its own recovery/removal aperture and metastability
resolution. It is possible for two-stage chains to deassert on different
source edge numbers, such as scan1=N, scan2=N+1, scan3=N. Positive
recovery/removal slack for settled routed paths does not prove that reset
deassertion cannot occur in an aperture; the purpose of the synchronizer is to
contain that uncertainty, not correlate separate chains.

The RTL has local consumer groups for each reset, but not a common release
barrier across them. There is also a concrete cross-group startup path:

- `rx_full_src` is reset and clocked in USER2 (`scan2_rst`, `tck2`). Its reset
  default is zero.
- `rx_full_s1/rx_full_s2` and USER3 status capture are reset in USER3
  (`scan3_rst`, `tck3`).
- The input FIFO reports `wr_full = !wr_ready || full_i`, so while USER2/FIFO
  startup is not ready, its actual full indication is high.
- If USER3 releases first, its status synchronizer can propagate the reset
  default zero from `rx_full_src` and USER3 can capture that status while USER2
  is still held in reset. The two-stage crossing contains metastability but
  does not make this startup status coherent. No readiness barrier in the
  immutable RTL prevents that capture.

The FIFO local-up handshakes do protect pointer epochs and block FIFO traffic
until both sides are ready. They do not gate USER3 status capture on USER2
readiness. Therefore divergent release is possible and the complete evidence
does not establish that it is architecturally safe. Under the requested strict
CDC-11 criterion, rows 3–5 fail pending a coherent same-domain release or a
separately proven isolation/startup protocol.

## Adjudication

```text
RIGHT_ACCEPTANCE_PREMISE=three named tck nets treated as three reset domains;
  CDC-9 + local tests + recovery/removal used as sufficient evidence
RIGHT_ACCEPTANCE_PREMISE_VALID=false
BSCAN_LOGICAL_CLOCK_DOMAINS=1
BSCAN_PHYSICAL_CLOCK_BRANCHES=3
INDEPENDENT_RELEASE_CHAINS=3
DIVERGENT_RELEASE_EDGE_POSSIBLE=true
DIVERGENT_RELEASE_ARCHITECTURALLY_SAFE=false (not established; status counterexample above)
CDC11_ACCEPTANCE_PASS=false
RIGHT_38_OF_38_RESULT_VALID=false (qualification result; component executions remain recorded)
RTL_FIX_REQUIRED=true
```

The prior rejection does not change. The new evidence did not add a domain
relationship or cross-island startup guarantee; it exposed that the passing
lane's code never checked either. This adjudication does not modify RTL or
constraints. Machine-readable detail is in
[`phk2-v4-cdc11-cross-qualification-audit.json`](../results/phk2-v4-cdc11-cross-qualification-audit.json).
