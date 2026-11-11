# PHK2 v5.1 independent intake

## Immutable identity and method

The intake reads evidence from immutable evidence commit
`e89810b832ee7c1909bd92c449f33abb26b6882e`. Its source commit is
`5f65f0ec8900ecaae3c498223bef0efb2542c047`, source tree
`dcc879775d80e07ab41bc9af955a29a3fd8ba6f9`. All 124 `SHA256SUMS` entries,
all three checkpoint hashes, and all 123 manifested report hashes and sizes
validate. The final route checkpoint is
`0bd52785662a3c38f68667f85c75acdef33c109502794610669ab8e1cf61e9af`.

The v5.1 source has no RTL or constraints delta from the failed-v5 source.
Source inspection finds one two-stage BSCAN common-reset resolver, with
`ASYNC_REG`, asynchronous assertion, synchronous shift release, and all three
USER reset aliases driven by its output. There are no branch-local reset
resolver instances. Routed CDC still recognizes one CDC-9 chain. The final
post-route phys-opt log reports 14 optimized cells/nets, zero cells added,
zero removed, and timing gains of `+0.272 ns` WNS and `+0.750 ns` TNS. The
routed CDC/recovery evidence preserves one common resolver and shows no new
reset bypass or independent chain. No branch-local synchronous distribution
stage was added.

## Timing and CDC result

The routed 50 MHz analysis reports WNS/TNS `0.000/0.000 ns`, WHS/THS
`+0.004/0.000 ns`, and zero setup/hold failing endpoints. Common-release
recovery/removal paths pass, with worst reported slack `+0.074 ns`.

The three routed CDC-11 rows are accounted for individually:

| Row | Classification | Evidence |
|---:|---|---|
| 3 | Common reset PRE | Same source/destination endpoint as the sole depth-two CDC-9 asynchronous-reset synchronizer. The source has one `ASYNC_REG` resolver and common release fanout. |
| 7 | FIFO local-up handshake | `input_fifo/rd_up_w1_reg/D`; level is synchronized through two `ASYNC_REG` stages, then gates the write-side ready state. |
| 13 | FIFO local-up handshake | `result_fifo/wr_up_r1_reg/D`; level is synchronized through two `ASYNC_REG` stages, then gates the read-side ready state. |

Each FIFO direction holds its pointer machine at zero until both local sides
are up. Each local-up level has one first/second-stage pair and a single
consumer path in that FIFO direction; it is not a pulse or a divergent
same-domain copy. The two FIFO CDC-11 endpoints have matching depth-two CDC-3
rows. CDC-11 is correlated rather than waived by CDC-9/CDC-3 recognition.

CDC-1 remains 42 raw report rows. The exact 42 destination endpoints match
the prior immutable row-by-row CDC-1 audit at commit
`46e225424be87c73557ff725c8dc7558393335f8`; that audit classified all 42 as
structurally safe with zero unsafe and zero indeterminate. The v5.1 intake
reuses those classifications only after verifying exact destination-set
identity. The mapped/routed hierarchy names differ in source memory clock
aliases, so the earlier report is not treated as a literal row-for-row source
match.

All four Gray max-delay reports remain active and finite; all four bus-skew
constraints remain active and pass. The routed table is 4/4 for each check.

## Updated forensic conclusion

Physical-only optimization succeeded on the v5.1 candidate: the final routed
setup and hold gates pass without RTL/XDC changes or reset distribution
staging. This updates the earlier likelihood forecast; it is confirmed by
the actual immutable result. Keep the one common reset resolver.

The 38 TCK-independent qualification cases remain passed, with two TCK cases
still blocked and zero qualification failures. These results support
`PHYSICAL_QUALIFICATION_EXCEPT_TCK=true`; they do not prove the host's actual
adapter-pin TCK. Physical host TCK contract remains unproven and requires the
previously prepared authorized measurement.

Machine-readable intake: [`v5_1-independent-intake.json`](../results/phk2-v5_1-independent-intake.json).
The read-only verifier is [`intake_v5_1_independent.py`](../tools/phk2_host/intake_v5_1_independent.py).

## Result

```text
COMMON_RESET_RELEASE_SYNCHRONIZERS=1
INDEPENDENT_ASYNC_RELEASE_CHAINS=0
CDC1_REAL_UNSAFE=0
CDC11_FINAL_ROWS=3
CDC11_STRUCTURALLY_SAFE=true
CDC11_REAL_UNSAFE=0
CDC11_INDETERMINATE=0
WNS=0.000 ns TNS=0.000 ns WHS=+0.004 ns THS=0.000 ns
GRAY_MAX_DELAY_ACTIVE_COUNT=4
GRAY_BUS_SKEW_ACTIVE_COUNT=4
GRAY_FINITE_TIMING_COUNT=4
PHYSICAL_ONLY_FIX_SUCCEEDED=true
SYNC_DISTRIBUTION_STAGE_REQUIRED=false
TCK_INDEPENDENT_PASS=38/38
PHYSICAL_HOST_TCK_CONTRACT_PROVEN=false
```
