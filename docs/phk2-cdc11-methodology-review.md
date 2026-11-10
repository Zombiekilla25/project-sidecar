# PHK2 CDC-11 reset-fanout review

> Superseded for v4 row count and evidence status by
> [the strict five-row v4 intake](phk2-v4-cdc11-five-row-review.md). This
> earlier note records the pre-v4 review state; it is not the current finding.

## Current evidence result

The current local HEAD at review start was
`5c8d045577bf10581a970585483fa5167ede62ad` (tree
`034526b6d917207fa2a4ee78f62a55dcb3c4f684`), with a clean worktree. This is
the immutable pre-v4 host/qualification snapshot. Its board source manifest is
`handoff/PHK2_REAL_BOARD_SOURCE_MANIFEST.json` (SHA256
`94d69d60a03ec971b21f6834b64d90d548249889aa30b4a4103749e15411efeb`); the
committed top RTL hash is
`e0d3dcdf88cf6487fa304ffa85b244a82f13097f569c80d0f84c2f8601a46faf`, and the
committed XDC hash is
`97c25163f6176271d93c727a54eb49116e4131cefc8d4c01c68aa44f29eee473`.

No v4 mapped checkpoint, mapped CDC report, mapped timing report, or v4 source
snapshot is currently present in this worktree. The retained FK33 physical
qualification record still says board synthesis and route `NOT_RUN`. The
mapped evidence described in the request therefore cannot yet be hash-bound to
the local source. The claimed three rows and gate result are not independently
verified here; no row IDs or endpoints are inferred from RTL instance names.

The committed pre-v4 RTL does instantiate three reset pipes around BSCANE2
TCK nets. That older source is not evidence for the v4 topology and is not used
to assign CDC row clocks/domains. BSCANE2 clock names alone cannot establish
clock-domain distinction; the clock roots, generated-clock relationships,
physical clock sources, periods, and downstream release nets must come from
the v4 mapped netlist/reports.

## AMD Vivado 2026.1 UG906 cross-check

The current official [UG906 asynchronous reset synchronizer guidance]
(https://docs.amd.com/r/en-US/ug906-vivado-design-analysis/Asynchronous-Reset-Synchronizer)
says reset synchronizers safely deassert reset in the destination domain and
calls out `ASYNC_REG`. It warns that multiple synchronizations of the same
reset inside one destination domain can release logic on different edges and
become an unknown state; UG906 identifies this as critical CDC-11 fanout from
the launch flop to destination clock. UG906 gives safe multiple-sync examples
for FIFO Generator and AXI designs, but those are architecture-specific
examples, not a blanket waiver for this PHK2 design.

The official [CDC rule and precedence table]
(https://docs.amd.com/r/en-US/ug906-vivado-design-analysis/CDC-Rules-Precedence)
classifies CDC-11 (fanout from launch flop to destination domain) as Critical /
Unsafe and CDC-9 (asynchronous reset synchronized with `ASYNC_REG`) as Info /
Safe. By default, report_cdc presents only the highest-precedence applicable
rule for an endpoint. `report_cdc -all_checks_per_endpoint` exposes all rules
for each endpoint, so a CDC-11 source-fanout row can coexist with CDC-9 evidence
that the destination synchronizer itself is recognized. CDC-9 does not erase
or automatically waive CDC-11; the launch fanout and domain topology still
need review.

The [UG906 report_cdc command guidance]
(https://docs.amd.com/r/en-US/ug906-vivado-design-analysis/Report-Clock-Domain-Crossings)
describes CDC as structural analysis, distinct from timing slack. The
[UG906 timing-path details]
(https://docs.amd.com/r/en-US/ug906-vivado-design-analysis/Timing-Path-Details)
and [other path groups guidance]
(https://docs.amd.com/r/en-US/ug906-vivado-design-analysis/Other-Path-Groups-Section)
place recovery in max-delay/setup analysis and removal in min-delay/hold
analysis; asynchronous checks appear in `**async_default**`. Recovery/removal
must be present and pass in routed timing evidence, with exceptions inspected
so reset checks were not cut. No false-path waiver is proposed here.

Methodology conclusion: three CDC-11 rows could be structurally understandable
if (and only if) they fan one asynchronous source reset into exactly one
coherent local release synchronizer in each of three genuinely distinct
destination domains, with all same-domain consumers sharing that release and
safe asynchronous assertion/synchronous deassertion. If two or more chains
resolve to the same equivalent destination clock/domain, CDC-11 is a real
unsafe duplicate release and RTL repair is required. Even if the topology is
structurally safe, the Critical CDC-11 findings remain visible for explicit
architecture disposition; this review does not waive them.

## Read-only report capture after route

The implementation lane can open the completed routed checkpoint and run the
script below. It only opens the supplied checkpoint and emits reports; it does
not launch or resume implementation, write a checkpoint, or modify RTL/XDC.
It must be invoked only after the active route completes and the lane owner
authorizes this read-only report capture.

```tcl
source tools/vivado_phk2_cdc11_readonly.tcl
phk2_cdc11_readonly_capture /evidence/v4_routed.dcp /evidence/v4_cdc_reports
```

The script captures default and `-all_checks_per_endpoint` CDC reports,
clock objects/properties, timing summary, exceptions/ignored objects, mapped
`ASYNC_REG` cells, and timing paths to asynchronous CLR/PRE pins using
`-delay_type min_max`. Keep all reports and record:

```sh
sha256sum /evidence/v4_routed.dcp /evidence/v4_cdc_reports/*
```

The mapped and routed normalized evidence input is
[`PHK2_VIVADO_CDC11_REVIEW.template.json`](../ops/PHK2_VIVADO_CDC11_REVIEW.template.json).
`tools/phk2_host/cdc11_reset_review.py` requires immutable source tree/file
hashes, all raw report/checkpoint hashes, exactly three CDC-11 rows and three
CDC-9 reset chains, clock fingerprints, mapped stage cells, consumer release
mapping, recovery/removal disposition, four finite active Gray max-delay
constraints and four active bus-skew constraints. It checks that route kept
the same CDC row/chain signatures, domains and `ASYNC_REG` properties.

The JSON inventory is an independently reviewed normalization of the raw
Vivado reports, not a replacement for them. Include the exact endpoint detail
and source/constraint identities so a reviewer can reproduce every row. If
any property is absent, contradicts the raw report, or is hidden by a timing
exception, intake refuses or leaves recovery/removal failed/indeterminate.

## Current disposition

```text
V4_MAPPED_IDENTITY_VERIFIED=false
CDC11_ROWS=unknown (request reports 3; no mapped report present locally)
CDC9_RESET_CHAINS=unknown (request reports 3; no mapped report present locally)
DESTINATION_DOMAINS=unknown
SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS=unknown
CDC11_STRUCTURALLY_SAFE=false (not demonstrated)
CDC11_REAL_UNSAFE=unknown
CDC11_INDETERMINATE=true
AMD_METHODOLOGY_CONSISTENT=true
CDC11_ACCEPTANCE_PENDING_ROUTE=true
CDC11_POST_ROUTE_ACCEPTANCE_PASS=false
RTL_FIX_REQUIRED=false (cannot determine without v4 row/domain evidence)
```
