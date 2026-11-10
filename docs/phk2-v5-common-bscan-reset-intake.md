# PHK2 v5 common BSCAN reset intake

This local-only watcher reads immutable Git objects and rejects worktree-only
files. It does not checkout commits or run any tool that can synthesize,
implement, configure, or access hardware.

Start continuous local polling with:

```sh
python3 tools/phk2_host/intake_v5_common_bscan_reset.py \
  --watch --interval 10 \
  --output results/phk2-v5-common-reset-intake.json
```

The watcher scans locally referenced and unreachable Git commit objects. It
first looks for a committed board-top source change descended from the v4
source, then statically verifies the source identity and reset structure:

- exactly one `phk2_domain_reset` instance in the board integration;
- asynchronous assertion, clocked synchronous release, at least two stages,
  and `ASYNC_REG`;
- each USER1/USER2/USER3 sequential reset consumer resolves to the common
  release output, with no direct core-reset bypass;
- no independent scan reset synchronizer instance remains;
- async FIFO local-up synchronizers, readiness gates, and reset epoch pointer
  protection remain present.

When a v5 immutable evidence manifest appears, it must bind to that exact
source commit/tree and include checksummed synthesis, placement, and route
checkpoints, raw mapped/routed `report_cdc` including
`-all_checks_per_endpoint`, exact CDC row mapping, recovery/removal evidence,
CDC-1 evidence, and four finite Gray max-delay reports plus four active
bus-skew constraints. The gate checks every listed SHA256SUMS object from Git,
requires the mapped/routed summary to report one common release, no duplicate
chains, preserved `ASYNC_REG`, passing recovery/removal, and zero real unsafe
CDC-1 rows. It also requires exact 38/38 TCK-independent qualification and two
cases blocked only by physical TCK.

Current local intake status: no v5 source commit or v5 evidence manifest is
present. The current v5-named local ref still points to the v4 evidence
package, which is explicitly rejected. Until a qualifying v5 package is
committed, `CDC11_ACCEPTANCE_PASS=false` and `RTL_FIX_REQUIRED=true` remain
fail-closed outputs. A source-only commit can pass the source audit, but does
not make mapped/routed qualification pass.
