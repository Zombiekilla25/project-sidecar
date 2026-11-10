# PHK2 v4 five-row CDC-11 intake

## Immutable input and result

The intake reads Git objects from evidence commit
`6b0080dcd82daef773c7a83235e4ede5fe1df31d` and source commit
`5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a` (tree
`18139976ecd88843c93a43d3f8bb08659049307b`). It does not checkout the v4
implementation branch. The evidence commit records the routed DCP SHA256 as
`853af691b7ab1d8e8ac8b108e5a13fba6c2c5a4e357171caf99c2154ad45d400`; the DCP
itself is not in the bundle, so this review cannot rehash it.

Run from this repository with:

```sh
python3 tools/phk2_host/v4_cdc11_five_row_gate.py \
  --output results/phk2-v4-cdc11-five-row-review.json
python3 -m unittest discover -s tools/phk2_host -p 'test_v4_cdc11_five_row_gate.py'
```

The intake requires exactly five rows in the immutable CSV and JSON summary.
It classifies by exact destination endpoint and source RTL, never by the
bundle's `TOPOLOGY` label. The classifications are:

| Row | Exact endpoint | Independent class |
|---:|---|---|
| 1 | `input_fifo/rd_up_w1_reg/D` | `FIFO_LOCAL_UP_HANDSHAKE` |
| 2 | `result_fifo/wr_up_r1_reg/D` | `FIFO_LOCAL_UP_HANDSHAKE` |
| 3 | `scan1_reset_release/release_pipe_reg[0]/PRE` | `RESET_RELEASE` |
| 4 | `scan2_reset_release/release_pipe_reg[0]/PRE` | `RESET_RELEASE` |
| 5 | `scan3_reset_release/release_pipe_reg[0]/PRE` | `RESET_RELEASE` |

Rows 1–2 are corroborated against the immutable async FIFO source. Each
crossing transfers a level (`local_up = !local_reset`) through two
`ASYNC_REG` stages. Each synchronized copy is consumed in its own FIFO domain
by the ready/empty/full and pointer gating. The RTL has no pulse reconvergence
or multiple same-domain copies of that handshake bit. Reset holds the pointer
machines at zero and gates traffic until both sides report up. This is source
structural evidence; it is not a substitute for a routed cell/endpoint
inventory.

Rows 3–5 map to the three reset-release module instances and are corroborated
against the immutable two-stage `ASYNC_REG` implementation. Its asynchronous
assertion and clocked deassertion keep each domain in reset until clock edges
advance the release pipe. The v4 JSON summary asserts shared same-domain
release and passing recovery/removal results, but the raw routed reset timing
reports and mapped reset-cell inventory are absent from the committed bundle.

## Why acceptance remains indeterminate

The bundle has endpoint names, but does not include raw routed `report_cdc`,
`report_cdc -all_checks_per_endpoint`, clock inventory/root relationships,
mapped `ASYNC_REG` endpoint cells, or recovery/removal reports. Therefore the
three reset endpoints cannot be tied row-by-row to CDC-9, and the clocks cannot
be independently compared by object, root, period, generated relationship,
physical source, and logical domain. The summary's tck1/tck2/tck3 labels are
retained as claims, not promoted to independent proof.

Also, the committed targeted XDC applies a single `bscan_tck` clock object to
the collection of all three `INTERNAL_TCK` pins. This does not prove that the
routed clock roots are the same, but it makes a separate routed clock/root
inventory essential before accepting the implementation lane's three-domain
description. The raw routed reports are required to resolve whether rows 1/3
and 2/4 are distinct destination clocks, equivalent same-domain chains, or
otherwise structurally unsafe.

The five reported source fanout endpoints group by the lane's destination
labels as tck1 (rows 2, 3), tck2 (rows 1, 4), and tck3 (row 5). These pairs
have different source-level functions (FIFO readiness versus reset release),
so they are not automatically duplicate reset releases. But the gate marks
same-domain duplicate status `INDETERMINATE` until routed clock identity and
consumer topology are present. CDC-9 co-occurrence cannot waive CDC-11.

Current machine-readable result in
[`phk2-v4-cdc11-five-row-review.json`](../results/phk2-v4-cdc11-five-row-review.json):

```text
V4_IDENTITY_VERIFIED=true
CDC11_ROWS_EXPECTED=5
CDC11_ROWS_ACCOUNTED=5
RESET_ROWS=3
FIFO_HANDSHAKE_ROWS=2
OTHER_ROWS=0
CDC11_STRUCTURALLY_SAFE=false (not demonstrated)
CDC11_REAL_UNSAFE=false (not demonstrated)
CDC11_INDETERMINATE=true
SAME_DOMAIN_DUPLICATE_CHAINS=INDETERMINATE
CDC11_ACCEPTANCE_PASS=false
RTL_FIX_REQUIRED=false (no proven structural failure)
```

All five rows remain acceptance-indeterminate pending the raw report package;
no unsupported RTL-fix conclusion is drawn. The required next offline input is
an immutable routed bundle containing raw CDC default/all-checks reports,
clock properties/root and generated-clock relationships, first-stage fanout
and mapped `ASYNC_REG` inventories, and recovery/removal timing reports with
the relevant exceptions. It must identify the same v4 source/tree and routed
DCP hash.
