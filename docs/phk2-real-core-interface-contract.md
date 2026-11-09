# PHK2 real-core interface and board adapter

The board endpoint now binds `phk2_timing_core_contract` through
`phk2_core_contract_adapter`. The exact port list, bit widths, reset behavior,
range limits, and source hashes are in
[`../handoff/PHK2_REAL_CORE_TRANSACTION_INTERFACE.json`](../handoff/PHK2_REAL_CORE_TRANSACTION_INTERFACE.json).
The source set and stub-exclusion guard are in
[`../handoff/PHK2_REAL_BOARD_SOURCE_MANIFEST.json`](../handoff/PHK2_REAL_BOARD_SOURCE_MANIFEST.json).

## Actual core boundary

The core accepts a 896-bit/112-byte descriptor through `descriptor_valid` /
`descriptor_ready`. Range work uses `range_valid` / `range_ready` with a
64-bit generation, 256-bit job key, 32-bit start, 16-bit count, and 16-bit
range ID. The current core accepts start index zero and count 1 through 64.
Abort has a separate valid/ready handshake and is bound to generation, job
key, and range ID. Results use a 896-bit ready/valid record with generation,
range ID, slot, row/column identity, 32-byte raw digest, and 64-byte canonical
transcript. Busy, result pending, error, stale-job, overflow, and aborted are
separate signals.

The candidate core uses one existing PHK1 4x8 tile serially across eight
subtiles. It XOR-composes the eight 512-bit transcripts before digest/filter
processing. That shape matches the CPU oracle in one-item and 64-item
diagnostic replays. The current core hard-codes an all-ones result target; the
112-byte descriptor has no pool target field, so production target filtering
is not yet established.

## Stub-to-core mapping

| Stub boundary | Real-core boundary | Adapter action | CDC | Latency |
|---|---|---|---|---|
| `cmd_valid/cmd_ready` | descriptor/range/abort valid-ready | Decode command, latch payload, hold request until accepted | Commands arrive in core domain after the USER2 async FIFO | Core-compute dependent |
| `cmd_opcode/length/payload` | descriptor fields or range/abort fields | Slice byte-packed protocol fields; reject invalid length and range locally | Same as command | One control handshake plus response framing |
| `busy` | core `busy` | Direct status mapping | Crossed by status synchronizer in top | Two synchronizer stages |
| `result_ready` | core candidate/result pending | Direct status mapping | Crossed by status synchronizer in top | Two synchronizer stages |
| `error/stale/aborted` | same independent core signals plus adapter sticky faults | Preserve independent flags and 16-bit error code | Crossed by status synchronizer in top | Two synchronizer stages |
| `result_byte` | 896-bit result record | Gather up to four records, then encode a CRC-framed READ_RESULT response | Response encoder is core-clocked; encoded bytes cross USER1 async FIFO | Adds frame serialization latency |
| `input_overflow` | endpoint/FIFO overflow | OR into top overflow flag; no work result is fabricated | FIFO full is observed in writer domain | Immediate sticky status in top |

## Qualification boundary

`phk2_real_core_endpoint` consumes the decoded command engine, binds the actual
core contract adapter and computational core, and emits framed responses.
The endpoint single-work and 64-work regressions passed with separate
transport/core clocks and input/output asynchronous FIFOs. The 64 results were
compared byte-for-byte with the CPU oracle. Physical BSCANE2 event-level simulation and vendor CDC review remain
unqualified. A variable-period asynchronous-clock endpoint stress passed
12,000 HELLO transactions (1,822,446 core/transport edges) with both FIFOs
reaching full and no dropped/duplicate responses. Vivado 2026.1 verified the
exact PHK2 clock-generator RTL at 175 MHz in a clock-only design. The board top no longer instantiates the test stub.
The authoritative board-clock constraint fragment is now installed and
hash-checked. Full board-core synthesis remains gated on physical-top structural
validation and vendor CDC review.

The 13 retained production descriptor endpoint replays and 64-item batch passed
before the HELLO capability-byte correction. On the corrected source, a single
production work item and six control scenarios were rerun successfully; the
computation/result datapath was unchanged by the HELLO-only correction. Replaying
all 13 board fixtures against that final HELLO source revision remains outstanding.
