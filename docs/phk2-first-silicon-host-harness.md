# PHK2 first-silicon host harness (offline qualification)

This isolated worktree adds a single-attempt host harness around the existing
PHK2 host runtime. It does not define or change descriptor or wire semantics.
The reference base is board-integration commit
`1978750ef21471076d463d99166f3ab011269d14`; the qualified host-runtime
implementation it consumes is commit `6ec5e5ac959c169df3e706377e7287f9c55b3392`.
The active RTL/integration worktree is not modified.

## Frozen inputs

`fixtures/phk2-first-silicon/descriptor-oracle-manifest-v1.json` indexes the
13 retained production descriptors plus the known single-work and Batch64
fixtures. It records descriptor and job identity hashes, generation, seed
identity hash, expected result count, expected raw and canonical result hashes,
and CPU-oracle hash. Expected result bytes remain in the existing authoritative
fixture tree; this index does not regenerate or replace those bytes. The
qualification checks the encoder against all 13 retained descriptors and the
single-work fixture (14 byte-exact checks).

## Session and fail-closed behavior

The harness uses the committed board-protocol v1 payloads and sequencing:
HELLO, LOAD_DESCRIPTOR, START_RANGE, bounded STATUS polling, READ_RESULT, and
final STATUS. A session sends no descriptor after failed HELLO, does not retry
commands, checks generation/range/slot/coordinate identity and result count
before treating results as valid, and compares raw and canonical results with
the existing CPU-oracle output. It supports the qualified count=1 and count=64
windows only. The mock verifies the full 64-record response via bounded result
reads.

The fault matrix covers HELLO failure/timeout, invalid descriptor and frame,
generation rejection, status and FIFO errors, short/extra/duplicate results,
timeout, wrong count, raw/canonical mismatch, and disconnect. The modeled
program budget permits one target callback and always rejects peer programming.
Recovery hooks are a separate interface; the offline tests call only mock hooks
and do not couple result validation to restoration behavior.

## Evidence and timing

Each attempt gets a new directory (existing directory names are refused). The
bundle records the manifest, descriptor bytes, request/response protocol
transcript, raw status payloads, result records, raw and canonical result
bytes when structurally valid, errors, timing, and recovery result. Evidence
files and directory entries are fsynced, including a pre-recovery evidence
sync marker before any recovery hook could be called. Python source hashes for
the CLI, harness, protocol codec, and transport reference are recorded. There
is no compiled host executable in this worktree, so its executable hash is null
rather than misreporting a source hash as a binary hash.

The future timing fields are `HELLO_US`, `HOST_PACK_US`, `TRANSPORT_IN_US`,
`FPGA_ACCEPTANCE_MONOTONIC_NS`, `FPGA_WAIT_US`, `FIRST_RESULT_MONOTONIC_NS`,
`LAST_RESULT_MONOTONIC_NS`, `TRANSPORT_OUT_US`, `COMPOSE_US`, `VERIFY_US`, and
`VECTOR_TOTAL_US`. Offline values are explicitly labeled `MOCK`; they are not
silicon measurements. An unavailable stage must remain null/unknown in a
physical evidence record rather than being estimated.

Throughput formulas for later measured data:

* `FPGA_WORK_ITEMS_PER_SEC = work_items / FPGA_BUSY_INTERVAL_SEC`, only when
  the device exposes an independently measured busy interval or cycle count.
* `END_TO_END_WORK_ITEMS_PER_SEC = work_items / VECTOR_TOTAL_SEC`.
* `RESULTS_PER_SEC = result_records / measured_result_receive_interval_sec`.
* `DESCRIPTOR_BYTES_PER_SEC = descriptor_frame_bytes / descriptor_transmit_sec`.
* `RESULT_BYTES_PER_SEC = result_wire_bytes / TRANSPORT_OUT_SEC`.

Transport and FPGA fractions are measured phase duration divided by total
transaction duration. None of these quantities is mining hashrate.

## Command and hardware boundary

`tools/phk2-first-silicon` accepts `--bitstream`, `--bitstream-sha`,
`--target-lock`, `--descriptor`, and `--evidence-dir`. It defaults to the
software emulator and dry-run. `--live` also requires `--authorization` and
validates a single-use authorization bound to the image, lock, and descriptor.
This worktree contains no PHK2 physical programmer/transactor adapter, and its
transport module explicitly disables physical access. Therefore a live request
is refused before hardware access. This host qualification does not qualify a
physical response endpoint, routed image, or FPGA behavior. Current integration
records still mark the wire/board physical path unqualified.

```sh
tools/phk2-first-silicon --descriptor fixtures/phk2-host-runtime/authoritative-vector-001/descriptor.bin
tools/phk2-first-silicon --help
PYTHONPATH=tools/phk2_host .venv/bin/python tools/phk2_host/first_silicon_qualify.py
```

The first command is an offline fixture run and emits an immutable mock evidence
bundle. No physical invocation is authorized by this document.
