# PHK2 FK33 board integration handoff

Frozen protocol: [`../protocol/phk2-board-v1.json`](../protocol/phk2-board-v1.json)

RTL team entry points:

- [`../rtl/phk2_board/phk2_fk33_board_top.sv`](../rtl/phk2_board/phk2_fk33_board_top.sv): FK33 BSCAN top shell, package clock-only boundary.
- [`../rtl/phk2_board/phk2_protocol_decoder.sv`](../rtl/phk2_board/phk2_protocol_decoder.sv): frame/CRC command decoder.
- [`../rtl/phk2_board/phk2_async_fifo.sv`](../rtl/phk2_board/phk2_async_fifo.sv): dual-clock FIFO wrapper, XPM synthesis path and Gray-pointer simulation path.
- [`../rtl/phk2_board/phk2_core_stub.sv`](../rtl/phk2_board/phk2_core_stub.sv): control stub to be replaced by timing-qualified PHK2 core.
- [`../rtl/phk2_board/phk2_core_contract_adapter.sv`](../rtl/phk2_board/phk2_core_contract_adapter.sv): frozen core-clock valid/ready boundary, job identity fence, status propagation, and stale-result drain.
- [`../tools/phk2_host/board_transport.py`](../tools/phk2_host/board_transport.py): byte-exact software transport emulator, host adapter, and deliberately disabled physical adapter.
- [`../tests/phk2_board/tb_phk2_board.sv`](../tests/phk2_board/tb_phk2_board.sv): Icarus offline control/CDC-facing bench.
- [`../tests/phk2_board/tb_core_contract_adapter.sv`](../tests/phk2_board/tb_core_contract_adapter.sv): adapter handshake, backpressure, status, stale identity, abort, and reset bench.
- [`phk2-core-board-contract-v1.json`](phk2-core-board-contract-v1.json): machine-readable board/core interface contract.
- [`PHK2_BOARD_CORE_SOURCES.json`](PHK2_BOARD_CORE_SOURCES.json): board, CDC, core, constraint, and test-only source partition.
- [`../tools/qualify_phk2_core_binding.py`](../tools/qualify_phk2_core_binding.py): future exact-commit/source-hash/import/simulation gate.
- [`../tools/integrate_phk2_timing_core.sh`](../tools/integrate_phk2_timing_core.sh): offline handoff runner; never invokes Vivado or hardware.

See [`../docs/phk2-core-board-contract.md`](../docs/phk2-core-board-contract.md) and [`../docs/phk2-core-integration-checklist.md`](../docs/phk2-core-integration-checklist.md).

Current boundary qualification: [`PHK2_CORE_BOUNDARY_QUALIFICATION.json`](PHK2_CORE_BOUNDARY_QUALIFICATION.json). The latest committed core wrapper is captured, but is not directly compatible with the transaction contract; the timing team must supply a wrapper/binding and timing-bound source manifest before a real-core integration can pass.
- [`PHK1_TRANSPORT_SOURCE_SHA256.json`](PHK1_TRANSPORT_SOURCE_SHA256.json): immutable reference inventory and provenance.

Status semantics, chain division, and top-level assumptions: [`../docs/phk2-board-integration.md`](../docs/phk2-board-integration.md). CDC structure/review boundary: [`../docs/phk2-cdc-review.md`](../docs/phk2-cdc-review.md). First-silicon sequence: [`../docs/phk2-first-silicon-procedure.md`](../docs/phk2-first-silicon-procedure.md).

The BSCAN primitive simulation stub is not an FPGA model. The core stub produces no valid PHK2 cryptographic results. Only the Python software emulator runs the authoritative host golden fixture. Physical access is disabled.
