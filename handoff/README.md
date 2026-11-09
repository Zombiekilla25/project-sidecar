# PHK2 FK33 board integration handoff

Frozen protocol: [`../protocol/phk2-board-v1.json`](../protocol/phk2-board-v1.json)

RTL team entry points:

- [`../rtl/phk2_board/phk2_fk33_board_top.sv`](../rtl/phk2_board/phk2_fk33_board_top.sv): FK33 BSCAN top shell, package clock-only boundary.
- [`../rtl/phk2_board/phk2_protocol_decoder.sv`](../rtl/phk2_board/phk2_protocol_decoder.sv): frame/CRC command decoder.
- [`../rtl/phk2_board/phk2_async_fifo.sv`](../rtl/phk2_board/phk2_async_fifo.sv): dual-clock FIFO wrapper, XPM synthesis path and Gray-pointer simulation path.
- [`../rtl/phk2_board/phk2_core_stub.sv`](../rtl/phk2_board/phk2_core_stub.sv): control stub to be replaced by timing-qualified PHK2 core.
- [`../tools/phk2_host/board_transport.py`](../tools/phk2_host/board_transport.py): byte-exact software transport emulator, host adapter, and deliberately disabled physical adapter.
- [`../tests/phk2_board/tb_phk2_board.sv`](../tests/phk2_board/tb_phk2_board.sv): Icarus offline control/CDC-facing bench.
- [`PHK1_TRANSPORT_SOURCE_SHA256.json`](PHK1_TRANSPORT_SOURCE_SHA256.json): immutable reference inventory and provenance.

Status semantics, chain division, and top-level assumptions: [`../docs/phk2-board-integration.md`](../docs/phk2-board-integration.md). CDC structure/review boundary: [`../docs/phk2-cdc-review.md`](../docs/phk2-cdc-review.md). First-silicon sequence: [`../docs/phk2-first-silicon-procedure.md`](../docs/phk2-first-silicon-procedure.md).

The BSCAN primitive simulation stub is not an FPGA model. The core stub produces no valid PHK2 cryptographic results. Only the Python software emulator runs the authoritative host golden fixture. Physical access is disabled.
