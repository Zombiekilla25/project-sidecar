# PHK2 board/core contract

The board transport owns BSCAN/TCK framing, CRC, command decoding, and the async input/result FIFOs. The PHK2 core contract is entirely in `core_clk`; no TCK signal crosses into the compute boundary. The async FIFOs remain the only bulk CDC boundary. Reset is synchronous active-high in the core domain; `reset_req` is the decoded reset operation and is ORed into `core_rst`.

The machine-readable contract is [`../handoff/phk2-core-board-contract-v1.json`](../handoff/phk2-core-board-contract-v1.json). Descriptor and result payloads are 896 bits (112 bytes). Job identity is the full 64-bit generation fence plus full 256-bit job key. Range identity additionally includes a 16-bit range ID. Range count is 1–64. Result payload is generation, range ID, slot, row/column tile, 256-bit raw result, and 512-bit canonical result. No internal operand arrays are exposed.

Every request/result channel uses valid/ready. Payloads remain stable until handshake. The board makes no fixed-latency assumption. The adapter passes busy/result-ready/error/stale/abort status, latches stale identity failures, locally rejects mismatched range/abort requests, and drains/discards results whose generation/range identity does not match the active request.

The test-only `phk2_core_stub` has a command/opcode interface coupled to the board decoder. It is not a physical core binding. Its complete ports and reset/valid-ready behavior are recorded in [`../handoff/PHK2_STUB_INTERFACE.json`](../handoff/PHK2_STUB_INTERFACE.json).

The latest locally committed core source inspected is `c4ec217a9073ba05f6826601e94680e067c495b7`, module `phk2_core_synth_top`. Its measured wrapper exposes single-item operand-valid/ready, candidate-valid/ready, transcript, and status ports. It has no 112-byte descriptor handshake, range/count/range-ID transaction interface, or 112-byte result record. It therefore cannot bind directly. The exact inventory and incompatibility list are in [`../handoff/PHK2_CURRENT_CORE_INTERFACE.json`](../handoff/PHK2_CURRENT_CORE_INTERFACE.json). A wrapper around that datapath or the forthcoming timing-qualified core is required.

The adapter itself has no independent clock. The board-side integration must connect it only after the decoder/FIFO read domain is already `core_clk`; do not synchronize multibit payloads with individual synchronizer flops. Use the existing async FIFO for transport-domain crossings.

## Verification

Run `python3 tools/verify_phk2_core_contract.py`, the `tb_core_contract_adapter` Icarus test, and `tools/phk2_host/core_contract_qualify.py` with the project BLAKE3 environment. A future timing-core handoff must pass `tools/qualify_phk2_core_binding.py`; the manifest must bind the exact source commit and hashes, target timing report, and a binding testbench. The current core dry import is intentionally reported as incompatible rather than coerced into the interface.
