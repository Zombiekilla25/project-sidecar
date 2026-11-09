# PHK2 FK33 board integration v1

This host-side integration freezes the compact command protocol and provides a synthesizable BSCAN/top skeleton. The core module is deliberately a stub; replace it with timing-qualified PHK2 RTL at the documented interface. No generated operands cross the host boundary: one LOAD_DESCRIPTOR carries exactly 112 production descriptor bytes, and START_RANGE carries generation, job key, start index, count, and range id.

## PHK1 transport reference captured

The reference inventory and SHA256 values are in `handoff/PHK1_TRANSPORT_SOURCE_SHA256.json`. It captures PHK1 USER2 LSB-first input, USER1 LSB-first output, USER3 status/control, Gray-pointer asynchronous FIFOs, two-flop status/abort synchronizers, synchronized reset deassertion, MPSSE exact reads/writes, <=512-byte bounded read draining, and the target runner's user-scan abstraction. The offline transport qualification was PASS. Candidate metadata explicitly records `physical_protocol_qualified:false`; this handoff does not claim physical USER-chain qualification. PHK1 source trees are untouched.

## Frozen protocol

Machine-readable definition: `protocol/phk2-board-v1.json`.

Every message is a byte stream frame: `C2 5A | version:u8 | opcode:u8 | flags:u8 | reserved:u8 | sequence:u16le | payload_bytes:u16le | payload | crc32:u32le`. CRC is CRC-32/ISO-HDLC over header and payload, little-endian on wire. Version is 1 and reserved is zero. Responses set opcode bit 7 and response flag bit 0; error responses also set flag bit 1. Unknown opcodes, invalid lengths, CRC errors, and nonzero reserved bits are rejected.

| Command | Opcode | Request payload |
|---|---:|---|
| HELLO | 0x01 | empty |
| LOAD_DESCRIPTOR | 0x10 | exact 112-byte frozen production descriptor |
| START_RANGE | 0x11 | 48 bytes: generation u64, job key 32 bytes, start index u32, count u16, range id u16 |
| STATUS | 0x12 | generation u64, range id u16 |
| READ_RESULT | 0x13 | generation u64, job key 32 bytes, range id u16, first slot u16, max records u16 |
| ABORT | 0x14 | generation u64, job key 32 bytes, range id u16 |
| RESET | 0x1f | empty |

Batch count is 1..64. LOAD_DESCRIPTOR transmits only the production descriptor; generation/job identity is derived from its frozen fields by host and device contract. Result record is 112 bytes: generation u64, range id u16, slot u16, row u16, column u16, raw result 32 bytes, canonical result 64 bytes. Four records plus framing is 462 bytes and fits the 512-byte maximum drain. Larger ranges use repeated bounded reads.

## USER chains and flow control

USER2 is the byte-stream command/input chain; USER3 is a separately captured status/control chain; USER1 is the result/output byte stream. The split avoids PHK1's combined status ambiguity. USER3 low bits independently indicate busy, result_ready, error, stale_job, overflow, and aborted. USER3 also carries bounded FIFO occupancy/capacity and error code in the protocol status response. The host observes ready/occupancy and drains result data in bounded chunks; it never uses blind fixed sleeps. USB/MPSSE reads are capped at 512 bytes. Sequence numbers correlate responses, and timeout does not trigger an implicit duplicate command.

## SystemVerilog integration

`rtl/phk2_board/phk2_fk33_board_top.sv` exposes only the existing differential package clock pair (`TOP_LEVEL_PACKAGE_IO_COUNT=2`). BSCAN pins, descriptor, operands, and result buses are internal. USER2 input and USER1 output pass through asynchronous FIFOs; USER3 status flags use two-flop synchronizers. Reset assertion is asynchronous into FIFO domains and deassertion is synchronized locally. The portable FIFO simulation model uses Gray pointers and two-stage pointer synchronization; synthesis selects Xilinx XPM asynchronous FIFO. Integrators must map XPM parameters to the target device/version and run vendor CDC/implementation checks when allowed.

The interface stub in `phk2_core_stub.sv` only models control/status and emits a zero-valued record. It is not a computational model and is not a candidate bitstream. Replace it with the qualified RTL while preserving the command and result handshakes. `phk2_protocol_decoder.sv` checks framing, length, and CRC before command acceptance.

## Offline qualification

Run `PYTHONPATH=tools/phk2_host .venv/bin/python tools/phk2_host/board_qualify.py` and compile/run the Icarus bench as shown in `docs/phk2-first-silicon-procedure.md`. The software emulator implements the same protocol and delegates authoritative results to the frozen CPU oracle. The BSCAN primitive stub only permits offline elaboration; no physical transport command is enabled.
