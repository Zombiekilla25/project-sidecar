# PHK2 first-silicon procedure

This procedure is prepared for a future physically qualified PHK2 image. Live execution is intentionally disabled in this worktree. Do not use this document as authorization to program hardware.

1. Confirm the routed image identity and physical qualification record, host adapter identity, and board/USB target identity. Record all identities in PHK2 Evidence-v1.
2. Connect through the selected transport adapter and issue **HELLO once**. Require protocol version and descriptor length 112 to match this contract.
3. Issue **LOAD_DESCRIPTOR once** with the exact frozen production descriptor. Confirm accepted generation/job identity in status.
4. For the first silicon transaction, issue **START_RANGE count=1** with the descriptor generation/job identity and a unique range id.
5. Poll **STATUS** based on ready/busy/error and FIFO occupancy. Use a bounded deadline and transport timeout. Do not use blind fixed sleeps.
6. Once result_ready is independently asserted, issue **READ_RESULT** for one record. Enforce the 112-byte record format and exact sequence/range/slot identity.
7. Run the CPU golden oracle for the same descriptor/range. Require raw and canonical result equality and preserve status/result traces and timing fields in Evidence-v1.
8. Exercise ABORT and recovery on a nonproduction fixture, then RESET and confirm flags/occupancies clear.
9. Only after successful single-item silicon qualification, run batch64 with bounded result drains, per-record CPU comparison, and structured performance timing.

The local offline simulator command is `iverilog -g2012 -DPHK2_SIM -s tb_phk2_board -o /tmp/phk2_board_tb rtl/phk2_board/phk2_async_fifo.sv rtl/phk2_board/phk2_protocol_decoder.sv rtl/phk2_board/phk2_core_stub.sv rtl/phk2_board/phk2_fk33_board_top.sv tests/phk2_board/bscan_stub.sv tests/phk2_board/tb_phk2_board.sv && vvp /tmp/phk2_board_tb`. Host mock qualification is `PYTHONPATH=tools/phk2_host .venv/bin/python tools/phk2_host/board_qualify.py`. The physical adapter remains disabled.
