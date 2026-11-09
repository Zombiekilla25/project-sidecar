# RTL elaboration and vendor CDC review only. This is not mapped board synthesis.
set out_dir "results/phk2-fk33-rtl-review"
file mkdir $out_dir
create_project -in_memory -part xcvu33p-fsvh2104-2-e
read_verilog -sv {
  rtl/phk2_board/phk2_protocol_decoder.sv
  rtl/phk2_board/phk2_protocol_response_encoder.sv
  rtl/phk2_board/phk2_async_fifo.sv
  rtl/phk2_board/phk2_real_core_endpoint.sv
  rtl/phk2_board/phk2_core_contract_adapter.sv
  rtl/phk2_board/phk2_fk33_clockgen.sv
  rtl/phk2_board/phk2_pll_reset_release.sv
  rtl/phk2_board/phk2_fk33_board_top.sv
  rtl/phk2_board/phk2_core/phk2_blake3_keyed_block_seq.sv
  rtl/phk2_board/phk2_core/phk2_philox4x32_10_seq.sv
  rtl/phk2_board/phk2_core/phk2_production_operand_seq.sv
  rtl/phk2_board/phk2_core/phk2_tile_adapter.sv
  rtl/phk2_board/phk2_core/phk2_compact_result.sv
  rtl/phk2_board/phk2_core/phk2_result_filter.sv
  rtl/phk2_board/phk2_core/phk2_timing_core_contract.sv
  rtl/phk2_board/phk2_core/vendor_phk1/packed_mul2.sv
  rtl/phk2_board/phk2_core/vendor_phk1/packed_tile.sv
}
read_xdc constraints/phk2-fk33-board-clock-contract.xdc
synth_design -rtl -top phk2_fk33_board_top -part xcvu33p-fsvh2104-2-e -flatten_hierarchy none
report_drc -file [file join $out_dir drc.rpt]
report_clocks -file [file join $out_dir clocks.rpt]
report_io -file [file join $out_dir io.rpt]
puts "RTL elaboration reports complete. report_cdc/check_timing are deferred: Vivado 2026.1 requires a mapped synthesized design."
exit
