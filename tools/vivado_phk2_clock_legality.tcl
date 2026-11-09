# Vivado 2026.1 legality check for the exact PHK2 clock generator RTL.
# Clock-shell-only synthesis; this is not the integrated board-core synthesis.
set out_dir "results/phk2-fk33-clock-legality"
file mkdir $out_dir
create_project -in_memory -part xcvu33p-fsvh2104-2-e
read_verilog {rtl/phk2_board/phk2_fk33_clockgen.sv rtl/phk2_board/phk2_pll_reset_release.sv tests/phk2_board/phk2_clock_legality_top.sv}
read_xdc constraints/phk2-fk33-board-clock-contract.xdc
synth_design -top phk2_clock_legality_top -part xcvu33p-fsvh2104-2-e -flatten_hierarchy none
report_clocks -file [file join $out_dir clocks.rpt]
report_clock_utilization -file [file join $out_dir utilization.rpt]
report_drc -file [file join $out_dir drc.rpt]
check_timing -verbose -file [file join $out_dir timing.rpt]
exit
