# READ-ONLY post-route report capture for PHK2 CDC-11/reset review.
# Invocation inside Vivado 2026.1 Tcl console after route has completed:
#   source tools/vivado_phk2_cdc11_readonly.tcl
#   phk2_cdc11_readonly_capture /evidence/v4_routed.dcp /evidence/v4_cdc
# This script opens the supplied routed checkpoint and runs reports only. It
# does not launch, resume, modify, or save an implementation run/checkpoint.

proc phk2_cdc11_readonly_capture {routed_dcp output_dir} {
  if {![file isfile $routed_dcp]} {
    error "routed checkpoint is not a file: $routed_dcp"
  }
  if {[file exists $output_dir]} {
    error "refusing to overwrite evidence directory: $output_dir"
  }
  file mkdir $output_dir
  open_checkpoint $routed_dcp

  report_cdc -details -file [file join $output_dir cdc_default.rpt]
  report_cdc -all_checks_per_endpoint -details -file [file join $output_dir cdc_all_checks_per_endpoint.rpt]
  report_timing_summary -check_timing_verbose -file [file join $output_dir timing_summary.rpt]
  report_clock_interaction -file [file join $output_dir clock_interaction.rpt]
  report_clocks -file [file join $output_dir clock_inventory.rpt]
  report_exceptions -coverage -file [file join $output_dir exceptions_coverage.rpt]
  report_exceptions -ignored -file [file join $output_dir exceptions_ignored.rpt]
  report_exceptions -ignored_objects -file [file join $output_dir exceptions_ignored_objects.rpt]
  report_property -all [get_clocks *] -file [file join $output_dir clocks_properties.rpt]

  set async_control_pins [get_pins -hier -filter {REF_PIN_NAME == CLR || REF_PIN_NAME == PRE}]
  if {[llength $async_control_pins] == 0} {
    error "no mapped asynchronous CLR/PRE pins found; cannot claim recovery/removal review"
  }
  report_timing -to $async_control_pins -delay_type min_max -max_paths 10000 \
    -nworst 10000 -file [file join $output_dir async_recovery_removal_paths.rpt]
  report_timing -user_ignored -to $async_control_pins -delay_type min_max -max_paths 10000 \
    -nworst 10000 -file [file join $output_dir async_control_ignored_paths.rpt]

  set async_cells [get_cells -hier -filter {ASYNC_REG == TRUE}]
  report_property -all $async_cells -file [file join $output_dir async_reg_cells_properties.rpt]
  puts "PHK2_CDC11_READONLY_CAPTURE=COMPLETE"
  puts "CHECKPOINT_SHA256_REQUIRED=sha256sum $routed_dcp"
  puts "REPORT_OUTPUT_DIR=$output_dir"
}
