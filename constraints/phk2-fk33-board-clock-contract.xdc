# Evidence-derived FK33 differential board clock contract.
# Source: qualified PHK1 routed board XDC and independent routed Stage 4A XDC.
# This fragment is not yet applied to a PHK2 top: this worktree has no
# PHK2-specific BSCAN/CDC board top.
set_property PACKAGE_PIN BC26 [get_ports clk_p]
set_property PACKAGE_PIN BC27 [get_ports clk_n]
set_property IOSTANDARD LVDS [get_ports {clk_p clk_n}]
create_clock -name clk200_input -period 5.000 [get_ports clk_p]
