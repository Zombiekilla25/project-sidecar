# PHK1 FK33 board shell constraints derived from the proven Stage4A FK33 shell.
# Device: xcvu33p-fsvh2104-2-e; differential board reference is 200 MHz.
set_property PACKAGE_PIN BC26 [get_ports clk_p]
set_property PACKAGE_PIN BC27 [get_ports clk_n]
set_property IOSTANDARD LVDS [get_ports {clk_p clk_n}]
create_clock -name clk200_input -period 5.000 [get_ports clk_p]

# Proven clock-region placements from the same board shell.
set_property LOC BUFGCE_DIV_X0Y7 [get_cells u_board_clk100]
set_property LOC PLL_X0Y2 [get_cells u_hbm_ref_pll]
set_property LOC PLL_X0Y3 [get_cells u_core_pll]
set_property LOC BUFGCE_X0Y28 [get_cells u_core_clk]

# Synchronizer first-stage exceptions only. BSCAN and compute data crossings
# use the PHK1 async FIFOs; no broad data-path false paths are declared here.
set_false_path -to [get_pins {board_ref_locked_sync_reg[0]/D}]
