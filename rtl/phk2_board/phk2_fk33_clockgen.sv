`timescale 1ns/1ps
// PHK2-specific 175 MHz core clock derived from the authoritative FK33 200 MHz
// differential board reference. This is a new PHK2 clock choice, not inherited
// PHK1 clock qualification.
module phk2_fk33_clockgen(input wire clk_p,input wire clk_n,output wire core_clk,output wire core_rst);
 wire clk200,pll_fb,pll_fb_buf,pll_core_unbuf,pll_locked;
 IBUFDS #(.DIFF_TERM("TRUE"),.IBUF_LOW_PWR("FALSE")) u_clk(.I(clk_p),.IB(clk_n),.O(clk200));
 // 200 MHz / DIVCLK(2) * FBMULT(14) / CLKOUT0_DIVIDE(8) = 175 MHz.
 PLLE4_ADV #(.CLKFBOUT_MULT(14),.DIVCLK_DIVIDE(2),.CLKOUT0_DIVIDE(8),.CLKIN_PERIOD(5.000),
             .CLKOUT0_DUTY_CYCLE(0.5),.CLKOUT0_PHASE(0.0),.STARTUP_WAIT("FALSE")) u_phk2_pll(
   .CLKIN(clk200),.CLKFBIN(pll_fb_buf),.CLKOUTPHYEN(1'b0),
   .CLKFBOUT(pll_fb),.CLKOUT0(pll_core_unbuf),.CLKOUT0B(),.CLKOUT1(),.CLKOUT1B(),.CLKOUTPHY(),
   .DADDR(7'b0),.DCLK(1'b0),.DEN(1'b0),.DI(16'b0),.DWE(1'b0),
   .DO(),.DRDY(),.LOCKED(pll_locked),.PWRDWN(1'b0),.RST(1'b0));
 BUFG u_pll_feedback(.I(pll_fb),.O(pll_fb_buf));
 BUFG u_core_clock(.I(pll_core_unbuf),.O(core_clk));
 phk2_pll_reset_release reset_release(.core_clk(core_clk),.pll_locked(pll_locked),.core_rst(core_rst));
endmodule
