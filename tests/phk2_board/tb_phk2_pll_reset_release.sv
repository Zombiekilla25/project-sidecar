`timescale 1ns/1ps
module tb_phk2_pll_reset_release;
 reg clk=0,locked=0;always #5 clk=~clk;wire rst;integer checks=0;
 phk2_pll_reset_release dut(.core_clk(clk),.pll_locked(locked),.core_rst(rst));
 initial begin
  #1;if(!rst)$fatal(1,"reset must assert before lock");checks=checks+1;
  locked=1;
  repeat(3)begin @(posedge clk);#1;if(!rst)$fatal(1,"reset released before four stable clock edges");end
  @(posedge clk);#1;if(rst)$fatal(1,"reset did not release after four locked edges");checks=checks+1;
  #1 locked=0;#1;if(!rst)$fatal(1,"lock loss did not asynchronously assert reset");checks=checks+1;
  locked=1;
  repeat(3)begin @(posedge clk);#1;if(!rst)$fatal(1,"reset released too early after relock");end
  @(posedge clk);#1;if(rst)$fatal(1,"reset did not release after relock");checks=checks+1;
  $display("CLOCK_STARTUP_RESET_TESTS=%0d/4",checks);$finish;
 end
endmodule
