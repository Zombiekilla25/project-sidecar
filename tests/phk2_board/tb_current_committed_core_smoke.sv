`timescale 1ns/1ps
module tb_current_committed_core_smoke;
  reg clk=0; always #5 clk=~clk;
  reg rst=1;
  wire busy,overflow; wire [31:0] stale_candidate_count;
  phk2_core_synth_top dut(.clk(clk),.rst(rst),.busy(busy),.overflow(overflow),
                           .stale_candidate_count(stale_candidate_count));
  initial begin
    repeat(4) @(negedge clk); rst=0;
    repeat(4) @(negedge clk);
    if (busy !== 1'b0) $fatal(1,"core busy did not clear after reset");
    $display("COMMITTED_CORE_SMOKE=PASS");
    $finish;
  end
endmodule
