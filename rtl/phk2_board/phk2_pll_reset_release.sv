`timescale 1ns/1ps
// Asynchronously assert reset when PLL lock is lost; release synchronously
// after four valid core-clock edges.
module phk2_pll_reset_release(input wire core_clk,input wire pll_locked,output wire core_rst);
 (* ASYNC_REG="TRUE",SHREG_EXTRACT="NO" *) reg [3:0] release_pipe=4'b0000;
 always @(posedge core_clk or negedge pll_locked)
   if(!pll_locked) release_pipe<=4'b0000; else release_pipe<={release_pipe[2:0],1'b1};
 assign core_rst=~release_pipe[3];
endmodule
