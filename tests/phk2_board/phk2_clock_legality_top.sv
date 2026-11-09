// Clock-only Vivado checker. The diagnostic divider is internal so the only
// package ports are the authoritative differential board reference pair.
module phk2_clock_legality_top(input wire clk_p,input wire clk_n);
 wire core_clk,core_rst;
 phk2_fk33_clockgen dut(.clk_p(clk_p),.clk_n(clk_n),.core_clk(core_clk),.core_rst(core_rst));
 (* KEEP="TRUE" *) reg [3:0] probe=0;
 always @(posedge core_clk or posedge core_rst)
   if(core_rst) probe<=0; else probe<=probe+1'b1;
endmodule
