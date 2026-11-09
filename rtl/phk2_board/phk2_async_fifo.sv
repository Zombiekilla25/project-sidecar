`timescale 1ns/1ps
// PHK2 async FIFO wrapper: XPM in FPGA builds, Gray-pointer model in RTL sim.
module phk2_async_fifo #(parameter integer WIDTH=8, parameter integer ADDR_BITS=9)(
 input wire wr_clk,input wire wr_arst,input wire wr_en,input wire [WIDTH-1:0] wr_data,output wire wr_full,output wire [ADDR_BITS:0] wr_count,
 input wire rd_clk,input wire rd_arst,input wire rd_en,output wire [WIDTH-1:0] rd_data,output wire rd_empty,output wire [ADDR_BITS:0] rd_count);
 localparam integer DEPTH=(1<<ADDR_BITS);
`ifdef SYNTHESIS
 wire [WIDTH-1:0] dout; wire [ADDR_BITS:0] wc,rc; wire unused_wr_busy,unused_rd_busy;
 xpm_fifo_async #(.CDC_SYNC_STAGES(2),.DOUT_RESET_VALUE("0"),.ECC_MODE("no_ecc"),.FIFO_MEMORY_TYPE("auto"),.FIFO_READ_LATENCY(0),.FIFO_WRITE_DEPTH(DEPTH),.FULL_RESET_VALUE(0),.PROG_EMPTY_THRESH(4),.PROG_FULL_THRESH(DEPTH-4),.RD_DATA_COUNT_WIDTH(ADDR_BITS+1),.READ_DATA_WIDTH(WIDTH),.READ_MODE("fwft"),.RELATED_CLOCKS(0),.SIM_ASSERT_CHK(1),.USE_ADV_FEATURES("0707"),.WAKEUP_TIME(0),.WRITE_DATA_WIDTH(WIDTH),.WR_DATA_COUNT_WIDTH(ADDR_BITS+1)) fifo_i(
 .almost_empty(),.almost_full(),.data_valid(),.dbiterr(),.dout(dout),.empty(rd_empty),.full(wr_full),.overflow(),.prog_empty(),.prog_full(),.rd_data_count(rc),.rd_rst_busy(unused_rd_busy),.sbiterr(),.underflow(),.wr_ack(),.wr_data_count(wc),.wr_rst_busy(unused_wr_busy),.din(wr_data),.injectdbiterr(1'b0),.injectsbiterr(1'b0),.rd_clk(rd_clk),.rd_en(rd_en),.rst(wr_arst|rd_arst),.sleep(1'b0),.wr_clk(wr_clk),.wr_en(wr_en));
 assign rd_data=dout; assign wr_count=wc; assign rd_count=rc;
`else
 reg [WIDTH-1:0] mem[0:DEPTH-1]; reg [ADDR_BITS:0] wbin=0,wgray=0,rbin=0,rgray=0;
 (* ASYNC_REG="TRUE",SHREG_EXTRACT="NO" *) reg [ADDR_BITS:0] rgray_w1=0,rgray_w2=0,wgray_r1=0,wgray_r2=0;
 (* ASYNC_REG="TRUE",SHREG_EXTRACT="NO" *) reg [1:0] wr_reset_pipe=2'b11,rd_reset_pipe=2'b11;
 always @(posedge wr_clk or posedge wr_arst) if(wr_arst)wr_reset_pipe<=2'b11;else wr_reset_pipe<={wr_reset_pipe[0],1'b0};
 always @(posedge rd_clk or posedge rd_arst) if(rd_arst)rd_reset_pipe<=2'b11;else rd_reset_pipe<={rd_reset_pipe[0],1'b0};
 wire wr_reset=wr_reset_pipe[1],rd_reset=rd_reset_pipe[1];
 wire [ADDR_BITS:0] wnext=wbin+(wr_en&&!wr_full),rnext=rbin+(rd_en&&!rd_empty);
 wire [ADDR_BITS:0] wg_next=(wnext>>1)^wnext,rg_next=(rnext>>1)^rnext;
 assign wr_full=(wgray=={~rgray_w2[ADDR_BITS:ADDR_BITS-1],rgray_w2[ADDR_BITS-2:0]}); assign rd_empty=(rgray==wgray_r2); assign rd_data=mem[rbin[ADDR_BITS-1:0]];
 function [ADDR_BITS:0] gray_to_bin(input [ADDR_BITS:0] g); integer i; begin gray_to_bin[ADDR_BITS]=g[ADDR_BITS];for(i=ADDR_BITS-1;i>=0;i=i-1)gray_to_bin[i]=gray_to_bin[i+1]^g[i];end endfunction
 assign wr_count=wbin-gray_to_bin(rgray_w2); assign rd_count=gray_to_bin(wgray_r2)-rbin;
 always @(posedge wr_clk) if(wr_reset)begin wbin<=0;wgray<=0;rgray_w1<=0;rgray_w2<=0;end else begin rgray_w1<=rgray;rgray_w2<=rgray_w1;if(wr_en&&!wr_full)begin mem[wbin[ADDR_BITS-1:0]]<=wr_data;wbin<=wnext;wgray<=wg_next;end end
 always @(posedge rd_clk) if(rd_reset)begin rbin<=0;rgray<=0;wgray_r1<=0;wgray_r2<=0;end else begin wgray_r1<=wgray;wgray_r2<=wgray_r1;if(rd_en&&!rd_empty)begin rbin<=rnext;rgray<=rg_next;end end
`endif
endmodule
