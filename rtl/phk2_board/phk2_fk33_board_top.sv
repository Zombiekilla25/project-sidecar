`timescale 1ns/1ps
// Minimal FK33 package shell. Only the existing differential clock pair is exposed.
module phk2_fk33_board_top(input wire clk_p,input wire clk_n);
 wire core_clk,core_rst;
`ifdef PHK2_SIM
 reg [3:0] sim_reset_pipe=0;
 always @(posedge clk_p) sim_reset_pipe<={sim_reset_pipe[2:0],1'b1};
 assign core_clk=clk_p; assign core_rst=~sim_reset_pipe[3];
`else
 wire clk200; IBUFDS #(.DIFF_TERM("TRUE"),.IBUF_LOW_PWR("FALSE")) u_clk(.I(clk_p),.IB(clk_n),.O(clk200));
 BUFGCE_DIV #(.BUFGCE_DIVIDE(2),.IS_CE_INVERTED(1'b0),.IS_CLR_INVERTED(1'b0),.IS_I_INVERTED(1'b0),.SIM_DEVICE("ULTRASCALE_PLUS")) u_core_clk(.I(clk200),.CE(1'b1),.CLR(1'b0),.O(core_clk));
 reg [3:0] reset_pipe=0; always @(posedge core_clk) reset_pipe<={reset_pipe[2:0],1'b1}; assign core_rst=~reset_pipe[3];
`endif
 wire c1,d1,r1,rt1,s1,sh1,tck1,tdi1,tms1,u1; wire c2,d2,r2,rt2,s2,sh2,tck2,tdi2,tms2,u2; wire c3,d3,r3,rt3,s3,sh3,tck3,tdi3,tms3,u3;
 wire tdo1,tdo3; wire tdo2=1'b0;
 BSCANE2 #(.JTAG_CHAIN(1)) u_user1(.CAPTURE(c1),.DRCK(d1),.RESET(r1),.RUNTEST(rt1),.SEL(s1),.SHIFT(sh1),.TCK(tck1),.TDI(tdi1),.TMS(tms1),.UPDATE(u1),.TDO(tdo1));
 BSCANE2 #(.JTAG_CHAIN(2)) u_user2(.CAPTURE(c2),.DRCK(d2),.RESET(r2),.RUNTEST(rt2),.SEL(s2),.SHIFT(sh2),.TCK(tck2),.TDI(tdi2),.TMS(tms2),.UPDATE(u2),.TDO(tdo2));
 BSCANE2 #(.JTAG_CHAIN(3)) u_user3(.CAPTURE(c3),.DRCK(d3),.RESET(r3),.RUNTEST(rt3),.SEL(s3),.SHIFT(sh3),.TCK(tck3),.TDI(tdi3),.TMS(tms3),.UPDATE(u3),.TDO(tdo3));
 (* ASYNC_REG="TRUE",SHREG_EXTRACT="NO" *) reg [1:0] rst1=2'b11,rst2=2'b11,rst3=2'b11;
 always @(posedge tck1 or posedge core_rst)if(core_rst)rst1<=2'b11;else rst1<={rst1[0],1'b0};
 always @(posedge tck2 or posedge core_rst)if(core_rst)rst2<=2'b11;else rst2<={rst2[0],1'b0};
 always @(posedge tck3 or posedge core_rst)if(core_rst)rst3<=2'b11;else rst3<={rst3[0],1'b0};
 reg [7:0] rx_shift=0; reg [2:0] rx_bits=0; wire rx_full,rx_empty,rx_rd; wire [7:0] rx_data; wire [9:0] rx_wc,rx_rc; wire [7:0] rx_complete={tdi2,rx_shift[6:0]}; wire rx_byte_fire=sh2&&(rx_bits==3'd7);
 always @(posedge d2 or posedge rst2[1])if(rst2[1])begin rx_shift<=0;rx_bits<=0;end else if(c2)rx_bits<=0;else if(sh2)begin rx_shift[rx_bits]<=tdi2;if(rx_bits==7)rx_bits<=0;else rx_bits<=rx_bits+1'b1;end
 phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(9)) input_fifo(.wr_clk(d2),.wr_arst(rst2[1]),.wr_en(rx_byte_fire&&!rx_full),.wr_data(rx_complete),.wr_full(rx_full),.wr_count(rx_wc),.rd_clk(core_clk),.rd_arst(core_rst),.rd_en(rx_rd),.rd_data(rx_data),.rd_empty(rx_empty),.rd_count(rx_rc));
 wire cmd_valid,cmd_ready,decoder_ready,decoder_error; wire [7:0] cmd_opcode,decoder_error_code; wire [15:0] cmd_sequence,cmd_length; wire [112*8-1:0] cmd_payload;
 assign rx_rd=!rx_empty&&decoder_ready;
 phk2_protocol_decoder decoder(.clk(core_clk),.rst(core_rst),.byte_valid(!rx_empty),.byte_ready(decoder_ready),.byte_data(rx_data),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(cmd_opcode),.cmd_sequence(cmd_sequence),.cmd_length(cmd_length),.cmd_payload(cmd_payload),.sticky_error(decoder_error),.error_code(decoder_error_code));
 wire busy,result_ready,error,stale_job,overflow,aborted,result_valid,result_rd,hello_seen,descriptor_loaded; wire [7:0] result_byte,error_code; wire result_full,result_empty; wire [9:0] result_wc,result_rc; wire [7:0] result_data;
 phk2_core_stub core_stub(.clk(core_clk),.rst(core_rst),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(cmd_opcode),.cmd_length(cmd_length),.cmd_payload(cmd_payload),.busy(busy),.result_ready(result_ready),.error(error),.hello_seen(hello_seen),.descriptor_loaded(descriptor_loaded),.stale_job(stale_job),.overflow(overflow),.aborted(aborted),.input_overflow(rx_full),.result_valid(result_valid),.result_ready_i(!result_full),.result_byte(result_byte),.error_code(error_code));
 phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(9)) result_fifo(.wr_clk(core_clk),.wr_arst(core_rst),.wr_en(result_valid&&!result_full),.wr_data(result_byte),.wr_full(result_full),.wr_count(result_wc),.rd_clk(d1),.rd_arst(rst1[1]),.rd_en(result_rd),.rd_data(result_data),.rd_empty(result_empty),.rd_count(result_rc));
 reg [7:0] tx_shift=0; reg [2:0] tx_bits=0; assign tdo1=tx_shift[0]; assign result_rd=c1&&!result_empty;
 always @(posedge d1 or posedge rst1[1])if(rst1[1])begin tx_shift<=0;tx_bits<=0;end else if(c1)begin tx_bits<=0;tx_shift<=result_empty?8'h00:result_data;end else if(sh1)begin tx_shift<={1'b0,tx_shift[7:1]};if(tx_bits==7)begin tx_bits<=0;if(!result_empty)tx_shift<=result_data;end else tx_bits<=tx_bits+1'b1;end
 (* ASYNC_REG="TRUE",SHREG_EXTRACT="NO" *) reg [5:0] stat_s1=0,stat_s2=0; reg [31:0] stat_shift=0; reg [5:0] status_flags;
 always @* begin status_flags=0;status_flags[0]=busy;status_flags[1]=result_ready;status_flags[2]=error|decoder_error;status_flags[3]=stale_job;status_flags[4]=overflow|rx_full|result_full;status_flags[5]=aborted;end
 always @(posedge tck3 or posedge rst3[1])if(rst3[1])begin stat_s1<=0;stat_s2<=0;stat_shift<=0;end else begin stat_s1<=status_flags;stat_s2<=stat_s1;if(c3)stat_shift<={26'b0,stat_s2};else if(sh3)stat_shift<={1'b0,stat_shift[31:1]};end
 assign tdo3=stat_shift[0];
endmodule
