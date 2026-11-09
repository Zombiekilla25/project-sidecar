`timescale 1ns/1ps
module tb_phk2_board;
 reg clk=0,tck=0; always #5 clk=~clk; always #7 tck=~tck;
 reg rst=1; reg byte_valid=0;reg [7:0] byte_data=0;wire byte_ready;wire cmd_valid,cmd_ready;wire [7:0] opcode;wire [15:0] seq,len;wire [112*8-1:0] payload;wire sticky;wire [7:0] dec_error;
 wire busy,result_ready,core_error,stale,overflow,aborted,result_valid,hello_seen,descriptor_loaded;wire [7:0] result_byte,core_error_code;reg input_overflow=0;reg result_ready_i=1;integer result_bytes=0,passed=0;
 phk2_protocol_decoder decoder(.clk(clk),.rst(rst),.byte_valid(byte_valid),.byte_ready(byte_ready),.byte_data(byte_data),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(opcode),.cmd_sequence(seq),.cmd_length(len),.cmd_payload(payload),.sticky_error(sticky),.error_code(dec_error));
 phk2_core_stub core(.clk(clk),.rst(rst),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(opcode),.cmd_length(len),.cmd_payload(payload),.busy(busy),.result_ready(result_ready),.error(core_error),.stale_job(stale),.overflow(overflow),.aborted(aborted),.input_overflow(input_overflow),.result_valid(result_valid),.result_ready_i(result_ready_i),.result_byte(result_byte),.error_code(core_error_code),.hello_seen(hello_seen),.descriptor_loaded(descriptor_loaded));
 always @(posedge clk) if(result_valid&&result_ready_i) result_bytes<=result_bytes+1;
 phk2_fk33_board_top board_shell(.clk_p(clk),.clk_n(~clk));
 reg fifo_wr=0,fifo_rd=0;reg [7:0] fifo_in=0;wire fifo_full,fifo_empty;wire [7:0] fifo_out;wire [2:0] fifo_wc,fifo_rc;
 phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(2)) cdc_fifo(.wr_clk(clk),.wr_arst(rst),.wr_en(fifo_wr),.wr_data(fifo_in),.wr_full(fifo_full),.wr_count(fifo_wc),.rd_clk(tck),.rd_arst(rst),.rd_en(fifo_rd),.rd_data(fifo_out),.rd_empty(fifo_empty),.rd_count(fifo_rc));
 function [31:0] crc_byte(input [31:0] ci,input [7:0] data);integer b;reg [31:0] c;begin c=ci^data;for(b=0;b<8;b=b+1)c=c[0]?(c>>1)^32'hedb88320:(c>>1);crc_byte=c;end endfunction
 task send_byte(input [7:0] v);begin @(negedge clk);byte_data=v;byte_valid=1;@(posedge clk);while(!byte_ready)@(posedge clk);@(negedge clk);byte_valid=0;end endtask
 task send_frame(input [7:0] op,input integer plen,input [112*8-1:0] pld,input [15:0] sn);integer i;reg [7:0] b;reg [31:0] c;begin
  c=32'hffffffff;b=8'hc2;send_byte(b);c=crc_byte(c,b);b=8'h5a;send_byte(b);c=crc_byte(c,b);b=1;send_byte(b);c=crc_byte(c,b);b=op;send_byte(b);c=crc_byte(c,b);b=0;send_byte(b);c=crc_byte(c,b);send_byte(0);c=crc_byte(c,0);b=sn[7:0];send_byte(b);c=crc_byte(c,b);b=sn[15:8];send_byte(b);c=crc_byte(c,b);b=plen[7:0];send_byte(b);c=crc_byte(c,b);b=plen[15:8];send_byte(b);c=crc_byte(c,b);
  for(i=0;i<plen;i=i+1)begin b=pld[i*8+:8];send_byte(b);c=crc_byte(c,b);end c=~c;for(i=0;i<4;i=i+1)send_byte(c[i*8+:8]);repeat(2)@(posedge clk);
 end endtask
 reg [112*8-1:0] desc,range_p,read_p,abort_p;integer i;
 initial begin
  repeat(4)@(posedge clk);rst=0;repeat(4)@(posedge clk);
  desc=0;desc[0+:8]=8'haa;desc[256+:64]=64'd1;
  send_frame(8'h01,0,0,1);if(!hello_seen)$fatal(1,"HELLO not accepted");passed=passed+1;
  send_frame(8'h10,112,desc,2);if(!descriptor_loaded||core_error)$fatal(1,"descriptor not accepted");passed=passed+1;
  range_p=0;range_p[0+:64]=1;range_p[64+:256]=desc[0+:256];range_p[352+:16]=64;range_p[368+:16]=9;
  send_frame(8'h11,48,range_p,3);if(!busy)$fatal(1,"range did not enter busy");passed=passed+1;
  wait(result_ready);if(busy||!result_ready)$fatal(1,"busy/result_ready status wrong");send_frame(8'h12,10,0,4);passed=passed+1;
  read_p=0;read_p[0+:64]=1;read_p[64+:256]=desc[0+:256];read_p[320+:16]=9;read_p[352+:16]=1;
  result_bytes=0;send_frame(8'h13,46,read_p,5);wait(!result_valid);if(result_bytes!=112)$fatal(1,"expected 112 result bytes got %0d",result_bytes);passed=passed+1;
  abort_p=0;abort_p[0+:64]=1;abort_p[64+:256]=desc[0+:256];abort_p[320+:16]=9;send_frame(8'h14,44,abort_p,6);if(!aborted||result_ready)$fatal(1,"abort status wrong");passed=passed+1;
  send_frame(8'h1f,0,0,7);if(descriptor_loaded||aborted||core_error)$fatal(1,"reset did not clear status");passed=passed+1;
  for(i=0;i<4;i=i+1)begin @(negedge clk);fifo_in=i+8'h40;fifo_wr=1;@(negedge clk);fifo_wr=0;end
  repeat(4)@(posedge clk);if(!fifo_full||fifo_wc!=4)$fatal(1,"FIFO full/occupancy not visible");passed=passed+1;
  for(i=0;i<4;i=i+1)begin wait(!fifo_empty);if(fifo_out!=(i+8'h40))$fatal(1,"CDC FIFO order mismatch");@(negedge tck);fifo_rd=1;@(negedge tck);fifo_rd=0;end
  repeat(4)@(posedge tck);if(!fifo_empty||fifo_rc!=0)$fatal(1,"FIFO empty/occupancy not visible");passed=passed+1;
  input_overflow=1;@(posedge clk);if(!overflow||!core_error)$fatal(1,"overflow/error bits not distinct");passed=passed+1;
  $display("PHK2_BOARD_RTL_TESTS=%0d/10",passed);if(passed!=10)$fatal(1,"RTL test count mismatch");$finish;
 end
endmodule
