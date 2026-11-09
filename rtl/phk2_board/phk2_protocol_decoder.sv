`timescale 1ns/1ps
// Request-frame decoder for PHK2 board protocol v1; max request payload 112 B.
module phk2_protocol_decoder #(parameter integer MAX_PAYLOAD=112)(input wire clk,input wire rst,input wire byte_valid,output wire byte_ready,input wire [7:0] byte_data,output reg cmd_valid,input wire cmd_ready,output reg [7:0] cmd_opcode,output reg [15:0] cmd_sequence,output reg [15:0] cmd_length,output reg [MAX_PAYLOAD*8-1:0] cmd_payload,output reg sticky_error,output reg [7:0] error_code);
 localparam integer HEADER_BYTES=10; reg [7:0] pos=0; reg [7:0] frame_mem[0:MAX_PAYLOAD+13]; reg [15:0] payload_len=0; reg [31:0] crc_state=32'hffffffff; reg [1:0] crc_bytes=0;
 assign byte_ready=!cmd_valid||cmd_ready;
 function [31:0] crc_byte(input [31:0] crc_in,input [7:0] data);integer b;reg [31:0] c;begin c=crc_in^data;for(b=0;b<8;b=b+1)c=c[0]?(c>>1)^32'hedb88320:(c>>1);crc_byte=c;end endfunction
 task parser_error(input [7:0] code);begin sticky_error<=1'b1;error_code<=code;pos<=0;payload_len<=0;crc_state<=32'hffffffff;crc_bytes<=0;end endtask
 always @(posedge clk) begin
  if(rst)begin pos<=0;payload_len<=0;crc_state<=32'hffffffff;crc_bytes<=0;cmd_valid<=0;cmd_opcode<=0;cmd_sequence<=0;cmd_length<=0;cmd_payload<=0;sticky_error<=0;error_code<=0;end
  else begin
   if(cmd_valid&&cmd_ready)cmd_valid<=0;
   if(byte_valid&&byte_ready) begin
    if(pos<HEADER_BYTES)begin
     frame_mem[pos]<=byte_data;crc_state<=crc_byte(crc_state,byte_data);
     if(pos==0&&byte_data!=8'hc2)parser_error(8'd1);
     else if(pos==1&&byte_data!=8'h5a)parser_error(8'd1);
     else if(pos==2&&byte_data!=8'd1)parser_error(8'd2);
     else if(pos==4&&byte_data!=0)parser_error(8'd3);
     else if(pos==5&&byte_data!=0)parser_error(8'd3);
     else if(pos==9)begin payload_len<={byte_data,frame_mem[8]};if({byte_data,frame_mem[8]}>MAX_PAYLOAD)parser_error(8'd4);else pos<=pos+1'b1;end
     else pos<=pos+1'b1;
    end else if(pos<HEADER_BYTES+payload_len)begin frame_mem[pos]<=byte_data;cmd_payload[(pos-HEADER_BYTES)*8 +:8]<=byte_data;crc_state<=crc_byte(crc_state,byte_data);pos<=pos+1'b1;end
    else begin frame_mem[pos]<=byte_data;if(crc_bytes==3)begin
      if({byte_data,frame_mem[pos-1],frame_mem[pos-2],frame_mem[pos-3]}!=~crc_state)parser_error(8'd5);
      else if(frame_mem[3][7])parser_error(8'd6);
      else begin cmd_opcode<=frame_mem[3];cmd_sequence<={frame_mem[7],frame_mem[6]};cmd_length<=payload_len;cmd_valid<=1'b1;pos<=0;payload_len<=0;crc_state<=32'hffffffff;crc_bytes<=0;end
     end else begin crc_bytes<=crc_bytes+1'b1;pos<=pos+1'b1;end end
   end
  end
 end
endmodule
