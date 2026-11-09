`timescale 1ns/1ps
module packed_tile #(parameter integer K=2048,R=128)(
 input wire clk,rst,start,in_valid,
 input wire [31:0] a_data,input wire [63:0] b_data,
 input wire [3:0] read_slot,
 output wire in_ready,output reg busy,done,xor_valid,
 output reg [31:0] xor_word,output wire [31:0] jackpot_word,
 output wire [1023:0] c_data
);
 localparam integer TERMS=(K/R)*R;
 localparam integer CW=$clog2(TERMS+1), RW=(R<2)?1:$clog2(R);
 reg [CW-1:0] count;reg [RW-1:0] rc;reg [3:0] slot;
 reg [1:0] state; // 0 feeding, 1 drain product pipeline, 2 reduction
 reg pending;
 wire signed [15:0] product[0:31];
 (* use_dsp="no" *) reg signed [31:0] accum[0:31];
 reg [31:0] jackpot[0:15];reg [31:0] reduced;
 genvar pair,col;
 generate for(pair=0;pair<2;pair=pair+1) begin: ap
  for(col=0;col<8;col=col+1) begin: bp
   packed_mul2 mul(.clk(clk),.a0(a_data[(pair*2)*8+:8]),.a1(a_data[(pair*2+1)*8+:8]),.b(b_data[col*8+:8]),.p0(product[pair*16+col]),.p1(product[pair*16+8+col]));
  end
 end
 for(pair=0;pair<32;pair=pair+1) begin: debug_c
  assign c_data[pair*32+:32]=accum[pair];
 end endgenerate
 assign jackpot_word=jackpot[read_slot];
 assign in_ready=busy && state==0;
 always @* begin
  reduced=0;
  for(integer q=0;q<32;q=q+1) reduced=reduced^accum[q];
 end
 integer i;
 always @(posedge clk) begin
  done<=0;xor_valid<=0;
  if(rst) begin
   busy<=0;count<=0;rc<=0;slot<=0;state<=0;pending<=0;xor_word<=0;
   for(i=0;i<32;i=i+1) accum[i]<=0;
   for(i=0;i<16;i=i+1) jackpot[i]<=0;
  end else if(start && !busy) begin
   busy<=1;count<=0;rc<=0;slot<=0;state<=0;pending<=0;xor_word<=0;
   for(i=0;i<32;i=i+1) accum[i]<=0;
   for(i=0;i<16;i=i+1) jackpot[i]<=0;
  end else if(busy) begin
   pending<=in_valid && in_ready;
   if(pending) for(i=0;i<32;i=i+1) accum[i]<=accum[i]+{{16{product[i][15]}},product[i]};
   case(state)
    0: if(in_valid) begin
     count<=count+1'b1;
     if(rc==R-1) begin rc<=0;state<=1;end else rc<=rc+1'b1;
    end
    1: state<=2;
    2: begin
     xor_word<=reduced;xor_valid<=1;
     jackpot[slot]<={jackpot[slot][18:0],jackpot[slot][31:19]}^reduced;
     slot<=slot+1'b1;state<=0;
     if(count==TERMS) begin busy<=0;done<=1;end
    end
   endcase
  end
 end
endmodule
