`timescale 1ns/1ps
// Exact two signed8 products sharing b. No packed multi-cycle accumulation.
module packed_mul2(input wire clk, input wire signed [7:0] a0,a1,b,
 output wire signed [15:0] p0,p1);
 wire signed [26:0] low_ext={{19{a0[7]}},a0};
 wire signed [26:0] high_ext={{19{a1[7]}},a1};
 (* use_dsp="no" *) wire signed [26:0] packed_a=low_ext+(high_ext<<<18);
 (* use_dsp="yes" *) reg signed [44:0] product;
 always @(posedge clk) product<=packed_a*b;
 assign p0=product[15:0];
 // Negative low product borrows one unit from the upper field.
 assign p1=product[33:18]+{{15{1'b0}},product[17]};
endmodule
