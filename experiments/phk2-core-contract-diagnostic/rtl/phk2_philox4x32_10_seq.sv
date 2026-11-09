`timescale 1ns/1ps
// Single-round-per-cycle Philox4x32-10. One multiplier round datapath is
// reused for ten rounds; output conversion matches the production int8 map.
module phk2_philox4x32_10_seq (
    input wire clk,input wire rst,input wire start,output wire ready,
    input wire [63:0] base,input wire [63:0] seed64,
    output reg busy,output reg done,output reg [3:0] round_count,
    output reg [31:0] c0,output reg [31:0] c1,output reg [31:0] c2,output reg [31:0] c3
);
    reg [31:0] x0,x1,x2,x3,kx,ky;
    wire [63:0] p0=64'hD2511F53*x0;
    wire [63:0] p1=64'hCD9E8D57*x2;
    wire [63:0] pk=64'h9E3779B9*kx;
    wire [31:0] n0=p1[63:32]^x1^kx;
    wire [31:0] n1=p1[31:0];
    wire [31:0] n2=p0[63:32]^x3^ky;
    wire [31:0] n3=p0[31:0];
    wire [31:0] nkx=pk[63:32]^ky^32'h9E3779B9;
    wire [31:0] nky=pk[31:0];
    assign ready=!busy;
    always @(posedge clk) begin
        done<=0;
        if(rst) begin
            busy<=0;round_count<=0;x0<=0;x1<=0;x2<=0;x3<=0;kx<=0;ky<=0;
            c0<=0;c1<=0;c2<=0;c3<=0;
        end else if(start&&ready) begin
            x0<=base[31:0];x1<=base[63:32];x2<=base[63:32]^base[31:0];x3<=0;
            kx<=seed64[31:0];ky<=seed64[63:32];round_count<=0;busy<=1;
        end else if(busy) begin
            if(round_count==4'd9) begin
                c0<={25'b0,n0[6:0]}-32'd64;c1<={25'b0,n1[6:0]}-32'd64;
                c2<={25'b0,n2[6:0]}-32'd64;c3<={25'b0,n3[6:0]}-32'd64;
                busy<=0;done<=1;round_count<=0;
            end else begin
                x0<=n0;x1<=n1;x2<=n2;x3<=n3;kx<=nkx;ky<=nky;
                round_count<=round_count+1'b1;
            end
        end
    end
endmodule
