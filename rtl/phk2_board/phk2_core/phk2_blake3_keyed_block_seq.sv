`timescale 1ns/1ps
// Single-round-per-cycle BLAKE3 keyed 64-byte ROOT block. This is the exact
// primitive used by phk2_blake3_keyed_block, but shares one round datapath
// over fourteen cycles, registering between column and diagonal halves of
// each round to limit the state-update critical path.
module phk2_blake3_keyed_block_seq (
    input wire clk, input wire rst,
    input wire start, output wire ready,
    input wire [255:0] key, input wire [511:0] message,
    output reg busy, output reg done, output reg [2:0] round_count,
    output reg [255:0] digest
);
    reg [511:0] v_state, m_state;
    reg round_phase;
    wire [511:0] column_v = column_round(v_state,m_state);
    wire [511:0] diagonal_v = diagonal_round(v_state,m_state);
    integer i;
    assign ready = !busy;

    function automatic [31:0] rotr32(input [31:0] x,input integer n);
        rotr32=(x>>n)|(x<<(32-n));
    endfunction

    function automatic [127:0] mix4(input [31:0] ai,bi,ci,di,xi,yi);
        reg [31:0] a,b,c,d;
        begin
            a=ai; b=bi; c=ci; d=di;
            a=a+b+xi; d=rotr32(d^a,16); c=c+d; b=rotr32(b^c,12);
            a=a+b+yi; d=rotr32(d^a,8); c=c+d; b=rotr32(b^c,7);
            mix4={a,b,c,d};
        end
    endfunction

    function automatic [511:0] column_round(input [511:0] vi,input [511:0] mi);
        reg [31:0] v[0:15];
        reg [31:0] m[0:15];
        reg [127:0] z;
        integer q;
        begin
            for(q=0;q<16;q=q+1) begin v[q]=vi[q*32+:32]; m[q]=mi[q*32+:32]; end
            z=mix4(v[0],v[4],v[8],v[12],m[0],m[1]); v[0]=z[127:96]; v[4]=z[95:64]; v[8]=z[63:32]; v[12]=z[31:0];
            z=mix4(v[1],v[5],v[9],v[13],m[2],m[3]); v[1]=z[127:96]; v[5]=z[95:64]; v[9]=z[63:32]; v[13]=z[31:0];
            z=mix4(v[2],v[6],v[10],v[14],m[4],m[5]); v[2]=z[127:96]; v[6]=z[95:64]; v[10]=z[63:32]; v[14]=z[31:0];
            z=mix4(v[3],v[7],v[11],v[15],m[6],m[7]); v[3]=z[127:96]; v[7]=z[95:64]; v[11]=z[63:32]; v[15]=z[31:0];
            for(q=0;q<16;q=q+1) column_round[q*32+:32]=v[q];
        end
    endfunction

    function automatic [511:0] diagonal_round(input [511:0] vi,input [511:0] mi);
        reg [31:0] v[0:15];
        reg [31:0] m[0:15];
        reg [127:0] z;
        integer q;
        begin
            for(q=0;q<16;q=q+1) begin v[q]=vi[q*32+:32]; m[q]=mi[q*32+:32]; end
            z=mix4(v[0],v[5],v[10],v[15],m[8],m[9]); v[0]=z[127:96]; v[5]=z[95:64]; v[10]=z[63:32]; v[15]=z[31:0];
            z=mix4(v[1],v[6],v[11],v[12],m[10],m[11]); v[1]=z[127:96]; v[6]=z[95:64]; v[11]=z[63:32]; v[12]=z[31:0];
            z=mix4(v[2],v[7],v[8],v[13],m[12],m[13]); v[2]=z[127:96]; v[7]=z[95:64]; v[8]=z[63:32]; v[13]=z[31:0];
            z=mix4(v[3],v[4],v[9],v[14],m[14],m[15]); v[3]=z[127:96]; v[4]=z[95:64]; v[9]=z[63:32]; v[14]=z[31:0];
            for(q=0;q<16;q=q+1) diagonal_round[q*32+:32]=v[q];
        end
    endfunction

    function automatic [511:0] permute(input [511:0] mi);
        reg [31:0] m[0:15];
        reg [31:0] t[0:15];
        integer q;
        begin
            for(q=0;q<16;q=q+1) begin m[q]=mi[q*32+:32]; t[q]=mi[q*32+:32]; end
            m[0]=t[2];m[1]=t[6];m[2]=t[3];m[3]=t[10];m[4]=t[7];m[5]=t[0];m[6]=t[4];m[7]=t[13];
            m[8]=t[1];m[9]=t[11];m[10]=t[12];m[11]=t[5];m[12]=t[9];m[13]=t[14];m[14]=t[15];m[15]=t[8];
            for(q=0;q<16;q=q+1) permute[q*32+:32]=m[q];
        end
    endfunction

    function automatic [31:0] iv(input integer idx);
        begin
            case(idx)
                8:iv=32'h6a09e667; 9:iv=32'hbb67ae85; 10:iv=32'h3c6ef372; 11:iv=32'ha54ff53a;
                14:iv=32'd64; 15:iv=32'd27; default:iv=0;
            endcase
        end
    endfunction

    always @(posedge clk) begin
        done<=0;
        if(rst) begin
            busy<=0; round_count<=0; round_phase<=0; digest<=0; v_state<=0; m_state<=0;
        end else if(start && ready) begin
            for(i=0;i<8;i=i+1) v_state[i*32+:32]<=key[i*32+:32];
            for(i=8;i<16;i=i+1) v_state[i*32+:32]<=iv(i);
            m_state<=message;
            round_count<=0;
            round_phase<=0;
            busy<=1;
        end else if(busy) begin
            if(!round_phase) begin
                v_state<=column_v;
                round_phase<=1;
            end else begin
                if(round_count==3'd6) begin
                    for(i=0;i<8;i=i+1) digest[i*32+:32]<=diagonal_v[i*32+:32]^diagonal_v[(i+8)*32+:32];
                    busy<=0; done<=1; round_count<=0; round_phase<=0;
                end else begin
                    v_state<=diagonal_v;
                    m_state<=permute(m_state);
                    round_count<=round_count+1'b1;
                    round_phase<=0;
                end
            end
        end
    end
endmodule
