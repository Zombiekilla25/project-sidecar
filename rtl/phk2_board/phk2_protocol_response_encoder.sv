`timescale 1ns/1ps
// Ready/valid response frame encoder for PHK2 wire v1. Payload is supplied
// byte 0 in payload[7:0]. CRC is CRC-32/ISO-HDLC over header and payload.
module phk2_protocol_response_encoder #(
    parameter integer MAX_PAYLOAD = 448
) (
    input wire clk,
    input wire rst,
    input wire start,
    output wire ready,
    input wire [7:0] request_opcode,
    input wire error_response,
    input wire [15:0] sequence_id,
    input wire [15:0] payload_length,
    input wire [MAX_PAYLOAD*8-1:0] payload,
    output wire tx_valid,
    input wire tx_ready,
    output reg [7:0] tx_data,
    output reg busy,
    output reg done,
    output reg length_error
);
    localparam [1:0] IDLE=2'd0, HEADER=2'd1, PAYLOAD=2'd2, CRC=2'd3;
    reg [1:0] state;
    reg [7:0] opcode_q, flags_q;
    reg [15:0] sequence_q, length_q, byte_index;
    reg [MAX_PAYLOAD*8-1:0] payload_q;
    reg [31:0] crc_state;
    reg [1:0] crc_index;
    wire [31:0] crc_final = ~crc_state;
    wire byte_fire = tx_valid && tx_ready;
    assign ready = (state==IDLE);
    assign tx_valid = busy;

    function automatic [31:0] crc_byte(input [31:0] crc_in,input [7:0] data);
        integer b;
        reg [31:0] c;
        begin
            c=crc_in^data;
            for(b=0;b<8;b=b+1) c=c[0]?(c>>1)^32'hedb88320:(c>>1);
            crc_byte=c;
        end
    endfunction

    always @* begin
        tx_data=8'h00;
        case(state)
            HEADER: case(byte_index)
                0:tx_data=8'hc2;
                1:tx_data=8'h5a;
                2:tx_data=8'd1;
                3:tx_data=opcode_q|8'h80;
                4:tx_data=flags_q;
                5:tx_data=8'h00;
                6:tx_data=sequence_q[7:0];
                7:tx_data=sequence_q[15:8];
                8:tx_data=length_q[7:0];
                9:tx_data=length_q[15:8];
                default:tx_data=8'h00;
            endcase
            PAYLOAD: tx_data=payload_q[byte_index*8+:8];
            CRC: tx_data=crc_final[crc_index*8+:8];
            default:tx_data=8'h00;
        endcase
    end

    always @(posedge clk) begin
        done<=1'b0;
        if(rst) begin
            state<=IDLE; busy<=1'b0; opcode_q<=0; flags_q<=0;
            sequence_q<=0; length_q<=0; byte_index<=0; payload_q<=0;
            crc_state<=32'hffffffff; crc_index<=0; length_error<=1'b0;
        end else begin
            if(start && ready) begin
                if(payload_length>MAX_PAYLOAD) begin
                    length_error<=1'b1;
                end else begin
                    length_error<=1'b0;
                    opcode_q<=request_opcode; flags_q<=error_response?8'h03:8'h01;
                    sequence_q<=sequence_id; length_q<=payload_length;
                    payload_q<=payload; byte_index<=0; crc_index<=0;
                    crc_state<=32'hffffffff; state<=HEADER; busy<=1'b1;
                end
            end else if(byte_fire) begin
                case(state)
                    HEADER: begin
                        crc_state<=crc_byte(crc_state,tx_data);
                        if(byte_index==9) begin
                            byte_index<=0;
                            if(length_q==0) begin state<=CRC; crc_index<=0; end
                            else state<=PAYLOAD;
                        end else byte_index<=byte_index+1'b1;
                    end
                    PAYLOAD: begin
                        crc_state<=crc_byte(crc_state,tx_data);
                        if(byte_index+1'b1>=length_q) begin
                            state<=CRC; byte_index<=0; crc_index<=0;
                        end else byte_index<=byte_index+1'b1;
                    end
                    CRC: begin
                        if(crc_index==3) begin
                            state<=IDLE; busy<=1'b0; done<=1'b1; crc_index<=0;
                        end else crc_index<=crc_index+1'b1;
                    end
                    default: begin state<=IDLE;busy<=1'b0;end
                endcase
            end
        end
    end
endmodule
