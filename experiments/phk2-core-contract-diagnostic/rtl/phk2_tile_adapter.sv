`timescale 1ns/1ps
// Interface-only adapter around the byte-identical PHK1 packed arithmetic
// tile. Operand generation is intentionally a separate block; this adapter
// does not claim that the production noise/Philox stream is generated here.
module phk2_tile_adapter #(
    parameter integer K = 4096,
    parameter integer R = 256
) (
    input wire clk, input wire rst, input wire abort_req,
    input wire item_start,
    input wire [95:0] operand_data,
    input wire operand_valid,
    output wire operand_ready,
    output reg result_valid,
    input wire result_ready,
    output reg [511:0] result_words,
    output reg busy, output reg [31:0] cycle_count
);
    localparam [1:0] IDLE = 2'd0, FEED = 2'd1, CAPTURE = 2'd2, HOLD = 2'd3;
    reg [1:0] state;
    reg tile_start;
    reg [3:0] slot;
    wire tile_ready, tile_done;
    wire [31:0] jackpot_word;
    wire [31:0] a_data = operand_data[31:0];
    wire [63:0] b_data = operand_data[95:32];

    packed_tile #(.K(K), .R(R)) phk1_arithmetic_tile (
        .clk(clk), .rst(rst | abort_req), .start(tile_start),
        .in_valid(operand_valid && state == FEED),
        .a_data(a_data), .b_data(b_data), .read_slot(slot),
        .in_ready(tile_ready), .busy(), .done(tile_done),
        .xor_valid(), .xor_word(), .jackpot_word(jackpot_word), .c_data()
    );

    assign operand_ready = (state == FEED) && tile_ready;
    always @(posedge clk) begin
        tile_start <= 0;
        if (rst || abort_req) begin
            state <= IDLE; slot <= 0; result_valid <= 0;
            result_words <= 0; busy <= 0; cycle_count <= 0;
        end else begin
            if (busy) cycle_count <= cycle_count + 1'b1;
            case (state)
                IDLE: if (item_start && !busy) begin
                    tile_start <= 1; state <= FEED; busy <= 1;
                    result_valid <= 0; slot <= 0; cycle_count <= 0;
                end
                FEED: if (operand_valid && tile_ready) begin
                    if (tile_done) state <= CAPTURE;
                end else if (tile_done) state <= CAPTURE;
                CAPTURE: begin
                    result_words[slot*32 +: 32] <= jackpot_word;
                    if (slot == 15) begin
                        result_valid <= 1;
                        state <= HOLD;
                    end else slot <= slot + 1'b1;
                end
                HOLD: if (result_valid && result_ready) begin
                    result_valid <= 0; busy <= 0; state <= IDLE;
                end
                default: begin state <= IDLE; busy <= 0; result_valid <= 0; end
            endcase
        end
    end
endmodule
