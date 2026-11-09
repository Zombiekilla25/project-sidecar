`timescale 1ns/1ps
// One 16-byte candidate locator. The host reconstructs and verifies the full
// result from its retained job/range context; this block never marks a share
// valid on its own. Coordinates are absolute tile indices, each bounded to u16.
module phk2_compact_result (
    input wire clk, input wire rst, input wire flush,
    input wire [63:0] active_generation,
    input wire candidate_valid,
    output wire candidate_ready,
    input wire [63:0] candidate_generation,
    input wire [15:0] work_index,
    input wire [15:0] row_tile,
    input wire [15:0] col_tile,
    input wire [15:0] candidate_flags,
    output wire result_valid,
    input wire result_ready,
    output reg [127:0] result_record,
    output reg [31:0] stale_candidate_count
);
    reg result_valid_reg;
    reg [63:0] stored_generation;
    wire held_stale = result_valid_reg && (stored_generation != active_generation);
    wire candidate_accept = candidate_valid && candidate_ready;
    wire candidate_stale = candidate_accept && (candidate_generation != active_generation);
    wire [32:0] stale_sum = {1'b0,stale_candidate_count} +
                             {32'd0,held_stale} + {32'd0,candidate_stale};

    assign result_valid = result_valid_reg && !held_stale;
    assign candidate_ready = !result_valid_reg || result_ready || held_stale;
    always @(posedge clk) begin
        if (rst) begin
            result_valid_reg <= 0; result_record <= 0; stored_generation <= 0;
            stale_candidate_count <= 0;
        end else if (flush) begin
            result_valid_reg <= 0;
        end else begin
            if (stale_sum[32] || (&stale_candidate_count))
                stale_candidate_count <= 32'hffffffff;
            else if (held_stale || candidate_stale)
                stale_candidate_count <= stale_sum[31:0];

            if (held_stale || (result_valid_reg && result_ready))
                result_valid_reg <= 0;
            if (candidate_accept && !candidate_stale) begin
                result_record <= {candidate_flags,col_tile,row_tile,work_index,candidate_generation};
                stored_generation <= candidate_generation;
                result_valid_reg <= 1;
            end
        end
    end
endmodule
