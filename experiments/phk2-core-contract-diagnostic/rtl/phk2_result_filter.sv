`timescale 1ns/1ps
// Sequential exact keyed digest, registered target comparison, then a
// generation-fenced compact locator. One result is in flight at a time; the
// source is backpressured until the digest/filter/compact stages retire it.
module phk2_result_filter (
    input wire clk, input wire rst, input wire abort,
    input wire [255:0] pow_key,
    input wire [255:0] pow_target,
    input wire [63:0] active_generation,
    input wire result_valid,
    output wire result_ready,
    input wire [63:0] result_generation,
    input wire [511:0] transcript_words,
    input wire [15:0] work_index,
    input wire [15:0] row_tile,
    input wire [15:0] col_tile,
    output wire candidate_valid,
    input wire candidate_ready,
    output wire [127:0] candidate_record,
    output wire [31:0] stale_candidate_count,
    output wire [255:0] debug_digest,
    output wire debug_hit
);
    localparam [1:0] S_IDLE=2'd0, S_HASH=2'd1, S_FILTER=2'd2, S_EMIT=2'd3;
    reg [1:0] state;
    reg [255:0] target_saved;
    reg [63:0] generation_saved;
    reg [15:0] work_index_saved, row_saved, col_saved;
    reg hit_saved;

    wire hash_ready, hash_busy, hash_done;
    wire [2:0] hash_round;
    wire [255:0] hash_digest;
    wire hash_start = result_valid && result_ready;
    wire compact_candidate_ready;
    wire compact_candidate_valid = (state==S_EMIT) && hit_saved && !abort;

    assign result_ready = (state==S_IDLE) && hash_ready && !abort;
    assign debug_digest = hash_digest;

    phk2_blake3_keyed_block_seq digest_engine (
        .clk(clk), .rst(rst), .start(hash_start), .ready(hash_ready),
        .key(pow_key), .message(transcript_words), .busy(hash_busy),
        .done(hash_done), .round_count(hash_round), .digest(hash_digest)
    );

    wire compact_result_valid;
    phk2_compact_result compact (
        .clk(clk), .rst(rst), .flush(abort), .active_generation(active_generation),
        .candidate_valid(compact_candidate_valid), .candidate_ready(compact_candidate_ready),
        .candidate_generation(generation_saved), .work_index(work_index_saved),
        .row_tile(row_saved), .col_tile(col_saved), .candidate_flags(16'h0001),
        .result_valid(compact_result_valid), .result_ready(candidate_ready), .result_record(candidate_record),
        .stale_candidate_count(stale_candidate_count)
    );
    assign candidate_valid = compact_result_valid;
    assign debug_hit = hit_saved || compact_result_valid;

    always @(posedge clk) begin
        if (rst) begin
            state <= S_IDLE;
            target_saved <= 0;
            generation_saved <= 0;
            work_index_saved <= 0;
            row_saved <= 0;
            col_saved <= 0;
            hit_saved <= 0;
        end else if (abort) begin
            // The serial hash engine is allowed to finish its current block;
            // no result can escape, and a new input waits for hash_ready.
            state <= S_IDLE;
            hit_saved <= 0;
        end else begin
            case (state)
                S_IDLE: if (result_valid && result_ready) begin
                    target_saved <= pow_target;
                    generation_saved <= result_generation;
                    work_index_saved <= work_index;
                    row_saved <= row_tile;
                    col_saved <= col_tile;
                    hit_saved <= 0;
                    state <= S_HASH;
                end
                S_HASH: if (hash_done) state <= S_FILTER;
                S_FILTER: begin
                    hit_saved <= (hash_digest <= target_saved);
                    state <= S_EMIT;
                end
                S_EMIT: begin
                    if (!hit_saved || compact_candidate_ready) begin
                        state <= S_IDLE;
                        hit_saved <= 0;
                    end
                end
                default: begin state <= S_IDLE; hit_saved <= 0; end
            endcase
        end
    end
endmodule
