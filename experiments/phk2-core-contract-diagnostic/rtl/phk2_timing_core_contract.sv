`timescale 1ns/1ps
// Offline transaction wrapper around one reusable PHK1 4x8 arithmetic tile.
// A full 16x16 production result is assembled from 8 subtiles (4 row groups x
// 2 column groups) and XOR-composed before keyed digest/filter processing.
// Diagnostic only; deliberately excluded from all physical source sets.
module phk2_timing_core_contract (
    input wire clk, input wire rst,
    input wire descriptor_valid, output wire descriptor_ready,
    input wire [895:0] descriptor_payload,
    input wire range_valid, output wire range_ready,
    input wire [63:0] range_generation, input wire [255:0] range_job_key,
    input wire [31:0] range_start, input wire [15:0] range_count,
    input wire [15:0] range_id,
    input wire abort_valid, output wire abort_ready,
    input wire [63:0] abort_generation, input wire [255:0] abort_job_key,
    input wire [15:0] abort_range_id, input wire [15:0] abort_reason,
    output wire busy, output wire result_ready, output reg error,
    output reg stale_job, output wire overflow, output reg aborted,
    output reg [15:0] error_code,
    output wire result_valid, input wire result_ready_i,
    output wire [895:0] result_payload
);
    localparam [2:0] S_IDLE=0, S_TILE_START=1, S_FEED=2,
                     S_TILE_WAIT=3, S_FILTER_SEND=4, S_RESULT_WAIT=5;
    reg [2:0] state;
    reg descriptor_loaded;
    reg [255:0] job_key, noise_a, noise_b;
    reg [63:0] generation, setup_seed;
    reg [15:0] active_range_id, count, item_slot;
    reg [12:0] issue_count;
    reg [16:0] row_base, col_base;
    reg [2:0] subtile_index;
    reg [511:0] combined_transcript, result_transcript;
    reg [15:0] row_tile, col_tile;

    wire cancel = rst || (descriptor_valid && descriptor_ready) ||
                  (abort_valid && abort_ready);
    wire [11:0] k_index = issue_count[11:0];
    wire [15:0] row_group = {14'b0,subtile_index[2:1]};
    wire [15:0] col_group = {15'b0,subtile_index[0]};
    wire [16:0] requested_row_base = ({14'b0,item_slot[5:3]} << 4) + (row_group << 2);
    wire [16:0] requested_col_base = ({14'b0,item_slot[2:0]} << 4) + (col_group << 3);
    wire candidate_valid, candidate_ready;

    assign descriptor_ready = !rst;
    assign range_ready = !rst && state==S_IDLE && descriptor_loaded;
    assign abort_ready = !rst && descriptor_loaded;
    assign busy = state!=S_IDLE;
    assign overflow = workgen_overflow;
    assign result_ready = candidate_valid;
    assign result_valid = candidate_valid && !cancel;
    assign candidate_ready = result_ready_i && !cancel;
    assign result_payload = {result_transcript,digest,col_tile,row_tile,
                             item_slot,active_range_id,generation};

    wire workgen_request_ready, workgen_valid, workgen_overflow;
    wire [95:0] workgen_operand;
    wire [31:0] workgen_cycles;
    wire item_start = state==S_TILE_START;
    wire workgen_request_valid = state==S_FEED && issue_count<13'd4096;
    wire request_fire = workgen_request_valid && workgen_request_ready;
    wire tile_operand_ready, tile_result_valid, tile_busy;
    wire [511:0] subtile_transcript;
    wire [31:0] tile_cycles;
    wire tile_result_ready = state==S_TILE_WAIT;
    wire filter_input_valid = state==S_FILTER_SEND;
    wire filter_input_ready;
    wire [127:0] candidate_record;
    wire [31:0] stale_count;
    wire [255:0] digest;
    wire debug_hit;

    phk2_production_operand_seq workgen (
        .clk(clk), .rst(rst), .abort(cancel),
        .request_valid(workgen_request_valid), .request_ready(workgen_request_ready),
        .setup_seed64(setup_seed), .noise_seed_a(noise_a), .noise_seed_b(noise_b),
        .row_base(row_base), .col_base(col_base), .k_index(k_index),
        .operand_valid(workgen_valid), .operand_ready(tile_operand_ready),
        .operand_record(workgen_operand), .overflow(workgen_overflow),
        .cycle_count(workgen_cycles)
    );

    phk2_tile_adapter #(.K(4096), .R(256)) tile (
        .clk(clk), .rst(rst), .abort_req(cancel), .item_start(item_start),
        .operand_data(workgen_operand), .operand_valid(workgen_valid),
        .operand_ready(tile_operand_ready), .result_valid(tile_result_valid),
        .result_ready(tile_result_ready), .result_words(subtile_transcript),
        .busy(tile_busy), .cycle_count(tile_cycles)
    );

    phk2_result_filter result_path (
        .clk(clk), .rst(rst), .abort(cancel), .pow_key(noise_a),
        .pow_target(256'hffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff),
        .active_generation(generation), .result_valid(filter_input_valid),
        .result_ready(filter_input_ready), .result_generation(generation),
        .transcript_words(result_transcript), .work_index(item_slot),
        .row_tile(row_tile), .col_tile(col_tile), .candidate_valid(candidate_valid),
        .candidate_ready(candidate_ready), .candidate_record(candidate_record),
        .stale_candidate_count(stale_count), .debug_digest(digest), .debug_hit(debug_hit)
    );

    always @(posedge clk) begin
        if (rst) begin
            state<=S_IDLE; descriptor_loaded<=0; job_key<=0; noise_a<=0; noise_b<=0;
            generation<=0; setup_seed<=0; active_range_id<=0; count<=0;
            item_slot<=0; issue_count<=0; row_base<=0; col_base<=0; subtile_index<=0;
            combined_transcript<=0; result_transcript<=0; row_tile<=0; col_tile<=0;
            error<=0; stale_job<=0; aborted<=0; error_code<=0;
        end else if (descriptor_valid && descriptor_ready) begin
            state<=S_IDLE; descriptor_loaded<=1;
            job_key<=descriptor_payload[0+:256];
            generation<=descriptor_payload[256+:64];
            setup_seed<=descriptor_payload[320+:64];
            noise_a<=descriptor_payload[384+:256];
            noise_b<=descriptor_payload[640+:256];
            active_range_id<=0; count<=0; item_slot<=0; issue_count<=0;
            subtile_index<=0; combined_transcript<=0; result_transcript<=0;
            error<=0; stale_job<=0; aborted<=0; error_code<=0;
        end else if (abort_valid && abort_ready) begin
            state<=S_IDLE; item_slot<=0; issue_count<=0; subtile_index<=0;
            combined_transcript<=0; result_transcript<=0; aborted<=1;
            error<=0; error_code<=0;
            if (abort_generation!=generation || abort_job_key!=job_key ||
                abort_range_id!=active_range_id) begin
                stale_job<=1; error<=1; error_code<=16'd4;
            end
        end else begin
            if (range_valid && range_ready) begin
                if (range_generation!=generation || range_job_key!=job_key) begin
                    stale_job<=1; error<=1; error_code<=16'd4;
                end else if (range_start!=0 || range_count==0 || range_count>64 ||
                             range_id==0 || range_id==active_range_id) begin
                    error<=1; error_code<=16'd10;
                end else begin
                    count<=range_count; active_range_id<=range_id; item_slot<=0;
                    issue_count<=0; subtile_index<=0; combined_transcript<=0;
                    result_transcript<=0; error<=0; error_code<=0; aborted<=0;
                    state<=S_TILE_START;
                end
            end
            case(state)
                S_TILE_START: begin
                    issue_count<=0;
                    row_tile<={13'b0,item_slot[5:3]};
                    col_tile<={13'b0,item_slot[2:0]};
                    row_base<=requested_row_base;
                    col_base<=requested_col_base;
                    state<=S_FEED;
                end
                S_FEED: if (request_fire) begin
                    if (issue_count==13'd4095) begin
                        issue_count<=13'd4096; state<=S_TILE_WAIT;
                    end else issue_count<=issue_count+1'b1;
                end
                S_TILE_WAIT: if (tile_result_valid && tile_result_ready) begin
                    combined_transcript<=combined_transcript ^ subtile_transcript;
                    if (subtile_index==3'd7) begin
                        result_transcript<=combined_transcript ^ subtile_transcript;
                        state<=S_FILTER_SEND;
                    end else begin
                        subtile_index<=subtile_index+1'b1;
                        state<=S_TILE_START;
                    end
                end
                S_FILTER_SEND: if (filter_input_valid && filter_input_ready)
                    state<=S_RESULT_WAIT;
                S_RESULT_WAIT: if (result_valid && result_ready_i) begin
                    if (item_slot+1'b1>=count) begin
                        state<=S_IDLE;
                    end else begin
                        item_slot<=item_slot+1'b1; subtile_index<=0;
                        combined_transcript<=0; result_transcript<=0;
                        state<=S_TILE_START;
                    end
                end
                default: begin end
            endcase
            if (workgen_overflow) begin
                state<=S_IDLE; error<=1; error_code<=16'd12;
            end
        end
    end
endmodule
