`timescale 1ns/1ps
// Stable core-clock boundary between the PHK2 board controller and a core
// implementation. BSCAN/TCK CDC stays outside this module in the board FIFOs.
module phk2_core_contract_adapter (
    input  wire         clk,
    input  wire         rst,
    input  wire         reset_req,
    input  wire         descriptor_valid,
    output wire         descriptor_ready,
    input  wire [895:0] descriptor_payload,
    input  wire         range_valid,
    output wire         range_ready,
    input  wire [63:0]  range_generation,
    input  wire [255:0] range_job_key,
    input  wire [31:0]  range_start,
    input  wire [15:0]  range_count,
    input  wire [15:0]  range_id,
    input  wire         abort_valid,
    output wire         abort_ready,
    input  wire [63:0]  abort_generation,
    input  wire [255:0] abort_job_key,
    input  wire [15:0]  abort_range_id,
    input  wire [15:0]  abort_reason,
    output wire         core_rst,
    output wire         core_descriptor_valid,
    input  wire         core_descriptor_ready,
    output wire [895:0] core_descriptor_payload,
    output wire         core_range_valid,
    input  wire         core_range_ready,
    output wire [63:0]  core_range_generation,
    output wire [255:0] core_range_job_key,
    output wire [31:0]  core_range_start,
    output wire [15:0]  core_range_count,
    output wire [15:0]  core_range_id,
    output wire         core_abort_valid,
    input  wire         core_abort_ready,
    output wire [63:0]  core_abort_generation,
    output wire [255:0] core_abort_job_key,
    output wire [15:0]  core_abort_range_id,
    output wire [15:0]  core_abort_reason,
    input  wire         core_busy,
    input  wire         core_result_ready,
    input  wire         core_error,
    input  wire         core_stale_job,
    input  wire         core_aborted,
    input  wire [15:0]  core_error_code,
    input  wire         core_result_valid,
    output wire         core_result_ready_i,
    input  wire [895:0] core_result_payload,
    output wire         busy,
    output wire         result_ready,
    output wire         error,
    output wire         stale_job,
    output wire         aborted,
    output wire [15:0]  error_code,
    output wire         result_valid,
    input  wire         result_ready_i,
    output wire [895:0] result_payload
);
    localparam integer PHK2_DESCRIPTOR_BITS = 112 * 8;
    localparam integer PHK2_RESULT_BITS = 112 * 8;
    initial begin
        if (($bits(descriptor_payload) != PHK2_DESCRIPTOR_BITS) ||
            ($bits(core_descriptor_payload) != PHK2_DESCRIPTOR_BITS) ||
            ($bits(core_result_payload) != PHK2_RESULT_BITS) ||
            ($bits(result_payload) != PHK2_RESULT_BITS) ||
            ($bits(range_generation) != 64) || ($bits(range_count) != 16) ||
            ($bits(range_id) != 16) || ($bits(error_code) != 16))
            $fatal(1, "PHK2 core contract width mismatch");
    end
    reg descriptor_loaded;
    reg [63:0] active_generation;
    reg [255:0] active_job_key;
    reg [15:0] active_range_id;
    reg range_active;
    reg sticky_stale;
    reg sticky_error;
    reg [15:0] sticky_error_code;

    wire range_identity_ok = descriptor_loaded &&
        range_generation == active_generation && range_job_key == active_job_key;
    wire range_count_ok = range_count != 0 && range_count <= 64;
    // Result payload contract begins with generation[63:0], range_id[15:0].
    wire result_identity_ok = descriptor_loaded && range_active &&
        core_result_payload[0 +: 64] == active_generation &&
        core_result_payload[64 +: 16] == active_range_id;
    wire abort_identity_ok = descriptor_loaded &&
        abort_generation == active_generation && abort_job_key == active_job_key &&
        abort_range_id == active_range_id;

    assign core_rst = rst | reset_req;
    assign core_descriptor_valid = descriptor_valid && !core_rst;
    assign descriptor_ready = core_descriptor_ready && !core_rst;
    assign core_descriptor_payload = descriptor_payload;

    // A mismatched request is consumed locally and reported as stale. It is
    // never forwarded to the candidate core.
    assign core_range_valid = range_valid && range_identity_ok && range_count_ok && !core_rst;
    assign range_ready = (!range_identity_ok || !range_count_ok) ? (range_valid && !core_rst) :
                         (core_range_ready && !core_rst);
    assign core_range_generation = range_generation;
    assign core_range_job_key = range_job_key;
    assign core_range_start = range_start;
    assign core_range_count = range_count;
    assign core_range_id = range_id;

    assign core_abort_valid = abort_valid && abort_identity_ok && !core_rst;
    assign abort_ready = !abort_identity_ok ? (abort_valid && !core_rst) :
                         (core_abort_ready && !core_rst);
    assign core_abort_generation = abort_generation;
    assign core_abort_job_key = abort_job_key;
    assign core_abort_range_id = abort_range_id;
    assign core_abort_reason = abort_reason;

    // A stale core result is drained and discarded; valid results obey the
    // caller's ready backpressure without relying on core latency.
    assign result_valid = core_result_valid && result_identity_ok && !core_rst;
    assign result_payload = core_result_payload;
    assign core_result_ready_i = core_rst ? 1'b0 :
                                 (!result_identity_ok ? 1'b1 : result_ready_i);

    assign busy = core_busy;
    assign result_ready = core_result_ready;
    assign error = core_error | sticky_error;
    assign stale_job = core_stale_job | sticky_stale;
    assign aborted = core_aborted;
    assign error_code = core_error ? core_error_code :
                        (sticky_error ? sticky_error_code : core_error_code);

    always @(posedge clk) begin
        if (core_rst) begin
            descriptor_loaded <= 1'b0;
            active_generation <= 64'b0;
            active_job_key <= 256'b0;
            active_range_id <= 16'b0;
            range_active <= 1'b0;
            sticky_stale <= 1'b0;
            sticky_error <= 1'b0;
            sticky_error_code <= 16'b0;
        end else begin
            if (descriptor_valid && descriptor_ready) begin
                active_generation <= descriptor_payload[256 +: 64];
                active_job_key <= descriptor_payload[0 +: 256];
                descriptor_loaded <= 1'b1;
                active_range_id <= 16'b0;
                range_active <= 1'b0;
                sticky_stale <= 1'b0;
                sticky_error <= 1'b0;
                sticky_error_code <= 16'b0;
            end
            if (range_valid && range_ready) begin
                if (!range_identity_ok || !range_count_ok) begin
                    if (!range_identity_ok) sticky_stale <= 1'b1;
                    sticky_error <= 1'b1;
                    sticky_error_code <= !range_identity_ok ? 16'd4 : 16'd10;
                end else begin
                    active_range_id <= range_id;
                    range_active <= 1'b1;
                end
            end
            if (abort_valid && abort_ready) begin
                if (!abort_identity_ok) begin
                    sticky_stale <= 1'b1;
                    sticky_error <= 1'b1;
                    sticky_error_code <= 16'd4;
                end else begin
                    range_active <= 1'b0;
                end
            end
            if (core_error) begin
                sticky_error <= 1'b1;
                sticky_error_code <= core_error_code;
            end
            if (core_stale_job) sticky_stale <= 1'b1;
            if (core_result_valid && !result_identity_ok) begin
                sticky_stale <= 1'b1;
                sticky_error <= 1'b1;
                sticky_error_code <= 16'd4;
            end
        end
    end
endmodule
