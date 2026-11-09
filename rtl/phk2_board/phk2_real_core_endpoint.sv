`timescale 1ns/1ps
// Core-clock command/response endpoint. It consumes decoded v1 commands,
// adapts them to the real descriptor/range/abort handshake, and frames replies.
module phk2_real_core_endpoint #(
    parameter integer MAX_RESPONSE_PAYLOAD = 448
) (
    input wire clk, input wire rst,
    input wire cmd_valid, output wire cmd_ready,
    input wire [7:0] cmd_opcode, input wire [15:0] cmd_sequence,
    input wire [15:0] cmd_length, input wire [895:0] cmd_payload,
    output wire tx_valid, input wire tx_ready, output wire [7:0] tx_data,
    output wire busy, output wire result_ready, output wire error,
    output wire stale_job, output wire overflow, output wire aborted,
    output wire hello_seen, output wire descriptor_loaded,
    output wire [15:0] error_code
);
    localparam [7:0] OP_HELLO=8'h01, OP_LOAD=8'h10, OP_START=8'h11,
                     OP_STATUS=8'h12, OP_READ=8'h13, OP_ABORT=8'h14,
                     OP_RESET=8'h1f;
    localparam [15:0] E_BAD_OPCODE=1, E_BAD_LENGTH=2, E_STALE=4,
                      E_NOT_READY=9, E_RANGE=10, E_INTERNAL=12;
    localparam [3:0] S_IDLE=0, S_LOAD=1, S_START=2, S_ABORT=3,
                     S_RESET=4, S_READ=5, S_RESP_START=6, S_RESP_WAIT=7;
    reg [3:0] state;
    reg [7:0] opcode_q;
    reg [15:0] sequence_q, length_q, response_length;
    reg [895:0] payload_q;
    reg [MAX_RESPONSE_PAYLOAD*8-1:0] response_payload;
    reg [63:0] active_generation;
    reg [255:0] active_job_key;
    reg [15:0] active_range_id, active_count, expected_slot;
    reg [15:0] read_limit, read_received;
    reg loaded, hello_q, sticky_error, sticky_stale, sticky_aborted;
    reg [15:0] sticky_error_code;
    reg reset_req;

    wire d_valid, d_ready, r_valid, r_ready, a_valid, a_ready;
    wire core_d_valid, core_d_ready, core_r_valid, core_r_ready, core_a_valid, core_a_ready;
    wire [895:0] core_d_payload;
    wire [63:0] core_r_generation, core_a_generation;
    wire [255:0] core_r_job_key, core_a_job_key;
    wire [31:0] core_r_start;
    wire [15:0] core_r_count, core_r_id, core_a_id, core_a_reason;
    wire [895:0] core_result_payload;
    wire core_result_valid, core_result_ready_i, result_valid;
    wire [895:0] result_payload;
    wire core_busy, core_result_ready, core_error, core_stale, core_aborted;
    wire [15:0] core_error_code;
    wire [895:0] core_descriptor_payload;
    wire [63:0] core_range_generation, core_abort_generation;
    wire [255:0] core_range_job_key, core_abort_job_key;
    wire [31:0] core_range_start;
    wire [15:0] core_range_count, core_range_id, core_abort_range_id, core_abort_reason;
    wire core_rst;

    assign cmd_ready=(state==S_IDLE);
    assign busy=core_busy;
    assign result_ready=core_result_ready;
    assign error=sticky_error|core_error;
    assign stale_job=sticky_stale|core_stale;
    assign overflow=1'b0;
    assign aborted=sticky_aborted|core_aborted;
    assign hello_seen=hello_q;
    assign descriptor_loaded=loaded;
    assign error_code=core_error ? core_error_code : sticky_error_code;

    assign d_valid=(state==S_LOAD);
    assign core_descriptor_payload=payload_q;
    assign r_valid=(state==S_START);
    assign core_range_generation=payload_q[0+:64];
    assign core_range_job_key=payload_q[64+:256];
    assign core_range_start=payload_q[320+:32];
    assign core_range_count=payload_q[352+:16];
    assign core_range_id=payload_q[368+:16];
    assign a_valid=(state==S_ABORT);
    assign core_abort_generation=payload_q[0+:64];
    assign core_abort_job_key=payload_q[64+:256];
    assign core_abort_range_id=payload_q[320+:16];
    assign core_abort_reason=payload_q[336+:16];
    wire result_ready_i=(state==S_READ);

    phk2_core_contract_adapter contract_adapter (
        .clk(clk),.rst(rst),.reset_req(reset_req),
        .descriptor_valid(d_valid),.descriptor_ready(d_ready),.descriptor_payload(core_descriptor_payload),
        .range_valid(r_valid),.range_ready(r_ready),.range_generation(core_range_generation),
        .range_job_key(core_range_job_key),.range_start(core_range_start),.range_count(core_range_count),.range_id(core_range_id),
        .abort_valid(a_valid),.abort_ready(a_ready),.abort_generation(core_abort_generation),
        .abort_job_key(core_abort_job_key),.abort_range_id(core_abort_range_id),.abort_reason(core_abort_reason),
        .core_rst(core_rst),.core_descriptor_valid(core_d_valid),.core_descriptor_ready(core_d_ready),.core_descriptor_payload(core_d_payload),
        .core_range_valid(core_r_valid),.core_range_ready(core_r_ready),.core_range_generation(core_r_generation),.core_range_job_key(core_r_job_key),
        .core_range_start(core_r_start),.core_range_count(core_r_count),.core_range_id(core_r_id),.core_abort_valid(core_a_valid),.core_abort_ready(core_a_ready),
        .core_abort_generation(core_a_generation),.core_abort_job_key(core_a_job_key),.core_abort_range_id(core_a_id),.core_abort_reason(core_a_reason),
        .core_busy(core_busy),.core_result_ready(core_result_ready),.core_error(core_error),.core_stale_job(core_stale),
        .core_aborted(core_aborted),.core_error_code(core_error_code),.core_result_valid(core_result_valid),
        .core_result_ready_i(core_result_ready_i),.core_result_payload(core_result_payload),
        .busy(),.result_ready(),.error(),.stale_job(),.aborted(),.error_code(),.result_valid(result_valid),
        .result_ready_i(result_ready_i),.result_payload(result_payload)
    );

    // Reuse the transaction-compatible, oracle-qualified full work-item core.
    phk2_timing_core_contract real_core (
        .clk(clk),.rst(core_rst),.descriptor_valid(core_d_valid),.descriptor_ready(core_d_ready),
        .descriptor_payload(core_d_payload),.range_valid(core_r_valid),.range_ready(core_r_ready),
        .range_generation(core_r_generation),.range_job_key(core_r_job_key),
        .range_start(core_r_start),.range_count(core_r_count),.range_id(core_r_id),
        .abort_valid(core_a_valid),.abort_ready(core_a_ready),.abort_generation(core_a_generation),
        .abort_job_key(core_a_job_key),.abort_range_id(core_a_id),.abort_reason(core_a_reason),
        .busy(core_busy),.result_ready(core_result_ready),.error(core_error),.stale_job(core_stale),.overflow(),.aborted(core_aborted),
        .error_code(core_error_code),.result_valid(core_result_valid),.result_ready_i(core_result_ready_i),
        .result_payload(core_result_payload)
    );

    wire enc_ready, enc_busy, enc_done, enc_len_error;
    reg enc_start;
    reg response_error;
    phk2_protocol_response_encoder #(.MAX_PAYLOAD(MAX_RESPONSE_PAYLOAD)) response_encoder (
        .clk(clk),.rst(rst),.start(enc_start),.ready(enc_ready),.request_opcode(opcode_q),
        .error_response(response_error),.sequence_id(sequence_q),.payload_length(response_length),
        .payload(response_payload),.tx_valid(tx_valid),.tx_ready(tx_ready),.tx_data(tx_data),
        .busy(enc_busy),.done(enc_done),.length_error(enc_len_error)
    );

    task automatic make_error(input [15:0] code);
        begin response_payload<=0;response_payload[0+:16]<=code;response_length<=2;response_error<=1'b1;state<=S_RESP_START;end
    endtask
    task automatic make_empty_success;
        begin response_payload<=0;response_length<=0;response_error<=1'b0;state<=S_RESP_START;end
    endtask

    integer i;
    always @(posedge clk) begin
        enc_start<=1'b0;
        reset_req<=1'b0;
        if(rst) begin
            state<=S_IDLE;opcode_q<=0;sequence_q<=0;length_q<=0;payload_q<=0;
            response_payload<=0;response_length<=0;active_generation<=0;active_job_key<=0;
            active_range_id<=0;active_count<=0;expected_slot<=0;read_limit<=0;read_received<=0;
            loaded<=0;hello_q<=0;sticky_error<=0;sticky_stale<=0;sticky_aborted<=0;
            sticky_error_code<=0;reset_req<=0;
            response_error<=0;
        end else begin
            if(enc_len_error) begin sticky_error<=1;sticky_error_code<=E_INTERNAL;state<=S_IDLE;end
            if(cmd_valid&&cmd_ready) begin
                opcode_q<=cmd_opcode;sequence_q<=cmd_sequence;length_q<=cmd_length;payload_q<=cmd_payload;
                case(cmd_opcode)
                    OP_HELLO: if(cmd_length!=0) make_error(E_BAD_LENGTH); else begin
                        response_payload<=0;response_payload[0+:8]<=1;response_payload[8+:8]<=0;
                        response_payload[16+:16]<=16'd3;response_payload[32+:16]<=16'd112;
                        response_payload[48+:16]<=16'd64;response_payload[64+:16]<=16'd112;
                        response_payload[80+:32]<=32'h3f;response_length<=14;hello_q<=1;state<=S_RESP_START;
                        response_error<=1'b0;
                    end
                    OP_LOAD: if(cmd_length!=112) make_error(E_BAD_LENGTH);
                             else if(loaded&&cmd_payload[256+:64]<=active_generation) make_error(E_STALE);
                             else state<=S_LOAD;
                    OP_START: if(cmd_length!=48) make_error(E_BAD_LENGTH);
                              else if(!loaded||cmd_payload[0+:64]!=active_generation||cmd_payload[64+:256]!=active_job_key) begin sticky_stale<=1;make_error(E_STALE);end
                              else if(cmd_payload[320+:32]!=0||cmd_payload[352+:16]==0||cmd_payload[352+:16]>64||cmd_payload[368+:16]==0) make_error(E_RANGE);
                              else state<=S_START;
                    OP_STATUS: if(cmd_length!=10) make_error(E_BAD_LENGTH);
                               else if(cmd_payload[0+:64]!=active_generation||cmd_payload[64+:16]!=active_range_id) begin sticky_stale<=1;make_error(E_STALE);end
                               else begin
                                   response_payload<=0;response_payload[0+:64]<=active_generation;
                                   response_payload[64+:16]<=active_range_id;
                                   response_payload[80+:8]<=core_busy?8'd2:(core_result_ready?8'd3:8'd1);
                                   response_payload[88+:8]<={2'b0,sticky_aborted,1'b0,(sticky_stale|core_stale),(sticky_error|core_error),core_result_ready,core_busy};
                                   response_payload[112+:16]<=core_result_ready?16'd1:16'd0;
                                   response_payload[144+:16]<=error_code;
                                   response_payload[160+:16]<=active_count;
                                   response_payload[176+:16]<=16'd512;
                                   response_length<=24;response_error<=1'b0;state<=S_RESP_START;
                               end
                    OP_READ: if(cmd_length!=46) make_error(E_BAD_LENGTH);
                             else if(cmd_payload[0+:64]!=active_generation||cmd_payload[64+:256]!=active_job_key||cmd_payload[320+:16]!=active_range_id) begin sticky_stale<=1;make_error(E_STALE);end
                             else if(cmd_payload[352+:16]>4) make_error(E_RANGE);
                             else if(cmd_payload[352+:16]==0) make_empty_success();
                             else if(!core_result_ready) make_error(E_NOT_READY);
                             else begin expected_slot<=cmd_payload[336+:16];read_limit<=cmd_payload[352+:16];read_received<=0;response_payload<=0;response_error<=1'b0;state<=S_READ;end
                    OP_ABORT: if(cmd_length!=44) make_error(E_BAD_LENGTH);
                              else if(cmd_payload[0+:64]!=active_generation||cmd_payload[64+:256]!=active_job_key||cmd_payload[320+:16]!=active_range_id) begin sticky_stale<=1;make_error(E_STALE);end
                              else state<=S_ABORT;
                    OP_RESET: if(cmd_length!=0) make_error(E_BAD_LENGTH);
                              else begin reset_req<=1;loaded<=0;active_generation<=0;active_job_key<=0;active_range_id<=0;active_count<=0;sticky_error<=0;sticky_stale<=0;sticky_aborted<=0;make_empty_success();end
                    default: make_error(E_BAD_OPCODE);
                endcase
            end
            if(state==S_LOAD && d_valid && d_ready) begin
                active_generation<=payload_q[256+:64];active_job_key<=payload_q[0+:256];
                active_range_id<=0;active_count<=0;loaded<=1;sticky_error<=0;sticky_stale<=0;sticky_aborted<=0;
                response_payload<=0;response_payload[0+:64]<=payload_q[256+:64];response_payload[64+:256]<=payload_q[0+:256];
                response_length<=40;state<=S_RESP_START;
                response_error<=1'b0;
            end
            if(state==S_START && r_valid && r_ready) begin
                active_range_id<=payload_q[368+:16];active_count<=payload_q[352+:16];expected_slot<=0;
                sticky_error<=0;sticky_stale<=0;sticky_aborted<=0;response_payload<=0;
                response_payload[0+:64]<=payload_q[0+:64];response_payload[64+:16]<=payload_q[368+:16];
                response_payload[80+:16]<=payload_q[352+:16];response_length<=12;state<=S_RESP_START;
                response_error<=1'b0;
            end
            if(state==S_ABORT && a_valid && a_ready) begin
                sticky_aborted<=1;response_payload<=0;response_length<=0;response_error<=1'b0;state<=S_RESP_START;
            end
            if(state==S_READ) begin
                if(result_valid && result_ready_i) begin
                    if(result_payload[0+:64]!=active_generation || result_payload[64+:16]!=active_range_id || result_payload[80+:16]!=expected_slot) begin
                        sticky_stale<=1;sticky_error<=1;sticky_error_code<=E_STALE;
                        response_payload<=0;response_payload[0+:16]<=E_STALE;response_length<=2;response_error<=1'b1;state<=S_RESP_START;
                    end else begin
                        response_payload[read_received*896+:896]<=result_payload;
                        read_received<=read_received+1'b1;expected_slot<=expected_slot+1'b1;
                        if(read_received+1'b1>=read_limit) begin response_length<=(read_received+1'b1)*112;state<=S_RESP_START;end
                    end
                end else if(!core_busy && read_received!=0) begin response_length<=read_received*112;state<=S_RESP_START;end
                else if(!core_busy && read_received==0) make_error(E_NOT_READY);
            end
            if(state==S_RESP_START && enc_ready) begin enc_start<=1'b1;state<=S_RESP_WAIT;end
            if(state==S_RESP_WAIT && enc_done) state<=S_IDLE;
        end
    end
endmodule
