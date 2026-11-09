`timescale 1ns/1ps
module tb_core_contract_adapter;
  reg clk=0; always #5 clk=~clk;
  reg rst=1, reset_req=0;
  reg descriptor_valid=0; wire descriptor_ready; reg [895:0] descriptor_payload=0;
  reg range_valid=0; wire range_ready; reg [63:0] range_generation=0;
  reg [255:0] range_job_key=0; reg [31:0] range_start=0; reg [15:0] range_count=0,range_id=0;
  reg abort_valid=0; wire abort_ready; reg [63:0] abort_generation=0;
  reg [255:0] abort_job_key=0; reg [15:0] abort_range_id=0,abort_reason=0;
  wire core_rst,core_descriptor_valid; reg core_descriptor_ready=0; wire [895:0] core_descriptor_payload;
  wire core_range_valid; reg core_range_ready=0; wire [63:0] core_range_generation;
  wire [255:0] core_range_job_key; wire [31:0] core_range_start; wire [15:0] core_range_count,core_range_id;
  wire core_abort_valid; reg core_abort_ready=0; wire [63:0] core_abort_generation;
  wire [255:0] core_abort_job_key; wire [15:0] core_abort_range_id,core_abort_reason;
  reg core_busy=0,core_result_ready=0,core_error=0,core_stale_job=0,core_aborted=0;
  reg [15:0] core_error_code=0; reg core_result_valid=0; wire core_result_ready_i;
  reg [895:0] core_result_payload=0; wire busy,result_ready,error,stale_job,aborted;
  wire [15:0] error_code; wire result_valid; reg result_ready_i=0; wire [895:0] result_payload;
  integer checks=0, delay_cycles, seed=32'h50484b32, i;

  phk2_core_contract_adapter dut(.*);

  task wait_desc_accept;
    begin
      descriptor_valid=1;
      for(i=0;i<100 && !descriptor_ready;i=i+1) begin
        core_descriptor_ready=($urandom(seed)%4)!=0; @(negedge clk);
      end
      if(!descriptor_ready) $fatal(1,"descriptor ready timeout");
      if(!core_descriptor_valid || core_descriptor_payload!==descriptor_payload) $fatal(1,"descriptor not passed unchanged");
      @(posedge clk); @(negedge clk); descriptor_valid=0; core_descriptor_ready=0; checks=checks+1;
    end
  endtask
  task start_range(input [63:0] gen,input [255:0] key,input [15:0] rid,input [15:0] cnt);
    begin
      range_generation=gen; range_job_key=key; range_start=32'h1234; range_count=cnt; range_id=rid; range_valid=1;
      #1;
      if(!range_ready) begin
        core_range_ready=1; #1;
      end
      if(range_generation==descriptor_payload[256+:64] && key==descriptor_payload[0+:256]) begin
        if(!core_range_valid) $fatal(1,"valid range was not forwarded");
      end else if(core_range_valid) $fatal(1,"stale range reached core");
      @(posedge clk); @(negedge clk); range_valid=0; core_range_ready=0; checks=checks+1;
    end
  endtask
  initial begin
    repeat(4) @(negedge clk); rst=0; repeat(2) @(negedge clk);
    descriptor_payload=0; descriptor_payload[0+:256]=256'h012345; descriptor_payload[256+:64]=64'd9;
    descriptor_payload[320+:64]=64'h12345678; wait_desc_accept();
    start_range(64'd9,256'h012345,16'd5,16'd1);
    if(busy||error||stale_job) $fatal(1,"unexpected status after valid start");

    // Variable core response delay and a long consumer stall. Payload must stay stable.
    delay_cycles=$urandom(seed)%80; repeat(delay_cycles) @(negedge clk);
    core_result_payload=0; core_result_payload[0+:64]=9; core_result_payload[64+:16]=5;
    core_result_payload[128+:256]=256'hdeadbeef; core_result_valid=1; result_ready_i=0; #1;
    if(!result_valid || core_result_ready_i || result_payload!==core_result_payload) $fatal(1,"result backpressure/payload failure");
    repeat(11) begin @(negedge clk); if(!result_valid || result_payload!==core_result_payload) $fatal(1,"result changed while stalled"); end
    result_ready_i=1; #1; if(!core_result_ready_i) $fatal(1,"result ready was not propagated");
    @(posedge clk); @(negedge clk); core_result_valid=0; result_ready_i=0; checks=checks+1;

    // Stale generation is acknowledged locally and never sent to the core.
    start_range(64'd8,256'h012345,16'd6,16'd1);
    if(!stale_job || !error || error_code!=16'd4) $fatal(1,"stale range not reported");
    checks=checks+1;

    // Stale result is drained, hidden from the board, and reported.
    core_result_payload[0+:64]=64'd8; core_result_payload[64+:16]=16'd5; core_result_valid=1; #1;
    if(result_valid || !core_result_ready_i) $fatal(1,"stale result was not discarded");
    @(posedge clk); @(negedge clk); core_result_valid=0;
    if(!stale_job || !error) $fatal(1,"stale result status missing"); checks=checks+1;

    // Invalid count is rejected at the boundary before reaching the core.
    range_generation=9; range_job_key=256'h012345; range_id=7; range_count=0; range_valid=1; #1;
    if(!range_ready || core_range_valid) $fatal(1,"invalid range count reached core");
    @(posedge clk); @(negedge clk); range_valid=0;
    if(!error || error_code!=16'd10) $fatal(1,"invalid range count status mismatch"); checks=checks+1;

    // Independent status propagation and abort identity handshake.
    core_busy=1; core_result_ready=1; core_error=1; core_error_code=16'd12; core_stale_job=1; core_aborted=1; #1;
    if(!busy || !result_ready || !error || !stale_job || !aborted || error_code!=16'd12) $fatal(1,"core status propagation mismatch");
    core_busy=0; core_result_ready=0; core_error=0; core_stale_job=0; core_aborted=0;
    abort_generation=9; abort_job_key=256'h012345; abort_range_id=5; abort_reason=2; abort_valid=1; core_abort_ready=1; #1;
    if(!abort_ready || !core_abort_valid || core_abort_reason!=2) $fatal(1,"abort handshake mismatch");
    @(posedge clk); @(negedge clk); abort_valid=0; core_abort_ready=0; checks=checks+1;

    // Reset clears adapter identity/status and reaches the core reset.
    reset_req=1; #1; if(!core_rst || result_valid || core_range_valid) $fatal(1,"reset isolation mismatch");
    @(posedge clk); @(negedge clk); reset_req=0; if(stale_job||error) $fatal(1,"reset did not clear status"); checks=checks+1;
    $display("CORE_ADAPTER_RTL_TESTS=%0d/9",checks); if(checks!=9) $fatal(1,"test count mismatch"); $finish;
  end
endmodule
