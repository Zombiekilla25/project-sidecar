`timescale 1ns/1ps
module tb_timing_core_contract;
  reg clk=0; always #5 clk=~clk;
  reg rst=1, descriptor_valid=0, range_valid=0, abort_valid=0;
  reg [895:0] descriptor_payload=0;
  reg [63:0] range_generation=0, abort_generation=0;
  reg [255:0] range_job_key=0, abort_job_key=0;
  reg [31:0] range_start=0;
  reg [15:0] range_count=0, range_id=0, abort_range_id=0, abort_reason=0;
  reg result_ready_i=1;
  wire descriptor_ready,range_ready,abort_ready,busy,result_ready,error,stale_job,overflow,aborted;
  wire [15:0] error_code;
  wire result_valid;
  wire [895:0] result_payload;
  reg [7:0] desc_bytes[0:111];
  reg [95:0] expected_operands[0:4095];
  integer count=1,slot=0,cycles=0,i;
  integer check_operands=0, operand_index=0;
  phk2_timing_core_contract dut(
    .clk(clk),.rst(rst),.descriptor_valid(descriptor_valid),.descriptor_ready(descriptor_ready),
    .descriptor_payload(descriptor_payload),.range_valid(range_valid),.range_ready(range_ready),
    .range_generation(range_generation),.range_job_key(range_job_key),.range_start(range_start),
    .range_count(range_count),.range_id(range_id),.abort_valid(abort_valid),.abort_ready(abort_ready),
    .abort_generation(abort_generation),.abort_job_key(abort_job_key),.abort_range_id(abort_range_id),
    .abort_reason(abort_reason),.busy(busy),.result_ready(result_ready),.error(error),
    .stale_job(stale_job),.overflow(overflow),.aborted(aborted),.error_code(error_code),
    .result_valid(result_valid),.result_ready_i(result_ready_i),.result_payload(result_payload));
  initial begin
    if ($value$plusargs("COUNT=%d",count)==0) count=1;
    check_operands=$test$plusargs("CHECK_OPERANDS");
    $readmemh("descriptor.mem",desc_bytes);
    if(check_operands) $readmemh("operands.mem",expected_operands);
    for(i=0;i<112;i=i+1) descriptor_payload[i*8+:8]=desc_bytes[i];
    repeat(5) @(posedge clk); #1 rst=0;
    @(negedge clk); descriptor_valid=1;
    do @(posedge clk); while(!descriptor_ready);
    @(negedge clk); descriptor_valid=0;
    range_generation=descriptor_payload[256+:64];
    range_job_key=descriptor_payload[0+:256];
    range_start=0; range_count=count; range_id=1;
    @(negedge clk); range_valid=1;
    do @(posedge clk); while(!range_ready);
    @(negedge clk); range_valid=0;
    while(slot<count) begin
      @(posedge clk); #1; cycles=cycles+1;
      if(check_operands && dut.workgen_valid && dut.tile_operand_ready) begin
        if(dut.workgen_operand!==expected_operands[operand_index])
          $fatal(1,"operand mismatch index=%0d got=%024h expected=%024h",operand_index,dut.workgen_operand,expected_operands[operand_index]);
        operand_index=operand_index+1;
      end
      if(error || stale_job || overflow) $fatal(1,"core error=%0d stale=%b overflow=%b",error_code,stale_job,overflow);
      if(result_valid && result_ready_i) begin
        $display("RESULT_%0d=%0224h",slot,result_payload);
        slot=slot+1;
      end
      if(cycles>200000000) $fatal(1,"watchdog expired");
    end
    $display("TIMING_CORE_CONTRACT_SIM=PASS COUNT=%0d CYCLES=%0d",count,cycles);
    $finish;
  end
endmodule
