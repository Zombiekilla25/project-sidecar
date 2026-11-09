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
  reg [255:0] expected_operands[0:4095];
  reg [95:0] expected_record;
  integer count=1,slot=0,cycles=0,i;
  integer check_operands=0, operand_index=0,last_subtile=-1,subrow,subcol,j;
  phk2_timing_core_contract dut(
    .clk(clk),.rst(rst),.descriptor_valid(descriptor_valid),.descriptor_ready(descriptor_ready),
    .descriptor_payload(descriptor_payload),.range_valid(range_valid),.range_ready(range_ready),
    .range_generation(range_generation),.range_job_key(range_job_key),.range_start(range_start),
    .range_count(range_count),.range_id(range_id),.abort_valid(abort_valid),.abort_ready(abort_ready),
    .abort_generation(abort_generation),.abort_job_key(abort_job_key),.abort_range_id(abort_range_id),
    .abort_reason(abort_reason),.busy(busy),.result_ready(result_ready),.error(error),
    .stale_job(stale_job),.overflow(overflow),.aborted(aborted),.error_code(error_code),
    .result_valid(result_valid),.result_ready_i(result_ready_i),.result_payload(result_payload));
  always @(negedge clk) begin
    if(check_operands && !rst && dut.item_slot==0 && dut.workgen_valid && dut.tile_operand_ready) begin
      if(last_subtile!=dut.subtile_index) begin operand_index=0;last_subtile=dut.subtile_index;end
      if(operand_index>=4096) $fatal(1,"too many workgen records in subtile=%0d",dut.subtile_index);
      subrow=dut.subtile_index/2; subcol=dut.subtile_index%2;
      expected_record=0;
      for(j=0;j<4;j=j+1) expected_record[j*8+:8]=expected_operands[operand_index][(subrow*4+j)*8+:8];
      for(j=0;j<8;j=j+1) expected_record[32+j*8+:8]=expected_operands[operand_index][(16+subcol*8+j)*8+:8];
      if(dut.workgen_operand!==expected_record)
        $fatal(1,"operand mismatch subtile=%0d k=%0d got=%024h expected=%024h",dut.subtile_index,operand_index,dut.workgen_operand,expected_record);
      operand_index=operand_index+1;
    end
  end
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
      if(error || stale_job || overflow) $fatal(1,"core error=%0d stale=%b overflow=%b",error_code,stale_job,overflow);
      if(result_valid && result_ready_i) begin
        $display("RESULT_%0d=%0224h",slot,result_payload);
        slot=slot+1;
      end
      // The diagnostic now executes eight 4x8 subtiles per work item; scale
      // the watchdog with batch count rather than timing out a valid Batch64.
      if(cycles>(count*20000000+1000000)) $fatal(1,"watchdog expired count=%0d cycles=%0d",count,cycles);
    end
    if(check_operands && (last_subtile!=7 || operand_index!=4096)) $fatal(1,"incomplete 8-subtile workgen final_subtile=%0d records=%0d",last_subtile,operand_index);
    $display("TIMING_CORE_CONTRACT_SIM=PASS COUNT=%0d CYCLES=%0d",count,cycles);
    $finish;
  end
endmodule
