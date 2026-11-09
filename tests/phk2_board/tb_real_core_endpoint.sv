`timescale 1ns/1ps
module tb_real_core_endpoint;
  reg clk=0; always #5 clk=~clk;
  reg tck=0; always #7 tck=~tck;
  reg rst=1, rx_wr_en=0, tx_rd_en=0;
  reg [7:0] rx_wr_data=0;
  wire rx_full,rx_empty,rx_valid,rx_ready,cmd_valid,cmd_ready,tx_valid,tx_ready,tx_full,tx_empty;
  wire [7:0] rx_data,tx_fifo_data;
  wire [9:0] rx_wc,rx_rc,tx_wc,tx_rc;
  wire [7:0] opcode,tx_data,parse_error_code;
  wire [15:0] sequence_id,length,error_code;
  wire [895:0] cmd_payload;
  wire sticky_error,busy,result_ready,error,stale_job,overflow,aborted,hello_seen,descriptor_loaded;
  integer response_count=0,cycles=0,i,j,slot,count=1,base,nrecords,seq=0;
  reg [7:0] response_bytes[0:20000];
  reg [7:0] desc_bytes[0:111];
  reg [7:0] expected_bytes[0:7167];
  reg [895:0] frame_payload;
  reg [63:0] generation, generation_next;
  reg [255:0] job_key;
  reg [31:0] crc;

  phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(9)) input_cdc(.wr_clk(tck),.wr_arst(rst),.wr_en(rx_wr_en&&!rx_full),.wr_data(rx_wr_data),.wr_full(rx_full),.wr_count(rx_wc),.rd_clk(clk),.rd_arst(rst),.rd_en(rx_valid&&rx_ready),.rd_data(rx_data),.rd_empty(rx_empty),.rd_count(rx_rc));
  assign rx_valid=!rx_empty;
  phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(9)) output_cdc(.wr_clk(clk),.wr_arst(rst),.wr_en(tx_valid&&!tx_full),.wr_data(tx_data),.wr_full(tx_full),.wr_count(tx_wc),.rd_clk(tck),.rd_arst(rst),.rd_en(tx_rd_en&&!tx_empty),.rd_data(tx_fifo_data),.rd_empty(tx_empty),.rd_count(tx_rc));
  assign tx_ready=!tx_full;
  phk2_protocol_decoder decoder(.clk(clk),.rst(rst),.byte_valid(rx_valid),.byte_ready(rx_ready),
    .byte_data(rx_data),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(opcode),
    .cmd_sequence(sequence_id),.cmd_length(length),.cmd_payload(cmd_payload),
    .sticky_error(sticky_error),.error_code(parse_error_code));
  phk2_real_core_endpoint endpoint(.clk(clk),.rst(rst),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),
    .cmd_opcode(opcode),.cmd_sequence(sequence_id),.cmd_length(length),.cmd_payload(cmd_payload),
    .tx_valid(tx_valid),.tx_ready(tx_ready),.tx_data(tx_data),.busy(busy),.result_ready(result_ready),
    .error(error),.stale_job(stale_job),.overflow(overflow),.aborted(aborted),
    .hello_seen(hello_seen),.descriptor_loaded(descriptor_loaded),.error_code(error_code));

  function [31:0] crc_byte(input [31:0] ci,input [7:0] data);
    integer b; reg [31:0] c; begin c=ci^data;for(b=0;b<8;b=b+1)c=c[0]?(c>>1)^32'hedb88320:(c>>1);crc_byte=c;end
  endfunction
  task send_byte(input [7:0] b);
    begin @(negedge tck);while(rx_full)@(negedge tck);rx_wr_data=b;rx_wr_en=1;@(posedge tck);@(negedge tck);rx_wr_en=0;end
  endtask
  task send_frame(input [7:0] op,input integer plen,input [895:0] pld,input [15:0] sn);
    integer n; reg [7:0] b; reg [31:0] c;
    begin
      c=32'hffffffff;
      b=8'hc2;send_byte(b);c=crc_byte(c,b);b=8'h5a;send_byte(b);c=crc_byte(c,b);
      b=1;send_byte(b);c=crc_byte(c,b);b=op;send_byte(b);c=crc_byte(c,b);
      b=0;send_byte(b);c=crc_byte(c,b);send_byte(0);c=crc_byte(c,0);
      b=sn[7:0];send_byte(b);c=crc_byte(c,b);b=sn[15:8];send_byte(b);c=crc_byte(c,b);
      b=plen[7:0];send_byte(b);c=crc_byte(c,b);b=plen[15:8];send_byte(b);c=crc_byte(c,b);
      for(n=0;n<plen;n=n+1)begin b=pld[n*8+:8];send_byte(b);c=crc_byte(c,b);end
      c=~c;for(n=0;n<4;n=n+1)send_byte(c[n*8+:8]);
    end
  endtask
  task await_frame(input integer base_index,input integer payload_bytes,input [7:0] expected_opcode,input [15:0] expected_seq);
    integer target,n; reg [31:0] c; reg [31:0] gotcrc;
    begin
      target=base_index+10+payload_bytes+4;
      n=0;while(response_count<target && n<100000000)begin
        @(negedge tck);
        if(!tx_empty)begin response_bytes[response_count]=tx_fifo_data;response_count=response_count+1;tx_rd_en=1;end else tx_rd_en=0;
        @(posedge tck);@(negedge tck);tx_rd_en=0;n=n+1;
      end
      if(response_count!=target)$fatal(1,"response timeout base=%0d got=%0d expected=%0d rxwc=%0d rxrc=%0d txwc=%0d txrc=%0d empty=%b sticky=%b parse=%0d cmd=%b ready=%b epstate=%0d",base_index,response_count,target,rx_wc,rx_rc,tx_wc,tx_rc,tx_empty,sticky_error,parse_error_code,cmd_valid,cmd_ready,endpoint.state);
      if(response_bytes[base_index+0]!=8'hc2||response_bytes[base_index+1]!=8'h5a||response_bytes[base_index+2]!=1||response_bytes[base_index+3]!=(expected_opcode|8'h80))$fatal(1,"response header/opcode mismatch");
      if({response_bytes[base_index+7],response_bytes[base_index+6]}!=expected_seq)$fatal(1,"response sequence mismatch");
      if({response_bytes[base_index+9],response_bytes[base_index+8]}!=payload_bytes)$fatal(1,"response length mismatch");
      c=32'hffffffff;for(n=0;n<10+payload_bytes;n=n+1)c=crc_byte(c,response_bytes[base_index+n]);c=~c;
      gotcrc={response_bytes[base_index+13+payload_bytes],response_bytes[base_index+12+payload_bytes],response_bytes[base_index+11+payload_bytes],response_bytes[base_index+10+payload_bytes]};
      if(gotcrc!==c)$fatal(1,"response CRC mismatch");
    end
  endtask

  initial begin
    if($value$plusargs("COUNT=%d",count)==0)count=1;
    $readmemh("descriptor.mem",desc_bytes);$readmemh("expected_results.mem",expected_bytes);
    for(i=0;i<112;i=i+1)frame_payload[i*8+:8]=desc_bytes[i];
    generation=0;job_key=0;for(i=0;i<8;i=i+1)generation[i*8+:8]=desc_bytes[32+i];for(i=0;i<32;i=i+1)job_key[i*8+:8]=desc_bytes[i];
    repeat(5)@(posedge clk);#1 rst=0;repeat(6)@(posedge tck);
    base=response_count;frame_payload=0;send_frame(8'h01,0,frame_payload,seq);await_frame(base,14,8'h01,seq);
    if(response_bytes[base+10]!=1||response_bytes[base+11]!=0||response_bytes[base+12]!=3||response_bytes[base+13]!=0||
       response_bytes[base+14]!=112||response_bytes[base+15]!=0||response_bytes[base+16]!=64||response_bytes[base+17]!=0||
       response_bytes[base+18]!=112||response_bytes[base+19]!=0||response_bytes[base+20]!=8'h3f||response_bytes[base+21]!=0||
       response_bytes[base+22]!=0||response_bytes[base+23]!=0)$fatal(1,"HELLO payload differs from host golden vector");
    seq=seq+1;$display("HELLO_OK");
    if(!hello_seen)$fatal(1,"HELLO state missing");
    // Reset from an idle, initialized endpoint before loading work.
    base=response_count;send_frame(8'h1f,0,0,seq);await_frame(base,0,8'h1f,seq);seq=seq+1;
    repeat(4)@(posedge clk);
    if(descriptor_loaded||busy||result_ready||error)$fatal(1,"reset-idle control failed");
    base=response_count;frame_payload=0;for(i=0;i<112;i=i+1)frame_payload[i*8+:8]=desc_bytes[i];send_frame(8'h10,112,frame_payload,seq);await_frame(base,40,8'h10,seq);seq=seq+1;$display("LOAD_OK");
    if(!descriptor_loaded||error)$fatal(1,"descriptor load failed");
    frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;frame_payload[352+:16]=count;frame_payload[368+:16]=16'd1;
    base=response_count;send_frame(8'h11,48,frame_payload,seq);await_frame(base,12,8'h11,seq);seq=seq+1;$display("START_OK");
    slot=0;
    while(slot<count) begin
      cycles=0;while(!result_ready&&cycles<300000000)begin @(posedge clk);cycles=cycles+1;end
      if(!result_ready)$fatal(1,"work result timeout slot=%0d",slot);
      if(slot==0) begin
        frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:16]=16'd1;
        base=response_count;send_frame(8'h12,10,frame_payload,seq);await_frame(base,24,8'h12,seq);seq=seq+1;
        if((response_bytes[base+10+11]&8'h02)==0)$fatal(1,"STATUS did not report result_ready");
      end
      nrecords=count-slot;if(nrecords>4)nrecords=4;
      frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;frame_payload[320+:16]=16'd1;frame_payload[336+:16]=slot;frame_payload[352+:16]=nrecords;
      base=response_count;send_frame(8'h13,46,frame_payload,seq);await_frame(base,nrecords*112,8'h13,seq);seq=seq+1;
      for(i=0;i<nrecords;i=i+1)for(j=0;j<112;j=j+1)
        if(response_bytes[base+10+i*112+j]!==expected_bytes[(slot+i)*112+j])
          $fatal(1,"result mismatch slot=%0d byte=%0d got=%02x expected=%02x",slot+i,j,response_bytes[base+10+i*112+j],expected_bytes[(slot+i)*112+j]);
      slot=slot+nrecords;
    end
    if(error||stale_job||overflow)$fatal(1,"endpoint error at completion code=%0d",error_code);

    // Board-path controls: stale identity, descriptor replacement, abort before
    // work, abort during work, reset during work, and reset with result pending.
    frame_payload=0;frame_payload[0+:64]=generation+1;frame_payload[64+:16]=1;
    base=response_count;send_frame(8'h12,10,frame_payload,seq);await_frame(base,2,8'h12,seq);seq=seq+1;
    if(response_bytes[base+4]!=8'h03||{response_bytes[base+11],response_bytes[base+10]}!=16'd4||!stale_job)
      $fatal(1,"stale-generation status control failed");
    generation_next=generation+1;
    frame_payload=0;for(i=0;i<112;i=i+1)frame_payload[i*8+:8]=desc_bytes[i];
    frame_payload[256+:64]=generation_next;
    base=response_count;send_frame(8'h10,112,frame_payload,seq);await_frame(base,40,8'h10,seq);seq=seq+1;
    generation=generation_next;
    frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;frame_payload[336+:16]=16'd1;
    base=response_count;send_frame(8'h14,44,frame_payload,seq);await_frame(base,0,8'h14,seq);seq=seq+1;
    if(!aborted||busy)$fatal(1,"abort-before-work control failed");

    frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;
    frame_payload[352+:16]=16'd64;frame_payload[368+:16]=16'd2;
    base=response_count;send_frame(8'h11,48,frame_payload,seq);await_frame(base,12,8'h11,seq);seq=seq+1;
    if(!busy)$fatal(1,"busy status was not asserted after START_RANGE");
    frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;frame_payload[320+:16]=16'd2;
    base=response_count;send_frame(8'h14,44,frame_payload,seq);await_frame(base,0,8'h14,seq);seq=seq+1;
    repeat(4)@(posedge clk);
    if(!aborted||busy||result_ready)$fatal(1,"abort-during-work control failed");

    frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;
    frame_payload[352+:16]=16'd64;frame_payload[368+:16]=16'd3;
    base=response_count;send_frame(8'h11,48,frame_payload,seq);await_frame(base,12,8'h11,seq);seq=seq+1;
    base=response_count;send_frame(8'h1f,0,0,seq);await_frame(base,0,8'h1f,seq);seq=seq+1;
    repeat(4)@(posedge clk);
    if(descriptor_loaded||busy||result_ready||error)$fatal(1,"reset-during-work control failed");

    // Load a fresh generation and let one result become pending; reset it
    // without reading it to exercise result invalidation at the board endpoint.
    generation_next=generation+2;frame_payload=0;
    for(i=0;i<112;i=i+1)frame_payload[i*8+:8]=desc_bytes[i];
    frame_payload[256+:64]=generation_next;
    base=response_count;send_frame(8'h10,112,frame_payload,seq);await_frame(base,40,8'h10,seq);seq=seq+1;
    generation=generation_next;
    frame_payload=0;frame_payload[0+:64]=generation;frame_payload[64+:256]=job_key;
    frame_payload[352+:16]=16'd1;frame_payload[368+:16]=16'd4;
    base=response_count;send_frame(8'h11,48,frame_payload,seq);await_frame(base,12,8'h11,seq);seq=seq+1;
    cycles=0;while(!result_ready&&cycles<300000000)begin @(posedge clk);cycles=cycles+1;end
    if(!result_ready)$fatal(1,"pending-result reset setup timed out");
    base=response_count;send_frame(8'h1f,0,0,seq);await_frame(base,0,8'h1f,seq);seq=seq+1;
    repeat(4)@(posedge clk);
    if(descriptor_loaded||busy||result_ready||error)$fatal(1,"reset-with-pending-result control failed");
    $display("REAL_CORE_CONTROL_TESTS=11/11");
    $display("REAL_CORE_ENDPOINT_PROTOCOL=PASS COUNT=%0d RESPONSE_BYTES=%0d",count,response_count);
    $finish;
  end
endmodule
