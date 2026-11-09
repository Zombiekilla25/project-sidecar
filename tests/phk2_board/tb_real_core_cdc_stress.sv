`timescale 1ns/1ps
module tb_real_core_cdc_stress;
  localparam integer N=12000;
  reg core_clk=0,tck=0,rst=1,rx_wr_en=0,tx_rd_en=0;
  always #5 core_clk=~core_clk;
  integer half_ns=7;
  reg [15:0] clock_lfsr=16'hbabe;
  always begin #half_ns;tck=~tck;clock_lfsr={clock_lfsr[14:0],clock_lfsr[15]^clock_lfsr[13]^clock_lfsr[12]^clock_lfsr[10]};half_ns=5+clock_lfsr[2:0];end
  reg [7:0] rx_wr_data=0;
  wire rx_full,rx_empty,rx_valid,rx_ready,cmd_valid,cmd_ready,tx_valid,tx_ready,tx_full,tx_empty;
  wire [7:0] rx_data,tx_fifo_data;
  wire [9:0] rx_wc,rx_rc,tx_wc,tx_rc;
  wire [7:0] opcode,tx_data,parse_error_code;
  wire [15:0] sequence_id,length,error_code;
  wire [895:0] cmd_payload;
  wire sticky_error,busy,result_ready,error,stale_job,overflow,aborted,hello_seen,descriptor_loaded;
  integer core_edges=0,tck_edges=0,full_input_edges=0,full_output_edges=0;
  integer sent=0,received=0,response_byte=0;
  reg producer_done=0,consumer_start=0;
  reg [7:0] observed;
  reg [7:0] expected[0:37];
  reg [7:0] frame_seen[0:33];
  reg [31:0] crc;

  phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(9)) input_cdc(.wr_clk(tck),.wr_arst(rst),.wr_en(rx_wr_en&&!rx_full),.wr_data(rx_wr_data),.wr_full(rx_full),.wr_count(rx_wc),.rd_clk(core_clk),.rd_arst(rst),.rd_en(rx_valid&&rx_ready),.rd_data(rx_data),.rd_empty(rx_empty),.rd_count(rx_rc));
  assign rx_valid=!rx_empty;
  phk2_async_fifo #(.WIDTH(8),.ADDR_BITS(9)) output_cdc(.wr_clk(core_clk),.wr_arst(rst),.wr_en(tx_valid&&!tx_full),.wr_data(tx_data),.wr_full(tx_full),.wr_count(tx_wc),.rd_clk(tck),.rd_arst(rst),.rd_en(tx_rd_en&&!tx_empty),.rd_data(tx_fifo_data),.rd_empty(tx_empty),.rd_count(tx_rc));
  assign tx_ready=!tx_full;
  phk2_protocol_decoder decoder(.clk(core_clk),.rst(rst),.byte_valid(rx_valid),.byte_ready(rx_ready),.byte_data(rx_data),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(opcode),.cmd_sequence(sequence_id),.cmd_length(length),.cmd_payload(cmd_payload),.sticky_error(sticky_error),.error_code(parse_error_code));
  phk2_real_core_endpoint endpoint(.clk(core_clk),.rst(rst),.cmd_valid(cmd_valid),.cmd_ready(cmd_ready),.cmd_opcode(opcode),.cmd_sequence(sequence_id),.cmd_length(length),.cmd_payload(cmd_payload),.tx_valid(tx_valid),.tx_ready(tx_ready),.tx_data(tx_data),.busy(busy),.result_ready(result_ready),.error(error),.stale_job(stale_job),.overflow(overflow),.aborted(aborted),.hello_seen(hello_seen),.descriptor_loaded(descriptor_loaded),.error_code(error_code));
  always @(posedge core_clk)if(!rst)begin core_edges=core_edges+1;if(tx_full)full_output_edges=full_output_edges+1;end
  always @(posedge tck)if(!rst)begin tck_edges=tck_edges+1;if(rx_full)full_input_edges=full_input_edges+1;end

  function [31:0] crc_byte(input [31:0] ci,input [7:0] data);integer b;reg [31:0] c;begin c=ci^data;for(b=0;b<8;b=b+1)c=c[0]?(c>>1)^32'hedb88320:(c>>1);crc_byte=c;end endfunction
  task send_byte(input [7:0] b);begin @(negedge tck);while(rx_full)@(negedge tck);rx_wr_data=b;rx_wr_en=1;@(posedge tck);@(negedge tck);rx_wr_en=0;end endtask
  task send_status(input [15:0] sn);integer n;reg [7:0] b;reg [31:0] c;begin
    c=32'hffffffff;
    b=8'hc2;send_byte(b);c=crc_byte(c,b);b=8'h5a;send_byte(b);c=crc_byte(c,b);
    b=1;send_byte(b);c=crc_byte(c,b);b=8'h12;send_byte(b);c=crc_byte(c,b);
    b=0;send_byte(b);c=crc_byte(c,b);send_byte(0);c=crc_byte(c,0);
    b=sn[7:0];send_byte(b);c=crc_byte(c,b);b=sn[15:8];send_byte(b);c=crc_byte(c,b);
    b=10;send_byte(b);c=crc_byte(c,b);send_byte(0);c=crc_byte(c,0);
    for(n=0;n<10;n=n+1)begin send_byte(0);c=crc_byte(c,0);end
    c=~c;for(n=0;n<4;n=n+1)send_byte(c[n*8+:8]);
  end endtask
  task consume_and_check(input integer sn);integer n;reg [31:0] c;begin
    for(n=0;n<38;n=n+1)begin
      @(negedge tck);while(tx_empty)@(negedge tck);observed=tx_fifo_data;
      if(n==0&&observed!=8'hc2)$fatal(1,"bad response magic");
      if(n==1&&observed!=8'h5a)$fatal(1,"bad response magic2");
      if(n==2&&observed!=1)$fatal(1,"bad version");
      if(n==3&&observed!=8'h92)$fatal(1,"bad STATUS response opcode");
      if(n==4&&observed!=1)$fatal(1,"bad response flags");
      if(n==6&&observed!=sn[7:0])$fatal(1,"response ordering low sequence got=%0d expected=%0d",observed,sn);
      if(n==7&&observed!=sn[15:8])$fatal(1,"response ordering high sequence");
      if(n==8&&observed!=24)$fatal(1,"bad STATUS response length");
      if(n==9&&observed!=0)$fatal(1,"bad HELLO response length high");
      if(n>=10&&n<34&&observed!==expected[n])$fatal(1,"STATUS response payload mismatch off=%0d got=%02x expected=%02x",n-10,observed,expected[n]);
      if(n<34)frame_seen[n]=observed;
      if(n>=34)begin
        c=32'hffffffff;
        for(integer k=0;k<34;k=k+1)c=crc_byte(c,frame_seen[k]);
        c=~c;
        if(observed!==c[(n-34)*8+:8])$fatal(1,"response CRC mismatch byte=%0d",n-34);
      end
      tx_rd_en=1;@(posedge tck);@(negedge tck);tx_rd_en=0;
    end
    received=received+1;
  end endtask

  initial begin
    for(integer e=0;e<38;e=e+1)expected[e]=0;
    expected[20]=1;expected[32]=0;expected[33]=2;
    repeat(8)@(posedge core_clk);repeat(8)@(posedge tck);#1 rst=0;
    repeat(5)@(posedge core_clk);repeat(5)@(posedge tck);consumer_start=1;
    fork
      begin
        for(sent=0;sent<N;sent=sent+1)send_status(sent[15:0]);
        producer_done=1;
      end
      begin
        // Host intentionally waits while both FIFOs fill, then drains responses.
        #50000;
        for(integer s=0;s<N;s=s+1)consume_and_check(s);
      end
    join
    if(sent!=N||received!=N)$fatal(1,"lost or duplicate command/response sent=%0d received=%0d",sent,received);
    if(sticky_error||error||stale_job||overflow||busy)$fatal(1,"unexpected endpoint state error=%b parse=%b",error,sticky_error);
    if(full_input_edges==0||full_output_edges==0)$fatal(1,"backpressure not exercised in/out=%0d/%0d",full_input_edges,full_output_edges);
    if(core_edges+tck_edges<500000)$fatal(1,"CDC transition count too low");
    $display("REAL_CORE_CDC_STRESS=PASS COMMAND=STATUS REQUESTS=%0d RESPONSES=%0d INPUT_FULL_EDGES=%0d RESULT_FULL_EDGES=%0d DUPLICATE_RESULTS=0 DROPPED_RESULTS=0 UNEXPECTED_FAILURES=0 DEADLOCKS=0 EVENTS=%0d",sent,received,full_input_edges,full_output_edges,core_edges+tck_edges);
    $finish;
  end
  initial begin #200000000;$fatal(1,"CDC stress watchdog sent=%0d received=%0d",sent,received);end
endmodule
