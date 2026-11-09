`timescale 1ns/1ps
module tb_phk2_async_fifo_backpressure;
  localparam integer N=100000;
  reg wr_clk=0,rd_clk=0,rst=1,wr_en=0,rd_en=0;
  always #3 wr_clk=~wr_clk;
  always #7 rd_clk=~rd_clk;
  reg [31:0] wr_data=0;
  wire full,empty;
  wire [31:0] rd_data;
  wire [9:0] wr_count,rd_count;
  integer sent=0,received=0,read_ticks=0,wr_edges=0,rd_edges=0,full_cycles=0,empty_read_attempts=0;
  reg writer_done=0,started=0;
  phk2_async_fifo #(.WIDTH(32),.ADDR_BITS(9)) dut(
    .wr_clk(wr_clk),.wr_arst(rst),.wr_en(wr_en),.wr_data(wr_data),.wr_full(full),.wr_count(wr_count),
    .rd_clk(rd_clk),.rd_arst(rst),.rd_en(rd_en),.rd_data(rd_data),.rd_empty(empty),.rd_count(rd_count));
  always @(posedge wr_clk) if(!rst) begin wr_edges=wr_edges+1;if(full)full_cycles=full_cycles+1;end
  always @(posedge rd_clk) if(!rst) rd_edges=rd_edges+1;
  initial begin
    repeat(6)@(posedge wr_clk);repeat(6)@(posedge rd_clk);#1 rst=0;repeat(4)@(posedge wr_clk);repeat(4)@(posedge rd_clk);started=1;
    fork
      begin
        while(sent<N) begin
          @(negedge wr_clk);wr_en=1;wr_data=sent;
          @(posedge wr_clk);
          if(!full)sent=sent+1;
        end
        @(negedge wr_clk);wr_en=0;writer_done=1;
      end
      begin
        while(received<N) begin
          @(negedge rd_clk);read_ticks=read_ticks+1;
          // Deliberately leave seven of every eight read opportunities stalled.
          rd_en=((read_ticks%8)==0);
          if(rd_en&&!empty&&rd_data!==received)
            $fatal(1,"FIFO ordering/data mismatch expected=%0d actual=%0d",received,rd_data);
          if(rd_en&&empty)empty_read_attempts=empty_read_attempts+1;
          @(posedge rd_clk);
          if(rd_en&&!empty)received=received+1;
        end
        @(negedge rd_clk);rd_en=0;
      end
    join
    if(!writer_done||sent!=N||received!=N)$fatal(1,"lost work sent=%0d received=%0d",sent,received);
    if(full_cycles==0)$fatal(1,"test did not exercise FIFO full/backpressure");
    if(wr_edges+rd_edges<500000)$fatal(1,"insufficient CDC edge coverage %0d",wr_edges+rd_edges);
    $display("FIFO_BACKPRESSURE=PASS SENT=%0d RECEIVED=%0d DUPLICATES=0 DROPS=0 FULL_CYCLES=%0d EMPTY_READ_ATTEMPTS=%0d CDC_CLOCK_EDGES=%0d",sent,received,full_cycles,empty_read_attempts,wr_edges+rd_edges);
    $finish;
  end
  initial begin #200000000;$fatal(1,"FIFO backpressure watchdog");end
endmodule
