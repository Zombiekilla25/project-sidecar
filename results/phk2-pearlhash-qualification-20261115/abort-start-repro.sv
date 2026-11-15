// Independent minimal reproducer for phk2_batch64_controller abort/start
// precedence. This is an audit fixture; it does not alter the candidate.
module abort_start_repro;
  reg clk=0, rst=1, abort=0, start=0;
  reg [63:0] loaded_generation=7, request_generation=7;
  reg [12:0] base_row=0, base_col=0;
  reg item_accept=0, item_done=0;
  wire active, stale;
  wire [5:0] work_index;
  wire [12:0] row_tile, col_tile;
  wire [6:0] issued_count, completed_count;
  phk2_batch64_controller dut(.*);
  always #5 clk=~clk;
  initial begin
    @(posedge clk); #1 rst=0; start=1;
    @(posedge clk); #1 start=0;
    if (active !== 1'b1) $fatal(1,"setup failed");
    abort=1; start=1;
    @(posedge clk); #1;
    $display("after simultaneous abort/start: active=%0d stale=%0d",active,stale);
    $finish;
  end
endmodule
