`timescale 1ns/1ps
// Offline RTL contract test only. It drives the BSCANE2 USER3 event pins
// directly; it is not a TAP/IR model and does not qualify a physical sequence.
module tb_phk2_case_b_user3_status_contract;
  reg clk=0;
  always #5 clk=~clk;
  reg tck3=0;
  reg capture3=0;
  reg shift3=0;
  reg tdi3=0;
  reg tms3=0;
  reg update3=0;
  reg [5:0] status_snapshot=0;
  reg [31:0] expected_word;
  integer sample, bit_index;
  phk2_fk33_board_top dut(.clk_p(clk), .clk_n(~clk));

  initial begin
    wait(dut.core_rst === 1'b0);
    // Isolate USER3's local observation behavior after reset release. This
    // force is testbench-only; physical reset/TAP setup remains unqualified.
    force dut.bscan_rst = 1'b0;
    force dut.tck3 = tck3;
    force dut.s3 = 1'b1;
    force dut.c3 = capture3;
    force dut.sh3 = shift3;
    force dut.tdi3 = tdi3;
    force dut.tms3 = tms3;
    force dut.u3 = update3;
    // Exhaust the six-bit status input space. Expected output is computed
    // from the source contract, not a production/physical response constant.
    for (sample=0; sample<64; sample=sample+1) begin
      status_snapshot=sample[5:0];
      release dut.busy_s2; release dut.ready_s2; release dut.error_s2;
      release dut.stale_s2; release dut.overflow_s2; release dut.rx_full_s2;
      release dut.aborted_s2;
      force dut.busy_s2 = status_snapshot[0];
      force dut.ready_s2 = status_snapshot[1];
      force dut.error_s2 = status_snapshot[2];
      force dut.stale_s2 = status_snapshot[3];
      force dut.overflow_s2 = status_snapshot[4];
      force dut.rx_full_s2 = 1'b0;
      force dut.aborted_s2 = status_snapshot[5];
      expected_word={26'b0, status_snapshot};
      capture3=1; tdi3=sample[0]; tms3=sample[1]; update3=sample[2];
      #1; tck3=1; #1; tck3=0; capture3=0; #1;
      for (bit_index=0; bit_index<32; bit_index=bit_index+1) begin
        if (dut.tdo3 !== expected_word[bit_index])
          $fatal(1, "USER3 status relationship mismatch at sample=%0d bit=%0d", sample, bit_index);
        shift3=1;
        tdi3=~tdi3; tms3=~tms3; update3=~update3;
        #1; tck3=1; #1; tck3=0; shift3=0; #1;
      end
      if (dut.tdo3 !== 1'b0)
        $fatal(1, "USER3 register did not shift the 32-bit snapshot completely");
    end
    $display("PHK2_USER3_STATUS_CONTRACT=PASS snapshots=64 shifts_per_snapshot=32");
    $display("TAP_SEQUENCE_TESTED=NO PHYSICAL_EXPECTED_RESPONSE=NONE");
    $finish;
  end
endmodule
