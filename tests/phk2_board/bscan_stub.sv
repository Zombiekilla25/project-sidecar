// Simulation-only stand-in for BSCANE2; not a vendor primitive model.
module BSCANE2 #(parameter integer JTAG_CHAIN=1)(output wire CAPTURE,DRCK,RESET,RUNTEST,SEL,SHIFT,TCK,TDI,TMS,UPDATE,input wire TDO);
 assign CAPTURE=0;assign DRCK=0;assign RESET=0;assign RUNTEST=0;assign SEL=0;assign SHIFT=0;assign TCK=0;assign TDI=0;assign TMS=0;assign UPDATE=0;
endmodule
