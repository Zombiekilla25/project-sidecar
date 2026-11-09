`timescale 1ns/1ps
// Integration stub only. Replace this module with the timing-qualified PHK2 core.
module phk2_core_stub(input wire clk,input wire rst,
 input wire cmd_valid,output wire cmd_ready,input wire [7:0] cmd_opcode,input wire [15:0] cmd_length,input wire [112*8-1:0] cmd_payload,
 output reg busy,output reg result_ready,output reg error,output reg stale_job,output reg overflow,output reg aborted,
 input wire input_overflow,
 output wire result_valid,input wire result_ready_i,output wire [7:0] result_byte,output reg [7:0] error_code,output reg hello_seen,output reg descriptor_loaded);
 localparam OP_HELLO=8'h01,OP_LOAD=8'h10,OP_START=8'h11,OP_STATUS=8'h12,OP_READ=8'h13,OP_ABORT=8'h14,OP_RESET=8'h1f;
 reg loaded=0; reg [63:0] generation=0,range_generation=0; reg [255:0] job_key=0,range_key=0; reg [15:0] range_id=0,count=0; reg [31:0] start_index=0;
 reg [2:0] busy_ticks=0; reg result_active=0; reg [6:0] result_index=0; reg [112*8-1:0] result_record=0;
 assign cmd_ready=!result_active; assign result_valid=result_active; assign result_byte=result_record[result_index*8 +:8];
 always @(posedge clk) begin
  if(rst)begin loaded<=0;generation<=0;range_generation<=0;job_key<=0;range_key<=0;range_id<=0;count<=0;start_index<=0;busy<=0;busy_ticks<=0;result_ready<=0;error<=0;stale_job<=0;overflow<=0;aborted<=0;error_code<=0;result_active<=0;result_index<=0;result_record<=0;hello_seen<=0;descriptor_loaded<=0;end
  else begin
   if(input_overflow)begin overflow<=1;error<=1;error_code<=8'd6;end
   if(busy)begin if(busy_ticks==0)begin busy<=0;result_ready<=1;end else busy_ticks<=busy_ticks-1'b1;end
   if(result_active&&result_ready_i)begin if(result_index==111)begin result_active<=0;result_index<=0;end else result_index<=result_index+1'b1;end
   if(cmd_valid&&cmd_ready)begin
    case(cmd_opcode)
     OP_HELLO: if(cmd_length!=0)begin error<=1;error_code<=8'd2;end else hello_seen<=1;
     OP_LOAD: if(cmd_length!=112)begin error<=1;error_code<=8'd2;end else if(loaded&&cmd_payload[256+:64]<=generation)begin error<=1;stale_job<=1;error_code<=8'd3;end else begin loaded<=1;descriptor_loaded<=1;generation<=cmd_payload[256+:64];job_key<=cmd_payload[0+:256];range_id<=0;result_ready<=0;aborted<=0;error<=0;stale_job<=0;error_code<=0;end
     OP_START: if(cmd_length!=48)begin error<=1;error_code<=8'd2;end else if(!loaded||cmd_payload[0+:64]!=generation||cmd_payload[64+:256]!=job_key)begin error<=1;stale_job<=1;error_code<=8'd4;end else if(cmd_payload[352+:16]==0||cmd_payload[352+:16]>64)begin error<=1;error_code<=8'd5;end else if(range_id==cmd_payload[368+:16]&&range_id!=0)begin error<=1;error_code<=8'd8;end else begin range_generation<=cmd_payload[0+:64];range_key<=cmd_payload[64+:256];start_index<=cmd_payload[320+:32];count<=cmd_payload[352+:16];range_id<=cmd_payload[368+:16];busy<=1;busy_ticks<=3;result_ready<=0;aborted<=0;error<=0;error_code<=0;end
     OP_STATUS: if(cmd_length!=10)begin error<=1;error_code<=8'd2;end
     OP_READ: if(cmd_length!=46)begin error<=1;error_code<=8'd2;end else if(!result_ready)begin error<=1;error_code<=8'd9;end else if(cmd_payload[0+:64]!=generation||cmd_payload[64+:256]!=job_key||cmd_payload[320+:16]!=range_id)begin error<=1;stale_job<=1;error_code<=8'd4;end else begin
       result_record<=0;result_record[0+:64]<=generation;result_record[64+:16]<=range_id;result_record[80+:16]<=cmd_payload[336+:16];result_record[96+:16]<=(start_index+cmd_payload[336+:16])/8;result_record[112+:16]<=(start_index+cmd_payload[336+:16])%8;result_active<=1;result_index<=0;
     end
     OP_ABORT: if(cmd_length!=44)begin error<=1;error_code<=8'd2;end else if(cmd_payload[0+:64]!=generation||cmd_payload[64+:256]!=job_key||cmd_payload[320+:16]!=range_id)begin error<=1;stale_job<=1;error_code<=8'd4;end else begin busy<=0;result_ready<=0;result_active<=0;aborted<=1;error<=0;end
     OP_RESET: if(cmd_length!=0)begin error<=1;error_code<=8'd2;end else begin loaded<=0;descriptor_loaded<=0;hello_seen<=0;generation<=0;job_key<=0;range_id<=0;count<=0;busy<=0;result_ready<=0;error<=0;stale_job<=0;overflow<=0;aborted<=0;error_code<=0;result_active<=0;end
     default: begin error<=1;error_code<=8'd1;end
    endcase
   end
  end
 end
endmodule
