`timescale 1ns/1ps
module tb_phk2_protocol_response_encoder;
    localparam integer MAX_PAYLOAD=448;
    localparam integer CASES=10;
    reg clk=0; always #5 clk=~clk;
    reg rst=1,start=0,error_response=0,tx_ready=0;
    reg [7:0] request_opcode=0;
    reg [15:0] sequence_id=0,payload_length=0;
    reg [MAX_PAYLOAD*8-1:0] payload=0;
    wire ready,tx_valid,busy,done,length_error;
    wire [7:0] tx_data;
    reg [MAX_PAYLOAD*8+39:0] input_vectors[0:CASES-1];
    reg [3695:0] expected_frames[0:CASES-1];
    reg [15:0] expected_lengths[0:CASES-1];
    integer case_index,byte_index,cycle_index;

    phk2_protocol_response_encoder #(.MAX_PAYLOAD(MAX_PAYLOAD)) dut(
        .clk(clk),.rst(rst),.start(start),.ready(ready),
        .request_opcode(request_opcode),.error_response(error_response),
        .sequence_id(sequence_id),.payload_length(payload_length),.payload(payload),
        .tx_valid(tx_valid),.tx_ready(tx_ready),.tx_data(tx_data),.busy(busy),
        .done(done),.length_error(length_error));

    initial begin
        $readmemh("encoder-input.mem",input_vectors);
        $readmemh("encoder-expected.mem",expected_frames);
        $readmemh("encoder-length.mem",expected_lengths);
        repeat(3) @(posedge clk); #1 rst=0;
        for(case_index=0;case_index<CASES;case_index=case_index+1) begin
            @(negedge clk);
            request_opcode=input_vectors[case_index][0+:8];
            sequence_id=input_vectors[case_index][8+:16];
            payload_length=input_vectors[case_index][24+:16];
            payload=input_vectors[case_index][40+:MAX_PAYLOAD*8];
            error_response=(case_index==9);
            start=1;
            @(posedge clk); #1;
            @(negedge clk); start=0; byte_index=0; cycle_index=0;
            while(busy || byte_index==0) begin
                tx_ready=((cycle_index%7)!=3)&&((cycle_index%7)!=4);
                #1;
                if(tx_valid && tx_ready) begin
                    if(byte_index>=expected_lengths[case_index]) $fatal(1,"extra output case=%0d",case_index);
                    if(tx_data!==expected_frames[case_index][byte_index*8+:8])
                        $fatal(1,"frame mismatch case=%0d byte=%0d got=%02x expected=%02x",case_index,byte_index,tx_data,expected_frames[case_index][byte_index*8+:8]);
                    byte_index=byte_index+1;
                end
                @(posedge clk); #1; cycle_index=cycle_index+1;
                if(cycle_index>2000) $fatal(1,"encoder timeout case=%0d",case_index);
            end
            tx_ready=0;
            if(length_error || byte_index!=expected_lengths[case_index]) $fatal(1,"length/error case=%0d bytes=%0d expected=%0d",case_index,byte_index,expected_lengths[case_index]);
            if(!done) $fatal(1,"missing done case=%0d",case_index);
            @(posedge clk); #1;
        end
        $display("PHK2_RESPONSE_ENCODER_GOLDEN=9/9 MAX_READ_4_RECORDS=PASS ERROR=PASS BACKPRESSURE=PASS");
        $finish;
    end
endmodule
