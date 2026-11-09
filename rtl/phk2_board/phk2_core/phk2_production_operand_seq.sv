`timescale 1ns/1ps
// Sequential, single-BLAKE3-engine producer for one production 4x8 operand
// record. The equations and schedule are identical to the combinational
// reference. It performs the two sparse and 24 lane-specific uniform hashes
// serially, then holds the 96-bit record until accepted.
module phk2_production_operand_seq (
    input wire clk, input wire rst, input wire abort,
    input wire request_valid, output wire request_ready,
    input wire [63:0] setup_seed64,
    input wire [255:0] noise_seed_a, input wire [255:0] noise_seed_b,
    input wire [16:0] row_base, input wire [16:0] col_base,
    input wire [11:0] k_index,
    output reg operand_valid, input wire operand_ready,
    output reg [95:0] operand_record, output reg overflow,
    output reg [31:0] cycle_count
);
    localparam [1:0] IDLE=2'd0, ISSUE=2'd1, WAIT_HASH=2'd2, EMIT=2'd3;
    localparam [1:0] P_IDLE=2'd0, P_ISSUE=2'd1, P_WAIT=2'd2;
    localparam [255:0] LABEL_A=256'h000000000000000000000000000000000000000000000000726f736e65745f41;
    localparam [255:0] LABEL_B=256'h000000000000000000000000000000000000000000000000726f736e65745f42;
    reg [1:0] state;
    reg [1:0] pstate;
    reg [63:0] seed_q;
    reg [255:0] noise_a_q,noise_b_q;
    reg [16:0] row_q,col_q;
    reg [11:0] k_q;
    reg [4:0] hash_index;
    reg [3:0] philox_index;
    reg raw_done;
    reg [15:0] sparse_pair_a,sparse_pair_b;
    reg [7:0] a_plus[0:3],a_minus[0:3],b_plus[0:7],b_minus[0:7];
    wire hash_ready,hash_busy,hash_done;
    wire [2:0] hash_round;
    wire [255:0] hash_digest;
    reg [255:0] hash_key;
    reg [511:0] hash_message;
    wire hash_start=(state==ISSUE)&&hash_ready;
    reg [31:0] uniform_index;
    reg [7:0] selected_uniform;
    integer lane_idx;
    reg is_minus;
    reg [7:0] selected_rank;
    reg [39:0] sparse_product;
    reg [31:0] sparse_word;
    reg [7:0] sparse_first,sparse_second;
    reg [7:0] raw_a[0:3];
    reg [7:0] raw_b[0:7];
    wire [63:0] seed_b=seed_q+64'd1;
    wire [63:0] k_aligned={52'b0,k_q[11:2],2'b00};
    wire p_ready,p_busy,p_done;
    wire [3:0] p_round_count;
    wire [31:0] p_c0,p_c1,p_c2,p_c3;
    reg [63:0] p_base,p_seed;
    reg [1:0] p_lane;
    reg [31:0] p_selected_word;
    wire p_start=(pstate==P_ISSUE)&&p_ready;
    wire [3:0] p_bindex=philox_index-4'd4;
    integer i;

    assign request_ready=(state==IDLE)&&!operand_valid&&(pstate==P_IDLE);
    phk2_blake3_keyed_block_seq hash_engine(.clk(clk),.rst(rst|abort),
      .start(hash_start),.ready(hash_ready),.key(hash_key),.message(hash_message),
      .busy(hash_busy),.done(hash_done),.round_count(hash_round),.digest(hash_digest));
    phk2_philox4x32_10_seq philox_engine(.clk(clk),.rst(rst|abort),.start(p_start),.ready(p_ready),
      .base(p_base),.seed64(p_seed),.busy(p_busy),.done(p_done),.round_count(p_round_count),
      .c0(p_c0),.c1(p_c1),.c2(p_c2),.c3(p_c3));

    function automatic [15:0] make_sparse_pair(input [255:0] digest_in,input [2:0] lane);
        reg [31:0] word_value;
        reg [39:0] product;
        reg [7:0] first_value,second_value;
        begin
            word_value=digest_in[lane*32+:32];
            product=40'd255*word_value;
            first_value=word_value[7:0];
            second_value=first_value^(8'd1+product[39:32]);
            make_sparse_pair={second_value,first_value};
        end
    endfunction

    always @* begin
        p_base=0;p_seed=seed_q;p_lane=0;p_selected_word=0;
        if(philox_index<4) begin
            p_base=((({47'b0,row_q}+{60'b0,philox_index})*64'd4096)+k_aligned);
            p_seed=seed_q;p_lane=k_q[1:0];
        end else begin
            p_base=(({52'b0,k_q}*64'd131072)+({47'b0,col_q}+({60'b0,philox_index}-64'd4)))&64'hfffffffffffffffc;
            p_seed=seed_b;p_lane=col_q[1:0]+philox_index[1:0];
        end
        case(p_lane)
            0:p_selected_word=p_c0;1:p_selected_word=p_c1;
            2:p_selected_word=p_c2;default:p_selected_word=p_c3;
        endcase
        hash_key=noise_a_q;
        hash_message={LABEL_A,256'b0};
        lane_idx=0; is_minus=0; selected_rank=0; uniform_index=0; selected_uniform=0;
        if(hash_index==0 || (hash_index>=2 && hash_index<=9)) hash_key=noise_a_q;
        else hash_key=noise_b_q;
        if(hash_index==0 || hash_index==1) begin
            hash_message[32+:32]=32'd1+{23'b0,k_q[11:3]};
            if(hash_index==1) begin
                hash_message={LABEL_B,256'b0};
                hash_message[32+:32]=32'd1+{23'b0,k_q[11:3]};
            end
        end else if(hash_index>=2 && hash_index<=9) begin
            lane_idx={29'b0,hash_index[3:1]}-32'd1; is_minus=hash_index[0];
            selected_rank=is_minus?sparse_pair_a[15:8]:sparse_pair_a[7:0];
            uniform_index=(({15'b0,row_q}+lane_idx)*32'd256)+{24'b0,selected_rank};
            hash_message[0+:32]=(uniform_index>>5)+32'd1;
        end else begin
            hash_message={LABEL_B,256'b0};
            lane_idx={28'b0,hash_index[4:1]}-32'd5; is_minus=hash_index[0];
            selected_rank=is_minus?sparse_pair_b[15:8]:sparse_pair_b[7:0];
            uniform_index=(({15'b0,col_q}+lane_idx)*32'd256)+{24'b0,selected_rank};
            hash_message[0+:32]=(uniform_index>>5)+32'd1;
        end
        selected_uniform=(hash_digest[(uniform_index[4:0])*8+:8]&8'h3f)-8'd32;
    end

    reg signed [8:0] sum_a,sum_b;
    reg [95:0] result_comb;
    reg overflow_comb;
    always @* begin
        result_comb=0; overflow_comb=0; sum_a=0; sum_b=0;
        for(integer q=0;q<4;q=q+1) begin
            sum_a=$signed(raw_a[q])+$signed(a_plus[q])-$signed(a_minus[q]);
            result_comb[q*8+:8]=sum_a[7:0];
            if(sum_a>127 || sum_a< -128) overflow_comb=1;
        end
        for(integer q=0;q<8;q=q+1) begin
            sum_b=$signed(raw_b[q])+$signed(b_plus[q])-$signed(b_minus[q]);
            result_comb[32+q*8+:8]=sum_b[7:0];
            if(sum_b>127 || sum_b< -128) overflow_comb=1;
        end
    end

    always @(posedge clk) begin
        if(rst || abort) begin
            state<=IDLE; operand_valid<=0; operand_record<=0; overflow<=0;
            pstate<=P_IDLE;philox_index<=0;raw_done<=0;
            cycle_count<=0; hash_index<=0; seed_q<=0; noise_a_q<=0; noise_b_q<=0;
            row_q<=0; col_q<=0; k_q<=0; sparse_pair_a<=0; sparse_pair_b<=0;
            for(i=0;i<4;i=i+1) begin a_plus[i]<=0; a_minus[i]<=0; end
            for(i=0;i<8;i=i+1) begin b_plus[i]<=0; b_minus[i]<=0; end
            for(i=0;i<4;i=i+1) raw_a[i]<=0;
            for(i=0;i<8;i=i+1) raw_b[i]<=0;
        end else begin
            if(state!=IDLE || request_valid) cycle_count<=cycle_count+1'b1;
            case(pstate)
                P_IDLE: if(state==IDLE && request_valid && request_ready) begin
                    philox_index<=0;raw_done<=0;pstate<=P_ISSUE;
                end
                P_ISSUE: if(p_ready) pstate<=P_WAIT;
                P_WAIT: if(p_done) begin
                    if(philox_index<4) raw_a[philox_index[1:0]]<=p_selected_word[7:0];
                    else raw_b[p_bindex[2:0]]<=p_selected_word[7:0];
                    if(philox_index==11) begin pstate<=P_IDLE;raw_done<=1;end
                    else begin philox_index<=philox_index+1'b1;pstate<=P_ISSUE;end
                end
                default: pstate<=P_IDLE;
            endcase
            case(state)
                IDLE: if(request_valid && request_ready) begin
                    seed_q<=setup_seed64; noise_a_q<=noise_seed_a; noise_b_q<=noise_seed_b;
                    row_q<=row_base; col_q<=col_base; k_q<=k_index;
                    hash_index<=0; cycle_count<=1; operand_valid<=0; state<=ISSUE;
                end
                ISSUE: if(hash_ready) state<=WAIT_HASH;
                WAIT_HASH: if(hash_done) begin
                    if(hash_index==0) sparse_pair_a<=make_sparse_pair(hash_digest,k_q[2:0]);
                    else if(hash_index==1) sparse_pair_b<=make_sparse_pair(hash_digest,k_q[2:0]);
                    else if(hash_index<=9) begin
                        if(is_minus) a_minus[lane_idx]<=selected_uniform;
                        else a_plus[lane_idx]<=selected_uniform;
                    end else begin
                        if(is_minus) b_minus[lane_idx]<=selected_uniform;
                        else b_plus[lane_idx]<=selected_uniform;
                    end
                    if(hash_index==25) state<=EMIT;
                    else begin hash_index<=hash_index+1'b1; state<=ISSUE; end
                end
                EMIT: if(!raw_done) operand_valid<=0;
                else if(operand_valid && operand_ready) begin
                    operand_valid<=0; state<=IDLE;
                end else begin
                    operand_record<=result_comb; overflow<=overflow_comb; operand_valid<=1;
                end
                default: begin state<=IDLE; operand_valid<=0; end
            endcase
        end
    end
endmodule
