module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

	parameter NUM_NONCES = 16;

	enum logic [3:0] {IDLE, READ, BLOCK_1, BLOCK_2, BLOCK_3, COMPUTE, WRITE} state;
	logic [31:0] hout[NUM_NONCES];

	parameter int k[64] = '{
		 32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
		 32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
		 32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
		 32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
		 32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
		 32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
		 32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
		 32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};

	// Student to add rest of the code here

	logic   [31:0] h0[NUM_NONCES];
	logic   [31:0] h1[NUM_NONCES];
	logic   [31:0] h2[NUM_NONCES];
	logic   [31:0] h3[NUM_NONCES];
	logic   [31:0] h4[NUM_NONCES];
	logic   [31:0] h5[NUM_NONCES];
	logic   [31:0] h6[NUM_NONCES];
	logic   [31:0] h7[NUM_NONCES];

	logic   [31:0] fh0, fh1, fh2, fh3, fh4, fh5, fh6, fh7;
	logic   [31:0] a, b, c, d, e, f, g, h;

	logic   [31:0] s1, s0;
	logic   [31:0] w[16];
	logic	  [31:0] message[20];

	int            m, n, t, j, i;
	logic   [15:0] offset;
	logic          cur_we;			// write enabler 
	logic   [15:0] cur_addr;
	logic   [31:0] cur_write_data;
	logic  [512:0] memory_block;


	// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
												input logic [7:0] t);
		logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
		begin
			S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			ch = (e & f) ^ ((~e) & g);
			t1 = h + S1 + ch + k[t] + w;
			S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			t2 = S0 + maj;

			sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
		end
	endfunction
	
	
	// wtnew
	function logic [31:0] wtnew; 
		logic [31:0] s1, s0;
		s0 = rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1] >> 3);
		s1 = rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10);
		wtnew = w[0] + s0 + w[9] + s1;
	endfunction

	
	// right rotation
	function logic [31:0] rightrotate(input logic [31:0] x,
												 input logic [7:0] r);
		begin
			rightrotate = (x >> r) | (x << (32-r));
		end
	endfunction

	
	assign mem_clk = clk;
	assign mem_addr = cur_addr + offset;
	assign mem_we = cur_we;
	assign mem_write_data = cur_write_data;


	always_ff @(posedge clk, negedge reset_n)
	begin
		if (!reset_n) begin
			cur_we <= 1'b0;
			state <= IDLE;
			offset <= 0;
		end 
		else case (state)
			IDLE: begin
				if(start) begin
					//Initialize hash values:
					//(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
					fh0 <= 32'h6a09e667;
					fh1 <= 32'hbb67ae85;
					fh2 <= 32'h3c6ef372;
					fh3 <= 32'ha54ff53a;
					fh4 <= 32'h510e527f;
					fh5 <= 32'h9b05688c;
					fh6 <= 32'h1f83d9ab;
					fh7 <= 32'h5be0cd19;
			 
					a <= 32'h0;
					b <= 32'h0;
					c <= 32'h0;
					d <= 32'h0;
					e <= 32'h0;
					f <= 32'h0;
					g <= 32'h0;
					h <= 32'h0;

					// Number of block iteration variable
					j <= 0;
					t <= 0;
					i <= 0;
					 
					// initialize pointer to access memory location
					offset <= 0;
			 
					// by default set write enable to '0' (i.e. memory read mode)
					cur_we <= 1'b0;
					 
					// get starting address of message 
					cur_addr <= message_addr;
					 
					// initialize write data to memory to '0'
					cur_write_data <= 32'h0;
					 
					// proceed to message block fetch stage
					state <= READ;
				end
			end
			
			
			READ: begin
				if(offset<=20) begin
					if(offset != 0) begin
						message[offset-1] <= mem_read_data;
					end
				
				// Increment memory address to fetch next block 
				offset <= offset + 1;

				// stay in read memory state until all input message words are read
				state <= READ;
				end
				else begin
					offset <= 0;
					state <= BLOCK_1;
				end
			end
			
			// First Hash Block
			BLOCK_1: begin
				j <= 0;
				a <= fh0;
				b <= fh1;
				c <= fh2;
				d <= fh3;
				e <= fh4;
				f <= fh5;
				g <= fh6;
				h <= fh7;
				for (n = 0; n < 16; n++) w[n] <= message[n];
				state <= COMPUTE;
				i <= 0;
			end
			
			// Second Hash Block
			BLOCK_2: begin
				//j <= 1;
				//for (n = 0; n < 8; n ++) begin
					h0[m] <= fh0;
					h1[m] <= fh1;
					h2[m] <= fh2;
					h3[m] <= fh3;
					h4[m] <= fh4;
					h5[m] <= fh5;
					h6[m] <= fh6;
					h7[m] <= fh7;
				//end	
				a <= fh0;
				b <= fh1;
				c <= fh2;
				d <= fh3;
				e <= fh4;
				f <= fh5;
				g <= fh6;
				h <= fh7;
							
				for (n = 16; n < 19; n++) w[n-16] <= message[n];
				w[3] <= m;
				w[4] <= 32'h80000000;
				for (n = 5; n < 15; n++) w[n] <= 0;
				w[15] <= 32'd640;
				state <= COMPUTE;
				i <= 0;
			end
			
			// Final hash block
			BLOCK_3: begin
				j <= 2;
				w[0] <= h0[m];
				w[1] <= h1[m];
				w[2] <= h2[m];
				w[3] <= h3[m];
				w[4] <= h4[m];
				w[5] <= h5[m];
				w[6] <= h6[m];
				w[7] <= h7[m];
	
				w[8] <= 32'h80000000;		 // padding
				for (n = 9; n < 15; n++) w[n] <= 0;
				w[15] <= 32'd256; // SIZE = 256 BITS
				
				h0[m] <= 32'h6a09e667;
				h1[m] <= 32'hbb67ae85;
				h2[m] <= 32'h3c6ef372;
				h3[m] <= 32'ha54ff53a;
				h4[m] <= 32'h510e527f;
				h5[m] <= 32'h9b05688c;
				h6[m] <= 32'h1f83d9ab;
				h7[m] <= 32'h5be0cd19;

				a <= 32'h6a09e667;
				b <= 32'hbb67ae85;
				c <= 32'h3c6ef372;
				d <= 32'ha54ff53a;
				e <= 32'h510e527f;
				f <= 32'h9b05688c;
				g <= 32'h1f83d9ab;
				h <= 32'h5be0cd19;
				
				state <= COMPUTE;
				i <= 0;
			end
			
			
			COMPUTE: begin
				if (i <= 64) begin
					if(i<16) begin 
						{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
					end
					else begin
						for (n = 0; n < 15; n++) w[n] <= w[n+1];
						w[15] <= wtnew(); // perform word expansion 
						// Since wtnew above mentioned line is non-blocking, the expanded w[16] to w[64] would take
						// 1 additional cycle to get its value available. Hence below mentioned guarded i!=16 in if block
						// where we do not do any SHA operation for 16th iteration as we are waiting for 1 cycle. From 17th iteration cycle
						// we perform SHA operation. Also note that due to this 1 dummy cycle of not doing anything when 
						// i moves to 17, then w[i-1] and i-1 are used in sha256_op below to compute SHA operation for w[16] word
						// And hence i<=64 used in above mentioned if(i<=64) line insted of if(i<64)
						if(i != 16) {a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
					end
					i <= i + 1;
					state <= COMPUTE;
				end
				else begin
					if (j == 0) begin		// First hash block
						fh0 <= fh0 + a;
						fh1 <= fh1 + b;
						fh2 <= fh2 + c;
						fh3 <= fh3 + d;
						fh4 <= fh4 + e;
						fh5 <= fh5 + f;
						fh6 <= fh6 + g;
						fh7 <= fh7 + h;
						state <= BLOCK_2;
						j <= j + 1;
						m <= 0;				// for the loop of NUM_NONCES in BLOCK_2
					end
					else begin				// For second and third blocks
						h0[m] <= h0[m] + a;
						h1[m] <= h1[m] + b;
						h2[m] <= h2[m] + c;
						h3[m] <= h3[m] + d;
						h4[m] <= h4[m] + e;
						h5[m] <= h5[m] + f;
						h6[m] <= h6[m] + g;
						h7[m] <= h7[m] + h;
						if (m >= NUM_NONCES-1) begin				// when m == NUM_NONCES, get out of loop;
							if (j == 1) begin						// j == 1 means coming out of second hash block
								state <= BLOCK_3;
								m <= 0;								// reset m for BLOCK_3 NUM_NONCES loop
							end
							else begin
								state <= WRITE;					// done with third hash block
								t <= 0; 
							end
						end
						else begin									// m < NUM_NONCES
							m <= m + 1;
							if (j == 1) state <= BLOCK_2;		// NUM_NONCES loop for BLOCK_2
							else state <= BLOCK_3;				// NUM_NONCES loop for BLOCK_3
						end
					end	
				end
			end
			
			
			
			
			WRITE: begin
				if (t < NUM_NONCES) begin
					offset <= t;
					cur_we <= 1'b1;
					cur_addr <= output_addr;
					cur_write_data <= h0[t];
					state <= WRITE;
					t <= t + 1;
				end
				else state <= IDLE;
			end
		endcase
	end  
 
	// Generate done when SHA256 hash computation has finished and moved to IDLE state
	assign done = (state == IDLE);

endmodule
