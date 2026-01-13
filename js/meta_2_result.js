/**
 * BLAKE3 compression function (optimized version)
 * 
 * @param {Uint32Array} cv      - Chaining value (8 x 32-bit words)
 * @param {Uint32Array} m       - Message block (16 x 32-bit words)
 * @param {number} counter      - 64-bit block counter
 * @param {number} blockLen     - Block length in bytes (0-64)
 * @param {number} flags        - Domain separation flags
 * @returns {Uint32Array}       - 512-bit output (16 x 32-bit words)
 */

function compress(chainingValue, blockWords, counter, blockLen, flags) {
  // ==========================================================================
  // STATE INITIALIZATION
  // ==========================================================================
  
  // Rows 0-1: Chaining value (8 words from previous compression or IV)
  let s_0  = cv[0] | 0;
  let s_1  = cv[1] | 0;
  let s_2  = cv[2] | 0;
  let s_3  = cv[3] | 0;
  let s_4  = cv[4] | 0;
  let s_5  = cv[5] | 0;
  let s_6  = cv[6] | 0;
  let s_7  = cv[7] | 0;
  
  // Row 2: First 4 words of BLAKE3 IV (same as SHA-256 IV)
  // These are the fractional parts of square roots of first 4 primes
  let s_8  = 0x6A09E667;  // sqrt(2)
  let s_9  = 0xBB67AE85;  // sqrt(3)
  let s_10 = 0x3C6EF372;  // sqrt(5)
  let s_11 = 0xA54FF53A;  // sqrt(7)
  
  // Row 3: Counter (64-bit), block length, and flags
  let s_12 = counter | 0;                   // Counter low bits
  let s_13 = (counter / 0x100000000) | 0;   // Counter high bits
  let s_14 = blockLen | 0;
  let s_15 = flags | 0;

  // Message schedule permutation index
  let p = 0;

  // ==========================================================================
  // 7 ROUNDS OF MIXING
  // ==========================================================================
  
  for (let r = 0; r < 7; ++r) {
    
    // ------------------------------------------------------------------------
    // Column mixing: G functions on columns of the 4x4 state matrix
    // ------------------------------------------------------------------------
    //
    // State matrix layout:
    //   [ s_0   s_1   s_2   s_3  ]
    //   [ s_4   s_5   s_6   s_7  ]
    //   [ s_8   s_9   s_10  s_11 ]
    //   [ s_12  s_13  s_14  s_15 ]
    //
    // Column 0: G(s_0, s_4, s_8,  s_12)
    // Column 1: G(s_1, s_5, s_9,  s_13)
    // Column 2: G(s_2, s_6, s_10, s_14)
    // Column 3: G(s_3, s_7, s_11, s_15)
    // ------------------------------------------------------------------------

    // Column 0
    s_0 = (((s_0 + s_4) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_12 ^= s_0;
    s_12 = (s_12 >>> 16) | (s_12 << 16);   // rotate right 16
    s_8 = (s_8 + s_12) | 0;
    s_4 ^= s_8;
    s_4 = (s_4 >>> 12) | (s_4 << 20);      // rotate right 12
    s_0 = (((s_0 + s_4) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_12 ^= s_0;
    s_12 = (s_12 >>> 8) | (s_12 << 24);    // rotate right 8
    s_8 = (s_8 + s_12) | 0;
    s_4 ^= s_8;
    s_4 = (s_4 >>> 7) | (s_4 << 25);       // rotate right 7

    // Column 1
    s_1 = (((s_1 + s_5) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_13 ^= s_1;
    s_13 = (s_13 >>> 16) | (s_13 << 16);
    s_9 = (s_9 + s_13) | 0;
    s_5 ^= s_9;
    s_5 = (s_5 >>> 12) | (s_5 << 20);
    s_1 = (((s_1 + s_5) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_13 ^= s_1;
    s_13 = (s_13 >>> 8) | (s_13 << 24);
    s_9 = (s_9 + s_13) | 0;
    s_5 ^= s_9;
    s_5 = (s_5 >>> 7) | (s_5 << 25);

    // Column 2
    s_2 = (((s_2 + s_6) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_14 ^= s_2;
    s_14 = (s_14 >>> 16) | (s_14 << 16);
    s_10 = (s_10 + s_14) | 0;
    s_6 ^= s_10;
    s_6 = (s_6 >>> 12) | (s_6 << 20);
    s_2 = (((s_2 + s_6) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_14 ^= s_2;
    s_14 = (s_14 >>> 8) | (s_14 << 24);
    s_10 = (s_10 + s_14) | 0;
    s_6 ^= s_10;
    s_6 = (s_6 >>> 7) | (s_6 << 25);

    // Column 3
    s_3 = (((s_3 + s_7) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_15 ^= s_3;
    s_15 = (s_15 >>> 16) | (s_15 << 16);
    s_11 = (s_11 + s_15) | 0;
    s_7 ^= s_11;
    s_7 = (s_7 >>> 12) | (s_7 << 20);
    s_3 = (((s_3 + s_7) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_15 ^= s_3;
    s_15 = (s_15 >>> 8) | (s_15 << 24);
    s_11 = (s_11 + s_15) | 0;
    s_7 ^= s_11;
    s_7 = (s_7 >>> 7) | (s_7 << 25);

    // ------------------------------------------------------------------------
    // Diagonal mixing: G functions on diagonals of the 4x4 state matrix
    // ------------------------------------------------------------------------
    //
    // Diagonal 0: G(s_0, s_5, s_10, s_15)
    // Diagonal 1: G(s_1, s_6, s_11, s_12)
    // Diagonal 2: G(s_2, s_7, s_8,  s_13)
    // Diagonal 3: G(s_3, s_4, s_9,  s_14)
    // ------------------------------------------------------------------------

    // Diagonal 0
    s_0 = (((s_0 + s_5) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_15 ^= s_0;
    s_15 = (s_15 >>> 16) | (s_15 << 16);
    s_10 = (s_10 + s_15) | 0;
    s_5 ^= s_10;
    s_5 = (s_5 >>> 12) | (s_5 << 20);
    s_0 = (((s_0 + s_5) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_15 ^= s_0;
    s_15 = (s_15 >>> 8) | (s_15 << 24);
    s_10 = (s_10 + s_15) | 0;
    s_5 ^= s_10;
    s_5 = (s_5 >>> 7) | (s_5 << 25);

    // Diagonal 1
    s_1 = (((s_1 + s_6) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_12 ^= s_1;
    s_12 = (s_12 >>> 16) | (s_12 << 16);
    s_11 = (s_11 + s_12) | 0;
    s_6 ^= s_11;
    s_6 = (s_6 >>> 12) | (s_6 << 20);
    s_1 = (((s_1 + s_6) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_12 ^= s_1;
    s_12 = (s_12 >>> 8) | (s_12 << 24);
    s_11 = (s_11 + s_12) | 0;
    s_6 ^= s_11;
    s_6 = (s_6 >>> 7) | (s_6 << 25);

    // Diagonal 2
    s_2 = (((s_2 + s_7) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_13 ^= s_2;
    s_13 = (s_13 >>> 16) | (s_13 << 16);
    s_8 = (s_8 + s_13) | 0;
    s_7 ^= s_8;
    s_7 = (s_7 >>> 12) | (s_7 << 20);
    s_2 = (((s_2 + s_7) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_13 ^= s_2;
    s_13 = (s_13 >>> 8) | (s_13 << 24);
    s_8 = (s_8 + s_13) | 0;
    s_7 ^= s_8;
    s_7 = (s_7 >>> 7) | (s_7 << 25);

    // Diagonal 3
    s_3 = (((s_3 + s_4) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_14 ^= s_3;
    s_14 = (s_14 >>> 16) | (s_14 << 16);
    s_9 = (s_9 + s_14) | 0;
    s_4 ^= s_9;
    s_4 = (s_4 >>> 12) | (s_4 << 20);
    s_3 = (((s_3 + s_4) | 0) + m[PERMUTATIONS[p++]]) | 0;
    s_14 ^= s_3;
    s_14 = (s_14 >>> 8) | (s_14 << 24);
    s_9 = (s_9 + s_14) | 0;
    s_4 ^= s_9;
    s_4 = (s_4 >>> 7) | (s_4 << 25);
  }

  // ==========================================================================
  // FINALIZATION
  // ==========================================================================
  //
  // Output[0..7]  = state_low  XOR state_high   (feed-forward for chaining)
  // Output[8..15] = state_high XOR cv           (for extended output)
  // ==========================================================================
  
  return new Uint32Array([
    // First 8 words: low XOR high (used as next chaining value)
    s_0  ^ s_8,
    s_1  ^ s_9,
    s_2  ^ s_10,
    s_3  ^ s_11,
    s_4  ^ s_12,
    s_5  ^ s_13,
    s_6  ^ s_14,
    s_7  ^ s_15,
    // Last 8 words: high XOR input cv (for XOF/extended output)
    s_8  ^ cv[0],
    s_9  ^ cv[1],
    s_10 ^ cv[2],
    s_11 ^ cv[3],
    s_12 ^ cv[4],
    s_13 ^ cv[5],
    s_14 ^ cv[6],
    s_15 ^ cv[7],
  ]);
}
