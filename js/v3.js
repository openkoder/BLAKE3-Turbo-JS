/**
 * ============================================================================
 * BLAKE3 — Naive JavaScript Implementation (Working v3)
 * ============================================================================
 * 
 * BLAKE3 is a cryptographic hash function designed in 2020.
 * It combines the best qualities of BLAKE2 and Bao (parallel Merkle tree).
 * 
 * Key characteristics:
 * - Block size: 64 bytes
 * - Chunk size: 1024 bytes (16 blocks)
 * - Output size: 32 bytes (default), but supports XOF
 * - Number of rounds: 7 (instead of 10 in BLAKE2s)
 * 
 * Algorithm structure:
 * 1. Input data is split into 1024-byte chunks
 * 2. Each chunk is processed as a chain of 16 blocks of 64 bytes
 * 3. Chunk results are combined into a Merkle tree
 * 4. The tree root gives the final hash
 * 
 * Input:  Uint8Array (any length)
 * Output: Uint8Array (32 bytes)
 */

/**
 * ============================================================================
 * BLAKE3 v3 - Inlining round() into compress()
 * ============================================================================
 * 
 * Optimizations in this version:
 * - v1: readLittleEndianWordsFull (no bounds checking)
 * - v2: Inline permutations (no array copying, precomputed access order)
 * - v3: Inlining round() into compress() + flat permutation array
 *       Result: ~1.1x speedup (from 99 ms to 89 ms on 1 MB of data)
 */

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Initialization Vector (IV) — first 32 bits of the fractional part
 * of square roots of the first 8 prime numbers: √2, √3, √5, √7, √11, √13, √17, √19
 * 
 * These same constants are used in SHA-256 and BLAKE2s.
 * They are chosen as "nothing-up-my-sleeve numbers" — values that
 * cannot be specially selected to create a backdoor.
 */
const IV = new Uint32Array([
  0x6a09e667,  // √2
  0xbb67ae85,  // √3
  0x3c6ef372,  // √5
  0xa54ff53a,  // √7
  0x510e527f,  // √11
  0x9b05688c,  // √13
  0x1f83d9ab,  // √17
  0x5be0cd19,  // √19
]);

/**
 * Domain flags — indicate the type of block being processed.
 * Used for domain separation, so that identical data
 * in different contexts produces different hashes.
 */
const CHUNK_START = 1;   // 0b0001 — first block in chunk
const CHUNK_END = 2;     // 0b0010 — last block in chunk
const PARENT = 4;        // 0b0100 — parent node in Merkle tree
const ROOT = 8;          // 0b1000 — root node (final hash)
// Also exist: KEYED_HASH = 16, DERIVE_KEY_CONTEXT = 32, DERIVE_KEY_MATERIAL = 64

/**
 * Block size in bytes.
 * BLAKE3 processes data in 64-byte blocks = 16 words of 4 bytes.
 */
const BLOCK_LEN = 64;

/**
 * Precomputed permutation indices in a flat array for all 7 rounds.
 * 
 * Instead of physically moving data in the message array after each round
 * (which requires creating a temporary copy), we precompute the ACCESS ORDER
 * to the original data for each round.
 * 
 * How it works:
 * - Original approach: permute(m) copies the array and shuffles data after each round
 * - Optimized approach v2: access m[ROUND_PERMUTATIONS[round][i]] with precomputed indices
 * - Optimized approach v3: access PERMUTATIONS[r * 16 + i], where r is round, i is index (flat array + running pointer)
 * 
 * Advantages of flat Uint8Array over 2D Array[][]:
 * - Linear memory storage → better cache locality
 * - Simple address arithmetic: p++ instead of [round][index]
 * - Uint8Array is stored contiguously → ideal for CPU prefetcher
 * - Indices 0-15 fit in a byte → compact (112 bytes vs ~900+ for Array)
 * - JIT compiler recognizes sequential access pattern
 * 
 * Memory savings per compress() call:
 * - Without optimization: 7 × 64 bytes = 448 bytes allocated (copies of array m)
 * - With optimization: 0 bytes allocated (only reads from static array)
 * 
 * Size: 7 rounds × 16 indices = 112 elements
 * Addressing: round r, index i → PERMUTATIONS[r * 16 + i]
 * (but we use a running pointer p++ for even greater efficiency)
 */
const PERMUTATIONS = new Uint8Array([
  // Round 1: identity permutation
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  // Round 2
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
  // Round 3
  3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1,
  // Round 4
  10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6,
  // Round 5
  12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4,
  // Round 6
  9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7,
  // Round 7
  11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13,
]);


// ============================================================================
// BASIC OPERATIONS
// ============================================================================

/**
 * Right rotation (rotate right).
 * 
 * Unlike regular shift (>>), bits are not lost,
 * but wrap around from the right edge to the left.
 * 
 * Example for 8 bits: rightRotate(0b11110000, 2) = 0b00111100
 * 
 * @param {number} word - 32-bit word
 * @param {number} bits - number of positions to shift
 * @returns {number} - result of cyclic shift
 * 
 * Note: We do NOT use >>> 0 at the end, since bitwise operations
 * in JavaScript automatically coerce the result to a 32-bit integer.
 */
function rightRotate(word, bits) {
  return (word >>> bits) | (word << (32 - bits));
}

/**
 * G-function v3 - the heart of BLAKE3 (self-contained).
 * 
 * This is a quarter-round function that mixes 4 state words (a, b, c, d)
 * with two message words (mx, my).
 * 
 * Operation scheme (ARX - Add-Rotate-XOR):
 * 
 *   a ← a + b + mx
 *   d ← (d ⊕ a) >>> 16
 *   c ← c + d
 *   b ← (b ⊕ c) >>> 12
 *   a ← a + b + my
 *   d ← (d ⊕ a) >>> 8
 *   c ← c + d
 *   b ← (b ⊕ c) >>> 7
 * 
 * Rotation constants (16, 12, 8, 7) are optimized for 32-bit words.
 *
 * Now the function itself determines which message words to use
 * by accessing the global permutation table via the passed indices.
 * 
 * @param {Uint32Array} state - 16-word state
 * @param {Uint32Array} m - message block (16 words, immutable)
 * @param {number} x - index in PERMUTATIONS table for the first word
 * @param {number} y - index in PERMUTATIONS table for the second word
 * @param {number} a,b,c,d - indices of state words to mix
 */
function g(state, m, x, y, a, b, c, d) {
  const mx = m[PERMUTATIONS[x]];  // Self-contained access
  const my = m[PERMUTATIONS[y]];  // to required words
  
  // ARX transformation remains unchanged
  // First half: mix in mx
  state[a] = (((state[a] + state[b]) | 0) + mx) | 0;  // a ← a + b + mx
  state[d] = rightRotate(state[d] ^ state[a], 16);    // d ← (d ⊕ a) >>> 16
  state[c] = (state[c] + state[d]) | 0;               // c ← c + d
  state[b] = rightRotate(state[b] ^ state[c], 12);    // b ← (b ⊕ c) >>> 12
  
  // Second half: mix in my
  state[a] = (((state[a] + state[b]) | 0) + my) | 0;  // a ← a + b + my
  state[d] = rightRotate(state[d] ^ state[a], 8);     // d ← (d ⊕ a) >>> 8
  state[c] = (state[c] + state[d]) | 0;               // c ← c + d
  state[b] = rightRotate(state[b] ^ state[c], 7);     // b ← (b ⊕ c) >>> 7
}


// ============================================================================
// COMPRESSION FUNCTION
// ============================================================================

/**
 * Compression function - the core cryptographic operation of BLAKE3.
 * 
 * Accepts:
 * - chainingValue: 8 words (256 bits) - result of previous compression or IV
 * - blockWords: 16 words (512 bits) - data block
 * - counter: 64-bit chunk counter
 * - blockLen: block length in bytes (for padding)
 * - flags: domain flags
 * 
 * Returns: 16 words (512 bits) - compression result
 * 
 * Initial state (16 words = 512 bits):
 * 
 *   ┌─────────────────────────────────────────────────┐
 *   │  h0    h1    h2    h3   ← chaining value (0-3)  │
 *   │  h4    h5    h6    h7   ← chaining value (4-7)  │
 *   │ IV0   IV1   IV2   IV3   ← IV constants          │
 *   │  t0    t1  blen  flags  ← counter, len, flags   │
 *   └─────────────────────────────────────────────────┘
 * 
 * @param {Uint32Array} chainingValue - input chaining value (8 words)
 * @param {Uint32Array} blockWords - message block (16 words)
 * @param {number} counter - chunk number (lower 32 bits)
 * @param {number} blockLen - data length in block
 * @param {number} flags - domain flags
 * @returns {Uint32Array} - compression result (16 words)
 */
function compress(chainingValue, blockWords, counter, blockLen, flags) {
  // State initialization
  const state = new Uint32Array([
    // Rows 0-1: chaining value (result of previous block or IV)
    chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
    chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
    // Row 2: IV constants
    IV[0], IV[1], IV[2], IV[3],
    // Row 3: counter (64 bits), block length, flags
    counter,                      // t0: lower 32 bits of counter
    (counter / 0x100000000) | 0,  // t1: upper 32 bits (counter >> 32)
    blockLen,                     // data length in block
    flags,                        // domain flags
  ]);

  // Start of round() function inlining
  // ═══════════════════════════════════════════════════════════════════════
  // 🚀 INLINING round() FUNCTION: 7 rounds in a single loop
  // ═══════════════════════════════════════════════════════════════════════
  // 
  // A round applies the G-function to all 16 state words.
  // The state is represented as a 4×4 matrix:
  // 
  //   ┌──────┬──────┬──────┬──────┐
  //   │  0   │  1   │  2   │  3   │
  //   ├──────┼──────┼──────┼──────┤
  //   │  4   │  5   │  6   │  7   │
  //   ├──────┼──────┼──────┼──────┤
  //   │  8   │  9   │ 10   │ 11   │
  //   ├──────┼──────┼──────┼──────┤
  //   │ 12   │ 13   │ 14   │ 15   │
  //   └──────┴──────┴──────┴──────┘
  // 
  // Each round consists of two phases:
  // 
  // 1. COLUMNS - G is applied to each column:
  //    G(0,4,8,12)  G(1,5,9,13)  G(2,6,10,14)  G(3,7,11,15)
  // 
  // 2. DIAGONALS - G is applied to diagonals:
  //    G(0,5,10,15) G(1,6,11,12) G(2,7,8,13)   G(3,4,9,14)
  // 
  // ───────────────────────────────────────────────────────────────────────
  // OPTIMIZATION v3: Inlining + flat permutation array
  // ───────────────────────────────────────────────────────────────────────
  // 
  // Instead of 7 calls to round() function:
  //   round(state, blockWords, ROUND_PERMUTATIONS[0]);
  //   round(state, blockWords, ROUND_PERMUTATIONS[1]);
  //   ... (7 calls)
  // 
  // We use a single loop with a running pointer p in the flat
  // PERMUTATIONS array. This avoids:
  // - Overhead of 7 round() function calls
  // - 2D indexing ROUND_PERMUTATIONS[round][index]
  // - Copying message block (no `new Uint32Array(m)`)
  // - Calling permute() after each round (no data movement)
  // 
  // Savings per compress() call:
  // - 7 stack frame allocations
  // - 7 × 16 = 112 indexing operations in 2D array
  // - Improved cache locality due to linear access to PERMUTATIONS
  // 
  // BLAKE2 has 10 rounds, BLAKE3 is optimized to 7 for speed.
  // ═══════════════════════════════════════════════════════════════════════
  
  // We use a single loop with a running pointer:
  let p = 0;  // Pointer in flat PERMUTATIONS array
  
  for (let round = 0; round < 7; ++round) {
    // ─────────────────────────────────────────────────────────────
    // Phase 1: Column mixing
    // ─────────────────────────────────────────────────────────────
    // G is applied vertically to each of 4 columns:
    //   
    //   ┌──────┬──────┬──────┬──────┐
    //   │  ↓   │  ↓   │  ↓   │  ↓   │  
    //   ├──────┼──────┼──────┼──────┤
    //   │  ↓   │  ↓   │  ↓   │  ↓   │
    //   ├──────┼──────┼──────┼──────┤
    //   │  ↓   │  ↓   │  ↓   │  ↓   │
    //   ├──────┼──────┼──────┼──────┤
    //   │  ↓   │  ↓   │  ↓   │  ↓   │
    //   └──────┴──────┴──────┴──────┘
    //
    // Message words are accessed via m[PERMUTATIONS[p++]], where p
    // automatically advances through the flat permutation array.

    g(state, blockWords, p++, p++, 0, 4,  8, 12);  // Column 0
    g(state, blockWords, p++, p++, 1, 5,  9, 13);  // Column 1
    g(state, blockWords, p++, p++, 2, 6, 10, 14);  // Column 2
    g(state, blockWords, p++, p++, 3, 7, 11, 15);  // Column 3
    
    // ─────────────────────────────────────────────────────────────
    // Phase 2: Diagonal mixing
    // ─────────────────────────────────────────────────────────────
    // G is applied along diagonals with wrap-around:
    //
    //   ┌──────┬──────┬──────┬──────┐
    //   │  ↘   │   ↘  │      │↘     │ 
    //   ├──────┼──────┼──────┼──────┤ 
    //   │      │  ↘   │   ↘  │      │
    //   ├──────┼──────┼──────┼──────┤
    //   │      │      │  ↘   │   ↘  │
    //   ├──────┼──────┼──────┼──────┤
    //   │   ↘  │      │      │  ↘   │
    //   └──────┴──────┴──────┴──────┘
    //
    g(state, blockWords, p++, p++, 0, 5, 10, 15);  // Diagonal 0
    g(state, blockWords, p++, p++, 1, 6, 11, 12);  // Diagonal 1
    g(state, blockWords, p++, p++, 2, 7,  8, 13);  // Diagonal 2
    g(state, blockWords, p++, p++, 3, 4,  9, 14);  // Diagonal 3
  }
  // End of round() function inlining

  // Finalization: XOR upper and lower halves of state
  // This "compresses" 512 bits to 256 bits and adds feed-forward
  for (let i = 0; i < 8; ++i) {
    state[i] ^= state[i + 8];           // out[i] = state[i] ⊕ state[i+8]
    state[i + 8] ^= chainingValue[i];   // out[i+8] = state[i+8] ⊕ h[i]
  }

  return state;
}

/**
 * Extracts first 8 words (256 bits) from compression result.
 * 
 * This is the "chaining value" that is passed
 * to the next block or used as a Merkle tree node.
 * 
 * @param {Uint32Array} compressionOutput - compress result (16 words)
 * @returns {Uint32Array} - first 8 words (new array)
 */
function first8Words(compressionOutput) {
  return new Uint32Array(compressionOutput).slice(0, 8);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Reads a full block (64 bytes) as 16 little-endian 32-bit words.
 * 
 * This is an OPTIMIZED version WITHOUT bounds checking.
 * Used for all blocks except the last one, where we know for certain
 * that we have exactly 64 bytes of data available.
 * 
 * Why this optimization matters:
 * - Removes `offset + 3 < array.length` check from every iteration
 * - JIT compiler can better optimize fixed-count loops (16 iterations)
 * - Better CPU branch prediction (no conditional exit)
 * - In benchmarks: ~85x speedup compared to bounds-checked version
 * 
 * Little-endian byte order:
 *   bytes [0x78, 0x56, 0x34, 0x12] → word 0x12345678
 *   Least significant byte comes first in memory.
 * 
 * @param {Uint8Array} array - Input byte array (must have at least offset + 64 bytes)
 * @param {number} offset - Starting position in the array
 * @param {Uint32Array} words - Output buffer for 16 words (must be pre-allocated)
 * 
 * @example
 * const input = new Uint8Array(64);
 * const block = new Uint32Array(16);
 * readLittleEndianWordsFull(input, 0, block);
 */
function readLittleEndianWordsFull(array, offset, words) {
  for (let i = 0; i < 16; ++i, offset += 4) {
    // Combine 4 bytes into one 32-bit word (little-endian)
    // byte[0] → bits 0-7   (no shift)
    // byte[1] → bits 8-15  (shift left 8)
    // byte[2] → bits 16-23 (shift left 16)
    // byte[3] → bits 24-31 (shift left 24)
    words[i] =
      array[offset] |
      (array[offset + 1] << 8) |
      (array[offset + 2] << 16) |
      (array[offset + 3] << 24);
  }
}

/**
 * Reads a partial (incomplete) block with bounds checking and zero-padding.
 * 
 * Used ONLY for the LAST block of input data, which may contain
 * fewer than 64 bytes. This function handles:
 * - Reading complete 4-byte words while data is available
 * - Zero-padding remaining words
 * - Reading trailing bytes (1-3 bytes that don't form a complete word)
 * 
 * BLAKE3 padding rule:
 *   Incomplete blocks are padded with zeros to 64 bytes.
 *   The actual data length is passed separately to compress().
 * 
 * Why separate from readLittleEndianWordsFull:
 * - Bounds checking is expensive in hot loops
 * - 99% of blocks are full blocks (don't need checking)
 * - Only the last block needs this slower, safer version
 * 
 * @param {Uint8Array} array - Input byte array
 * @param {number} offset - Starting position in the array
 * @param {Uint32Array} words - Output buffer for 16 words (will be zero-padded)
 * 
 * @example
 * // Reading last 37 bytes of data
 * const input = new Uint8Array(37);
 * const block = new Uint32Array(16);
 * readLittleEndianWordsPartial(input, 0, block);
 * // words[0..8] contain data, words[9..15] are zero-padded
 */
function readLittleEndianWordsPartial(array, offset, words) {
  let i = 0;
  
  // Phase 1: Read complete 4-byte words while we have enough data
  // Condition: need at least 4 bytes remaining (offset + 3 < length)
  for (; offset + 3 < array.length && i < 16; ++i, offset += 4) {
    words[i] =
      array[offset] |
      (array[offset + 1] << 8) |
      (array[offset + 2] << 16) |
      (array[offset + 3] << 24);
  }
  
  // Phase 2: Zero-fill all remaining words
  // This ensures clean padding for incomplete blocks
  for (let j = i; j < 16; ++j) {
    words[j] = 0;
  }
  
  // Phase 3: Read trailing bytes (1-3 bytes that don't form a complete word)
  // These bytes are OR'd into the current word position
  // s = bit shift amount (0, 8, 16 for bytes 0, 1, 2)
  for (let s = 0; offset < array.length; s += 8, ++offset) {
    words[i] |= array[offset] << s;
  }
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

/**
 * Computes BLAKE3 hash of input data.
 * 
 * Algorithm works in three stages:
 * 
 * 1. PROCESSING FULL CHUNKS (1024 bytes each):
 *    - Each chunk consists of 16 blocks of 64 bytes
 *    - Blocks are chain-compressed into a single 256-bit value
 *    - Chunk results are pushed onto stack for Merkle tree
 * 
 * 2. PROCESSING LAST (INCOMPLETE) CHUNK:
 *    - May contain 0 to 1023 bytes
 *    - Padded with zeros to block boundary
 * 
 * 3. BUILDING MERKLE TREE:
 *    - Node pairs are combined into parent nodes
 *    - Repeated until single root is obtained
 *    - Root is hashed with ROOT flag
 * 
 * Tree visualization for 4 chunks:
 * 
 *              ROOT
 *             /    \
 *        PARENT    PARENT
 *        /   \     /    \
 *     CV0   CV1  CV2   CV3
 *      |     |    |     |
 *   Chunk0 Chunk1 Chunk2 Chunk3
 * 
 * @param {Uint8Array} input - input data
 * @returns {Uint8Array} - hash (32 bytes)
 */
function blake3(input) {
  // Input type validation
  if (!(input instanceof Uint8Array)) {
    throw new Error('Input must be Uint8Array');
  }

  // Initialization
  const flags = 0;                    // Base flags (can add KEYED_HASH etc.)
  const keyWords = IV;                // Key (IV for regular hashing)
  const blockWords = new Uint32Array(16);  // Block buffer
  const cvStack = [];                 // Stack for Merkle tree

  let chunkCounter = 0;               // Counter of processed chunks
  let offset = 0;                     // Current position in input data

  const length = input.length;
  
  // Calculate how many full chunks to process in Stage 1
  // take = largest multiple of 1024 that is strictly less than length
  // This ensures at least 1 byte remains for Stage 2 (last chunk processing)
  let take = length - (length % 1024);
  if (take === length && length > 0) { 
    // Edge case: length is exact multiple of 1024
    // We must leave the last chunk for Stage 2 to handle finalization correctly
    take -= 1024;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 1: Process full chunks (1024 bytes = 16 blocks each)
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < take; ) {
    let cv = keyWords;  // Chaining value (start with IV)

    // Process 16 blocks of the chunk
    for (let i = 0; i < 16; ++i, offset += 64) {
      readLittleEndianWordsFull(input, offset, blockWords);

      // Determine flags for block:
      // - First block: CHUNK_START
      // - Last block (15th): CHUNK_END
      // - Others: no flags
      cv = first8Words(
        compress(
          cv,
          blockWords,
          chunkCounter,
          BLOCK_LEN,
          flags | (i === 0 ? CHUNK_START : i === 15 ? CHUNK_END : 0)
        )
      );
    }

    chunkCounter += 1;
    cvStack.push(cv);  // Add chunk result to stack

    // Merge Merkle tree nodes while possible
    // (while chunk count is divisible by 2)
    let totalChunks = chunkCounter;
    while ((totalChunks & 1) === 0) {
      // Extract two child nodes
      const rightChildCv = cvStack.pop();
      const leftChildCv = cvStack.pop();
      
      // Form block for parent node:
      // left child (8 words) + right child (8 words) = 16 words
      blockWords.set(leftChildCv, 0);
      blockWords.set(rightChildCv, 8);
      
      // Compress with PARENT flag
      cv = first8Words(
        compress(keyWords, blockWords, 0, BLOCK_LEN, flags | PARENT)
      );
      cvStack.push(cv);
      
      totalChunks >>= 1;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 2: Process last (possibly incomplete) chunk
  // ═══════════════════════════════════════════════════════════════════════

  const remainingBytes = length - take;
  const fullBlocks = remainingBytes > 0 ? ((remainingBytes - 1) / 64) | 0 : 0;

  let cv = keyWords;

  // Process full blocks of last chunk
  for (let i = 0; i < fullBlocks; ++i, offset += 64) {
    readLittleEndianWordsFull(input, offset, blockWords);

    cv = first8Words(
      compress(
        cv,
        blockWords,
        chunkCounter,
        BLOCK_LEN,
        flags | (i === 0 ? CHUNK_START : i === 15 ? CHUNK_END : 0)
      )
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 3: Finalization — process last block and build root
  // ═══════════════════════════════════════════════════════════════════════

  let finalChainingValue;
  let finalBlockLen;
  let finalFlags;

  // Read last (possibly incomplete) block
  readLittleEndianWordsPartial(input, offset, blockWords);

  if (cvStack.length === 0) {
    // Special case: all data fits in one chunk
    // Final block is also the tree root
    finalChainingValue = cv;
    finalBlockLen = length - offset;
    finalFlags = flags | ROOT | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0);
  } else {
    // General case: need to build Merkle tree
    finalChainingValue = keyWords;
    finalBlockLen = BLOCK_LEN;
    finalFlags = flags | PARENT | ROOT;

    // Complete last chunk
    cv = first8Words(
      compress(
        cv,
        blockWords,
        chunkCounter,
        length - offset,
        flags | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
      )
    );

    cvStack.push(cv);

    // Merge remaining nodes into tree
    while (cvStack.length > 2) {
      const rightChildCv = cvStack.pop();
      const leftChildCv = cvStack.pop();
      blockWords.set(leftChildCv, 0);
      blockWords.set(rightChildCv, 8);
      cv = first8Words(
        compress(keyWords, blockWords, 0, BLOCK_LEN, flags | PARENT)
      );
      cvStack.push(cv);
    }

    // Prepare final block from two last nodes
    const rightChildCv = cvStack.pop();
    const leftChildCv = cvStack.pop();
    blockWords.set(leftChildCv, 0);
    blockWords.set(rightChildCv, 8);
  }

  // Final compression with ROOT flag
  const out = compress(
    finalChainingValue,
    blockWords,
    0,
    finalBlockLen,
    finalFlags
  );

  // Return first 32 bytes (256 bits) as hash
  return new Uint8Array(out.buffer, 0, 32);
}
const hash = blake3;


// ============================================================================
// EXPORT
// ============================================================================

export { blake3 };
export { hash };

/*
┌─────────────────────────────────────────────────────────────────┐
│                         INPUT DATA                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Split into CHUNKS (1024 bytes = 16 blocks of 64 bytes)         │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                 ▼
       ┌─────────┐       ┌─────────┐       ┌─────────┐
       │ Chunk 0 │       │ Chunk 1 │       │ Chunk N │
       └────┬────┘       └────┬────┘       └────┬────┘
            │                 │                 │
            ▼                 ▼                 ▼
       ┌─────────┐       ┌─────────┐       ┌─────────┐
       │   CV0   │       │   CV1   │       │   CVN   │
       └────┬────┘       └────┬────┘       └────┬────┘
            │                 │                 │
            └────────┬────────┴────────┬────────┘
                     ▼                 ▼
                ┌─────────┐       ┌─────────┐
                │ PARENT  │       │ PARENT  │
                └────┬────┘       └────┬────┘
                     └────────┬────────┘
                              ▼
                         ┌─────────┐
                         │  ROOT   │
                         └────┬────┘
                              │
                              ▼
                   ┌───────────────────┐
                   │   HASH (32 bytes) │
                   └───────────────────┘
*/
