/**
 * ============================================================================
 * BLAKE3 — Naive JavaScript Implementation (Working v0)
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
 * Message permutation table between rounds.
 * After each round, message words are permuted according to this table.
 * 
 * Example: word at index 0 moves to position 2,
 *          word at index 1 moves to position 6, etc.
 * 
 * This ensures better diffusion of data.
 */
const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

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
 * G function — the heart of BLAKE3.
 * 
 * This is a quarter-round function that mixes
 * 4 state words (a, b, c, d) with two message words (mx, my).
 * 
 * Operation scheme (ARX — Add-Rotate-XOR):
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
 * @param {Uint32Array} state - array of 16 state words
 * @param {number} a, b, c, d - indices of words to mix
 * @param {number} mx, my - message words to mix in
 * 
 * Note: we use | 0 after addition to force
 * coercion to 32-bit signed integer (as in reference implementation).
 */
function g(state, a, b, c, d, mx, my) {
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

/**
 * Round — applies G function to all 16 state words.
 * 
 * State is represented as a 4×4 matrix:
 * 
 *   ┌──────┬──────┬──────┬──────┐
 *   │  0   │  1   │  2   │  3   │
 *   ├──────┼──────┼──────┼──────┤
 *   │  4   │  5   │  6   │  7   │
 *   ├──────┼──────┼──────┼──────┤
 *   │  8   │  9   │ 10   │ 11   │
 *   ├──────┼──────┼──────┼──────┤
 *   │ 12   │ 13   │ 14   │ 15   │
 *   └──────┴──────┴──────┴──────┘
 * 
 * Round consists of two phases:
 * 
 * 1. COLUMNS — G is applied to each column:
 *    G(0,4,8,12)  G(1,5,9,13)  G(2,6,10,14)  G(3,7,11,15)
 * 
 * 2. DIAGONALS — G is applied to diagonals:
 *    G(0,5,10,15) G(1,6,11,12) G(2,7,8,13)   G(3,4,9,14)
 * 
 * @param {Uint32Array} state - state of 16 words
 * @param {Uint32Array} m - message block of 16 words
 */
function round(state, m) {
  // Phase 1: process columns
  g(state, 0, 4,  8, 12, m[0],  m[1]);   // column 0
  g(state, 1, 5,  9, 13, m[2],  m[3]);   // column 1
  g(state, 2, 6, 10, 14, m[4],  m[5]);   // column 2
  g(state, 3, 7, 11, 15, m[6],  m[7]);   // column 3
  
  // Phase 2: process diagonals
  g(state, 0, 5, 10, 15, m[8],  m[9]);   // diagonal 0
  g(state, 1, 6, 11, 12, m[10], m[11]);  // diagonal 1
  g(state, 2, 7,  8, 13, m[12], m[13]);  // diagonal 2
  g(state, 3, 4,  9, 14, m[14], m[15]);  // diagonal 3
}

/**
 * Permutation of message words between rounds.
 * 
 * After each round, message words are permuted
 * according to MSG_PERMUTATION table. This ensures
 * that G functions receive words in different order each round.
 * 
 * @param {Uint32Array} m - message block (modified in place)
 */
function permute(m) {
  const copy = new Uint32Array(m);  // Save a copy
  for (let i = 0; i < 16; ++i) {
    m[i] = copy[MSG_PERMUTATION[i]];
  }
}

// ============================================================================
// COMPRESSION FUNCTION
// ============================================================================

/**
 * Compression function — the main cryptographic operation of BLAKE3.
 * 
 * Takes:
 * - chainingValue: 8 words (256 bits) — result of previous compression or IV
 * - blockWords: 16 words (512 bits) — data block
 * - counter: 64-bit chunk counter
 * - blockLen: block length in bytes (for padding)
 * - flags: domain flags
 * 
 * Returns: 16 words (512 bits) — compression result
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
    // Rows 0-1: chaining value (result from previous block or IV)
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

  // Copy of message block (will be modified by permute)
  const block = new Uint32Array(blockWords);

  // 7 rounds with permutation after each
  // (BLAKE2 has 10 rounds, BLAKE3 is optimized for speed)
  round(state, block); permute(block);  // Round 1
  round(state, block); permute(block);  // Round 2
  round(state, block); permute(block);  // Round 3
  round(state, block); permute(block);  // Round 4
  round(state, block); permute(block);  // Round 5
  round(state, block); permute(block);  // Round 6
  round(state, block); permute(block);  // Round 7

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
 * Reads bytes as little-endian 32-bit words.
 * 
 * Little-endian means the least significant byte comes first.
 * Example: bytes [0x78, 0x56, 0x34, 0x12] → word 0x12345678
 * 
 * Function also handles incomplete blocks (zero padding).
 * 
 * @param {Uint8Array} array - input bytes
 * @param {number} offset - starting position
 * @param {Uint32Array} words - array to write words (16 elements)
 */
function readLittleEndianWords(array, offset, words) {
  let i = 0;
  
  // Read complete 4-byte words
  for (; offset + 3 < array.length; ++i, offset += 4) {
    words[i] =
      array[offset] |                  // byte 0 → bits 0-7
      (array[offset + 1] << 8) |       // byte 1 → bits 8-15
      (array[offset + 2] << 16) |      // byte 2 → bits 16-23
      (array[offset + 3] << 24);       // byte 3 → bits 24-31
  }
  
  // Fill remaining words with zeros (padding)
  for (let j = i; j < words.length; ++j) {
    words[j] = 0;
  }
  
  // Process remaining 1-3 bytes (incomplete word)
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
  
  // Calculate how many full chunks to process
  // take = largest multiple of 1024 that is < length
  const take = Math.max(0, ((length - 1) | 1023) - 1023);

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 1: Process full chunks (1024 bytes = 16 blocks each)
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < take; ) {
    let cv = keyWords;  // Chaining value (start with IV)

    // Process 16 blocks of the chunk
    for (let i = 0; i < 16; ++i, offset += 64) {
      readLittleEndianWords(input, offset, blockWords);

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
    readLittleEndianWords(input, offset, blockWords);

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
  readLittleEndianWords(input, offset, blockWords);

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
