/**
 * ============================================================================
 * BLAKE3 — Naive JavaScript Implementation (Working v9)
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
 * BLAKE3 v9 — WASM SIMD (compress4x)
 * ============================================================================
 * 
 * Optimizations in this version:
 * - v1: readLittleEndianWordsFull (no bounds checking)
 * - v2: Inline permutations (no array copying, precomputed access order)
 * - v3: Inlining round() into compress() + flat permutation array
 * - v4: Register-based state storage
 *       Replacing Uint32Array with 16 local variables (SMI)
 *       Full inlining of G-function with hardcoded indices
 * - v5: Zero-copy — in-place writing in compress() to out[outOffset...], cvStack as Uint32Array
 * - v6: Message block in local variables message_0...message_15
 *       Removal of PERMUTATIONS table, physical permutation
 *       Result: ~1.26x speedup (from 9.3 ms to 7.4 ms on 1 MB of data)
 * - v7: Global buffer reuse (workBuffer, cvStack)
 *       getCvStack() function with grow-only caching
 *       Elimination of allocations on repeated blake3() calls
 * - v8: Little-Endian Zero-Copy
 *       Byte order detection: IsBigEndian = !new Uint8Array(new Uint32Array([1]).buffer)[0]
 *       Creating Uint32Array view on input buffer (no data copying)
 *       compress() reads directly from inputWords instead of workBuffer
 *       Complete elimination of readLittleEndianWordsFull for full blocks
 *       Buffer alignment check (byteOffset % 4 === 0)
 *       Result: ~1.33x speedup (from 7.7 ms to 5.8 ms on 1 MB of data)
 * - v9: WASM SIMD (compress4x)
 *       This version generates a WebAssembly module on the fly and uses SIMD
 *       for parallel processing of 4 chunks simultaneously.
 * 
 *       Key features:
 *       - WASM bytecode generation at runtime (no external .wasm files)
 *       - compress4x: 4 parallel compress operations via SIMD (i32x4)
 *       - Fallback to JavaScript for remainder and finalization
 *       - Constant memory usage: 1 WASM page (64 KB)
 * 
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
const CHUNK_LEN = 1024;

// Endianness detection (runs once at module load time)
// If the first byte of Uint32Array([1]) is 0, we're on a big-endian system
const IsBigEndian = !new Uint8Array(new Uint32Array([1]).buffer)[0];


// ============================================================================
// WASM MODULE GENERATOR
// ============================================================================

/**
 * Message permutation table for 7 rounds of BLAKE3.
 * Each round permutes message words according to a fixed scheme.
 */
const MSG_PERMUTATION = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
];

/**
 * Precomputed message word access order for all 7 rounds.
 * For each round: 16 indices (8 pairs for 8 G-calls).
 */
function computeMessageSchedule() {
  const schedule = [];
  let perm = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
  
  for (let round = 0; round < 7; round++) {
    // Columns: G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
    schedule.push(perm[0], perm[1]);  // G0
    schedule.push(perm[2], perm[3]);  // G1
    schedule.push(perm[4], perm[5]);  // G2
    schedule.push(perm[6], perm[7]);  // G3
    // Diagonals: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
    schedule.push(perm[8], perm[9]);   // G4
    schedule.push(perm[10], perm[11]); // G5
    schedule.push(perm[12], perm[13]); // G6
    schedule.push(perm[14], perm[15]); // G7
    
    // Apply permutation for the next round
    if (round < 6) {
      perm = perm.map((_, i) => perm[MSG_PERMUTATION[i]]);
    }
  }
  
  return schedule;
}

const MESSAGE_SCHEDULE = computeMessageSchedule();

/**
 * Encodes a number in LEB128 format (Little Endian Base 128).
 * This is a variable-length format used in WASM.
 */
function toLebU32(n) {
  const bytes = [];
  do {
    let byte = n & 0x7f;
    n >>>= 7;
    if (n !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (n !== 0);
  return bytes;
}

/**
 * Generates a WASM module with the compress4x function.
 * 
 * compress4x performs 4 parallel compress operations via SIMD.
 * No parameters — works with fixed memory addresses.
 * 
 * Memory layout:
 *   0x000-0x0FF: blockWords[0..15] — 16 × v128 (256 bytes)
 *   0x100-0x1FF: CV input [0..7] × 4 — 8 × v128 (128 bytes)  
 *   0x180-0x1FF: counter_lo, counter_hi, blockLen, flags × 4
 *   0x200-0x2FF: state output [0..7] × 4 — 8 × v128 (128 bytes)
 */
function generateWasmModule() {
  const code = [];
  
  // ═══════════════════════════════════════════════════════════════════════
  // WASM HEADER
  // ═══════════════════════════════════════════════════════════════════════
  code.push(
    0x00, 0x61, 0x73, 0x6d,  // Magic: "\0asm"
    0x01, 0x00, 0x00, 0x00   // Version: 1
  );
  
  // ═══════════════════════════════════════════════════════════════════════
  // SECTION 1: Types
  // ═══════════════════════════════════════════════════════════════════════
  code.push(
    0x01,       // Section ID
    0x04,       // Section size: 4 bytes
    0x01,       // 1 type
    0x60,       // func type
    0x00,       // 0 params
    0x00        // 0 results
  );
  
  // ═══════════════════════════════════════════════════════════════════════
  // SECTION 2: Imports (memory from host)
  // ═══════════════════════════════════════════════════════════════════════
  code.push(
    0x02,       // Section ID
    0x0b,       // Section size: 11 bytes
    0x01,       // 1 import
    0x02, 0x6a, 0x73,       // module: "js"
    0x03, 0x6d, 0x65, 0x6d, // name: "mem"
    0x02,       // import kind: memory
    0x00,       // limits flags: no max
    0x01        // initial: 1 page (64KB)
  );
  
  // ═══════════════════════════════════════════════════════════════════════
  // SECTION 3: Functions
  // ═══════════════════════════════════════════════════════════════════════
  code.push(
    0x03,       // Section ID
    0x02,       // Section size: 2 bytes
    0x01,       // 1 function
    0x00        // function 0 uses type 0
  );
  
  // ═══════════════════════════════════════════════════════════════════════
  // SECTION 7: Exports
  // ═══════════════════════════════════════════════════════════════════════
  const exportName = "compress4x";
  code.push(
    0x07,                           // Section ID
    2 + exportName.length + 2,      // Section size
    0x01,                           // 1 export
    exportName.length               // name length
  );
  for (let i = 0; i < exportName.length; i++) {
    code.push(exportName.charCodeAt(i));
  }
  code.push(
    0x00,       // export kind: function
    0x00        // function index: 0
  );
  
  // ═══════════════════════════════════════════════════════════════════════
  // SECTION 10: Code
  // ═══════════════════════════════════════════════════════════════════════
  
  // Start code section
  const codeSectionStart = code.length;
  code.push(0x0a);  // Section ID
  
  // Reserve space for section size (5 bytes LEB128)
  const sectionSizePos = code.length;
  code.push(0x00, 0x00, 0x00, 0x00, 0x00);
  
  code.push(0x01);  // 1 function
  
  // Reserve space for function size
  const funcSizePos = code.length;
  code.push(0x00, 0x00, 0x00, 0x00, 0x00);
  
  const funcStart = code.length;
  
  // Local variables: 32 × v128
  // (16 for blockWords + 16 for state)
  code.push(
    0x01,       // 1 group of local variables
    0x20,       // 32 variables
    0x7b        // type v128
  );
  
  // ─────────────────────────────────────────────────────────────────────────
  // Load blockWords from memory into local variables $0..$15
  // ─────────────────────────────────────────────────────────────────────────
  for (let i = 0; i < 16; i++) {
    code.push(
      0x41, ...toLebU32(i * 16),  // i32.const [address]
      0xfd, 0x00, 0x04, 0x00,     // v128.load align=4
      0x21, i                      // local.set $i
    );
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Initialize state ($16..$31)
  // CV is loaded from memory (addresses 0x100-0x17F)
  // ─────────────────────────────────────────────────────────────────────────
  
  // state[0..7] = CV[0..7] from memory
  for (let i = 0; i < 8; i++) {
    code.push(
      0x41, ...toLebU32(0x100 + i * 16),  // i32.const [address]
      0xfd, 0x00, 0x04, 0x00,              // v128.load
      0x21, 16 + i                          // local.set $[16+i]
    );
  }
  
  // state[8..11] = IV[0..3] (constants, need to create)
  // Create v128 from 4 identical i32 values
  const ivValues = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
  for (let i = 0; i < 4; i++) {
    // v128.const with 4 identical IV[i] values
    code.push(0xfd, 0x0c);  // v128.const
    // 16 bytes little-endian (4 copies of IV[i])
    for (let j = 0; j < 4; j++) {
      const v = ivValues[i];
      code.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff);
    }
    code.push(0x21, 24 + i);  // local.set $[24+i]
  }
  
  // state[12..15] = counter_lo, counter_hi, blockLen, flags
  // Load from memory (addresses 0x180-0x1BF)
  for (let i = 0; i < 4; i++) {
    code.push(
      0x41, ...toLebU32(0x180 + i * 16),
      0xfd, 0x00, 0x04, 0x00,
      0x21, 28 + i
    );
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // 7 rounds
  // ─────────────────────────────────────────────────────────────────────────
  let msgIdx = 0;
  
  for (let round = 0; round < 7; round++) {
    // 8 G-calls (4 columns + 4 diagonals)
    const gCalls = [
      [16, 20, 24, 28],  // G(0,4,8,12) → state indices + 16
      [17, 21, 25, 29],  // G(1,5,9,13)
      [18, 22, 26, 30],  // G(2,6,10,14)
      [19, 23, 27, 31],  // G(3,7,11,15)
      [16, 21, 26, 31],  // G(0,5,10,15)
      [17, 22, 27, 28],  // G(1,6,11,12)
      [18, 23, 24, 29],  // G(2,7,8,13)
      [19, 20, 25, 30],  // G(3,4,9,14)
    ];
    
    for (let g = 0; g < 8; g++) {
      const [a, b, c, d] = gCalls[g];
      const mx = MESSAGE_SCHEDULE[msgIdx++];
      const my = MESSAGE_SCHEDULE[msgIdx++];
      
      // Generate G-function
      emitG(code, a, b, c, d, mx, my);
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Finalization: state[i] ^= state[i+8], write to memory
  // ─────────────────────────────────────────────────────────────────────────
  for (let i = 0; i < 8; i++) {
    code.push(
      0x41, ...toLebU32(0x200 + i * 16),  // i32.const [output address]
      0x20, 16 + i,                        // local.get $[state_i]
      0x20, 24 + i,                        // local.get $[state_i+8]
      0xfd, 0x51,                          // v128.xor
      0xfd, 0x0b, 0x04, 0x00               // v128.store align=4
    );
  }
  
  // end
  code.push(0x0b);
  
  // ─────────────────────────────────────────────────────────────────────────
  // Fill in sizes
  // ─────────────────────────────────────────────────────────────────────────
  const funcSize = code.length - funcStart;
  const funcSizeBytes = toLebU32(funcSize);
  // Pad to 5 bytes
  while (funcSizeBytes.length < 5) funcSizeBytes.push(0);
  for (let i = 0; i < 5; i++) {
    code[funcSizePos + i] = funcSizeBytes[i];
  }
  
  const sectionSize = code.length - sectionSizePos - 5;
  const sectionSizeBytes = toLebU32(sectionSize);
  while (sectionSizeBytes.length < 5) sectionSizeBytes.push(0);
  for (let i = 0; i < 5; i++) {
    code[sectionSizePos + i] = sectionSizeBytes[i];
  }
  
  return new Uint8Array(code);
}

/**
 * Generates G-function code for SIMD.
 * 
 * G(a, b, c, d, mx, my):
 *   a = a + b + m[mx]; d = rotr(d ^ a, 16); c = c + d; b = rotr(b ^ c, 12);
 *   a = a + b + m[my]; d = rotr(d ^ a, 8);  c = c + d; b = rotr(b ^ c, 7);
 */
const ROTR16 = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];
const ROTR8  = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
 
function emitG(code, a, b, c, d, mx, my) {
  // First half of G (rotation 16, 12)
  emitGHalf(code, a, b, c, d, mx, 16, 12);
  // Second half of G (rotation 8, 7)
  emitGHalf(code, a, b, c, d, my, 8, 7);
}

function emitGHalf(code, a, b, c, d, m, rotD, rotB) {
  // a = a + b + m[m]
  code.push(
    0x20, a,            // local.get $a
    0x20, b,            // local.get $b
    0xfd, 0xae, 0x01,   // i32x4.add
    0x20, m,            // local.get $m (blockWords index)
    0xfd, 0xae, 0x01,   // i32x4.add
    0x22, a             // local.tee $a
  );
  
  // d = rotr(d ^ a, rotD)
  code.push(
    0x20, d,            // local.get $d
    0xfd, 0x51,         // v128.xor
    0x22, d,            // local.tee $d
    0x41, rotD,         // i32.const rotD
    0xfd, 0xad, 0x01,   // i32x4.shr_u
    0x20, d,            // local.get $d
    0x41, 32 - rotD,    // i32.const (32 - rotD)
    0xfd, 0xab, 0x01,   // i32x4.shl
    0xfd, 0x50,         // v128.or
    0x22, d             // local.tee $d
  );
  
  // c = c + d
  code.push(
    0x20, c,            // local.get $c
    0xfd, 0xae, 0x01,   // i32x4.add
    0x22, c             // local.tee $c
  );
  
  // b = rotr(b ^ c, rotB)
  code.push(
    0x20, b,            // local.get $b
    0xfd, 0x51,         // v128.xor
    0x22, b,            // local.tee $b
    0x41, rotB,         // i32.const rotB
    0xfd, 0xad, 0x01,   // i32x4.shr_u
    0x20, b,            // local.get $b
    0x41, 32 - rotB,    // i32.const (32 - rotB)
    0xfd, 0xab, 0x01,   // i32x4.shl
    0xfd, 0x50,         // v128.or
    0x21, b             // local.set $b
  );
}

// ============================================================================
// WASM INITIALIZATION
// ============================================================================

let wasmMemory = null;
let wasmCompress4x = null;
let wasmMemoryView = null;
let wasmMemoryU32 = null;
let wasmSupported = false;

/**
 * WASM module initialization.
 * Called once on load.
 */
async function initWasm() {
  try {
    // Check WASM SIMD support
    const simdTest = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b,
      0x03, 0x02, 0x01, 0x00,
      0x0a, 0x0a, 0x01, 0x08, 0x00, 0x41, 0x00, 0xfd, 0x0c,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b
    ]);
    
    await WebAssembly.compile(simdTest);
    
    // Generate our module
    const wasmBytes = generateWasmModule();
    
    // Create memory
    wasmMemory = new WebAssembly.Memory({ initial: 1 });
    wasmMemoryView = new Uint8Array(wasmMemory.buffer);
    wasmMemoryU32 = new Uint32Array(wasmMemory.buffer);
    
    // Compile and instantiate
    const module = await WebAssembly.compile(wasmBytes);
    const instance = await WebAssembly.instantiate(module, {
      js: { mem: wasmMemory }
    });
    
    wasmCompress4x = instance.exports.compress4x;
    wasmSupported = true;
    
    console.log('BLAKE3 WASM SIMD initialized successfully');
  } catch (e) {
    console.warn('BLAKE3 WASM SIMD not available, using JS fallback:', e.message);
    wasmSupported = false;
  }
}

// Synchronous initialization (for module systems)
function initWasmSync() {
  try {
    const wasmBytes = generateWasmModule();
    wasmMemory = new WebAssembly.Memory({ initial: 1 });
    wasmMemoryView = new Uint8Array(wasmMemory.buffer);
    wasmMemoryU32 = new Uint32Array(wasmMemory.buffer);
    
    const module = new WebAssembly.Module(wasmBytes);
    const instance = new WebAssembly.Instance(module, {
      js: { mem: wasmMemory }
    });
    
    wasmCompress4x = instance.exports.compress4x;
    wasmSupported = true;
  } catch (e) {
    wasmSupported = false;
  }
}

// Try to initialize synchronously
initWasmSync();

// ============================================================================
// WASM MEMORY FUNCTIONS
// ============================================================================

/**
 * Writes transposed blocks to WASM memory.
 * 
 * 4 chunks × 16 blocks = 64 blocks
 * But compress4x processes 4 blocks at a time (one from each chunk).
 * 
 * For block #i:
 *   blockWords[j] = [chunk0[i*16+j], chunk1[i*16+j], chunk2[i*16+j], chunk3[i*16+j]]
 */
function writeTransposedBlock(input, offsets, blockIndex) {
  // offsets = [offset0, offset1, offset2, offset3] — starts of 4 chunks
  // blockIndex = 0..15 — block number within chunk
  
  const blockOffset = blockIndex * BLOCK_LEN;
  
  for (let word = 0; word < 16; word++) {
    const memAddr = word * 16;  // Address in WASM memory
    
    for (let chunk = 0; chunk < 4; chunk++) {
      const inputOffset = offsets[chunk] + blockOffset + word * 4;
      
      // Read 4 bytes as little-endian word
      const w = input[inputOffset] |
                (input[inputOffset + 1] << 8) |
                (input[inputOffset + 2] << 16) |
                (input[inputOffset + 3] << 24);
      
      // Write to corresponding v128 position
      wasmMemoryU32[(memAddr >> 2) + chunk] = w;
    }
  }
}

/**
 * Writes CV and parameters for 4 parallel compress operations.
 */
function writeCVAndParams(cvs, counters, blockLen, flags) {
  // cvs = [[cv0], [cv1], [cv2], [cv3]] — 4 arrays of 8 words each
  // counters = [counter0, counter1, counter2, counter3]
  
  // CV: addresses 0x100-0x17F (8 × v128)
  for (let i = 0; i < 8; i++) {
    const memAddr = 0x100 + i * 16;
    for (let chunk = 0; chunk < 4; chunk++) {
      wasmMemoryU32[(memAddr >> 2) + chunk] = cvs[chunk][i];
    }
  }
  
  // counter_lo: address 0x180
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x180 >> 2) + chunk] = counters[chunk] | 0;
  }
  
  // counter_hi: address 0x190
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x190 >> 2) + chunk] = (counters[chunk] / 0x100000000) | 0;
  }
  
  // blockLen: address 0x1A0
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x1A0 >> 2) + chunk] = blockLen;
  }
  
  // flags: address 0x1B0
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x1B0 >> 2) + chunk] = flags[chunk];
  }
}

/**
 * Reads compress4x results from WASM memory.
 */
function readResults(cvs) {
  // Results at addresses 0x200-0x27F (8 × v128)
  for (let i = 0; i < 8; i++) {
    const memAddr = 0x200 + i * 16;
    for (let chunk = 0; chunk < 4; chunk++) {
      cvs[chunk][i] = wasmMemoryU32[(memAddr >> 2) + chunk];
    }
  }
}


// ═══════════════════════════════════════════════════════════════════════
// GLOBAL REUSABLE PRE-ALLOCATED BUFFERS
// Global buffers (created once when the module loads)
// No allocations in blake3() function and hot loop
// ═══════════════════════════════════════════════════════════════════════

// Buffer for current CV (8 words) and message block (16 words)
// Combined into one array for better locality
const globalWorkBuffer = new Uint32Array(8 + 16);  // cv[0..7] + block[0..15]

// Cached CV stack — grows when needed, but never shrinks
let globalCvStack = null;


/**
 * Get a CV stack of the required size.
 * Reuses the existing one if it's large enough.
 * 
 * @param {number} inputLength - input length for calculating tree depth
 * @returns {Uint32Array} - Stack of sufficient size
 */
function getCvStack(inputLength) {
  // Maximum tree depth: log2(max_chunks)
  const maxDepth = Math.log2(1 + Math.ceil(inputLength / 1024)) + 1;
  // Minimum 54 levels — covers files up to 2^54 chunks long
  const depth = Math.max(maxDepth, 54);
  const length = depth * 8;
  
  if (globalCvStack === null || globalCvStack.length < length) {
    // Create new only if the old one is too small
    globalCvStack = new Uint32Array(length);
  }
  
  return globalCvStack;
}


// ============================================================================
// COMPRESSION FUNCTION
// ============================================================================

/**
 * Compression function - the core cryptographic operation of BLAKE3.
 * 
 * BLAKE3 compression function with in-place result writing and
 * register-based state storage.
 * 
 * Instead of using Uint32Array for state (which requires memory access),
 * we use 16 local variables s_0...s_15 that the JIT compiler
 * can place directly in CPU registers.
 * 
 * This eliminates:
 * - 448 array writes per compress() call
 * - 1008 array reads per compress() call
 * - Bounds checking overhead
 * - Memory indirection
 * 
 * The G-function is fully inlined with hardcoded indices.
 * Code is generated via metaprogramming (see generator in comments).
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * INITIAL STATE STRUCTURE (16 words = 512 bits)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  s_0    s_1    s_2    s_3   ← chaining value [0..3]                 │
 *   │  s_4    s_5    s_6    s_7   ← chaining value [4..7]                 │
 *   │  s_8    s_9    s_10   s_11  ← IV constants (roots of primes)        │
 *   │  s_12   s_13   s_14   s_15  ← counter_lo, counter_hi, length, flags │
 *   └─────────────────────────────────────────────────────────────────────┘
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * ROUND STRUCTURE (7 rounds total)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Each round applies the G-function to all 16 state words in two phases:
 * 
 * Phase 1 - COLUMNS:          Phase 2 - DIAGONALS:
 * 
 *   ┌────┬────┬────┬────┐       ┌────┬────┬────┬────┐
 *   │ ↓  │ ↓  │ ↓  │ ↓  │       │ ↘  │  ↘ │    │↘   │
 *   ├────┼────┼────┼────┤       ├────┼────┼────┼────┤
 *   │ ↓  │ ↓  │ ↓  │ ↓  │       │    │ ↘  │  ↘ │    │
 *   ├────┼────┼────┼────┤       ├────┼────┼────┼────┤
 *   │ ↓  │ ↓  │ ↓  │ ↓  │       │    │    │ ↘  │  ↘ │
 *   ├────┼────┼────┼────┤       ├────┼────┼────┼────┤
 *   │ ↓  │ ↓  │ ↓  │ ↓  │       │  ↘ │    │    │ ↘  │
 *   └────┴────┴────┴────┘       └────┴────┴────┴────┘
 * 
 *   G(0,4,8,12)   G(1,5,9,13)     G(0,5,10,15)  G(1,6,11,12)
 *   G(2,6,10,14)  G(3,7,11,15)    G(2,7,8,13)   G(3,4,9,14)
 * 
 * Total operations: 7 rounds × 8 G-calls × 12 operations = 672 operations
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * G-FUNCTION (ARX - Add-Rotate-XOR)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   a ← a + b + mx        a ← a + b + my
 *   d ← (d ⊕ a) >>> 16    d ← (d ⊕ a) >>> 8
 *   c ← c + d             c ← c + d
 *   b ← (b ⊕ c) >>> 12    b ← (b ⊕ c) >>> 7
 * 
 * Rotation constants (16, 12, 8, 7) are optimized for 32-bit diffusion.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * FINALIZATION
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   output[0..7]  = low_half ⊕ high_half  (feed-forward for chaining)
 *   output[8..15] = high_half ⊕ cv        (for XOF extended output)
 * 
 * @param {Uint32Array} cv        - Chaining value (8 × 32-bit words)
 * @param {number}      cvOffset  - CV offset in array
 * @param {Uint32Array} m         - Message block (16 × 32-bit words)
 * @param {number}      mOffset   - Block offset in array
 * @param {Uint32Array} out       - Output array for result
 * @param {number}      outOffset - Output write offset
 * @param {boolean}     truncate  - true = write only 8 words (CV)
 *                                  false = write all 16 words (XOF)
 * @param {number}      counter   - 64-bit block counter (as JS number)
 * @param {number}      blockLen  - Block length in bytes (0-64)
 * @param {number}      flags     - Domain separation flags
 * @returns {Uint32Array}         - 512-bit output (16 × 32-bit words)
 */
function compress(
  cv, cvOffset,
  m, mOffset,
  out, outOffset,
  truncate,
  counter, blockLen, flags
) {
  // ═══════════════════════════════════════════════════════════════════════
  // State initialization - 16 local variables instead of Uint32Array
  // ═══════════════════════════════════════════════════════════════════════
  let s_0 = cv[cvOffset + 0] | 0;
  let s_1 = cv[cvOffset + 1] | 0;
  let s_2 = cv[cvOffset + 2] | 0;
  let s_3 = cv[cvOffset + 3] | 0;
  let s_4 = cv[cvOffset + 4] | 0;
  let s_5 = cv[cvOffset + 5] | 0;
  let s_6 = cv[cvOffset + 6] | 0;
  let s_7 = cv[cvOffset + 7] | 0;
  let s_8 = 0x6A09E667;   // IV[0] - sqrt(2)
  let s_9 = 0xBB67AE85;   // IV[1] - sqrt(3)
  let s_10 = 0x3C6EF372;  // IV[2] - sqrt(5)
  let s_11 = 0xA54FF53A;  // IV[3] - sqrt(7)
  let s_12 = counter | 0;                   // Counter low 32 bits
  let s_13 = (counter / 0x100000000) | 0;   // Counter high 32 bits
  let s_14 = blockLen | 0;
  let s_15 = flags | 0;

  // ═══════════════════════════════════════════════════════════════════════
  // Message initialization message_ - 16 local variables instead of Uint32Array
  // NEW: Message block also in local variables!
  // ═══════════════════════════════════════════════════════════════════════
  let message_0 = m[mOffset + 0] | 0;
  let message_1 = m[mOffset + 1] | 0;
  let message_2 = m[mOffset + 2] | 0;
  let message_3 = m[mOffset + 3] | 0;
  let message_4 = m[mOffset + 4] | 0;
  let message_5 = m[mOffset + 5] | 0;
  let message_6 = m[mOffset + 6] | 0;
  let message_7 = m[mOffset + 7] | 0;
  let message_8 = m[mOffset + 8] | 0;
  let message_9 = m[mOffset + 9] | 0;
  let message_10 = m[mOffset + 10] | 0;
  let message_11 = m[mOffset + 11] | 0;
  let message_12 = m[mOffset + 12] | 0;
  let message_13 = m[mOffset + 13] | 0;
  let message_14 = m[mOffset + 14] | 0;
  let message_15 = m[mOffset + 15] | 0;

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
  for (let round = 0; round < 7; ++round) {
    // ─────────────────────────────────────────────────────────────
    // Phase 1: Column mixing
    // G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
    // ─────────────────────────────────────────────────────────────
    // G is applied vertically to each of 4 columns.
    //
    // Message words are accessed via m[PERMUTATIONS[p++]], where p
    // automatically advances through the flat permutation array.

    // G(0, 4, 8, 12) with message_0, message_1
    s_0 = (((s_0 + s_4) | 0) + message_0) | 0;
    s_12 ^= s_0;
    s_12 = (s_12 >>> 16) | (s_12 << 16);
    s_8 = (s_8 + s_12) | 0;
    s_4 ^= s_8;
    s_4 = (s_4 >>> 12) | (s_4 << 20);
    s_0 = (((s_0 + s_4) | 0) + message_1) | 0;
    s_12 ^= s_0;
    s_12 = (s_12 >>> 8) | (s_12 << 24);
    s_8 = (s_8 + s_12) | 0;
    s_4 ^= s_8;
    s_4 = (s_4 >>> 7) | (s_4 << 25);

    // G(1, 5, 9, 13) with message_2, message_3
    s_1 = (((s_1 + s_5) | 0) + message_2) | 0;
    s_13 ^= s_1;
    s_13 = (s_13 >>> 16) | (s_13 << 16);
    s_9 = (s_9 + s_13) | 0;
    s_5 ^= s_9;
    s_5 = (s_5 >>> 12) | (s_5 << 20);
    s_1 = (((s_1 + s_5) | 0) + message_3) | 0;
    s_13 ^= s_1;
    s_13 = (s_13 >>> 8) | (s_13 << 24);
    s_9 = (s_9 + s_13) | 0;
    s_5 ^= s_9;
    s_5 = (s_5 >>> 7) | (s_5 << 25);

    // G(2, 6, 10, 14) with message_4, message_5
    s_2 = (((s_2 + s_6) | 0) + message_4) | 0;
    s_14 ^= s_2;
    s_14 = (s_14 >>> 16) | (s_14 << 16);
    s_10 = (s_10 + s_14) | 0;
    s_6 ^= s_10;
    s_6 = (s_6 >>> 12) | (s_6 << 20);
    s_2 = (((s_2 + s_6) | 0) + message_5) | 0;
    s_14 ^= s_2;
    s_14 = (s_14 >>> 8) | (s_14 << 24);
    s_10 = (s_10 + s_14) | 0;
    s_6 ^= s_10;
    s_6 = (s_6 >>> 7) | (s_6 << 25);

    // G(3, 7, 11, 15) with message_6, message_7
    s_3 = (((s_3 + s_7) | 0) + message_6) | 0;
    s_15 ^= s_3;
    s_15 = (s_15 >>> 16) | (s_15 << 16);
    s_11 = (s_11 + s_15) | 0;
    s_7 ^= s_11;
    s_7 = (s_7 >>> 12) | (s_7 << 20);
    s_3 = (((s_3 + s_7) | 0) + message_7) | 0;
    s_15 ^= s_3;
    s_15 = (s_15 >>> 8) | (s_15 << 24);
    s_11 = (s_11 + s_15) | 0;
    s_7 ^= s_11;
    s_7 = (s_7 >>> 7) | (s_7 << 25);
    
    // ─────────────────────────────────────────────────────────────
    // Phase 2: Diagonal mixing
    // G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
    // ─────────────────────────────────────────────────────────────
    // G is applied along diagonals with wrap-around.
    //
    
    // G(0, 5, 10, 15) with message_8, message_9
    s_0 = (((s_0 + s_5) | 0) + message_8) | 0;
    s_15 ^= s_0;
    s_15 = (s_15 >>> 16) | (s_15 << 16);
    s_10 = (s_10 + s_15) | 0;
    s_5 ^= s_10;
    s_5 = (s_5 >>> 12) | (s_5 << 20);
    s_0 = (((s_0 + s_5) | 0) + message_9) | 0;
    s_15 ^= s_0;
    s_15 = (s_15 >>> 8) | (s_15 << 24);
    s_10 = (s_10 + s_15) | 0;
    s_5 ^= s_10;
    s_5 = (s_5 >>> 7) | (s_5 << 25);

    // G(1, 6, 11, 12) with message_10, message_11
    s_1 = (((s_1 + s_6) | 0) + message_10) | 0;
    s_12 ^= s_1;
    s_12 = (s_12 >>> 16) | (s_12 << 16);
    s_11 = (s_11 + s_12) | 0;
    s_6 ^= s_11;
    s_6 = (s_6 >>> 12) | (s_6 << 20);
    s_1 = (((s_1 + s_6) | 0) + message_11) | 0;
    s_12 ^= s_1;
    s_12 = (s_12 >>> 8) | (s_12 << 24);
    s_11 = (s_11 + s_12) | 0;
    s_6 ^= s_11;
    s_6 = (s_6 >>> 7) | (s_6 << 25);

    // G(2, 7, 8, 13) with message_12, message_13
    s_2 = (((s_2 + s_7) | 0) + message_12) | 0;
    s_13 ^= s_2;
    s_13 = (s_13 >>> 16) | (s_13 << 16);
    s_8 = (s_8 + s_13) | 0;
    s_7 ^= s_8;
    s_7 = (s_7 >>> 12) | (s_7 << 20);
    s_2 = (((s_2 + s_7) | 0) + message_13) | 0;
    s_13 ^= s_2;
    s_13 = (s_13 >>> 8) | (s_13 << 24);
    s_8 = (s_8 + s_13) | 0;
    s_7 ^= s_8;
    s_7 = (s_7 >>> 7) | (s_7 << 25);

    // G(3, 4, 9, 14) with message_14, message_15
    s_3 = (((s_3 + s_4) | 0) + message_14) | 0;
    s_14 ^= s_3;
    s_14 = (s_14 >>> 16) | (s_14 << 16);
    s_9 = (s_9 + s_14) | 0;
    s_4 ^= s_9;
    s_4 = (s_4 >>> 12) | (s_4 << 20);
    s_3 = (((s_3 + s_4) | 0) + message_15) | 0;
    s_14 ^= s_3;
    s_14 = (s_14 >>> 8) | (s_14 << 24);
    s_9 = (s_9 + s_14) | 0;
    s_4 ^= s_9;
    s_4 = (s_4 >>> 7) | (s_4 << 25);
    
    // ─────────────────────────────────────────────────────────────────────
    // Permutation (except for the last round)
    // ─────────────────────────────────────────────────────────────────────
    if (round !== 6) {
      const t0 = message_0;
      const t1 = message_1;
      message_0 = message_2;
      message_2 = message_3;
      message_3 = message_10;
      message_10 = message_12;
      message_12 = message_9;
      message_9 = message_11;
      message_11 = message_5;
      message_5 = t0;
      message_1 = message_6;
      message_6 = message_4;
      message_4 = message_7;
      message_7 = message_13;
      message_13 = message_14;
      message_14 = message_15;
      message_15 = message_8;
      message_8 = t1;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Finalization
  // XOR upper and lower halves of state
  //
  // This "compresses" 512 bits to 256 bits and adds feed-forward
  // Writing to out instead of return
  //
  // Write order is CRITICAL for in-place correctness!
  // If out === cv and outOffset === cvOffset, then writing to out[0]
  // would destroy cv[0] before we read it for out[8].
  // Therefore we write the upper half (8-15) first, then the lower (0-7).
  // ═══════════════════════════════════════════════════════════════════════
  if (!truncate) {
    // Extended output (XOF) — need all 16 words
    out[outOffset + 8] = s_8 ^ cv[cvOffset + 0];
    out[outOffset + 9] = s_9 ^ cv[cvOffset + 1];
    out[outOffset + 10] = s_10 ^ cv[cvOffset + 2];
    out[outOffset + 11] = s_11 ^ cv[cvOffset + 3];
    out[outOffset + 12] = s_12 ^ cv[cvOffset + 4];
    out[outOffset + 13] = s_13 ^ cv[cvOffset + 5];
    out[outOffset + 14] = s_14 ^ cv[cvOffset + 6];
    out[outOffset + 15] = s_15 ^ cv[cvOffset + 7];
  }
  
  // Lower half — chaining value for the next block
  out[outOffset + 0] = s_0 ^ s_8;
  out[outOffset + 1] = s_1 ^ s_9;
  out[outOffset + 2] = s_2 ^ s_10;
  out[outOffset + 3] = s_3 ^ s_11;
  out[outOffset + 4] = s_4 ^ s_12;
  out[outOffset + 5] = s_5 ^ s_13;
  out[outOffset + 6] = s_6 ^ s_14;
  out[outOffset + 7] = s_7 ^ s_15;
}


// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Reads bytes as little-endian 32-bit words.
 * 
 * Little-endian means the least significant byte comes first.
 * Example: bytes [0x78, 0x56, 0x34, 0x12] → word 0x12345678
 */

/**
 * Fast reading of a full block (64 bytes) without bounds checking.
 * 
 * @param {Uint8Array}  array       - input byte array
 * @param {number}      offset      - starting read position
 * @param {Uint32Array} words       - output word array
 * @param {number}      wordsOffset - write position in output array
 */
// ═══════════════════════════════════════════════════════════════════════════
// ✅ OPTIMIZATION: Two versions of the read function
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Fast reading of a full block (64 bytes).
 * No bounds checking - for 99% of calls.
 */
function readLittleEndianWordsFull(array, offset, words, wordsOffset) {
  for (let i = 0; i < 16; ++i, offset += 4) {
    words[wordsOffset + i] = // Now writing with offset
      array[offset] |
      (array[offset + 1] << 8) |
      (array[offset + 2] << 16) |
      (array[offset + 3] << 24);
  }
}

/**
 * Reading a partial block with padding.
 * Only for the last block of data.
 */
/**
 * Handles partial blocks with zero padding.
 * Used only for the last block of data.
 * 
 * @param {Uint8Array}  array       - input byte array
 * @param {number}      offset      - starting read position
 * @param {number}      length      - total data length (for boundary detection)
 * @param {Uint32Array} words       - output word array
 * @param {number}      wordsOffset - write position in output array
 */
function readLittleEndianWordsPartial(array, offset, length, words, wordsOffset) {
  // Fill with zeros
  for (let i = 0; i < 16; ++i) {
    words[wordsOffset + i] = 0;
  }
  
  let i = 0;
  // Full 4-byte words
  for (; offset + 3 < length && i < 16; ++i, offset += 4) {
    words[wordsOffset + i] =
      array[offset] |
      (array[offset + 1] << 8) |
      (array[offset + 2] << 16) |
      (array[offset + 3] << 24);
  }
  
  // Remaining bytes
  for (let s = 0; offset < length; s += 8, ++offset) {
    words[wordsOffset + i] |= array[offset] << s;
  }
}

// ============================================================================
// MAIN FUNCTION WITH SIMD
// ============================================================================

/**
 * Processes 4 chunks in parallel via WASM SIMD.
 * 
 * @param {Uint8Array} input - input data
 * @param {number} baseOffset - starting offset
 * @param {number} baseChunkCounter - initial chunk counter
 * @returns {Array} - 4 CVs (each is Uint32Array[8])
 */
function process4ChunksSimd(input, baseOffset, baseChunkCounter) {
  const offsets = [
    baseOffset,
    baseOffset + CHUNK_LEN,
    baseOffset + CHUNK_LEN * 2,
    baseOffset + CHUNK_LEN * 3
  ];
  
  const counters = [
    baseChunkCounter,
    baseChunkCounter + 1,
    baseChunkCounter + 2,
    baseChunkCounter + 3
  ];
  
  // Initialize CV = IV for all 4 chunks
  for (let c = 0; c < 4; c++) {
    simdCVs[c].set(IV);
  }
  
  // 16 blocks per chunk
  for (let block = 0; block < 16; block++) {
    // Write transposed block
    writeTransposedBlock(input, offsets, block);
    
    // Determine flags
    const flags = [];
    for (let c = 0; c < 4; c++) {
      let f = 0;
      if (block === 0) f |= CHUNK_START;
      if (block === 15) f |= CHUNK_END;
      flags.push(f);
    }
    
    // Write CV and parameters
    writeCVAndParams(simdCVs, counters, BLOCK_LEN, flags);
    
    // Call SIMD compress
    wasmCompress4x();
    
    // Read results back into simdCVs
    readResults(simdCVs);
  }
  
  // Return copies of CVs
  return simdCVs.map(cv => new Uint32Array(cv));
}

// ============================================================================
// MAIN FUNCTION 
// BLAKE3 hash using WASM SIMD
// ============================================================================

/**
 * Computes BLAKE3 hash of input data.
 * 
 * The algorithm works in three stages:
 * 1a. PROCESSING FULL GROUPS OF 4 CHUNKS (4*1024 bytes each) via SIMD:
 * 
 * 1b. PROCESSING REMAINING FULL CHUNKS (1024 bytes each) (0-3 pieces) via JS:
 *    - Each chunk consists of 16 blocks of 64 bytes
 *    - Blocks are chained together into a single 256-bit value
 *    - Chunk results are pushed onto a stack for the Merkle tree
 * 
 * 2. PROCESSING THE LAST (PARTIAL) CHUNK:
 *    - May contain 0 to 1023 bytes
 *    - Padded with zeros to block boundary
 * 
 * 3. BUILDING THE MERKLE TREE:
 *    - Pairs of nodes are combined into parent nodes
 *    - Repeated until a single root is obtained
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
  const length = input.length;
  
  
  // ═══════════════════════════════════════════════════════════════════════
  // ADAPTIVE ALGORITHM SELECTION
  // ═══════════════════════════════════════════════════════════════════════
  //
  // For small inputs or without WASM — use JS version
  //
  // For data < 4 KB:
  //   - SIMD provides no advantage (need at least 4 chunks)
  //   - Overhead of copying to WASM memory
  //   - Overhead of data transposition
  //   - JavaScript v8 version is faster
  //
  // For data >= 4 KB:
  //   - SIMD processes 4 chunks in parallel
  //   - Parallelism gains outweigh the overhead
  // ═══════════════════════════════════════════════════════════════════════
  if (!wasmSupported || length < CHUNK_LEN * 4) {
    return blake3Fallback(input);
  }
  

  // ═════════════════════════════════════════════════════════════════════
  // Create Uint32Array view on input data (ONCE before loops)
  // On Little-Endian this gives direct access without copying
  // ═════════════════════════════════════════════════════════════════════
  const canUseDirectView = !IsBigEndian && (input.byteOffset % 4 === 0);
  const inputWords = canUseDirectView ? new Uint32Array(
    input.buffer,
    input.byteOffset,
    input.byteLength >> 2
  ) : null;

  const cvStack = getCvStack(length);  // May reuse existing one
  let cvStackPos = 0;

  const workBuffer = globalWorkBuffer;  // Always reuse
  const CV_OFFSET = 0;
  const BLOCK_OFFSET = 8;

  // Initialize CV = IV
  workBuffer.set(IV, CV_OFFSET);

  let chunkCounter = 0;               // Counter of processed chunks
  let offset = 0;                     // Current position in input data
  
  // ═══════════════════════════════════════════════════════════════════════
  // Calculate boundaries for different stages
  // ═══════════════════════════════════════════════════════════════════════
  
  // How many full groups of 4 chunks? (for SIMD)
  const fullGroups = Math.floor(length / (CHUNK_LEN * 4));
  const simdEnd = fullGroups * CHUNK_LEN * 4;
  
  // How many full chunks total?
  let take = length - (length % CHUNK_LEN);
  if (take === length && length > 0) {
    take -= CHUNK_LEN;
  }
  

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 1a: Processing full groups of 4 chunks (4*1024 bytes = 4*16 blocks)
  // via SIMD
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < simdEnd; offset += CHUNK_LEN * 4, chunkCounter += 4) {
    // Process 4 chunks in parallel
    const cvResults = process4ChunksSimd(input, offset, chunkCounter);

    // Process 4 chunk groups
    // Push CV to stack. Add chunk result to stack
    for (let c = 0; c < 4; c++) {
      cvStack.set(cvResults[c], cvStackPos);
      cvStackPos += 8;
      
      // Merkle tree merge
      // Merge Merkle tree nodes while possible
      // (while chunk count is divisible by 2)
      let totalChunks = chunkCounter + c + 1;
      while ((totalChunks & 1) === 0) {
        // Extract two child nodes
        cvStackPos -= 16;  // "Pop" two elements - just shift the number!
        
        // Compress with PARENT flag
        // Two CVs already lie adjacent in cvStack — use as blockWords!
        compress(
          IV, 0,                  // cv = IV (for parent node)
          cvStack, cvStackPos,    // message = two CVs, already adjacent!
          cvStack, cvStackPos,    // out = write result back to CV
          true,                   // truncate = only need 8 words
          0, BLOCK_LEN,
          flags | PARENT
        );
        
        // Add to array
        cvStackPos += 8;   // "Push" one element - result already in place!
        totalChunks >>= 1;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 1b: Processing remaining full chunks (0-3 pieces) via JS
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < take; ) {
    workBuffer.set(IV, CV_OFFSET);

    for (let i = 0; i < 16; ++i, offset += 64) {
      if (!canUseDirectView) {
        readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);
      }

      compress(
        workBuffer, CV_OFFSET,
        canUseDirectView ? inputWords : workBuffer,
        canUseDirectView ? (offset >> 2) : BLOCK_OFFSET,
        workBuffer, CV_OFFSET,
        true,
        chunkCounter,
        BLOCK_LEN,
        flags | (i === 0 ? CHUNK_START : i === 15 ? CHUNK_END : 0)
      );
    }

    cvStack.set(workBuffer.subarray(CV_OFFSET, CV_OFFSET + 8), cvStackPos);
    cvStackPos += 8;
    chunkCounter += 1;

    let totalChunks = chunkCounter;
    while ((totalChunks & 1) === 0) {
      cvStackPos -= 16;
      compress(
        IV, 0,
        cvStack, cvStackPos,
        cvStack, cvStackPos,
        true,
        0, BLOCK_LEN,
        flags | PARENT
      );
      cvStackPos += 8;
      totalChunks >>= 1;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 2: Processing the last (possibly partial) chunk
  // ═══════════════════════════════════════════════════════════════════════

  const remainingBytes = length - take;
  const fullBlocks = remainingBytes > 0 ? ((remainingBytes - 1) / 64) | 0 : 0;

  workBuffer.set(IV, CV_OFFSET);

  // Process full blocks of the last chunk
  for (let i = 0; i < fullBlocks; ++i, offset += 64) {
    if (!canUseDirectView) {
      // If big-endian, byte conversion is needed
      readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);  // ✅ Fast version
    }

    compress(
      workBuffer, CV_OFFSET,
      // block: workBuffer or directly input
      canUseDirectView ? inputWords : workBuffer, 
      // offset: in workBuffer or in inputWords
      canUseDirectView ? (offset >> 2) : BLOCK_OFFSET,
      workBuffer, CV_OFFSET,
      true,
      chunkCounter,
      BLOCK_LEN,
      flags | (i === 0 ? CHUNK_START : 0)
    );
  }
  
 
  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 3: Finalization - processing last block and building root
  // ═══════════════════════════════════════════════════════════════════════

  // Read last block (may be partial)
  readLittleEndianWordsPartial(input, offset, length, workBuffer, BLOCK_OFFSET);
  const lastBlockLen = length - offset;

  if (cvStackPos === 0) {
    // Special case: all data fits in one chunk
    // Final block is also the tree root
    // All data in one chunk — compute ROOT directly
    compress(
      workBuffer, CV_OFFSET,
      workBuffer, BLOCK_OFFSET,
      workBuffer, CV_OFFSET,
      true,
      chunkCounter,
      lastBlockLen,
      flags | ROOT | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
    );
  } else {
    // General case: need to build Merkle tree

    // Complete the last chunk
    compress(
      workBuffer, CV_OFFSET,
      workBuffer, BLOCK_OFFSET,
      cvStack, cvStackPos,  // Push result to stack
      true,
      chunkCounter,
      lastBlockLen,
      flags | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
    );
    cvStackPos += 8;

    // Merge remaining nodes into tree
    while (cvStackPos > 16) {
      cvStackPos -= 16;
      compress(
        IV, 0,
        cvStack, cvStackPos,
        cvStack, cvStackPos,
        true,
        0,
        BLOCK_LEN,
        flags | PARENT
      );
      cvStackPos += 8;
    }

    // Final merge with ROOT flag
    cvStackPos -= 16;
    compress(
      IV, 0,
      cvStack, cvStackPos,
      workBuffer, CV_OFFSET,  // Result in workBuffer
      true,
      0,
      BLOCK_LEN,
      flags | PARENT | ROOT
    );
  }
  // Return first 32 bytes (256 bits) as hash
  return new Uint8Array(workBuffer.buffer, CV_OFFSET * 4, 32);
}

/**
 * Fallback to pure JavaScript (code from v8).
 */
function blake3Fallback(input) {
  // Input type validation
  if (!(input instanceof Uint8Array)) {
    throw new Error('Input must be Uint8Array');
  }

  // Initialization
  const flags = 0;                    // Base flags (can add KEYED_HASH etc.)
  const length = input.length;

  // ═════════════════════════════════════════════════════════════════════
  // Create Uint32Array view on input data (ONCE before loops)
  // On Little-Endian this gives direct access without copying
  // ═════════════════════════════════════════════════════════════════════
    const canUseDirectView = !IsBigEndian && (input.byteOffset % 4 === 0);
    const inputWords = canUseDirectView ? new Uint32Array(
      input.buffer,
      input.byteOffset,
      input.byteLength >> 2
    ) : null;

  const cvStack = getCvStack(length);  // May reuse existing one
  let cvStackPos = 0;

  const workBuffer = globalWorkBuffer;  // Always reuse
  const CV_OFFSET = 0;
  const BLOCK_OFFSET = 8;

  // Initialize CV = IV
  workBuffer.set(IV, CV_OFFSET);

  let chunkCounter = 0;               // Counter of processed chunks
  let offset = 0;                     // Current position in input data
  
  // Calculate how many full chunks to process
  // take = largest multiple of 1024 that is < length
  let take = length - (length % 1024);
  if (take === length && length > 0) { 
    // If length is divisible by 1024, the last chunk is still processed separately (as partial),
    // or as full, but with CHUNK_END flag. 
    // In original logic, take must be less than length if length > 0.
    take -= 1024;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 1: Processing full chunks (1024 bytes = 16 blocks each)
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < take; ) {
    // Reset CV to IV for new chunk
    workBuffer.set(IV, CV_OFFSET);

    // Process 16 blocks of chunk
    for (let i = 0; i < 16; ++i, offset += 64) {
      // ═══════════════════════════════════════════════════════════════════
      // v8: Little-Endian optimization — Zero-Copy!
      // ═══════════════════════════════════════════════════════════════
      if (!canUseDirectView) {
        // If big-endian, byte conversion is needed
        readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);  // ✅ Fast version
      }
      // In other cases notation is little-endian and
      // then we read directly from inputWords — no copying!

      // Determine flags for block:
      // - First block: CHUNK_START
      // - Last block (15th): CHUNK_END
      // - Others: no flags
      compress(
        workBuffer, CV_OFFSET,      // cv
        // block: workBuffer or directly input
        canUseDirectView ? inputWords : workBuffer,      // ← direct access!
        // offset: in workBuffer or in inputWords
        canUseDirectView ? (offset >> 2): BLOCK_OFFSET,  // ← offset in words   
        workBuffer, CV_OFFSET,      // out = write back to CV
        true,                       // truncate
        chunkCounter,
        BLOCK_LEN,
        flags | (i === 0 ? CHUNK_START : i === 15 ? CHUNK_END : 0)
      );
    }

    // Push CV to stack. Add chunk result to stack
    cvStack.set(workBuffer.subarray(CV_OFFSET, CV_OFFSET + 8), cvStackPos);
    cvStackPos += 8;
    chunkCounter += 1;

    // Merge Merkle tree nodes while possible
    // (while chunk count is divisible by 2)
    let totalChunks = chunkCounter;
    while ((totalChunks & 1) === 0) {
      // Extract two child nodes
      cvStackPos -= 16;  // "Pop" two elements - just shift the number!
      
      // Compress with PARENT flag
      // Two CVs already lie adjacent in cvStack — use as blockWords!
      compress(
        IV, 0,                    // cv = IV (for parent node)
        cvStack, cvStackPos,      // m = two CVs, already adjacent!
        cvStack, cvStackPos,      // out = write result to same location
        true,                     // truncate = only need 8 words
        0, BLOCK_LEN, 
        flags | PARENT
      );
      
      // Add to array
      cvStackPos += 8;   // "Push" one element - result already in place!

      totalChunks >>= 1;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 2: Processing the last (possibly partial) chunk
  // ═══════════════════════════════════════════════════════════════════════

  const remainingBytes = length - take;
  const fullBlocks = remainingBytes > 0 ? ((remainingBytes - 1) / 64) | 0 : 0;

  // Reset CV to IV
  workBuffer.set(IV, CV_OFFSET);

  // Process full blocks of the last chunk
  for (let i = 0; i < fullBlocks; ++i, offset += 64) {
    if (!canUseDirectView) {
      // If big-endian, byte conversion is needed
      readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);  // ✅ Fast version
    }

    compress(
      workBuffer, CV_OFFSET,
      // block: workBuffer or directly input
      canUseDirectView ? inputWords : workBuffer, 
      // offset: in workBuffer or in inputWords
      canUseDirectView ? (offset >> 2) : BLOCK_OFFSET,
      workBuffer, CV_OFFSET,
      true,
      chunkCounter,
      BLOCK_LEN,
      flags | (i === 0 ? CHUNK_START : 0)
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // STAGE 3: Finalization - processing last block and building root
  // ═══════════════════════════════════════════════════════════════════════

  let finalChainingValue;
  let finalBlockLen;
  let finalFlags;

  // Read last block (may be partial)
  readLittleEndianWordsPartial(input, offset, length, workBuffer, BLOCK_OFFSET);  // ✅ With bounds checking
  const lastBlockLen = length - offset;

  if (cvStackPos === 0) {
    // Special case: all data fits in one chunk
    // Final block is also the tree root
    // All data in one chunk — compute ROOT directly
    compress(
      workBuffer, CV_OFFSET,
      workBuffer, BLOCK_OFFSET,
      workBuffer, CV_OFFSET,
      true,
      chunkCounter,
      lastBlockLen,
      flags | ROOT | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
    );
  } else {
    // General case: need to build Merkle tree

    // Complete the last chunk
    compress(
      workBuffer, CV_OFFSET,
      workBuffer, BLOCK_OFFSET,
      cvStack, cvStackPos,  // Push result to stack
      true,
      chunkCounter,
      lastBlockLen,
      flags | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
    );
    cvStackPos += 8;

    // Merge remaining nodes into tree
    while (cvStackPos > 16) {
      cvStackPos -= 16;
      compress(
        IV, 0,
        cvStack, cvStackPos,
        cvStack, cvStackPos,
        true,
        0,
        BLOCK_LEN,
        flags | PARENT
      );
      cvStackPos += 8;
    }

    // Final merge with ROOT flag
    cvStackPos -= 16;
    compress(
      IV, 0,
      cvStack, cvStackPos,
      workBuffer, CV_OFFSET,  // Result in workBuffer
      true,
      0,
      BLOCK_LEN,
      flags | PARENT | ROOT
    );
  }
  // Return first 32 bytes (256 bits) as hash
  return new Uint8Array(workBuffer.buffer, CV_OFFSET * 4, 32);
}
const hash = blake3;


// ============================================================================
// EXPORT
// ============================================================================

export { blake3, hash, initWasm, wasmSupported };

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
