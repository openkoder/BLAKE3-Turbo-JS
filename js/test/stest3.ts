// benchmark_copy.ts
// Запуск: deno run benchmark_copy.ts

// ==========================================
// 1. Подготовка фиктивного WASM
// ==========================================
function createDummyWasm() {
    // Минимальный валидный WASM модуль: () -> i32, возвращает 0
    const wasmCode = new Uint8Array([
        // Magic + Version
        0x00, 0x61, 0x73, 0x6d,  // \0asm
        0x01, 0x00, 0x00, 0x00,  // version 1
        
        // Type section (id=1)
        0x01,                    // section id
        0x05,                    // section size: 5 bytes
        0x01,                    // num types: 1
        0x60,                    // func type
        0x00,                    // num params: 0
        0x01, 0x7f,              // num results: 1, type: i32
        
        // Function section (id=3)
        0x03,                    // section id
        0x02,                    // section size: 2 bytes
        0x01,                    // num functions: 1
        0x00,                    // type index: 0
        
        // Memory section (id=5)
        0x05,                    // section id
        0x03,                    // section size: 3 bytes
        0x01,                    // num memories: 1
        0x00,                    // flags: no max
        0x01,                    // initial pages: 1 (64KB)
        
        // Export section (id=7)
        0x07,                    // section id
        0x0d,                    // section size: 13 bytes
        0x02,                    // num exports: 2
        // export "mem" -> memory 0
        0x03, 0x6d, 0x65, 0x6d,  // name length + "mem"
        0x02,                    // kind: memory
        0x00,                    // index: 0
        // export "run" -> function 0
        0x03, 0x72, 0x75, 0x6e,  // name length + "run"
        0x00,                    // kind: function
        0x00,                    // index: 0
        
        // Code section (id=10)
        0x0a,                    // section id
        0x06,                    // section size: 6 bytes
        0x01,                    // num functions: 1
        0x04,                    // function body size: 4 bytes
        0x00,                    // num locals: 0
        0x41, 0x00,              // i32.const 0
        0x0b                     // end
    ]);
    
    const mod = new WebAssembly.Module(wasmCode);
    const instance = new WebAssembly.Instance(mod);
    return {
        fn: instance.exports.run as () => number,
        mem: new Uint8Array((instance.exports.mem as WebAssembly.Memory).buffer),
        mem32: new Uint32Array((instance.exports.mem as WebAssembly.Memory).buffer)
    };
}

const { fn: wasmFn, mem: wasmMem, mem32: wasmMem32 } = createDummyWasm();

// ==========================================
// 2. Константы
// ==========================================
const CHUNK_LEN = 1024;      // 1KB чанк
const BLOCK_LEN = 64;        // 64 байта блок
const BLOCKS_PER_CHUNK = 16; // 16 блоков в чанке
const WORDS_PER_BLOCK = 16;  // 16 слов (u32) в блоке

// ==========================================
// 3. Подготовка входных данных
// ==========================================
function createRandomChunks(count: number): Uint8Array[] {
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < count; i++) {
        const chunk = new Uint8Array(CHUNK_LEN);
        crypto.getRandomValues(chunk);
        chunks.push(chunk);
    }
    return chunks;
}

// ==========================================
// 4. Вариант 1: Block-by-Block (16 вызовов WASM на группу)
// ==========================================
function processBlockByBlock(
    chunks: Uint8Array[], 
    iterations: number
): number {
    let dummySum = 0;
    const numGroups = Math.floor(chunks.length / 4);
    
    for (let iter = 0; iter < iterations; iter++) {
        for (let g = 0; g < numGroups; g++) {
            const c0 = new Uint32Array(chunks[g * 4].buffer);
            const c1 = new Uint32Array(chunks[g * 4 + 1].buffer);
            const c2 = new Uint32Array(chunks[g * 4 + 2].buffer);
            const c3 = new Uint32Array(chunks[g * 4 + 3].buffer);
            
            // 16 блоков, каждый обрабатывается отдельно
            for (let block = 0; block < BLOCKS_PER_CHUNK; block++) {
                const blockOffset = block * WORDS_PER_BLOCK;
                let memPtr = 0;
                
                // Транспонируем 1 блок (16 слов × 4 чанка = 64 слова)
                for (let word = 0; word < WORDS_PER_BLOCK; word++) {
                    wasmMem32[memPtr]     = c0[blockOffset + word];
                    wasmMem32[memPtr + 1] = c1[blockOffset + word];
                    wasmMem32[memPtr + 2] = c2[blockOffset + word];
                    wasmMem32[memPtr + 3] = c3[blockOffset + word];
                    memPtr += 4;
                }
                
                // Вызов WASM для обработки 1 блока
                dummySum += wasmFn();
            }
        }
    }
    return dummySum;
}

// ==========================================
// 5. Вариант 2: Chunk-at-Once (1 вызов WASM на группу)
// ==========================================
function transpose4Chunks(
    c0: Uint32Array, c1: Uint32Array, c2: Uint32Array, c3: Uint32Array,
    dst32: Uint32Array, dstOffset: number
): void {
    let d = dstOffset;
    
    // 256 слов в чанке, транспонируем все сразу
    for (let i = 0; i < 256; i += 4) {
        dst32[d]      = c0[i];
        dst32[d + 1]  = c1[i];
        dst32[d + 2]  = c2[i];
        dst32[d + 3]  = c3[i];
        
        dst32[d + 4]  = c0[i + 1];
        dst32[d + 5]  = c1[i + 1];
        dst32[d + 6]  = c2[i + 1];
        dst32[d + 7]  = c3[i + 1];
        
        dst32[d + 8]  = c0[i + 2];
        dst32[d + 9]  = c1[i + 2];
        dst32[d + 10] = c2[i + 2];
        dst32[d + 11] = c3[i + 2];
        
        dst32[d + 12] = c0[i + 3];
        dst32[d + 13] = c1[i + 3];
        dst32[d + 14] = c2[i + 3];
        dst32[d + 15] = c3[i + 3];
        
        d += 16;
    }
}

function processChunkAtOnce(
    chunks: Uint8Array[], 
    iterations: number
): number {
    let dummySum = 0;
    const numGroups = Math.floor(chunks.length / 4);
    
    for (let iter = 0; iter < iterations; iter++) {
        for (let g = 0; g < numGroups; g++) {
            const c0 = new Uint32Array(chunks[g * 4].buffer);
            const c1 = new Uint32Array(chunks[g * 4 + 1].buffer);
            const c2 = new Uint32Array(chunks[g * 4 + 2].buffer);
            const c3 = new Uint32Array(chunks[g * 4 + 3].buffer);
            
            // Транспонируем ВСЕ 4 чанка сразу (4KB)
            transpose4Chunks(c0, c1, c2, c3, wasmMem32, 0);
            
            // 1 вызов WASM на все 16 блоков
            dummySum += wasmFn();
        }
    }
    return dummySum;
}

// ==========================================
// 6. Вариант 3: Block-by-Block с memcpy (set)
// ==========================================
function processBlockByBlockMemcpy(
    chunks: Uint8Array[], 
    iterations: number
): number {
    let dummySum = 0;
    const numGroups = Math.floor(chunks.length / 4);
    
    for (let iter = 0; iter < iterations; iter++) {
        for (let g = 0; g < numGroups; g++) {
            for (let block = 0; block < BLOCKS_PER_CHUNK; block++) {
                const blockByteOffset = block * BLOCK_LEN;
                
                wasmMem.set(
                    chunks[g * 4].subarray(blockByteOffset, blockByteOffset + BLOCK_LEN), 
                    0
                );
                wasmMem.set(
                    chunks[g * 4 + 1].subarray(blockByteOffset, blockByteOffset + BLOCK_LEN), 
                    BLOCK_LEN
                );
                wasmMem.set(
                    chunks[g * 4 + 2].subarray(blockByteOffset, blockByteOffset + BLOCK_LEN), 
                    BLOCK_LEN * 2
                );
                wasmMem.set(
                    chunks[g * 4 + 3].subarray(blockByteOffset, blockByteOffset + BLOCK_LEN), 
                    BLOCK_LEN * 3
                );
                
                dummySum += wasmFn();
            }
        }
    }
    return dummySum;
}

// ==========================================
// 7. Вариант 4: Chunk-at-Once с memcpy (set)
// ==========================================
function processChunkAtOnceMemcpy(
    chunks: Uint8Array[], 
    iterations: number
): number {
    let dummySum = 0;
    const numGroups = Math.floor(chunks.length / 4);
    
    for (let iter = 0; iter < iterations; iter++) {
        for (let g = 0; g < numGroups; g++) {
            wasmMem.set(chunks[g * 4], 0);
            wasmMem.set(chunks[g * 4 + 1], CHUNK_LEN);
            wasmMem.set(chunks[g * 4 + 2], CHUNK_LEN * 2);
            wasmMem.set(chunks[g * 4 + 3], CHUNK_LEN * 3);
            
            dummySum += wasmFn();
        }
    }
    return dummySum;
}

// ==========================================
// 8. Бенчмарк
// ==========================================
interface BenchResult {
    name: string;
    totalMs: number;
    perGroupNs: number;
    wasmCallsPerGroup: number;
    throughputGBps: number;
}

function runBenchmark(
    name: string,
    fn: (chunks: Uint8Array[], iterations: number) => number,
    chunks: Uint8Array[],
    iterations: number,
    wasmCallsPerGroup: number
): BenchResult {
    const numGroups = Math.floor(chunks.length / 4);
    
    // Прогрев
    fn(chunks, 10);
    
    // Замер
    const start = performance.now();
    fn(chunks, iterations);
    const end = performance.now();
    
    const totalMs = end - start;
    const totalGroups = numGroups * iterations;
    const perGroupNs = (totalMs * 1_000_000) / totalGroups;
    
    const totalBytes = totalGroups * 4 * CHUNK_LEN;
    const throughputGBps = (totalBytes / (1024 * 1024 * 1024)) / (totalMs / 1000);
    
    return { name, totalMs, perGroupNs, wasmCallsPerGroup, throughputGBps };
}

function printResult(r: BenchResult) {
    console.log(`  ${r.name.padEnd(35)} | ` +
        `${r.totalMs.toFixed(2).padStart(8)} ms | ` +
        `${r.perGroupNs.toFixed(0).padStart(6)} ns/grp | ` +
        `${r.wasmCallsPerGroup.toString().padStart(2)} calls | ` +
        `${r.throughputGBps.toFixed(2).padStart(5)} GB/s`);
}

// ==========================================
// 9. Main
// ==========================================
console.log("═".repeat(80));
console.log("BENCHMARK: Block-by-Block vs Chunk-at-Once Copy Strategies");
console.log("═".repeat(80));
console.log(`Chunk size: ${CHUNK_LEN} bytes | Blocks/chunk: ${BLOCKS_PER_CHUNK} | Block size: ${BLOCK_LEN} bytes`);
console.log("");

const CHUNK_COUNTS = [1000, 10000];
const ITERATIONS = 100;

for (const numChunks of CHUNK_COUNTS) {
    const actualChunks = Math.floor(numChunks / 4) * 4;
    const numGroups = actualChunks / 4;
    
    console.log("─".repeat(80));
    console.log(`${actualChunks} chunks (${numGroups} groups) × ${ITERATIONS} iterations = ${numGroups * ITERATIONS} total ops`);
    console.log("");
    
    const chunks = createRandomChunks(actualChunks);
    const results: BenchResult[] = [];
    
    results.push(runBenchmark("Block-by-Block + Transpose", processBlockByBlock, chunks, ITERATIONS, 16));
    results.push(runBenchmark("Chunk-at-Once + Transpose", processChunkAtOnce, chunks, ITERATIONS, 1));
    results.push(runBenchmark("Block-by-Block + memcpy", processBlockByBlockMemcpy, chunks, ITERATIONS, 16));
    results.push(runBenchmark("Chunk-at-Once + memcpy", processChunkAtOnceMemcpy, chunks, ITERATIONS, 1));
    
    console.log("  Method                              |   Time    | Latency  | Calls | Speed");
    console.log("  " + "─".repeat(74));
    
    for (const r of results) {
        printResult(r);
    }
    
    console.log("");
    const ratio = results[0].totalMs / results[1].totalMs;
    const overheadNs = results[0].perGroupNs - results[1].perGroupNs;
    console.log(`  📊 Block-by-Block is ${ratio.toFixed(2)}x ${ratio > 1 ? "SLOWER" : "FASTER"} than Chunk-at-Once`);
    console.log(`  📊 15 extra WASM calls cost: ${overheadNs.toFixed(0)} ns (~${(overheadNs/15).toFixed(0)} ns/call)`);
    console.log("");
}

console.log("═".repeat(80));
