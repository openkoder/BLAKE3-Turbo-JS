// ═══════════════════════════════════════════════════════════════════════════
// БЕНЧМАРК v4: + transpose4Chunks (batch обработка)
// ═══════════════════════════════════════════════════════════════════════════

// Эмуляция WASM памяти (увеличена для transpose4Chunks: 64 × 16 = 1024 слова)
const wasmMemoryBuffer = new ArrayBuffer(4096);
const wasmMemoryU32 = new Uint32Array(wasmMemoryBuffer);

// ═══════════════════════════════════════════════════════════════════════════
// Подготовка тестовых данных
// ═══════════════════════════════════════════════════════════════════════════

const CHUNK_SIZE = 16 * 64;  // 1024 байт = 256 u32
const TOTAL_SIZE = 4 * CHUNK_SIZE;  // 4096 байт

const inputBuffer = new ArrayBuffer(TOTAL_SIZE);
const input = new Uint8Array(inputBuffer);

for (let i = 0; i < TOTAL_SIZE; i++) {
  input[i] = Math.floor(Math.random() * 256);
}

const offsets = [0, CHUNK_SIZE, CHUNK_SIZE * 2, CHUNK_SIZE * 3];

// ═══════════════════════════════════════════════════════════════════════════
// ПРЕДОБЪЯВЛЕННЫЕ ПЕРЕМЕННЫЕ
// ═══════════════════════════════════════════════════════════════════════════

let view0, view1, view2, view3;
const inputU32 = new Uint32Array(inputBuffer);

// ═══════════════════════════════════════════════════════════════════════════
// Версия 1: Предобъявленные переменные
// ═══════════════════════════════════════════════════════════════════════════
function fastPathPreDeclared(input, offsets, blockIndex) {
  const blockOffset = blockIndex << 6;
  
  view0 = new Uint32Array(input.buffer, input.byteOffset + offsets[0] + blockOffset, 16);
  view1 = new Uint32Array(input.buffer, input.byteOffset + offsets[1] + blockOffset, 16);
  view2 = new Uint32Array(input.buffer, input.byteOffset + offsets[2] + blockOffset, 16);
  view3 = new Uint32Array(input.buffer, input.byteOffset + offsets[3] + blockOffset, 16);
  
  for (let word = 0; word < 16; word++) {
    const memIdx = word << 2;
    wasmMemoryU32[memIdx + 0] = view0[word];
    wasmMemoryU32[memIdx + 1] = view1[word];
    wasmMemoryU32[memIdx + 2] = view2[word];
    wasmMemoryU32[memIdx + 3] = view3[word];
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Версия 2: Локальные const
// ═══════════════════════════════════════════════════════════════════════════
function fastPathLocalConst(input, offsets, blockIndex) {
  const blockOffset = blockIndex << 6;
  
  const v0 = new Uint32Array(input.buffer, input.byteOffset + offsets[0] + blockOffset, 16);
  const v1 = new Uint32Array(input.buffer, input.byteOffset + offsets[1] + blockOffset, 16);
  const v2 = new Uint32Array(input.buffer, input.byteOffset + offsets[2] + blockOffset, 16);
  const v3 = new Uint32Array(input.buffer, input.byteOffset + offsets[3] + blockOffset, 16);
  
  for (let word = 0; word < 16; word++) {
    const memIdx = word << 2;
    wasmMemoryU32[memIdx + 0] = v0[word];
    wasmMemoryU32[memIdx + 1] = v1[word];
    wasmMemoryU32[memIdx + 2] = v2[word];
    wasmMemoryU32[memIdx + 3] = v3[word];
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Версия 3: Единый Uint32Array
// ═══════════════════════════════════════════════════════════════════════════
function fastPathSingleView(input, offsets, blockIndex) {
  const blockOffset = blockIndex << 6;
  
  const base0 = (offsets[0] + blockOffset) >> 2;
  const base1 = (offsets[1] + blockOffset) >> 2;
  const base2 = (offsets[2] + blockOffset) >> 2;
  const base3 = (offsets[3] + blockOffset) >> 2;
  
  for (let word = 0; word < 16; word++) {
    const memIdx = word << 2;
    wasmMemoryU32[memIdx + 0] = inputU32[base0 + word];
    wasmMemoryU32[memIdx + 1] = inputU32[base1 + word];
    wasmMemoryU32[memIdx + 2] = inputU32[base2 + word];
    wasmMemoryU32[memIdx + 3] = inputU32[base3 + word];
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Версия 4: Побайтово
// ═══════════════════════════════════════════════════════════════════════════
function slowPath(input, offsets, blockIndex) {
  const blockOffset = blockIndex << 6;
  
  let offsetWord0 = offsets[0] + blockOffset;
  let offsetWord1 = offsets[1] + blockOffset;
  let offsetWord2 = offsets[2] + blockOffset;
  let offsetWord3 = offsets[3] + blockOffset;
  
  for (let word = 0; word < 16; word++) {
    const memIdx = word << 2;
    
    wasmMemoryU32[memIdx] = input[offsetWord0] |
              (input[offsetWord0 + 1] << 8) |
              (input[offsetWord0 + 2] << 16) |
              (input[offsetWord0 + 3] << 24);
    
    wasmMemoryU32[memIdx + 1] = input[offsetWord1] |
              (input[offsetWord1 + 1] << 8) |
              (input[offsetWord1 + 2] << 16) |
              (input[offsetWord1 + 3] << 24);
    
    wasmMemoryU32[memIdx + 2] = input[offsetWord2] |
              (input[offsetWord2 + 1] << 8) |
              (input[offsetWord2 + 2] << 16) |
              (input[offsetWord2 + 3] << 24);
    
    wasmMemoryU32[memIdx + 3] = input[offsetWord3] |
              (input[offsetWord3 + 1] << 8) |
              (input[offsetWord3 + 2] << 16) |
              (input[offsetWord3 + 3] << 24);
    
    offsetWord0 += 4;
    offsetWord1 += 4;
    offsetWord2 += 4;
    offsetWord3 += 4;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// Версия 5: transpose4Chunks (BATCH — все 16 блоков за один вызов!)
// ═══════════════════════════════════════════════════════════════════════════
function transpose4Chunks(src32, srcOffset, dst32, dstOffset) {
  let s = srcOffset;
  let d = dstOffset;

  for (let i = 0; i < 64; i++) {
    dst32[d] = src32[s];
    dst32[d + 1] = src32[s + 256];
    dst32[d + 2] = src32[s + 512];
    dst32[d + 3] = src32[s + 768];

    dst32[d + 4] = src32[s + 1];
    dst32[d + 5] = src32[s + 257];
    dst32[d + 6] = src32[s + 513];
    dst32[d + 7] = src32[s + 769];

    dst32[d + 8] = src32[s + 2];
    dst32[d + 9] = src32[s + 258];
    dst32[d + 10] = src32[s + 514];
    dst32[d + 11] = src32[s + 770];

    dst32[d + 12] = src32[s + 3];
    dst32[d + 13] = src32[s + 259];
    dst32[d + 14] = src32[s + 515];
    dst32[d + 15] = src32[s + 771];

    d += 16;
    s += 4;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// БЕНЧМАРК
// ═══════════════════════════════════════════════════════════════════════════

const WARMUP = 50000;
const ITERATIONS = 10000000;

console.log('═══════════════════════════════════════════════════════════════════');
console.log('    БЕНЧМАРК v4: + transpose4Chunks (batch)');
console.log('═══════════════════════════════════════════════════════════════════');
console.log(`Итераций: ${ITERATIONS.toLocaleString()}`);
console.log(`⚠️  transpose4Chunks вызывается в 16 раз реже (batch)\n`);

// Прогрев
console.log('Прогрев JIT...');
for (let i = 0; i < WARMUP; i++) {
  fastPathPreDeclared(input, offsets, i % 16);
  fastPathLocalConst(input, offsets, i % 16);
  fastPathSingleView(input, offsets, i % 16);
  slowPath(input, offsets, i % 16);
  if (i % 16 === 0) transpose4Chunks(inputU32, 0, wasmMemoryU32, 0);
}

const results = {};

console.log('\n[1/5] Предобъявленные view0-3 (let снаружи)...');
let t = performance.now();
for (let i = 0; i < ITERATIONS; i++) fastPathPreDeclared(input, offsets, i % 16);
results.preDeclared = performance.now() - t;

console.log('[2/5] Локальные const v0-3...');
t = performance.now();
for (let i = 0; i < ITERATIONS; i++) fastPathLocalConst(input, offsets, i % 16);
results.localConst = performance.now() - t;

console.log('[3/5] Единый Uint32Array (0 аллокаций)...');
t = performance.now();
for (let i = 0; i < ITERATIONS; i++) fastPathSingleView(input, offsets, i % 16);
results.singleView = performance.now() - t;

console.log('[4/5] Побайтово...');
t = performance.now();
for (let i = 0; i < ITERATIONS; i++) slowPath(input, offsets, i % 16);
results.bytewise = performance.now() - t;

// transpose4Chunks обрабатывает 16 блоков за раз!
// Для честного сравнения вызываем в 16 раз меньше
console.log('[5/5] transpose4Chunks (batch × 16 блоков)...');
t = performance.now();
for (let i = 0; i < ITERATIONS / 16; i++) transpose4Chunks(inputU32, 0, wasmMemoryU32, 0);
results.transpose4 = performance.now() - t;

// ═══════════════════════════════════════════════════════════════════════════
// Результаты
// ═══════════════════════════════════════════════════════════════════════════

console.log('\n═══════════════════════════════════════════════════════════════════');
console.log('                          РЕЗУЛЬТАТЫ');
console.log('═══════════════════════════════════════════════════════════════════');

const sorted = Object.entries(results).sort((a, b) => a[1] - b[1]);
const fastest = sorted[0][1];

const names = {
  preDeclared: 'let view0-3 снаружи      ',
  localConst:  'const v0-3 внутри        ',
  singleView:  'Единый Uint32Array       ',
  bytewise:    'Побайтово (сдвиги)       ',
  transpose4:  'transpose4Chunks (batch) '
};

sorted.forEach(([key, time], idx) => {
  const ops = (ITERATIONS / time * 1000).toFixed(0);
  const slower = ((time / fastest - 1) * 100).toFixed(1);
  const medal = idx === 0 ? '🥇' : idx === 1 ? '🥈' : idx === 2 ? '🥉' : '  ';
  console.log(`${medal} ${names[key]} ${time.toFixed(2).padStart(8)} ms  ${ops.padStart(10)} ops/s  +${slower}%`);
});

console.log('═══════════════════════════════════════════════════════════════════');

console.log('\n📊 АНАЛИЗ transpose4Chunks:');
console.log('   • Обрабатывает все 16 блоков за один вызов (batch)');
console.log('   • 64 итерации × 16 записей = 1024 слова');
console.log('   • Фиксированные смещения 256/512/768 (hardcoded для 1KB чанков)');
console.log('   • Меньше вызовов функций = меньше overhead');
