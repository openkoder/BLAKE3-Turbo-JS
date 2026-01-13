// ============================================================================
// БЕНЧМАРК: Сравнение двух подходов записи IV в память
// ============================================================================

// Симуляция WASM памяти
const wasmMemoryU32 = new Uint32Array(256);
const stateBase = 64;

// IV массив
const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

// ============================================================================
// Вариант 1: Цикл с чтением из массива
// ============================================================================
function variant1_loop() {
  for (let i = 0, addr = stateBase + 32; i < 4; i++, addr += 4) {
    const v = IV[i];
    wasmMemoryU32[addr]     = v;
    wasmMemoryU32[addr + 1] = v;
    wasmMemoryU32[addr + 2] = v;
    wasmMemoryU32[addr + 3] = v;
  }
}

// ============================================================================
// Вариант 2: Хардкод констант (полностью развёрнутый)
// ============================================================================
function variant2_hardcode() {
  // state[8] = 0x6a09e667
  wasmMemoryU32[stateBase + 32]     = 0x6a09e667;
  wasmMemoryU32[stateBase + 32 + 1] = 0x6a09e667;
  wasmMemoryU32[stateBase + 32 + 2] = 0x6a09e667;
  wasmMemoryU32[stateBase + 32 + 3] = 0x6a09e667;
  
  // state[9] = 0xbb67ae85
  wasmMemoryU32[stateBase + 36]     = 0xbb67ae85;
  wasmMemoryU32[stateBase + 36 + 1] = 0xbb67ae85;
  wasmMemoryU32[stateBase + 36 + 2] = 0xbb67ae85;
  wasmMemoryU32[stateBase + 36 + 3] = 0xbb67ae85;
  
  // state[10] = 0x3c6ef372
  wasmMemoryU32[stateBase + 40]     = 0x3c6ef372;
  wasmMemoryU32[stateBase + 40 + 1] = 0x3c6ef372;
  wasmMemoryU32[stateBase + 40 + 2] = 0x3c6ef372;
  wasmMemoryU32[stateBase + 40 + 3] = 0x3c6ef372;
  
  // state[11] = 0xa54ff53a
  wasmMemoryU32[stateBase + 44]     = 0xa54ff53a;
  wasmMemoryU32[stateBase + 44 + 1] = 0xa54ff53a;
  wasmMemoryU32[stateBase + 44 + 2] = 0xa54ff53a;
  wasmMemoryU32[stateBase + 44 + 3] = 0xa54ff53a;
}

// ============================================================================
// Вариант 3: Хардкод с предвычисленными адресами
// ============================================================================
const ADDR_8  = stateBase + 32;
const ADDR_9  = stateBase + 36;
const ADDR_10 = stateBase + 40;
const ADDR_11 = stateBase + 44;

function variant3_hardcode_precomputed() {
  wasmMemoryU32[ADDR_8]     = 0x6a09e667;
  wasmMemoryU32[ADDR_8 + 1] = 0x6a09e667;
  wasmMemoryU32[ADDR_8 + 2] = 0x6a09e667;
  wasmMemoryU32[ADDR_8 + 3] = 0x6a09e667;
  
  wasmMemoryU32[ADDR_9]     = 0xbb67ae85;
  wasmMemoryU32[ADDR_9 + 1] = 0xbb67ae85;
  wasmMemoryU32[ADDR_9 + 2] = 0xbb67ae85;
  wasmMemoryU32[ADDR_9 + 3] = 0xbb67ae85;
  
  wasmMemoryU32[ADDR_10]     = 0x3c6ef372;
  wasmMemoryU32[ADDR_10 + 1] = 0x3c6ef372;
  wasmMemoryU32[ADDR_10 + 2] = 0x3c6ef372;
  wasmMemoryU32[ADDR_10 + 3] = 0x3c6ef372;
  
  wasmMemoryU32[ADDR_11]     = 0xa54ff53a;
  wasmMemoryU32[ADDR_11 + 1] = 0xa54ff53a;
  wasmMemoryU32[ADDR_11 + 2] = 0xa54ff53a;
  wasmMemoryU32[ADDR_11 + 3] = 0xa54ff53a;
}

// ============================================================================
// Вариант 4: Как в референсе (один цикл, 4 итерации)
// ============================================================================
function variant4_reference_style() {
  for (let i = 0; i < 4; ++i) {
    wasmMemoryU32[96 + i]  = 0x6a09e667;
    wasmMemoryU32[100 + i] = 0xbb67ae85;
    wasmMemoryU32[104 + i] = 0x3c6ef372;
    wasmMemoryU32[108 + i] = 0xa54ff53a;
  }
}

// ============================================================================
// БЕНЧМАРК
// ============================================================================

function benchmark(name, fn, iterations = 10_000_000) {
  // Прогрев JIT
  for (let i = 0; i < 10000; i++) fn();
  
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  const end = performance.now();
  
  const totalMs = end - start;
  const opsPerSec = (iterations / totalMs * 1000).toFixed(0);
  const nsPerOp = ((totalMs / iterations) * 1_000_000).toFixed(2);
  
  console.log(`${name.padEnd(35)} ${totalMs.toFixed(2).padStart(8)} ms | ${opsPerSec.padStart(12)} ops/s | ${nsPerOp.padStart(6)} ns/op`);
  
  return totalMs;
}

console.log('='.repeat(80));
console.log('Бенчмарк: Запись IV констант в WASM память');
console.log('Итераций: 10,000,000');
console.log('='.repeat(80));
console.log('');

const results = [];

results.push({ name: 'Цикл + IV[i]', time: benchmark('1. Цикл + IV[i]', variant1_loop) });
results.push({ name: 'Хардкод', time: benchmark('2. Хардкод', variant2_hardcode) });
results.push({ name: 'Хардкод + предвыч. адреса', time: benchmark('3. Хардкод + предвыч. адреса', variant3_hardcode_precomputed) });
results.push({ name: 'Референс стиль', time: benchmark('4. Референс стиль', variant4_reference_style) });

console.log('');
console.log('='.repeat(80));

// Найти лучший
results.sort((a, b) => a.time - b.time);
const best = results[0];
console.log(`\n🏆 Лучший: "${best.name}"`);
console.log('\nОтносительная скорость:');
for (const r of results) {
  const ratio = (r.time / best.time).toFixed(2);
  const bar = '█'.repeat(Math.round(r.time / best.time * 20));
  console.log(`  ${r.name.padEnd(30)} ${ratio}x ${bar}`);
}

// Проверка корректности
console.log('\n--- Проверка корректности ---');
variant1_loop();
const check1 = [wasmMemoryU32[96], wasmMemoryU32[100], wasmMemoryU32[104], wasmMemoryU32[108]];
variant4_reference_style();
const check2 = [wasmMemoryU32[96], wasmMemoryU32[100], wasmMemoryU32[104], wasmMemoryU32[108]];
console.log('Вариант 1:', check1.map(x => '0x' + x.toString(16)).join(', '));
console.log('Вариант 4:', check2.map(x => '0x' + x.toString(16)).join(', '));
console.log('Совпадают:', JSON.stringify(check1) === JSON.stringify(check2) ? '✅' : '❌');
