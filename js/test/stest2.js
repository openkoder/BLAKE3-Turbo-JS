// --- Реализация 1: Через таблицу и хеш ---
const CTZ_TABLE = new Uint8Array([
  0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
  31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
]);

function ctz32_table(n) {
  if (n === 0) return 32;
  return CTZ_TABLE[(((n & -n) * 0x077cb531) >>> 27) & 31];
}

// --- Реализация 2: Через Math.clz32 ---
function ctz32_clz(n) {
  if (n === 0) return 32;
  return Math.clz32(n & -n) ^ 31;
}

// --- Генерация тестовых данных ---
function generateTestData(count) {
  const data = new Uint32Array(count);
  for (let i = 0; i < count; i++) {
    // Генерируем случайные 32-битные числа, включая нули
    data[i] = Math.floor(Math.random() * 0xFFFFFFFF) | 0;
  }
  return data;
}

// --- Настройки теста ---
const ITERATIONS = 100_000_000; // 10 миллионов операций
const testData = generateTestData(ITERATIONS);

// --- Функция для прогрева и замера ---
function benchmark(fn, data, name) {
  // Прогрев (холодный запуск)
  for (let i = 0; i < 100000; i++) {
    fn(testData[i % testData.length]);
  }

  // Основное измерение
  const start = performance.now();
  let sum = 0; // Чтобы компилятор не удалил вызов как "мёртвый код"
  for (let i = 0; i < data.length; i++) {
    sum += fn(data[i]);
  }
  const end = performance.now();

  console.log(`${name}: ${(end - start).toFixed(2)} ms (checksum: ${sum})`);
  return end - start;
}

// --- Запуск теста ---
console.log(`Запуск теста: ${ITERATIONS.toLocaleString()} вызовов ctz32...\n`);

benchmark(ctz32_table, testData, "CTZ via Lookup Table");
benchmark(ctz32_clz,  testData, "CTZ via Math.clz32 XOR 31");
