/**
 * ============================================================================
 * BLAKE3 - Naive JavaScript Implementation (Working v9)
 * ============================================================================
 * 
 * BLAKE3 - это криптографическая хэш-функция, разработанная в 2020 году.
 * Она объединяет лучшие качества BLAKE2 и Bao (параллельное дерево Меркла).
 * 
 * Основные характеристики:
 * - Размер блока: 64 байта
 * - Размер чанка: 1024 байта (16 блоков)
 * - Размер вывода: 32 байта (по умолчанию), но поддерживает XOF
 * - Количество раундов: 7 (вместо 10 в BLAKE2s)
 * 
 * Структура алгоритма:
 * 1. Входные данные разбиваются на чанки по 1024 байта
 * 2. Каждый чанк обрабатывается как цепочка из 16 блоков по 64 байта
 * 3. Результаты чанков объединяются в дерево Меркла
 * 4. Корень дерева даёт финальный хэш
 * 
 * Вход:  Uint8Array (любой длины)
 * Выход: Uint8Array (32 байта)
 */

/**
 * ============================================================================
 * BLAKE3 v9 — WASM SIMD (compress4x)
 * ============================================================================
 * 
 * Оптимизации в этой версии:
 * - v1: readLittleEndianWordsFull (без проверок границ)
 * - v2: Встроенные перестановки (без копирования массива, предвычисленный порядок доступа)
 * - v3: Инлайнинг round() в compress() + плоский массив перестановок
 * - v4: Состояние в памяти на регистрах процессора
 *       Замена Uint32Array на 16 локальных переменных (SMI)
 *       Полный инлайнинг G-функции с хардкодом индексов
 * - v5: Zero-copy — in-place запись в compress() в out[outOffset...], cvStack как Uint32Array
 * - v6: Блок сообщения в локальных переменных message_0...message_15
 *       Удаление таблицы PERMUTATIONS, физическая перестановка
 *       Результат: ускорение ~1.26x (с 9.3 мс до 7.4 мс на 1 МБ данных)
 * - v7: Переиспользование глобальных буферов (workBuffer, cvStack)
 *       Функция getCvStack() с grow-only кэшированием
 *       Устранение аллокаций при повторных вызовах blake3()
 * - v8: Little-Endian без копирования (Zero-Copy)
 *       Детекция порядка байтов: IsBigEndian = !new Uint8Array(new Uint32Array([1]).buffer)[0]
 *       Создание Uint32Array view на входной буфер (без копирования данных)
 *       compress() читает напрямую из inputWords вместо workBuffer
 *       Полное устранение readLittleEndianWordsFull для полных блоков
 *       Проверка выравнивания буфера (byteOffset % 4 === 0)
 *       Результат: ускорение ~1.33x (с 7.7 мс до 5.8 мс на 1 МБ данных)
 * - v9: WASM SIMD (compress4x)
 *       Эта версия генерирует WebAssembly модуль на лету и использует SIMD
 *       для параллельной обработки 4 чанков одновременно.
 * 
 *       Ключевые особенности:
 *       - Генерация WASM байткода в runtime (никаких внешних .wasm файлов)
 *       - compress4x: 4 параллельных compress через SIMD (i32x4)
 *       - Fallback на JavaScript для остатка и финализации
 *       - Константное использование памяти: 1 страница WASM (64 КБ)
 * 
 */

// =====================================================================
// 1. КОНСТАНТЫ
// =====================================================================

/**
 * Вектор инициализации (IV) - первые 32 бита дробной части 
 * квадратных корней первых 8 простых чисел: √2, √3, √5, √7, √11, √13, √17, √19
 * 
 * Эти же константы используются в SHA-256 и BLAKE2s.
 * Они выбраны как "nothing-up-my-sleeve numbers" - числа, которые
 * невозможно подобрать специально для создания backdoor.
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
 * Флаги домена - указывают тип обрабатываемого блока.
 * Используются для domain separation (разделения доменов),
 * чтобы одинаковые данные в разных контекстах давали разные хэши.
 */
const CHUNK_START = 1;   // 0b0001 - первый блок в чанке
const CHUNK_END = 2;     // 0b0010 - последний блок в чанке
const PARENT = 4;        // 0b0100 - родительский узел в дереве Меркла
const ROOT = 8;          // 0b1000 - корневой узел (финальный хэш)
// Также существуют: KEYED_HASH = 16, DERIVE_KEY_CONTEXT = 32, DERIVE_KEY_MATERIAL = 64

/**
 * Размер блока в байтах.
 * BLAKE3 обрабатывает данные блоками по 64 байта = 16 слов по 4 байта.
 */
const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;


// ============================================================================
// 2. ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// создаются один раз при загрузке модуля
// никаких аллокаций в функции blake3() и горячем цикле
// ============================================================================

// Детекция порядка байтов (выполняется один раз при загрузке модуля)
const IsBigEndian = !new Uint8Array(new Uint32Array([1]).buffer)[0];

// Храним количество чанков (минимум 1)
   let numChunks = 1;


// Буфер для текущего CV (8 слов) и блока сообщения (16 слов)
// Объединяем в один массив для лучшей локальности
const globalWorkBuffer = new Uint32Array(8 + 16);  // cv[0..7] + block[0..15]

// Кэшированный стек CV — растёт при необходимости, но никогда не уменьшается
let globalCvStack = null;


// =====================================================================
// 3. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =====================================================================

/**
 * Count trailing zeros (CTZ) — количество нулевых бит справа для 32-битного числа.
 * Используется для определения количества merge операций в дереве Меркла.
 * 
 * Примеры:
 *   ctz32(1)  = 0   (0b0001)
 *   ctz32(2)  = 1   (0b0010)
 *   ctz32(4)  = 2   (0b0100)
 *   ctz32(8)  = 3   (0b1000)
 *   ctz32(12) = 2   (0b1100)
 * 
 * @param {number} n - 32-битное целое
 * @returns {number} - количество trailing zeros (0-32)
 */

const CTZ_TABLE = new Uint8Array([
  0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
  31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
]);

function ctz32(n) {
  if (n === 0) return 32;
  return CTZ_TABLE[(((n & -n) * 0x077CB531) >>> 27)];
}

/**
 * Count trailing zeros для BigInt (64-бит и более).
 * Для файлов > 4 ТБ (когда chunkCounter > 2^32).
 * 
 * @param {bigint} n - 64-битное целое
 * @returns {number} - количество trailing zeros (0-64)
 */
function ctz64(n) {
  if (n === 0n) return 64;
  
  // Оптимизация: проверяем младшие 32 бита сначала
  const lo = Number(n & 0xFFFFFFFFn);
  if (lo !== 0) return ctz32(lo);
  
  // Младшие 32 бита — нули, проверяем старшие
  //const hi = Number((n >> 32n) & 0xFFFFFFFFn);
  return 32 + ctz32(Number((n >> 32n) & 0xFFFFFFFFn));
}

// ============================================================================
// 3. ГЕНЕРАТОР WASM МОДУЛЯ
// ============================================================================

/**
 * Таблица перестановок сообщения для 7 раундов BLAKE3.
 * Каждый раунд переставляет слова сообщения по фиксированной схеме.
 */
const MSG_PERMUTATION = [
  2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
];

/**
 * Предвычисленный порядок доступа к словам сообщения для всех 7 раундов.
 * Для каждого раунда: 16 индексов (8 пар для 8 вызовов G).
 */
function computeMessageSchedule() {
  const schedule = [];
  let perm = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
  
  for (let round = 0; round < 7; round++) {
    // Столбцы: G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
    schedule.push(perm[0], perm[1]);  // G0
    schedule.push(perm[2], perm[3]);  // G1
    schedule.push(perm[4], perm[5]);  // G2
    schedule.push(perm[6], perm[7]);  // G3
    // Диагонали: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
    schedule.push(perm[8], perm[9]);   // G4
    schedule.push(perm[10], perm[11]); // G5
    schedule.push(perm[12], perm[13]); // G6
    schedule.push(perm[14], perm[15]); // G7
    
    // Применяем перестановку для следующего раунда
    if (round < 6) {
      perm = perm.map((_, i) => perm[MSG_PERMUTATION[i]]);
    }
  }
  
  return schedule;
}

const MESSAGE_SCHEDULE = computeMessageSchedule();

/**
 * Кодирует число в формат LEB128 (Little Endian Base 128).
 * Это формат переменной длины, используемый в WASM.
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
 * Генерирует WASM модуль с функцией compress4x.
 * 
 * compress4x выполняет 4 параллельных compress через SIMD.
 * Без параметров — работает с фиксированными адресами памяти.
 * 
 * Layout памяти:
 *   0x000-0x0FF: blockWords[0..15] — 16 × v128 (256 байт)
 *   0x100-0x1FF: CV input [0..7] × 4 — 8 × v128 (128 байт)  
 *   0x180-0x1FF: counter_lo, counter_hi, blockLen, flags × 4
 *   0x200-0x2FF: state output [0..7] × 4 — 8 × v128 (128 байт)
 */
function generateWasmModule() {
  const code = [];
  
  // ═══════════════════════════════════════════════════════════════════════
  // ЗАГОЛОВОК WASM
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
  // SECTION 2: Imports (память от хоста)
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
  
  // Начинаем секцию кода
  const codeSectionStart = code.length;
  code.push(0x0a);  // Section ID
  
  // Резервируем место для размера секции (5 байт LEB128)
  const sectionSizePos = code.length;
  code.push(0x00, 0x00, 0x00, 0x00, 0x00);
  
  code.push(0x01);  // 1 function
  
  // Резервируем место для размера функции
  const funcSizePos = code.length;
  code.push(0x00, 0x00, 0x00, 0x00, 0x00);
  
  const funcStart = code.length;
  
  // Локальные переменные: 32 × v128
  // (16 для blockWords + 16 для state)
  code.push(
    0x01,       // 1 группа локальных переменных
    0x20,       // 32 переменные
    0x7b        // тип v128
  );
  
  // ─────────────────────────────────────────────────────────────────────────
  // Загрузка blockWords из памяти в локальные переменные $0..$15
  // ─────────────────────────────────────────────────────────────────────────
  for (let i = 0; i < 16; i++) {
    code.push(
      0x41, ...toLebU32(i * 16),  // i32.const [address]
      0xfd, 0x00, 0x04, 0x00,     // v128.load align=4
      0x21, i                      // local.set $i
    );
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Инициализация state ($16..$31)
  // CV загружается из памяти (адреса 0x100-0x17F)
  // ─────────────────────────────────────────────────────────────────────────
  
  // state[0..7] = CV[0..7] из памяти
  for (let i = 0; i < 8; i++) {
    code.push(
      0x41, ...toLebU32(0x100 + i * 16),  // i32.const [address]
      0xfd, 0x00, 0x04, 0x00,              // v128.load
      0x21, 16 + i                          // local.set $[16+i]
    );
  }
  
  // state[8..11] = IV[0..3] (константы, нужно создать)
  // Создаём v128 из 4 одинаковых i32
  const ivValues = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
  for (let i = 0; i < 4; i++) {
    // v128.const с 4 одинаковыми значениями IV[i]
    code.push(0xfd, 0x0c);  // v128.const
    // 16 байт little-endian (4 копии IV[i])
    for (let j = 0; j < 4; j++) {
      const v = ivValues[i];
      code.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff);
    }
    code.push(0x21, 24 + i);  // local.set $[24+i]
  }
  
  // state[12..15] = counter_lo, counter_hi, blockLen, flags
  // Загружаем из памяти (адреса 0x180-0x1BF)
  for (let i = 0; i < 4; i++) {
    code.push(
      0x41, ...toLebU32(0x180 + i * 16),
      0xfd, 0x00, 0x04, 0x00,
      0x21, 28 + i
    );
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // 7 раундов
  // ─────────────────────────────────────────────────────────────────────────
  let msgIdx = 0;
  
  for (let round = 0; round < 7; round++) {
    // 8 вызовов G (4 столбца + 4 диагонали)
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
      
      // Генерируем G-функцию
      emitG(code, a, b, c, d, mx, my);
    }
  }
  
  // ─────────────────────────────────────────────────────────────────────────
  // Финализация: state[i] ^= state[i+8], записываем в память
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
  // Заполняем размеры
  // ─────────────────────────────────────────────────────────────────────────
  const funcSize = code.length - funcStart;
  const funcSizeBytes = toLebU32(funcSize);
  // Дополняем до 5 байт
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
 * Генерирует код G-функции для SIMD.
 * 
 * G(a, b, c, d, mx, my):
 *   a = a + b + message[mx]; d = rotr(d ^ a, 16); c = c + d; b = rotr(b ^ c, 12);
 *   a = a + b + message[my]; d = rotr(d ^ a, 8);  c = c + d; b = rotr(b ^ c, 7);
 */
function emitG(code, a, b, c, d, mx, my) {
  // Первая половина G (rotation 16, 12)
  emitGHalf(code, a, b, c, d, mx, 16, 12);
  // Вторая половина G (rotation 8, 7)
  emitGHalf(code, a, b, c, d, my, 8, 7);
}

/**
 * Генерирует половину G-функции с оптимизированной ротацией.
 * 
 * Для ROTR16 и ROTR8 используем i8x16.shuffle (1 инструкция)
 * вместо shift+or (5 инструкций).
 */
const ROTR16_SHUFFLE = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];
const ROTR8_SHUFFLE  = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

function emitGHalf(code, a, b, c, d, message, rotD, rotB) {
  // a = a + b + message
  code.push(
    0x20, a,            // local.get $a
    0x20, b,            // local.get $b
    0xfd, 0xae, 0x01,   // i32x4.add
    0x20, message,      // local.get $message
    0xfd, 0xae, 0x01,   // i32x4.add
    0x22, a             // local.tee $a
  );
  
  // d = rotr(d ^ a, rotD)
  code.push(
    0x20, d,            // local.get $d
    0xfd, 0x51,         // v128.xor
    0x22, d             // local.tee $d
  );
  
  if (rotD === 16) {
    // ═══════════════════════════════════════════════════════════════
    // ОПТИМИЗАЦИЯ: i8x16.shuffle вместо shift+or для ROTR16
    // ═══════════════════════════════════════════════════════════════
    code.push(
      0x20, d,          // local.get $d
      0xfd, 0x0d,       // i8x16.shuffle
      ...ROTR16_SHUFFLE,
      0x22, d           // local.tee $d
    );
  } else if (rotD === 8) {
    // ═══════════════════════════════════════════════════════════════
    // ОПТИМИЗАЦИЯ: i8x16.shuffle вместо shift+or для ROTR8
    // ═══════════════════════════════════════════════════════════════
    code.push(
      0x20, d,          // local.get $d
      0xfd, 0x0d,       // i8x16.shuffle
      ...ROTR8_SHUFFLE,
      0x22, d           // local.tee $d
    );
  } else {
    // Fallback для других ротаций (12, 7) - остаётся shift+or
    code.push(
      0x41, rotD,         // i32.const rotD
      0xfd, 0xad, 0x01,   // i32x4.shr_u
      0x20, d,            // local.get $d
      0x41, 32 - rotD,    // i32.const (32 - rotD)
      0xfd, 0xab, 0x01,   // i32x4.shl
      0xfd, 0x50,         // v128.or
      0x22, d             // local.tee $d
    );
  }
  
  // c = c + d
  code.push(
    0x20, c,            // local.get $c
    0xfd, 0xae, 0x01,   // i32x4.add
    0x22, c             // local.tee $c
  );
  
  // b = rotr(b ^ c, rotB) — всегда 12 или 7, используем shift+or
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
// ИНИЦИАЛИЗАЦИЯ WASM
// ============================================================================

let wasmMemory = null;
let wasmCompress4x = null;
let wasmMemoryView = null;
let wasmMemoryU32 = null;
let wasmSupported = false;

/**
 * Инициализация WASM модуля.
 * Вызывается один раз при загрузке.
 */
async function initWasm() {
  try {
    // Проверяем поддержку WASM SIMD
    const simdTest = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b,
      0x03, 0x02, 0x01, 0x00,
      0x0a, 0x0a, 0x01, 0x08, 0x00, 0x41, 0x00, 0xfd, 0x0c,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b
    ]);
    
    await WebAssembly.compile(simdTest);
    
    // Генерируем наш модуль
    const wasmBytes = generateWasmModule();
    
    // Создаём память
    wasmMemory = new WebAssembly.Memory({ initial: 1 });
    wasmMemoryView = new Uint8Array(wasmMemory.buffer);
    wasmMemoryU32 = new Uint32Array(wasmMemory.buffer);
    
    // Компилируем и инстанцируем
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

// Синхронная инициализация (для модульных систем)
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

// Пытаемся инициализировать синхронно
initWasmSync();

// ============================================================================
// ФУНКЦИИ РАБОТЫ С WASM ПАМЯТЬЮ
// ============================================================================

 /**
 * Оптимизированная запись транспонированного блока в WASM память.
 * Записывает транспонированные блоки в WASM память.
 * 
 * 4 чанка × 16 блоков = 64 блока всего, но compress4x обрабатывает
 * 4 блока за раз (по одному от каждого чанка параллельно через SIMD).
 * 
 * Использует блочное копирование через Uint32Array views вместо
 * побайтового чтения, что значительно снижает накладные расходы.
 * 
 * Layout в WASM памяти (для одного блока):
 *   Адрес 0x000: [word0_chunk0, word0_chunk1, word0_chunk2, word0_chunk3]  ← v128 для message[0]
 *   Адрес 0x010: [word1_chunk0, word1_chunk1, word1_chunk2, word1_chunk3]  ← v128 для message[1]
 *   ...
 *   Адрес 0x0F0: [word15_chunk0, word15_chunk1, word15_chunk2, word15_chunk3] ← v128 для message[15]
 * 
 * Для блока #i: 
 * blockWords[j] = [chunk0[i*16+j], chunk1[i*16+j], chunk2[i*16+j], chunk3[i*16+j]]
 * 
 * @param {Uint8Array} input - входные данные
 * @param {number[]} offsets - массив из 4 смещений (начала 4 чанков)
 * @param {number} blockIndex - номер блока внутри чанка (0..15)
 */
 let viewInputU32 = null; // для просмотра массива input
 
function writeTransposedBlockFast(input, offsets, blockIndex) {
  // offsets = [offset0, offset1, offset2, offset3] — начала 4 чанков
  // blockIndex = 0..15 — номер блока внутри чанка
  
  // Кэшируем для многократного использования
  const inputByteOffset = input.byteOffset;
  
  // const blockOffset = blockIndex * BLOCK_LEN;
  const blockOffset = blockIndex << 6; // blockIndex * 64 (BLOCK_LEN)
  
  
  // ═══════════════════════════════════════════════════════════════════════
  // Попытка создать Uint32Array views для всех 4 чанков
  // Это работает только если данные выровнены по 4 байта
  // ═══════════════════════════════════════════════════════════════════════
  
  const byteOffset0 = inputByteOffset + offsets[0] + blockOffset;
  const byteOffset1 = inputByteOffset + offsets[1] + blockOffset;
  const byteOffset2 = inputByteOffset + offsets[2] + blockOffset;
  const byteOffset3 = inputByteOffset + offsets[3] + blockOffset;
  
  // Проверяем выравнивание всех 4 смещений
  /*const allAligned = 
    (input.byteOffset + byteOffsets[0]) % 4 === 0 &&
    (input.byteOffset + byteOffsets[1]) % 4 === 0 &&
    (input.byteOffset + byteOffsets[2]) % 4 === 0 &&
    (input.byteOffset + byteOffsets[3]) % 4 === 0;*/
  const allAligned = ((byteOffset0 | byteOffset1 | byteOffset2 | byteOffset3) & 3) === 0;

  
  if (allAligned && !IsBigEndian) {
    // ═══════════════════════════════════════════════════════════════════
    // БЫСТРЫЙ ПУТЬ: прямое чтение через Uint32Array views
    // ═══════════════════════════════════════════════════════════════════
    
    // Кэшируем view (одна переменная!)
    if (viewInputU32 === null || viewInputU32.buffer !== input.buffer) {
      viewInputU32 = new Uint32Array(input.buffer);
    }
    
    // Вычисляем базовые индексы в Uint32Array (байты → слова)
    const baseIndex0 = byteOffset0 >> 2;  // смещение в байтах делим на 4
    const baseIndex1 = byteOffset1 >> 2;  // получаем индекс в массиве Uint32
    const baseIndex2 = byteOffset2 >> 2;
    const baseIndex3 = byteOffset3 >> 2;
    
    // Транспонируем: для каждого слова message[i] собираем значения из 4 чанков
    for (let word = 0; word < 16; word++) {
      //const memIdx = word * 4;  // 4 слова (i32) на каждый v128
      const memIdx = word << 2;  // 4 слова (i32) на каждый v128
      wasmMemoryU32[memIdx + 0] = viewInputU32[baseIndex0 + word];
      wasmMemoryU32[memIdx + 1] = viewInputU32[baseIndex1 + word];
      wasmMemoryU32[memIdx + 2] = viewInputU32[baseIndex2 + word];
      wasmMemoryU32[memIdx + 3] = viewInputU32[baseIndex3 + word];
    }
  } else {
    // ═══════════════════════════════════════════════════════════════════
    // МЕДЛЕННЫЙ ПУТЬ: побайтовое чтение
    // Используется для невыровненных данных или Big-Endian систем
    // ═══════════════════════════════════════════════════════════════════
    
    // Предвычисляем базовые смещения ДО цикла (выносим из 16 итераций)
    // аналог byteOffsets[]
    // Используем локальные переменные, чтобы V8 держал их в регистрах
    let offsetWord0 = offsets[0] + blockOffset;
    let offsetWord1 = offsets[1] + blockOffset;
    let offsetWord2 = offsets[2] + blockOffset;
    let offsetWord3 = offsets[3] + blockOffset;
    
    for (let word = 0; word < 16; word++) {
      // Адрес в WASM памяти 4 слова на v128
      const memIdx = word << 2;  // word * 4 = word << 2 — переиспользуем
      
      /* разворачиваем цикл 
      for (let chunk = 0; chunk < 4; chunk++) {
        const inputOffset = offsets[chunk] + blockOffset + word * 4;
        
        // Читаем 4 байта как little-endian 32-битное слово
        const w = input[inputOffset] |
                  (input[inputOffset + 1] << 8) |
                  (input[inputOffset + 2] << 16) |
                  (input[inputOffset + 3] << 24);
        
        // Записываем в соответствующую позицию v128
        wasmMemoryU32[memIdx + chunk] = w;
      }
      */
      
      // Chunk 0
      // Читаем 4 байта как little-endian 32-битное слово  
      // Записываем в соответствующую позицию v128
      wasmMemoryU32[memIdx] = input[offsetWord0] |
                (input[offsetWord0 + 1] << 8) |
                (input[offsetWord0 + 2] << 16) |
                (input[offsetWord0 + 3] << 24);
      
      // Chunk 1
      // Читаем 4 байта как little-endian 32-битное слово
      // Записываем в соответствующую позицию v128
      wasmMemoryU32[memIdx + 1] = input[offsetWord1] |
                (input[offsetWord1 + 1] << 8) |
                (input[offsetWord1 + 2] << 16) |
                (input[offsetWord1 + 3] << 24);
      
      // Chunk 2
      // Читаем 4 байта как little-endian 32-битное слово
      // Записываем в соответствующую позицию v128
      wasmMemoryU32[memIdx + 2] = input[offsetWord2] |
                (input[offsetWord2 + 1] << 8) |
                (input[offsetWord2 + 2] << 16) |
                (input[offsetWord2 + 3] << 24);
      
      // Chunk 3
      // Читаем 4 байта как little-endian 32-битное слово
      // Записываем в соответствующую позицию v128
      wasmMemoryU32[memIdx + 3] = input[offsetWord3] |
                (input[offsetWord3 + 1] << 8) |
                (input[offsetWord3 + 2] << 16) |
                (input[offsetWord3 + 3] << 24);
                
      // Сдвигаем указатели.
      offsetWord0 += 4;
      offsetWord1 += 4;
      offsetWord2 += 4;
      offsetWord3 += 4;
    }
  }
}

/**
 * Записывает CV и параметры для 4 параллельных compress.
 */
function writeCVAndParams(cvs, counters, blockLen, flags) {
  // cvs = [[cv0], [cv1], [cv2], [cv3]] — 4 массива по 8 слов
  // counters = [counter0, counter1, counter2, counter3]
  
  // CV: адреса 0x100-0x17F (8 × v128)
  for (let i = 0; i < 8; i++) {
    const memAddr = 0x100 + i * 16;
    for (let chunk = 0; chunk < 4; chunk++) {
      wasmMemoryU32[(memAddr >> 2) + chunk] = cvs[chunk][i];
    }
  }
  
  // counter_lo: адрес 0x180
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x180 >> 2) + chunk] = counters[chunk] | 0;
  }
  
  // counter_hi: адрес 0x190
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x190 >> 2) + chunk] = (counters[chunk] / 0x100000000) | 0;
  }
  
  // blockLen: адрес 0x1A0
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x1A0 >> 2) + chunk] = blockLen;
  }
  
  // flags: адрес 0x1B0
  for (let chunk = 0; chunk < 4; chunk++) {
    wasmMemoryU32[(0x1B0 >> 2) + chunk] = flags[chunk];
  }
}

/**
 * Читает результаты compress4x из WASM памяти.
 */
function readResults(cvs) {
  // Результаты в адресах 0x200-0x27F (8 × v128)
  for (let i = 0; i < 8; i++) {
    const memAddr = 0x200 + i * 16;
    for (let chunk = 0; chunk < 4; chunk++) {
      cvs[chunk][i] = wasmMemoryU32[(memAddr >> 2) + chunk];
    }
  }
}


/**
 * Получить стек CV нужного размера.
 * Переиспользует существующий, если он достаточно большой.
 * 
 * @param {number} inputLength - длинна входа для подсчета глубины дерева
 * @returns {Uint32Array} - Стек достаточного размера
 */
function getCvStack(inputLength) {
  // Количество чанков (минимум 1)
  numChunks = Math.ceil(inputLength / CHUNK_LEN) || 1;
  
  // Максимальная глубина дерева через CLZ (быстрее чем Math.log2):
  // 32 - clz32(n) = floor(log2(n)) + 1 для n > 0
  // +1 для запаса на неполное дерево
  const maxDepth = (32 - Math.clz32(numChunks)) + 1;
  
  // Минимум 54 уровней — покрывает файлы длинной до 2^54 чанков
  // 2^54 Kb - — это 2^24 терабайта (ТБ), или примерно 16.78 миллионов терабайт
  const depth = Math.max(maxDepth, 54);
  //const length = depth * 8;  // 8 слов (32 байта) на каждый CV
  const length = depth << 3;  // 8 слов (32 байта) на каждый CV
  
  if (globalCvStack === null || globalCvStack.length < length) {
    // Создаём новый только если старый слишком мал
    globalCvStack = new Uint32Array(length);
  }
  
  return globalCvStack;
}


// Буферы для SIMD версии
const simdCVs = [
  new Uint32Array(8),
  new Uint32Array(8),
  new Uint32Array(8),
  new Uint32Array(8)
];


// ============================================================================
// ФУНКЦИЯ СЖАТИЯ
// ============================================================================

/**
 * Функция сжатия - основная криптографическая операция BLAKE3.
 * 
 * Функция сжатия BLAKE3 с in-place записью результата и 
 * с хранением состояния в регистрах.
 * 
 * Вместо использования Uint32Array для состояния (что требует обращения к памяти),
 * мы используем 16 локальных переменных s_0...s_15, которые JIT-компилятор
 * может разместить непосредственно в регистрах процессора.
 * 
 * Это устраняет:
 * - 448 записей в массив за один вызов compress()
 * - 1008 чтений из массива за один вызов compress()
 * - Накладные расходы на проверку границ
 * - Косвенную адресацию памяти
 * 
 * G-функция полностью встроена с захардкоженными индексами.
 * Код сгенерирован с помощью метапрограммирования (см. генератор в комментариях).
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * СТРУКТУРА НАЧАЛЬНОГО СОСТОЯНИЯ (16 слов = 512 бит)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │  s_0    s_1    s_2    s_3   ← цепное значение [0..3]                │
 *   │  s_4    s_5    s_6    s_7   ← цепное значение [4..7]                │
 *   │  s_8    s_9    s_10   s_11  ← константы IV (корни простых чисел)    │
 *   │  s_12   s_13   s_14   s_15  ← счётчик_мл, счётчик_ст, длина, флаги  │
 *   └─────────────────────────────────────────────────────────────────────┘
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * СТРУКТУРА РАУНДА (всего 7 раундов)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Каждый раунд применяет G-функцию ко всем 16 словам состояния в две фазы:
 * 
 * Фаза 1 - СТОЛБЦЫ:           Фаза 2 - ДИАГОНАЛИ:
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
 * Всего операций: 7 раундов × 8 вызовов G × 12 операций = 672 операции
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * G-ФУНКЦИЯ (ARX - сложение-вращение-XOR)
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   a ← a + b + mx        a ← a + b + my
 *   d ← (d ⊕ a) >>> 16    d ← (d ⊕ a) >>> 8
 *   c ← c + d             c ← c + d
 *   b ← (b ⊕ c) >>> 12    b ← (b ⊕ c) >>> 7
 * 
 * Константы вращения (16, 12, 8, 7) оптимизированы для 32-битной диффузии.
 * 
 * ═══════════════════════════════════════════════════════════════════════════
 * ФИНАЛИЗАЦИЯ
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 *   выход[0..7]  = младшая_часть ⊕ старшая_часть  (прямая связь для цепочки)
 *   выход[8..15] = старшая_часть ⊕ cv             (для расширенного вывода XOF)
 * 
 * @param {Uint32Array} cv        - Цепное значение chaining value (8 × 32-битных слов)
 * @param {number}      cvOffset  - Смещение CV в массиве
 * @param {Uint32Array} message         - Блок сообщения (16 × 32-битных слов)
 * @param {number}      messageOffset   - Смещение блока в массиве
 * @param {Uint32Array} out       - Массив для записи результата
 * @param {number}      outOffset - Смещение для записи результата
 * @param {boolean}     truncate  - true = записать только 8 слов (CV)
 *                                  false = записать все 16 слов (XOF)
 * @param {number}      counter   - 64-битный счётчик блоков (как число JS)
 * @param {number}      blockLen  - Длина блока в байтах (0-64)
 * @param {number}      flags     - Флаги разделения доменов
 * @returns {Uint32Array}         - 512-битный выход (16 × 32-битных слов)
 */
function compress(
  cv, cvOffset,
  message, messageOffset,
  out, outOffset,
  truncate,
  counter, blockLen, flags
) {
  // ═══════════════════════════════════════════════════════════════════════
  // Инициализация состояния - 16 локальных переменных вместо Uint32Array
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
  let s_12 = counter | 0;                   // Младшие 32 бита счётчика
  let s_13 = (counter / 0x100000000) | 0;   // Старшие 32 бита счётчика
  let s_14 = blockLen | 0;
  let s_15 = flags | 0;
  
  // ═══════════════════════════════════════════════════════════════════════
  // Инициализация сообщения message_ - 16 локальных переменных вместо Uint32Array
  // НОВОЕ: Блок сообщения тоже в локальных переменных!
  // ═══════════════════════════════════════════════════════════════════════
  let message_0 = message[messageOffset + 0] | 0;
  let message_1 = message[messageOffset + 1] | 0;
  let message_2 = message[messageOffset + 2] | 0;
  let message_3 = message[messageOffset + 3] | 0;
  let message_4 = message[messageOffset + 4] | 0;
  let message_5 = message[messageOffset + 5] | 0;
  let message_6 = message[messageOffset + 6] | 0;
  let message_7 = message[messageOffset + 7] | 0;
  let message_8 = message[messageOffset + 8] | 0;
  let message_9 = message[messageOffset + 9] | 0;
  let message_10 = message[messageOffset + 10] | 0;
  let message_11 = message[messageOffset + 11] | 0;
  let message_12 = message[messageOffset + 12] | 0;
  let message_13 = message[messageOffset + 13] | 0;
  let message_14 = message[messageOffset + 14] | 0;
  let message_15 = message[messageOffset + 15] | 0;

  // ═══════════════════════════════════════════════════════════════════════
  // 🚀 ИНЛАЙНИНГ ФУНКЦИИ round(): 7 раундов в одном цикле
  // ═══════════════════════════════════════════════════════════════════════
  // 
  // Раунд применяет G-функцию ко всем 16 словам состояния.
  // Состояние представлено как матрица 4×4:
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
  // Каждый раунд состоит из двух фаз:
  // 
  // 1. СТОЛБЦЫ - G применяется к каждому столбцу:
  //    G(0,4,8,12)  G(1,5,9,13)  G(2,6,10,14)  G(3,7,11,15)
  // 
  // 2. ДИАГОНАЛИ - G применяется к диагоналям:
  //    G(0,5,10,15) G(1,6,11,12) G(2,7,8,13)   G(3,4,9,14)
  // 
  // ───────────────────────────────────────────────────────────────────────
  // ОПТИМИЗАЦИЯ v3: Инлайнинг + плоский массив перестановок
  // ───────────────────────────────────────────────────────────────────────
  // 
  // Вместо 7 вызовов функции round():
  //   round(state, blockWords, ROUND_PERMUTATIONS[0]);
  //   round(state, blockWords, ROUND_PERMUTATIONS[1]);
  //   ... (7 вызовов)
  // 
  // Мы используем один цикл с бегущим указателем p в плоском
  // массиве PERMUTATIONS. Это позволяет избежать:
  // - Накладных расходов на 7 вызовов функции round()
  // - 2D-индексации ROUND_PERMUTATIONS[round][index]
  // - Копирования блока сообщения (без `new Uint32Array(message)`)
  // - Вызова permute() после каждого раунда (без перемещения данных)
  // 
  // Экономия на один вызов compress():
  // - 7 выделений стекового фрейма
  // - 7 × 16 = 112 операций индексации в 2D-массиве
  // - Улучшенная локальность кэша благодаря линейному доступу к PERMUTATIONS
  // 
  // BLAKE2 имеет 10 раундов, BLAKE3 оптимизирован до 7 для скорости.
  // ═══════════════════════════════════════════════════════════════════════
  
  // Используем один цикл с бегущим указателем:
  for (let round = 0; round < 7; ++round) {
    // ─────────────────────────────────────────────────────────────
    // Фаза 1: Перемешивание по столбцам
    // G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
    // ─────────────────────────────────────────────────────────────
    // G применяется вертикально к каждому из 4 столбцов.
    //
    // Слова сообщения доступны через message[PERMUTATIONS[p++]], где p
    // автоматически продвигается по плоскому массиву перестановок.

    // G(0, 4, 8, 12) с message_0, message_1
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

    // G(1, 5, 9, 13) с message_2, message_3
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

    // G(2, 6, 10, 14) с message_4, message_5
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

    // G(3, 7, 11, 15) с message_6, message_7
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
    // Фаза 2: Перемешивание по диагоналям
    // G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
    // ─────────────────────────────────────────────────────────────
    // G применяется вдоль диагоналей с переносом.
    //
    
    // G(0, 5, 10, 15) с message_8, message_9
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

    // G(1, 6, 11, 12) с message_10, message_11
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

    // G(2, 7, 8, 13) с message_12, message_13
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

    // G(3, 4, 9, 14) с message_14, message_15
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
    // Перестановка (кроме последнего раунда)
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
  // Финализация 
  // XOR верхней и нижней половин состояния
  //
  // Это "сжимает" 512 бит до 256 бит и добавляет прямую связь
  // Запись в out вместо return
  //
  // Порядок записи КРИТИЧЕН для in-place корректности!
  // Если out === cv и outOffset === cvOffset, то запись в out[0]
  // уничтожит cv[0] до того, как мы его прочитаем для out[8].
  // Поэтому сначала пишем старшую половину (8-15), потом младшую (0-7).
  // ═══════════════════════════════════════════════════════════════════════
  if (!truncate) {
    // Расширенный вывод (XOF) — нужны все 16 слов
    out[outOffset + 8] = s_8 ^ cv[cvOffset + 0];
    out[outOffset + 9] = s_9 ^ cv[cvOffset + 1];
    out[outOffset + 10] = s_10 ^ cv[cvOffset + 2];
    out[outOffset + 11] = s_11 ^ cv[cvOffset + 3];
    out[outOffset + 12] = s_12 ^ cv[cvOffset + 4];
    out[outOffset + 13] = s_13 ^ cv[cvOffset + 5];
    out[outOffset + 14] = s_14 ^ cv[cvOffset + 6];
    out[outOffset + 15] = s_15 ^ cv[cvOffset + 7];
  }
  
  // Младшая половина — chaining value для следующего блока
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
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

/**
 * Читает байты как little-endian 32-битные слова.
 * 
 * Little-endian означает, что младший байт идёт первым.
 * Пример: байты [0x78, 0x56, 0x34, 0x12] → слово 0x12345678
 */
 
 /**
 * Быстрое чтение полного блока (64 байта) без проверок границ.
 * 
 * @param {Uint8Array}  array       - входной массив байтов
 * @param {number}      offset      - начальная позиция чтения
 * @param {Uint32Array} words       - выходной массив слов
 * @param {number}      wordsOffset - позиция записи в выходном массиве
 */
// ═══════════════════════════════════════════════════════════════════════════
// ✅ ОПТИМИЗАЦИЯ: Две версии функции чтения
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Быстрое чтение полного блока (64 байта).
 * Без проверок границ - для 99% вызовов.
 */
function readLittleEndianWordsFull(array, offset, words, wordsOffset) {
  for (let i = 0; i < 16; ++i, offset += 4) {
    words[wordsOffset + i] = // Теперь пишем с учётом смещения
      array[offset] |
      (array[offset + 1] << 8) |
      (array[offset + 2] << 16) |
      (array[offset + 3] << 24);
  }
}

/**
 * Чтение неполного блока с padding.
 * Только для последнего блока данных.
 */
 /**
 * Функция обрабатывает неполные блоки с дополнением нулями (padding).
 * Используется только для последнего блока данных.
 * 
 * @param {Uint8Array}  array       - входной массив байтов
 * @param {number}      offset      - начальная позиция чтения
 * @param {number}      length      - общая длина данных (для определения границы)
 * @param {Uint32Array} words       - выходной массив слов
 * @param {number}      wordsOffset - позиция записи в выходном массиве
 */
function readLittleEndianWordsPartial(array, offset, length, words, wordsOffset) {
  // Заполняем нулями
  for (let i = 0; i < 16; ++i) {
    words[wordsOffset + i] = 0;
  }
  
  let i = 0;
  // Полные 4-байтные слова
  for (; offset + 3 < length && i < 16; ++i, offset += 4) {
    words[wordsOffset + i] =
      array[offset] |
      (array[offset + 1] << 8) |
      (array[offset + 2] << 16) |
      (array[offset + 3] << 24);
  }
  
  // Оставшиеся байты
  for (let s = 0; offset < length; s += 8, ++offset) {
    words[wordsOffset + i] |= array[offset] << s;
  }
}


// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ С SIMD
// ============================================================================

/**
 * Обрабатывает 4 чанка параллельно через WASM SIMD.
 * 
 * @param {Uint8Array} input - входные данные
 * @param {number} baseOffset - начальное смещение
 * @param {number} baseChunkCounter - начальный счётчик чанков
 * @returns {Array} - 4 CV (каждый — Uint32Array[8])
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
  
  // Инициализируем CV = IV для всех 4 чанков
  for (let c = 0; c < 4; c++) {
    simdCVs[c].set(IV);
  }
  
  // 16 блоков на чанк
  for (let block = 0; block < 16; block++) {
    // Записываем транспонированный блок
    writeTransposedBlockFast(input, offsets, block);
    
    // Определяем флаги
    const flags = [];
    for (let c = 0; c < 4; c++) {
      let f = 0;
      if (block === 0) f |= CHUNK_START;
      if (block === 15) f |= CHUNK_END;
      flags.push(f);
    }
    
    // Записываем CV и параметры
    writeCVAndParams(simdCVs, counters, BLOCK_LEN, flags);
    
    // Вызываем SIMD compress
    wasmCompress4x();
    
    // Читаем результаты обратно в simdCVs
    readResults(simdCVs);
  }
  
  // Возвращаем копии CV
  return simdCVs.map(cv => new Uint32Array(cv));
}

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ 
// BLAKE3 хэш с использованием WASM SIMD
// ============================================================================

/**
 * Вычисляет BLAKE3 хэш входных данных.
 * 
 * Алгоритм работает в три этапа:
 * 1a. ОБРАБОТКА ПОЛНЫХ ГРУПП ПО 4 ЧАНКа (по 4*1024 байта) через SIMD:
 * 
 * 1b. ОБРАБОТКА ОСТАВШИХСЯ ПОЛНЫХ ЧАНКОВ (по 1024 байта) (0-3 штуки) через JS:
 *    - Каждый чанк состоит из 16 блоков по 64 байта
 *    - Блоки цепочкой сжимаются в одно 256-битное значение
 *    - Результаты чанков складываются в стек для дерева Меркла
 * 
 * 2. ОБРАБОТКА ПОСЛЕДНЕГО (НЕПОЛНОГО) ЧАНКА:
 *    - Может содержать от 0 до 1023 байт
 *    - Паддится нулями до границы блока
 * 
 * 3. ПОСТРОЕНИЕ ДЕРЕВА МЕРКЛА:
 *    - Пары узлов объединяются в родительские узлы
 *    - Повторяется до получения единственного корня
 *    - Корень хэшируется с флагом ROOT
 * 
 * Визуализация дерева для 4 чанков:
 * 
 *              ROOT
 *             /    \
 *        PARENT    PARENT
 *        /   \     /    \
 *     CV0   CV1  CV2   CV3
 *      |     |    |     |
 *   Chunk0 Chunk1 Chunk2 Chunk3
 * 
 * @param {Uint8Array} input - входные данные
 * @returns {Uint8Array} - хэш (32 байта)
 */
function blake3(input) {
  // Проверка типа входных данных
  if (!(input instanceof Uint8Array)) {
    throw new Error('Input must be Uint8Array');
  }

  // Инициализация
  const flags = 0;                    // Базовые флаги (можно добавить KEYED_HASH и др.)
  const length = input.length;
  
  
  // ═══════════════════════════════════════════════════════════════════════
  // АДАПТИВНЫЙ ВЫБОР АЛГОРИТМА
  // ═══════════════════════════════════════════════════════════════════════
  //
  // Для маленьких входов или без WASM — используем JS версию
  //
  // Для данных < 4 KB:
  //   - SIMD не даёт преимущества (нужно минимум 4 чанка)
  //   - Накладные расходы на копирование в WASM память
  //   - Накладные расходы на транспонирование данных
  //   - JavaScript v8 версия быстрее
  //
  // Для данных >= 4 KB:
  //   - SIMD обрабатывает 4 чанка параллельно
  //   - Выигрыш от параллелизма перевешивает накладные расходы
  // ═══════════════════════════════════════════════════════════════════════
  if (!wasmSupported || length < CHUNK_LEN * 4) {
    return blake3Fallback(input);
  }
  

  // ═════════════════════════════════════════════════════════════════════
  // Создаём Uint32Array view на входные данные (ОДИН РАЗ перед циклами)
  // На Little-Endian это даёт прямой доступ без копирования
  // ═════════════════════════════════════════════════════════════════════
  const canUseDirectView = !IsBigEndian && (input.byteOffset % 4 === 0);
  const inputWords = canUseDirectView ? new Uint32Array(
    input.buffer,
    input.byteOffset,
    input.byteLength >> 2
  ) : null;

  const cvStack = getCvStack(length);  // Может переиспользовать существующий
  let cvStackPos = 0;

  const workBuffer = globalWorkBuffer;  // Всегда переиспользуем
  const CV_OFFSET = 0;
  const BLOCK_OFFSET = 8;

  // Инициализация CV = IV
  workBuffer.set(IV, CV_OFFSET);

  let chunkCounter = 0;               // Счётчик обработанных чанков
  let offset = 0;                     // Текущая позиция во входных данных
  
  // ═══════════════════════════════════════════════════════════════════════
  // Вычисляем границы для разных этапов
  // ═══════════════════════════════════════════════════════════════════════
  
  // Сколько полных групп по 4 чанка? (для SIMD)
  const fullGroups = Math.floor(length / (CHUNK_LEN * 4));
  const simdEnd = fullGroups * CHUNK_LEN * 4;
  
  // Сколько полных чанков всего?
  let take = length - (length % CHUNK_LEN);
  if (take === length && length > 0) {
    take -= CHUNK_LEN;
  }
  

  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 1a: Обработка полных групп по 4 чанка (по 4*1024 байта = 4*16 блоков)
  // через SIMD
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < simdEnd; offset += CHUNK_LEN * 4, chunkCounter += 4) {
    // Обрабатываем 4 чанка параллельно
    const cvResults = process4ChunksSimd(input, offset, chunkCounter);

    // Обрабатываем 4 группы чанков
    // Push CV в стек. Добавляем результат чанка в стек
    for (let c = 0; c < 4; c++) {
      cvStack.set(cvResults[c], cvStackPos);
      cvStackPos += 8;
      
      // Merge дерева Меркла
      // Объединяем узлы дерева Меркла, пока можем
      // (пока количество чанков кратно 2)
      let totalChunks = chunkCounter + c + 1;
      const mergeCount = ctz32(totalChunks);
      
      for (let m = 0; m < mergeCount; m++) {
        // Извлекаем два дочерних узла
        cvStackPos -= 16;  // "Pop" два элемента - просто сдвиг числа!
        
        // Сжимаем с флагом PARENT
        // Два CV уже лежат рядом в cvStack — используем как blockWords!
        compress(
          IV, 0,                  // cv = IV (для parent node)
          cvStack, cvStackPos,    // message = два CV, уже лежащих рядом!
          cvStack, cvStackPos,    // out = записать результат обратно в CV
          true,                   // truncate = нужны только 8 слов
          0, BLOCK_LEN,
          flags | PARENT
        );
        
        // Добавить в массив
        cvStackPos += 8;   // "Push" один элемент - результат уже на месте!
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 1b: Обработка оставшихся полных чанков (0-3 штуки) через JS
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

    // CTZ определяет количество merge операций
    const mergeCount = ctz32(chunkCounter);

    for (let m = 0; m < mergeCount; m++) {
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
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 2: Обработка последнего (возможно неполного) чанка
  // ═══════════════════════════════════════════════════════════════════════

  const remainingBytes = length - take;
  const fullBlocks = remainingBytes > 0 ? ((remainingBytes - 1) / 64) | 0 : 0;

  workBuffer.set(IV, CV_OFFSET);

  // Обрабатываем полные блоки последнего чанка
  for (let i = 0; i < fullBlocks; ++i, offset += 64) {
    if (!canUseDirectView) {
      // Если big-Endian, то нужно преобразование байтов
      readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);  // ✅ Быстрая версия
    }

    compress(
      workBuffer, CV_OFFSET,
      // block: workBuffer или напрямую input
      canUseDirectView ? inputWords : workBuffer, 
      // смещение: в workBuffer или в inputWords
      canUseDirectView ? (offset >> 2) : BLOCK_OFFSET,
      workBuffer, CV_OFFSET,
      true,
      chunkCounter,
      BLOCK_LEN,
      flags | (i === 0 ? CHUNK_START : 0)
    );
  }
  
 
  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 3: Финализация - обработка последнего блока и построение корня
  // ═══════════════════════════════════════════════════════════════════════

  // Читаем последний блок (может быть неполным)
  readLittleEndianWordsPartial(input, offset, length, workBuffer, BLOCK_OFFSET);
  const lastBlockLen = length - offset;

  if (cvStackPos === 0) {
    // Особый случай: все данные помещаются в один чанк
    // Финальный блок - это и корень дерева
    // Все данные в одном чанке — сразу вычисляем ROOT
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
    // Общий случай: нужно построить дерево Меркла

    // Завершаем последний чанк
    compress(
      workBuffer, CV_OFFSET,
      workBuffer, BLOCK_OFFSET,
      cvStack, cvStackPos,  // Push результат в стек
      true,
      chunkCounter,
      lastBlockLen,
      flags | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
    );
    cvStackPos += 8;

    // Объединяем оставшиеся узлы в дерево
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

    // Финальное слияние с флагом ROOT
    cvStackPos -= 16;
    compress(
      IV, 0,
      cvStack, cvStackPos,
      workBuffer, CV_OFFSET,  // Результат в workBuffer
      true,
      0,
      BLOCK_LEN,
      flags | PARENT | ROOT
    );
  }
  // Возвращаем первые 32 байта (256 бит) как хэш
  return new Uint8Array(workBuffer.buffer, CV_OFFSET * 4, 32);
}

/**
 * Fallback на чистый JavaScript (код из v8).
 */
function blake3Fallback(input) {
  // Проверка типа входных данных
  if (!(input instanceof Uint8Array)) {
    throw new Error('Input must be Uint8Array');
  }

  // Инициализация
  const flags = 0;                    // Базовые флаги (можно добавить KEYED_HASH и др.)
  const length = input.length;

  // ═════════════════════════════════════════════════════════════════════
  // Создаём Uint32Array view на входные данные (ОДИН РАЗ перед циклами)
  // На Little-Endian это даёт прямой доступ без копирования
  // ═════════════════════════════════════════════════════════════════════
    const canUseDirectView = !IsBigEndian && (input.byteOffset % 4 === 0);
    const inputWords = canUseDirectView ? new Uint32Array(
      input.buffer,
      input.byteOffset,
      input.byteLength >> 2
    ) : null;

  const cvStack = getCvStack(length);  // Может переиспользовать существующий
  let cvStackPos = 0;

  const workBuffer = globalWorkBuffer;  // Всегда переиспользуем
  const CV_OFFSET = 0;
  const BLOCK_OFFSET = 8;

  // Инициализация CV = IV
  workBuffer.set(IV, CV_OFFSET);

  let chunkCounter = 0;               // Счётчик обработанных чанков
  let offset = 0;                     // Текущая позиция во входных данных
  
  // Вычисляем, сколько полных чанков обработать
  // take = наибольшее число, кратное 1024, которое < length
  let take = length - (length % 1024);
  if (take === length && length > 0) { 
    // Если длина кратна 1024, последний чанк все равно обрабатывается отдельно (как partial),
    // или как полный, но с флагом CHUNK_END. 
    // В оригинальной логике take должен быть меньше length, если length > 0.
    take -= 1024;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 1: Обработка полных чанков (по 1024 байта = 16 блоков)
  // ═══════════════════════════════════════════════════════════════════════
  
  for (; offset < take; ) {
    // Сбросить CV в IV для нового чанка
    workBuffer.set(IV, CV_OFFSET);

    // Обрабатываем 16 блоков чанка
    for (let i = 0; i < 16; ++i, offset += 64) {
      // ═══════════════════════════════════════════════════════════════════
      // v8: Little-Endian оптимизация — Zero-Copy!
      // ═══════════════════════════════════════════════════════════════
      if (!canUseDirectView) {
        // Если big-Endian, то нужно преобразование байтов
        readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);  // ✅ Быстрая версияread
      }
      // В остальных случаях нотация - little-endian и 
      // тогда читаем напрямую из inputWords — никакого копирования!

      // Определяем флаги для блока:
      // - Первый блок: CHUNK_START
      // - Последний блок (15-й): CHUNK_END
      // - Остальные: без флагов
      compress(
        workBuffer, CV_OFFSET,      // cv
        // block: workBuffer или напрямую input
        canUseDirectView ? inputWords : workBuffer,      // ← прямой доступ!
        // смещение: в workBuffer или в inputWords
        canUseDirectView ? (offset >> 2): BLOCK_OFFSET,  // ← смещение в словах   
        workBuffer, CV_OFFSET,      // out = записать обратно в CV
        true,                       // truncate
        chunkCounter,
        BLOCK_LEN,
        flags | (i === 0 ? CHUNK_START : i === 15 ? CHUNK_END : 0)
      );
    }

    // Push CV в стек. Добавляем результат чанка в стек
    cvStack.set(workBuffer.subarray(CV_OFFSET, CV_OFFSET + 8), cvStackPos);
    cvStackPos += 8;
    chunkCounter += 1;

    // Объединяем узлы дерева Меркла, пока можем
    // (пока количество чанков кратно 2)
    const totalChunks = chunkCounter;
    const mergeCount = ctz32(totalChunks);
    
    for (let m = 0; m < mergeCount; m++) {
      // Извлекаем два дочерних узла
      cvStackPos -= 16;  // "Pop" два элемента - просто сдвиг числа!
      
      // Сжимаем с флагом PARENT
      // Два CV уже лежат рядом в cvStack — используем как blockWords!
      compress(
        IV, 0,                    // cv = IV (для parent node)
        cvStack, cvStackPos,      // message = два CV, уже лежащих рядом!
        cvStack, cvStackPos,      // out = записать результат туда же
        true,                     // truncate = нужны только 8 слов
        0, BLOCK_LEN, 
        flags | PARENT
      );
      
      // Добавить в массив
      cvStackPos += 8;   // "Push" один элемент - результат уже на месте!
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 2: Обработка последнего (возможно неполного) чанка
  // ═══════════════════════════════════════════════════════════════════════

  const remainingBytes = length - take;
  const fullBlocks = remainingBytes > 0 ? ((remainingBytes - 1) / 64) | 0 : 0;

  // Сбросить CV в IV
  workBuffer.set(IV, CV_OFFSET);

  // Обрабатываем полные блоки последнего чанка
  for (let i = 0; i < fullBlocks; ++i, offset += 64) {
    if (!canUseDirectView) {
      // Если big-Endian, то нужно преобразование байтов
      readLittleEndianWordsFull(input, offset, workBuffer, BLOCK_OFFSET);  // ✅ Быстрая версия
    }

    compress(
      workBuffer, CV_OFFSET,
      // block: workBuffer или напрямую input
      canUseDirectView ? inputWords : workBuffer, 
      // смещение: в workBuffer или в inputWords
      canUseDirectView ? (offset >> 2) : BLOCK_OFFSET,
      workBuffer, CV_OFFSET,
      true,
      chunkCounter,
      BLOCK_LEN,
      flags | (i === 0 ? CHUNK_START : 0)
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ЭТАП 3: Финализация - обработка последнего блока и построение корня
  // ═══════════════════════════════════════════════════════════════════════

  let finalChainingValue;
  let finalBlockLen;
  let finalFlags;

  // Читаем последний блок (может быть неполным)
  readLittleEndianWordsPartial(input, offset, length, workBuffer, BLOCK_OFFSET);  // ✅ С проверками границ
  const lastBlockLen = length - offset;

  if (cvStackPos === 0) {
    // Особый случай: все данные помещаются в один чанк
    // Финальный блок - это и корень дерева
    // Все данные в одном чанке — сразу вычисляем ROOT
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
    // Общий случай: нужно построить дерево Меркла

    // Завершаем последний чанк
    compress(
      workBuffer, CV_OFFSET,
      workBuffer, BLOCK_OFFSET,
      cvStack, cvStackPos,  // Push результат в стек
      true,
      chunkCounter,
      lastBlockLen,
      flags | CHUNK_END | (fullBlocks === 0 ? CHUNK_START : 0)
    );
    cvStackPos += 8;

    // Объединяем оставшиеся узлы в дерево
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

    // Финальное слияние с флагом ROOT
    cvStackPos -= 16;
    compress(
      IV, 0,
      cvStack, cvStackPos,
      workBuffer, CV_OFFSET,  // Результат в workBuffer
      true,
      0,
      BLOCK_LEN,
      flags | PARENT | ROOT
    );
  }
  // Возвращаем первые 32 байта (256 бит) как хэш
  return new Uint8Array(workBuffer.buffer, CV_OFFSET * 4, 32);
}
const hash = blake3;


// ============================================================================
// ЭКСПОРТ
// ============================================================================

export { blake3, hash, initWasm, wasmSupported };


/*
┌─────────────────────────────────────────────────────────────────┐
│                         ВХОДНЫЕ ДАННЫЕ                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Разбиение на ЧАНКИ (1024 байта = 16 блоков по 64 байта)        │
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
