/**
 * ============================================================================
 * Big-Endian Tester для BLAKE3 — Универсальная версия
 * ============================================================================
 * 
 * Поддерживает модули с разными экспортами:
 *   - export { blake3 }
 *   - export { hash }
 *   - export { blake3, hash }
 *   - export default function
 * 
 * Запуск:
 *   deno test --allow-read blake3_bigendian_test.ts
 */

// ============================================================================
// ИМПОРТ МОДУЛЯ — ИЗМЕНИТЕ ПУТЬ ЗДЕСЬ
// ============================================================================

//import * as blake3Module from "./v0.js"; // Passed
//import * as blake3Module from "./v1.js"; // Passed
import * as blake3Module from "./v9.js"; // Passed
//import * as blake3Module from "./v9_ru_b.js"; // Passed
//import * as blake3Module from "./v9_ru.js"; // Passed
//import * as blake3Module from "./vt0.ts"; // Fault
//import * as blake3Module from "./vt1.js"; // Passed
//import * as blake3Module from "./vt2.ts"; // Fault
//import * as blake3Module from "./vt3_simd-4-fast.ts"; // Passed
//import * as blake3Module from "./vt4.js"; // Fault


// ============================================================================
// УНИВЕРСАЛЬНОЕ ОПРЕДЕЛЕНИЕ ФУНКЦИИ ХЭШИРОВАНИЯ
// ============================================================================

type HashFunction = (input: Uint8Array) => Uint8Array;

/**
 * Извлекает функцию хэширования из модуля.
 * Поддерживает разные варианты экспорта.
 */
function getHashFunction(module: Record<string, unknown>): HashFunction {
  // Вариант 1: module.blake3
  if (typeof module.blake3 === 'function') {
    console.log("  Найдена функция: blake3");
    return module.blake3 as HashFunction;
  }
  
  // Вариант 2: module.hash
  if (typeof module.hash === 'function') {
    console.log("  Найдена функция: hash");
    return module.hash as HashFunction;
  }
  
  // Вариант 3: module.default (export default)
  if (typeof module.default === 'function') {
    console.log("  Найдена функция: default");
    return module.default as HashFunction;
  }
  
  // Вариант 4: сам модуль — функция
  if (typeof module === 'function') {
    console.log("  Модуль сам является функцией");
    return module as unknown as HashFunction;
  }
  
  // Ничего не найдено — показываем что есть в модуле
  const exports = Object.keys(module).join(', ');
  throw new Error(
    `Не найдена функция хэширования в модуле.\n` +
    `Доступные экспорты: [${exports}]\n` +
    `Ожидается: blake3, hash или default`
  );
}

/**
 * Проверяет наличие флага поддержки WASM SIMD
 */
function getWasmSupported(module: Record<string, unknown>): boolean | undefined {
  if (typeof module.wasmSupported === 'boolean') {
    return module.wasmSupported;
  }
  if (typeof module.simdSupported === 'boolean') {
    return module.simdSupported;
  }
  return undefined;
}

// ============================================================================
// ИНИЦИАЛИЗАЦИЯ
// ============================================================================

console.log("\n" + "═".repeat(70));
console.log("  BLAKE3 Big-Endian Tester для Deno");
console.log("═".repeat(70));

// Получаем функцию хэширования
const blake3 = getHashFunction(blake3Module as Record<string, unknown>);

// Проверяем WASM поддержку
const wasmSupported = getWasmSupported(blake3Module as Record<string, unknown>);

// ============================================================================
// УТИЛИТЫ
// ============================================================================

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function createSequentialBytes(length: number): Uint8Array {
  const arr = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    arr[i] = i % 251;
  }
  return arr;
}

// ============================================================================
// ЭМУЛЯТОР BIG-ENDIAN
// ============================================================================

class BigEndianEmulator {
  readonly isActualBigEndian: boolean;
  
  constructor() {
    this.isActualBigEndian = !new Uint8Array(new Uint32Array([1]).buffer)[0];
  }
  
  readLE32(array: Uint8Array, offset: number): number {
    return array[offset] |
           (array[offset + 1] << 8) |
           (array[offset + 2] << 16) |
           (array[offset + 3] << 24);
  }
  
  readBE32(array: Uint8Array, offset: number): number {
    return (array[offset] << 24) |
           (array[offset + 1] << 16) |
           (array[offset + 2] << 8) |
           array[offset + 3];
  }
  
  writeLE32(array: Uint8Array, offset: number, value: number): void {
    array[offset] = value & 0xff;
    array[offset + 1] = (value >>> 8) & 0xff;
    array[offset + 2] = (value >>> 16) & 0xff;
    array[offset + 3] = (value >>> 24) & 0xff;
  }
}

const emulator = new BigEndianEmulator();

// ============================================================================
// ВЫВОД ИНФОРМАЦИИ О СИСТЕМЕ
// ============================================================================

console.log(`  Deno версия: ${Deno.version.deno}`);
console.log(`  V8 версия:   ${Deno.version.v8}`);
console.log(`  Архитектура: ${emulator.isActualBigEndian ? 'Big-Endian' : 'Little-Endian'}`);
console.log(`  WASM SIMD:   ${wasmSupported === undefined ? 'Неизвестно' : wasmSupported ? 'Доступен' : 'Недоступен'}`);
console.log("═".repeat(70) + "\n");

// ============================================================================
// ТЕСТ-ВЕКТОРЫ
// ============================================================================

interface TestVector {
  name: string;
  input: Uint8Array;
  expected: string;
}

const TEST_VECTORS: TestVector[] = [
  {
    name: "Пустой вход",
    input: new Uint8Array([]),
    expected: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
  },
  {
    name: "Один байт (0x00)",
    input: new Uint8Array([0x00]),
    expected: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
  },
  {
    name: "Строка 'abc'",
    input: new TextEncoder().encode("abc"),
    expected: "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
  },
];

// ============================================================================
// ГРУППА 1: НИЗКОУРОВНЕВЫЕ ФУНКЦИИ
// ============================================================================

Deno.test("Группа 1: Низкоуровневые функции", async (t) => {
  
  await t.step("1.1 readLE32 базовый", () => {
    const data = new Uint8Array([0x78, 0x56, 0x34, 0x12]);
    const expected = 0x12345678;
    const actual = emulator.readLE32(data, 0);
    if (actual !== expected) {
      throw new Error(`Ожидалось 0x${expected.toString(16)}, получено 0x${actual.toString(16)}`);
    }
  });
  
  await t.step("1.2 readLE32 со смещением", () => {
    const data = new Uint8Array([0xFF, 0x78, 0x56, 0x34, 0x12, 0xFF]);
    const expected = 0x12345678;
    const actual = emulator.readLE32(data, 1);
    if (actual !== expected) {
      throw new Error(`Ожидалось 0x${expected.toString(16)}, получено 0x${actual.toString(16)}`);
    }
  });
  
  await t.step("1.3 readBE32 отличается от readLE32", () => {
    const data = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const le = emulator.readLE32(data, 0);
    const be = emulator.readBE32(data, 0);
    
    if (le === be) {
      throw new Error("LE и BE чтение не должны совпадать");
    }
    if (le !== 0x78563412) {
      throw new Error(`LE должно быть 0x78563412, получено 0x${le.toString(16)}`);
    }
    if (be !== 0x12345678) {
      throw new Error(`BE должно быть 0x12345678, получено 0x${be.toString(16)}`);
    }
  });
  
  await t.step("1.4 writeLE32 → readLE32 roundtrip", () => {
    const testValues = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x12345678];
    for (const value of testValues) {
      const buf = new Uint8Array(4);
      emulator.writeLE32(buf, 0, value);
      const read = emulator.readLE32(buf, 0);
      if ((read >>> 0) !== (value >>> 0)) {
        throw new Error(`Roundtrip failed для 0x${value.toString(16)}: получено 0x${read.toString(16)}`);
      }
    }
  });
});

// ============================================================================
// ГРУППА 2: ОФИЦИАЛЬНЫЕ ТЕСТ-ВЕКТОРЫ
// ============================================================================

Deno.test("Группа 2: Официальные тест-векторы", async (t) => {
  for (const vector of TEST_VECTORS) {
    await t.step(vector.name, () => {
      const hash = blake3(vector.input);
      const hashHex = toHex(hash);
      if (hashHex !== vector.expected) {
        throw new Error(`\nОжидалось: ${vector.expected}\nПолучено:  ${hashHex}`);
      }
    });
  }
});

// ============================================================================
// ГРУППА 3: ВЫРАВНИВАНИЕ БУФЕРОВ
// ============================================================================

Deno.test("Группа 3: Выравнивание буферов", async (t) => {
  
  await t.step("3.1 Выровненный буфер стабилен", () => {
    const data = new Uint8Array(64);
    for (let i = 0; i < 64; i++) data[i] = i;
    
    const hash1 = toHex(blake3(data));
    const hash2 = toHex(blake3(data));
    
    if (hash1 !== hash2) {
      throw new Error("Повторные вызовы должны давать одинаковый хэш");
    }
  });
  
  await t.step("3.2 Невыровненный буфер (offset=1)", () => {
    const alignedBuf = new ArrayBuffer(64);
    const unalignedBuf = new ArrayBuffer(68);
    
    const aligned = new Uint8Array(alignedBuf, 0, 64);
    const unaligned = new Uint8Array(unalignedBuf, 1, 64);
    
    for (let i = 0; i < 64; i++) {
      aligned[i] = i;
      unaligned[i] = i;
    }
    
    const hashAligned = toHex(blake3(aligned));
    const hashUnaligned = toHex(blake3(unaligned));
    
    console.log(`    Aligned (offset=0):   ${hashAligned.slice(0, 16)}...`);
    console.log(`    Unaligned (offset=1): ${hashUnaligned.slice(0, 16)}...`);
    
    if (hashAligned !== hashUnaligned) {
      throw new Error(
        `Хэши различаются!\n` +
        `  Выровненный:   ${hashAligned}\n` +
        `  Невыровненный: ${hashUnaligned}`
      );
    }
  });
  
  await t.step("3.3 Невыровненный буфер (offset=2)", () => {
    const alignedBuf = new ArrayBuffer(64);
    const unalignedBuf = new ArrayBuffer(68);
    
    const aligned = new Uint8Array(alignedBuf, 0, 64);
    const unaligned = new Uint8Array(unalignedBuf, 2, 64);
    
    for (let i = 0; i < 64; i++) {
      aligned[i] = i;
      unaligned[i] = i;
    }
    
    const hashAligned = toHex(blake3(aligned));
    const hashUnaligned = toHex(blake3(unaligned));
    
    if (hashAligned !== hashUnaligned) {
      throw new Error(`Хэши различаются!`);
    }
  });
  
  await t.step("3.4 Невыровненный буфер (offset=3)", () => {
    const alignedBuf = new ArrayBuffer(64);
    const unalignedBuf = new ArrayBuffer(68);
    
    const aligned = new Uint8Array(alignedBuf, 0, 64);
    const unaligned = new Uint8Array(unalignedBuf, 3, 64);
    
    for (let i = 0; i < 64; i++) {
      aligned[i] = i;
      unaligned[i] = i;
    }
    
    const hashAligned = toHex(blake3(aligned));
    const hashUnaligned = toHex(blake3(unaligned));
    
    if (hashAligned !== hashUnaligned) {
      throw new Error(`Хэши различаются!`);
    }
  });
  
  await t.step("3.5 Большой невыровненный буфер (1025 байт, offset=3)", () => {
    const alignedBuf = new ArrayBuffer(1025);
    const unalignedBuf = new ArrayBuffer(1028);
    
    const aligned = new Uint8Array(alignedBuf, 0, 1025);
    const unaligned = new Uint8Array(unalignedBuf, 3, 1025);
    
    for (let i = 0; i < 1025; i++) {
      aligned[i] = i % 251;
      unaligned[i] = i % 251;
    }
    
    const hashAligned = toHex(blake3(aligned));
    const hashUnaligned = toHex(blake3(unaligned));
    
    if (hashAligned !== hashUnaligned) {
      throw new Error(`Хэши различаются для 1025 байт!`);
    }
  });
});

// ============================================================================
// ГРУППА 4: ГРАНИЧНЫЕ СЛУЧАИ
// ============================================================================

Deno.test("Группа 4: Граничные случаи", async (t) => {
  
  await t.step("4.1 Ровно 64 байта (граница блока)", () => {
    const data = createSequentialBytes(64);
    const hash = blake3(data);
    if (hash.length !== 32) {
      throw new Error(`Длина хэша должна быть 32, получено ${hash.length}`);
    }
  });
  
  await t.step("4.2 Около границы блока (63, 64, 65 байт)", () => {
    const hash63 = toHex(blake3(createSequentialBytes(63)));
    const hash64 = toHex(blake3(createSequentialBytes(64)));
    const hash65 = toHex(blake3(createSequentialBytes(65)));
    
    console.log(`    63 байт: ${hash63.slice(0, 16)}...`);
    console.log(`    64 байт: ${hash64.slice(0, 16)}...`);
    console.log(`    65 байт: ${hash65.slice(0, 16)}...`);
    
    if (hash63 === hash64 || hash64 === hash65 || hash63 === hash65) {
      throw new Error("Все хэши должны быть уникальными");
    }
  });
  
  await t.step("4.3 Ровно 1024 байта (граница чанка)", () => {
    const data = createSequentialBytes(1024);
    const hash = blake3(data);
    if (hash.length !== 32) {
      throw new Error(`Длина хэша должна быть 32`);
    }
  });
  
  await t.step("4.4 Около границы чанка (1023, 1024, 1025 байт)", () => {
    const hash1023 = toHex(blake3(createSequentialBytes(1023)));
    const hash1024 = toHex(blake3(createSequentialBytes(1024)));
    const hash1025 = toHex(blake3(createSequentialBytes(1025)));
    
    console.log(`    1023 байт: ${hash1023.slice(0, 16)}...`);
    console.log(`    1024 байт: ${hash1024.slice(0, 16)}...`);
    console.log(`    1025 байт: ${hash1025.slice(0, 16)}...`);
    
    if (hash1023 === hash1024 || hash1024 === hash1025) {
      throw new Error("Все хэши должны быть уникальными");
    }
  });
  
  await t.step("4.5 Ровно 4096 байт (порог SIMD)", () => {
    const data = createSequentialBytes(4096);
    const hash = blake3(data);
    console.log(`    4096 байт: ${toHex(hash).slice(0, 16)}...`);
    if (hash.length !== 32) {
      throw new Error(`Длина хэша должна быть 32`);
    }
  });
  
  await t.step("4.6 Степени двойки", () => {
    const sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];
    const hashes = new Set<string>();
    
    for (const size of sizes) {
      const hash = toHex(blake3(createSequentialBytes(size)));
      if (hashes.has(hash)) {
        throw new Error(`Коллизия при размере ${size}`);
      }
      hashes.add(hash);
    }
  });
});

// ============================================================================
// ГРУППА 5: SIMD ПУТЬ
// ============================================================================

Deno.test("Группа 5: SIMD путь", async (t) => {
  
  await t.step("5.1 Консистентность до/после SIMD порога", () => {
    const dataSmall = createSequentialBytes(4095);
    const hashSmall = blake3(dataSmall);
    const hashSmallHex = toHex(hashSmall);
    
    const dataLarge = createSequentialBytes(4096);
    const hashLarge = blake3(dataLarge);
    const hashLargeHex = toHex(hashLarge);
    
    console.log(`    4095 байт (JS):   ${hashSmallHex.slice(0, 16)}...`);
    console.log(`    4096 байт (SIMD): ${hashLargeHex.slice(0, 16)}...`);
    
    if (hashSmall.length !== 32 || hashLarge.length !== 32) {
      throw new Error("Оба хэша должны быть 32 байта");
    }
    
    if (hashSmallHex === hashLargeHex) {
      throw new Error("КРИТИЧЕСКИЙ БАГ: Хэши разных данных совпадают!");
    }
  });
  
  await t.step("5.2 Большие данные (16 KB через SIMD)", () => {
    const data = createSequentialBytes(16384);
    const hash = blake3(data);
    console.log(`    16384 байт: ${toHex(hash).slice(0, 16)}...`);
    if (hash.length !== 32) {
      throw new Error(`Длина хэша должна быть 32`);
    }
  });
  
  await t.step("5.3 Повторяемость SIMD (20 KB)", () => {
    const data = createSequentialBytes(20480);
    const hash1 = toHex(blake3(data));
    const hash2 = toHex(blake3(data));
    
    if (hash1 !== hash2) {
      throw new Error("Хэши должны быть идентичны при повторном вычислении");
    }
  });
  
  await t.step("5.4 SIMD + остаток (5000 байт)", () => {
    const data = createSequentialBytes(5000);
    const hash = blake3(data);
    console.log(`    5000 байт: ${toHex(hash).slice(0, 16)}...`);
    if (hash.length !== 32) {
      throw new Error(`Длина хэша должна быть 32`);
    }
  });
  
  await t.step("5.5 Много SIMD групп (100 KB)", () => {
    const data = createSequentialBytes(102400);
    const hash1 = toHex(blake3(data));
    const hash2 = toHex(blake3(data));
    
    console.log(`    100 KB: ${hash1.slice(0, 16)}...`);
    
    if (hash1 !== hash2) {
      throw new Error("Результаты нестабильны!");
    }
  });
});

// ============================================================================
// ГРУППА 6: КОНСИСТЕНТНОСТЬ ENDIAN
// ============================================================================

Deno.test("Группа 6: Консистентность Endian", async (t) => {
  
  await t.step("6.1 Детекция архитектуры", () => {
    const testValue = new Uint32Array([0x01020304]);
    const bytes = new Uint8Array(testValue.buffer);
    
    const isLE = bytes[0] === 0x04;
    
    console.log(`    Архитектура: ${isLE ? 'Little-Endian' : 'Big-Endian'}`);
    console.log(`    Байты [0x01020304]: [${bytes.join(', ')}]`);
  });
  
  await t.step("6.2 Стабильность хэша (10 итераций)", () => {
    const data = createSequentialBytes(1234);
    const firstHash = toHex(blake3(data));
    
    for (let i = 0; i < 10; i++) {
      const hash = toHex(blake3(data));
      if (hash !== firstHash) {
        throw new Error(`Итерация ${i}: хэш изменился!`);
      }
    }
  });
  
  await t.step("6.3 Avalanche effect (изменение 1 бита)", () => {
    const data1 = createSequentialBytes(100);
    const data2 = new Uint8Array(data1);
    data2[50] ^= 0x01;
    
    const hash1 = toHex(blake3(data1));
    const hash2 = toHex(blake3(data2));
    
    let diffBits = 0;
    for (let i = 0; i < 64; i++) {
      const b1 = parseInt(hash1[i], 16);
      const b2 = parseInt(hash2[i], 16);
      let diff = b1 ^ b2;
      while (diff) {
        diffBits += diff & 1;
        diff >>>= 1;
      }
    }
    
    console.log(`    Изменённых бит: ${diffBits}/256 (${(diffBits/256*100).toFixed(1)}%)`);
    
    if (diffBits < 80 || diffBits > 176) {
      console.log(`    ⚠️ Подозрительное распределение!`);
    }
  });
  
  await t.step("6.4 Порядок байтов в выходе", () => {
    const emptyHash = blake3(new Uint8Array([]));
    const expectedStart = "af1349b9";
    const actualStart = toHex(emptyHash.slice(0, 4));
    
    console.log(`    Первые 4 байта пустого хэша: ${actualStart}`);
    
    if (actualStart !== expectedStart) {
      throw new Error(`Ожидалось ${expectedStart}, получено ${actualStart}`);
    }
  });
});

// ============================================================================
// ГРУППА 7: ДИАГНОСТИКА
// ============================================================================

Deno.test("Группа 7: Глубокая диагностика", async (t) => {
  
  await t.step("7.1 Пошаговая проверка размеров вокруг SIMD порога", () => {
    const sizes = [4090, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100];
    const hashes: Map<string, number[]> = new Map();
    
    console.log("\n    Размер → Хэш (первые 8 символов):");
    
    for (const size of sizes) {
      const data = createSequentialBytes(size);
      const hash = toHex(blake3(data));
      
      if (hashes.has(hash)) {
        const collisionSizes = hashes.get(hash)!;
        collisionSizes.push(size);
        throw new Error(`Коллизия между размерами ${collisionSizes.join(', ')}`);
      } else {
        hashes.set(hash, [size]);
        console.log(`    ${size.toString().padStart(5)} → ${hash.slice(0, 8)}...`);
      }
    }
  });
  
  await t.step("7.2 Проверка чанковой обработки", () => {
    const oneChunk = createSequentialBytes(1024);
    const hashOne = toHex(blake3(oneChunk));
    
    const twoChunks = createSequentialBytes(2048);
    const hashTwo = toHex(blake3(twoChunks));
    
    const threeChunks = createSequentialBytes(3072);
    const hashThree = toHex(blake3(threeChunks));
    
    const fourChunks = createSequentialBytes(4096);
    const hashFour = toHex(blake3(fourChunks));
    
    console.log(`    1 чанк (1024):  ${hashOne.slice(0, 16)}...`);
    console.log(`    2 чанка (2048): ${hashTwo.slice(0, 16)}...`);
    console.log(`    3 чанка (3072): ${hashThree.slice(0, 16)}...`);
    console.log(`    4 чанка (4096): ${hashFour.slice(0, 16)}...`);
    
    const all = [hashOne, hashTwo, hashThree, hashFour];
    const unique = new Set(all);
    
    if (unique.size !== 4) {
      throw new Error("Все хэши должны быть уникальными!");
    }
  });
});

// ============================================================================
// ГРУППА 8: БЕНЧМАРК
// ============================================================================

Deno.test("Группа 8: Производительность", async (t) => {
  
  await t.step("8.1 Бенчмарк 1 MB", () => {
    const data = createSequentialBytes(1024 * 1024);
    
    const start = performance.now();
    const iterations = 10;
    
    for (let i = 0; i < iterations; i++) {
      blake3(data);
    }
    
    const elapsed = performance.now() - start;
    const msPerMB = elapsed / iterations;
    const mbPerSecond = 1000 / msPerMB;
    
    console.log(`    Скорость: ${mbPerSecond.toFixed(1)} MB/s (${msPerMB.toFixed(2)} ms/MB)`);
  });
});
