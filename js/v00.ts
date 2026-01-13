/**
 * ============================================================================
 * BLAKE3 — Автономная реализация на TypeScript
 * ============================================================================
 * 
 * Основано на noble-hashes (https://github.com/paulmillr/noble-hashes)
 * Все зависимости встроены в один файл.
 * 
 * @example
 * // Простое использование
 * const hash = blake3(new TextEncoder().encode("hello world"));
 * 
 * // С опциями
 * const hash256 = blake3(data, { dkLen: 64 });
 * 
 * // XOF режим (расширяемый вывод)
 * const hasher = createBlake3();
 * hasher.update(data);
 * const xofOutput = hasher.xof(1024);
 */

// ============================================================================
// ТИПЫ
// ============================================================================

/** Опции BLAKE3 */
export type Blake3Opts = {
  /** Длина выхода в байтах (по умолчанию 32) */
  dkLen?: number;
  /** 32-байтный ключ для keyed hashing */
  key?: Uint8Array;
  /** Контекст для key derivation */
  context?: Uint8Array;
};

/** Внутренний тип для 16 переменных состояния */
type Num16 = {
  v0: number; v1: number; v2: number; v3: number;
  v4: number; v5: number; v6: number; v7: number;
  v8: number; v9: number; v10: number; v11: number;
  v12: number; v13: number; v14: number; v15: number;
};

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/** SHA-256 IV — первые 32 бита дробной части √2, √3, √5, √7, √11, √13, √17, √19 */
const B3_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

/** Флаги BLAKE3 */
const B3_Flags = {
  CHUNK_START: 1,
  CHUNK_END: 2,
  PARENT: 4,
  ROOT: 8,
  KEYED_HASH: 16,
  DERIVE_KEY_CONTEXT: 32,
  DERIVE_KEY_MATERIAL: 64,
} as const;

/** BLAKE3 sigma — 7 раундов перестановок */
const B3_SIGMA: Uint8Array = (() => {
  const Id = Array.from({ length: 16 }, (_, i) => i);
  const permute = (arr: number[]) =>
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8].map((i) => arr[i]);
  const res: number[] = [];
  for (let i = 0, v = Id; i < 7; i++, v = permute(v)) res.push(...v);
  return Uint8Array.from(res);
})();

/** Размер блока */
const BLOCK_LEN = 64;

// ============================================================================
// УТИЛИТЫ
// ============================================================================

/** Проверка, является ли значение Uint8Array */
function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array ||
    (a != null && typeof a === 'object' && (a as any).constructor.name === 'Uint8Array');
}

/** Проверка байтового массива */
function abytes(b: Uint8Array, len?: number, name = 'data'): void {
  if (!isBytes(b)) throw new Error(`${name} must be Uint8Array`);
  if (len !== undefined && b.length !== len) {
    throw new Error(`${name} must be ${len} bytes, got ${b.length}`);
  }
}

/** Проверка числа */
function anumber(n: number): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('positive integer expected');
}

/** Представление Uint8Array как Uint32Array */
function u32(arr: Uint8Array): Uint32Array {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}

/** Представление Uint32Array как Uint8Array */
function u8(arr: Uint32Array): Uint8Array {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}

/** Очистка массивов (заполнение нулями) */
function clean(...arrays: (Uint8Array | Uint32Array)[]): void {
  for (const arr of arrays) arr.fill(0);
}

/** Определение порядка байтов (little-endian?) */
const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;

/** Swap bytes если система big-endian */
function swap32IfBE(arr: Uint32Array): void {
  if (isLE) return;
  for (let i = 0; i < arr.length; i++) {
    const v = arr[i];
    arr[i] = ((v << 24) | ((v << 8) & 0xff0000) | ((v >>> 8) & 0xff00) | (v >>> 24)) >>> 0;
  }
}

/** Разбиение BigInt на два 32-битных числа */
function fromBig(n: bigint, le = false): { h: number; l: number } {
  const h = Number(n >> 32n) >>> 0;
  const l = Number(n & 0xffffffffn) >>> 0;
  return le ? { h: l, l: h } : { h, l };
}

/** Циклический сдвиг вправо */
function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

// ============================================================================
// G-ФУНКЦИИ
// ============================================================================

/** G-функция, часть 1 (rotations 16, 12) */
function G1(a: number, b: number, c: number, d: number, x: number): { a: number; b: number; c: number; d: number } {
  a = (a + b + x) | 0;
  d = rotr(d ^ a, 16);
  c = (c + d) | 0;
  b = rotr(b ^ c, 12);
  return { a, b, c, d };
}

/** G-функция, часть 2 (rotations 8, 7) */
function G2(a: number, b: number, c: number, d: number, x: number): { a: number; b: number; c: number; d: number } {
  a = (a + b + x) | 0;
  d = rotr(d ^ a, 8);
  c = (c + d) | 0;
  b = rotr(b ^ c, 7);
  return { a, b, c, d };
}

// ============================================================================
// ФУНКЦИЯ СЖАТИЯ
// ============================================================================

/** Основная функция сжатия */
function compress(
  s: Uint8Array,
  offset: number,
  msg: Uint32Array,
  rounds: number,
  v0: number, v1: number, v2: number, v3: number,
  v4: number, v5: number, v6: number, v7: number,
  v8: number, v9: number, v10: number, v11: number,
  v12: number, v13: number, v14: number, v15: number
): Num16 {
  let j = 0;
  for (let i = 0; i < rounds; i++) {
    // Колонки
    ({ a: v0, b: v4, c: v8, d: v12 } = G1(v0, v4, v8, v12, msg[offset + s[j++]]));
    ({ a: v0, b: v4, c: v8, d: v12 } = G2(v0, v4, v8, v12, msg[offset + s[j++]]));
    ({ a: v1, b: v5, c: v9, d: v13 } = G1(v1, v5, v9, v13, msg[offset + s[j++]]));
    ({ a: v1, b: v5, c: v9, d: v13 } = G2(v1, v5, v9, v13, msg[offset + s[j++]]));
    ({ a: v2, b: v6, c: v10, d: v14 } = G1(v2, v6, v10, v14, msg[offset + s[j++]]));
    ({ a: v2, b: v6, c: v10, d: v14 } = G2(v2, v6, v10, v14, msg[offset + s[j++]]));
    ({ a: v3, b: v7, c: v11, d: v15 } = G1(v3, v7, v11, v15, msg[offset + s[j++]]));
    ({ a: v3, b: v7, c: v11, d: v15 } = G2(v3, v7, v11, v15, msg[offset + s[j++]]));

    // Диагонали
    ({ a: v0, b: v5, c: v10, d: v15 } = G1(v0, v5, v10, v15, msg[offset + s[j++]]));
    ({ a: v0, b: v5, c: v10, d: v15 } = G2(v0, v5, v10, v15, msg[offset + s[j++]]));
    ({ a: v1, b: v6, c: v11, d: v12 } = G1(v1, v6, v11, v12, msg[offset + s[j++]]));
    ({ a: v1, b: v6, c: v11, d: v12 } = G2(v1, v6, v11, v12, msg[offset + s[j++]]));
    ({ a: v2, b: v7, c: v8, d: v13 } = G1(v2, v7, v8, v13, msg[offset + s[j++]]));
    ({ a: v2, b: v7, c: v8, d: v13 } = G2(v2, v7, v8, v13, msg[offset + s[j++]]));
    ({ a: v3, b: v4, c: v9, d: v14 } = G1(v3, v4, v9, v14, msg[offset + s[j++]]));
    ({ a: v3, b: v4, c: v9, d: v14 } = G2(v3, v4, v9, v14, msg[offset + s[j++]]));
  }
  return { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 };
}

// ============================================================================
// КЛАСС BLAKE3
// ============================================================================

/** Реализация BLAKE3 с поддержкой XOF */
class Blake3 {
  // Публичные свойства
  readonly blockLen = BLOCK_LEN;
  readonly outputLen: number;

  // Состояние
  private buffer: Uint8Array;
  private buffer32: Uint32Array;
  private pos = 0;
  private chunkPos = 0;
  private chunksDone = 0;
  private flags: number;
  private IV: Uint32Array;
  private state: Uint32Array;
  private stack: Uint32Array[] = [];

  // Вывод
  private posOut = 0;
  private bufferOut32 = new Uint32Array(16);
  private bufferOut: Uint8Array;
  private chunkOut = 0;

  // Флаги состояния
  private finished = false;
  private destroyed = false;
  private enableXOF = true;

  constructor(opts: Blake3Opts = {}, flags = 0) {
    this.outputLen = opts.dkLen ?? 32;
    anumber(this.outputLen);

    this.buffer = new Uint8Array(BLOCK_LEN);
    this.buffer32 = u32(this.buffer);
    this.bufferOut = u8(this.bufferOut32);

    const { key, context } = opts;

    if (key !== undefined && context !== undefined) {
      throw new Error('Only "key" or "context" can be specified at same time');
    }

    if (key !== undefined) {
      abytes(key, 32, 'key');
      this.IV = u32(key.slice());
      swap32IfBE(this.IV);
      this.flags = flags | B3_Flags.KEYED_HASH;
    } else if (context !== undefined) {
      abytes(context, undefined, 'context');
      const contextKey = new Blake3({ dkLen: 32 }, B3_Flags.DERIVE_KEY_CONTEXT)
        .update(context)
        .digest();
      this.IV = u32(contextKey);
      swap32IfBE(this.IV);
      this.flags = flags | B3_Flags.DERIVE_KEY_MATERIAL;
    } else {
      this.IV = B3_IV.slice();
      this.flags = flags;
    }

    this.state = this.IV.slice();
  }

  /** Добавить данные для хэширования */
  update(data: Uint8Array): this {
    if (this.destroyed) throw new Error('Hash instance has been destroyed');
    if (this.finished) throw new Error('Hash already finalized');
    abytes(data);

    const { buffer, buffer32 } = this;
    const len = data.length;

    for (let pos = 0; pos < len; ) {
      // Если буфер полон — сжимаем
      if (this.pos === BLOCK_LEN) {
        swap32IfBE(buffer32);
        this.compressBlock(buffer32, 0, false);
        swap32IfBE(buffer32);
        this.pos = 0;
      }

      // Сколько можем взять
      const take = Math.min(BLOCK_LEN - this.pos, len - pos);

      // Оптимизация: если данные выровнены и их достаточно
      const dataOffset = data.byteOffset + pos;
      if (take === BLOCK_LEN && !(dataOffset % 4) && pos + take < len) {
        const data32 = new Uint32Array(data.buffer, dataOffset, Math.floor((len - pos) / 4));
        swap32IfBE(data32);
        for (let pos32 = 0; pos + BLOCK_LEN < len; pos32 += buffer32.length, pos += BLOCK_LEN) {
          this.compressBlock(data32, pos32, false);
        }
        swap32IfBE(data32);
        continue;
      }

      // Копируем в буфер
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
    }

    return this;
  }

  /** Внутреннее сжатие блока */
  private b2Compress(counter: number, flags: number, buf: Uint32Array, bufPos = 0): void {
    const { state: s, pos } = this;
    const { h, l } = fromBig(BigInt(counter), true);

    const result = compress(
      B3_SIGMA, bufPos, buf, 7,
      s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
      B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], h, l, pos, flags
    );

    s[0] = result.v0 ^ result.v8;
    s[1] = result.v1 ^ result.v9;
    s[2] = result.v2 ^ result.v10;
    s[3] = result.v3 ^ result.v11;
    s[4] = result.v4 ^ result.v12;
    s[5] = result.v5 ^ result.v13;
    s[6] = result.v6 ^ result.v14;
    s[7] = result.v7 ^ result.v15;
  }

  /** Сжатие блока с обработкой чанков */
  private compressBlock(buf: Uint32Array, bufPos = 0, isLast = false): void {
    let flags = this.flags;
    if (!this.chunkPos) flags |= B3_Flags.CHUNK_START;
    if (this.chunkPos === 15 || isLast) flags |= B3_Flags.CHUNK_END;
    if (!isLast) this.pos = BLOCK_LEN;

    this.b2Compress(this.chunksDone, flags, buf, bufPos);
    this.chunkPos += 1;

    // Обработка завершённого чанка
    if (this.chunkPos === 16 || isLast) {
      let chunk = this.state;
      this.state = this.IV.slice();

      for (let last, chunks = this.chunksDone + 1; isLast || !(chunks & 1); chunks >>= 1) {
        if (!(last = this.stack.pop())) break;
        this.buffer32.set(last, 0);
        this.buffer32.set(chunk, 8);
        this.pos = BLOCK_LEN;
        this.b2Compress(0, this.flags | B3_Flags.PARENT, this.buffer32, 0);
        chunk = this.state;
        this.state = this.IV.slice();
      }

      this.chunksDone++;
      this.chunkPos = 0;
      this.stack.push(chunk);
    }

    this.pos = 0;
  }

  /** Сжатие для вывода */
  private b2CompressOut(): void {
    const { state: s, pos, flags, buffer32, bufferOut32: out32 } = this;
    const { h, l } = fromBig(BigInt(this.chunkOut++));

    swap32IfBE(buffer32);

    const result = compress(
      B3_SIGMA, 0, buffer32, 7,
      s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
      B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3], l, h, pos, flags
    );

    out32[0] = result.v0 ^ result.v8;
    out32[1] = result.v1 ^ result.v9;
    out32[2] = result.v2 ^ result.v10;
    out32[3] = result.v3 ^ result.v11;
    out32[4] = result.v4 ^ result.v12;
    out32[5] = result.v5 ^ result.v13;
    out32[6] = result.v6 ^ result.v14;
    out32[7] = result.v7 ^ result.v15;
    out32[8] = s[0] ^ result.v8;
    out32[9] = s[1] ^ result.v9;
    out32[10] = s[2] ^ result.v10;
    out32[11] = s[3] ^ result.v11;
    out32[12] = s[4] ^ result.v12;
    out32[13] = s[5] ^ result.v13;
    out32[14] = s[6] ^ result.v14;
    out32[15] = s[7] ^ result.v15;

    swap32IfBE(buffer32);
    swap32IfBE(out32);
    this.posOut = 0;
  }

  /** Финализация хэша */
  private finish(): void {
    if (this.finished) return;
    this.finished = true;

    // Очистка оставшейся части буфера
    clean(this.buffer.subarray(this.pos));

    let flags = this.flags | B3_Flags.ROOT;

    if (this.stack.length) {
      flags |= B3_Flags.PARENT;
      swap32IfBE(this.buffer32);
      this.compressBlock(this.buffer32, 0, true);
      swap32IfBE(this.buffer32);
      this.chunksDone = 0;
      this.pos = BLOCK_LEN;
    } else {
      flags |= (!this.chunkPos ? B3_Flags.CHUNK_START : 0) | B3_Flags.CHUNK_END;
    }

    this.flags = flags;
    this.b2CompressOut();
  }

  /** Запись результата в буфер */
  private writeInto(out: Uint8Array): Uint8Array {
    if (this.destroyed) throw new Error('Hash instance has been destroyed');
    abytes(out);
    this.finish();

    const { bufferOut } = this;

    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= BLOCK_LEN) this.b2CompressOut();
      const take = Math.min(BLOCK_LEN - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }

    return out;
  }

  /** XOF: записать расширенный вывод в буфер */
  xofInto(out: Uint8Array): Uint8Array {
    if (!this.enableXOF) throw new Error('XOF is not possible after digest call');
    return this.writeInto(out);
  }

  /** XOF: получить расширенный вывод заданной длины */
  xof(bytes: number): Uint8Array {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }

  /** Записать хэш в существующий буфер */
  digestInto(out: Uint8Array): Uint8Array {
    abytes(out);
    if (out.length < this.outputLen) {
      throw new Error(`output length must be at least ${this.outputLen}`);
    }
    if (this.finished) throw new Error('digest() was already called');

    this.enableXOF = false;
    this.writeInto(out);
    this.destroy();
    return out;
  }

  /** Получить хэш */
  digest(): Uint8Array {
    return this.digestInto(new Uint8Array(this.outputLen));
  }

  /** Клонировать состояние хэшера */
  clone(): Blake3 {
    const to = new Blake3({ dkLen: this.outputLen });

    to.buffer.set(this.buffer);
    to.pos = this.pos;
    to.chunkPos = this.chunkPos;
    to.chunksDone = this.chunksDone;
    to.flags = this.flags;
    to.IV.set(this.IV);
    to.state.set(this.state);
    to.stack = this.stack.map(s => Uint32Array.from(s));
    to.posOut = this.posOut;
    to.bufferOut32.set(this.bufferOut32);
    to.chunkOut = this.chunkOut;
    to.finished = this.finished;
    to.destroyed = this.destroyed;
    to.enableXOF = this.enableXOF;

    return to;
  }

  /** Уничтожить состояние (очистить память) */
  destroy(): void {
    this.destroyed = true;
    clean(this.state, this.buffer32, this.IV, this.bufferOut32);
    for (const s of this.stack) clean(s);
  }
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

/**
 * Конвертация Uint8Array в hex-строку
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Конвертация hex-строки в Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// ============================================================================
// УПРОЩЁННЫЙ API
// ============================================================================

/**
 * Вычисляет BLAKE3 хэш
 * 
 * @param msg - входные данные (Uint8Array)
 * @param opts - опции
 * @returns хэш в виде Uint8Array
 * 
 * @example
 * const hash = blake3(new TextEncoder().encode("hello"));
 */
export function blake3(msg: Uint8Array, opts?: Blake3Opts): Uint8Array {
  return new Blake3(opts).update(msg).digest();
}

/**
 * Создаёт экземпляр BLAKE3 для инкрементального хэширования
 * 
 * @example
 * const hasher = createBlake3();
 * hasher.update(chunk1);
 * hasher.update(chunk2);
 * const hash = hasher.digest();
 */
export function createBlake3(opts?: Blake3Opts): Blake3 {
  return new Blake3(opts);
}

/**
 * Вычисляет BLAKE3 хэш и возвращает hex-строку
 * 
 * @example
 * const hexHash = blake3Hex(new TextEncoder().encode("hello"));
 */
export function blake3Hex(msg: Uint8Array, opts?: Blake3Opts): string {
  return bytesToHex(blake3(msg, opts));
}

// Метаданные
blake3.outputLen = 32;
blake3.blockLen = BLOCK_LEN;
blake3.create = createBlake3;
