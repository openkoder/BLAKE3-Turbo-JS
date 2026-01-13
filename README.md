```markdown
<div align="center">

# ⚡ blake3-turbo-js

### Blazingly Fast BLAKE3 for JavaScript

[![npm version](https://img.shields.io/npm/v/blake3-turbo-js.svg?style=flat-square)](https://www.npmjs.com/package/blake3-turbo-js)
[![bundle size](https://img.shields.io/bundlephobia/minzip/blake3-turbo-js?style=flat-square)](https://bundlephobia.com/package/blake3-turbo-js)
[![license](https://img.shields.io/npm/l/blake3-turbo-js.svg?style=flat-square)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue?style=flat-square)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-3119_vectors-brightgreen.svg?style=flat-square)](https://github.com/pskzcompern/blake3-turbo-js)

**700–1600 MB/s** BLAKE3 in pure TypeScript. No native bindings, no `node-gyp`, no Python.

Just drop it in and hash. Works in Node.js, browsers, Deno, Bun—anywhere JavaScript runs.

[Installation](#-installation) •
[Usage](#-usage) •
[Benchmarks](#-benchmarks) •
[API](#-api) •
[Why BLAKE3?](#-why-blake3)

</div>

---

## 📖 Articles

**Read more about the optimization journey:**

1. [Part 1: Initial Implementation](https://openkoder.medium.com/9bc73549fcc8)
2. [Part 2: Advanced Optimizations](https://openkoder.medium.com/4b43fa67c2d4)
3. [Part 3: WASM SIMD & Final Results](https://openkoder.medium.com/7d9299885273)

---

## 🏆 Background

This project was created in response to the [bounty placed by Zooko Wilcox-O'Hearn](https://x.com/zooko/status/1998185559542657145) (Zcash founder and BLAKE3 co-author) for a fast JavaScript implementation of BLAKE3.

The implementation is based on optimization techniques from the [Fleek Network BLAKE3 case study](https://web.archive.org/web/20250320125147/https://blog.fleek.network/post/fleek-network-blake3-case-study/).

---

## 💝 Support

If you find this project useful, consider supporting development:

**Zcash Shielded Address:**
```
u1c9qqs5knwe360w6snjuhcldtpf6tcc9nz6xuanmz2xwyf7l4ufze89tze43yz90ajgcej5ylh0a4h2ac65flsvp7a8ewaauvtt4hwsxuhuqvv9h5fkxntw9yk0eyrrlcu004e2havqs0yx58u7kk75e8hff47srsaslc9g6u6rxfn7j9es2g6zc0drd6ajus8wjj2f8p3als53dfc9l
```

**Zcash Transparent Address:**
```
t1UT1TmcpZBoaCRWLC5evpyN97vXnEVVfWW

```

---

## ❓ Why This Library?

The official `blake3` npm package uses native bindings. That means:

- ❌ **Build failures on CI** — `node-gyp` errors, missing compilers
- ❌ **Platform-specific headaches** — different binaries for Linux/macOS/Windows
- ❌ **Pain when deploying to serverless** — Lambda, Cloudflare Workers, Vercel Edge
- ❌ **Python requirement** — `node-gyp` needs Python installed

**This library generates WebAssembly SIMD bytecode at runtime.** Same interface, zero dependencies, actually fast.

---

## ✨ Highlights

- 🚀 **700–1600 MB/s throughput** depending on hardware
- ⚡ **7x faster** than Node.js native SHA-256
- 🎯 **1.59x** of Rust/WASM performance — almost native speed!
- 📦 **Zero dependencies** — pure JavaScript with optional WASM SIMD
- 🔧 **No build step** — no `node-gyp`, no Python, no native compilation
- 🌐 **Universal** — works in Node.js, Deno, Bun, and browsers
- 🔒 **Cryptographically secure** — 256-bit security level
- ✅ **Battle-tested** — verified against **3119 official test vectors**
- 🔧 **Self-contained** — single file, no external `.wasm` files

---

## 📊 Performance Visualization

```
╔═══════════════════════════════════════════════════════════╗
║      BLAKE3 Performance Evolution (JS/WASM)               ║
║              Processing 1 MB of data                      ║
╚═══════════════════════════════════════════════════════════╝

                    Log₁₀ time scale (ms)
                    1     10    100   1s    10s
                    │      │      │      │      │
Rust: 3.7 ms       ▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░░│ ← NATIVE (target)
v9:   5.9 ms       ▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░│ ⚡ WASM SIMD (1.59x from Rust)
v8:   6.5 ms       ▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░│ (JS Zero-Copy)
v6:   7.5 ms       ▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░░│ (Locals)
v5:   9.9 ms       ▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░░░░│ (In-place)
                   ─────────────────────────────────────────────
SHA:  41.5 ms      ▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░│ ← SHA-256 (Native C++)
Noble:55.2 ms      ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░│ (@paulmillr/noble-hashes)
v4:   65.2 ms      ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░│
v3:   81.7 ms      ▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░│
v2:   95.2 ms      ▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░│
v1:  219.6 ms      ▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░│
v0:   20.4 s       ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓│ 🐢 (Naive)

     ↓ RESULTS:
SHA-256: ▎ 41.5 ms ← 7x SLOWER than our JS v9!
Rust:    ▏  3.7 ms ← Gap reduced to only 1.59x!
```

---

## 📦 Installation

### npm / yarn / pnpm

```bash
npm install blake3-turbo-js

yarn add blake3-turbo-js

pnpm add blake3-turbo-js
```

### Deno

```typescript
import { blake3 } from "https://deno.land/x/blake3_turbo/mod.ts";
```

### Bun

```bash
bun add blake3-turbo-js
```

### Browser (ESM)

```html
<script type="module">
  import { blake3 } from 'https://esm.sh/blake3-turbo-js';
</script>
```

### From Source

```bash
git clone https://github.com/pskzcompern/blake3-turbo-js.git
cd blake3-turbo-js
```

#### Run BLAKE3 Tests

```bash
cd ./js
# Edit test_blake3_v0.js to use your implementation:
# import { hash, hash as blake3 } from './v9.js';
deno run test_blake3_v0.js
```

#### Run Big-Endian Tests

```bash
cd ./js
# Edit blake3_bigendian_test.ts:
# import * as blake3Module from "./v9.js";
deno test --allow-read blake3_bigendian_test.ts
```

#### Run Benchmarks

```bash
# Edit benchmark.ts to use your implementation:
# import { blake3 as jsBlake3HashV1 } from "./js/v1.js";
deno bench --allow-read --allow-import --allow-env benchmark.ts
```

---

## 🚀 Usage

### Quick Start

```typescript
import { hash, createHash, keyedHash, deriveKey, toHex } from 'blake3-turbo-js';

// One-shot hashing
const digest = hash("hello world");
console.log(toHex(digest));

// Streaming
const hasher = createHash();
hasher.update(chunk1);
hasher.update(chunk2);
const result = hasher.digest();

// Keyed hash (MAC)
const mac = keyedHash(key32bytes, message);

// Key derivation
const derived = deriveKey("my-app-v1", password);
```

### Basic Hashing

```javascript
import { blake3, toHex } from 'blake3-turbo-js';

// Hash a string
const data = new TextEncoder().encode('Hello, BLAKE3!');
const hash = blake3(data);

console.log(toHex(hash));
// → "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
```

### Hash a File (Node.js)

```javascript
import { blake3, toHex } from 'blake3-turbo-js';
import { readFileSync } from 'fs';

const fileData = readFileSync('large-file.bin');
const hash = blake3(new Uint8Array(fileData));

console.log('File hash:', toHex(hash));
```

### Hash a File (Deno)

```typescript
import { blake3, toHex } from 'blake3-turbo-js';

const fileData = await Deno.readFile('large-file.bin');
const hash = blake3(fileData);

console.log('File hash:', toHex(hash));
```

### Browser File Hashing

```html
<!DOCTYPE html>
<html>
<head>
  <title>BLAKE3 File Hasher</title>
</head>
<body>
  <input type="file" id="fileInput" />
  <pre id="result"></pre>

  <script type="module">
    import { blake3, toHex } from 'https://esm.sh/blake3-turbo-js';
    
    document.getElementById('fileInput').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      const buffer = await file.arrayBuffer();
      const data = new Uint8Array(buffer);
      
      const start = performance.now();
      const hash = blake3(data);
      const elapsed = performance.now() - start;
      
      const speed = (file.size / 1024 / 1024 / (elapsed / 1000)).toFixed(1);
      
      document.getElementById('result').textContent = 
        `Hash: ${toHex(hash)}\nTime: ${elapsed.toFixed(2)} ms\nSpeed: ${speed} MB/s`;
    });
  </script>
</body>
</html>
```

### Streaming API

```javascript
import { createHash, toHex } from 'blake3-turbo-js';

// Process data in chunks (useful for large files)
const hasher = createHash();

hasher.update(chunk1);
hasher.update(chunk2);
hasher.update(chunk3);

const hash = hasher.digest();
console.log(toHex(hash));
```

### Keyed Hashing (MAC)

```javascript
import { keyedHash, toHex } from 'blake3-turbo-js';

// 32-byte key
const key = new Uint8Array(32);
crypto.getRandomValues(key);

const message = new TextEncoder().encode('Authenticate this message');
const mac = keyedHash(key, message);

console.log('MAC:', toHex(mac));
```

### Key Derivation (KDF)

```javascript
import { deriveKey, toHex } from 'blake3-turbo-js';

// Derive a key from a password
const context = "my-app-v1 encryption key";
const password = new TextEncoder().encode('user-password');

const derivedKey = deriveKey(context, password);
console.log('Derived key:', toHex(derivedKey));
```

### Verify Data Integrity

```javascript
import { blake3, toHex } from 'blake3-turbo-js';

// Original data
const original = new TextEncoder().encode('Important data');
const originalHash = toHex(blake3(original));

// Verify after transmission/storage
const received = new TextEncoder().encode('Important data');
const receivedHash = toHex(blake3(received));

if (originalHash === receivedHash) {
  console.log('✅ Data integrity verified!');
} else {
  console.log('❌ Data has been corrupted!');
}
```

---

## 📊 Benchmarks

### Apple M4 Max (Node.js v22)

| Input Size | Throughput | vs @noble/hashes |
|------------|------------|------------------|
| 96 B       | 224 MB/s   | 5× faster        |
| 512 B      | 426 MB/s   | 7× faster        |
| 1 KB       | 465 MB/s   | 8× faster        |
| 32 KB      | **1.20 GB/s** | 24× faster    |
| 64 KB      | **1.20 GB/s** | 23× faster    |
| 256 KB     | **1.6 GB/s**  | 26× faster    |
| 1 MB       | **1.6 GB/s**  | 26× faster    |

### Intel Core i7 2.2 GHz 6-Core (MacBook Pro, 32 GB DDR4)

| Input Size | Throughput | Ops/sec |
|------------|------------|---------|
| 1 KB       | 305 MB/s   | 312,516 |
| 32 KB      | 720 MB/s   | 23,046  |
| 1 MB       | **845 MB/s** | 845   |

### Apple M4 Pro (macOS)

| Input Size | Throughput |
|------------|------------|
| 96 bytes   | ~40 MB/s   |
| 512 bytes  | ~224 MB/s  |
| 1 KiB      | ~811 MB/s  |
| 32 KiB     | ~958 MB/s  |
| 64 KiB     | ~1000 MB/s |
| 256 KiB    | ~972 MB/s  |
| 1 MB       | ~978 MB/s  |

### Intel Core i3-5005U @ 2.00GHz (Linux x64, Deno 2.5.6)

| Implementation | Time (1 MB) | Throughput | Comparison |
|----------------|-------------|------------|------------|
| **blake3-turbo-js v9** | **5.9 ms** | **170 MB/s** | **baseline** |
| BLAKE3-Rust (WASM) | 3.7 ms | 270 MB/s | 1.59x faster |
| SHA-256 (Node.js native C++) | 41.5 ms | 24 MB/s | **7x slower** |
| @noble/hashes blake3 | 55.2 ms | 18 MB/s | **9.4x slower** |

### Summary

```
BLAKE3-Rust [crypto] 1MB
   1.58x faster than blake3-turbo-js v9
   1.76x faster than blake3-turbo-js v8
  11.14x faster than SHA-256 [crypto]
  14.84x faster than @noble/hashes
  59.02x faster than naive implementation v1
   5470x faster than naive implementation v0
```

Run `deno bench` or `npm run bench` to test on your machine.

### Optimization Journey

| Version | Time (1MB) | Speedup | Key Optimization |
|---------|------------|---------|------------------|
| v0 | 20.4 s | — | Naive implementation |
| v1 | 219.6 ms | 93x | Optimized byte reading |
| v2 | 95.2 ms | 2.3x | Precomputed permutations |
| v3 | 81.7 ms | 1.17x | Inlined rounds |
| v4 | 65.2 ms | 1.25x | State in CPU registers (SMI) |
| **v5** | **9.9 ms** | **6.6x** | **Zero-copy compress** |
| v6 | 7.5 ms | 1.32x | Message in registers |
| v7 | 7.3 ms | 1.03x | Buffer reuse, no allocations |
| v8 | 6.5 ms | 1.12x | Little-endian zero-copy |
| **v9** | **5.9 ms** | **1.10x** | **WASM SIMD (i32x4)** |

**Total speedup: 3458x** (from 20.4 seconds to 5.9 milliseconds)

---

## 📖 API Reference

### `blake3(input: Uint8Array): Uint8Array`

Computes the BLAKE3 hash of the input data.

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | `Uint8Array` | Data to hash (any length from 0 to 2^64 bytes) |

**Returns:** `Uint8Array` — 32-byte (256-bit) hash

```javascript
import { blake3 } from 'blake3-turbo-js';

const hash = blake3(new Uint8Array([0x61, 0x62, 0x63])); // "abc"
```

---

### `hash(input: string | Uint8Array, options?: { length?: number }): Uint8Array`

Flexible hashing function that accepts strings directly.

```javascript
import { hash } from 'blake3-turbo-js';

const digest = hash("hello world");
const shortHash = hash("hello", { length: 16 }); // 16 bytes
```

---

### `createHash(): Hash`

Creates a streaming hasher for incremental hashing.

```javascript
import { createHash } from 'blake3-turbo-js';

const hasher = createHash();
hasher.update(chunk1);
hasher.update(chunk2);
const digest = hasher.digest();
```

---

### `keyedHash(key: Uint8Array, input: string | Uint8Array): Uint8Array`

Keyed hashing for message authentication (MAC).

```javascript
import { keyedHash } from 'blake3-turbo-js';

const key = new Uint8Array(32); // 32-byte key
const mac = keyedHash(key, "message to authenticate");
```

---

### `createKeyed(key: Uint8Array): Hash`

Creates a keyed streaming hasher.

```javascript
import { createKeyed } from 'blake3-turbo-js';

const hasher = createKeyed(key32bytes);
hasher.update(data);
const mac = hasher.digest();
```

---

### `deriveKey(context: string, material: string | Uint8Array): Uint8Array`

Key derivation function (KDF) for deriving keys from passwords or other material.

```javascript
import { deriveKey } from 'blake3-turbo-js';

const encryptionKey = deriveKey("my-app-v1 encryption", password);
const signingKey = deriveKey("my-app-v1 signing", password);
```

---

### `toHex(bytes: Uint8Array): string`

Convert bytes to hexadecimal string.

```javascript
import { blake3, toHex } from 'blake3-turbo-js';

console.log(toHex(blake3(data))); // "6437b3ac..."
```

---

### `fromHex(hex: string): Uint8Array`

Convert hexadecimal string to bytes.

```javascript
import { fromHex } from 'blake3-turbo-js';

const bytes = fromHex("6437b3ac38465133...");
```

---

### `initWasm(): Promise<void>`

Explicitly initialize the WASM SIMD module (optional, auto-initializes on first use ~1ms).

```javascript
import { initWasm, blake3 } from 'blake3-turbo-js';

await initWasm(); // Pre-initialize
const hash = blake3(data); // No init overhead
```

---

### `wasmSupported: boolean`

Indicates whether WASM SIMD is available.

```javascript
import { wasmSupported } from 'blake3-turbo-js';

if (wasmSupported) {
  console.log('🚀 WASM SIMD enabled!');
} else {
  console.log('⚠️ Falling back to pure JS');
}
```

---

## 🔧 TypeScript Support

Full TypeScript definitions included:

```typescript
import { 
  blake3, hash, createHash, keyedHash, createKeyed,
  deriveKey, toHex, fromHex, initWasm, wasmSupported 
} from 'blake3-turbo-js';

const digest: Uint8Array = blake3(new TextEncoder().encode('hello'));
const hex: string = toHex(digest);
```

---

## 🏗️ How It Works

The library automatically picks the best strategy based on input size:

- **Small inputs** → SIMD-accelerated compression (~450 MB/s)
- **Large inputs** → 4-way parallel chunks (~1.6 GB/s)

For large data, we process 4 independent chunks simultaneously. BLAKE3's Merkle tree makes chunks independent—we interleave them across the four lanes of each 128-bit SIMD register. One `i32x4.add` = four additions.

**No `.wasm` files to load.** The bytecode is generated programmatically at startup (~1ms).

### Algorithm Overview

BLAKE3 processes data in **1024-byte chunks**, each split into **16 blocks of 64 bytes**. Each block goes through a compression function with **7 rounds** of ARX (Add-Rotate-XOR) mixing operations.

```
INPUT DATA
    │
    ▼
Split into CHUNKS (1024 bytes = 16 blocks × 64 bytes)
    │
    ├──────────┬──────────┐
    ▼          ▼          ▼
 Chunk 0    Chunk 1    Chunk N    ← SIMD parallel processing
    │          │          │
    ▼          ▼          ▼
   CV0        CV1        CVN
    │          │          │
    └────┬─────┴────┬─────┘
         ▼          ▼
      PARENT     PARENT           ← Merkle tree merge
         │          │
         └────┬─────┘
              ▼
            ROOT
              │
              ▼
         HASH (32 bytes)
```

### The G Function (Core of BLAKE3)

```
G(a, b, c, d, mx, my):
    a = a + b + mx
    d = (d ⊕ a) >>> 16
    c = c + d
    b = (b ⊕ c) >>> 12
    a = a + b + my
    d = (d ⊕ a) >>> 8
    c = c + d
    b = (b ⊕ c) >>> 7
```

### Optimization Techniques

1. **Local Variables Over Arrays** — JIT keeps values in CPU registers
2. **Zero-Copy Operations** — Offsets and views instead of copying
3. **Little-Endian Fast Path** — Direct `Uint32Array` view (99% of platforms)
4. **Buffer Reuse** — Pre-allocated, reused across operations
5. **Inline Permutations** — Variable swaps instead of array lookups
6. **4-Way SIMD Parallelism** — Process 4 chunks simultaneously

---

## 🧠 Why BLAKE3?

BLAKE3 is a cryptographic hash function designed in 2020 by:
- **Jack O'Connell** (Keybase)
- **Jean-Philippe Aumasson** (author of BLAKE, BLAKE2, Argon2)
- **Samuel Neves** (University of Coimbra)
- **Zooko Wilcox-O'Hearn** (Zcash founder)

### Comparison with Other Hash Functions

| Feature | BLAKE3 | SHA-256 | SHA-3 | BLAKE2 | MD5 |
|---------|--------|---------|-------|--------|-----|
| Speed (software) | ⚡⚡⚡ | ⚡ | ⚡ | ⚡⚡ | ⚡⚡ |
| Parallelizable | ✅ Yes | ❌ No | ❌ No | ❌ No | ❌ No |
| Rounds | 7 | 64 | 24 | 10-12 | 64 |
| Output size | 1-∞ bytes | 32 bytes | 1-∞ | 1-64 | 16 |
| Security (bits) | 256 | 256 | 256 | 256 | ❌ Broken |
| Year | 2020 | 2001 | 2015 | 2012 | 1992 |

### Key Advantages

- **Only 7 rounds** (vs 64 in SHA-256)
- **ARX operations** — no S-boxes, cache-timing resistant
- **Built-in parallelism** — Merkle tree, SIMD-friendly
- **Versatile** — hash, MAC, KDF, XOF in one function
- **256-bit security** — quantum-resistant for pre-image

---

## 📁 Project Structure

| File | Purpose |
|------|---------|
| `js/v0.js` – `js/v9.js` | Implementation versions (v9 = fastest) |
| `js/test_blake3_v0.js` | BLAKE3 correctness tests |
| `js/blake3_bigendian_test.ts` | Big-endian compatibility tests |
| `benchmark.ts` | Performance benchmarks |
| `examples/` | Node.js, HTML, browser demos |

---

## 🌐 Platform Support

| Platform | Supported | WASM SIMD |
|----------|-----------|-----------|
| Node.js 16+ | ✅ | ✅ |
| Deno | ✅ | ✅ |
| Bun | ✅ | ✅ |
| Chrome 91+ | ✅ | ✅ |
| Firefox 89+ | ✅ | ✅ |
| Safari 16.4+ | ✅ | ✅ |
| Edge 91+ | ✅ | ✅ |

When WASM SIMD is unavailable, the library automatically falls back to optimized pure JavaScript.

---

## 🧪 Test Vectors

Verified against **3119 official BLAKE3 test vectors**:

| Input | Expected Hash |
|-------|---------------|
| `""` (empty) | `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262` |
| `"abc"` | `6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85` |
| `0x00` (1 byte) | `2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213` |

---

## 🤝 Contributing

Contributions welcome! Ideas:

- [ ] XOF support (extended output)
- [ ] Further SIMD optimizations
- [ ] ARM NEON support
- [ ] Worker thread parallelism
- [ ] More platform benchmarks

---

## 📚 References

- [BLAKE3 Specification (PDF)](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3) — Reference implementations
- [BLAKE3 JS Bounty by Zooko](https://x.com/zooko/status/1998185559542657145)
- [Fleek Network Case Study](https://web.archive.org/web/20250320125147/https://blog.fleek.network/post/fleek-network-blake3-case-study/)

---

## 📄 License

MIT © 2024 [pskzcompern](https://github.com/pskzcompern)

---

## 🙏 Acknowledgments

- **BLAKE3 team** — for the amazing hash function
- **Zooko Wilcox-O'Hearn** — for the bounty and motivation
- **Fleek Network** — for optimization insights

---

<div align="center">

**If you find this useful, please ⭐ star the repo!**

Made with ⚡ and mass amounts of ☕

[Report Bug](https://github.com/pskzcompern/blake3-turbo-js/issues) •
[Request Feature](https://github.com/pskzcompern/blake3-turbo-js/issues)

</div>
```
