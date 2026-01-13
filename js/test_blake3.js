/**
 * Тесты для проверки корректности BLAKE3
 * 
 * Запуск:
 *   node test_blake3_v0.js
 *   # или
 *   deno run test_blake3_v0.js
 */

import { hash, hash as blake3 } from './v9.js';

import { VECTOR, STRING_VECTORS } from './testvec.js';

// ============================================================================
// УТИЛИТЫ
// ============================================================================

/** Конвертация Uint8Array в hex-строку */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}


// ============================================================================
// ГЕНЕРАТОР ТЕСТОВЫХ ДАННЫХ
// ============================================================================

/**
 * Генерирует тестовые данные по официальному паттерну BLAKE3
 * @param length - длина данных в байтах
 * @returns Uint8Array с паттерном i % 251
 */
export function generateTestInput(length) {
  const data = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    data[i] = i % 251;
  }
  return data;
}


// ============================================================================
// ЗАПУСК ТЕСТОВ
// ============================================================================

function runTests() {
  console.log('='.repeat(60));
  console.log('BLAKE3 Test Suite');
  console.log('='.repeat(60));
  
  let passed = 0;
  let failed = 0;

  // ========================================
  // Тест 1: Числовые векторы (паттерн i % 251)
  // ========================================
  console.log('\n📊 Pattern-based vectors (i % 251):');
  
  for (const [size, expected] of VECTOR) {
    try {
      const input = generateTestInput(size);
      const result = blake3(input);
      const resultHex = bytesToHex(result);
      
      if (resultHex === expected) {
        console.log(`✅ PASS: ${size} bytes`);
        passed++;
      } else {
        console.log(`❌ FAIL: ${size} bytes`);
        console.log(`   Expected: ${expected}`);
        console.log(`   Got:      ${resultHex}`);
        failed++;
      }
    } catch (error) {
      console.log(`💥 ERROR: ${size} bytes`);
      console.log(`   ${error.message}`);
      failed++;
    }
  }

  // ========================================
  // Тест 2: Строковые векторы
  // ========================================
  console.log('\n📝 String vectors:');
  
  for (const [str, expected] of STRING_VECTORS) {
    const displayName = str === '' ? '(empty string)' : `"${str}"`;
    
    try {
      const input = new TextEncoder().encode(str);
      const result = blake3(input);
      const resultHex = bytesToHex(result);
      
      if (resultHex === expected) {
        console.log(`✅ PASS: ${displayName}`);
        passed++;
      } else {
        console.log(`❌ FAIL: ${displayName}`);
        console.log(`   Expected: ${expected}`);
        console.log(`   Got:      ${resultHex}`);
        failed++;
      }
    } catch (error) {
      console.log(`💥 ERROR: ${displayName}`);
      console.log(`   ${error.message}`);
      failed++;
    }
  }

  // ========================================
  // Итоги
  // ========================================
  console.log('\n' + '='.repeat(60));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(60));
  
  if (failed > 0) {
    console.log('\n⚠️  Some tests failed!');
    // Для Deno используем Deno.exit, для Node — process.exitCode
    if (typeof Deno !== 'undefined') {
      Deno.exit(1);
    } else if (typeof process !== 'undefined') {
      process.exitCode = 1;
    }
  } else {
    console.log('\n🎉 All tests passed!');
  }
}

// Запуск
runTests();
