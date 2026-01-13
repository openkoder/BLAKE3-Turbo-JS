// Code generator for v4
const w = console.log;

function rightRotate(x, y, r) {
  w(`  s_${x} ^= s_${y};`);
  w(`  s_${x} = (s_${x} >>> ${r}) | (s_${x} << ${32 - r});`);
}

function gHalf(a, b, c, d, dRot, bRot) {
  w(`  s_${a} = (((s_${a} + s_${b}) | 0) + m[PERMUTATIONS[p++]]) | 0;`);
  rightRotate(d, a, dRot);
  w(`  s_${c} = (s_${c} + s_${d}) | 0;`);
  rightRotate(b, c, bRot);
}

function g(a, b, c, d) {
  gHalf(a, b, c, d, 16, 12);
  gHalf(a, b, c, d, 8, 7);
}

// Generate initialization
for (let i = 0; i < 8; ++i) {
  w(`let s_${i} = cv[${i}] | 0;`);
}
w(`let s_8 = 0x6A09E667;`);
w(`let s_9 = 0xBB67AE85;`);
w(`let s_10 = 0x3C6EF372;`);
w(`let s_11 = 0xA54FF53A;`);
w(`let s_12 = counter | 0;`);
w(`let s_13 = (counter / 0x100000000) | 0;`);
w(`let s_14 = blockLen | 0;`);
w(`let s_15 = flags | 0;`);

// Generate 7 rounds
w(`let p = 0;`);
w(`for (let r = 0; r < 7; ++r) {`);
// Columns
g(0, 4, 8, 12);
g(1, 5, 9, 13);
g(2, 6, 10, 14);
g(3, 7, 11, 15);
// Diagonals
g(0, 5, 10, 15);
g(1, 6, 11, 12);
g(2, 7, 8, 13);
g(3, 4, 9, 14);
w(`}`);

// Generate finalization
w(`return new Uint32Array([`);
for (let i = 0; i < 8; ++i) {
  w(`  s_${i} ^ s_${i + 8},`);
}
for (let i = 0; i < 8; ++i) {
  w(`  s_${i + 8} ^ cv[${i}],`);
}
w(`]);`);
