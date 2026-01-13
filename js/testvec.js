/**
 * ============================================================================
 * BLAKE3 Test Vectors
 * ============================================================================
 * 
 * Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
 * Online verification: https://connor4312.github.io/blake3/index.html
 * 
 * Format: [input_size, expected_hash]
 * 
 * Input data is generated with pattern: data[i] = i % 251
 * Special cases (strings) are listed separately.
 * 
 * /

/*
 * JS to generate input pattern
{
  const length = 127;
  const input = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    input[i] = i % 251;
  }

  // Преобразуем каждый байт в двузначное число 16-ричной системы (00, 01, ... FF)
  const hexString = Array.from(input)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  console.log("Скопируйте строку ниже:");
  console.log(hexString);
}
*/


// ============================================================================
// TEST VECTORS
// ============================================================================

/**
 * Main test vectors
 * Format: [size_in_bytes, expected_hex_hash]
 * @type {Array<[number, string]>}
 * 
 * Input data: generateTestInput(size)
 */
export const VECTOR = [
  // Edge cases
  [0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"],
  
  // Small sizes (1-8 bytes)
  [1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"],
  [2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"],
  [3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"],
  [4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"],
  [5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"],
  [6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"],
  [7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"],
  [8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"],
  
  // Block boundary (64 bytes)
  [63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"],
  [64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"],
  [65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"],
  
  // 2 blocks boundary (128 bytes)
  [127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"],
  [128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"],
  [129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"],
  
  // 3 blocks boundary (192 bytes)
  [191, "67950b54b585e93b7234229ed3a00bcba5f1fa8e6226f367e638f24916384d89"],
  [192, "4abc5d2328fb4acc549aff4b877df00ba52d469757749d6b8c33d45870b8fcff"],
  [193, "a8934f0168769c388914ee5c2de61aefbdd6251c9d7e658068e348f6b8bd0a29"],
  
  // 4 blocks boundary (256 bytes)
  [255, "cb97b80a66306dd2d4f1ab7ff9fd17d3d62d88c974e8daf0ea9fbd0b1ae1b1c1"],
  [256, "f462b63aae56ed9fb899ad8eb93aa35d3dd62773fda9c33bfe20f9dab5d3df5f"],
  [257, "3d41df314e2c7af6919d994b391780a7d8abb9a57b1abf64e04ec5d49428788e"],
  
  // 5 blocks boundary (320 bytes)
  [319, "ce21e90a76c4a57b80f99c50c0d56383ecd85085809b525491ec2b66d8cfe5cc"],
  [320, "903c2e3b10f271075910c05a2b30c67a140badf0c5dc6d3eb3875fba46eb19a9"],
  [321, "de9dd4aa73bfecbbed26046a57fd344e2cb6c21bde3db2188b7ac1437b4cc622"],
  
  // 6 blocks boundary (384 bytes)
  [383, "bcd1c37d3184f20bad0761a8b59afec3127ee5cb7c80fae2a3ca5d8f3b32d468"],
  [384, "811d13da83e9d2e69f23267993a93f263170d619bd89a2ef891a9768f2a50631"],
  [385, "a782f0b55f9ab29cd46aef1151a19d89ba213cd27fae75c0dc8b7df3e9f8668b"],
  
  // 7 blocks boundary (448 bytes)
  [447, "9e4464e6b8a43e3a0ac0bf2566567a11bbbddce001c2499ae5a62713fdb9ba36"],
  [448, "5123acf08d1fbeeebf4100da5ecbc6f19dc8d210ca53b5b014685f214563fb84"],
  [449, "68daf47c78621b4c8d962803c79b82e07155aa30b32bd1a26ccd66b4bc2f16df"],
  
  // 8 blocks boundary (512 bytes)
  [511, "7469b385b5290a1011288fc80a7fdb8677497dbc1d3b6daf93667725f68708f5"],
  [512, "87aa0321ee04decf72d6fe8d5799d6216db538c0da4a367d6d456643e9ea7994"],
  [513, "8e89cd63966193dfaecf124fe5893bf609aba748067b321afadc974d58374498"],
  
  // 9 blocks boundary (576 bytes)
  [575, "25637e6b978882dff2b1da5bbb12f65ee48e544e70b8d04d4f0c4f7b147939dd"],
  [576, "60b70fd3325e647bb99d4e69ed42b9d33f00f29e0e441a272ecdbeb858461c1c"],
  [577, "ce2349308e0aa503b4291bbab650da2b5544b27e873e68f961252cf16aa1be96"],
  
  // 10 blocks boundary (640 bytes)
  [639, "5f69abf86b748d9d289de6764f199cf5814ad97151b6d2b3037f07e468fccab4"],
  [640, "29dbeca150847d06d0470f2aee46a85bacaa3361375ff0e33124a19c574ade0f"],
  [641, "da83dbb80e4e880e10d78e384643b6d4907c35ab7e98055ed39622b1e2ee8263"],
  
  // 11 blocks boundary (704 bytes)
  [703, "61873102398553a36bbdd6c805cff83471da71ab4521305cd9724420e865b6a0"],
  [704, "907676c7892936c58b2ba0c3c9655aaee7189c3f4a5114780a5a117806b06314"],
  [705, "c8ff8ecd3915e88b63f696cae50fc540319ec7b9abeda5d409b14b2c2939276e"],
  
  // 12 blocks boundary (768 bytes)
  [767, "6d8cf1ac522e7abdbc5afa1d7b8516ee4a3e1700fd7dabf390376ba11a4ad26a"],
  [768, "fb888f4f3827814595f4f71391ac2fbf4d3d78a136f5b5226bb4a04fa94f624f"],
  [769, "5aa9007aa5cef8a69351dd3e4e6825c96b48913059f8c88676fff9b1834d263f"],
  
  // 13 blocks boundary (832 bytes)
  [831, "ffce0f39cd0d42aab300d8e0adb22a7a9f4d922f8583eaf90e5efba9a7960b00"],
  [832, "4a9410e39c8d26e16ad25638b211c87a13c0eb5a38e6c4ad906026a8b9aac20b"],
  
  // Chunk boundary (1024 bytes = 16 blocks)
  [1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"],
  [1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"],
  [1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"],
  
  // Multiple chunks
  [2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"],
  [2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"],
  [3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"],
  [3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"],
  [4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"],
  [8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"],
  [16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"],
  [31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"],
  [102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085"],
  
   //More
  [833, "fd8a1f8ebc61b34f562824ffe7d7f27df275e95932e0e1e7543077948c90b0d3"],
  [895, "d8f58b0507c439d9d83d21951b5db30759dd381917995ce768e02b77046575c6"],
  [896, "ebf97176a6f047d66ad1605b7618f00b9cbd664353e15c7b9aa242fc230421c2"],
  [897, "3ca417aa14b1955eaadc0a5aee524316757504a21781cd26f408abe7f6ff99c8"],
  [959, "87a466d37769edb980266201709499d2d1a6d6d6ea9667b22424d4f2c3f8db47"],
  [960, "ccc77ee941c7c4ea0371d55fc11949b3d2ceb886e441efa5604565c1e1b1b643"],
  [961, "e78a4911bd8d3a1e2018053b9d89d4abe2ca86af1305bf1dce1e8310ec2ec7f0"],
  [66497, "376b17655308e84079e3ca285b80b24cc8c64d5a73fba1bada87b5809df7d998"],
];

// ============================================================================
// SPECIAL TEST CASES (strings)
// ============================================================================

/**
 * String-based tests
 * Format: [string, expected_hex_hash]
 * @type {Array<[string, string]>}
 */
export const STRING_VECTORS = [
  ["", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"],
  ["hello world", "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"],
  ["BLAKE3", "f890484173e516bfd935ef3d22b912dc9738de38743993cfedf2c9473b3216a4"],
];
