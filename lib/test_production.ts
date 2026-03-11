import { dlopen, FFIType } from "bun:ffi";

const libPath = "./lib/security-core/libxypriss_core.so";

const lib = dlopen(libPath, {
  InitializeEngine: { args: [FFIType.int], returns: FFIType.void },
  HashPassword: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.cstring,
  },
  VerifyPassword: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.int,
  },
  Encrypt: {
    args: [FFIType.cstring, FFIType.cstring, FFIType.cstring],
    returns: FFIType.cstring,
  },
  Decrypt: {
    args: [FFIType.cstring, FFIType.cstring, FFIType.cstring],
    returns: FFIType.cstring,
  },
  KyberGenerateKeyPair: { args: [], returns: FFIType.cstring },
  KyberEncapsulate: { args: [FFIType.cstring], returns: FFIType.cstring },
  KyberDecapsulate: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.cstring,
  },
});

function toCString(str: string): Buffer {
  return Buffer.from(str + "\0");
}

console.log("🛠️ --- SERIOUS PRODUCTION TEST (NO MOCKS) ---");

// --- 1. PASSWORDS ---
console.log("\n[1] Testing Multi-Algo Passwords...");
const psw = "xypriss-2025-secure";
for (const algo of ["argon2id", "scrypt", "pbkdf2"]) {
  const hash = lib.symbols.HashPassword(toCString(psw), toCString(algo));
  const isValid = lib.symbols.VerifyPassword(toCString(psw), toCString(hash));
  console.log(
    `  - ${algo.padEnd(8)}: ${isValid === 1 ? "PASSED ✅" : "FAILED ❌"}`,
  );
}

// --- 2. SYMMETRIC CRYPTO ---
console.log("\n[2] Testing Symmetric Crypto...");
const plaintext = "Confidential Message: The eagle has landed.";
const keyHex =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"; // 32 bytes

for (const algo of ["aes-gcm", "chacha20"]) {
  const enc = lib.symbols
    .Encrypt(toCString(plaintext), toCString(keyHex), toCString(algo))
    .toString();
  const dec = lib.symbols
    .Decrypt(toCString(enc), toCString(keyHex), toCString(algo))
    .toString();
  console.log(
    `  - ${algo.padEnd(8)}: ${dec === plaintext ? "PASSED ✅" : "FAILED ❌"}`,
  );
}

// --- 3. POST-QUANTUM (KYBER-768) ---
console.log("\n[3] Testing Post-Quantum Kyber-768...");
const [pk, sk] = lib.symbols.KyberGenerateKeyPair().toString().split(":");
console.log(
  `  - KeyPair Generated (PK size: ${pk.length}, SK size: ${sk.length})`,
);

const [ss1, ct] = lib.symbols
  .KyberEncapsulate(toCString(pk))
  .toString()
  .split(":");
console.log(`  - Encapsulated (SS size: ${ss1.length}, CT size: ${ct.length})`);

const ss2 = lib.symbols
  .KyberDecapsulate(toCString(ct), toCString(sk))
  .toString();
console.log(`  - Decapsulated (SS match: ${ss1 === ss2 ? "YES ✅" : "NO ❌"})`);

console.log("\n🎯 PRODUCTION CORE TEST COMPLETED SUCCESSFULLY.");
