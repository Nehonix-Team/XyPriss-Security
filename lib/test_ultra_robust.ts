import { dlopen, FFIType } from "bun:ffi";

const libPath = "./lib/security-core/libxypriss_core.so";

const lib = dlopen(libPath, {
  HashPassword: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.cstring,
  },
  VerifyPassword: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.int,
  },
  GetSHA256: { args: [FFIType.ptr, FFIType.int], returns: FFIType.cstring },
  GetHMAC: {
    args: [FFIType.ptr, FFIType.int, FFIType.ptr, FFIType.int],
    returns: FFIType.cstring,
  },
  SampleLWEError: { args: [], returns: FFIType.int },
});

function toCString(str: string): Buffer {
  return Buffer.from(str + "\0");
}

console.log("🛡️ --- ULTRA ROBUST SECURITY TEST ---");

// 1. Test signature $xypriss$
console.log("\n[1] Testing XyPriss Password Pattern...");
const psw = "ultra-robust-2025";
const hash = lib.symbols
  .HashPassword(toCString(psw), toCString("argon2id"))
  .toString();

console.log(`  - Generated Hash: ${hash}`);
if (hash.startsWith("$xypriss$")) {
  console.log("  - Signature Check: PASSED ✅");
} else {
  console.log("  - Signature Check: FAILED ❌");
}

const isValid = lib.symbols.VerifyPassword(toCString(psw), toCString(hash));
console.log(`  - Verification: ${isValid === 1 ? "PASSED ✅" : "FAILED ❌"}`);

// 2. Test Standalone Crypto (Replacing JS dependencies)
console.log("\n[2] Testing Standalone Go Crypto (SHA256 / HMAC)...");
const data = "XyPriss Security Core";
const dataBuf = Buffer.from(data);
const sha256 = lib.symbols.GetSHA256(dataBuf, dataBuf.length).toString();
console.log(`  - Go SHA256: ${sha256}`);

const key = "secret-key";
const keyBuf = Buffer.from(key);
const hmac = lib.symbols
  .GetHMAC(keyBuf, keyBuf.length, dataBuf, dataBuf.length)
  .toString();
console.log(`  - Go HMAC: ${hmac}`);

// 3. Test Quantum Primitives (LWE)
console.log("\n[3] Testing LWE Primitives...");
const errors = [];
for (let i = 0; i < 10; i++) errors.push(lib.symbols.SampleLWEError());
console.log(`  - LWE Error Samples: [${errors.join(", ")}]`);

console.log("\n🎯 ULTRA ROBUST CORE MODULES READY.");
