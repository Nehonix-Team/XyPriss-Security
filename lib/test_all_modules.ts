import { dlopen, FFIType, ptr } from "bun:ffi";

const libPath = "./lib/security-core/libxypriss_core.so";

const lib = dlopen(libPath, {
  InitializeEngine: {
    args: [FFIType.int],
    returns: FFIType.void,
  },
  HashPassword: {
    args: [FFIType.cstring],
    returns: FFIType.cstring,
  },
  VerifyPassword: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.int,
  },
  KyberGenerateKeyPair: {
    args: [],
    returns: FFIType.cstring,
  },
  RunFullStackTest: {
    args: [],
    returns: FFIType.cstring,
  },
});

console.log("🚀 --- TESTING UNIFIED GO CORE (Engine + Quantum + Password) ---");

// 1. Initialiser le moteur Ultra-Fast (Goroutines)
console.log("Initializing Go Engine with 4 workers...");
lib.symbols.InitializeEngine(4);

// 2. Test Quantum Kyber-768
console.log("\n🧬 Testing Post-Quantum Kyber...");
console.time("Go Kyber KeyGen");
const kyberKeys = lib.symbols.KyberGenerateKeyPair();
console.timeEnd("Go Kyber KeyGen");
console.log(`Keys: ${kyberKeys}`);

// 3. Test Full Stack Concourant
// Ce test lance 4 hachages Argon2id lourds en parallèle dans le pool de workers Go
console.log(
  "\n⚡ Testing Concurrency (4x Parallel Argon2id + Quantum KeyGen)...",
);
console.time("Unified Full Stack Execution");
const testResult = lib.symbols.RunFullStackTest();
console.timeEnd("Unified Full Stack Execution");
console.log(`Result: ${testResult}`);

console.log("\n✅ All Go Modules are functional and bridged.");
