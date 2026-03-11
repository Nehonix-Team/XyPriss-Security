import { dlopen, FFIType, ptr } from "bun:ffi";

// Path to the shared library
const libPath = "./lib/security-core/libxypriss_core.so";

const lib = dlopen(libPath, {
  HashPassword: {
    args: [FFIType.cstring],
    returns: FFIType.cstring,
  },
  VerifyPassword: {
    args: [FFIType.cstring, FFIType.cstring],
    returns: FFIType.int,
  },
  GeneratePassword: {
    args: [FFIType.int],
    returns: FFIType.cstring,
  },
});

console.log("--- GO REWRITE FFI TEST ---");

const password = "my-secure-password";
console.log(`Password: ${password}`);

// 1. Test Hashing
console.time("Go Argon2id Hash");
const hash = lib.symbols.HashPassword(Buffer.from(password + "\0"));
console.timeEnd("Go Argon2id Hash");
console.log(`Encoded Hash: ${hash}`);

// 2. Test Verification
console.time("Go Argon2id Verify (Correct)");
const isValid = lib.symbols.VerifyPassword(
  Buffer.from(password + "\0"),
  Buffer.from(hash + "\0"),
);
console.timeEnd("Go Argon2id Verify (Correct)");
console.log(`Is valid? ${isValid === 1 ? "YES ✅" : "NO ❌"}`);

console.time("Go Argon2id Verify (Wrong)");
const isInvalid = lib.symbols.VerifyPassword(
  Buffer.from("wrong-password\0"),
  Buffer.from(hash + "\0"),
);
console.timeEnd("Go Argon2id Verify (Wrong)");
console.log(`Is invalid valid? ${isInvalid === 1 ? "YES ✅" : "NO ❌"}`);

// 3. Test Generation
console.log("Generating 32-char password...");
const generated = lib.symbols.GeneratePassword(32);
console.log(`Generated: ${generated}`);
