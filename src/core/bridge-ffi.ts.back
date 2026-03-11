/***************************************************************************
 * XyPriss Security Core - Runtime Agnostic FFI Bridge (Bun & Node.js)
 ****************************************************************************/

import { join } from "path";

// 1. Runtime Detection
const isBun = typeof Bun !== "undefined";

// 2. Locate Shared Library
const extension =
  process.platform === "win32"
    ? ".dll"
    : process.platform === "darwin"
      ? ".dylib"
      : ".so";
const libPath = join(
  process.cwd(),
  `lib/security-core/libxypriss_core${extension}`,
);

// 3. FFI Provider Setup
let lib: any;
let nativePtr: (val: any) => any;
let nativeFree: (ptr: any) => void;
let getStr: (ptr: any) => string;

if (isBun) {
  // --- Bun Implementation ---
  const { dlopen, FFIType, ptr, CString } = require("bun:ffi");

  lib = dlopen(libPath, {
    FreeString: { args: [FFIType.ptr], returns: FFIType.void },
    HashPassword: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.i32, FFIType.i32, FFIType.i32],
      returns: FFIType.ptr,
    },
    VerifyPassword: { args: [FFIType.ptr, FFIType.ptr], returns: FFIType.int },
    GeneratePassword: {
      args: [FFIType.i32, FFIType.ptr],
      returns: FFIType.ptr,
    },
    GetRandomBytes: { args: [FFIType.i32], returns: FFIType.ptr },
    GetRandomInt: { args: [FFIType.i64], returns: FFIType.i64 },
    GenerateOTP: { args: [FFIType.i32], returns: FFIType.ptr },
    GetSHA256: { args: [FFIType.ptr, FFIType.i32], returns: FFIType.ptr },
    GetHash: {
      args: [FFIType.ptr, FFIType.i32, FFIType.ptr],
      returns: FFIType.ptr,
    },
    GetHMAC: {
      args: [FFIType.ptr, FFIType.i32, FFIType.ptr, FFIType.i32, FFIType.ptr],
      returns: FFIType.ptr,
    },
    HKDF: {
      args: [
        FFIType.ptr,
        FFIType.i32,
        FFIType.ptr,
        FFIType.i32,
        FFIType.ptr,
        FFIType.i32,
        FFIType.i32,
      ],
      returns: FFIType.ptr,
    },
    PBKDF2: {
      args: [
        FFIType.ptr,
        FFIType.ptr,
        FFIType.i32,
        FFIType.i32,
        FFIType.i32,
        FFIType.ptr,
      ],
      returns: FFIType.ptr,
    },
    ConstantTimeCompare: {
      args: [FFIType.ptr, FFIType.i32, FFIType.ptr, FFIType.i32],
      returns: FFIType.int,
    },
    Encrypt: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.ptr],
      returns: FFIType.ptr,
    },
    Decrypt: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.ptr],
      returns: FFIType.ptr,
    },
    EncryptRaw: {
      args: [FFIType.ptr, FFIType.i32, FFIType.ptr, FFIType.i32, FFIType.ptr],
      returns: FFIType.ptr,
    },
    DecryptRaw: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.i32],
      returns: FFIType.ptr,
    },
    KyberGenerateKeyPair: { args: [], returns: FFIType.ptr },
    GenerateX25519KeyPair: { args: [], returns: FFIType.ptr },
    DeriveSharedSecretX25519: {
      args: [FFIType.ptr, FFIType.ptr],
      returns: FFIType.ptr,
    },
    SampleLWEError: { args: [], returns: FFIType.int },
  });

  nativePtr = ptr;
  nativeFree = (p) => lib.symbols.FreeString(p);
  getStr = (p) => new CString(p).toString();
} else {
  // --- Node.js Implementation (Koffi) ---
  const koffi = require("koffi");
  lib = koffi.load(libPath);

  const symbols = {
    FreeString: lib.func("void FreeString(void *)"),
    HashPassword: lib.func(
      "char * HashPassword(const char *, const char *, int, int, int)",
    ),
    VerifyPassword: lib.func("int VerifyPassword(const char *, const char *)"),
    GeneratePassword: lib.func("char * GeneratePassword(int, const char *)"),
    GetRandomBytes: lib.func("char * GetRandomBytes(int)"),
    GetRandomInt: lib.func("int64_t GetRandomInt(int64_t)"),
    GenerateOTP: lib.func("char * GenerateOTP(int)"),
    GetSHA256: lib.func("char * GetSHA256(const void *, int)"),
    GetHash: lib.func("char * GetHash(const void *, int, const char *)"),
    GetHMAC: lib.func(
      "char * GetHMAC(const void *, int, const void *, int, const char *)",
    ),
    HKDF: lib.func(
      "char * HKDF(const void *, int, const void *, int, const void *, int, int)",
    ),
    PBKDF2: lib.func(
      "char * PBKDF2(const char *, const void *, int, int, int, const char *)",
    ),
    ConstantTimeCompare: lib.func(
      "int ConstantTimeCompare(const void *, int, const void *, int)",
    ),
    Encrypt: lib.func(
      "char * Encrypt(const char *, const char *, const char *)",
    ),
    Decrypt: lib.func(
      "char * Decrypt(const char *, const char *, const char *)",
    ),
    EncryptRaw: lib.func(
      "char * EncryptRaw(const void *, int, const void *, int, const char *)",
    ),
    DecryptRaw: lib.func(
      "char * DecryptRaw(const char *, const void *, const char *, int)",
    ),
    KyberGenerateKeyPair: lib.func("char * KyberGenerateKeyPair()"),
    GenerateX25519KeyPair: lib.func("char * GenerateX25519KeyPair()"),
    DeriveSharedSecretX25519: lib.func(
      "char * DeriveSharedSecretX25519(const char *, const char *)",
    ),
    SampleLWEError: lib.func("int SampleLWEError()"),
  };

  lib.symbols = symbols;
  nativePtr = (val) => val;
  nativeFree = () => {}; // Node mode handles it safely via automated string conversion
  getStr = (p) => p;
}

/**
 * Common handler for Go-allocated strings
 */
function handleGoString(resPtr: any): string {
  if (!resPtr) return "";
  const str = getStr(resPtr);
  try {
    nativeFree(resPtr);
  } catch (e) {}
  return str;
}

/**
 * Standard Bridge Interface
 */
export const Bridge = {
  hashPassword: (
    pass: string,
    algo: string = "argon2id",
    iterations: number = 0,
    memory: number = 0,
    parallelism: number = 0,
  ) =>
    handleGoString(
      lib.symbols.HashPassword(
        nativePtr(Buffer.from(pass + "\0")),
        nativePtr(Buffer.from(algo + "\0")),
        iterations,
        memory,
        parallelism,
      ),
    ),

  verifyPassword: (pass: string, hash: string) =>
    lib.symbols.VerifyPassword(
      nativePtr(Buffer.from(pass + "\0")),
      nativePtr(Buffer.from(hash + "\0")),
    ) === 1,

  generatePassword: (len: number, charset: string = "") =>
    handleGoString(
      lib.symbols.GeneratePassword(len, nativePtr(Buffer.from(charset + "\0"))),
    ),

  getRandomBytes: (len: number) => {
    const hex = handleGoString(lib.symbols.GetRandomBytes(len));
    if (hex.startsWith("error:")) throw new Error(hex);
    const matches = hex.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
  },

  getRandomInt: (max: number) => {
    const val = lib.symbols.GetRandomInt(isBun ? BigInt(max) : max);
    return Number(val);
  },

  generateOTP: (digits: number) =>
    handleGoString(lib.symbols.GenerateOTP(digits)),

  hash: (data: string | Uint8Array, algo: string = "sha256") => {
    const buf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(
      lib.symbols.GetHash(
        nativePtr(buf),
        buf.length,
        nativePtr(Buffer.from(algo + "\0")),
      ),
    );
  },

  sha256: (data: string | Uint8Array) => {
    const buf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(lib.symbols.GetSHA256(nativePtr(buf), buf.length));
  },

  hmac: (
    key: string | Uint8Array,
    data: string | Uint8Array,
    algo: string = "sha256",
  ) => {
    const kBuf = typeof key === "string" ? Buffer.from(key) : Buffer.from(key);
    const dBuf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(
      lib.symbols.GetHMAC(
        nativePtr(kBuf),
        kBuf.length,
        nativePtr(dBuf),
        dBuf.length,
        nativePtr(Buffer.from(algo + "\0")),
      ),
    );
  },

  hkdf: (
    ikm: string | Uint8Array,
    salt: string | Uint8Array,
    info: string | Uint8Array,
    len: number,
  ) => {
    const iBuf = typeof ikm === "string" ? Buffer.from(ikm) : Buffer.from(ikm);
    const sBuf =
      typeof salt === "string" ? Buffer.from(salt) : Buffer.from(salt);
    const fBuf =
      typeof info === "string" ? Buffer.from(info) : Buffer.from(info);
    return handleGoString(
      lib.symbols.HKDF(
        nativePtr(iBuf),
        iBuf.length,
        nativePtr(sBuf),
        sBuf.length,
        nativePtr(fBuf),
        fBuf.length,
        len,
      ),
    );
  },

  pbkdf2: (
    pass: string,
    salt: Uint8Array,
    iterations: number,
    keyLen: number,
    algo: string = "sha256",
  ) => {
    return handleGoString(
      lib.symbols.PBKDF2(
        nativePtr(Buffer.from(pass + "\0")),
        nativePtr(salt),
        salt.length,
        iterations,
        keyLen,
        nativePtr(Buffer.from(algo + "\0")),
      ),
    );
  },

  constantTimeCompare: (a: Uint8Array, b: Uint8Array) => {
    return (
      lib.symbols.ConstantTimeCompare(
        nativePtr(a),
        a.length,
        nativePtr(b),
        b.length,
      ) === 1
    );
  },

  encrypt: (data: string, key: string, algo: string = "aes") =>
    handleGoString(
      lib.symbols.Encrypt(
        nativePtr(Buffer.from(data + "\0")),
        nativePtr(Buffer.from(key + "\0")),
        nativePtr(Buffer.from(algo + "\0")),
      ),
    ),

  decrypt: (encrypted: string, key: string, algo: string = "aes") =>
    handleGoString(
      lib.symbols.Decrypt(
        nativePtr(Buffer.from(encrypted + "\0")),
        nativePtr(Buffer.from(key + "\0")),
        nativePtr(Buffer.from(algo + "\0")),
      ),
    ),

  encryptRaw: (data: Uint8Array, key: Uint8Array, algo: string = "aes") => {
    const dBuf = Buffer.from(data);
    const kBuf = Buffer.from(key);
    return handleGoString(
      lib.symbols.EncryptRaw(
        nativePtr(dBuf),
        dBuf.length,
        nativePtr(kBuf),
        kBuf.length,
        nativePtr(Buffer.from(algo + "\0")),
      ),
    );
  },

  decryptRaw: (encryptedHex: string, key: Uint8Array, algo: string = "aes") => {
    const kBuf = Buffer.from(key);
    return handleGoString(
      lib.symbols.DecryptRaw(
        nativePtr(Buffer.from(encryptedHex + "\0")),
        nativePtr(kBuf),
        nativePtr(Buffer.from(algo + "\0")),
        kBuf.length,
      ),
    );
  },

  kyberGenerateKeyPair: () =>
    handleGoString(lib.symbols.KyberGenerateKeyPair()),
  generateX25519KeyPair: () =>
    handleGoString(lib.symbols.GenerateX25519KeyPair()),
  deriveSharedSecretX25519: (priv: string, pub: string) =>
    handleGoString(
      lib.symbols.DeriveSharedSecretX25519(
        nativePtr(Buffer.from(priv + "\0")),
        nativePtr(Buffer.from(pub + "\0")),
      ),
    ),
  sampleLWEError: () => lib.symbols.SampleLWEError(),
};
