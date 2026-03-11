/***************************************************************************
 * XyPriss Security Core - Bun FFI Bridge
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 ****************************************************************************/
//@ts-ignore
/// <reference types="bun-types" />
import { dlopen, FFIType, ptr, CString } from "bun:ffi";

import { join } from "path";

// Locate the shared library
const libPath = join(process.cwd(), "lib/security-core/libxypriss_core.so");

const lib = dlopen(libPath, {
  FreeString: {
    args: [FFIType.ptr],
    returns: FFIType.void,
  },
  HashPassword: {
    args: [FFIType.ptr, FFIType.ptr, FFIType.i32, FFIType.i32, FFIType.i32],
    returns: FFIType.ptr,
  },

  VerifyPassword: {
    args: [FFIType.ptr, FFIType.ptr],
    returns: FFIType.int,
  },
  GeneratePassword: {
    args: [FFIType.i32, FFIType.ptr],
    returns: FFIType.ptr,
  },

  GetRandomBytes: {
    args: [FFIType.i32],
    returns: FFIType.ptr,
  },
  GetRandomInt: {
    args: [FFIType.i64],
    returns: FFIType.i64,
  },
  GenerateOTP: {
    args: [FFIType.i32],
    returns: FFIType.ptr,
  },

  GetSHA256: {
    args: [FFIType.ptr, FFIType.i32],
    returns: FFIType.ptr,
  },
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

  KyberGenerateKeyPair: {
    args: [],
    returns: FFIType.ptr,
  },
  GenerateX25519KeyPair: {
    args: [],
    returns: FFIType.ptr,
  },
  DeriveSharedSecretX25519: {
    args: [FFIType.ptr, FFIType.ptr],
    returns: FFIType.ptr,
  },
  SampleLWEError: {
    args: [],
    returns: FFIType.int,
  },
});

/**
 * Helper to handle Go-allocated C strings
 */
function handleGoString(resPtr: any): string {
  if (!resPtr) return "";
  // In Bun FFI, if return type is FFIType.ptr, resPtr is the memory address.
  // We wrap it in CString which reads until null terminator.
  const str = new CString(resPtr).toString();

  try {
    lib.symbols.FreeString(resPtr);
  } catch (e) {}
  return str;
}

/**
 * Professional Bridge to Go Security Core
 */
export const Bridge = {
  // Passwords
  hashPassword: (
    pass: string,
    algo: string = "argon2id",
    iterations: number = 0,
    memory: number = 0,
    parallelism: number = 0,
  ) =>
    handleGoString(
      lib.symbols.HashPassword(
        ptr(Buffer.from(pass + "\0")),
        ptr(Buffer.from(algo + "\0")),
        iterations,
        memory,
        parallelism,
      ),
    ),

  verifyPassword: (pass: string, hash: string) =>
    lib.symbols.VerifyPassword(
      ptr(Buffer.from(pass + "\0")),
      ptr(Buffer.from(hash + "\0")),
    ) === 1,

  generatePassword: (len: number, charset: string = "") =>
    handleGoString(
      lib.symbols.GeneratePassword(len, ptr(Buffer.from(charset + "\0"))),
    ),

  getRandomBytes: (len: number) => {
    const hex = handleGoString(lib.symbols.GetRandomBytes(len));
    if (hex.startsWith("error:")) throw new Error(hex);
    // Convert hex back to Uint8Array
    const matches = hex.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
  },

  getRandomInt: (max: number) => {
    return Number(lib.symbols.GetRandomInt(BigInt(max)));
  },

  generateOTP: (digits: number) =>
    handleGoString(lib.symbols.GenerateOTP(digits)),

  // Crypto Primitives
  hash: (data: string | Uint8Array, algo: string = "sha256") => {
    const buf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(
      lib.symbols.GetHash(ptr(buf), buf.length, ptr(Buffer.from(algo + "\0"))),
    );
  },

  sha256: (data: string | Uint8Array) => {
    const buf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(lib.symbols.GetSHA256(ptr(buf), buf.length));
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
        ptr(kBuf),
        kBuf.length,
        ptr(dBuf),
        dBuf.length,
        ptr(Buffer.from(algo + "\0")),
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
        ptr(iBuf),
        iBuf.length,
        ptr(sBuf),
        sBuf.length,
        ptr(fBuf),
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
        ptr(Buffer.from(pass + "\0")),
        ptr(salt),
        salt.length,
        iterations,
        keyLen,
        ptr(Buffer.from(algo + "\0")),
      ),
    );
  },

  constantTimeCompare: (a: Uint8Array, b: Uint8Array) => {
    return (
      lib.symbols.ConstantTimeCompare(ptr(a), a.length, ptr(b), b.length) === 1
    );
  },

  // AES / Encryption (Legacy String)
  encrypt: (data: string, key: string, algo: string = "aes") =>
    handleGoString(
      lib.symbols.Encrypt(
        ptr(Buffer.from(data + "\0")),
        ptr(Buffer.from(key + "\0")),
        ptr(Buffer.from(algo + "\0")),
      ),
    ),

  decrypt: (encrypted: string, key: string, algo: string = "aes") =>
    handleGoString(
      lib.symbols.Decrypt(
        ptr(Buffer.from(encrypted + "\0")),
        ptr(Buffer.from(key + "\0")),
        ptr(Buffer.from(algo + "\0")),
      ),
    ),

  // AES / Encryption (Raw Binary for native Uint8Array)
  encryptRaw: (data: Uint8Array, key: Uint8Array, algo: string = "aes") => {
    const dBuf = Buffer.from(data);
    const kBuf = Buffer.from(key);
    return handleGoString(
      lib.symbols.EncryptRaw(
        ptr(dBuf),
        dBuf.length,
        ptr(kBuf),
        kBuf.length,
        ptr(Buffer.from(algo + "\0")),
      ),
    );
  },

  decryptRaw: (encryptedHex: string, key: Uint8Array, algo: string = "aes") => {
    const kBuf = Buffer.from(key);
    return handleGoString(
      lib.symbols.DecryptRaw(
        ptr(Buffer.from(encryptedHex + "\0")),
        ptr(kBuf),
        ptr(Buffer.from(algo + "\0")),
        kBuf.length,
      ),
    );
  },

  // Post-Quantum
  kyberGenerateKeyPair: () =>
    handleGoString(lib.symbols.KyberGenerateKeyPair()),

  generateX25519KeyPair: () =>
    handleGoString(lib.symbols.GenerateX25519KeyPair()),

  deriveSharedSecretX25519: (priv: string, pub: string) =>
    handleGoString(
      lib.symbols.DeriveSharedSecretX25519(
        ptr(Buffer.from(priv + "\0")),
        ptr(Buffer.from(pub + "\0")),
      ),
    ),
  sampleLWEError: () => lib.symbols.SampleLWEError(),
};
