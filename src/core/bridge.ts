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
    args: [FFIType.ptr, FFIType.ptr],
    returns: FFIType.ptr,
  },
  VerifyPassword: {
    args: [FFIType.ptr, FFIType.ptr],
    returns: FFIType.int,
  },
  GeneratePassword: {
    args: [FFIType.i32],
    returns: FFIType.ptr,
  },
  GetRandomBytes: {
    args: [FFIType.i32],
    returns: FFIType.ptr,
  },
  GetSHA256: {
    args: [FFIType.ptr, FFIType.i32],
    returns: FFIType.ptr,
  },
  GetHMAC: {
    args: [FFIType.ptr, FFIType.i32, FFIType.ptr, FFIType.i32],
    returns: FFIType.ptr,
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
  hashPassword: (pass: string, algo: string = "argon2id") =>
    handleGoString(
      lib.symbols.HashPassword(
        ptr(Buffer.from(pass + "\0")),
        ptr(Buffer.from(algo + "\0")),
      ),
    ),

  verifyPassword: (pass: string, hash: string) =>
    lib.symbols.VerifyPassword(
      ptr(Buffer.from(pass + "\0")),
      ptr(Buffer.from(hash + "\0")),
    ) === 1,

  generatePassword: (len: number) =>
    handleGoString(lib.symbols.GeneratePassword(len)),

  getRandomBytes: (len: number) => {
    const hex = handleGoString(lib.symbols.GetRandomBytes(len));
    if (hex.startsWith("error:")) throw new Error(hex);
    // Convert hex back to Uint8Array
    const matches = hex.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
  },

  // Crypto Primitives
  sha256: (data: string | Uint8Array) => {
    const buf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(lib.symbols.GetSHA256(ptr(buf), buf.length));
  },

  hmac: (key: string | Uint8Array, data: string | Uint8Array) => {
    const kBuf = typeof key === "string" ? Buffer.from(key) : Buffer.from(key);
    const dBuf =
      typeof data === "string" ? Buffer.from(data) : Buffer.from(data);
    return handleGoString(
      lib.symbols.GetHMAC(ptr(kBuf), kBuf.length, ptr(dBuf), dBuf.length),
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
  sampleLWEError: () => lib.symbols.SampleLWEError(),
};
