/***************************************************************************
 * XyPriss Security Core - Runtime Agnostic Spawn Bridge (Bun & Node.js)
 * Replacing FFI with direct process execution for absolute cross-platform stability.
 ****************************************************************************/

import { join } from "path";
import { spawnSync } from "child_process";

// 1. Locate Executable
const extension = process.platform === "win32" ? ".exe" : "";

/**
 * Robust binary resolution:
 * 1. Check relative to this file (works in node_modules and local dev)
 * 2. Fallback to process.cwd() (manual setups)
 */
/**
 * Exhaustive binary resolution:
 * Tests multiple combinations of paths to find the core executable
 * regardless of the runtime environment or package manager layout.
 */
const getBinaryPath = () => {
  const fs = require("fs");
  const binaryName = `libxypriss_core${extension}`;

  const possiblePaths = [
    // 1. Production layout (from dist/src/core/bridge.js -> root/lib/security-core/...)
    join(__dirname, "..", "..", "..", "lib", "security-core", binaryName),
    // 2. Dev layout (from src/core/bridge.ts -> root/lib/security-core/...)
    join(__dirname, "..", "..", "lib", "security-core", binaryName),
    // 3. Fallback to process.cwd (useful for some monorepos)
    join(process.cwd(), "lib", "security-core", binaryName),
    // 4. Nested node_modules (if caller is at project root)
    join(
      process.cwd(),
      "node_modules",
      "xypriss-security",
      "lib",
      "security-core",
      binaryName,
    ),
    // 5. Direct sibling (for specialized build environments)
    join(__dirname, binaryName),
  ];

  for (const p of possiblePaths) {
    try {
      if (fs.existsSync(p)) {
        // Double check it's not a directory
        const stats = fs.statSync(p);
        if (stats.isFile()) return p;
      }
    } catch (e) {
      // Ignore errors for specific path checks
    }
  }

  // Final fallback (will likely throw ENOENT if reached, which is the correct behavior)
  return join(process.cwd(), "lib", "security-core", binaryName);
};

const libPath = getBinaryPath();

/**
 * Standard Bridge Interface using Spawn
 */
export const Bridge = {
  /**
   * Internal helper to call the Go binary
   */
  _call: (command: string, ...args: any[]): string => {
    const result = spawnSync(libPath, [
      command,
      ...args.map((a) => (a === null || a === undefined ? "" : String(a))),
    ]);

    if (result.error) {
      throw new Error(
        `Failed to execute security core: ${result.error.message}`,
      );
    }

    const out = result.stdout.toString();
    if (out.startsWith("error:")) {
      throw new Error(`Security Core Error (${command}): ${out.substring(6)}`);
    }
    return out;
  },

  hashPassword: (
    pass: string,
    algo: string = "argon2id",
    iterations: number = 0,
    memory: number = 0,
    parallelism: number = 0,
  ) =>
    Bridge._call("hash-password", pass, algo, iterations, memory, parallelism),

  verifyPassword: (pass: string, hash: string) =>
    Bridge._call("verify-password", pass, hash) === "1",

  isHashed: (hash: string, algo?: string) =>
    Bridge._call("is-hashed", hash, algo) === "1",

  generatePassword: (len: number, charset: string = "") =>
    Bridge._call("generate-password", len, charset),

  getRandomBytes: (len: number) => {
    const hex = Bridge._call("get-random-bytes", len);
    const matches = hex.match(/.{1,2}/g) || [];
    return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
  },

  getRandomInt: (max: number) => {
    const val = Bridge._call("get-random-int", max);
    return Number(val);
  },

  generateOTP: (digits: number) => Bridge._call("generate-otp", digits),

  hash: (data: string | Uint8Array, algo: string = "sha256") => {
    const hexData =
      typeof data === "string"
        ? Buffer.from(data).toString("hex")
        : Buffer.from(data).toString("hex");
    return Bridge._call("get-hash", hexData, algo);
  },

  sha256: (data: string | Uint8Array) => {
    const hexData =
      typeof data === "string"
        ? Buffer.from(data).toString("hex")
        : Buffer.from(data).toString("hex");
    return Bridge._call("get-sha256", hexData);
  },

  hmac: (
    key: string | Uint8Array,
    data: string | Uint8Array,
    algo: string = "sha256",
  ) => {
    const hexKey =
      typeof key === "string"
        ? Buffer.from(key).toString("hex")
        : Buffer.from(key).toString("hex");
    const hexData =
      typeof data === "string"
        ? Buffer.from(data).toString("hex")
        : Buffer.from(data).toString("hex");
    return Bridge._call("get-hmac", hexKey, hexData, algo);
  },

  hkdf: (
    ikm: string | Uint8Array,
    salt: string | Uint8Array,
    info: string | Uint8Array,
    len: number,
  ) => {
    const hexIkm =
      typeof ikm === "string"
        ? Buffer.from(ikm).toString("hex")
        : Buffer.from(ikm).toString("hex");
    const hexSalt =
      typeof salt === "string"
        ? Buffer.from(salt).toString("hex")
        : Buffer.from(salt).toString("hex");
    const hexInfo =
      typeof info === "string"
        ? Buffer.from(info).toString("hex")
        : Buffer.from(info).toString("hex");
    return Bridge._call("hkdf", hexIkm, hexSalt, hexInfo, len);
  },

  pbkdf2: (
    pass: string,
    salt: Uint8Array,
    iterations: number,
    keyLen: number,
    algo: string = "sha256",
  ) => {
    const hexSalt = Buffer.from(salt).toString("hex");
    return Bridge._call("pbkdf2", pass, hexSalt, iterations, keyLen, algo);
  },

  constantTimeCompare: (a: Uint8Array, b: Uint8Array) => {
    const hexA = Buffer.from(a).toString("hex");
    const hexB = Buffer.from(b).toString("hex");
    return Bridge._call("constant-time-compare", hexA, hexB) === "1";
  },

  encrypt: (data: string, key: string, algo: string = "aes") =>
    Bridge._call("encrypt", data, key, algo),

  decrypt: (encrypted: string, key: string, algo: string = "aes") =>
    Bridge._call("decrypt", encrypted, key, algo),

  encryptRaw: (data: Uint8Array, key: Uint8Array, algo: string = "aes") => {
    const hexData = Buffer.from(data).toString("hex");
    const hexKey = Buffer.from(key).toString("hex");
    return Bridge._call("encrypt-raw", hexData, hexKey, algo);
  },

  decryptRaw: (encryptedHex: string, key: Uint8Array, algo: string = "aes") => {
    const hexKey = Buffer.from(key).toString("hex");
    return Bridge._call("decrypt-raw", encryptedHex, hexKey, algo);
  },

  kyberGenerateKeyPair: () => Bridge._call("kyber-generate-key-pair"),
  generateX25519KeyPair: () => Bridge._call("generate-x25519-key-pair"),
  deriveSharedSecretX25519: (priv: string, pub: string) =>
    Bridge._call("derive-shared-secret-x25519", priv, pub),
  sampleLWEError: () => Number(Bridge._call("sample-lwe-error")),
  getByteLength: (str: string) => Number(Bridge._call("get-byte-length", str)),
  isValidByteLength: (str: string, length: number) =>
    Bridge._call("is-valid-byte-length", str, length) === "1",

  generateRSAKeyJSON: () => JSON.parse(Bridge._call("generate-rsa-key-json")),
  rsaSign: (privateKey: string, data: string) =>
    Bridge._call("rsa-sign", privateKey, data),
  rsaVerify: (publicKey: string, data: string, signature: string) =>
    Bridge._call("rsa-verify", publicKey, data, signature) === "1",
  rsaEncrypt: (publicKey: string, data: string) =>
    Bridge._call("rsa-encrypt", publicKey, data),
  rsaDecrypt: (privateKey: string, encryptedHex: string) =>
    Bridge._call("rsa-decrypt", privateKey, encryptedHex),
};
