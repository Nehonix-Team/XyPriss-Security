/***************************************************************************
 * XyPriss Security - Unified Utility Hub
 *
 * @author NEHONIX (Nehonix-Team - https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

export * from "./encoding";

import { Hash } from "../core/Hash";
import { Random } from "../core/Random";
import { Bridge } from "../core/bridge";
import {
  HashOptions,
  HashAlgorithm,
  HashBufferFormat,
  HashStringFormat,
} from "../types";
import { SecureBuffer } from "../core/SecureBuffer";

/**
 * High-performance cryptographic hashing utility.
 * Leverages the Go-backed core engine for extreme throughput and security.
 *
 * Automatically returns a `SecureBuffer` when binary output format (`"buffer"` or `"uint8array"`) is requested.
 *
 * @param data - The string or byte array payload to hash.
 * @param options - Configuration options specifying `outputFormat: "buffer" | "uint8array"`.
 * @returns A `SecureBuffer` instance wrapping the raw cryptographic hash bytes.
 *
 * @example
 * ```typescript
 * import { hash } from "xypriss-security";
 *
 * // Returns a SecureBuffer
 * const rawBuffer = hash("secret payload", { outputFormat: "buffer" });
 * console.log(rawBuffer.toUint8Array());
 * ```
 */
export function hash(
  data: string | Uint8Array,
  options: HashOptions<HashBufferFormat> & { outputFormat: HashBufferFormat },
): SecureBuffer;

/**
 * Fast cryptographic hashing with direct string truncation.
 * Ideal for generating concise unique identifiers, user IDs, or short slugs without manual `.substring()`.
 *
 * @param data - The string or byte array payload to hash.
 * @param length - Maximum character length of the resulting hex string (e.g. `12`).
 * @returns The truncated hexadecimal hash string.
 *
 * @example
 * ```typescript
 * import { hash } from "xypriss-security";
 *
 * // Produces a 12-character hex ID (e.g., "e505a1409236")
 * const userId = hash("user@example.com", 12);
 * ```
 */
export function hash(
  data: string | Uint8Array,
  length: number,
): string;

/**
 * High-performance cryptographic hashing using a specified algorithm and optional length truncation.
 *
 * @param data - The string or byte array payload to hash.
 * @param algorithm - Target cryptographic algorithm (e.g. `"sha256"`, `"blake2b"`, `"sha512"`, `"argon2id"`, `"scrypt"`).
 * @param length - Optional maximum character length to truncate the output string.
 * @returns The resulting cryptographic hash string.
 *
 * @example
 * ```typescript
 * import { hash } from "xypriss-security";
 *
 * // Standard Blake2b-256 hash (64 hex characters)
 * const blakeHash = hash("data", "blake2b");
 *
 * // Truncated SHA-512 hash (16 hex characters)
 * const shortHash = hash("data", "sha512", 16);
 * ```
 */
export function hash(
  data: string | Uint8Array,
  algorithm: HashAlgorithm,
  length?: number,
): string;

/**
 * High-performance cryptographic hashing utility with comprehensive configuration options.
 *
 * @param data - The string or byte array payload to hash.
 * @param options - Configuration options for algorithm, encoding, salt, iterations, or length.
 * @returns The resulting cryptographic hash string (hex or base64).
 *
 * @example
 * ```typescript
 * import { hash } from "xypriss-security";
 *
 * // 1. Default SHA-256 in hex
 * const hexDigest = hash("sensitive data");
 *
 * // 2. Truncated output directly in options (e.g. 12 characters for short IDs)
 * const shortId = hash("user@example.com", { length: 12 });
 *
 * // 3. Custom algorithm and Base64 output format
 * const b64 = hash("sensitive data", { algorithm: "sha512", outputFormat: "base64" });
 *
 * // 4. PBKDF2 derivation with custom salt and iteration count
 * const pbkdf2Hex = hash("myPassword", {
 *   algorithm: "pbkdf2",
 *   iterations: 100000,
 *   salt: "random_salt_16b",
 *   length: 32,
 * });
 * ```
 */
export function hash(
  data: string | Uint8Array,
  options?: HashOptions<HashStringFormat>,
): string;

/**
 * High-performance cryptographic hashing utility implementation.
 */
export function hash(
  data: string | Uint8Array,
  optionsOrAlgoOrLength?: HashOptions | HashAlgorithm | number,
  length?: number,
): string | SecureBuffer {
  return Hash.create(data, optionsOrAlgoOrLength as any, length);
}

/**
 * Generates cryptographically secure random bytes.
 * Utilizing Go's native `crypto/rand` module, it ensures true randomness
 * suitable for key generation, salts, and nonces.
 *
 * @param length - The number of bytes to generate.
 * @returns A specialized object containing the bytes and utility methods.
 * @example
 * const salt = Utils.getRandomBytes(16)
 */
export const getRandomBytes = (length: number) => {
  return Random.getRandomBytes(length);
};

/**
 * Military-grade string encryption utilizing AES-256-GCM or ChaCha20-Poly1305.
 * Designed for maximum performance with atomic Go FFI calls.
 *
 * @param data - The plaintext string to encrypt.
 * @param key - The secret key used for encryption (hex string).
 * @param algo - The target algorithm ("aes" or "chacha20").
 * @returns Encrypted payload as `nonce:tag:ciphertext` hex string.
 * @throws {Error} If key size is invalid or encryption fails.
 */
export const encrypt = (data: string, key: string, algo: string = "aes") =>
  Bridge.encrypt(data, key, algo);

/**
 * High-speed string decryption utilizing AES-256-GCM or ChaCha20-Poly1305.
 *
 * @param encrypted - The encrypted payload in hex format.
 * @param key - The secret key used for decryption (hex string).
 * @param algo - The target algorithm ("aes" or "chacha20").
 * @returns The original plaintext string.
 * @throws {Error} If authentication fails or format is corrupted.
 */
export const decrypt = (encrypted: string, key: string, algo: string = "aes") =>
  Bridge.decrypt(encrypted, key, algo);
