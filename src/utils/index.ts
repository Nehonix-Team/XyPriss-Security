/***************************************************************************
 * XyPriss Security - Unified Utility Hub
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

export * from "./encoding";

import { Hash, Random } from "../core/index";
import { Bridge } from "../core/bridge";

/**
 * High-performance cryptographic hashing utility.
 * Leverages the Go-backed core engine for extreme throughput and security.
 *
 * @param data - The string or byte array payload to hash.
 * @param options - Configuration options for the hashing algorithm.
 * @returns The resulting cryptographic hash in hex format.
 * @example
 * const hash = Utils.hash("sensitive data");
 */
export const hash = (data: string | Uint8Array, options?: any) =>
  Hash.create(data, options);

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

export const Utils = {
  hash,
  getRandomBytes,
  encrypt,
  decrypt,
};
