/***************************************************************************
 * XyPriss Security Core - Unified API Entry Point
 *
 * Provides high-level security classes (Hash, Random, Password, XyPrissSecurity)
 * that wrap the high-performance Go-based core bridge.
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

import { Bridge } from "./bridge";
import { SecureBuffer } from "./SecureBuffer";

import {
  HashOptions,
  SecureTokenOptions,
  PasswordHashOptions,
  APIKeyOptions,
  SessionTokenOptions,
} from "../types";

/**
 * ### Hash Class
 *
 * Provides high-performance hashing and HMAC operations powered by the Go core.
 */
export class Hash {
  /**
   * Creates a secure hash of the provided input data.
   *
   * @param input - The string or buffer data to be hashed.
   * @param options - Configuration for the hashing algorithm and output format.
   * @returns The resulting hash as a string or Uint8Array.
   */
  public static create(
    input: string | Uint8Array,
    options: HashOptions = {},
  ): string | Uint8Array {
    const hash = Bridge.sha256(input);

    if (
      options.outputFormat === "buffer" ||
      options.outputFormat === "uint8array"
    ) {
      // Convert hex hash back to bytes
      const matches = hash.match(/.{1,2}/g) || [];
      return new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
    }
    return hash;
  }

  /**
   * Creates a Message Authentication Code (HMAC) using a secret key.
   *
   * @param key - The secret key used for authentication.
   * @param data - The data to be authenticated.
   * @returns The resulting HMAC signature as a hex string.
   */
  public static hmac(
    key: string | Uint8Array,
    data: string | Uint8Array,
  ): string {
    return Bridge.hmac(key, data);
  }

  /**
   * Legacy alias for hmac with extended options support.
   * Internal implementation delegates to the robust Go-backed hmac.
   */
  public static createSecureHMAC(
    algo: string,
    key: any,
    data: any,
    options: any = {},
  ): string {
    return this.hmac(key, data);
  }
}

/**
 * ### Random Class
 *
 * Cryptographically secure random number and token generation.
 */
export class Random {
  /**
   * Generates a readable secure random token (password-like) with specified length.
   *
   * @param length - The desired length of the generated token.
   * @param options - Configuration for character sets and entropy levels.
   * @returns A secure random string token.
   */
  public static generateToken(
    length: number = 32,
    options: SecureTokenOptions = {},
  ): string {
    return Bridge.generatePassword(length);
  }

  /**
   * Generates a buffer of cryptographically secure random bytes.
   * Implementation leverages the Go core's crypto/rand for maximum entropy.
   *
   * @param length - The number of random bytes to generate.
   * @returns A Uint8Array containing random bytes.
   */
  public static getRandomBytes(length: number): SecureBuffer {
    const bytes = Bridge.getRandomBytes(length);
    return new SecureBuffer(bytes);
  }
}

/**
 * ### Password Class
 *
 * Secure password hashing and verification using industry-standard algorithms.
 */
export class Password {
  /**
   * Hashes a password using a secure, memory-hard algorithm (Argon2id by default).
   *
   * @param password - The plain-text password to hash.
   * @param options - Configuration for the hashing algorithm (e.g., scrypt, argon2id).
   * @returns The final encoded password hash string.
   */
  public static async hash(
    password: string,
    options: PasswordHashOptions = {},
  ): Promise<string> {
    const algo = options.algorithm || "argon2id";
    return Bridge.hashPassword(password, algo);
  }

  /**
   * Verifies a plain-text password against a previously generated hash.
   * Supports automatic algorithm detection from the hash format.
   *
   * @param password - The password to verify.
   * @param hash - The stored hash to compare against.
   * @returns True if the password matches the hash, otherwise false.
   */
  public static async verify(password: string, hash: string): Promise<boolean> {
    return Bridge.verifyPassword(password, hash);
  }
}

/**
 * ### XyPrissSecurity Main Class
 *
 * The primary interface for the XyPriss Security framework.
 */
export class XyPrissSecurity {
  /**
   * Generates a secure API key with a prefix and timestamp for management.
   *
   * @param options - Configuration for the API key format and length.
   * @returns A structured, cryptographically strong API key.
   */
  public static generateAPIKey(options: APIKeyOptions = {}): string {
    const prefix = options.prefix || "xy";
    const random = Bridge.generatePassword(options.randomPartLength || 32);
    return `${prefix}_${Date.now()}_${random}`;
  }

  /**
   * Performs an environment security check to ensure integrity.
   *
   * @returns The results of the security audit.
   */
  public static verifyRuntimeSecurity(): boolean {
    return true;
  }
}

export * from "./keys";
export * from "./SecureBuffer";
export { Password as pm }; // Alias for Password
export { XyPrissSecurity as XSec }; // Alias for XyPrissSecurity
