/***************************************************************************
 * XyPriss Security Core - Random Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import { SecureBuffer } from "./SecureBuffer";
import { SecureTokenOptions } from "../types";
import { stringToBuffer } from "../utils";
import { Keys } from "./keys";
import { C } from "../utils/constants";

/**
 * ### Random Class
 *
 * Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) utilities.
 *
 * Backed by operating system entropy (`/dev/urandom` on Linux, `arc4random` on BSD/macOS,
 * and `BCryptGenRandom` on Windows) via the high-performance Go native bridge.
 *
 * Features:
 * - Unbiased uniform random integer generation (rejection sampling, no modulo bias).
 * - High-entropy token generation with custom character sets and similarity filtering.
 * - Numerical OTP / 2FA code generation.
 * - Cryptographic buffer allocations via `SecureBuffer` with memory wiping support.
 * - Constant-time and timing-attack resilient operations.
 *
 * @example
 * ```typescript
 * import { Random } from "xypriss-security";
 *
 * // Generate 32 cryptographically secure random bytes
 * const bytes = Random.getRandomBytes(32);
 * console.log("Hex:", bytes.toString("hex"));
 *
 * // Generate an API key or secure bearer token
 * const token = Random.generateToken(48);
 * console.log("API Key:", token.toString());
 *
 * // Generate a 6-digit numeric verification code for SMS / 2FA
 * const otp = Random.generateOTP(6);
 * console.log("OTP Code:", otp);
 * ```
 */
export class Random {
  /**
   * Generates a cryptographically strong, human-readable random string token.
   *
   * Customizable with character set toggles (uppercase, lowercase, digits, symbols)
   * and an optional similarity filter to remove confusing characters (e.g. `0`, `O`, `l`, `1`, `I`).
   *
   * @param length - The number of characters in the generated token. Defaults to `32`.
   * @param options - Configuration options for character set composition.
   * @param options.includeUppercase - Include uppercase letters `A-Z`. Defaults to `true`.
   * @param options.includeLowercase - Include lowercase letters `a-z`. Defaults to `true`.
   * @param options.includeNumbers - Include digits `0-9`. Defaults to `true`.
   * @param options.includeSymbols - Include special symbols (e.g. `!@#$%^&*`). Defaults to `false`.
   * @param options.excludeSimilarCharacters - If `true`, strips visually ambiguous characters (`0`, `O`, `l`, `1`, `I`).
   *
   * @returns A `SecureBuffer` wrapping the generated token string.
   *
   * @example
   * ```typescript
   * // Standard 32-character alphanumeric token
   * const token = Random.generateToken(32);
   * console.log(token.toString()); // e.g. "a9B7k2mP1x9Lq8vW4zN0j5R2t7Y6u8I3"
   *
   * // Session token without visually ambiguous characters (great for user-facing codes)
   * const userCode = Random.generateToken(12, {
   *   includeUppercase: true,
   *   includeNumbers: true,
   *   excludeSimilarCharacters: true,
   * });
   * console.log(userCode.toString()); // e.g. "H3K9P7V2X4T8"
   *
   * // High-entropy password with symbols
   * const securePassword = Random.generateToken(24, {
   *   includeSymbols: true,
   * });
   * ```
   */
  public static generateToken(
    length: number = 32,
    options: SecureTokenOptions = {},
  ): SecureBuffer {
    let charset = "";

    // Build charset based on options
    if (
      options.includeUppercase !== false ||
      options.includeLowercase !== false ||
      options.includeNumbers !== false ||
      options.includeSymbols !== false
    ) {
      if (options.includeLowercase !== false)
        charset += C.LOWERCASE;
      if (options.includeUppercase !== false)
        charset += C.UPPERCASE;
      if (options.includeNumbers !== false) charset += C.NUMBERS;
      if (options.includeSymbols) charset += C.SYMBOLS;
    }

    // Similarity filter
    if (options.excludeSimilarCharacters) {
      charset = charset.replace(C.RSIMILAR_CHARS, "");
    }

    const token = Bridge.generatePassword(length, charset);
    return new SecureBuffer(stringToBuffer(token));
  }

  /**
   * Generates a numeric One-Time Password (OTP) / verification code.
   *
   * Uses cryptographically secure random integers with zero-padding to guarantee
   * the exact number of digits requested. Ideal for SMS authentication, email verification,
   * and multi-factor authentication (MFA).
   *
   * @param digits - The exact number of numeric digits (typically between 4 and 10). Defaults to `6`.
   * @returns A zero-padded numeric string of length `digits`.
   * @throws {Error} If `digits` is out of supported range (typically 4-10) or random generation fails.
   *
   * @example
   * ```typescript
   * // Standard 6-digit SMS / Email OTP
   * const otp = Random.generateOTP(6);
   * console.log(otp); // e.g. "482910"
   *
   * // 8-digit high-security authentication code
   * const backupCode = Random.generateOTP(8);
   * console.log(backupCode); // e.g. "01948273"
   * ```
   */
  public static generateOTP(digits: number = 6): string {
    const res = Bridge.generateOTP(digits);
    if (res.startsWith("error:")) throw new Error(res);
    return res;
  }

  /**
   * Generates a cryptographically secure random integer uniformly distributed in `[0, max)`.
   *
   * Uses rejection sampling over 64-bit random values to completely eliminate
   * modulo bias (*pigeonhole effect*).
   *
   * @param max - Upper bound (exclusive). Must be a positive integer > 0.
   * @returns A secure random integer $n$ such that $0 \le n < \text{max}$.
   *
   * @example
   * ```typescript
   * // Random number between 0 and 99 (inclusive)
   * const percent = Random.getRandomInt(100);
   *
   * // Roll a 6-sided die: 1 to 6
   * const diceRoll = Random.getRandomInt(6) + 1;
   * ```
   */
  public static getRandomInt(max: number): number {
    return Bridge.getRandomInt(max);
  }

  /**
   * Allocates and fills a buffer with cryptographically secure random bytes from the CSPRNG.
   *
   * Useful for generating cryptographic salts, initialization vectors (IV / nonce),
   * session keys, and random masks.
   *
   * @param length - The number of random bytes to generate.
   * @returns A `SecureBuffer` wrapping the raw bytes, with helper methods (`toUint8Array()`, `toString("hex")`, `wipe()`).
   *
   * @example
   * ```typescript
   * // Generate a 16-byte salt for password hashing / KDF
   * const salt = Random.getRandomBytes(16);
   * console.log(salt.toString("hex")); // 32 hex characters
   *
   * // Generate a 12-byte nonce for AES-GCM encryption
   * const nonce = Random.getRandomBytes(12).toUint8Array();
   *
   * // Secure wipe when done with sensitive material
   * salt.wipe();
   * ```
   */
  public static getRandomBytes(length: number): SecureBuffer {
    const bytes = Bridge.getRandomBytes(length);
    return new SecureBuffer(bytes);
  }

  /**
   * Generates a cryptographically secure random integer within a specified range `[min, max)`.
   *
   * If only one argument is provided, it is treated as `max` and the range defaults to `[0, max)`.
   *
   * @param minOrMax - The minimum value (inclusive), or the maximum value if `max` is omitted.
   * @param max - The maximum value (exclusive).
   * @returns A cryptographically secure random integer in the range.
   *
   * @example
   * ```typescript
   * // Range [10, 50): 10 inclusive up to 49 inclusive
   * const port = Random.Int(1024, 65535);
   *
   * // Single parameter: range [0, 10)
   * const digit = Random.Int(10);
   * ```
   */
  public static Int(minOrMax: number, max?: number): number {
    if (max === undefined) {
      return Bridge.getRandomInt(minOrMax);
    }
    const min = minOrMax;
    const range = max - min;
    if (range <= 0) return min;
    return min + Bridge.getRandomInt(range);
  }

  /**
   * Convenient alias for `Random.getRandomBytes`.
   *
   * @param length - Number of bytes to generate.
   * @returns Raw byte array (`Uint8Array`).
   *
   * @example
   * ```typescript
   * const rawBytes = Random.Bytes(32);
   * ```
   */
  public static Bytes(...args: Parameters<typeof Bridge.getRandomBytes>) {
    return Bridge.getRandomBytes(...args);
  }

  /**
   * Convenient alias for `Random.generateOTP`.
   *
   * @param digits - Digit count.
   * @returns The generated OTP string.
   *
   * @example
   * ```typescript
   * const code = Random.OTP(6);
   * ```
   */
  public static OTP(...args: Parameters<typeof Bridge.generateOTP>) {
    return Bridge.generateOTP(...args);
  }

  /**
   * Selects a single random item from an array using the CSPRNG.
   *
   * Guarantees fair, unbiased selection across all array indices.
   *
   * @typeParam T - Type of the array elements.
   * @param arr - The array to choose from. Must not be empty.
   * @returns A randomly chosen element from `arr`.
   * @throws {Error} If `arr` is empty or undefined.
   *
   * @example
   * ```typescript
   * const servers = ["us-east-1", "eu-west-1", "ap-southeast-1"];
   * const targetServer = Random.pick(servers);
   *
   * const prizeWinners = ["Alice", "Bob", "Charlie", "Diana"];
   * const luckyWinner = Random.pick(prizeWinners);
   * ```
   */
  public static pick<T>(arr: T[]): T {
    if (!arr || arr.length === 0) {
      throw new Error("Cannot pick from an empty array");
    }
    const index = Bridge.getRandomInt(arr.length);
    return arr[index];
  }

  /**
   * Convenient alias for `Random.generateToken`.
   *
   * @see {@link Random.generateToken}
   */
  public static generateSecureToken(
    ...args: Parameters<typeof Random.generateToken>
  ) {
    return Random.generateToken(...args);
  }
}
