/***************************************************************************
 * XyPriss Security Core - Random Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import { SecureBuffer } from "./SecureBuffer";
import { SecureTokenOptions } from "../types";
import { stringToBuffer } from "../utils";
import { Keys } from "./keys";

/**
 * ### Random Class
 *
 * Cryptographically secure random number and token generation.
 */
export class Random extends Keys {
  /**
   * Generates a readable secure random token with specified constraints.
   *
   * @param length - The desired length of the generated token.
   * @param options - Configuration for character sets and entropy levels.
   * @returns A secure random string token.
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
        charset += "abcdefghijklmnopqrstuvwxyz";
      if (options.includeUppercase !== false)
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      if (options.includeNumbers !== false) charset += "0123456789";
      if (options.includeSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    }

    // Similarity filter
    if (options.excludeSimilarCharacters) {
      charset = charset.replace(/[il1Lo0O]/g, "");
    }

    const token = Bridge.generatePassword(length, charset);
    return new SecureBuffer(stringToBuffer(token));
  }

  /**
   * Generates a numeric OTP of specified length.
   */
  public static generateOTP(digits: number = 6): string {
    const res = Bridge.generateOTP(digits);
    if (res.startsWith("error:")) throw new Error(res);
    return res;
  }

  /**
   * Generates a secure random integer in [0, max).
   */
  public static getRandomInt(max: number): number {
    return Bridge.getRandomInt(max);
  }

  /**
   * Generates a buffer of cryptographically secure random bytes.
   *
   * @param length - The number of random bytes to generate.
   * @returns A SecureBuffer containing random bytes.
   */
  public static getRandomBytes(length: number): SecureBuffer {
    const bytes = Bridge.getRandomBytes(length);
    return new SecureBuffer(bytes);
  }

  /**
   * Generates a secure random integer in [min, max).
   * If only one argument is provided, it's treated as the maximum.
   *
   * @param minOrMax - The minimum value (inclusive) or maximum if second arg missing.
   * @param max - The maximum value (exclusive).
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
   * Alias for getRandomBytes.
   */
  public static Bytes(...args: Parameters<typeof Bridge.getRandomBytes>) {
    return Bridge.getRandomBytes(...args);
  }

  /**
   * Alias for generateOTP.
   */
  public static OTP(...args: Parameters<typeof Bridge.generateOTP>) {
    return Bridge.generateOTP(...args);
  }

  /**
   * Alias for generateToken.
   */
  public static generateSecureToken(
    ...args: Parameters<typeof Random.generateToken>
  ) {
    return Random.generateToken(...args);
  }
}
