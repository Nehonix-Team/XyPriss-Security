/***************************************************************************
 * XyPriss Security Core - Password Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import { PasswordHashOptions } from "../types";

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
   * @param options - Configuration for the hashing algorithm (iterations, memory, parallelism).
   * @returns The final encoded password hash string.
   */
  public static async hash(
    password: string,
    options: PasswordHashOptions = {},
  ): Promise<string> {
    const algo = (options.algorithm || "argon2id").toLowerCase();
    const iterations = options.iterations || 0;
    const memory = options.memoryCost || 0;
    const parallelism = options.parallelism || 0;

    // Optional pepper support if provided in options
    const finalPassword = options.pepper ? password + options.pepper : password;

    return Bridge.hashPassword(
      finalPassword,
      algo,
      iterations,
      memory,
      parallelism,
    );
  }

  /**
   * Verifies a plain-text password against a previously generated hash.
   *
   * @param password - The password to verify.
   * @param hash - The stored hash to compare against.
   * @param options - Optional configuration (e.g., pepper).
   * @returns True if the password matches the hash, otherwise false.
   */
  public static async verify(
    password: string,
    hash: string,
    options: { pepper?: string } = {},
  ): Promise<boolean> {
    const finalPassword = options.pepper ? password + options.pepper : password;
    return Bridge.verifyPassword(finalPassword, hash);
  }

  /**
   * Checks if a string is a valid XyPriss hash.
   *
   * @param hash - The string to check.
   * @param algorithm - Optional algorithm name to check against.
   * @returns True if it's a valid hash, otherwise false.
   */
  public static isHashed(hash: string, algorithm?: string): boolean {
    return Bridge.isHashed(hash, algorithm);
  }
}
