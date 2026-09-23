/***************************************************************************
 * XyPriss Security Core - Password Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import { PasswordHashOptions } from "../types";

/**
 * ### Password Class
 *
 * Industrial-grade password hashing, salting, and constant-time verification.
 * Powered by a high-performance Go native core with support for memory-hard
 * algorithms (Argon2id, Scrypt, PBKDF2) and modular hash formatting.
 *
 * All hashes generated follow the structured modular XyPriss signature format:
 * `$xypriss$<algorithm>$<parameters>$<base64Salt>$<base64Hash>`
 *
 * This allows safe storage in database fields without separate salt columns,
 * automatic parameter upgrades, and timing-attack-resistant verification.
 *
 * @example
 * ```typescript
 * import { Password } from "xypriss-security";
 *
 * // 1. Hash a user password during registration
 * const passwordHash = await Password.hash("SuperSecretP@ssw0rd!");
 * // Store passwordHash in database (e.g. users.password_hash)
 *
 * // 2. Verify password during login
 * const isValid = await Password.verify("SuperSecretP@ssw0rd!", passwordHash);
 * if (isValid) {
 *   console.log("Authentication successful!");
 * }
 * ```
 */
export class Password {
  /**
   * Hashes a plain-text password using a memory-hard cryptographic algorithm.
   *
   * By default, uses **Argon2id** (the OWASP and RFC 9106 recommended winner of the
   * Password Hashing Competition), offering optimal defense against both GPU and
   * ASIC-based brute force attacks.
   *
   * @param password - The raw plain-text password or PIN to hash.
   * @param options - Configuration options for algorithm selection and cost tuning.
   * @param options.algorithm - Hash algorithm: `"argon2id"` (default), `"scrypt"`, or `"pbkdf2"`.
   * @param options.iterations - Time cost (iterations/passes over memory). Default: 3 for Argon2id, 100,000 for PBKDF2.
   * @param options.memoryCost - Memory cost in KiB (e.g., 65536 = 64 MiB).
   * @param options.parallelism - Number of parallel threads/lanes (default: 4 for Argon2id).
   * @param options.pepper - Optional application-level secret string appended to the password before hashing.
   *
   * @returns A promise resolving to the self-contained modular hash string prefixed with `$xypriss$`.
   * @throws {Error} If an unsupported algorithm is provided or if cryptographic hashing fails.
   *
   * @example
   * ```typescript
   * // Basic usage (safe Argon2id production defaults: 64MB memory, 3 passes, 4 threads)
   * const hash = await Password.hash("MyUserP@ss123");
   * // => "$xypriss$argon2id$v=19,m=65536,t=3,p=4$..."
   *
   * // Custom Argon2id parameters for high-security environments
   * const highSecHash = await Password.hash("AdminSecretPassphrase", {
   *   algorithm: "argon2id",
   *   memoryCost: 128 * 1024, // 128 MiB
   *   iterations: 4,          // 4 passes
   *   parallelism: 8,
   * });
   *
   * // Using Scrypt algorithm
   * const scryptHash = await Password.hash("Pin1234", {
   *   algorithm: "scrypt",
   * });
   *
   * // Using an application-level pepper
   * const pepperedHash = await Password.hash("UserPassword", {
   *   pepper: process.env.APP_PEPPER,
   * });
   * ```
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
   * Verifies a plain-text password against a previously generated modular XyPriss hash.
   *
   * The verification algorithm, salt, and cost parameters are automatically extracted
   * directly from the encoded hash string. Verification is executed in constant-time
   * to eliminate timing side-channel attacks.
   *
   * @param password - The candidate plain-text password to test.
   * @param hash - The stored modular `$xypriss$` hash string to verify against.
   * @param options - Verification options.
   * @param options.pepper - Application pepper string (must match the pepper used during hashing).
   *
   * @returns A promise resolving to `true` if the password is valid, `false` otherwise.
   *
   * @example
   * ```typescript
   * // Simple verification
   * const isMatch = await Password.verify("candidatePass", storedHash);
   * if (!isMatch) {
   *   throw new Error("Invalid username or password");
   * }
   *
   * // Verification with application pepper
   * const isPepperMatch = await Password.verify("candidatePass", storedHash, {
   *   pepper: process.env.APP_PEPPER,
   * });
   * ```
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
   * Inspects a string to determine whether it is a valid XyPriss modular hash.
   *
   * Optionally checks if the hash was created using a specific target algorithm.
   *
   * @param hash - The string to inspect.
   * @param algorithm - Optional algorithm name to filter by (e.g. `"argon2id"`, `"scrypt"`, `"pbkdf2"`).
   *
   * @returns `true` if the string matches the XyPriss hash format (and algorithm if specified), `false` otherwise.
   *
   * @example
   * ```typescript
   * const str = "$xypriss$argon2id$v=19,m=65536,t=3,p=4$abc...$xyz...";
   *
   * Password.isHashed(str); // true
   * Password.isHashed(str, "argon2id"); // true
   * Password.isHashed(str, "scrypt"); // false
   * Password.isHashed("plaintext_password"); // false
   * ```
   */
  public static isHashed(hash: string, algorithm?: string): boolean {
    return Bridge.isHashed(hash, algorithm);
  }
}
