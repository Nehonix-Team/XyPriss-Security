/**
 * Key Management and Derivation
 * High-performance Go-backed operations
 */

import { KeyDerivationOptions } from "../types";
import { Password } from "./Password";
import { Bridge } from "./bridge";
import { Random } from "./Random";

export class Keys {
  /**
   * Derives a cryptographically strong key from an input secret.
   * Supports complex derivation paths including Argon2id, PBKDF2, and HKDF.
   *
   * @param input - The base secret or password to derive from.
   * @param options - Detailed configuration for the derivation process.
   * @returns A Promise resolving to the derived key (hex format for PBKDF2/HKDF, signed for others).
   */
  public static async deriveKey(
    input: string | Uint8Array,
    options: KeyDerivationOptions = {},
  ): Promise<string> {
    const algo = (options.algorithm || "argon2id").toLowerCase();
    const strInput =
      typeof input === "string" ? input : new TextDecoder().decode(input);

    // Handle high-performance PBKDF2 branch
    if (algo === "pbkdf2") {
      const salt = options.salt || Random.getRandomBytes(32).toUint8Array();
      const saltBytes = typeof salt === "string" ? Buffer.from(salt) : salt;
      return Bridge.pbkdf2(
        strInput,
        saltBytes,
        options.iterations || 100000,
        options.keyLength || 32,
        options.digest || "sha256",
      );
    }

    // Handle modern HKDF branch
    if (algo === "hkdf") {
      const inputBytes =
        typeof input === "string" ? new TextEncoder().encode(input) : input;
      const salt = options.salt || new Uint8Array(0);
      const saltBytes = typeof salt === "string" ? Buffer.from(salt) : salt;
      const info = options.info || new Uint8Array(0);
      const infoBytes = typeof info === "string" ? Buffer.from(info) : info;

      return Bridge.hkdf(
        inputBytes,
        saltBytes,
        infoBytes,
        options.keyLength || 32,
      );
    }

    // Default to Argon2id/Scrypt via Password module
    return Password.hash(strInput, options);
  }

  public static getMetrics(): object {
    return { derivationTimeMs: 0, memoryUsedMb: 0, operationsCount: 0 };
  }

  public static getEnvironmentInfo(): object {
    return {
      platform: "XyPriss-GCo",
      cryptoSupport: ["argon2id", "scrypt", "kyber"],
    };
  }

  public static getRecommendedAlgorithm(): string {
    return "argon2id";
  }
}
