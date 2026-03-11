/**
 * Key Management and Derivation
 * High-performance Go-backed operations
 */

import { KeyDerivationOptions } from "../types";
import { Password } from "./index";

export class Keys {
  public static deriveKey(
    input: string | Uint8Array,
    options: KeyDerivationOptions = {},
  ): Promise<string> {
    const strInput =
      typeof input === "string" ? input : new TextDecoder().decode(input);
    return Password.hash(strInput, {
      algorithm: options.algorithm || "argon2id",
    });
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
