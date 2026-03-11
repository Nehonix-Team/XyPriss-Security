/***************************************************************************
 * XyPriss Security - Cryptographic Algorithm Utilities
 *
 * Provides professional metadata and classification for supported algorithms.
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

import { AlgorithmInfo } from "../types";

/**
 * Utility class for managing cryptographic algorithm information.
 */
export class CryptoAlgorithmUtils {
  /**
   * Retrieves detailed metrics and metadata for a specific algorithm.
   *
   * @param name - The identifier of the algorithm.
   * @returns Detailed algorithm specifications.
   */
  public static getAlgorithmInfo(name: string): AlgorithmInfo {
    const registry: Record<string, AlgorithmInfo> = {
      sha256: {
        name: "SHA-256",
        type: "hash",
        keySize: 0,
        blockSize: 64,
        description: "NIST standard 256-bit hash.",
      },
      sha512: {
        name: "SHA-512",
        type: "hash",
        keySize: 0,
        blockSize: 128,
        description: "NIST standard 512-bit hash.",
      },
      argon2id: {
        name: "Argon2id",
        type: "kdf",
        description: "State-of-the-art memory-hard password hash.",
      },
      "aes-256-gcm": {
        name: "AES-256-GCM",
        type: "encryption",
        keySize: 32,
        ivSize: 12,
        description: "Authenticated symmetric encryption.",
      },
    };

    const key = name.toLowerCase();
    return (
      registry[key] || {
        name: name,
        type: "hash",
        description: "Standard security primitive.",
      }
    );
  }

  /**
   * Standardizes algorithm names to framework-recognized formats.
   */
  public static standardizeName(name: string): string {
    return name.toUpperCase().replace(/_/g, "-");
  }
}
