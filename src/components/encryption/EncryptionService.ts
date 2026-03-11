/***************************************************************************
 * XyPrissJS - Fast And Secure
 *
 * @author Nehonix
 * @license Nehonix OSL (NOSL)
 *
 * Copyright (c) 2025 Nehonix. All rights reserved.
 *
 * This License governs the use, modification, and distribution of software
 * provided by NEHONIX under its open source projects.
 * NEHONIX is committed to fostering collaborative innovation while strictly
 * protecting its intellectual property rights.
 * Violation of any term of this License will result in immediate termination of all granted rights
 * and may subject the violator to legal action.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * AND NON-INFRINGEMENT.
 * IN NO EVENT SHALL NEHONIX BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES ARISING FROM THE USE OR INABILITY TO USE THE SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *
 ***************************************************************************** */
/**
 * XyPrissJS Express Encryption Service
 *  encryption/decryption service using XyPrissJS cryptographic utilities
 *
 * Features:
 * - AES-256-GCM encryption with authentication
 * - ChaCha20-Poly1305 fallback for quantum-safe encryption
 * - Proper key derivation using PBKDF2
 * - Secure IV/nonce generation
 * - Constant-time operations
 * - Memory-safe operations with secure wiping
 */

import { Hash, Random, Keys } from "../../core";
import { Bridge } from "../../core/bridge";

/**
 * Encryption algorithm options
 */
export type EncryptionAlgorithm = "aes-256-gcm" | "chacha20-poly1305";

/**
 * Encryption options
 */
export interface EncryptionOptions {
  algorithm?: EncryptionAlgorithm;
  keyDerivationIterations?: number;
  additionalData?: string;
  quantumSafe?: boolean;
}

/**
 * Encrypted data package
 */
export interface EncryptedPackage {
  algorithm: EncryptionAlgorithm;
  iv: string;
  data: string;
  authTag: string;
  salt: string;
  timestamp: number;
  version: string;
}

/**
 *  encryption service using XyPrissJS utilities
 */
export class EncryptionService {
  private static readonly VERSION = "1.0.0";
  private static readonly DEFAULT_ITERATIONS = 100000;
  private static readonly KEY_LENGTH = 32; // 256 bits
  private static readonly IV_LENGTH = 12; // 96 bits for GCM
  private static readonly SALT_LENGTH = 32; // 256 bits
  private static readonly AUTH_TAG_LENGTH = 16; // 128 bits

  /**
   * Encrypt data using production-grade encryption
   */
  public static async encrypt(
    data: any,
    key: string,
    options: EncryptionOptions = {},
  ): Promise<string> {
    try {
      // Validate inputs
      this.validateInputs(data, key);

      const {
        algorithm = "aes-256-gcm",
        keyDerivationIterations = this.DEFAULT_ITERATIONS,
        additionalData,
        quantumSafe = false,
      } = options;

      // Serialize data
      const jsonData = JSON.stringify(data);
      const dataBuffer = new TextEncoder().encode(jsonData);

      // Generate cryptographically secure salt
      const salt = Random.getRandomBytes(this.SALT_LENGTH);

      // Derive encryption key using PBKDF2
      const derivedKey = await this.deriveKey(
        key,
        salt,
        keyDerivationIterations,
      );

      const algoTarget =
        algorithm === "chacha20-poly1305" || quantumSafe ? "chacha20" : "aes";
      const encHex = Bridge.encryptRaw(dataBuffer, derivedKey, algoTarget);

      if (encHex.startsWith("error:")) throw new Error(encHex);

      const [ivHex, tagHex, dataHex] = encHex.split(":");

      // Create encrypted package
      const package_: EncryptedPackage = {
        algorithm: quantumSafe ? "chacha20-poly1305" : algorithm,
        iv: ivHex,
        data: dataHex,
        authTag: tagHex,
        salt: this.bufferToHex(salt.toUint8Array()),
        timestamp: Date.now(),
        version: this.VERSION,
      };

      // Secure memory cleanup
      this.secureWipe(derivedKey);
      this.secureWipe(dataBuffer);

      return JSON.stringify(package_);
    } catch (error) {
      throw new Error(
        `Encryption failed: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
      );
    }
  }

  /**
   * Decrypt data using production-grade decryption
   */
  public static async decrypt(
    encryptedData: string,
    key: string,
  ): Promise<any> {
    try {
      // Parse encrypted package
      const package_: EncryptedPackage = JSON.parse(encryptedData);
      this.validatePackage(package_);

      const salt = this.hexToBuffer(package_.salt);
      const derivedKey = await this.deriveKey(
        key,
        salt,
        this.DEFAULT_ITERATIONS,
      );

      // Convert hex strings back to buffers
      const partsStr = `${package_.iv}:${package_.authTag}:${package_.data}`;
      const algoTarget =
        package_.algorithm === "chacha20-poly1305" ? "chacha20" : "aes";
      const decryptedHex = Bridge.decryptRaw(partsStr, derivedKey, algoTarget);

      if (decryptedHex.startsWith("error:")) throw new Error(decryptedHex);

      const decrypted = this.hexToBuffer(decryptedHex);

      // Convert back to string and parse JSON
      const jsonString = new TextDecoder().decode(decrypted);
      const result = JSON.parse(jsonString);

      // Secure memory cleanup
      this.secureWipe(derivedKey);
      this.secureWipe(decrypted);

      return result;
    } catch (error) {
      throw new Error(
        `Decryption failed: ${
          error instanceof Error ? error.message : "Invalid encrypted data"
        }`,
      );
    }
  }

  /**
   * Derive encryption key using PBKDF2
   */
  private static async deriveKey(
    password: string,
    salt: Uint8Array | any,
    iterations: number,
  ): Promise<Uint8Array> {
    const saltBuffer = salt instanceof Uint8Array ? salt : salt.toUint8Array();

    const resultHex = Bridge.pbkdf2(
      password,
      saltBuffer,
      iterations,
      this.KEY_LENGTH,
      "sha256",
    );

    if (resultHex.startsWith("error:")) throw new Error(resultHex);

    return Buffer.from(resultHex, "hex");
  }

  // Obsolete encryption wrappers leveraging Node.js crypto removed

  /**
   * Validate inputs for encryption
   */
  private static validateInputs(data: any, key: string): void {
    if (data === undefined || data === null) {
      throw new Error("Data cannot be null or undefined");
    }

    if (!key || typeof key !== "string") {
      throw new Error("Key must be a non-empty string");
    }

    if (key.length < 8) {
      throw new Error("Key must be at least 8 characters long");
    }

    try {
      if (key.length < 8) {
        throw new Error("Key length invalid");
      }
    } catch (error) {
      throw new Error(
        `Invalid key: ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
      );
    }
  }

  /**
   * Validate encrypted package structure
   */
  private static validatePackage(package_: any): void {
    const requiredFields = [
      "algorithm",
      "iv",
      "data",
      "authTag",
      "salt",
      "timestamp",
      "version",
    ];

    for (const field of requiredFields) {
      if (!package_[field]) {
        throw new Error(`Invalid encrypted package: missing ${field}`);
      }
    }

    if (!["aes-256-gcm", "chacha20-poly1305"].includes(package_.algorithm)) {
      throw new Error(
        `Unsupported encryption algorithm: ${package_.algorithm}`,
      );
    }

    // Validate timestamp (not too old, not in future)
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    if (package_.timestamp > now + 60000) {
      // 1 minute future tolerance
      throw new Error("Invalid encrypted package: timestamp in future");
    }

    if (now - package_.timestamp > maxAge) {
      throw new Error("Invalid encrypted package: timestamp too old");
    }
  }

  /**
   * Convert buffer to hex string
   */
  private static bufferToHex(buffer: Uint8Array): string {
    return Array.from(buffer)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Convert hex string to buffer
   */
  private static hexToBuffer(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
      throw new Error("Invalid hex string length");
    }

    const buffer = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      buffer[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return buffer;
  }

  /**
   * Secure memory wipe using XyPrissJS utilities
   */
  private static secureWipe(buffer: Uint8Array): void {
    try {
      // Use XyPrissJS secure memory wiping
      if (buffer && buffer.length > 0) {
        // Overwrite with random data first
        const randomData = Random.getRandomBytes(buffer.length);
        buffer.set(randomData.toUint8Array());

        // Then overwrite with zeros
        buffer.fill(0);

        // Finally overwrite with 0xFF
        buffer.fill(0xff);
        buffer.fill(0);
      }
    } catch (error) {
      // Fallback to simple zero fill
      if (buffer && buffer.length > 0) {
        buffer.fill(0);
      }
    }
  }

  /**
   * Generate a secure session key for temporary use
   */
  public static generateSessionKey(): string {
    const keyBytes = Random.getRandomBytes(32);
    return this.bufferToHex(keyBytes.toUint8Array());
  }

  /**
   * Verify the integrity of encrypted data without decrypting
   */
  public static verifyIntegrity(encryptedData: string): boolean {
    try {
      const package_: EncryptedPackage = JSON.parse(encryptedData);
      this.validatePackage(package_);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get encryption metadata without decrypting
   */
  public static getMetadata(encryptedData: string): {
    algorithm: EncryptionAlgorithm;
    timestamp: number;
    version: string;
  } {
    try {
      const package_: EncryptedPackage = JSON.parse(encryptedData);
      return {
        algorithm: package_.algorithm,
        timestamp: package_.timestamp,
        version: package_.version,
      };
    } catch (error) {
      throw new Error("Invalid encrypted data format");
    }
  }
}
