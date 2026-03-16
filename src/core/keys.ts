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



  /**
   * Generates a new RSA key pair in JSON format.
   * @returns A Promise resolving to an object containing publicKey and privateKey.
   */
  public static async generateRSAKeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    return Bridge.generateRSAKeyJSON();
  }

  /**
   * Signs data using RSA-PSS.
   * @param privateKey - The PEM-encoded RSA private key.
   * @param data - The data to sign.
   * @returns The signature in hex format.
   */
  public static async rsaSign(
    privateKey: string,
    data: string,
  ): Promise<string> {
    return Bridge.rsaSign(privateKey, data);
  }

  /**
   * Verifies an RSA-PSS signature.
   * @param publicKey - The PEM-encoded RSA public key.
   * @param data - The original data.
   * @param signature - The hex-encoded signature.
   * @returns True if the signature is valid.
   */
  public static async rsaVerify(
    publicKey: string,
    data: string,
    signature: string,
  ): Promise<boolean> {
    return Bridge.rsaVerify(publicKey, data, signature);
  }

  /**
   * Encrypts data using RSA-OAEP.
   * @param publicKey - The PEM-encoded RSA public key.
   * @param data - The data to encrypt.
   * @returns The encrypted data in hex format.
   */
  public static async rsaEncrypt(
    publicKey: string,
    data: string,
  ): Promise<string> {
    return Bridge.rsaEncrypt(publicKey, data);
  }

  /**
   * Decrypts RSA-OAEP encrypted data.
   * @param privateKey - The PEM-encoded RSA private key.
   * @param encryptedHex - The hex-encoded encrypted data.
   * @returns The decrypted plaintext.
   */
  public static async rsaDecrypt(
    privateKey: string,
    encryptedHex: string,
  ): Promise<string> {
    return Bridge.rsaDecrypt(privateKey, encryptedHex);
  }
}


// =================================== UTILES ==========================

/**
 * Generates a high-entropy 4096-bit RSA key pair.
 *
 * @returns A promise resolving to an object containing PEM-encoded publicKey and privateKey.
 */
export const generateRSAKeyPair = Keys.generateRSAKeyPair;

/**
 * Signs data using RSA-PSS with SHA-256.
 *
 * @param privateKey - The PEM-encoded RSA private key.
 * @param data - The data string to sign.
 * @returns A promise resolving to the hex-encoded signature.
 */
export const rsaSign = Keys.rsaSign;

/**
 * Verifies an RSA-PSS signature.
 *
 * @param publicKey - The PEM-encoded RSA public key.
 * @param data - The original data string that was signed.
 * @param signature - The hex-encoded signature to verify.
 * @returns A promise resolving to true if valid, false otherwise.
 */
export const rsaVerify = Keys.rsaVerify;

/**
 * Encrypts data using RSA-OAEP with SHA-256.
 *
 * @param publicKey - The PEM-encoded RSA public key.
 * @param data - The plaintext data string to encrypt.
 * @returns A promise resolving to the hex-encoded ciphertext.
 */
export const rsaEncrypt = Keys.rsaEncrypt;

/**
 * Decrypts data using RSA-OAEP with SHA-256.
 *
 * @param privateKey - The PEM-encoded RSA private key.
 * @param encryptedHex - The hex-encoded ciphertext to decrypt.
 * @returns A promise resolving to the decrypted plaintext string.
 */
export const rsaDecrypt = Keys.rsaDecrypt;

/**
 * Derives a cryptographically strong key from an input secret.
 * Supports multiple algorithms including Argon2id, PBKDF2, and HKDF.
 *
 * @param input - The base secret or password.
 * @param options - Configuration for the derivation process.
 * @returns A promise resolving to the derived key.
 */
export const deriveKey = Keys.deriveKey;
