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

  /**
   * Verifies an Ed25519 signature.
   * @param publicKey - The public key (hex or Uint8Array).
   * @param data - The data that was signed (string or Uint8Array).
   * @param signature - The signature (base64 or Uint8Array).
   * @returns True if valid.
   */
  public static ed25519Verify(
    publicKey: string | Uint8Array,
    data: string | Uint8Array,
    signature: string | Uint8Array,
  ): boolean {
    return Bridge.ed25519Verify(publicKey, data, signature);
  }

  /**
   * Encrypts a large file using high-performance, hardware-accelerated chunking.
   *
   * @description
   * Processes files via a native encryption bridge using derived keys (PBKDF2).
   * Implements a staging strategy to ensure data integrity: ciphertext is
   * finalized with a 32-byte salt header before an atomic move to the target path.
   *
   * @param {string} inputPath - Absolute path to the source file.
   * @param {string} outputPath - Target destination for the encrypted data.
   * @param {string} key - Raw passphrase for cryptographic derivation.
   * @param {object} [options={}] - Encryption parameters.
   * @param {string} [options.algorithm="aes-256-gcm"] - Selection of the cipher suite.
   * @param {number} [options.keyDerivationIterations=100000] - Cost factor for PBKDF2.
   * @param {boolean} [options.quantumSafe=false] - If true, enforces Post-Quantum resistant ciphers.
   *
   * @throws {Error | SystemError} On bridge failure, I/O exhaustion, or permission issues.
   * @returns {Promise<void>}
   *
   * @example
   * await Cipher.crypto.encryptFile('./data.zip', './data.vault', 'secret-key');
   */
  public static async encryptFile(
    inputPath: string,
    outputPath: string,
    key: string,
    options: any = {},
  ): Promise<void> {
    const fs = require("fs");
    const os = require("os");
    const path = require("path");
    const { pipeline: pl } = require("stream");
    const { promisify: pr } = require("util");
    const pipelineAsync = pr(pl);

    const id = Math.random().toString(36).substring(7);
    const tmpDir = os.tmpdir();
    const goTempPath = path.join(tmpDir, `xy-enc-${id}.go.tmp`);
    const finalTempPath = path.join(tmpDir, `xy-enc-${id}.out.tmp`);

    try {
      const {
        algorithm = "aes-256-gcm",
        keyDerivationIterations = 100000,
        quantumSafe = false,
      } = options;

      const SALT_LENGTH = 32;
      const salt = Random.getRandomBytes(SALT_LENGTH);

      const derivedKeyHex = await Bridge.pbkdf2(
        key,
        salt.toUint8Array(),
        keyDerivationIterations,
        32,
        "sha256",
      );
      const derivedKey = Buffer.from(derivedKeyHex, "hex");
      const algoTarget =
        algorithm === "chacha20-poly1305" || quantumSafe ? "chacha20" : "aes";

      // 1. Encrypt input into a temporary Go output file
      const result = Bridge.encryptFile(
        inputPath,
        goTempPath,
        derivedKey,
        algoTarget,
      );
      if (result !== "OK") throw new Error(result);

      // 2. Combine Salt + Go Output into finalTempPath
      fs.writeFileSync(finalTempPath, Buffer.from(salt.toUint8Array()));
      const finalOut = fs.createWriteStream(finalTempPath, { flags: "a" });
      const goTempIn = fs.createReadStream(goTempPath);
      await pipelineAsync(goTempIn, finalOut);

      // 3. Atomically move to final output
      await this.moveFileAtomic(finalTempPath, outputPath);
    } catch (error) {
      if (fs.existsSync(finalTempPath)) fs.unlinkSync(finalTempPath);
      throw error;
    } finally {
      if (fs.existsSync(goTempPath)) fs.unlinkSync(goTempPath);
    }
  }

  /**
   * Decrypts a large file using PBKDF2 key derivation and a secure bridge.
   *
   * @description
   * This method extracts a 32-byte salt from the input file header, derives a 256-bit key
   * (100,000 iterations), and performs decryption via temporary staging files to
   * ensure data integrity. The final output is moved atomically.
   *
   * @param {string} inputPath - Absolute path to the encrypted source file.
   * @param {string} outputPath - Destination path for the decrypted plaintext.
   * @param {string} key - The raw passphrase used for key derivation.
   *
   * @throws {Error} If the salt extraction fails or the decryption bridge returns an error.
   * @throws {SystemError} If disk space is insufficient for temp files or if file moves fail.
   *
   * @returns {Promise<void>} Resolves once the file is successfully decrypted and moved to `outputPath`.
   *
   * @example
   * await Cipher.crypto.decryptFile('./vault.enc', './vault.txt', 'super-secret-key');
   */
  public static async decryptFile(
    inputPath: string,
    outputPath: string,
    key: string,
  ): Promise<void> {
    const fs = require("fs");
    const os = require("os");
    const path = require("path");
    const { pipeline: pl2 } = require("stream");
    const { promisify: pr2 } = require("util");
    const pipelineAsync2 = pr2(pl2);

    const SALT_LENGTH = 32;
    const id = Math.random().toString(36).substring(7);
    const tmpDir = os.tmpdir();
    const tempInPath = path.join(tmpDir, `xy-dec-${id}.in.tmp`);
    const tempOutPath = path.join(tmpDir, `xy-dec-${id}.out.tmp`);

    try {
      const fd = fs.openSync(inputPath, "r");
      const salt = Buffer.alloc(SALT_LENGTH);
      fs.readSync(fd, salt, 0, SALT_LENGTH, 0);
      fs.closeSync(fd);

      const derivedKeyHex = await Bridge.pbkdf2(
        key,
        salt,
        100000,
        32,
        "sha256",
      );
      const derivedKey = Buffer.from(derivedKeyHex, "hex");

      // 1. Prepare input for Go (remove salt) into tempInPath
      const finalInStream = fs.createReadStream(inputPath, {
        start: SALT_LENGTH,
      });
      const tempOutInStream = fs.createWriteStream(tempInPath);
      await pipelineAsync2(finalInStream, tempOutInStream);

      // 2. Decrypt from tempInPath to tempOutPath
      const result = Bridge.decryptFile(tempInPath, tempOutPath, derivedKey);
      if (result !== "OK") throw new Error(result);

      // 3. Atomically move to final output
      await this.moveFileAtomic(tempOutPath, outputPath);
    } catch (error) {
      if (fs.existsSync(tempOutPath)) fs.unlinkSync(tempOutPath);
      throw error;
    } finally {
      if (fs.existsSync(tempInPath)) fs.unlinkSync(tempInPath);
    }
  }

  /**
   * Moves a file atomically from src to dest.
   * Handles EXDEV errors for cross-partition moves.
   */
  private static async moveFileAtomic(
    src: string,
    dest: string,
  ): Promise<void> {
    const fs = require("fs");
    try {
      // Fast path: rename (on same partition)
      if (fs.existsSync(dest) && src !== dest) fs.unlinkSync(dest);
      fs.renameSync(src, dest);
    } catch (error: any) {
      // Fallback path: copy + unlink (cross-partition)
      if (error.code === "EXDEV") {
        fs.copyFileSync(src, dest);
        fs.unlinkSync(src);
      } else {
        throw error;
      }
    }
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
 * Verifies an Ed25519 signature.
 *
 * @param publicKey - Public key (hex or Uint8Array).
 * @param data - Original data.
 * @param signature - Signature (base64 or Uint8Array).
 * @returns True if valid.
 */
export const ed25519Verify = Keys.ed25519Verify;

/**
 * Derives a cryptographically strong key from an input secret.
 * Supports multiple algorithms including Argon2id, PBKDF2, and HKDF.
 *
 * @param input - The base secret or password.
 * @param options - Configuration for the derivation process.
 * @returns A promise resolving to the derived key.
 */
export const deriveKey = Keys.deriveKey;
