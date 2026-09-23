/**
 * Key Management, Asymmetric Cryptography, and Key Derivation
 * High-performance Go-backed operations.
 */

import { KeyDerivationOptions } from "../types";
import { Password } from "./Password";
import { Bridge } from "./bridge";
import { Random } from "./Random";

/**
 * ### Keys Class
 *
 * Comprehensive cryptographic key management, key derivation, and asymmetric operations.
 *
 * Powered by the native Go core for military-grade performance and security:
 * - **Key Derivation (KDF)**:
 *   - **Scrypt**: Memory-hard KDF, 100% compatible with Node.js `crypto.scryptSync`.
 *   - **PBKDF2**: OWASP-compliant password-based key derivation (HMAC-SHA256, HMAC-SHA512).
 *   - **HKDF**: RFC 5869 HMAC-based Extract-and-Expand key derivation.
 *   - **Argon2id**: Memory-hard derivation via modular password hashing.
 * - **Asymmetric Cryptography**:
 *   - **RSA-4096**: Keypair generation, RSA-PSS signatures, and RSA-OAEP encryption/decryption.
 *   - **Ed25519**: High-performance signature verification with automatic streaming for large payloads (>32KB).
 * - **Secure Streaming File Vault**:
 *   - Hardware-accelerated, chunked AEAD encryption/decryption (`AES-256-GCM`, `ChaCha20-Poly1305`)
 *     with atomic filesystem staging and salt extraction.
 *
 * @example
 * ```typescript
 * import { Keys } from "xypriss-security";
 *
 * // 1. Scrypt key derivation (raw 64-byte key in hex)
 * const salt = Keys.scrypt("mypassword", "salt123", 64);
 *
 * // 2. Generate RSA-4096 key pair
 * const { publicKey, privateKey } = await Keys.generateRSAKeyPair();
 *
 * // 3. Sign & verify data using RSA-PSS
 * const signature = await Keys.rsaSign(privateKey, "Important transaction data");
 * const isValid = await Keys.rsaVerify(publicKey, "Important transaction data", signature);
 * ```
 */
export class Keys {
  /**
   * Derives a cryptographically strong symmetric key from a master secret or password.
   *
   * Automatically dispatches to the requested KDF algorithm:
   * - `"scrypt"`: High-security memory-hard KDF, compatible with Node.js `crypto.scryptSync`. Returns hex string.
   * - `"pbkdf2"`: OWASP-standard derivation using HMAC-SHA256 or HMAC-SHA512. Returns hex string.
   * - `"hkdf"`: RFC 5869 extract-and-expand key derivation for deriving subkeys from high-entropy inputs. Returns hex string.
   * - `"argon2id"`: Default memory-hard password hashing format (returns `$xypriss$argon2id$...`).
   *
   * @param input - The base secret, passphrase, or input key material (string or `Uint8Array`).
   * @param options - Detailed configuration options for the derivation process.
   * @param options.algorithm - KDF algorithm: `"scrypt"`, `"pbkdf2"`, `"hkdf"`, or `"argon2id"`. Defaults to `"argon2id"`.
   * @param options.salt - Cryptographic salt (string or `Uint8Array`). If omitted, a secure random salt is generated.
   * @param options.keyLength - Desired derived key length in bytes. Defaults to `64` for Scrypt, `32` for others.
   * @param options.iterations - Iteration count for PBKDF2 (e.g. 100,000) or CPU cost parameter $N$ for Scrypt (e.g. 16384).
   * @param options.digest - Hash digest for PBKDF2 (`"sha256"` or `"sha512"`).
   * @param options.info - Context/application-specific info string or buffer for HKDF expansion.
   * @param options.parallelism - Parallelism factor $p$ for Scrypt / Argon2id. Defaults to `1`.
   *
   * @returns A promise resolving to the derived key (hex-encoded string for Scrypt/PBKDF2/HKDF, or `$xypriss$` modular format for Argon2id).
   * @throws {Error} If an unsupported algorithm is specified or derivation fails.
   *
   * @example
   * ```typescript
   * // Scrypt: Derive a 64-byte key in hex (drop-in equivalent to crypto.scryptSync)
   * const scryptKey = await Keys.deriveKey("user_pin_1234", {
   *   algorithm: "scrypt",
   *   salt: Buffer.from("c72cccea0dea40e308f5958e8f41564b", "hex"),
   *   keyLength: 64,
   * });
   * console.log("Scrypt Key (hex):", scryptKey);
   *
   * // PBKDF2: Derive a 32-byte AES key using 100,000 iterations of SHA-256
   * const pbkdf2Key = await Keys.deriveKey("master_passphrase", {
   *   algorithm: "pbkdf2",
   *   iterations: 100000,
   *   keyLength: 32,
   *   digest: "sha256",
   * });
   *
   * // HKDF: Derive subkeys from a shared secret with context info
   * const encryptionSubkey = await Keys.deriveKey(sharedSecret, {
   *   algorithm: "hkdf",
   *   info: "app-encryption-v1",
   *   keyLength: 32,
   * });
   * ```
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

    // Handle modern Scrypt KDF branch (compatible with crypto.scryptSync)
    if (algo === "scrypt") {
      const salt = options.salt || Random.getRandomBytes(16).toUint8Array();
      const saltBytes = typeof salt === "string" ? Buffer.from(salt) : salt;
      return Bridge.scrypt(
        strInput,
        saltBytes,
        options.keyLength || 64,
        options.iterations || options.memoryCost || 16384,
        8,
        options.parallelism || 1,
      );
    }

    // Default to Argon2id via Password module
    return Password.hash(strInput, {
      ...options,
      algorithm: (options.algorithm as "argon2id" | "scrypt" | "pbkdf2") || "argon2id",
    });
  }

  /**
   * Derives a raw cryptographic key of `keyLength` bytes using the Scrypt algorithm.
   *
   * Direct, synchronous equivalent to Node.js `crypto.scryptSync(password, salt, keyLength, options)`.
   * Produces identical output to the Node.js standard library with matching parameters.
   *
   * @param password - The password, PIN, or passphrase (string or `Uint8Array`).
   * @param salt - The cryptographic salt (string or `Uint8Array`).
   * @param keyLength - Desired key length in bytes. Defaults to `64`.
   * @param cost - CPU/memory cost parameter $N$ (must be a power of 2). Defaults to `16384` (Node.js default).
   * @param r - Block size parameter. Defaults to `8`.
   * @param p - Parallelization factor. Defaults to `1`.
   *
   * @returns The derived key as a lowercase hexadecimal string ($2 \times \text{keyLength}$ characters).
   * @throws {Error} If Scrypt derivation fails or parameters are invalid.
   *
   * @example
   * ```typescript
   * import { Keys, Random } from "xypriss-security";
   *
   * const salt = Random.getRandomBytes(16).toUint8Array();
   *
   * // Derive a 64-byte key in hex (128 hex chars)
   * const derivedKeyHex = Keys.scrypt("my_secret_pin", salt, 64);
   * console.log(derivedKeyHex);
   * // => "e505a1409236798a55e4cb907b8458d5bf80a514..."
   * ```
   */
  public static scrypt(
    password: string | Uint8Array,
    salt: string | Uint8Array,
    keyLength: number = 64,
    cost: number = 16384,
    r: number = 8,
    p: number = 1,
  ): string {
    const strPass =
      typeof password === "string" ? password : new TextDecoder().decode(password);
    const saltBytes = typeof salt === "string" ? Buffer.from(salt) : salt;
    return Bridge.scrypt(strPass, saltBytes, keyLength, cost, r, p);
  }

  /**
   * Generates a high-entropy 4096-bit RSA asymmetric key pair.
   *
   * Both keys are returned in standard PEM encoding (PKCS#1 for private key, PKIX for public key).
   *
   * @returns A promise resolving to an object containing PEM-formatted `publicKey` and `privateKey`.
   * @throws {Error} If key generation fails in the native engine.
   *
   * @example
   * ```typescript
   * const { publicKey, privateKey } = await Keys.generateRSAKeyPair();
   * console.log(publicKey);
   * // -----BEGIN PUBLIC KEY-----
   * // MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA...
   * // -----END PUBLIC KEY-----
   * ```
   */
  public static async generateRSAKeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    return Bridge.generateRSAKeyJSON();
  }

  /**
   * Digitally signs arbitrary data using RSA-PSS with SHA-256.
   *
   * RSA-PSS (Probabilistic Signature Scheme, RFC 8017 / PKCS#1 v2.1) provides
   * provable security and is strictly preferred over legacy RSA PKCS#1 v1.5.
   *
   * @param privateKey - The PEM-encoded 4096-bit RSA private key.
   * @param data - The plaintext data string or message to sign.
   *
   * @returns A promise resolving to the signature as a hexadecimal string.
   * @throws {Error} If private key parsing or signing fails.
   *
   * @example
   * ```typescript
   * const message = JSON.stringify({ transferId: "TX-1092", amount: 5000 });
   * const signatureHex = await Keys.rsaSign(privateKey, message);
   * ```
   */
  public static async rsaSign(
    privateKey: string,
    data: string,
  ): Promise<string> {
    return Bridge.rsaSign(privateKey, data);
  }

  /**
   * Verifies an RSA-PSS digital signature against original data using the public key.
   *
   * @param publicKey - The PEM-encoded RSA public key.
   * @param data - The original plaintext data string that was signed.
   * @param signature - The hexadecimal-encoded signature string to verify.
   *
   * @returns A promise resolving to `true` if the signature is authentic and unaltered, `false` otherwise.
   * @throws {Error} If public key parsing fails.
   *
   * @example
   * ```typescript
   * const isValid = await Keys.rsaVerify(publicKey, message, signatureHex);
   * if (!isValid) {
   *   throw new Error("Tampered or forged message detected!");
   * }
   * ```
   */
  public static async rsaVerify(
    publicKey: string,
    data: string,
    signature: string,
  ): Promise<boolean> {
    return Bridge.rsaVerify(publicKey, data, signature);
  }

  /**
   * Encrypts data using RSA-OAEP (Optimal Asymmetric Encryption Padding) with SHA-256.
   *
   * Safe for asymmetric encryption of small payloads (e.g. symmetric keys or credentials).
   *
   * @param publicKey - The recipient's PEM-encoded RSA public key.
   * @param data - The plaintext data string to encrypt.
   *
   * @returns A promise resolving to the ciphertext as a hexadecimal string.
   * @throws {Error} If public key parsing fails or payload exceeds RSA maximum size.
   *
   * @example
   * ```typescript
   * const encryptedSecret = await Keys.rsaEncrypt(publicKey, "symmetric-session-key-32b");
   * ```
   */
  public static async rsaEncrypt(
    publicKey: string,
    data: string,
  ): Promise<string> {
    return Bridge.rsaEncrypt(publicKey, data);
  }

  /**
   * Decrypts RSA-OAEP encrypted ciphertext using the corresponding private key.
   *
   * @param privateKey - The recipient's PEM-encoded RSA private key.
   * @param encryptedHex - The hexadecimal-encoded ciphertext to decrypt.
   *
   * @returns A promise resolving to the original decrypted plaintext string.
   * @throws {Error} If private key parsing or decryption/padding verification fails.
   *
   * @example
   * ```typescript
   * const decryptedSecret = await Keys.rsaDecrypt(privateKey, encryptedSecret);
   * ```
   */
  public static async rsaDecrypt(
    privateKey: string,
    encryptedHex: string,
  ): Promise<string> {
    return Bridge.rsaDecrypt(privateKey, encryptedHex);
  }

  /**
   * Verifies an Ed25519 (Edwards-curve Digital Signature Algorithm, RFC 8032) signature.
   *
   * Features:
   * - Ultra-high verification speed.
   * - High security level (Curve25519).
   * - Automatic transparent streaming through stdin when payload exceeds 32KB to bypass OS `E2BIG` argument limits.
   *
   * @param publicKey - The 32-byte Ed25519 public key (as hexadecimal string or `Uint8Array`).
   * @param data - The original data payload that was signed (string or `Uint8Array`).
   * @param signature - The 64-byte Ed25519 signature (as base64 string or `Uint8Array`).
   *
   * @returns `true` if the signature is valid, `false` otherwise.
   *
   * @example
   * ```typescript
   * import { Keys } from "xypriss-security";
   *
   * const pubKeyHex = "fad62d1d5e3c59f68ca394cc71bd174e12eb68111106a7d897b9fd6709adacc8";
   * const data = "Payload to authenticate";
   * const signatureBase64 = "9pe5W9PBJ0BUCK+QDDteUSElxo3XwG3ORzbT5HbhtVBT...";
   *
   * const isVerified = Keys.ed25519Verify(pubKeyHex, data, signatureBase64);
   * console.log("Signature valid:", isVerified);
   * ```
   */
  public static ed25519Verify(
    publicKey: string | Uint8Array,
    data: string | Uint8Array,
    signature: string | Uint8Array,
  ): boolean {
    return Bridge.ed25519Verify(publicKey, data, signature);
  }

  /**
   * Encrypts a file of arbitrary size using chunked AEAD (Authenticated Encryption with Associated Data).
   *
   * Architecture & Reliability:
   * - **Memory Efficient**: Streams file in chunks, maintaining minimal memory footprint regardless of file size.
   * - **Atomic Staging**: Encrypts into a temporary staging file before performing an atomic move to the target path, preventing partial or corrupted files.
   * - **Integrated Salt Header**: Automatically generates and prefixes a 32-byte salt header.
   * - **Cipher Choice**: Supports `AES-256-GCM` (default) and `ChaCha20-Poly1305` (ideal for mobile/ARM or quantum-safe profiles).
   *
   * @param inputPath - Absolute path to the cleartext source file.
   * @param outputPath - Target destination path for the encrypted `.vault` or ciphertext file.
   * @param key - The raw passphrase or secret used for PBKDF2 key derivation.
   * @param options - Encryption configuration options.
   * @param options.algorithm - Cipher suite: `"aes-256-gcm"` (default) or `"chacha20-poly1305"`.
   * @param options.keyDerivationIterations - PBKDF2 iteration count (default: 100,000).
   * @param options.quantumSafe - If `true`, enforces ChaCha20-Poly1305.
   *
   * @throws {Error} If file I/O fails, disk space is exhausted, or encryption bridge returns an error.
   *
   * @example
   * ```typescript
   * import { Keys } from "xypriss-security";
   *
   * // Encrypt a database backup or archive
   * await Keys.encryptFile(
   *   "/var/backups/db.tar.gz",
   *   "/var/backups/db.tar.gz.vault",
   *   "VeryStrongMasterPassphrase",
   *   { algorithm: "aes-256-gcm", keyDerivationIterations: 100000 }
   * );
   * ```
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
   * Decrypts a file previously encrypted with `Keys.encryptFile`.
   *
   * Automatically extracts the embedded 32-byte salt header, derives the symmetric key
   * using PBKDF2 (100,000 rounds), authenticates and decrypts all chunks, and writes
   * the output atomically.
   *
   * @param inputPath - Absolute path to the encrypted source file.
   * @param outputPath - Destination path for the decrypted plaintext file.
   * @param key - The raw passphrase originally used for encryption.
   *
   * @throws {Error} If authentication fails (tampering/wrong password) or file I/O fails.
   *
   * @example
   * ```typescript
   * import { Keys } from "xypriss-security";
   *
   * await Keys.decryptFile(
   *   "/var/backups/db.tar.gz.vault",
   *   "/var/backups/db-restored.tar.gz",
   *   "VeryStrongMasterPassphrase"
   * );
   * ```
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

// =================================== UTILITIES ==========================

/**
 * Generates a high-entropy 4096-bit RSA asymmetric key pair.
 *
 * @returns A promise resolving to an object containing PEM-formatted `publicKey` and `privateKey`.
 * @see {@link Keys.generateRSAKeyPair}
 */
export const generateRSAKeyPair = Keys.generateRSAKeyPair;

/**
 * Digitally signs arbitrary data using RSA-PSS with SHA-256.
 *
 * @param privateKey - The PEM-encoded RSA private key.
 * @param data - The data string to sign.
 * @returns A promise resolving to the signature as a hexadecimal string.
 * @see {@link Keys.rsaSign}
 */
export const rsaSign = Keys.rsaSign;

/**
 * Verifies an RSA-PSS signature against original data using the public key.
 *
 * @param publicKey - The PEM-encoded RSA public key.
 * @param data - The original data string that was signed.
 * @param signature - The hexadecimal signature string to verify.
 * @returns A promise resolving to `true` if valid, `false` otherwise.
 * @see {@link Keys.rsaVerify}
 */
export const rsaVerify = Keys.rsaVerify;

/**
 * Encrypts data using RSA-OAEP with SHA-256.
 *
 * @param publicKey - The recipient's PEM-encoded RSA public key.
 * @param data - The plaintext data string to encrypt.
 * @returns A promise resolving to the ciphertext in hex format.
 * @see {@link Keys.rsaEncrypt}
 */
export const rsaEncrypt = Keys.rsaEncrypt;

/**
 * Decrypts RSA-OAEP ciphertext using the recipient's private key.
 *
 * @param privateKey - The PEM-encoded RSA private key.
 * @param encryptedHex - The hex-encoded ciphertext to decrypt.
 * @returns A promise resolving to the decrypted plaintext string.
 * @see {@link Keys.rsaDecrypt}
 */
export const rsaDecrypt = Keys.rsaDecrypt;

/**
 * Verifies an Ed25519 digital signature.
 *
 * @param publicKey - The 32-byte Ed25519 public key (hex or `Uint8Array`).
 * @param data - Original data (string or `Uint8Array`).
 * @param signature - 64-byte Ed25519 signature (base64 or `Uint8Array`).
 * @returns `true` if the signature is valid, `false` otherwise.
 * @see {@link Keys.ed25519Verify}
 */
export const ed25519Verify = Keys.ed25519Verify;

/**
 * Derives a cryptographically strong symmetric key from an input secret.
 * Supports multiple algorithms including Scrypt, PBKDF2, HKDF, and Argon2id.
 *
 * @param input - The base secret, password, or key material.
 * @param options - Configuration options for the derivation process.
 * @returns A promise resolving to the derived key.
 * @see {@link Keys.deriveKey}
 */
export const deriveKey = Keys.deriveKey;

/**
 * Derives a raw cryptographic key of `keyLength` bytes using the Scrypt key derivation function.
 * Direct equivalent to Node.js `crypto.scryptSync`.
 *
 * @param password - The password, PIN, or passphrase.
 * @param salt - Cryptographic salt (string or `Uint8Array`).
 * @param keyLength - Desired key length in bytes (default: `64`).
 * @param cost - CPU/memory cost parameter $N$ (default: `16384`).
 * @param r - Block size parameter (default: `8`).
 * @param p - Parallelization parameter (default: `1`).
 * @returns Derived key as a hexadecimal string.
 * @see {@link Keys.scrypt}
 */
export const scrypt = Keys.scrypt;
