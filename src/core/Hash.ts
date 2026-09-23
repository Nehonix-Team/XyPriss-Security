/***************************************************************************
 * XyPriss Security Core - Hash Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import {
  HashOptions,
  HMACAlgorithm,
  HashAlgorithm,
  HashBufferFormat,
  HashStringFormat,
} from "../types";
import { Random } from "./Random";
import { SecureBuffer } from "./SecureBuffer";

/**
 * ### Hash Class
 *
 * Provides high-performance hashing and HMAC operations powered by the Go core.
 */
export class Hash {
  /**
   * Creates a secure cryptographic hash returning a `SecureBuffer` when binary output (`"buffer"` or `"uint8array"`) is requested.
   *
   * @param input - The string or buffer data to be hashed.
   * @param options - Configuration specifying `outputFormat: "buffer" | "uint8array"`.
   * @returns A `SecureBuffer` containing the raw hash bytes.
   */
  public static create(
    input: string | Uint8Array,
    options: HashOptions<HashBufferFormat> & { outputFormat: HashBufferFormat },
  ): SecureBuffer;

  /**
   * Creates a secure cryptographic hash truncated to a specific string length.
   * Useful for generating short unique IDs or compact tokens.
   *
   * @param input - The string or buffer data to be hashed.
   * @param length - Maximum character length of the resulting hex string (e.g. `12`).
   * @returns The truncated hexadecimal hash string.
   */
  public static create(
    input: string | Uint8Array,
    length: number,
  ): string;

  /**
   * Creates a secure cryptographic hash using a specific algorithm and optional length.
   *
   * @param input - The string or buffer data to be hashed.
   * @param algorithm - Cryptographic hash algorithm (e.g. `"sha256"`, `"blake2b"`, `"sha512"`).
   * @param length - Optional maximum character length to truncate the output.
   * @returns The hexadecimal hash string.
   */
  public static create(
    input: string | Uint8Array,
    algorithm: HashAlgorithm,
    length?: number,
  ): string;

  /**
   * Creates a secure cryptographic hash returning a string in hex or base64 format.
   *
   * @param input - The string or buffer data to be hashed.
   * @param options - Optional configuration for algorithm, salt, format, and length.
   * @returns The resulting cryptographic hash string.
   */
  public static create(
    input: string | Uint8Array,
    options?: HashOptions<HashStringFormat>,
  ): string;

  /**
   * General implementation of hash creation.
   */
  public static create(
    input: string | Uint8Array,
    optionsOrAlgoOrLength?: HashOptions | HashAlgorithm | number,
    lengthParam?: number,
  ): string | SecureBuffer {
    let options: HashOptions = {};
    if (typeof optionsOrAlgoOrLength === "number") {
      options = { length: optionsOrAlgoOrLength };
    } else if (typeof optionsOrAlgoOrLength === "string") {
      options = {
        algorithm: optionsOrAlgoOrLength as HashAlgorithm,
        length: typeof lengthParam === "number" ? lengthParam : undefined,
      };
    } else if (optionsOrAlgoOrLength && typeof optionsOrAlgoOrLength === "object") {
      options = { ...optionsOrAlgoOrLength };
      if (typeof lengthParam === "number") {
        options.length = lengthParam;
      }
    }

    const algo = (options.algorithm?.toString() || "sha256").toLowerCase();
    let resultHex: string;

    if (algo === "pbkdf2") {
      const salt = options.salt
        ? typeof options.salt === "string"
          ? Buffer.from(options.salt)
          : options.salt
        : Random.getRandomBytes(32).toUint8Array();
      const iterations = options.iterations || 100000;
      const keyLen = options.keyLength || 32;
      const digest = options.digest || "sha256";
      resultHex = Bridge.pbkdf2(
        input.toString(),
        salt,
        iterations,
        keyLen,
        digest,
      );
    } else if (algo === "argon2id" || algo === "scrypt") {
      resultHex = Bridge.hashPassword(input.toString(), algo);
    } else {
      resultHex = Bridge.hash(input, algo);
    }

    if (resultHex.startsWith("error:")) throw new Error(resultHex);

    const format = options.outputFormat || "hex";
    switch (format) {
      case "buffer":
      case "uint8array": {
        const matches = resultHex.match(/.{1,2}/g) || [];
        const bytes = new Uint8Array(matches.map((byte) => parseInt(byte, 16)));
        const finalBytes =
          typeof options.length === "number" && options.length > 0
            ? bytes.subarray(0, options.length)
            : bytes;
        return new SecureBuffer(finalBytes);
      }
      case "base64": {
        const buf = Buffer.from(resultHex, "hex");
        const b64 = buf.toString("base64");
        return typeof options.length === "number" && options.length > 0
          ? b64.substring(0, options.length)
          : b64;
      }
      default: {
        return typeof options.length === "number" && options.length > 0
          ? resultHex.substring(0, options.length)
          : resultHex;
      }
    }
  }

  /**
   * Generates a PKCE code challenge from a code verifier.
   *
   * @param verifier - The code verifier string.
   * @param method - The challenge method (default: 'S256').
   * @returns The generated code challenge.
   */
  public static pkce(
    verifier: string,
    method: "S256" | "plain" = "S256",
  ): string {
    if (method === "plain") return verifier;

    // S256: base64url(sha256(verifier))
    const hashed = Bridge.sha256(verifier);
    const buf = Buffer.from(hashed, "hex");
    return buf
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  /**
   * Creates a Message Authentication Code (HMAC) using a secret key.
   *
   * @param key - The secret key used for authentication.
   * @param data - The data to be authenticated.
   * @param algo - The HMAC algorithm (default: "sha256").
   * @returns The resulting HMAC signature as a hex string.
   */
  public static hmac(
    key: string | Uint8Array,
    data: string | Uint8Array,
    algo: HMACAlgorithm = "sha256",
  ): string {
    const res = Bridge.hmac(key, data, algo);
    if (res.startsWith("error:")) throw new Error(res);
    return res;
  }

  /**
   * Compares two buffers or strings in constant time to prevent timing side-channel attacks.
   * Direct equivalent to Node.js `crypto.timingSafeEqual`.
   *
   * @param a - First buffer or string to compare.
   * @param b - Second buffer or string to compare.
   * @returns True if both values are strictly equal, false otherwise.
   *
   * @example
   * ```typescript
   * // Comparing hex strings directly
   * const isMatch = Hash.timingSafeEqual(storedHashHex, calculatedHashHex);
   *
   * // Comparing Buffers / Uint8Arrays
   * const isBufMatch = Hash.timingSafeEqual(Buffer.from(key, "hex"), Buffer.from(hash, "hex"));
   * ```
   */
  public static timingSafeEqual(
    a: string | Uint8Array,
    b: string | Uint8Array,
  ): boolean {
    const bufA = typeof a === "string" ? Buffer.from(a) : a;
    const bufB = typeof b === "string" ? Buffer.from(b) : b;
    return Bridge.constantTimeCompare(bufA, bufB);
  }

  /**
   * Legacy alias for hmac with proper typing.
   */
  public static createSecureHMAC(
    algo: HMACAlgorithm,
    key: string | Uint8Array,
    data: string | Uint8Array,
  ): string {
    return this.hmac(key, data, algo);
  }
}

/**
 * Compares two buffers or strings in constant time to prevent timing attacks.
 * Direct replacement for Node.js `crypto.timingSafeEqual`.
 */
export const timingSafeEqual = Hash.timingSafeEqual;

