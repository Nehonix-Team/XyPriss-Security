/***************************************************************************
 * XyPriss Security Core - Hash Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import { HashOptions, HMACAlgorithm } from "../types";
import { Random } from "./Random";
import { SecureBuffer } from "./SecureBuffer";
import { stringToBuffer } from "../utils";

/**
 * ### Hash Class
 *
 * Provides high-performance hashing and HMAC operations powered by the Go core.
 */
export class Hash {
  /**
   * Creates a secure hash of the provided input data.
   *
   * @param input - The string or buffer data to be hashed.
   * @param options - Configuration for the hashing algorithm and output format.
   * @returns The resulting hash as a string or SecureBuffer.
   */
  public static create(
    input: string | Uint8Array,
    options: HashOptions = {},
  ): string | SecureBuffer {
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
      case "uint8array":
        const matches = resultHex.match(/.{1,2}/g) || [];
        return new SecureBuffer(
          new Uint8Array(matches.map((byte) => parseInt(byte, 16))),
        );
      case "base64":
        const buf = Buffer.from(resultHex, "hex");
        return buf.toString("base64") as any;
      default:
        return resultHex;
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
    algo: string = "sha256",
  ): string {
    const res = Bridge.hmac(key, data, algo);
    if (res.startsWith("error:")) throw new Error(res);
    return res;
  }

  /**
   * Legacy alias for hmac with proper typing.
   */
  public static createSecureHMAC(
    algo: HMACAlgorithm | string,
    key: string | Uint8Array,
    data: string | Uint8Array,
  ): string {
    return this.hmac(key, data, algo);
  }
}
