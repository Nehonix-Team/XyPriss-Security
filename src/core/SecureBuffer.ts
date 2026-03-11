/***************************************************************************
 * XyPriss Security Core - SecureBuffer
 *
 * An enhanced Uint8Array that provides familiar encoding methods
 * similar to Node.js Buffer, optimized for security operations.
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

import { __strl__ } from "strulink";
import {
  bufferToHex,
  bufferToBase64,
  bufferToString,
  bufferToBinary,
} from "../utils/encoding";

type localEncodings = "utf-8" | "hex" | "base64" | "binary" | "utf8";

/**
 * ### SecureBuffer
 *
 * A specialized version of Uint8Array that includes high-performance
 * encoding utilities. It maintains compatibility with standard Uint8Array
 * while adding the flexibility of Node-style Buffers.
 */
export class SecureBuffer extends Uint8Array {
  /**
   * Convert the buffer to a string with the specified encoding.
   *
   * @param encoding - The target encoding ('hex', 'base64', 'utf8', 'binary').
   * @returns The encoded string.
   */
  public override toString(
    encoding: Parameters<typeof __strl__.encode>[1] | localEncodings = "hex",
  ): string {
    switch (encoding.toLowerCase()) {
      case "hex":
        return bufferToHex(this);
      case "base64":
        return bufferToBase64(this);
      case "utf8":
      case "utf-8":
        return bufferToString(this);
      case "binary":
        return bufferToBinary(this);
      default:
        // If it looks like a standard JS toString call (e.g. from String(buf))
        // we might want to default to hex for security contexts or keep default.
        // But the user specifically asked for encodings.
        const rs = __strl__.encode(this.toString(), encoding as any);
        console.log("using strulink");
        return rs;
    }
  }

  /**
   * Alias for toBuffer() to maintain compatibility with older XyPriss versions.
   */
  public getBuffer(): Buffer {
    return this.toBuffer();
  }

  /**
   * Returns a standard Node.js Buffer representation.
   */
  public toBuffer(): Buffer {
    return Buffer.from(this);
  }

  /**
   * Returns a clean Uint8Array (stripping XyPriss enhancements).
   */
  public toUint8Array(): Uint8Array {
    return new Uint8Array(this);
  }

  /**
   * Slice with SecureBuffer return type.
   */
  public override slice(start?: number, end?: number): SecureBuffer {
    return new SecureBuffer(super.slice(start, end));
  }
}
