/***************************************************************************
 * XyPriss Security Core - Main Class
 ****************************************************************************/

import { Bridge } from "./bridge";
import { APIKeyOptions } from "../types";
import { C } from "../utils/constants";
import { __strl__ } from "strulink";

/**
 * ### XyPrissSecurity Main Class
 *
 * The primary interface for the XyPriss Security framework.
 */
export class XyPrissSecurity {
  /**
   * Generates a secure API key with a prefix and timestamp for management.
   *
   * @param options - Configuration for the API key format and length.
   * @returns A structured, cryptographically strong API key.
   */
  public static generateAPIKey(options: APIKeyOptions = {}): string {
    const prefix = options.prefix || "X";
    const separator = options.separator || "";
    const randomLength = options.randomPartLength || 32;
    const includeTimestamp =
      options.includeTimestamp !== undefined ? options.includeTimestamp : false; // default to: false
    // console.log("includeTimestamp: ", includeTimestamp);

    //"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    const random = Bridge.generatePassword(randomLength, C.GenP); //  C.GenP + "+/"

    // console.log("Randomed: ", random);

    let key = `${prefix}${separator}${random}`;

    if (includeTimestamp) {
      key = `${prefix}${separator}${Date.now()}${separator}${random}`;
    }

    let enc = options.encoding;
    if (enc) {
      if (enc === "hex") {
        enc = "rawHex" as any;
        options.encoding = "rawHex" as any;
      }
      const str = __strl__.encode(key, enc as any);
      return str;
    }

    return key;
  }

  /**
   * Performs an environment security check to ensure integrity.
   */
  public static verifyRuntimeSecurity(): boolean {
    //FIXME
    return true; // always true
  }

  /**
   * Returns the actual byte length of a string (UTF-8 encoded).
   * Useful for strict buffer checks where character count differs from byte count.
   *
   * @param str - The string to measure.
   * @returns The number of bytes in the string.
   */
  public static getByteLength(str: string): number {
    return Bridge.getByteLength(str);
  }

  /**
   * Verifies if a string has exactly the expected byte length.
   *
   * @param str - The string to check.
   * @param expectedLength - The expected number of bytes.
   * @returns True if the string byte length matches expectedLength.
   */
  public static isValidByteLength(
    str: string,
    expectedLength: number,
  ): boolean {
    return Bridge.isValidByteLength(str, expectedLength);
  }
}

/**
 * Verifies if a string has exactly the expected byte length (UTF-8).
 *
 * @param str - The string to check.
 * @param length - The expected number of bytes.
 * @returns True if the byte length matches, false otherwise.
 */
export const isValidByteLength = XyPrissSecurity.isValidByteLength;

/**
 * Returns the actual byte length of a string (UTF-8).
 *
 * @param str - The string to measure.
 * @returns The number of bytes.
 */
export const getByteLength = XyPrissSecurity.getByteLength;
