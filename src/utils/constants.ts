/**
 * Constants used throughout the library
 */

/**
 * Character sets for token generation
 */
export const CHAR_SETS = {
  /**
   * Uppercase letters
   */
  UPPERCASE: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",

  /**
   * Lowercase letters
   */
  LOWERCASE: "abcdefghijklmnopqrstuvwxyz",

  /**
   * Numeric characters
   */
  NUMBERS: "0123456789",

  /**
   * Special symbols
   */
  SYMBOLS: "!@#$%^&*()_+-=[]{}|;:,.<>?",

  /**
   * Similar characters that can be confused
   */
  SIMILAR_CHARS: "il1Lo0O",
  RSIMILAR_CHARS: /[il1Lo0O]/g,

  /**
   * Base58 alphabet (Bitcoin style, no similar characters)
   */
  B58: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",

  /**
   * Charset for gen pass
   */
  GenP: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",

  /**
   * Base32 alphabet (RFC 4648)
   */
  B32: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
};

export { CHAR_SETS as C };
