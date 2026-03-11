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

    /**
     * Base58 alphabet (Bitcoin style, no similar characters)
     */
    BASE58: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",

    /**
     * Base32 alphabet (RFC 4648)
     */
    BASE32: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
};
