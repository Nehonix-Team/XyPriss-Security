/***************************************************************************
 * XyPriss Security - Unified Type System
 *
 * This module defines the core types and interfaces used throughout the
 * XyPriss Security framework. It ensures consistent data structures and
 * type safety across all security-related operations.
 *
 * @author NEHONIX (Nehonix-Team - https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

/**
 * Defines the security levels available for cryptographic operations.
 */
export enum SecurityLevel {
  STANDARD = "standard",
  HIGH = "high",
  MAXIMUM = "maximum",
}

/**
 * Supported hashing algorithms.
 * Includes both Node.js standard names and NIST standard names.
 */
export type HashAlgorithm =
  | "sha256"
  | "sha512"
  | "sha3-256"
  | "blake2b"
  | "pbkdf2"
  | "argon2id"
  | "scrypt";

/**
 * Supported output formats for cryptographic results.
 */
export type HashOutputFormat = "hex" | "base64" | "buffer" | "uint8array";

/**
 * Supported HMAC algorithms.
 */
export type HMACAlgorithm = "sha256" | "sha512" | "SHA-256" | "SHA-512";

/**
 * Base encoding types for data conversion.
 */
export type BaseEncodingType =
  | "hex"
  | "base64"
  | "base64url"
  | "utf-8"
  | "ascii";

/**
 * Configuration options for hashing operations.
 */
export interface HashOptions {
  /** The hashing algorithm to utilize. Defaults to 'sha256'. */
  algorithm?: HashAlgorithm | string;
  /** The desired output format of the hash (hex, base64, buffer). */
  outputFormat?: HashOutputFormat | string;
  /** The number of iterations for the hashing process (relevant for KDFs like PBKDF2). */
  iterations?: number;
  /** An optional salt to add entropy to the hash. */
  salt?: string | Uint8Array;
  /** Desired length of the output in bytes (relevant for PBKDF2). */
  keyLength?: number;
  /** Internal digest algorithm (relevant for PBKDF2). */
  digest?: HashAlgorithm | string;
}

/**
 * Detailed information about a cryptographic algorithm.
 */
export interface AlgorithmInfo {
  name: string;
  type: "hash" | "hmac" | "encryption" | "kdf";
  keySize?: number;
  blockSize?: number;
  ivSize?: number;
  description?: string;
  complexity?: AlgorithmComplexity;
}

export type AlgorithmComplexity = "standard" | "high" | "maximum";

/**
 * Enumeration of supported cryptographic algorithms for selection.
 */
export type CryptoAlgorithm =
  | "AES-256-GCM"
  | "CHACHA20-POLY1305"
  | "AES-256-CTR"
  | HashAlgorithm;

/**
 * Configuration for key derivation functions (KDF).
 */
export interface KeyDerivationOptions {
  /**
   * The derivation algorithm to utilize.
   * Defaults to 'argon2id'.
   */
  algorithm?: "pbkdf2" | "argon2id" | "scrypt" | "hkdf" | string;
  /**
   * Number of iterations or rounds for the hashing process.
   * High iteration counts increase resistance to brute-force attacks.
   */
  iterations?: number;
  /**
   * Desired length of the derived key in bytes.
   * Defaults to 32 (256-bit key) for most operations.
   */
  keyLength?: number;
  /**
   * Salt used in the derivation process to prevent rainbow table attacks.
   * If not provided, a secure random salt is typically generated.
   */
  salt?: string | Uint8Array;
  /**
   * Additional context/info string for HKDF operations.
   * Helps separate derived keys for different purposes from the same base secret.
   */
  info?: string | Uint8Array;
  /**
   * Digest algorithm to be used with the KDF (e.g., 'sha256', 'sha512').
   */
  digest?: HashAlgorithm | string;
  /**
   * Memory cost parameter for memory-hard algorithms like Argon2id.
   * Represents the memory usage in Kilobytes.
   */
  memoryCost?: number;
  /**
   * Time cost parameter for Argon2id, representing the number of passes over the memory.
   */
  timeCost?: number;
  /**
   * Parallelism degree for Argon2id (number of threads to use).
   */
  parallelism?: number;
  /** Legacy alias for salt - discouraged in new code. */
  hash?: string | Uint8Array;
}

/**
 * Options for configuring HMAC operations.
 */
export interface HMACOptions extends HashOptions {
  /** The secret key for the HMAC. */
  key: string | Uint8Array;
  /** The algorithm to use for the HMAC. */
  algorithm?: HMACAlgorithm | string;
}

/**
 * Options for PBKDF2 key derivation.
 */
export interface PBKDF2Options extends KeyDerivationOptions {
  /** The digest function used for HMAC in PBKDF2. */
  digest?: HashAlgorithm | string;
}

/**
 * Configuration for password hashing and verification.
 */
export interface PasswordHashOptions extends KeyDerivationOptions {
  /** A secret pepper value applied before hashing. */
  pepper?: string;
  /** The specific algorithm for password hashing. */
  algorithm?: "argon2id" | "scrypt" | "pbkdf2" | string;
}

/**
 * Options for generating secure random tokens.
 */
export interface SecureTokenOptions {
  /** Length of the token. */
  length?: number;
  /** Whether to include uppercase characters. */
  includeUppercase?: boolean;
  /** Whether to include lowercase characters. */
  includeLowercase?: boolean;
  /** Whether to include numeric digits. */
  includeNumbers?: boolean;
  /** Whether to include special symbols. */
  includeSymbols?: boolean;
  /** Whether to exclude similar characters (e.g., 'i' and '1'). */
  excludeSimilarCharacters?: boolean;
  /** Level of entropy required for the token. */
  entropy?: "standard" | "high" | "maximum";
}

/**
 * Options for generating unique API keys.
 */
export interface APIKeyOptions {
  /** Prefix for the API key. */
  prefix?: string;
  /** Separator between key components. */
  separator?: string;
  /** Whether to include a timestamp. */
  includeTimestamp?: boolean;
  /** Length of the random portion of the key. */
  randomPartLength?: number;
  /** Encoding format for the key. */
  encoding?: BaseEncodingType;
}

/**
 * Configuration for session token generation.
 */
export interface SessionTokenOptions {
  /** Optional user identifier associated with the session. */
  userId?: string;
  /** Optional IP address for session binding. */
  ipAddress?: string;
  /** Optional user agent string for session binding. */
  userAgent?: string;
  /** Session expiration time in seconds. */
  expiresIn?: number;
}

/**
 * Represents the result of a security verification operation.
 */
export interface SecurityResult<T = any> {
  /** Indicates if the operation was successful. */
  success: boolean;
  /** The resulting data of the operation. */
  data?: T;
  /** An error message if the operation failed. */
  error?: string;
  /** Additional metadata associated with the result. */
  metadata?: Record<string, any>;
}

/**
 * Detailed result of a password strength evaluation.
 */
export interface PasswordStrengthResult {
  /** Numerical score representing password strength (0-100). */
  score: number;
  /** Qualitative feedback regarding password security. */
  feedback: string[];
  /** Estimated time required to crack the password. */
  estimatedCrackTime: string;
  /** Granular analysis of password components. */
  analysis: {
    length: number;
    entropy: number;
    variety: number;
    patterns: number;
  };
}

/**
 * Configuration for initializing a SecureObject.
 */
export interface SecureObjectOptions {
  /** The master encryption key for sensitive fields. */
  encryptionKey?: string;
  /** Whether to track metadata for each stored value. */
  enableMetadata?: boolean;
  /** Whether to automatically clean up memory resources. */
  autoCleanup?: boolean;
  /** Whether the object should be immutable after creation. */
  readOnly?: boolean;
  /** Maximum memory allocation permitted for the object. */
  maxMemory?: number;
  /** Threshold for triggering garbage collection. */
  gcThreshold?: number;
  /** Whether to enable active memory tracking. */
  enableMemoryTracking?: boolean;
}

/**
 * Acceptable values for storage in secure data structures.
 */
export type SecureValue =
  | string
  | number
  | boolean
  | null
  | Uint8Array
  | object
  | any;

/**
 * Aggregated statistics for cryptographic operations.
 */
export interface CryptoStats {
  /** Total number of operations performed. */
  operationsCount: number;
  /** Average latency per operation in milliseconds. */
  averageLatency: number;
  /** Current memory usage in bytes. */
  memoryUsage: number;
  /** Number of failed operations. */
  errorsCount: number;
  /** Description of the last operation performed. */
  lastOperation?: string;
  /** Timestamp of the last update. */
  timestamp: number;
}
