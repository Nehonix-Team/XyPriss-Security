// ─── Types ────────────────────────────────────────────────────────────────────

import { PasswordHashOptions } from ".";

/**
 * Constructor options for `PasswordManager`.
 * These become the permanent defaults for every `hash()` and `verify()` call.
 */
export interface PasswordManagerOptions extends PasswordHashOptions {
  /**
   * Hashing algorithm to use.
   * @default "argon2id"
   */
  algorithm?: "argon2id" | "scrypt" | "pbkdf2" | string;

  /**
   * Memory cost in KiB (Argon2id).
   * Higher = more resistant to brute-force at the cost of RAM.
   * @default 65536 (64 MiB)
   */
  memoryCost?: number;

  /**
   * Number of time iterations (Argon2id / PBKDF2).
   * @default 3
   */
  iterations?: number;

  /**
   * Degree of parallelism / thread count (Argon2id).
   * @default 4
   */
  parallelism?: number;

  /**
   * Secret pepper appended to every password before hashing.
   * Store separately from the database (e.g., an environment variable).
   */
  pepper?: string;
}

/**
 * Criteria for generating a secure random password.
 */
export interface PasswordGenerateOptions {
  /**
   * Total length of the generated password.
   * Must be between 8 and 512 inclusive.
   * @default 20
   */
  length?: number;
  /** Include uppercase letters (A-Z). @default true */
  uppercase?: boolean;
  /** Include lowercase letters (a-z). @default true */
  lowercase?: boolean;
  /** Include digits (0-9). @default true */
  numbers?: boolean;
  /** Include special symbols. @default true */
  symbols?: boolean;
  /** Remove visually similar characters (e.g. 0, O, l, 1). @default false */
  excludeSimilar?: boolean;
  /**
   * Custom characters to inject into the password (guarantee at least one
   * occurrence of each char in this string).
   * Extra chars are *injected* at random positions, not appended.
   */
  extra?: string;
}

/**
 * Criteria for generating a memorable passphrase.
 */
export interface PassphraseOptions {
  /**
   * Number of words in the passphrase.
   * Must be between 3 and 20 inclusive.
   * @default 5
   */
  wordCount?: number;
  /** Word separator. @default "-" */
  separator?: string;
  /** Capitalize the first letter of each word. @default true */
  capitalize?: boolean;
  /**
   * Append a random number block at the end (e.g. "-4827").
   * Significantly increases entropy.
   * @default true
   */
  appendNumbers?: boolean;

  // ── Wordlist source (optional) ─────────────────────────────────────────────
  /**
   * EFF wordlist variant to use.
   * - `"large"` (default): 7 776 words, ~12.9 bits/word
   * - `"short1"`: 1 296 words, ~10.3 bits/word
   * - `"short2"`: 1 296 words, ~10.3 bits/word (uniquely decodable)
   * @default "large"
   */
  variant?: "large" | "short1" | "short2";
  /**
   * Directory containing the EFF `.txt` wordlist files.
   * Defaults to the `src/mods/` directory bundled with the package.
   */
  dir?: string;
  /**
   * Custom file path to an EFF-formatted wordlist.
   * Takes precedence over `dir` + `variant`.
   */
  filePath?: string;
  /**
   * Fallback behaviour if the EFF file cannot be loaded.
   * - `"silent"` (default): use built-in 256-word list silently.
   * - `"warn"`: use built-in list but print a console warning.
   * - `false`: throw an error instead of falling back.
   * @default "silent"
   */
  allowFallback?: "silent" | "warn" | false;
}

/**
 * Result of a password strength analysis.
 */
export interface PasswordStrengthResult {
  /** Score from 0 (very weak) to 100 (extremely strong). */
  score: number;
  /** Human-readable label. */
  label: "very-weak" | "weak" | "fair" | "strong" | "very-strong";
  /** Specific improvement suggestions. */
  suggestions: string[];
  /** Detailed breakdown of the analysis. */
  analysis: {
    length: number;
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasNumbers: boolean;
    hasSymbols: boolean;
    hasRepeats: boolean;
    hasSequences: boolean;
    entropy: number;
  };
}

/**
 * Result of a HaveIBeenPwned breach check.
 */
export interface BreachCheckResult {
  /** Whether the password was found in any known breach corpus. */
  breached: boolean;
  /**
   * Number of times the password appeared across all known breaches.
   * `0` means no match was found.
   */
  occurrences: number;
}
