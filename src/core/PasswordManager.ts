/***************************************************************************
 * XyPriss Security - Advanced Hyper-Modular Security Framework
 *
 * @author NEHONIX (Nehonix-Team - https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 ****************************************************************************/

import { createHash } from "crypto";
import { join } from "path";
import { Password } from "./Password";
import { Random } from "./Random";
import {
  CHARSETS,
  MIN_GENERATE_LENGTH,
  MAX_GENERATE_LENGTH,
  getWordlist,
} from "../mods/PasswordMDict";
import type {
  PasswordManagerOptions,
  BreachCheckResult,
  PassphraseOptions,
  PasswordGenerateOptions,
  PasswordStrengthResult,
} from "../types/PasswordManagerOptions";

// ─── PasswordManager ──────────────────────────────────────────────────────────

/***************************************************************************
 * ### PasswordManager
 *
 * A configurable, instance-based password manager.
 * Unlike the static `Password` class, `PasswordManager` is instantiated
 * once with all options pre-configured, so callers only need to pass
 * the raw password string at call time.
 *
 * This is the recommended pattern for large-scale projects:
 * configure once in a dedicated file, export the instance, and reuse
 * everywhere without repeating options.
 *
 * @example
 * // config/security.ts
 * export const passwords = new PasswordManager({
 *   algorithm: "argon2id",
 *   memoryCost: 65536,
 *   parallelism: 4,
 *   iterations: 3,
 *   pepper: process.env.PASSWORD_PEPPER,
 * });
 *
 * // anywhere in the app:
 * const hash       = await passwords.hash("user-raw-password");
 * const valid      = await passwords.verify("user-raw-password", hash);
 * const temp       = passwords.generate({ length: 24, symbols: true });
 * const passphrase = passwords.generatePassphrase({ wordCount: 5 });
 * const pin        = passwords.generatePin(6);
 * const info       = passwords.strength("MyP@ss1!");
 * const breach     = await passwords.isBreached("hunter2");
 * const stale      = passwords.needsRehash(storedHash);
 */
export class PasswordManager {
  private readonly algo: string;
  private readonly memoryCost: number;
  private readonly iterations: number;
  private readonly parallelism: number;
  private readonly pepper: string | undefined;

  constructor(options: PasswordManagerOptions = {}) {
    this.algo = (options.algorithm ?? "argon2id").toLowerCase();
    this.memoryCost = options.memoryCost ?? 65536; // 64 MiB
    this.iterations = options.iterations ?? 3;
    this.parallelism = options.parallelism ?? 4;
    this.pepper = options.pepper;
  }

  // ─── Hashing ───────────────────────────────────────────────────────────────

  /**
   * Hashes a password using the instance's pre-configured options.
   *
   * @param password - The plain-text password to hash.
   * @param overrides - Optional per-call overrides for any constructor option.
   * @returns The encoded hash string, ready to be stored.
   */
  public async hash(
    password: string,
    overrides: Partial<PasswordManagerOptions> = {},
  ): Promise<string> {
    const pepper = overrides.pepper ?? this.pepper;
    const finalPassword = pepper ? password + pepper : password;

    return Password.hash(finalPassword, {
      algorithm: overrides.algorithm ?? this.algo,
      memoryCost: overrides.memoryCost ?? this.memoryCost,
      iterations: overrides.iterations ?? this.iterations,
      parallelism: overrides.parallelism ?? this.parallelism,
    });
  }

  /**
   * Verifies a plain-text password against a stored hash.
   *
   * @param password - The password to verify.
   * @param hash - The stored hash to compare against.
   * @param overrides - Optional per-call override for the pepper.
   * @returns `true` if the password matches the hash, `false` otherwise.
   */
  public async verify(
    password: string,
    hash: string,
    overrides: Pick<PasswordManagerOptions, "pepper"> = {},
  ): Promise<boolean> {
    const pepper = overrides.pepper ?? this.pepper;
    const finalPassword = pepper ? password + pepper : password;
    return Password.verify(finalPassword, hash);
  }

  /**
   * Checks if a string is a valid XyPriss hash, optionally matching
   * this manager's current algorithm.
   *
   * @param hash - The string to check.
   * @param strict - If `true`, only returns `true` if the hash matches the manager's algorithm.
   * @returns `true` if it's a valid hash, `false` otherwise.
   */
  public isHashed(hash: string, strict: boolean = true): boolean {
    return Password.isHashed(hash, strict ? this.algo : undefined);
  }

  // ─── Generation ────────────────────────────────────────────────────────────

  /**
   * Generates a cryptographically secure random password matching the given
   * criteria, with **guaranteed character-type coverage**.
   *
   * Security properties:
   * - Every enabled character type appears **at least once** in the output.
   * - `extra` characters are **injected at cryptographically random positions**
   *   rather than appended, ensuring they don't cluster at the end.
   * - The final array is **Fisher-Yates shuffled** via `Random.Int` to remove
   *   any positional bias introduced during construction.
   * - `length` is clamped to [8, 512] to prevent misuse.
   * - Throws `RangeError` if no character type is enabled (empty charset).
   *
   * @param options - Character set and length configuration.
   * @returns A plain-text randomly generated password string.
   *
   * @example
   * const pwd = passwords.generate({ length: 24, symbols: true });
   */
  public generate(options: PasswordGenerateOptions = {}): string {
    const {
      uppercase = true,
      lowercase = true,
      numbers = true,
      symbols = true,
      excludeSimilar = false,
      extra = "",
    } = options;

    // ── 1. Clamp & validate length ──────────────────────────────────────────
    const length = Math.min(
      MAX_GENERATE_LENGTH,
      Math.max(MIN_GENERATE_LENGTH, Math.floor(options.length ?? 20)),
    );

    // ── 2. Build charset ────────────────────────────────────────────────────
    let charset = "";
    const mandatory: string[] = []; // at least one char from each active set

    const addSet = (chars: string, enabled: boolean): void => {
      if (!enabled) return;
      const cleaned = excludeSimilar
        ? chars.replace(CHARSETS.similarChars, "")
        : chars;
      if (cleaned.length === 0) return;
      charset += cleaned;
      // Reserve one guaranteed character from this set
      mandatory.push(cleaned[Random.Int(0, cleaned.length)]);
    };

    addSet(CHARSETS.lowercase, lowercase);
    addSet(CHARSETS.uppercase, uppercase);
    addSet(CHARSETS.numbers, numbers);
    addSet(CHARSETS.symbols, symbols);

    if (charset.length === 0) {
      throw new RangeError(
        "PasswordManager.generate: no character types enabled — charset is empty.",
      );
    }

    // Guarantee at least one char per extra string (injected, not appended)
    if (extra) {
      for (const ch of extra) {
        if (!charset.includes(ch)) charset += ch;
        mandatory.push(ch);
      }
    }

    // ── 3. Guard: mandatory set cannot exceed requested length ───────────────
    if (mandatory.length > length) {
      throw new RangeError(
        `PasswordManager.generate: requested length (${length}) is too short ` +
          `to satisfy all enabled character types (need at least ${mandatory.length}).`,
      );
    }

    // ── 4. Fill remaining slots from full charset ────────────────────────────
    const arr: string[] = [...mandatory];
    const remaining = length - arr.length;

    for (let i = 0; i < remaining; i++) {
      arr.push(charset[Random.Int(0, charset.length)]);
    }

    // ── 5. Fisher-Yates shuffle (crypto-safe via Random.Int) ─────────────────
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Random.Int(0, i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    return arr.join("");
  }

  // ─── Passphrase Generation ─────────────────────────────────────────────────

  /**
   * Generates a **memorable, high-entropy passphrase** using a curated
   * 256-word list (similar to Diceware / EFF methodology).
   *
   * Entropy: `log2(256^wordCount)` = `8 * wordCount` bits minimum.
   * With 5 words: ~40 bits base + number suffix ≈ 53 bits total.
   * With 6 words: ~48 bits base + number suffix ≈ 61 bits total.
   *
   * Security note: word selection uses `Random.Int` which must be backed
   * by a CSPRNG (e.g. `crypto.randomInt`).
   *
   * @param options - Passphrase configuration.
   * @returns A plain-text passphrase string.
   *
   * @example
   * passwords.generatePassphrase({ wordCount: 5, separator: "-" });
   * // → "Bold-Cave-Iron-Jump-Warm-4827"
   */
  public generatePassphrase(options: PassphraseOptions = {}): string {
    const {
      wordCount = 5,
      separator = "-",
      capitalize = true,
      appendNumbers = true,
      variant = "large",
      dir,
      filePath,
      allowFallback = "silent",
    } = options;

    if (wordCount < 3 || wordCount > 20) {
      throw new RangeError(
        "PasswordManager.generatePassphrase: wordCount must be between 3 and 20.",
      );
    }

    // Resolve the bundled mods dir relative to this compiled file
    // dist/src/core/PasswordManager.js → ../../mods  (production)
    // src/core/PasswordManager.ts      → ../mods      (dev/bun direct)
    const modsDir =
      dir ??
      join(__dirname, "..", "mods") +
        // ts-source fallback: if __dirname ends with /core, ../mods resolves correctly
        "";

    const wordlist = getWordlist({
      dir: modsDir,
      variant,
      filePath,
      allowFallback,
    });

    const words: string[] = [];
    for (let i = 0; i < wordCount; i++) {
      let word = wordlist[Random.Int(0, wordlist.length)];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      words.push(word);
    }

    if (appendNumbers) {
      // 4-digit suffix adds ~13 extra bits of entropy
      const suffix = String(Random.Int(1000, 9999));
      words.push(suffix);
    }

    return words.join(separator);
  }

  // ─── PIN Generation ────────────────────────────────────────────────────────

  /**
   * Generates a cryptographically secure numeric PIN.
   *
   * Each digit is drawn independently from the full [0-9] range.
   * The PIN is **zero-padded** to the requested length and returned as a
   * string to preserve leading zeros (e.g. "0472").
   *
   * @param length - Number of digits. Must be between 4 and 32. @default 6
   * @returns A plain-text numeric PIN string.
   *
   * @example
   * passwords.generatePin(6); // → "047291"
   */
  public generatePin(length: number = 6): string {
    if (!Number.isInteger(length) || length < 4 || length > 32) {
      throw new RangeError(
        "PasswordManager.generatePin: length must be an integer between 4 and 32.",
      );
    }

    const digits: string[] = [];
    for (let i = 0; i < length; i++) {
      digits.push(String(Random.Int(0, 10)));
    }
    return digits.join("");
  }

  // ─── Strength Analysis ─────────────────────────────────────────────────────

  /**
   * Evaluates the strength of a password and returns a detailed report.
   *
   * The score is computed from multiple orthogonal criteria:
   * - Length (up to 30 points)
   * - Character variety (up to 50 points)
   * - Absence of repetitions and sequences (up to 20 points deducted)
   *
   * @param password - The password to evaluate.
   * @returns A `PasswordStrengthResult` with score, label, and actionable suggestions.
   *
   * @example
   * const info = passwords.strength("MyP@ssw0rd!");
   * console.log(info.score, info.label); // 82 "strong"
   */
  public strength(password: string): PasswordStrengthResult {
    const suggestions: string[] = [];

    // ── Characteristic flags ────────────────────────────────────────────────
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSymbols = /[^A-Za-z0-9]/.test(password);
    const hasRepeats = /(.)\1{2,}/.test(password);
    const hasSequences =
      /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(
        password,
      );

    // ── Length score (0-30) ─────────────────────────────────────────────────
    const len = password.length;
    let lengthScore = 0;
    if (len >= 8) lengthScore += 10;
    if (len >= 12) lengthScore += 10;
    if (len >= 16) lengthScore += 5;
    if (len >= 20) lengthScore += 5;

    // ── Variety score (0-50) ────────────────────────────────────────────────
    let varietyScore = 0;
    if (hasLowercase) varietyScore += 10;
    if (hasUppercase) varietyScore += 10;
    if (hasNumbers) varietyScore += 10;
    if (hasSymbols) varietyScore += 15;
    if (hasLowercase && hasUppercase && hasNumbers && hasSymbols)
      varietyScore += 5;

    // ── Penalty score (0..20 subtracted) ───────────────────────────────────
    let penaltyScore = 0;
    if (hasRepeats) penaltyScore += 10;
    if (hasSequences) penaltyScore += 10;

    // ── Entropy estimation (bits) ───────────────────────────────────────────
    let charsetSize = 0;
    if (hasLowercase) charsetSize += 26;
    if (hasUppercase) charsetSize += 26;
    if (hasNumbers) charsetSize += 10;
    if (hasSymbols) charsetSize += 32;
    const entropy =
      charsetSize > 0 ? Math.round(len * Math.log2(charsetSize)) : 0;

    const score = Math.max(
      0,
      Math.min(100, lengthScore + varietyScore - penaltyScore),
    );

    // ── Suggestions ────────────────────────────────────────────────────────
    if (len < 8) suggestions.push("Use at least 8 characters.");
    if (len < 12) suggestions.push("A length of 12 or more is recommended.");
    if (len < 16)
      suggestions.push("Aim for 16+ characters for high-security contexts.");
    if (!hasUppercase) suggestions.push("Add uppercase letters (A-Z).");
    if (!hasLowercase) suggestions.push("Add lowercase letters (a-z).");
    if (!hasNumbers) suggestions.push("Include at least one digit (0-9).");
    if (!hasSymbols)
      suggestions.push("Include at least one special character (!@#$%...).");
    if (hasRepeats)
      suggestions.push("Avoid repeating characters (e.g. 'aaa').");
    if (hasSequences)
      suggestions.push("Avoid common sequences (e.g. '123', 'abc').");

    // ── Label ──────────────────────────────────────────────────────────────
    let label: PasswordStrengthResult["label"];
    if (score < 20) label = "very-weak";
    else if (score < 40) label = "weak";
    else if (score < 60) label = "fair";
    else if (score < 80) label = "strong";
    else label = "very-strong";

    return {
      score,
      label,
      suggestions,
      analysis: {
        length: len,
        hasUppercase,
        hasLowercase,
        hasNumbers,
        hasSymbols,
        hasRepeats,
        hasSequences,
        entropy,
      },
    };
  }

  // ─── Breach Check ──────────────────────────────────────────────────────────

  /**
   * Checks whether a password has appeared in a publicly known data breach
   * using the **HaveIBeenPwned Pwned Passwords API v3** with **k-anonymity**.
   *
   * The full password is **never transmitted**. Only the first 5 characters of
   * its SHA-1 hex digest are sent over the network; the remainder of the
   * matching is performed locally.
   *
   * @param password - The plain-text password to check.
   * @returns A `BreachCheckResult` indicating breach status and occurrence count.
   * @throws If the network request fails or returns an unexpected status code.
   *
   * @example
   * const result = await passwords.isBreached("hunter2");
   * if (result.breached) {
   *   console.warn(`Password found ${result.occurrences} times in breach databases.`);
   * }
   */
  public async isBreached(password: string): Promise<BreachCheckResult> {
    const sha1 = createHash("sha1")
      .update(password)
      .digest("hex")
      .toUpperCase();

    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: {
          // Padding header reduces response-size side-channel leakage
          "Add-Padding": "true",
        },
      },
    );

    if (!response.ok) {
      throw new Error(
        `PasswordManager.isBreached: HIBP API returned HTTP ${response.status}.`,
      );
    }

    const body = await response.text();

    // Each line: "<SUFFIX>:<COUNT>" or "<SUFFIX>:0" (padding entries)
    for (const line of body.split("\r\n")) {
      const [hashSuffix, countStr] = line.split(":");
      if (hashSuffix === suffix) {
        const occurrences = parseInt(countStr, 10);
        return { breached: occurrences > 0, occurrences };
      }
    }

    return { breached: false, occurrences: 0 };
  }

  // ─── Rehash Detection ──────────────────────────────────────────────────────

  /**
   * Determines whether a stored hash was produced with weaker parameters than
   * the instance's current configuration (e.g. after a security upgrade).
   *
   * Supports Argon2id hash strings in the PHC string format:
   * `$argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<hash>`
   *
   * For other algorithms, returns `false` (no opinion) so the caller can
   * decide on a case-by-case basis.
   *
   * @param hash - The stored hash string to inspect.
   * @returns `true` if the hash should be re-hashed on next successful login.
   *
   * @example
   * if (passwords.needsRehash(user.passwordHash)) {
   *   user.passwordHash = await passwords.hash(rawPassword);
   *   await user.save();
   * }
   */
  public needsRehash(hash: string): boolean {
    if (!hash.startsWith("$argon2id$")) return false;

    // Parse PHC format: $argon2id$v=19$m=65536,t=3,p=4$...
    const paramsMatch = hash.match(/\$m=(\d+),t=(\d+),p=(\d+)\$/);
    if (!paramsMatch) return true; // malformed → force rehash

    const [, m, t, p] = paramsMatch.map(Number);

    return m < this.memoryCost || t < this.iterations || p < this.parallelism;
  }

  // ─── Input Sanitization ────────────────────────────────────────────────────

  /**
   * Validates and normalizes a raw password string before hashing.
   *
   * Checks performed:
   * - Not empty or whitespace-only.
   * - Minimum length of 8 characters.
   * - Maximum length of 1024 characters (DoS guard against bcrypt-style
   *   long-password attacks on other algorithms).
   * - Unicode NFC normalization (prevents homoglyph bypass attacks).
   *
   * @param password - The raw password string from user input.
   * @returns The NFC-normalized password, ready for hashing.
   * @throws `TypeError` if the input is not a string.
   * @throws `RangeError` if the password fails length validation.
   *
   * @example
   * const normalized = passwords.sanitizeInput(req.body.password);
   * const hash = await passwords.hash(normalized);
   */
  public sanitizeInput(password: unknown): string {
    if (typeof password !== "string") {
      throw new TypeError(
        "PasswordManager.sanitizeInput: password must be a string.",
      );
    }

    const trimmed = password.trim();

    if (trimmed.length === 0) {
      throw new RangeError(
        "PasswordManager.sanitizeInput: password must not be empty.",
      );
    }

    if (trimmed.length < 8) {
      throw new RangeError(
        "PasswordManager.sanitizeInput: password must be at least 8 characters long.",
      );
    }

    if (trimmed.length > 1024) {
      throw new RangeError(
        "PasswordManager.sanitizeInput: password exceeds the maximum allowed length (1024).",
      );
    }

    // NFC normalization: prevents ā (U+0101) vs a + combining macron attacks
    return trimmed.normalize("NFC");
  }

  // ─── Utilities ─────────────────────────────────────────────────────────────

  /**
   * Returns a summary of the instance's current configuration.
   * The `pepper` is intentionally omitted from the output.
   */
  public getConfig(): {
    algorithm: string;
    memoryCost: number;
    iterations: number;
    parallelism: number;
  } {
    return {
      algorithm: this.algo,
      memoryCost: this.memoryCost,
      iterations: this.iterations,
      parallelism: this.parallelism,
    };
  }
}
