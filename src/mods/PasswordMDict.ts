/***************************************************************************
 * XyPriss Security - Advanced Hyper-Modular Security Framework
 *
 * @author NEHONIX (Nehonix-Team - https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 ****************************************************************************/

import { readFileSync } from "fs";
import { resolve } from "path";

// ─── Character Sets ───────────────────────────────────────────────────────────

export const CHARSETS = {
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
  similarChars: /[0O1lI|]/g,
} as const;

/** Minimum length enforced on every `generate()` call. */
export const MIN_GENERATE_LENGTH = 8;
/** Maximum length enforced on every `generate()` call. */
export const MAX_GENERATE_LENGTH = 512;

// ─── EFF Wordlist Loader ──────────────────────────────────────────────────────

/**
 * Supported EFF wordlist variants.
 *
 * | Variant      | Dice | Words | Entropy/word |
 * |--------------|------|-------|--------------|
 * | `large`      | 5×d6 | 7 776 | ~12.9 bits   |
 * | `short1`     | 4×d6 | 1 296 | ~10.3 bits   |
 * | `short2`     | 4×d6 | 1 296 | ~10.3 bits   |
 */
export type EFFWordlistVariant = "large" | "short1" | "short2";

/**
 * Canonical filenames used by the EFF for each wordlist variant.
 * Match the files available at:
 *   https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
 *   https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt
 *   https://www.eff.org/files/2016/09/08/eff_short_wordlist_2_0.txt
 */
export const EFF_FILENAMES: Record<EFFWordlistVariant, string> = {
  large: "eff_large_wordlist.txt",
  short1: "eff_short_wordlist_1.txt",
  short2: "eff_short_wordlist_2_0.txt",
};

/**
 * Options for `loadEFFWordlist`.
 */
export interface LoadWordlistOptions {
  /**
   * Directory that contains the EFF `.txt` files.
   * Resolved relative to `process.cwd()` if not absolute.
   * @default process.cwd()
   */
  dir?: string;

  /**
   * Wordlist variant to load.
   * @default "large"
   */
  variant?: EFFWordlistVariant;

  /**
   * Custom file path, taking precedence over `dir` + `variant`.
   * Use this to load any EFF-formatted wordlist from an arbitrary location.
   */
  filePath?: string;
}

/**
 * Parses a raw EFF `.txt` wordlist file and returns a deduplicated,
 * validated `readonly string[]` ready for use in `generatePassphrase()`.
 *
 * **Supported line formats (both are handled automatically):**
 * ```
 * # Numbered (dice-index prefix, tab-separated):
 * 11111\tabacus
 * 11112\tabrupt
 *
 * # Plain (one word per line):
 * abacus
 * abrupt
 * ```
 *
 * Lines that are empty, start with `#`, or produce a word of length < 2
 * after stripping are silently ignored.
 *
 * @param options - File location and variant configuration.
 * @returns A readonly array of lowercased, trimmed words.
 * @throws `Error` if the file cannot be read or yields fewer than 10 words.
 *
 * @example
 * // Load from ./wordlists/eff_large_wordlist.txt
 * const words = loadEFFWordlist({ dir: "./wordlists", variant: "large" });
 *
 * @example
 * // Load a custom EFF-format file
 * const words = loadEFFWordlist({ filePath: "/opt/security/my_words.txt" });
 */
export function loadEFFWordlist(
  options: LoadWordlistOptions = {},
): readonly string[] {
  const { dir, variant = "large", filePath } = options;

  // ── Resolve path ────────────────────────────────────────────────────────────
  let absolutePath: string | undefined;

  if (filePath) {
    absolutePath = resolve(filePath);
  } else if (dir) {
    absolutePath = resolve(dir, EFF_FILENAMES[variant]);
  } else {
    const fs = require("fs");
    const targetFile = EFF_FILENAMES[variant];

    const possiblePaths = [
      // 1. Direct sibling (production: dist/src/mods or dev: src/mods)
      resolve(__dirname, targetFile),
      // 2. process.cwd() fallback
      resolve(process.cwd(), "src", "mods", targetFile),
      resolve(process.cwd(), "dist", "src", "mods", targetFile),
      // 3. node_modules lookup
      resolve(
        process.cwd(),
        "node_modules",
        "xypriss-security",
        "dist",
        "src",
        "mods",
        targetFile,
      ),
    ];

    for (const p of possiblePaths) {
      try {
        if (fs.existsSync(p)) {
          const stats = fs.statSync(p);
          if (stats.isFile()) {
            absolutePath = p;
            break;
          }
        }
      } catch (e) {
        // Ignore errors for specific path checks
      }
    }

    if (!absolutePath) {
      // Final fallback (will trigger caught exception in the read step)
      absolutePath = resolve(__dirname, targetFile);
    }
  }

  // ── Read file ───────────────────────────────────────────────────────────────
  let raw: string;
  try {
    raw = readFileSync(absolutePath, "utf-8");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `loadEFFWordlist: could not read wordlist file at "${absolutePath}". ` +
        `Ensure the EFF .txt file is present in the specified directory.\n` +
        `Original error: ${msg}`,
    );
  }

  // ── Parse lines ─────────────────────────────────────────────────────────────
  const seen = new Set<string>();
  const words: string[] = [];

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();

    // Skip blank lines and comments
    if (line.length === 0 || line.startsWith("#")) continue;

    // Numbered format: "11111\tword" or "1-1-1-1-1\tword"
    // Plain format:    "word"
    const word = line.includes("\t")
      ? line.split("\t")[1]?.trim().toLowerCase()
      : line.toLowerCase();

    if (!word || word.length < 2) continue;

    // Deduplicate (paranoid guard — EFF lists should already be unique)
    if (!seen.has(word)) {
      seen.add(word);
      words.push(word);
    }
  }

  // ── Validate result ─────────────────────────────────────────────────────────
  if (words.length < 10) {
    throw new Error(
      `loadEFFWordlist: file "${absolutePath}" yielded only ${words.length} valid word(s). ` +
        `Expected an EFF wordlist with at least 10 entries.`,
    );
  }

  return Object.freeze(words);
}

// ─── Fallback Wordlist ────────────────────────────────────────────────────────

/**
 * Compact built-in fallback wordlist (256 words).
 *
 * This is used by `getWordlist()` when no external file is provided and
 * `allowFallback` is `true`. It satisfies the EFF's criteria of being
 * unambiguous, easy to spell, and free of visually confusable entries.
 *
 * **Do not import this array directly for production passphrases** — use
 * `getWordlist()` instead, which will prefer a full EFF file when available.
 */
export const FALLBACK_WORDLIST: readonly string[] = Object.freeze([
  "able",
  "acid",
  "aged",
  "also",
  "area",
  "army",
  "away",
  "baby",
  "back",
  "bail",
  "bake",
  "ball",
  "barn",
  "base",
  "bath",
  "beam",
  "bear",
  "beat",
  "been",
  "bell",
  "belt",
  "best",
  "bird",
  "bite",
  "blade",
  "bold",
  "bolt",
  "bond",
  "bone",
  "book",
  "boom",
  "boot",
  "born",
  "both",
  "bowl",
  "bred",
  "brew",
  "bull",
  "burn",
  "bush",
  "busy",
  "cage",
  "calm",
  "came",
  "camp",
  "card",
  "care",
  "cart",
  "case",
  "cash",
  "cast",
  "cave",
  "cent",
  "chat",
  "chef",
  "chin",
  "chip",
  "city",
  "clam",
  "clap",
  "clay",
  "clip",
  "club",
  "clue",
  "coal",
  "coat",
  "code",
  "coil",
  "coin",
  "cold",
  "colt",
  "cord",
  "core",
  "cork",
  "corn",
  "cost",
  "coup",
  "crab",
  "crew",
  "crop",
  "crow",
  "cube",
  "cure",
  "curl",
  "cute",
  "dark",
  "dart",
  "data",
  "date",
  "dawn",
  "days",
  "dead",
  "deal",
  "dean",
  "debt",
  "deck",
  "deed",
  "deep",
  "deer",
  "desk",
  "dew",
  "dial",
  "diet",
  "dime",
  "dirt",
  "dish",
  "disk",
  "dive",
  "dock",
  "doll",
  "dome",
  "done",
  "door",
  "dose",
  "dote",
  "dove",
  "down",
  "draw",
  "drop",
  "drum",
  "dual",
  "duel",
  "dune",
  "dust",
  "duty",
  "each",
  "earl",
  "earn",
  "ease",
  "east",
  "easy",
  "edge",
  "edit",
  "epic",
  "even",
  "exam",
  "exit",
  "face",
  "fact",
  "fair",
  "fall",
  "fame",
  "farm",
  "fate",
  "fern",
  "file",
  "fill",
  "film",
  "find",
  "fire",
  "firm",
  "fish",
  "fist",
  "flag",
  "flat",
  "flaw",
  "fled",
  "flew",
  "flip",
  "flow",
  "foam",
  "fold",
  "folk",
  "fond",
  "font",
  "food",
  "fool",
  "fork",
  "form",
  "fort",
  "foul",
  "four",
  "free",
  "from",
  "fuel",
  "full",
  "fund",
  "fuse",
  "gain",
  "gale",
  "gaze",
  "gear",
  "gene",
  "gift",
  "girl",
  "give",
  "glad",
  "glow",
  "glue",
  "goal",
  "gold",
  "golf",
  "gone",
  "good",
  "gore",
  "gown",
  "grab",
  "grin",
  "grip",
  "grow",
  "gulf",
  "hall",
  "halt",
  "hare",
  "harm",
  "harp",
  "haul",
  "have",
  "haze",
  "head",
  "heap",
  "heat",
  "heel",
  "help",
  "herb",
  "hide",
  "high",
  "hill",
  "hint",
  "hire",
  "hold",
  "hole",
  "home",
  "hook",
  "hope",
  "horn",
  "huge",
  "hull",
  "hunt",
  "hymn",
  "icon",
  "idea",
  "idle",
  "inch",
  "into",
  "iris",
  "iron",
  "jade",
  "jail",
  "jest",
  "join",
  "joke",
  "jury",
  "just",
  "keen",
  "keep",
  "kern",
  "kind",
  "king",
  "knee",
  "knew",
  "knit",
]);

// ─── Unified Accessor ─────────────────────────────────────────────────────────

/**
 * Options for `getWordlist`.
 */
export interface GetWordlistOptions extends LoadWordlistOptions {
  /**
   * Whether to fall back to the built-in 256-word list if the external
   * file cannot be loaded.
   *
   * - `"silent"` — fall back without any output.
   * - `"warn"`   — print a `console.warn` before falling back.
   * - `false`    — rethrow the file load error (no fallback).
   *
   * @default "warn"
   */
  allowFallback?: "silent" | "warn" | false;
}

/**
 * Unified wordlist accessor: tries to load an EFF file, falls back to the
 * built-in list according to `allowFallback`.
 *
 * Use this function in `PasswordManager.generatePassphrase()` to stay
 * decoupled from both the file system and the hardcoded list.
 *
 * @param options - File location, variant, and fallback policy.
 * @returns A readonly array of words suitable for passphrase generation.
 *
 * @example
 * // Prefer the large EFF list; warn & fall back if absent
 * const words = getWordlist({ dir: "./assets/wordlists", variant: "large" });
 *
 * @example
 * // Never fall back — throw if the file is missing
 * const words = getWordlist({ filePath: "./eff_large_wordlist.txt", allowFallback: false });
 *
 * @example
 * // Only use the built-in list (no file needed)
 * const words = getWordlist({ allowFallback: "silent" });
 * // → returns FALLBACK_WORDLIST without attempting any file read
 */
export function getWordlist(
  options: GetWordlistOptions = {},
): readonly string[] {
  const { allowFallback = "warn", ...loadOptions } = options;

  // If no file location is specified and fallback is allowed, skip the I/O
  // entirely and return the built-in list immediately.
  const hasFileHint = Boolean(loadOptions.filePath ?? loadOptions.dir);
  if (!hasFileHint && allowFallback !== false) {
    if (allowFallback === "warn") {
      console.warn(
        "[PasswordMDict] No EFF wordlist path provided. " +
          "Using built-in 256-word fallback list. " +
          "For production use, supply `dir` or `filePath` pointing to an EFF .txt file.",
      );
    }
    return FALLBACK_WORDLIST;
  }

  try {
    return loadEFFWordlist(loadOptions);
  } catch (err) {
    if (allowFallback === false) throw err;

    if (allowFallback === "warn") {
      console.warn(
        `[PasswordMDict] Failed to load EFF wordlist: ${(err as Error).message}\n` +
          `Falling back to built-in 256-word list.`,
      );
    }
    return FALLBACK_WORDLIST;
  }
}
