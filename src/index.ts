/***************************************************************************
 * XyPriss Security - Advanced Hyper-Modular Security Framework
 *
 * @author NEHONIX (Nehonix-Team - https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 ****************************************************************************/

export { Password } from "./core/Password";

/**
 * # XyPriss Security
 *
 * An advanced, high-performance security framework powered by a Go-based core.
 */

// --- 1. CORE API (Go-Powered High-Level Primitives) ---
export * from "./core/index"; // Exposes Hash, Password, Random, Keys, etc.

// --- 2. MODULAR COMPONENTS (TS-Enhanced Logic) ---
export * from "./components/index";

// --- 3. UTILITIES ---
export * from "./utils/index";
export * from "./components/encryption/index";
export * from "./components/serializer";
export * from "./components/cache/SecureCacheAdapter";

export {
  CHARSETS,
  MIN_GENERATE_LENGTH,
  MAX_GENERATE_LENGTH,
  getWordlist,
} from "./mods/PasswordMDict";