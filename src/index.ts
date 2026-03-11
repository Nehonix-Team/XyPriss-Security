/***************************************************************************
 * XyPriss Security - Advanced Hyper-Modular Security Framework
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 *
 * Copyright (c) 2025 NEHONIX. All rights reserved.
 ****************************************************************************/

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
