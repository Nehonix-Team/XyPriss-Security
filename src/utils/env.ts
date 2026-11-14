/***************************************************************************
 * XyPriss Security - Environment Variable Resolver
 *
 * @author NEHONIX (Nehonix-Team - https://github.com/Nehonix-Team)
 * @license Nehonix Open Source License (NOSL: https://dll.nehonix.com/licenses/NOSL)
 ***************************************************************************/

/**
 * Safely resolves an environment variable by querying XyPriss's official system API
 * (`globalThis.__sys__.__env__.get(key)`) first, falling back to `process.env[key]`
 * when running in standalone mode outside XyPriss.
 *
 * ### XyPriss libXESS Environment Shield & Whitelisting
 *
 * Under XyPriss's Zero-Trust runtime architecture, the **libXESS Environment Shield**
 * intercepts and restricts all environment variable access from third-party packages in `node_modules`.
 * In order for `xypriss-security` to read configuration variables and secrets
 * (such as `ENC_SECRET_KEY`, `ENC_SECRET_SEED`, `ENC_SECRET_SALT`, or `XYPRISS_SEC_WARNINGS`),
 * the host application must explicitly declare them in the environment whitelist within `xypriss.config.jsonc` (or `xypriss.config.json`).
 *
 * @example
 * **Declaring whitelisted variables in `xypriss.config.jsonc`:**
 * ```jsonc
 * {
 *   "$env": {
 *     "packages": {
 *       // Dedicated sandbox whitelist for xypriss-security
 *       "xypriss-security": {
 *         "whitelist": [
 *           "ENC_SECRET_KEY",
 *           "ENC_SECRET_SEED",
 *           "ENC_SECRET_SALT",
 *           "XYPRISS_SEC_WARNINGS"
 *         ],
 *         "inheritGlobal": false
 *       }
 *     }
 *   }
 * }
 * ```
 *
 * Or via global whitelist:
 * ```jsonc
 * {
 *   "$env": {
 *     "whitelist": ["ENC_SECRET_KEY", "ENC_SECRET_SEED", "ENC_SECRET_SALT", "XYPRISS_SEC_WARNINGS"]
 *   }
 * }
 * ```
 *
 * @see {@link https://xypriss.nehonix.com/docs/security/environment-shield XyPriss Environment Security Shield Documentation}
 *
 * @param key - The environment variable name.
 * @returns The resolved variable value or undefined if not set or not whitelisted.
 */
export function getEnv(key: string): string | undefined {
  if (typeof globalThis !== "undefined") {
    const sys = (globalThis as any).__sys__;
    if (sys?.__env__ && typeof sys.__env__.get === "function") {
      return sys.__env__.get(key);
    }
  }

  if (typeof process !== "undefined" && process.env) {
    return process.env[key];
  }

  return undefined;
}

/**
 * Safely retrieves a required environment variable or throws an error if it is not defined.
 * Prioritizes `globalThis.__sys__.__env__.getStrict(key)` when running inside XyPriss.
 *
 * ### XyPriss libXESS Environment Shield Notice
 *
 * Required variables must be whitelisted for `xypriss-security` in `xypriss.config.jsonc`.
 * Unwhitelisted access attempts will return `undefined` and throw an error.
 *
 * @example
 * ```typescript
 * import { getEnvStrict } from "xypriss-security";
 *
 * const encKey = getEnvStrict("ENC_SECRET_KEY");
 * ```
 *
 * @see {@link https://xypriss.nehonix.com/docs/security/environment-shield XyPriss Environment Security Shield Documentation}
 *
 * @param key - The environment variable name.
 * @returns The resolved variable value (guaranteed defined).
 * @throws {Error} When the environment variable is missing or empty.
 */
export function getEnvStrict(key: string): string {
  if (typeof globalThis !== "undefined") {
    const sys = (globalThis as any).__sys__;
    if (sys?.__env__ && typeof sys.__env__.getStrict === "function") {
      return sys.__env__.getStrict(key);
    }
  }

  const value = getEnv(key);
  if (value === undefined) {
    throw new Error(`Missing required environment variable: "${key}"`);
  }
  return value;
}

