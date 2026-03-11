/***************************************************************************
 * XyPriss Security Core - Unified API Entry Point
 *
 * Provides high-level security classes (Hash, Random, Password, XyPrissSecurity)
 * that wrap the high-performance Go-based core bridge.
 *
 * @author NEHONIX (iDevo - https://github.com/iDevo-ll)
 * @license Nehonix Open Source License (NOSL)
 ****************************************************************************/

export * from "./Hash";
export * from "./Random";
export * from "./Password";
export * from "./XyPrissSecurity";
export * from "./SecureBuffer";
export * from "./keys";
export * from "./bridge";

export { XyPrissSecurity as XSec } from "./XyPrissSecurity"; // Alias for XyPrissSecurity
export { Password as pm } from "./Password"; // Alias for Password

import { Hash } from "./Hash";
import { Random } from "./Random";
import { XyPrissSecurity } from "./XyPrissSecurity";

/**
 * ### Cipher Class (Compatibility)
 *
 * A unified entry point providing access to all security modules.
 * This class ensures compatibility with previous versions of the library.
 */
export class Cipher {
  /** High-performance hashing and PKCE operations. */
  public static readonly hash = Hash;
  /** Cryptographically secure random number and token generation. */
  public static readonly random = Random;
  /** Alias for random module. */
  public static readonly crypto = Random;
  /** Framework-level security management and configuration. */
  public static readonly XSec = XyPrissSecurity;
}
