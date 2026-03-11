# Core Module

The Core module provides the foundational cryptographic primitives and binary handling for the XyPriss Security framework. These operations are powered by a native Go engine for high performance.

## Classes

- [Cipher](#cipher-compatibility) (Compatibility Entry Point)
- [Hash](#hash)
- [Random](#random)
- [Password](#password)
- [SecureBuffer](#securebuffer)
- [XyPrissSecurity](#xyprisssecurity)

---

## Cipher (Compatibility)

A unified entry point that aggregates all core modules for convenience and backward compatibility.

### Static Properties

- `hash`: Re-exports the [Hash](#hash) class.
- `random`: Re-exports the [Random](#random) class.
- `crypto`: Alias for the [Random](#random) class.
- `XSec`: Re-exports the [XyPrissSecurity](#xyprisssecurity) class.

**Example:**

```typescript
import { Cipher } from "xypriss-security";

const bytes = Cipher.random.getRandomBytes(32);
const digest = Cipher.hash.create("data");
const apiKey = Cipher.XSec.generateAPIKey();
```

---

## Hash

High-performance hashing, HMAC, and PBKDF2 operations.

### static create(input, options?)

Creates a secure hash or derived key.

**Parameters:**

- `input`: `string | Uint8Array` - The data to be hashed.
- `options`: `HashOptions` (Optional)
  - `algorithm`: `"sha256" | "sha512" | "pbkdf2" | "argon2id"` - Default is `"sha256"`.
  - `iterations`: `number` - For PBKDF2 (Default: 100,000).
  - `outputFormat`: `"hex" | "base64" | "buffer"` - Default is `"hex"`.

**Returns:** `string | SecureBuffer`

**Example:**

```typescript
import { Hash } from "xypriss-security";

// Standard Hash
const hexHash = Hash.create("message");

// PBKDF2 Key Derivation
const key = Hash.create("password", {
  algorithm: "pbkdf2",
  iterations: 210000,
  outputFormat: "buffer",
});
```

### static pkce(verifier, method?)

Generates a PKCE code challenge.

- `verifier`: `string`
- `method`: `"S256" | "plain"` (Default: `"S256"`)

**Returns:** `string` (Base64Url encoded)

---

## Random

Cryptographically secure random generation.

### static Int(minOrMax, max?)

Generates a secure random integer.

- `Cipher.random.Int(100)` -> Range [0, 100)
- `Cipher.random.Int(50, 150)` -> Range [50, 150)

### static generateToken(length?, options?)

Generates a secure alphanumeric random token. Supports character set constraints and similarity filtering.

---

## Password

Secure password hashing (Argon2id/Scrypt).

### static async hash(password, options?)

Hashes a password with memory-hard parameters.

**Options:**

- `memoryCost`: Memory usage in KB (Default: 65536).
- `parallelism`: Number of threads (Default: 4).
- `iterations`: Time cost (Default: 3).

---

## SecureBuffer

Enhanced `Uint8Array` with familiar encoding methods.

### toString(encoding?)

Converts the binary data to a string. Supported encodings: `hex`, `base64`, `utf8`, `binary`.

---

## XyPrissSecurity (XSec)

General framework utilities for environment and key management.

### static generateAPIKey(options?)

Generates a structured API key.

**Options:**

- `prefix`: string (Default: `"xy"`)
- `includeTimestamp`: boolean (Default: `true`)
- `randomPartLength`: number (Default: 32)
