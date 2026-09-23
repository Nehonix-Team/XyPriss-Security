# Core Module

The Core module provides the foundational cryptographic primitives and binary handling for the XyPriss Security framework. These operations are powered by a native Go engine for high performance.

## Classes

- [Cipher](#cipher-compatibility) (Compatibility Entry Point)
- [Hash](#hash)
- [Random](#random)
- [PasswordManager (`pm`)](#passwordmanager-pm)
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

### static create(input, optionsOrAlgoOrLength?, length?)

Creates a secure cryptographic hash or derived key with conditioned return types and optional length truncation.

**Overload Signatures:**

- `create(input, options: { outputFormat: "buffer" | "uint8array" }): SecureBuffer`
- `create(input, length: number): string`
- `create(input, algorithm: HashAlgorithm, length?: number): string`
- `create(input, options?: HashOptions): string`

**Parameters:**

- `input`: `string | Uint8Array` - The data to be hashed.
- `options`: `HashOptions` (Optional)
  - `algorithm`: `"sha256" | "sha512" | "sha3-256" | "blake2b" | "blake2s" | "pbkdf2" | "argon2id" | "scrypt"` - Default is `"sha256"`.
  - `length`: `number` - Desired character length of output string (e.g. `12` for short IDs).
  - `outputFormat`: `"hex" | "base64" | "buffer" | "uint8array"` - Default is `"hex"`.
  - `iterations`: `number` - For PBKDF2 (Default: 100,000).
  - `salt`: `string | Uint8Array` - For PBKDF2.

**Returns:** `SecureBuffer` when binary format is requested, `string` otherwise.

**Example:**

```typescript
import { Hash } from "xypriss-security";

// Short ID generation (12 chars hex)
const shortId = Hash.create("user@domain.com", 12);

// Standard Hash
const hexHash = Hash.create("message");

// PBKDF2 Key Derivation
const key = Hash.create("password", {
  algorithm: "pbkdf2",
  iterations: 210000,
  outputFormat: "buffer",
});
```

> For the complete reference, see [Hashing, Scrypt & Verification](./hashing.md).

### static timingSafeEqual(a, b)

Compares two strings or `Uint8Array` / `Buffer` in constant time to eliminate timing side channels.

```typescript
import { Hash } from "xypriss-security";

const isMatch = Hash.timingSafeEqual(storedHashHex, calculatedHashHex);
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

## PasswordManager (`pm`)

Configurable, instance-based secure password management (hashing, verifying, and generating). Exported as `PasswordManager` and aliased as `pm`.

### Initialization

```typescript
import { pm } from "xypriss-security";

const passwords = new pm({
  algorithm: "argon2id",
  memoryCost: 65536,
  parallelism: 4,
  iterations: 3,
  pepper: "optional-secret-pepper",
});
```

### async hash(password, overrides?)

Hashes a password with the instance's pre-configured memory-hard parameters.

**Returns:** `Promise<string>` (Argon2id PHC string)

### async verify(password, hash)

Verifies a plain-text password against a stored hash.

**Returns:** `Promise<boolean>`

### generate(options?)

Generates a cryptographically secure random password matching specific criteria.

**Options:**

- `length`: number (Default: 20)
- `uppercase`, `lowercase`, `numbers`, `symbols`: boolean (Default: `true`)
- `excludeSimilar`: boolean (Default: `false`)

### generatePassphrase(options?)

Generates a memorable, high-entropy passphrase using the EFF wordlist.

**Options:**

- `wordCount`: number (Default: 5)
- `separator`: string (Default: `"-"`)

### strength(password)

Evaluates the strength of a password and returns a detailed report including score (0-100), label, and actionable suggestions.

### isHashed(hash, strict?)

Checks whether a string is a valid XyPriss hash. By default, `strict` mode also verifies that the hash matches the algorithm configured for the current instance. Set `strict` to `false` to accept any XyPriss hash regardless of algorithm.

- `hash`: `string` - The string to inspect.
- `strict`: `boolean` (Default: `true`) - When `true`, validates against the instance algorithm.

**Returns:** `boolean`

**Example:**

```typescript
const passwords = new pm({ algorithm: "argon2id" });
const hash = await passwords.hash("user-password");

passwords.isHashed(hash); // true  (argon2id hash, strict mode)
passwords.isHashed("plaintext"); // false
passwords.isHashed(hash, false); // true  (any valid XyPriss hash)
```

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

### static getByteLength(str)

Returns the actual UTF-8 byte count of a string.

- `str`: `string`

**Returns:** `number`

### static isValidByteLength(str, expectedLength)

Verifies that a string has exactly the specified number of UTF-8 bytes. Useful before passing key material to Go operations that require strict byte sizes (e.g. AES-256 requires 32 bytes).

- `str`: `string`
- `expectedLength`: `number`

**Returns:** `boolean`

**Example:**

```typescript
import { XyPrissSecurity } from "xypriss-security";

const byteLen = XyPrissSecurity.getByteLength("caf\u00e9"); // 5
const valid = XyPrissSecurity.isValidByteLength(
  "32-byte-key-for-aes-256-exactly",
  32,
); // true
```
