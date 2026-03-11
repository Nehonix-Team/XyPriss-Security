# Core Module

The Core module provides the foundational cryptographic primitives and binary handling for the XyPriss Security framework. These operations are powered by a native Go engine for high performance.

## Classes

- [Hash](#hash)
- [Random](#random)
- [Password](#password)
- [SecureBuffer](#securebuffer)
- [XyPrissSecurity](#xyprisssecurity)

---

## Hash

High-performance hashing and HMAC operations.

### static create(input, options?)

Creates a secure SHA-256 hash.

**Parameters:**

- `input`: `string | Uint8Array` - The data to be hashed.
- `options`: `HashOptions` (Optional)
  - `outputFormat`: `"hex" | "base64" | "buffer" | "uint8array"` - The desired format of the output. Default is `"hex"`.

**Returns:** `string | Uint8Array`

**Example:**

```typescript
import { Hash } from "xypriss-security";

const hexHash = Hash.create("message");
const bufferHash = Hash.create("message", { outputFormat: "buffer" });
```

### static hmac(key, data)

Generates a Message Authentication Code (HMAC) using SHA-256.

**Parameters:**

- `key`: `string | Uint8Array` - The secret key.
- `data`: `string | Uint8Array` - The data to authenticate.

**Returns:** `string` (Hex-encoded)

---

## Random

Cryptographically secure random generation.

### static getRandomBytes(length)

Generates cryptographically strong random bytes.

**Parameters:**

- `length`: `number` - Number of bytes to generate.

**Returns:** `SecureBuffer`

### static generateToken(length?, options?)

Generates a secure alphanumeric random token.

**Parameters:**

- `length`: `number` (Default: 32)
- `options`: `SecureTokenOptions` (Optional)

**Returns:** `string`

---

## Password

Secure password hashing and verification using memory-hard algorithms.

### static async hash(password, options?)

Hashes a password with Argon2id or Scrypt.

**Parameters:**

- `password`: `string`
- `options`: `PasswordHashOptions` (Optional)
  - `algorithm`: `"argon2id" | "scrypt"` (Default: `"argon2id"`)

**Returns:** `Promise<string>`

### static async verify(password, hash)

Verifies a password against an encoded hash.

**Parameters:**

- `password`: `string`
- `hash`: `string`

**Returns:** `Promise<boolean>`

---

## SecureBuffer

Enhanced `Uint8Array` with familiar encoding methods.

### toString(encoding?)

Converts the binary data to a string.

**Support Encodings:**

- `"hex"` (Default): Hexadecimal string.
- `"base64"`: Base64 encoding.
- `"utf8"` / `"utf-8"`: UTF-8 string.
- `"binary"`: Raw binary string.
- `"strulink"`: Native Strulink obfuscation (if integrated).

**Returns:** `string`

### toBuffer()

Converts the instance to a Node.js `Buffer`.

**Returns:** `Buffer`

---

## XyPrissSecurity

General framework utilities for environment and key management.

### static generateAPIKey(options?)

Generates a structured API key with a prefix and timestamp.

**Parameters:**

- `options`: `APIKeyOptions` (Optional)
  - `prefix`: `string` (Default: `"xy"`)
  - `randomPartLength`: `number` (Default: 32)

**Returns:** `string`
