# Utilities Module

Foundational helpers for encoding, decoding, byte manipulation, RSA cryptography, and key derivation. All functions are re-exported from their original modules for convenience.

## Module Exports

- [Encoding Utilities](#encoding-utilities)
- [Unified Utils Interface](#unified-utils-interface)
- [RSA Cryptography](#rsa-cryptography)
- [Byte Length Utilities](#byte-length-utilities)
- [Key Derivation](#key-derivation)

---

## Encoding Utilities

Functions for converting data between different formats.

### bufferToHex(buffer, uppercase?, separator?)

Converts a `Uint8Array` to a hexadecimal string.

### hexToBuffer(hex)

Converts a hexadecimal string to a `Uint8Array`.

### bufferToBase64(buffer, urlSafe?)

Converts a `Uint8Array` to a Base64 string.

### base64ToBuffer(base64, urlSafe?)

Converts a Base64 string to a `Uint8Array`.

### stringToBuffer(str)

Converts a UTF-8 string to a `Uint8Array`.

### bufferToString(buffer)

Converts a `Uint8Array` to a UTF-8 string.

---

## Unified Utils Interface

The `Utils` object provides a consolidated entry point for common operations.

### hash(data, optionsOrAlgoOrLength?, length?)

High-performance cryptographic hashing with conditioned return types, direct string truncation, and algorithm selection.

- **Returns:** `SecureBuffer` when `outputFormat: "buffer" | "uint8array"`; `string` otherwise.
- **Truncation:** Pass a `number` to truncate the hex string natively without `.substring(0, N)`.

```typescript
import { hash } from "xypriss-security";

// 1. Direct ID generation with truncation (12 chars hex)
const shortId = hash("user@example.com", 12); // "b4c9a289323b"

// 2. Specific algorithm with truncation
const blakeShort = hash("user@example.com", "blake2b", 16);

// 3. Binary output (returns SecureBuffer)
const buf = hash("sensitive data", { outputFormat: "buffer" });

// 4. Default full SHA-256 hash (64 chars hex)
const full = hash("sensitive data");
```

> For the comprehensive guide and advanced patterns, see [Hashing, Scrypt & Verification](./hashing.md).

### timingSafeEqual(a, b)

Compares two strings (e.g. hex hashes) or `Uint8Array` / `Buffer` in constant time using Go's `subtle.ConstantTimeCompare`. Direct replacement for Node.js `crypto.timingSafeEqual`.

```typescript
import { timingSafeEqual } from "xypriss-security";

const isValid = timingSafeEqual(keyHex, computedHashHex);
```

### getRandomBytes(length)

Generates cryptographically secure random bytes via Go's native `crypto/rand`.

```typescript
import { getRandomBytes } from "xypriss-security";

const salt = getRandomBytes(16).toString("hex");
```

### encrypt(data, key, algo?)

Performs quick string-to-string encryption using the native bridge (AES/ChaCha20).

### decrypt(encrypted, key, algo?)

Performs quick string-to-string decryption.

---

## RSA Cryptography

> For full documentation, see [RSA and Byte Utilities](./rsa-and-byte-utils.md).

### generateRSAKeyPair()

Generates a 4096-bit RSA key pair.

**Returns:** `Promise<{ publicKey: string; privateKey: string }>`

### rsaSign(privateKey, data)

Signs data using RSA-PSS with SHA-256.

**Returns:** `Promise<string>` (hex-encoded signature)

### rsaVerify(publicKey, data, signature)

Verifies an RSA-PSS signature.

**Returns:** `Promise<boolean>`

### rsaEncrypt(publicKey, data)

Encrypts data using RSA-OAEP with SHA-256.

**Returns:** `Promise<string>` (hex-encoded ciphertext)

### rsaDecrypt(privateKey, encryptedHex)

Decrypts RSA-OAEP ciphertext.

**Returns:** `Promise<string>` (plaintext)

**Example:**

```typescript
import { generateRSAKeyPair, rsaSign, rsaVerify } from "xypriss-security";

const { publicKey, privateKey } = await generateRSAKeyPair();
const sig = await rsaSign(privateKey, "payload");
const valid = await rsaVerify(publicKey, "payload", sig); // true
```

---

## Byte Length Utilities

> For full documentation, see [RSA and Byte Utilities](./rsa-and-byte-utils.md).

### getByteLength(str)

Returns the actual UTF-8 byte count of a string. Unlike `.length`, this correctly handles multi-byte Unicode characters.

**Returns:** `number`

### isValidByteLength(str, expectedLength)

Checks whether a string has exactly the specified number of UTF-8 bytes.

**Returns:** `boolean`

**Example:**

```typescript
import { getByteLength, isValidByteLength } from "xypriss-security";

getByteLength("you好"); // 8 (y=1, o=1, u=1, 好=3 bytes)
isValidByteLength("32-byte-key-padding-to-fill-it!", 32); // true
```

---

## Key Derivation

### deriveKey(input, options?)

Derives a cryptographically strong key from a secret using Argon2id, PBKDF2, or HKDF.

**Returns:** `Promise<string>` (hex-encoded derived key)

**Example:**

```typescript
import { deriveKey } from "xypriss-security";

const key = await deriveKey("my-secret", {
  algorithm: "pbkdf2",
  iterations: 310000,
  keyLength: 32,
  salt: "unique-salt",
});
```
