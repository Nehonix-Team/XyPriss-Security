# Hashing, Scrypt & Constant-Time Verification

High-performance cryptographic hashing, Scrypt key derivation, and timing-safe comparison powered by XyPriss Security's native Go engine.

---

## Table of Contents

- [Overview & Highlights](#overview--highlights)
- [Supported Algorithms](#supported-algorithms)
- [The `hash()` Function](#the-hash-function)
  - [Short ID / Truncated Hash (No `.substring()` needed)](#short-id--truncated-hash-no-substring-needed)
  - [Specifying an Algorithm](#specifying-an-algorithm)
  - [Binary Output (`SecureBuffer`)](#binary-output-securebuffer)
  - [Comprehensive Options](#comprehensive-options)
- [Constant-Time Comparison (`timingSafeEqual`)](#constant-time-comparison-timingsafeequal)
- [Scrypt Key Derivation (`scrypt`)](#scrypt-key-derivation-scrypt)
  - [Node.js `crypto.scryptSync` Migration](#nodejs-cryptoscryptsync-migration)
  - [Full PIN Hashing & Verification Example](#full-pin-hashing--verification-example)
- [Password Hashing (`Password.hash` & `Password.verify`)](#password-hashing-passwordhash--passwordverify)
- [API Reference](#api-reference)

---

## Overview & Highlights

- **Dynamic Return Types (TypeScript Overloads)**: TypeScript automatically infers `SecureBuffer` when binary output format (`"buffer"` or `"uint8array"`) is requested, and `string` for hex/base64 outputs.
- **Built-in Truncation (`length`)**: Pass a length parameter to truncate output strings natively, eliminating the need for `.substring(0, 12)`.
- **IntelliSense & Strict Typing**: Algorithms are typed via exhaustive literal unions (`HashAlgorithm`, `HMACAlgorithm`, etc.), providing instant IDE autocompletion and compile-time validation.
- **Timing-Attack Resistance**: Native constant-time comparison via Go's `subtle.ConstantTimeCompare` protects against side-channel analysis.
- **100% Bit-for-Bit Compatibility**: Native Scrypt and PBKDF2 implementations match Node.js standard outputs with zero native compilation overhead.

---

## Supported Algorithms

All algorithms are compiled into the native Go engine and strictly validated at runtime:

| Algorithm Name | Aliases / Formats | Key / Output Size | Best For |
| :--- | :--- | :--- | :--- |
| `sha256` | `"sha-256"`, `"SHA-256"`, `"SHA256"` | 256 bits (64 hex chars) | Standard general-purpose hashing |
| `sha512` | `"sha-512"`, `"SHA-512"`, `"SHA512"` | 512 bits (128 hex chars) | High-entropy hashing (64-bit platforms) |
| `sha3-256` | `"sha3_256"` | 256 bits | NIST Keccak standard |
| `sha3-512` | `"sha3_512"` | 512 bits | NIST Keccak standard |
| `blake2b` | `"blake2b-256"`, `"blake2b-512"` | Up to 512 bits | High-speed cryptographic hashing |
| `blake2s` | `"blake2s-256"` | 256 bits | 32-bit CPU / IoT optimized |
| `scrypt` | — | Configurable (default: 64B) | Memory-hard key derivation & PIN protection |
| `pbkdf2` | — | Configurable (default: 32B) | Legacy key derivation (RFC 2898) |
| `argon2id` | — | 32 bytes | OWASP winner for password storage |

---

## The `hash()` Function

The `hash()` utility provides multiple convenient signatures with conditioned return types.

### Short ID / Truncated Hash (No `.substring()` needed)

Pass the desired length directly as a number:

```typescript
import { hash } from "xypriss-security";

// Generates a 12-character hex ID (e.g. "b4c9a289323b")
const shortId = hash("user@example.com", 12);

// Direct database ID assignment
const user = {
  id: hash(email, 12),
  email,
  createdAt: new Date().toISOString(),
};
```

### Specifying an Algorithm

Pass the algorithm directly as a string with optional length truncation:

```typescript
import { hash } from "xypriss-security";

// Blake2b-256 hash (64 hex chars)
const blake = hash("payload", "blake2b");

// Truncated SHA-512 hash (16 hex chars)
const shortSha512 = hash("payload", "sha512", 16);
```

### Binary Output (`SecureBuffer`)

When specifying `"buffer"` or `"uint8array"` in `outputFormat`, TypeScript automatically infers the return type as `SecureBuffer`:

```typescript
import { hash } from "xypriss-security";

// TypeScript infers: const rawBuffer: SecureBuffer
const rawBuffer = hash("secret-data", { outputFormat: "buffer" });

console.log(rawBuffer.byteLength); // 32
const uint8 = rawBuffer.toUint8Array();
```

### Comprehensive Options

```typescript
import { hash } from "xypriss-security";

// 1. Truncated output via options
const customId = hash("john.doe@domain.com", { length: 14 });

// 2. Base64 encoding
const b64 = hash("sensitive data", { 
  algorithm: "sha512", 
  outputFormat: "base64" 
});

// 3. PBKDF2 derivation with custom salt and iterations
const pbkdf2Hex = hash("myPassword", {
  algorithm: "pbkdf2",
  iterations: 100000,
  salt: "random_salt_16b",
  length: 32,
});
```

---

## Constant-Time Comparison (`timingSafeEqual`)

Direct replacement for Node.js `crypto.timingSafeEqual`. Uses Go's `subtle.ConstantTimeCompare` under the hood to ensure execution time is independent of the input contents, completely preventing timing side-channel attacks.

Accepts **hex strings**, **plain strings**, or **`Uint8Array` / `Buffer`** directly:

```typescript
import { timingSafeEqual } from "xypriss-security";

// 1. Comparing two hex strings directly (no Buffer.from needed!)
const isValid = timingSafeEqual(storedHashHex, calculatedHashHex);

// 2. Comparing raw Uint8Arrays / Buffers
const isBufferMatch = timingSafeEqual(bufA, bufB);
```

---

## Scrypt Key Derivation (`scrypt`)

Scrypt is a memory-hard password-based key derivation function designed to make hardware brute-force attacks (ASIC / FPGA / GPU) prohibitively expensive.

### Node.js `crypto.scryptSync` Migration

```typescript
// ❌ Old Node.js crypto code:
import crypto from "crypto";
const salt = crypto.randomBytes(16);
const key = crypto.scryptSync(password, salt, 64).toString("hex");

// ✅ Modern XyPriss Security code (No Node.js crypto dependency):
import { scrypt, getRandomBytes } from "xypriss-security";
const salt = getRandomBytes(16).toString("hex");
const key = scrypt(password, salt, 64); // returns 128-char hex string
```

### Full PIN Hashing & Verification Example

Here is a complete, production-ready implementation for storing and verifying sensitive PINs:

```typescript
import { scrypt, timingSafeEqual, getRandomBytes } from "xypriss-security";

/**
 * Hashes a PIN with a fresh 16-byte random salt using Scrypt.
 * Format: "<salt_hex>:<hash_hex>"
 */
export function hashPin(pin: string): string {
  const salt = getRandomBytes(16).toString("hex");
  const hash = scrypt(pin, salt, 64);
  return `${salt}:${hash}`;
}

/**
 * Verifies a candidate PIN against a stored "salt:hash" string in constant time.
 */
export function verifyPin(pin: string, stored: string): boolean {
  if (!pin || !stored) return false;
  const [salt, key] = stored.split(":");
  if (!salt || !key) return false;

  try {
    const hash = scrypt(pin, salt, 64);
    return timingSafeEqual(key, hash);
  } catch {
    return false;
  }
}
```

Or condensed into a single clean line:

```typescript
export const verifyPin = (pin: string, stored: string): boolean => {
  const [salt, key] = (stored || "").split(":");
  return Boolean(pin && salt && key && timingSafeEqual(key, scrypt(pin, salt, 64)));
};
```

---

## Password Hashing (`Password.hash` & `Password.verify`)

For user accounts and standard passwords, XyPriss provides a modular, self-contained hashing engine using **Argon2id** by default.

Unlike custom `salt:hash` concatenation, the modular `$xypriss$` format bundles algorithm, cost parameters, salt, and hash together:

```typescript
import { Password } from "xypriss-security";

// 1. Hash during registration (auto-generates salt & Argon2id params)
const storedHash = await Password.hash("SuperSecretP@ssw0rd!");
// Result: "$xypriss$argon2id$v=19,m=65536,t=3,p=4$<salt>$<hash>"

// 2. Verify during login (automatically parses salt, cost, and verifies in constant time)
const isValid = await Password.verify("candidatePassword", storedHash);
if (!isValid) {
  throw new Error("Invalid credentials");
}
```

---

## API Reference

### `hash(data, options?)`

```typescript
function hash(data: string | Uint8Array, options: HashOptions<HashBufferFormat> & { outputFormat: HashBufferFormat }): SecureBuffer;
function hash(data: string | Uint8Array, length: number): string;
function hash(data: string | Uint8Array, algorithm: HashAlgorithm, length?: number): string;
function hash(data: string | Uint8Array, options?: HashOptions<HashStringFormat>): string;
```

### `Hash.create(input, options?)`

Static method on `Hash` identical to `hash()`:

```typescript
Hash.create(input: string | Uint8Array, optionsOrAlgoOrLength?: HashOptions | HashAlgorithm | number, length?: number): string | SecureBuffer;
```

### `timingSafeEqual(a, b)`

```typescript
function timingSafeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean;
```

- Returns `true` if `a` and `b` are strictly identical.
- Executes in constant time to thwart timing side channels.

### `scrypt(password, salt, keyLength?, cost?, r?, p?)`

```typescript
function scrypt(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  keyLength: number = 64,
  cost: number = 16384,
  r: number = 8,
  p: number = 1
): string;
```

- Derives a raw cryptographic key in lowercase hexadecimal format.
- Default parameters ($N=16384, r=8, p=1$, length=64) produce identical outputs to Node.js `crypto.scryptSync`.

### `Hash.hmac(key, data, algo?)`

```typescript
Hash.hmac(key: string | Uint8Array, data: string | Uint8Array, algo: HMACAlgorithm = "sha256"): string;
```

- Returns a hexadecimal HMAC signature.

### `Hash.pkce(verifier, method?)`

```typescript
Hash.pkce(verifier: string, method: "S256" | "plain" = "S256"): string;
```

- Generates an RFC 7636 Base64Url-encoded code challenge from a code verifier.
