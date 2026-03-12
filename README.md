# XyPriss Security

XyPriss Security is an enterprise-grade cryptographic framework for TypeScript / JavaScript environments. It utilizes a high-performance Go-based core engine compiled as a static, dependency-free CLI binary to provide military-grade security with absolute cross-platform reliability.

## Core Principles

- **Performance**: Optimized execution using lightweight process spawning, bypassing the overhead of standard JavaScript cryptographic implementations without the complexity of CGO.
- **Universal Portability**: Zero native compilation required. Statically linked pure Go binaries run flawlessly on Linux, Windows, and macOS (amd64/arm64) via a unified interface.
- **Modern Standards**: Native support for AES-256-GCM, Argon2id, PBKDF2, HKDF, and Post-Quantum algorithms (Kyber-768).
- **Security by Default**: Automatic memory sanitization and secure key derivation patterns.
- **Zero-Config Installation**: Automatically downloads the exact pre-built binary for your platform during installation (no local Go toolchain required).

## Documentation

The framework documentation is modularized for clarity and depth.

### Modules

- [Core](docs/modules/core.md) - Foundational primitives (Hash, Random, Password, SecureBuffer).
- [Cache](docs/modules/cache.md) - Ultra-fast secure in-memory cache system (UFSIMC).
- [Encryption](docs/modules/encryption.md) - High-level data protection services.
- [Utilities](docs/modules/utils.md) - Encoding and general helpers.

### Reference

- [Type System](docs/api/types.md) - API options and data structure references.

## Quick Start

### Installation

```bash
xfpm add xypriss-security
```

### The Unified `Cipher` API (Compatibility)

For maximum convenience and compatibility with previous versions, use the `Cipher` class. It aggregates `Hash`, `Random`, and `XSec` into a single entry point.

```typescript
import { Cipher } from "xypriss-security";

// --- RANDOM & TOKENS ---
// Generate 32 secure random bytes
const bytes = Cipher.random.getRandomBytes(32);
console.log(bytes.toString("hex"));

// Generate a secure integer in range [1000, 9999]
const pin = Cipher.random.Int(1000, 9999);

// Create a high-entropy API key
const apiKey = Cipher.XSec.generateAPIKey({ prefix: "sk_live" });

// --- HASHING & PKCE ---
// Create a standard SHA-256 hash
const digest = Cipher.hash.create("sensitive-payload");

// Generate a PKCE Code Challenge for OAuth2
const challenge = Cipher.hash.pkce("verifier-string-123");

// --- KEY DERIVATION (PBKDF2) ---
const derivedKey = await Cipher.hash.create("my-password", {
  algorithm: "pbkdf2",
  iterations: 200000,
  salt: "unique-salt-string",
});
```

### Professional Passwords (Argon2id)

XyPriss uses Argon2id by default, providing superior resistance to GPU/ASIC cracking.

```typescript
import { pm } from "xypriss-security"; // 'pm' is an alias for PasswordManager

// 1. Configure once per app
const passwords = new pm({
  memoryCost: 65536, // 64MiB
  parallelism: 4,
});

// 2. Use everywhere
const hash = await passwords.hash("user-password-123");
const isValid = await passwords.verify("user-password-123", hash);
```

### Ultra-Fast Secure Caching (UFSIMC)

The caching system automatically handles encryption and compression using the Go core.

```typescript
import { Cache } from "xypriss-security";

// Stores data securely with a 1-hour TTL
await Cache.set(
  "session:88",
  { role: "admin", permissions: ["*"] },
  { ttl: 3600 },
);

const session = await Cache.get("session:88");
```

## Performance Benchmarks

XyPriss Security leverages a multi-threaded Go core, consistently outperforming native JavaScript implementations:

| Operation | Standard JS | XyPriss (Go Core) | Improvement |
| --------- | ----------- | ----------------- | ----------- |
| Argon2id  | ~450ms      | ~85ms             | 5.3x        |
| AES-GCM   | ~12ms       | ~2ms              | 6x          |
| SHA-256   | ~5ms        | ~0.8ms            | 6.2x        |

## Binary Handling with `SecureBuffer`

`SecureBuffer` extends standard `Uint8Array` to support multiple encodings directly, optimized for security contexts.

```typescript
import { Random } from "xypriss-security";

const data = Random.getRandomBytes(32);
console.log(data.toString("base64")); // Output as Base64
console.log(data.toString("binary")); // Output as Binary String
```

## License

Copyright (c) 2025 NEHONIX. Licensed under the Nehonix Open Source License (NOSL).
All rights reserved.
