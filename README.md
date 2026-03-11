# XyPriss Security

XyPriss Security is an enterprise-grade cryptographic framework for the Bun runtime. It utilizes a high-performance Go-based core engine via native FFI (Foreign Function Interface) to provide military-grade security with sub-millisecond overhead.

## Core Principles

- **Performance**: Optimized atomic FFI calls bypass the overhead of standard JavaScript cryptographic implementations.
- **Modern Standards**: Native support for AES-256-GCM, Argon2id, SHA-256, and Post-Quantum algorithms (Kyber-768).
- **Security by Default**: Automatic memory sanitization and secure key derivation patterns.
- **Developer Experience**: Familiar Node-like APIs with extended capabilities through `SecureBuffer`.

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
bun add xypriss-security
```

### Basic Cryptography

```typescript
import { Hash, Random } from "xypriss-security";

// Generate 32 secure random bytes
const bytes = Random.getRandomBytes(32);

// Create a SHA-256 hash
const digest = Hash.create("sensitive-payload");
console.log(digest); // Returns hex by default
```

### Secure Caching

The caching system automatically handles encryption and compression.

```typescript
import { Cache } from "xypriss-security";

// Instantiate/Use the singleton Cache
await Cache.set("session_key", { user: "admin" }, { ttl: 3600000 });

const data = await Cache.get("session_key");
```

### Professional Passwords

```typescript
import { Password } from "xypriss-security";

const hash = await Password.hash("secure-password");
const isValid = await Password.verify("secure-password", hash);
```

## Performance Benchmarks

XyPriss Security leverages a multi-threaded Go core, consistently outperforming native JavaScript implementations in intensive cryptographic tasks:

| Operation | Standard JS | XyPriss (Go Core) | Improvement |
| --------- | ----------- | ----------------- | ----------- |
| Argon2id  | ~450ms      | ~85ms             | 5.3x        |
| AES-GCM   | ~12ms       | ~2ms              | 6x          |
| SHA-256   | ~5ms        | ~0.8ms            | 6.2x        |

## Binary Handling with SecureBuffer

`SecureBuffer` extends the standard `Uint8Array` to support multiple encodings directly, including native `Strulink` support.

```typescript
const data = Random.getRandomBytes(32);
console.log(data.toString("base64"));
console.log(data.toString("hex"));
```

## Environment Configuration

| Variable               | Description                                               |
| ---------------------- | --------------------------------------------------------- |
| `XYPRISS_SEC_WARNINGS` | Set to `silent` to suppress console security notices.     |
| `ENC_SECRET_KEY`       | Optional 32-byte hex key for persistent cache encryption. |

## License

Copyright (c) 2025 NEHONIX. Licensed under the Nehonix Open Source License (NOSL).
All rights reserved.
