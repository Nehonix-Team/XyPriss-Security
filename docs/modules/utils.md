# Utilities Module

Foundational helpers for encoding, decoding, and byte manipulation.

## Module Exports

- [Encoding Utilities](#encoding-utilities)
- [Unified Utils Interface](#unified-utils-interface)

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

### Utils.hash(data, options?)

Alias for `Hash.create`.

### Utils.getRandomBytes(length)

Alias for `Random.getRandomBytes`.

### Utils.encrypt(data, key, algo?)

Performs quick string-to-string encryption using the native bridge (AES/ChaCha20).

### Utils.decrypt(encrypted, key, algo?)

Performs quick string-to-string decryption.

**Example:**

```typescript
import { Utils } from "xypriss-security";

const bytes = Utils.getRandomBytes(16);
const hex = Utils.hash("test");
```
