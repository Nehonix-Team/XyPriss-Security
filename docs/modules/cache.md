# Cache Module (UFSIMC)

The Ultra-Fast Secure In-Memory Cache (UFSIMC) is a high-performance, encrypted caching engine designed for low-latency operations and memory efficiency.

## Classes

- [UFSIMC](#ufsimc)

---

## UFSIMC

The main cache class providing encrypted in-memory storage.

### Constructor

```typescript
new UFSIMC(maxEntries?: number, logger?: Logger)
```

**Parameters:**

- `maxEntries`: `number` (Default: 10,000) - Maximum number of entries before eviction.
- `logger`: `Logger` (Optional) - Custom logger instance.

---

### Methods

#### set(key, value, options?)

Stores a value in the cache with encryption and optional compression.

**Parameters:**

- `key`: `string` - Cache identifier.
- `value`: `any` - Serializable data.
- `options`: `UltraCacheOptions` (Optional)
  - `ttl`: `number` - Time-to-live in milliseconds.
  - `priority`: `number` (1-10, Default: 5) - Higher priority entries are less likely to be evicted.
  - `tags`: `string[]` - Logical groups for mass invalidation.
  - `skipCompression`: `boolean` - Disable automated compression.
  - `skipEncryption`: `boolean` - Disable automated encryption.
  - `metadata`: `Record<string, any>` - Custom metadata.

**Returns:** `Promise<boolean>`

**Example:**

```typescript
import { Cache } from "xypriss-security";

await Cache.set(
  "user:123",
  { name: "John" },
  {
    ttl: 3600000,
    priority: 8,
    tags: ["users"],
  },
);
```

#### get(key)

Retrieves and decrypts data from the cache.

**Parameters:**

- `key`: `string`

**Returns:** `Promise<any | null>`

#### delete(key)

Removes an entry from the cache.

**Parameters:**

- `key`: `string`

**Returns:** `boolean`

#### has(key)

Checks if an entry exists and is not expired.

**Parameters:**

- `key`: `string`

**Returns:** `boolean`

#### clear()

Removes all entries from the cache.

#### invalidateByTags(tags)

Invalidates all entries associated with the specified tags.

**Parameters:**

- `tags`: `string[]`

**Returns:** `number` (Count of removed entries)

---

### Statistics

Access real-time performance metrics via `getUltraStats`.

```typescript
const stats = Cache.getUltraStats;
console.log(stats.hitRate);
console.log(stats.memoryUsage.used);
```

---

## Production Security & Environment Whitelisting

When running under XyPriss, UFSIMC automatically resolves encryption keys and seeds through the official `__sys__.__env__` API.

To provide dedicated production encryption keys and avoid ephemeral generated key warnings, declare your secrets in your environment (`.env`) and authorize `xypriss-security` in `xypriss.config.jsonc` as documented in the [XyPriss Environment Security Shield Documentation](https://xypriss.nehonix.com/docs/security/environment-shield):

```jsonc
{
  "$env": {
    "packages": {
      "xypriss-security": {
        "whitelist": [
          "ENC_SECRET_KEY",
          "ENC_SECRET_SEED",
          "ENC_SECRET_SALT",
          "XYPRISS_SEC_WARNINGS"
        ],
        "inheritGlobal": false
      }
    }
  }
}
```

- `ENC_SECRET_KEY`: Pre-shared master encryption key (hex or raw string).
- `ENC_SECRET_SEED` & `ENC_SECRET_SALT`: Key derivation seed and salt used when a static key is not provided.
- `XYPRISS_SEC_WARNINGS`: Set to `"silent"` to suppress development warnings regarding ephemeral key generation.

For full specifications on package sandboxing, see [XyPriss Environment Security Shield](https://xypriss.nehonix.com/docs/security/environment-shield).
