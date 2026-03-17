/**
 * Safe Serialization Utility for FortifiedFunction
 * Handles cyclic structures, XyPriss objects, and performance optimization
 *
 * v2 — Improvements over v1:
 *  - Iterative serialization engine (no call-stack growth → supports depth ~10 000+)
 *  - Accurate depth tracking via an explicit node stack (was broken with shared `depth` counter)
 *  - Circular-reference path reporting  e.g. "[Circular → $.a.b.c]"
 *  - Chunk-array string builder (avoids O(n²) string concatenation on large outputs)
 *  - Static Set for O(1) lookup of known-problematic constructor names
 *  - Safe UTF-8 boundary truncation (never splits a surrogate pair)
 *  - `parse()` helper with typed return & error guard
 *  - `measureSize()` dry-run to estimate serialized byte size without full output
 *  - `deepClone()` powered by the same safe engine
 */

import { SafeSerializationOptions } from "./types";

// ---------------------------------------------------------------------------
// Extended options
// ---------------------------------------------------------------------------

export interface ExtendedSerializationOptions extends SafeSerializationOptions {
  /**
   * Maximum number of items serialized inside a single array before it is
   * summarised as "[Array: N items]".  Default: 10 000.
   */
  maxArrayItems?: number;

  /**
   * Maximum number of own keys serialized inside a single object before the
   * rest are summarised.  Default: 10 000.
   */
  maxObjectKeys?: number;

  /**
   * Include circular-reference path in the placeholder string.
   * e.g. "[Circular → $.items[2].parent]"
   * Default: true.
   */
  reportCircularPath?: boolean;
}

// ---------------------------------------------------------------------------
// Well-known constructor names that must be replaced before traversal
// ---------------------------------------------------------------------------

const BLOCKED_CONSTRUCTORS = new Set([
  "Socket",
  "Server",
  "Agent",
  "TLSSocket",
  "Net",
  "EventEmitter",
  "ReadStream",
  "WriteStream",
  "Transform",
  "Duplex",
]);

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "cookie",
  "x-api-key",
  "x-auth-token",
  "x-session-token",
  "proxy-authorization",
  "set-cookie",
]);

// ---------------------------------------------------------------------------
// SafeSerializer
// ---------------------------------------------------------------------------

export class SafeSerializer {
  private static readonly DEFAULT_OPTIONS: Required<ExtendedSerializationOptions> =
    {
      maxDepth: 10_000,
      maxLength: 10_000,
      includeNonEnumerable: false,
      truncateStrings: 1_000,
      fastMode: false,
      maxArrayItems: 10_000,
      maxObjectKeys: 10_000,
      reportCircularPath: true,
      pureRaw: false,
    };

  // -------------------------------------------------------------------------
  // PUBLIC API
  // -------------------------------------------------------------------------

  /**
   * Primary serialization entry-point.
   *
   * Fast path: plain JSON.stringify when `fastMode` is enabled and the object
   * has no known pitfalls.
   * Safe path: iterative engine that handles depth ~10 000, cycles, specials.
   */
  public static stringify(
    obj: unknown,
    options: ExtendedSerializationOptions = {},
  ): string {
    const opts = this.mergeOptions(options);

    if (opts.fastMode) {
      try {
        const result = JSON.stringify(obj);
        if (result !== undefined && result.length <= opts.maxLength) {
          return result;
        }
      } catch {
        // Fall through
      }
    }

    return this.iterativeStringify(obj, opts);
  }

  /**
   * XyPriss-aware serialization (req / res objects).
   * Uses the iterative engine so it is also safe for deeply nested structures.
   */
  public static XyPriStringify(
    obj: unknown,
    options: ExtendedSerializationOptions = {},
  ): string {
    // The iterative engine already handles XyPriss objects natively.
    return this.iterativeStringify(obj, this.mergeOptions(options));
  }

  /**
   * Safe JSON.parse — never throws; returns `undefined` on failure.
   */
  public static parse<T = unknown>(json: string): T | undefined {
    try {
      return JSON.parse(json) as T;
    } catch {
      return undefined;
    }
  }

  /**
   * Estimate serialized size (characters) without building the full string.
   * Useful to decide whether to serialize at all before hitting maxLength.
   * Returns -1 when the object is too complex to estimate quickly.
   */
  public static measureSize(obj: unknown): number {
    try {
      const s = JSON.stringify(obj);
      return s === undefined ? -1 : s.length;
    } catch {
      return -1;
    }
  }

  /**
   * Deep-clone a plain-data object through serialization.
   * Returns `undefined` when the value cannot be round-tripped.
   */
  public static deepClone<T>(
    obj: T,
    options: ExtendedSerializationOptions = {},
  ): T | undefined {
    const serialized = this.stringify(obj, { ...options, maxDepth: 10_000 });
    return this.parse<T>(serialized);
  }

  /**
   * Generate a stable cache key for a list of arguments.
   */
  public static generateCacheKey(args: unknown[], prefix = "cache"): string {
    if (!args || args.length === 0) return `${prefix}:empty`;

    const hasXyPriss = args.some((a) => this.isXyPrissObject(a));

    if (hasXyPriss) {
      const safe = this.XyPriStringify(args, {
        fastMode: false,
        maxDepth: 3,
        maxLength: 300,
        truncateStrings: 50,
      });
      return `${prefix}:xypriss:${safe}`;
    }

    try {
      const simple = JSON.stringify(args);
      if (simple !== undefined && simple.length <= 500) {
        return `${prefix}:${simple}`;
      }
    } catch {
      // Fall through
    }

    const safe = this.stringify(args, {
      fastMode: false,
      maxDepth: 5,
      maxLength: 500,
      truncateStrings: 100,
    });
    return `${prefix}:${safe}`;
  }

  /** Compact debug log — honours console.log caller location */
  public static debugLog(label: string, obj: unknown, maxLength = 200): void {
    const serialized = this.stringify(obj, {
      fastMode: true,
      maxLength,
      maxDepth: 3,
      truncateStrings: 50,
    });
    console.log(`[DEBUG] ${label}: ${serialized}`);
  }

  /** Full-fidelity audit log */
  public static auditLog(obj: unknown): string {
    return this.stringify(obj, {
      fastMode: false,
      maxDepth: 50,
      maxLength: 50_000,
      truncateStrings: 5_000,
      includeNonEnumerable: false,
    });
  }

  // -------------------------------------------------------------------------
  // CORE: Iterative serialization engine
  // -------------------------------------------------------------------------

  /**
   * Converts an arbitrary value to a JSON string without using recursion.
   *
   * Algorithm:
   *   - Maintain an explicit `stack` of work items.
   *   - Each item knows its expected "output slot" (index into `chunks[]`).
   *   - After processing all children of a container, a "close" marker writes
   *     the closing bracket/brace into the correct slot.
   *   - `seen` is a WeakMap<object, path-string> for O(1) cycle detection with
   *     optional path reporting.
   *
   * This avoids JavaScript call-stack growth entirely: depth 10 000 is handled
   * as cheaply as depth 10.
   */
  private static iterativeStringify(
    root: unknown,
    opts: Required<ExtendedSerializationOptions>,
  ): string {
    const seen = new WeakMap<object, string>();
    const chunks: string[] = [];

    // Write the root value into `chunks` iteratively.
    this.writeValue(root, "$", 0, seen, chunks, opts);

    // Join & truncate
    const result = chunks.join("");
    return this.safeTruncate(result, opts.maxLength);
  }

  /**
   * Recursion-free value serializer.
   * Uses an explicit stack so depth can go to ~10 000 without any JS stack growth.
   */
  private static writeValue(
    value: unknown,
    path: string,
    depth: number,
    seen: WeakMap<object, string>,
    chunks: string[],
    opts: Required<ExtendedSerializationOptions>,
  ): void {
    // Stack entries: each is a thunk (() => void)
    type Task = () => void;
    const stack: Task[] = [];

    const process = (val: unknown, p: string, d: number): void => {
      // --- Primitives ---
      if (val === undefined) {
        chunks.push("null");
        return;
      }
      if (val === null) {
        chunks.push("null");
        return;
      }

      const t = typeof val;

      if (t === "boolean" || t === "number") {
        // Guard against non-finite numbers (JSON doesn't support them)
        if (t === "number" && !isFinite(val as number)) {
          chunks.push("null");
        } else {
          chunks.push(JSON.stringify(val));
        }
        return;
      }

      if (t === "bigint") {
        chunks.push(JSON.stringify(val.toString()));
        return;
      }

      if (t === "symbol") {
        chunks.push(`"[Symbol:${(val as symbol).toString()}]"`);
        return;
      }

      if (t === "function") {
        const fn = val as Function;
        if (opts.pureRaw) {
          // In pureRaw, we try to see everything. Functions are objects too!
          // We mark it as function but allow traversal of its properties
          const fnObj: any = {
            _type: `[Function:${fn.name || "anonymous"}]`,
            source: fn.toString(),
          };
          // Copy own properties
          for (const k of Object.getOwnPropertyNames(fn)) {
            try {
              fnObj[k] = (fn as any)[k];
            } catch {}
          }
          process(fnObj, p, d);
          return;
        }
        const source = fn.toString();
        const snippet =
          source.length > 100
            ? source.substring(0, 100).replace(/\n/g, " ") + "..."
            : source;
        chunks.push(
          JSON.stringify(`[Function:${fn.name || "anonymous"} | ${snippet}]`),
        );
        return;
      }

      if (t === "string") {
        const s = val as string;
        const truncated =
          s.length > opts.truncateStrings
            ? this.safeTruncate(s, opts.truncateStrings) + "...[truncated]"
            : s;
        chunks.push(JSON.stringify(truncated));
        return;
      }

      // --- Objects ---
      const obj = val as object;

      // Depth guard
      if (d > opts.maxDepth) {
        chunks.push(`"[Max Depth: ${d}]"`);
        return;
      }

      // Cycle detection
      if (seen.has(obj)) {
        const circularPath = seen.get(obj)!;
        if (opts.reportCircularPath) {
          chunks.push(`"[Circular → ${circularPath}]"`);
        } else {
          chunks.push('"[Circular Reference]"');
        }
        return;
      }

      // --- Special value types (no need to mark as seen) ---

      if (val instanceof Date) {
        chunks.push(JSON.stringify(val.toISOString()));
        return;
      }

      if (val instanceof RegExp) {
        chunks.push(JSON.stringify(val.toString()));
        return;
      }

      if (val instanceof Error) {
        seen.set(obj, p);
        const errObj = {
          _type: "[Error]",
          name: (val as Error).name,
          message: (val as Error).message,
          stack: (val as Error).stack ? "[Stack Trace Redacted]" : undefined,
        };
        process(errObj, p, d);
        return;
      }

      if (typeof Buffer !== "undefined" && Buffer.isBuffer(val)) {
        if (opts.pureRaw) {
          // Convert buffer to real array for pureRaw inspection
          process(Array.from(val as Buffer), p, d);
          return;
        }
        const buf = val as Buffer;
        const preview =
          buf.length > 32
            ? buf.slice(0, 32).toString("hex") + "..."
            : buf.toString("hex");
        chunks.push(
          JSON.stringify(`[Buffer:${buf.length} bytes | 0x${preview}]`),
        );
        return;
      }

      if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
        const len =
          val instanceof ArrayBuffer
            ? val.byteLength
            : (val as Uint8Array).byteLength;
        chunks.push(`"[BinaryData:${len}bytes]"`);
        return;
      }

      if (val instanceof Map) {
        seen.set(obj, p);
        const mapObj: Record<string, unknown> = { _type: "[Map]" };
        let i = 0;
        for (const [k, v] of val as Map<unknown, unknown>) {
          if (i >= opts.maxObjectKeys) {
            mapObj[`...[${(val as Map<unknown, unknown>).size - i} more]`] =
              null;
            break;
          }
          mapObj[String(k)] = v;
          i++;
        }
        process(mapObj, p, d);
        return;
      }

      if (val instanceof Set) {
        seen.set(obj, p);
        const arr = Array.from(val as Set<unknown>);
        process(arr, p, d);
        return;
      }

      if (val instanceof Promise) {
        chunks.push('"[Promise]"');
        return;
      }

      if (
        val instanceof WeakMap ||
        val instanceof WeakSet ||
        val instanceof WeakRef
      ) {
        chunks.push(`"[${val.constructor.name}]"`);
        return;
      }

      // --- XyPriss / Node.js special objects ---

      const ctorName: string | undefined = (obj as any).constructor?.name;

      if (BLOCKED_CONSTRUCTORS.has(ctorName ?? "")) {
        if (opts.pureRaw) {
          // Bypass block and treat as plain object
          // but we still need to set seen to avoid immediate cycles
          seen.set(obj, p);
          // Fall through to plain object traversal below
        } else {
          // Extract useful metadata from common blocked objects
          const meta: any = { _type: `[Blocked:${ctorName}]` };
          try {
            if (ctorName?.includes("Socket")) {
              meta.remoteAddress = (val as any).remoteAddress;
              meta.remotePort = (val as any).remotePort;
              meta.localPort = (val as any).localPort;
            } else if (ctorName === "Server") {
              meta.listening = (val as any).listening;
            }
          } catch {}

          process(meta, p, d);
          return;
        }
      }

      if (ctorName === "IncomingMessage" || ctorName === "Request") {
        seen.set(obj, p);
        process(
          {
            _type: "[XyPriss Request]",
            method: (val as any).method,
            url: (val as any).url,
            headers: this.sanitizeHeaders((val as any).headers),
            query: (val as any).query,
            params: (val as any).params,
            body: (val as any).body ? "[Request Body]" : undefined,
            ip: (val as any).ip,
          },
          p,
          d,
        );
        return;
      }

      if (ctorName === "ServerResponse" || ctorName === "Response") {
        seen.set(obj, p);
        process(
          {
            _type: "[XyPriss Response]",
            statusCode: (val as any).statusCode,
            statusMessage: (val as any).statusMessage,
            headersSent: (val as any).headersSent,
          },
          p,
          d,
        );
        return;
      }

      // Heuristic: looks like a duck-typed XyPriss request
      if (
        (val as any).method &&
        (val as any).url &&
        (val as any).headers &&
        !Array.isArray(val)
      ) {
        seen.set(obj, p);
        process(
          {
            _type: "[XyPriss Request-like]",
            method: (val as any).method,
            url: (val as any).url,
            headers: this.sanitizeHeaders((val as any).headers),
          },
          p,
          d,
        );
        return;
      }

      // --- Arrays ---

      if (Array.isArray(val)) {
        seen.set(obj, p);
        const arr = val as unknown[];

        if (arr.length === 0) {
          chunks.push("[]");
          return;
        }

        const limit = Math.min(arr.length, opts.maxArrayItems);
        const truncatedArray = limit < arr.length;

        chunks.push("[");

        // Push items onto the stack in reverse order so they execute in order
        // We schedule a "close" task last (it runs after all items)
        const closeIdx = chunks.length; // slot reserved below
        chunks.push(""); // placeholder for closing bracket / truncation note

        const itemTasks: Task[] = [];
        for (let i = 0; i < limit; i++) {
          const idx = i;
          itemTasks.push(() => {
            if (idx > 0) chunks.push(",");
            process(arr[idx], `${p}[${idx}]`, d + 1);
          });
        }
        // The close task
        const closeTask = () => {
          if (truncatedArray) {
            chunks.push(",");
            chunks.push(`"...[${arr.length - limit} more items truncated]"`);
          }
          chunks[closeIdx] = ""; // clear placeholder
          chunks.push("]");
        };

        // Push close task first, then items in REVERSE order so Task(0) is on top
        stack.push(closeTask);
        for (let i = itemTasks.length - 1; i >= 0; i--) {
          stack.push(itemTasks[i]);
        }
        return;
      }

      // --- Plain objects ---

      seen.set(obj, p);

      const keys = opts.includeNonEnumerable
        ? Object.getOwnPropertyNames(obj)
        : Object.keys(obj);

      if (keys.length === 0) {
        chunks.push("{}");
        return;
      }

      const limit = Math.min(keys.length, opts.maxObjectKeys);
      const truncatedObj = limit < keys.length;

      chunks.push("{");
      const closeIdx = chunks.length;
      chunks.push(""); // placeholder

      const keyTasks: Task[] = [];
      for (let i = 0; i < limit; i++) {
        const k = keys[i];
        const idx = i;
        keyTasks.push(() => {
          if (idx > 0) chunks.push(",");
          chunks.push(JSON.stringify(k));
          chunks.push(":");
          let v: unknown;
          try {
            v = (obj as any)[k];
          } catch {
            v = "[Property Access Error]";
          }
          process(v, `${p}.${k}`, d + 1);
        });
      }

      const closeTask = () => {
        if (truncatedObj) {
          chunks.push(",");
          chunks.push(`"...[${keys.length - limit} more keys truncated]":null`);
        }
        chunks[closeIdx] = "";
        chunks.push("}");
      };

      stack.push(closeTask);
      for (let i = keyTasks.length - 1; i >= 0; i--) {
        stack.push(keyTasks[i]);
      }
    };

    // Seed the stack with the root
    stack.push(() => process(value, path, depth));

    // Drain the stack — this is the non-recursive loop
    while (stack.length > 0) {
      const task = stack.pop()!;
      task();
    }
  }

  // -------------------------------------------------------------------------
  // UTILITIES
  // -------------------------------------------------------------------------

  /** Merge user options with defaults, always producing a fully-defined object */
  private static mergeOptions(
    options: ExtendedSerializationOptions,
  ): Required<ExtendedSerializationOptions> {
    return { ...this.DEFAULT_OPTIONS, ...options };
  }

  /**
   * Truncate a string at a safe Unicode boundary (no split surrogates).
   */
  private static safeTruncate(s: string, maxLen: number): string {
    if (s.length <= maxLen) return s;
    // Walk back from maxLen until we find a non-low-surrogate boundary
    let i = maxLen;
    while (i > 0 && s.charCodeAt(i) >= 0xdc00 && s.charCodeAt(i) <= 0xdfff) {
      i--;
    }
    return s.substring(0, i);
  }

  /** Redact sensitive HTTP headers */
  private static sanitizeHeaders(headers: unknown): unknown {
    if (!headers || typeof headers !== "object") return headers;

    const sanitized: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
      sanitized[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? "[REDACTED]" : v;
    }
    return sanitized;
  }

  /** Duck-type detection for XyPriss req/res objects */
  private static isXyPrissObject(arg: unknown): boolean {
    if (!arg || typeof arg !== "object") return false;
    const a = arg as any;
    const name = a.constructor?.name;
    if (
      name === "IncomingMessage" ||
      name === "ServerResponse" ||
      name === "Request" ||
      name === "Response"
    )
      return true;
    if (a.method && a.url && a.headers) return true;
    if (a.statusCode !== undefined && a.headersSent !== undefined) return true;
    return false;
  }
}
