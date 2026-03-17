export interface SafeSerializationOptions {
  maxDepth?: number;
  maxLength?: number;
  includeNonEnumerable?: boolean;
  truncateStrings?: number;
  fastMode?: boolean;
  /**
   * Maximum number of items serialized inside a single array before
   * summarisation.  Default: 10 000.
   */
  maxArrayItems?: number;
  /**
   * Maximum number of own keys serialized inside a single object before
   * summarisation.  Default: 10 000.
   */
  maxObjectKeys?: number;
  /**
   * Include the path to the circular reference in the placeholder string.
   * e.g. "[Circular → $.items[2].parent]"
   * Default: true.
   */
  reportCircularPath?: boolean;
  /**
   * If true, disables safety redactions (Buffers, Functions, Sockets, etc.)
   * and attempts to serialize them as objects/arrays where possible.
   * Use with caution as it can produce very large outputs.
   */
  pureRaw?: boolean;
}
