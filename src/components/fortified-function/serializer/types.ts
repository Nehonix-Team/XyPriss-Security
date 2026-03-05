export interface SafeSerializationOptions {
    maxDepth?: number;
    maxLength?: number;
    includeNonEnumerable?: boolean;
    truncateStrings?: number;
    fastMode?: boolean;
}