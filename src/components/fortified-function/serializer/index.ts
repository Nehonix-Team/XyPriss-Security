/**
 * **CONVENIENCE FUNCTIONS: Quick access to common serialization patterns**
 */

import { SafeSerializer } from "./safe-serializer";
 
// Ultra-fast serialization for performance-critical paths
export const fastStringify = (obj: any): string =>
  SafeSerializer.stringify(obj, { fastMode: true, maxLength: 1000 });

// Safe serialization for complex objects
export const safeStringify = (obj: any): string =>
  SafeSerializer.stringify(obj, { fastMode: false });

// XyPriss-safe serialization for req/res objects
export const XyPriStringify = (obj: any): string =>
  SafeSerializer.XyPriStringify(obj, { fastMode: false });

// Cache key generation
export const generateSafeCacheKey = (args: any[], prefix?: string): string =>
  SafeSerializer.generateCacheKey(args, prefix);

// Debug logging
export const debugLog = (label: string, obj: any): void =>
  SafeSerializer.debugLog(label, obj);

// Audit logging
export const auditStringify = (obj: any): string =>
  SafeSerializer.auditLog(obj);

export { SafeSerializer } from "./safe-serializer";

export * from "./types";
