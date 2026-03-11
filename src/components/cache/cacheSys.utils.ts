import { promisify } from "util";
import { existsSync, mkdirSync, statSync, readdirSync } from "fs";
import path from "path";
import zlib from "zlib";
import { Bridge } from "../../core/bridge";

/**
 * Ensure directory exists for file cache operations
 */
export const ensureDirectoryExists = async (
  filePath: string,
): Promise<void> => {
  const dir = path.dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
};

/**
 * Encrypt data for file storage
 */
export const encryptFileData = (
  data: string,
  key?: Buffer,
): {
  encrypted: string;
  iv: string;
  authTag: string;
  key: string;
} => {
  const encryptionKey = key || Buffer.from(Bridge.getRandomBytes(32));

  const encHex = Bridge.encryptRaw(
    new TextEncoder().encode(data),
    encryptionKey,
    "aes",
  );
  if (encHex.startsWith("error:")) throw new Error(encHex);

  const [ivHex, tagHex, dataHex] = encHex.split(":");

  return {
    encrypted: dataHex,
    iv: ivHex,
    authTag: tagHex,
    key: encryptionKey.toString("base64"),
  };
};

/**
 * Decrypt data from file storage
 */
export const decryptFileData = (
  encrypted: string,
  iv: string,
  authTag: string,
  key: string,
): string => {
  const keyBuffer = Buffer.from(key, "base64");

  // Format parts to reconstruct "nonce:tag:ciphertext" in hex format
  const partsStr = `${iv}:${authTag}:${encrypted}`;

  const decryptedHex = Bridge.decryptRaw(partsStr, keyBuffer, "aes");
  if (decryptedHex.startsWith("error:")) throw new Error(decryptedHex);

  // Convert hex bytes back to string
  const decMatches = decryptedHex.match(/.{1,2}/g) || [];
  const bytes = new Uint8Array(decMatches.map((byte) => parseInt(byte, 16)));

  return new TextDecoder().decode(bytes);
};

/**
 * Compress data if beneficial
 */
export const compressFileData = async (
  data: string,
): Promise<{
  data: string;
  compressed: boolean;
}> => {
  if (data.length < 1024) {
    // Don't compress small data
    return { data, compressed: false };
  }

  try {
    const deflate = promisify(zlib.deflate);
    const compressed = await deflate(Buffer.from(data, "utf8"));
    const compressedString = compressed.toString("base64");

    if (compressedString.length < data.length * 0.9) {
      return { data: compressedString, compressed: true };
    }
  } catch (error) {
    console.warn("File compression failed:", error);
  }

  return { data, compressed: false };
};

/**
 * Decompress data
 */
export const decompressFileData = async (
  data: string,
  compressed: boolean,
): Promise<string> => {
  if (!compressed) return data;

  try {
    const inflate = promisify(zlib.inflate);
    const decompressed = await inflate(Buffer.from(data, "base64"));
    return decompressed.toString("utf8");
  } catch (error) {
    console.error("File decompression failed:", error);
    throw new Error("Data decompression failed");
  }
};
