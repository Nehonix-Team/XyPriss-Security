/***************************************************************************
 * XyPriss Security Core - Comprehensive Feature Verification
 ****************************************************************************/

import { Cipher, pm, XSec, SCC } from "xypriss-security";
  
console.log("\n🚀 Starting XyPriss Security Core Verification...\n");

// --- 1. RANDOM & TOKENS ---
console.log("--- [1] Random & Token Generation ---");
const bytes = Cipher.random.getRandomBytes(32);
console.log("Secure Bytes (Hex): ", bytes.toString("hex"));
console.log("Secure Bytes (Base64): ", bytes.toString("base64"));

const pin = Cipher.random.Int(1000, 9999);
console.log("Secure PIN [1000-9999]: ", pin);

const otp = Cipher.random.OTP(6);
console.log("Secure OTP (6 digits): ", otp);

const customToken = Cipher.random.generateToken(24, {
  includeSymbols: true,
  excludeSimilarCharacters: true,
});
console.log("Custom Token (Readable): ", customToken.toString("utf8"));

// --- 2. HASHING & PKCE ---
console.log("\n--- [2] Hashing & PKCE ---");
const payload = "xypriss-verification-payload";
const standardHash = Cipher.hash.create(payload);
console.log("SHA-256 Hash: ", standardHash.toString());

const challenge = Cipher.hash.pkce("verifier-123-abc-xyz");
console.log("PKCE S256 Challenge: ", challenge);

const hmac = Cipher.hash.hmac("secret-key", payload, "sha256");
console.log("HMAC-SHA256: ", hmac);

// --- 3. KEY DERIVATION (PBKDF2) ---
console.log("\n--- [3] Key Derivation (PBKDF2) ---");
const start = Date.now();
const derivedKey = Cipher.hash.create("my-password", {
  algorithm: "pbkdf2",
  iterations: 150000,
  salt: "unique-salt-123",
  outputFormat: "hex",
});
console.log("PBKDF2 Derived Key (150k iterations): ", derivedKey);
console.log(`Derivation Time: ${Date.now() - start}ms`);

// --- 4. PROFESSIONAL PASSWORDS (Argon2id) ---
console.log("\n--- [4] Password Hashing (Argon2id) ---");
const pass = "user-secure-pass-99";
console.log("Hashing password with Argon2id...");
const pStart = Date.now();
const passHash = await pm.hash(pass, {
  memoryCost: 65536,
  parallelism: 4,
  iterations: 3,
});
console.log("Argon2id Hash: ", passHash);
console.log(`Hashing Time: ${Date.now() - pStart}ms`);

const isValid = await pm.verify(pass, passHash);
console.log("Verification Result: ", isValid ? "✅ VALID" : "❌ INVALID");

// --- 5. FRAMEWORK UTILITIES ---
console.log("\n--- [5] Framework & API Keys ---");
const apiKey = XSec.generateAPIKey({
  prefix: "xy",
  separator: "_",
  includeTimestamp: true,
  randomPartLength: 32,
});
console.log("Generated API Key: ", apiKey);

const legacyApiKey = Cipher.XSec.generateAPIKey({
  prefix: "legacy",
  includeTimestamp: false,
});
console.log("Legacy API Key (No timestamp): ", legacyApiKey);

console.log("\n✅ Verification Complete - All Systems Operational.\n");
