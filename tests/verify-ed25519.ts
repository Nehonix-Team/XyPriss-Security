import { Cipher } from "../src/core";
import crypto from "crypto";

async function test() {
  console.log("Testing Ed25519 Verification via Go Core...");

  // 1. Generate Ed25519 key pair using Node's crypto
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  const pubKeyBytes = publicKey
    .export({ type: "spki", format: "der" })
    .subarray(12); // Extract raw 32 bytes
  const pubKeyHex = pubKeyBytes.toString("hex");

  const data =
    "Hello XyPriss Security Core! This is a test of the optimized Go bridge.";
  const signature = crypto.sign(null, Buffer.from(data), privateKey);
  const signatureBase64 = signature.toString("base64");

  console.log("Public Key Hex:", pubKeyHex);
  console.log("Data:", data);
  console.log("Signature (Base64):", signatureBase64);

  // 2. Verify using our Go-backed library
  const isVerified = Cipher.crypto.ed25519Verify(
    pubKeyHex,
    data,
    signatureBase64,
  );
  console.log("Verification Result:", isVerified);

  if (isVerified) {
    console.log("✅ Ed25519 Verification Successful!");
  } else {
    console.error("❌ Ed25519 Verification Failed!");
    process.exit(1);
  }

  // 3. Test large data (E2BIG fix)
  console.log("\nTesting Large Data (E2BIG fix)...");
  const largeData = crypto.randomBytes(1024 * 512); // 512KB (well above E2BIG limit of ~128KB for CLI args)
  const largeSignature = crypto.sign(null, largeData, privateKey);

  const isLargeVerified = Cipher.crypto.ed25519Verify(
    pubKeyHex,
    largeData,
    largeSignature.toString("base64"),
  );
  console.log("Large Data Verification Result:", isLargeVerified);

  if (isLargeVerified) {
    console.log("✅ Large Data Verification Successful (stdin pipe working)!");
  } else {
    console.error("❌ Large Data Verification Failed!");
    process.exit(1);
  }
}

test().catch((err) => {
  console.error("Test Error:", err);
  process.exit(1);
});
