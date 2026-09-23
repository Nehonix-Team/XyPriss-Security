import { Cipher, Hash, hash } from "../src";

async function main() {
  const h2 = Cipher.crypto.scrypt("123456", Buffer.from("c72cccea0dea40e308f5958e8f41564b", "hex"), 32, 16384, 8, 1);
  console.log("scrypt key:", h2);

  const fullHash: string = hash("user@example.com");
  console.log("fullHash:", fullHash, "len:", fullHash.length);

  const shortId: string = hash("user@example.com", 12);
  console.log("shortId (12 chars):", shortId, "len:", shortId.length);

  const optionLength: string = hash("user@example.com", { length: 14 });
  console.log("optionLength (14 chars):", optionLength, "len:", optionLength.length);

  const blakeShort: string = hash("user@example.com", "blake2b", 16);
  console.log("blakeShort (16 chars):", blakeShort, "len:", blakeShort.length);

  const buf = hash("user@example.com", { outputFormat: "buffer" });
  console.log("buf is SecureBuffer:", buf.byteLength, "bytes");

  const hashCreateShort: string = Hash.create("123456", 10);
  console.log("Hash.create short (10 chars):", hashCreateShort, "len:", hashCreateShort.length);
}

main();
