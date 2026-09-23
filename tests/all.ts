import { Cipher } from "../src";

async function main() {
  const h2 = Cipher.crypto.scrypt("123456", Buffer.from("c72cccea0dea40e308f5958e8f41564b", "hex"), 32, 16384, 8, 1);
  console.log(h2);
}

main();
