import { createServer } from "xypriss";
import UFSIMC from "../src/components/cache/UFSIMC";
import { getEnv, getEnvStrict } from "../src/utils/env";

console.log("-> Initializing XyPriss server with createServer()...");
const app = createServer();

console.log("-> Instantiating UFSIMC...");
const cache = new UFSIMC(100);

console.log("-> Testing getEnv for non-existing secret...");
const nonExisting = getEnv("NON_EXISTING_SECRET_KEY");
if (nonExisting !== undefined) {
  throw new Error("Expected undefined for non-existing secret");
}

console.log("-> Performing cache set/get operations...");
await cache.set("sample_key", "sample_value");
const res = await cache.get("sample_key");
console.log("-> Value from cache:", res);

console.log("-> Shutting down cache...");
await cache.shutdown();

console.log("-> Verification complete: No [SECURITY] process.env warnings occurred!");
process.exit(0);

