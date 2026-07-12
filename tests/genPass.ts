import "xypriss";
import { PasswordManager } from "../src";

export const pwd = new PasswordManager({
  algorithm: "argon2id",
  memoryCost: 65536,
  parallelism: 4,
  iterations: 3,
  pepper: __sys__.__env__.get("PASSWORD_PEPPER"),
  strength: {
    minLength: 8,
    checkDictionary: false,
    requireSymbols: false,
    requireLowercase: false,
    requireUppercase: false,
    preventSequences: false
  },
});

const p = "12345678";

console.log("res: ", pwd.strength(p));
