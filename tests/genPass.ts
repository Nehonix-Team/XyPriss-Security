import { PasswordManager, XyPrissSecurity } from "../src/core";
console.log(XyPrissSecurity.generateAPIKey());

// import {__strl__} from "strulink"

const pwd = new PasswordManager({
  strength: {
    minLength: 8,
    checkDictionary: true,
  },
});

const strongPassword = pwd.strength("acid1234");
console.log(strongPassword);
