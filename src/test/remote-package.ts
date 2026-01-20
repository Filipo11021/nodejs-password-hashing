import {
  createScryptHashing,
  createArgon2Hashing,
} from "@filipo11021/nodejs-password-hashing";
import { runAcceptanceTests } from "./acceptance-tests.ts";

const testImplementations = [
  {
    describe: "remote scrypt",
    instance: createScryptHashing(),
    instanceWithDifferentOptions: createScryptHashing({
      cost: 2 ** 10,
    }),
    instanceWithDifferentAlgorithm: createArgon2Hashing(),
  },
  {
    describe: "remote argon2",
    instance: createArgon2Hashing(),
    instanceWithDifferentOptions: createArgon2Hashing({
      memory: 2 ** 10,
    }),
    instanceWithDifferentAlgorithm: createScryptHashing(),
  },
];

runAcceptanceTests(testImplementations);
