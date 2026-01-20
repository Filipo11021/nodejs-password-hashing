import { createScryptHashing } from "../scrypt/scrypt.ts";
import { createArgon2Hashing } from "../argon2/argon2.ts";
import { runAcceptanceTests } from "./acceptance-tests.ts";

const testImplementations = [
  {
    describe: "local scrypt",
    instance: createScryptHashing(),
    instanceWithDifferentOptions: createScryptHashing({
      cost: 2 ** 10,
    }),
    instanceWithDifferentAlgorithm: createArgon2Hashing(),
  },
  {
    describe: "local argon2",
    instance: createArgon2Hashing(),
    instanceWithDifferentOptions: createArgon2Hashing({
      memory: 2 ** 10,
    }),
    instanceWithDifferentAlgorithm: createScryptHashing(),
  },
];

runAcceptanceTests(testImplementations);
