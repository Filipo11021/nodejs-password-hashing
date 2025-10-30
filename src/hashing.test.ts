import { scryptHashing } from "./scrypt.ts";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { argon2Hashing } from "./argon2.ts";

const testImplementations = [
  {
    describe: "scrypt",
    instance: scryptHashing,
  },
  {
    describe: "argon2",
    instance: argon2Hashing,
  },
];

for (const implementation of testImplementations) {
  const hashing = implementation.instance;

  void describe(implementation.describe, () => {
    void it("should return true if the password is valid", async () => {
      const hash = await hashing.hash("password");
      const isValid = await hashing.verify("password", hash);
      assert.equal(isValid, true);
    });

    void it("should return false if the password is invalid", async () => {
      const hash = await hashing.hash("password");
      const isValid = await hashing.verify("test", hash);
      assert.equal(isValid, false);
    });

    void it("should return different hashes for the same password", async () => {
      const hash = await hashing.hash("password");
      const hash2 = await hashing.hash("password");

      assert.notEqual(hash, hash2);
    });

    void it("should throw an error if the hash is malformed", async () => {
      await assert.rejects(async () => {
        await hashing.verify("test", "0");
      }, Error);
    });
  });
}
