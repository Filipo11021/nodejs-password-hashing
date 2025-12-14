import { createScryptHashing } from "./scrypt.ts";
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createArgon2Hashing } from "./argon2.ts";

const testImplementations = [
  {
    describe: "scrypt",
    instance: createScryptHashing(),
    instanceWithDifferentOptions: createScryptHashing({
      cost: 2 ** 10,
    }),
    instanceWithDifferentAlgorithm: createArgon2Hashing(),
  },
  {
    describe: "argon2",
    instance: createArgon2Hashing(),
    instanceWithDifferentOptions: createArgon2Hashing({
      memory: 2 ** 10,
    }),
    instanceWithDifferentAlgorithm: createScryptHashing(),
  },
];

for (const implementation of testImplementations) {
  const hashing = implementation.instance;
  const hashingWithDifferentOptions =
    implementation.instanceWithDifferentOptions;
  const instanceWithDifferentAlgorithm =
    implementation.instanceWithDifferentAlgorithm;

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

  describe(`needsReHash - ${implementation.describe}`, () => {
    void it("should return true if the hash is empty", () => {
      const res = hashing.needsReHash("");
      assert.equal(res, true);
    });

    void it("should return true if the hash is malformed", () => {
      const res = hashing.needsReHash("halo");
      assert.equal(res, true);
    });

    void it("should return false if configuration is the same", async () => {
      const hash = await hashing.hash("password");

      const res = hashing.needsReHash(hash);

      assert.equal(res, false);
    });

    void it("should return true if configuration differs", async () => {
      const hash = await hashing.hash("password");

      const res = hashingWithDifferentOptions.needsReHash(hash);

      assert.equal(res, true);
    });

    void it("should return true if the hash algorithm differs", async () => {
      const hash = await instanceWithDifferentAlgorithm.hash("password");

      const res = hashing.needsReHash(hash);

      assert.equal(res, true);
    });
  });
}
