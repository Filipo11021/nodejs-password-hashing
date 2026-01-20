import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Hashing } from "../hashing.ts";

type TestImplementation = {
  describe: string;
  instance: Hashing;
  instanceWithDifferentOptions: Hashing;
  instanceWithDifferentAlgorithm: Hashing;
};

export function runAcceptanceTests(testImplementations: TestImplementation[]) {
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

      void it("should return false if the hash is malformed", async () => {
        const isValid = await hashing.verify("test", "malformed-hash");
        assert.equal(isValid, false);
      });

      void it("should return false if the hash is empty", async () => {
        const isValid = await hashing.verify("test", "");
        assert.equal(isValid, false);
      });
    });

    void describe(`needsReHash - ${implementation.describe}`, () => {
      void it("should return true if the hash is empty", async () => {
        const res = await hashing.needsReHash("");
        assert.equal(res, true);
      });

      void it("should return true if the hash is malformed", async () => {
        const res = await hashing.needsReHash("halo");
        assert.equal(res, true);
      });

      void it("should return false if configuration is the same", async () => {
        const hash = await hashing.hash("password");

        const res = await hashing.needsReHash(hash);

        assert.equal(res, false);
      });

      void it("should return true if configuration differs", async () => {
        const hash = await hashing.hash("password");

        const res = await hashingWithDifferentOptions.needsReHash(hash);

        assert.equal(res, true);
      });

      void it("should return true if the hash algorithm differs", async () => {
        const hash = await instanceWithDifferentAlgorithm.hash("password");

        const res = await hashing.needsReHash(hash);

        assert.equal(res, true);
      });
    });
  }
}
