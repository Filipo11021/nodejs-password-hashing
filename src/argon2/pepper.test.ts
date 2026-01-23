import { createArgon2Hashing } from "./argon2.ts";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

void describe("Argon2 Pepper Support", () => {
  const password = "my-secret-password";
  const firstPepper = "secret-pepper-one";
  const secondPepper = "secret-pepper-two";

  void it("should successfully verify a password when the correct pepper is provided", async () => {
    const hashing = createArgon2Hashing({ pepper: firstPepper });
    const hash = await hashing.hash(password);

    const isValid = await hashing.verify(password, hash);
    assert.strictEqual(
      isValid,
      true,
      "Verification with the correct pepper should succeed",
    );
  });

  void it("should fail verification if a different pepper is used", async () => {
    const hashingA = createArgon2Hashing({ pepper: firstPepper });
    const hashingB = createArgon2Hashing({ pepper: secondPepper });
    const hash = await hashingA.hash(password);
    const isValid = await hashingB.verify(password, hash);

    assert.strictEqual(
      isValid,
      false,
      "Verification with a mismatched pepper should fail",
    );
  });
});

void describe("Argon2 Pepper Validation", () => {
  const minIncludedPepper = "a";
  const minExcludedPepper = "";

  const maxIncludedPepper = "a".repeat(1024);
  const maxExcludedPepper = "a".repeat(1025);

  for (const pepper of [minIncludedPepper, maxIncludedPepper]) {
    const password = "my-secret-password";

    void it(`should verify a password when the pepper is ${pepper.length} characters long`, async () => {
      const hashing = createArgon2Hashing({ pepper });
      const hash = await hashing.hash(password);

      const isValid = await hashing.verify(password, hash);
      assert.strictEqual(
        isValid,
        true,
        "Verification with the correct pepper should succeed",
      );
    });
  }

  for (const pepper of [minExcludedPepper, maxExcludedPepper]) {
    void it(`should throw an error if the pepper is ${pepper.length} characters long`, () => {
      assert.throws(() => {
        createArgon2Hashing({ pepper });
      }, "Expected error to be thrown");
    });
  }
});
