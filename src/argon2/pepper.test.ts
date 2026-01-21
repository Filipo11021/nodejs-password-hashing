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

  void it("should generate distinct hashes for the same password with different peppers", async () => {
    const hashingA = createArgon2Hashing({ pepper: firstPepper });
    const hashingB = createArgon2Hashing({ pepper: secondPepper });
    const hashingNone = createArgon2Hashing();

    const hashA = await hashingA.hash(password);
    const hashB = await hashingB.hash(password);
    const hashNone = await hashingNone.hash(password);

    assert.notStrictEqual(
      hashA,
      hashB,
      "Hashes with different peppers must be distinct",
    );
    assert.notStrictEqual(
      hashA,
      hashNone,
      "A hashed password with a pepper must be distinct from one without",
    );
  });

  void it("should handle long peppers correctly (BinaryLike input support)", async () => {
    const longPepper = Buffer.alloc(32, "a");
    const hashing = createArgon2Hashing({ pepper: longPepper });

    const hash = await hashing.hash(password);
    const isValid = await hashing.verify(password, hash);

    assert.strictEqual(isValid, true, "Should support Buffer-based peppers");
  });
});
