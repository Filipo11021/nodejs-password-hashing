import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Hashing } from "../hashing.ts";
import { createArgon2PhcFormatter } from "./argon2-phc-formatter.ts";
import { createArgon2KeyGenerator } from "./argon2-key-generator.ts";

type Argon2HashingOptions = Readonly<{
  memory: number;
  passes: number;
  parallelism: number;
  tagLength: number;
}>;

/**
 * Recommended Argon2id configuration.
 * @see https://www.rfc-editor.org/rfc/rfc9106.html#section-4-5
 */
const recommendedOptions: Argon2HashingOptions = {
  memory: 2 ** 16,
  passes: 3,
  parallelism: 4,
  tagLength: 32,
};

/**
 * Creates an Argon2id hashing instance.
 * @param options - Optional Argon2id configuration to override the recommended defaults.
 * @see recommended defaults {@link recommendedOptions}
 */
export function createArgon2Hashing(
  options?: Partial<Argon2HashingOptions>,
): Hashing {
  const phcFormatter = createArgon2PhcFormatter();

  const defaultOptions = Object.freeze({ ...recommendedOptions, ...options });

  const keyGenerator = createArgon2KeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const salt = randomBytes(16);
      const key = await keyGenerator.generateKey(password, salt);

      return phcFormatter.serialize({
        id: "argon2id",
        salt,
        hash: key,
        params: {
          memory: defaultOptions.memory,
          passes: defaultOptions.passes,
          parallelism: defaultOptions.parallelism,
        },
      });
    },
    async verify(password, hash) {
      try {
        const phcNode = await phcFormatter.deserialize(hash);

        const targetKey = await createArgon2KeyGenerator({
          memory: phcNode.params.memory,
          passes: phcNode.params.passes,
          parallelism: phcNode.params.parallelism,
          tagLength: phcNode.hash.byteLength,
        }).generateKey(password, phcNode.salt);

        return timingSafeEqual(targetKey, phcNode.hash);
      } catch {
        return false;
      }
    },
    async needsReHash(hash) {
      try {
        const phcNode = await phcFormatter.deserialize(hash);

        const rehashConditions = [
          phcNode.params.memory !== defaultOptions.memory,
          phcNode.params.passes !== defaultOptions.passes,
          phcNode.params.parallelism !== defaultOptions.parallelism,
          phcNode.hash.byteLength !== defaultOptions.tagLength,
        ];

        const requiresRehash = rehashConditions.some(Boolean);

        return requiresRehash;
      } catch {
        return true;
      }
    },
  };
}
