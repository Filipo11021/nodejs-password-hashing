import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Hashing } from "../hashing.ts";
import {
  argon2DeserializePHC,
  argon2SerializePHC,
  isArgon2Version,
} from "./argon2-phc-formatter.ts";
import { createArgon2KeyGenerator } from "./argon2-key-generator.ts";
import z from "zod";
import { MAX_UINT24, MAX_UINT32 } from "../utils/numbers.ts";

const optionsSchema = z
  .object({
    memory: z.number().max(MAX_UINT32),
    passes: z.number().min(2).max(MAX_UINT32),
    parallelism: z.number().min(1).max(MAX_UINT24),
    tagLength: z.number().min(4).max(MAX_UINT32),
  })
  .refine(
    (params) => {
      return params.memory >= 8 * params.parallelism;
    },
    {
      message: "memory parameter must be at least 8 * parallelism",
    },
  )
  .readonly();

type Argon2HashingOptions = z.input<typeof optionsSchema>;

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
  const defaultOptions = optionsSchema.parse({
    ...recommendedOptions,
    ...options,
  });

  const keyGenerator = createArgon2KeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const salt = randomBytes(16);
      const key = await keyGenerator.generateKey(password, salt);

      return argon2SerializePHC({
        id: "argon2id",
        salt,
        hash: key,
        version: 19,
        params: {
          memory: defaultOptions.memory,
          passes: defaultOptions.passes,
          parallelism: defaultOptions.parallelism,
        },
      });
    },
    async verify(password, hash) {
      try {
        const phcNode = argon2DeserializePHC(hash);

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
        const phcNode = argon2DeserializePHC(hash);

        const rehashConditions = [
          !isArgon2Version(phcNode.version),
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
