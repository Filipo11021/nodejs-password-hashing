import {
  argon2,
  randomBytes,
  timingSafeEqual,
  type BinaryLike,
} from "node:crypto";
import { promisify } from "node:util";
import type { Hashing } from "./hashing.ts";
import { normalizePassword } from "./utils/normalize-password.ts";
import { createPhcFormatter } from "./utils/phc-formatter.ts";
import z from "zod";

const argon2Async = promisify(argon2);

type KeyGenerator = {
  generateKey: (password: string, salt: BinaryLike) => Promise<Buffer>;
};

function createKeyGenerator({
  memory,
  passes,
  parallelism,
  tagLength,
}: {
  memory: number;
  passes: number;
  parallelism: number;
  tagLength: number;
}): KeyGenerator {
  return {
    generateKey(password, salt) {
      return argon2Async("argon2id", {
        message: normalizePassword(password),
        nonce: salt,
        memory,
        passes,
        parallelism,
        tagLength,
      });
    },
  };
}

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
  const phcFormatter = createPhcFormatter(
    z.object({
      hash: z.instanceof(Buffer),
      salt: z.instanceof(Buffer),
      id: z.literal("argon2id"),
      params: z.object({
        memory: z.number(),
        passes: z.number(),
        parallelism: z.number(),
      }),
    }),
  );

  const defaultOptions = { ...recommendedOptions, ...options };

  const keyGenerator = createKeyGenerator(defaultOptions);

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
      const phcNode = await phcFormatter.deserialize(hash);

      const targetKey = await createKeyGenerator({
        memory: phcNode.params.memory,
        passes: phcNode.params.passes,
        parallelism: phcNode.params.parallelism,
        tagLength: phcNode.hash.byteLength,
      }).generateKey(password, phcNode.salt);

      return timingSafeEqual(targetKey, phcNode.hash);
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
