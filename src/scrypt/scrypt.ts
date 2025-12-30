import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Hashing } from "../hashing.ts";
import { createScryptKeyGenerator } from "./scrypt-key-generator.ts";
import {
  scryptDeserializePHC,
  scryptSerializePHC,
} from "./scrypt-phc-formatter.ts";
import z from "zod";
import { MAX_UINT32 } from "../utils/numbers.ts";
import { isValidParallelization } from "./parallelization-validation.ts";

const optionsSchema = z
  .object({
    blockSize: z.number().min(1).max(MAX_UINT32),
    cost: z.number().min(2).max(MAX_UINT32),
    parallelization: z.number().min(1),
    keyLength: z.number().min(64).max(128),
    saltLength: z.number().min(16).max(1024),
  })
  .refine(
    (params) =>
      isValidParallelization({
        blocksize: params.blockSize,
        parallelization: params.parallelization,
      }),
    {
      message: "parallelization value exceeds maximum based on blocksize",
    },
  )
  .readonly();

type ScryptHashingOptions = z.input<typeof optionsSchema>;

/**
 * Recommended Scrypt configuration.
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
 */
const recommendedOptions: ScryptHashingOptions = {
  cost: 2 ** 17,
  blockSize: 8,
  parallelization: 1,
  keyLength: 64,
  saltLength: 16,
};

/**
 * Creates a Scrypt hashing instance.
 * @param options - Optional Scrypt configuration to override the recommended defaults.
 * @see recommended defaults {@link recommendedOptions}
 */
export function createScryptHashing(
  options?: Partial<ScryptHashingOptions>,
): Hashing {
  const defaultOptions = optionsSchema.parse({
    ...recommendedOptions,
    ...options,
  });

  const keyGenerator = createScryptKeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const salt = randomBytes(defaultOptions.saltLength);
      const key = await keyGenerator.generateKey(password, salt);

      return scryptSerializePHC({
        id: "scrypt",
        salt,
        hash: key,
        params: {
          cost: defaultOptions.cost,
          blocksize: defaultOptions.blockSize,
          parallelization: defaultOptions.parallelization,
        },
      });
    },
    async verify(password, hash) {
      try {
        const phcNode = scryptDeserializePHC(hash);

        const targetKey = await createScryptKeyGenerator({
          cost: phcNode.params.cost,
          blockSize: phcNode.params.blocksize,
          parallelization: phcNode.params.parallelization,
          keyLength: phcNode.hash.byteLength,
        }).generateKey(password, phcNode.salt);

        return timingSafeEqual(targetKey, phcNode.hash);
      } catch {
        return false;
      }
    },
    async needsReHash(hash) {
      try {
        const phcNode = scryptDeserializePHC(hash);

        const rehashConditions = [
          phcNode.params.cost !== defaultOptions.cost,
          phcNode.params.blocksize !== defaultOptions.blockSize,
          phcNode.params.parallelization !== defaultOptions.parallelization,
          phcNode.hash.byteLength !== defaultOptions.keyLength,
        ];

        const requiresRehash = rehashConditions.some(Boolean);

        return requiresRehash;
      } catch {
        return true;
      }
    },
  };
}
