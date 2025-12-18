import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Hashing } from "../hashing.ts";
import { createScryptPhcFormatter } from "./scrypt-phc-formatter.ts";
import { createScryptKeyGenerator } from "./scrypt-key-generator.ts";

type ScryptHashingOptions = Readonly<{
  cost: number;
  blockSize: number;
  parallelization: number;
  keyLength: number;
}>;

/**
 * Recommended Scrypt configuration.
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
 */
const recommendedOptions: ScryptHashingOptions = {
  cost: 2 ** 17,
  blockSize: 8,
  parallelization: 1,
  keyLength: 64,
};

/**
 * Creates a Scrypt hashing instance.
 * @param options - Optional Scrypt configuration to override the recommended defaults.
 * @see recommended defaults {@link recommendedOptions}
 */
export function createScryptHashing(
  options?: Partial<ScryptHashingOptions>,
): Hashing {
  const phcFormatter = createScryptPhcFormatter();

  const defaultOptions = Object.freeze({ ...recommendedOptions, ...options });

  const keyGenerator = createScryptKeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const salt = randomBytes(16);
      const key = await keyGenerator.generateKey(password, salt);

      return phcFormatter.serialize({
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
        const phcNode = await phcFormatter.deserialize(hash);

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
        const phcNode = await phcFormatter.deserialize(hash);

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
