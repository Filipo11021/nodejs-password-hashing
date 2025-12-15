import {
  randomBytes,
  scrypt,
  timingSafeEqual,
  type BinaryLike,
  type ScryptOptions,
} from "node:crypto";
import { promisify } from "node:util";
import type { Hashing } from "./hashing.ts";
import { normalizePassword } from "./utils/normalize-password.ts";
import { createPhcFormatter } from "./utils/phc-formatter.ts";
import z from "zod";

const scryptAsync = promisify<
  BinaryLike,
  BinaryLike,
  number,
  ScryptOptions,
  Buffer<ArrayBuffer>
>(scrypt);

type KeyGenerator = {
  generateKey: (password: string, salt: BinaryLike) => Promise<Buffer>;
};

function createKeyGenerator({
  cost,
  blockSize,
  parallelization,
  keyLength,
}: {
  cost: number;
  blockSize: number;
  parallelization: number;
  keyLength: number;
}): KeyGenerator {
  return {
    generateKey(password, salt) {
      return scryptAsync(normalizePassword(password), salt, keyLength, {
        cost,
        blockSize,
        parallelization,
        maxmem: 128 * blockSize * cost * 2,
      });
    },
  };
}

type ScryptHashingOptions = Readonly<{
  cost: number;
  blockSize: number;
  parallelization: number;
  keyLength: number;
}>;

// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
// https://github.com/pilcrowonpaper/oslo/blob/main/src/password/scrypt.ts
// https://github.com/better-auth/better-auth/blob/canary/packages/better-auth/src/crypto/password.ts
// https://docs.adonisjs.com/guides/security/hashing#scrypt
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
  const phcFormatter = createPhcFormatter(
    z.object({
      hash: z.instanceof(Buffer),
      salt: z.instanceof(Buffer),
      id: z.literal("scrypt"),
      params: z.object({
        cost: z.number(),
        blocksize: z.number(),
        parallelization: z.number(),
      }),
    }),
  );

  const defaultOptions = { ...recommendedOptions, ...options };

  const keyGenerator = createKeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const saltBuffer = randomBytes(16);
      const key = await keyGenerator.generateKey(password, saltBuffer);
      return phcFormatter.serialize(saltBuffer, key, {
        id: "scrypt",
        params: {
          cost: defaultOptions.cost,
          blocksize: defaultOptions.blockSize,
          parallelization: defaultOptions.parallelization,
        },
      });
    },
    async verify(password, hash) {
      const phcNode = await phcFormatter.deserialize(hash);

      const targetKey = await createKeyGenerator({
        cost: phcNode.params.cost,
        blockSize: phcNode.params.blocksize,
        parallelization: phcNode.params.parallelization,
        keyLength: phcNode.hash.byteLength,
      }).generateKey(password, phcNode.salt);

      return timingSafeEqual(targetKey, phcNode.hash);
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
