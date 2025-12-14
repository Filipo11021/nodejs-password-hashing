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
import { createPhcFormatter, type PhcNode } from "./utils/phc-formatter.ts";

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

// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
// https://github.com/pilcrowonpaper/oslo/blob/main/src/password/scrypt.ts
// https://github.com/better-auth/better-auth/blob/canary/packages/better-auth/src/crypto/password.ts
// https://docs.adonisjs.com/guides/security/hashing#scrypt
function createKeyGenerator({
  cost = 2 ** 17,
  blockSize = 8,
  parallelization = 1,
  keyLength = 64,
}: {
  cost?: number;
  blockSize?: number;
  parallelization?: number;
  keyLength?: number;
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

type ScryptHashingOptions = {
  cost?: number;
  blockSize?: number;
  parallelization?: number;
  keyLength?: number;
};

function validatePhcNode(phcNode: PhcNode) {
  if (phcNode.id !== "scrypt") {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.params) {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.params.n) {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.params.r) {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.params.p) {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.hash) {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.salt) {
    throw new Error("Invalid password hash");
  }

  return phcNode as PhcNode<{ n: number; r: number; p: number }>;
}

export function createScryptHashing(options?: ScryptHashingOptions): Hashing {
  const phcFormatter = createPhcFormatter();
  const defaultOptions = {
    cost: options?.cost ?? 2 ** 17,
    blockSize: options?.blockSize ?? 8,
    parallelization: options?.parallelization ?? 1,
    keyLength: options?.keyLength ?? 64,
  };
  const keyGenerator = createKeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const saltBuffer = randomBytes(16);
      const key = await keyGenerator.generateKey(password, saltBuffer);
      return phcFormatter.serialize(saltBuffer, key, {
        id: "scrypt",
        params: {
          n: defaultOptions.cost,
          r: defaultOptions.blockSize,
          p: defaultOptions.parallelization,
        },
      });
    },
    async verify(password, hash) {
      const phcNode = phcFormatter.deserialize(hash);
      if (phcNode.id !== "scrypt") {
        throw new Error("Invalid password hash");
      }

      const validatedPhcNode = validatePhcNode(phcNode);
      if (!validatedPhcNode.params) {
        throw new Error("Invalid password hash");
      }

      const targetKey = await createKeyGenerator({
        cost: Number(validatedPhcNode.params.n),
        blockSize: Number(validatedPhcNode.params.r),
        parallelization: Number(validatedPhcNode.params.p),
        keyLength: validatedPhcNode.hash.byteLength,
      }).generateKey(password, validatedPhcNode.salt);

      return timingSafeEqual(targetKey, validatedPhcNode.hash);
    },
    needsReHash(hash) {
      try {
        const phcNode = phcFormatter.deserialize(hash);
        if (!phcNode) return false;

        const validatedPhcNode = validatePhcNode(phcNode);
        if (!validatedPhcNode.params) return false;

        if (validatedPhcNode.params.n !== defaultOptions.cost) return true;
        if (validatedPhcNode.params.r !== defaultOptions.blockSize) return true;
        if (validatedPhcNode.params.p !== defaultOptions.parallelization)
          return true;
        if (validatedPhcNode.hash.byteLength !== defaultOptions.keyLength)
          return true;

        return false;
      } catch {
        return true;
      }
    },
  };
}
