import {
  argon2,
  randomBytes,
  timingSafeEqual,
  type BinaryLike,
} from "node:crypto";
import { promisify } from "node:util";
import type { Hashing } from "./hashing.ts";
import { normalizePassword } from "./utils/normalize-password.ts";
import { createPhcFormatter, type PhcNode } from "./utils/phc-formatter.ts";

const argon2Async = promisify(argon2);

type KeyGenerator = {
  generateKey: (password: string, salt: BinaryLike) => Promise<Buffer>;
};
// https://github.com/ranisalt/node-argon2/blob/master/argon2.cjs#L29
// https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
// https://docs.adonisjs.com/guides/security/hashing#argon
function createKeyGenerator({
  memory = 2 ** 16,
  passes = 3,
  parallelism = 4,
  tagLength = 32,
}: {
  memory?: number;
  passes?: number;
  parallelism?: number;
  tagLength?: number;
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

function validatePhcNode(phcNode: Readonly<PhcNode>): PhcNode<{
  memory: number;
  passes: number;
  parallelism: number;
}> {
  if (phcNode.id !== "argon2") {
    throw new TypeError("Invalid password hash");
  }

  if (!phcNode.params) {
    throw new TypeError("Invalid password hash");
  }

  if (!phcNode.params.memory) {
    throw new TypeError("Invalid password hash");
  }

  if (!phcNode.params.passes) {
    throw new TypeError("Invalid password hash");
  }

  if (!phcNode.params.parallelism) {
    throw new TypeError("Invalid password hash");
  }

  if (!phcNode.hash) {
    throw new Error("Invalid password hash");
  }

  if (!phcNode.salt) {
    throw new Error("Invalid password hash");
  }

  return {
    hash: phcNode.hash,
    salt: phcNode.salt,
    id: phcNode.id,
    version: phcNode.version,
    params: {
      memory: Number(phcNode.params.memory),
      parallelism: Number(phcNode.params.parallelism),
      passes: Number(phcNode.params.passes),
    },
  };
}

type Argon2HashingOptions = {
  memory?: number;
  passes?: number;
  parallelism?: number;
  tagLength?: number;
};
export function createArgon2Hashing(options?: Argon2HashingOptions): Hashing {
  const phcFormatter = createPhcFormatter();
  const defaultOptions = {
    memory: options?.memory ?? 2 ** 16,
    passes: options?.passes ?? 3,
    parallelism: options?.parallelism ?? 4,
    tagLength: options?.tagLength ?? 32,
  };
  const keyGenerator = createKeyGenerator(defaultOptions);

  return {
    async hash(password) {
      const saltBuffer = randomBytes(16);
      const key = await keyGenerator.generateKey(password, saltBuffer);
      const { tagLength: _tagLength, ...params } = defaultOptions;
      return phcFormatter.serialize(saltBuffer, key, {
        id: "argon2",
        params,
      });
    },
    async verify(password, hash) {
      const phcNode = phcFormatter.deserialize(hash);
      if (phcNode.id !== "argon2") {
        throw new Error("Invalid password hash");
      }

      const validatedPhcNode = validatePhcNode(phcNode);
      if (!validatedPhcNode.params) {
        throw new Error("Invalid password hash");
      }
      const targetKey = await createKeyGenerator({
        memory: Number(validatedPhcNode.params.memory),
        passes: Number(validatedPhcNode.params.passes),
        parallelism: Number(validatedPhcNode.params.parallelism),
        tagLength: validatedPhcNode.hash.byteLength,
      }).generateKey(password, validatedPhcNode.salt);

      return timingSafeEqual(targetKey, validatedPhcNode.hash);
    },
    needsReHash(hash) {
      try {
        const phcNode = phcFormatter.deserialize(hash);
        const validatedPhcNode = validatePhcNode(phcNode);
        if (!validatedPhcNode.params) return true;

        if (validatedPhcNode.params.memory !== defaultOptions.memory) {
          return true;
        }
        if (validatedPhcNode.params.passes !== defaultOptions.passes) {
          return true;
        }
        if (
          validatedPhcNode.params.parallelism !== defaultOptions.parallelism
        ) {
          return true;
        }
        if (validatedPhcNode.hash.byteLength !== defaultOptions.tagLength) {
          return true;
        }

        return false;
      } catch {
        return true;
      }
    },
  };
}
