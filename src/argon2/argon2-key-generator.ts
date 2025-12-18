import { promisify } from "node:util";
import { normalizePassword } from "../utils/normalize-password.ts";
import { argon2, type BinaryLike } from "node:crypto";

const argon2Async = promisify(argon2);

type KeyGenerator = {
  generateKey: (password: string, salt: BinaryLike) => Promise<Buffer>;
};

export function createArgon2KeyGenerator({
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
