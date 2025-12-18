import { scrypt, type BinaryLike, type ScryptOptions } from "node:crypto";
import { normalizePassword } from "../utils/normalize-password.ts";
import { promisify } from "node:util";

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

export function createScryptKeyGenerator({
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
