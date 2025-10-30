import {
  randomBytes,
  scrypt,
  timingSafeEqual,
  type BinaryLike,
  type ScryptOptions,
} from "node:crypto";
import { promisify } from "node:util";
import { normalizePassword } from "./utils/normalize-password.ts";
import { fromHex, toHex } from "./utils/hex.ts";
import type { Hashing } from "./hashing.ts";

const scryptAsync = promisify<
  BinaryLike,
  BinaryLike,
  number,
  ScryptOptions,
  Buffer<ArrayBuffer>
>(scrypt);

function generateKey({
  password,
  salt,
}: {
  password: string;
  salt: BinaryLike;
}) {
  // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt
  // https://github.com/pilcrowonpaper/oslo/blob/main/src/password/scrypt.ts
  // https://github.com/better-auth/better-auth/blob/canary/packages/better-auth/src/crypto/password.ts
  // https://docs.adonisjs.com/guides/security/hashing#scrypt
  const keyLength = 64;
  const cost = 2 ** 17;
  const blockSize = 8;
  const parallelization = 1;

  return scryptAsync(normalizePassword(password), salt, keyLength, {
    cost,
    blockSize,
    parallelization,
    maxmem: 128 * blockSize * cost * 2,
  });
}

const hash: Hashing["hash"] = async (password) => {
  const salt = toHex(randomBytes(16));
  const key = await generateKey({ password, salt });

  return salt + ":" + toHex(key);
};

const verify: Hashing["verify"] = async (password, hash) => {
  const [salt, key] = hash.split(":");
  if (!salt || !key) {
    throw Error("Invalid password hash");
  }

  const targetKey = await generateKey({ password, salt });
  return timingSafeEqual(targetKey, fromHex(key));
};

export const scryptHashing: Hashing = {
  hash,
  verify,
};
