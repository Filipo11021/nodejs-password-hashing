import {
  argon2,
  randomBytes,
  timingSafeEqual,
  type BinaryLike,
} from "node:crypto";
import { promisify } from "node:util";
import type { Hashing } from "./hashing.ts";
import { normalizePassword } from "./utils/normalize-password.ts";
import { fromHex, toHex } from "./utils/hex.ts";

const argon2Async = promisify(argon2);

function generateKey({
  password,
  salt,
}: {
  password: string;
  salt: BinaryLike;
}) {
  // https://github.com/ranisalt/node-argon2/blob/master/argon2.cjs#L29
  // https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4
  // https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
  // https://docs.adonisjs.com/guides/security/hashing#argon
  return argon2Async("argon2id", {
    message: normalizePassword(password),
    nonce: salt,
    memory: 2 ** 16, //64MB,
    passes: 3,
    parallelism: 4,
    tagLength: 32,
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

export const argon2Hashing: Hashing = {
  hash,
  verify,
};
