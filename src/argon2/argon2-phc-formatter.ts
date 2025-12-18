import z from "zod";
import { createPhcFormatter } from "../utils/phc-formatter.ts";
import { bufferSchema } from "../utils/schemas.ts";
import { MAX_UINT24, MAX_UINT32 } from "../utils/numbers.ts";

const argon2PhcFormatterSchema = z.object({
  hash: bufferSchema({ min: 4, max: MAX_UINT32 }),
  salt: bufferSchema({ min: 8, max: 1024 }),
  id: z.literal("argon2id"),
  params: z
    .object({
      memory: z.number().max(MAX_UINT32),
      passes: z.number().int().min(1).max(MAX_UINT32),
      parallelism: z.number().int().min(1).max(MAX_UINT24),
    })
    .refine(
      (params) => {
        return params.memory >= 8 * params.parallelism;
      },
      {
        message: "memory parameter must be at least 8 * parallelism",
      },
    ),
});

export function createArgon2PhcFormatter() {
  return createPhcFormatter(argon2PhcFormatterSchema);
}
