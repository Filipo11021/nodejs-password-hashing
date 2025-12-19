import z from "zod";
import { bufferSchema } from "../utils/schemas.ts";
import { MAX_UINT24, MAX_UINT32 } from "../utils/numbers.ts";

export const argon2Versions = [16, 19] as const;

export const argon2PHCDeserializeSchema = z.object({
  hash: bufferSchema({ min: 4, max: MAX_UINT32 }),
  salt: bufferSchema({ min: 8, max: 1024 }),
  id: z.literal("argon2id"),
  // default to 16 for backwards compatibility
  version: z
    .union(argon2Versions.map((version) => z.literal(version)))
    .default(16),
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

export type Argon2PhcInput = z.input<typeof argon2PHCDeserializeSchema> & {
  version: 19;
};
