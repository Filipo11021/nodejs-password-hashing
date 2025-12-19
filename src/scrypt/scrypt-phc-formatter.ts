import z from "zod";
import { MAX_UINT32 } from "../utils/numbers.ts";
import { bufferSchema } from "../utils/schemas.ts";

const getMaxParallelization = (blockSize: number) =>
  Math.floor(((Math.pow(2, 32) - 1) * 32) / (128 * blockSize));

export const scryptPHCDeserializeSchema = z.object({
  id: z.literal("scrypt"),
  hash: bufferSchema({ min: 64, max: 128 }),
  salt: bufferSchema({ min: 8, max: 1024 }),
  params: z
    .object({
      cost: z.number().int().min(1).max(MAX_UINT32),
      blocksize: z.number().int().min(1).max(MAX_UINT32),
      parallelization: z.number().int().min(1),
    })
    .refine(
      (params) => {
        const maxP = getMaxParallelization(params.blocksize);
        return params.parallelization <= maxP;
      },
      {
        message: "parallelization value exceeds maximum based on blocksize",
      },
    ),
});

export type ScryptPhcInput = z.input<typeof scryptPHCDeserializeSchema>;
