import z from "zod";
import { MAX_UINT32 } from "../utils/numbers.ts";
import { bufferSchema } from "../utils/schemas.ts";
import { createPhcFormatter } from "../utils/phc-formatter.ts";

const getMaxParallelization = (blockSize: number) =>
  Math.floor(((Math.pow(2, 32) - 1) * 32) / (128 * blockSize));

const scryptPhcFormatterSchema = z.object({
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

export function createScryptPhcFormatter() {
  const phcFormatter = createPhcFormatter(scryptPhcFormatterSchema);

  return phcFormatter;
}
