import z from "zod";
import { MAX_UINT32 } from "../utils/numbers.ts";
import { bufferSchema } from "../utils/schemas.ts";
import { isValidParallelization } from "./parallelization-validation.ts";
import phcFormatter from "@phc/format";

export const scryptPHCDeserializeSchema = z.object({
  id: z.literal("scrypt"),
  hash: bufferSchema({ min: 64, max: 128 }),
  salt: bufferSchema({ min: 8, max: 1024 }),
  params: z
    .object({
      n: z.number().int().min(1).max(MAX_UINT32),
      r: z.number().int().min(1).max(MAX_UINT32),
      p: z.number().int().min(1),
    })
    .refine(
      (params) =>
        isValidParallelization({
          blocksize: params.r,
          parallelization: params.p,
        }),
      {
        message: "parallelization value exceeds maximum based on blocksize",
      },
    ),
});

type ScryptSharedContract = {
  id: "scrypt";
  hash: Buffer;
  salt: Buffer;
  params: {
    cost: number;
    blocksize: number;
    parallelization: number;
  };
};

type ScryptPhcInputContract = ScryptSharedContract;

type ScryptPhcOutputContract = ScryptSharedContract;

function fromContractInput(
  input: ScryptPhcInputContract,
): z.infer<typeof scryptPHCDeserializeSchema> {
  return {
    ...input,
    params: {
      n: input.params.cost,
      r: input.params.blocksize,
      p: input.params.parallelization,
    },
  };
}

function toContractOutput(
  input: z.infer<typeof scryptPHCDeserializeSchema>,
): ScryptPhcOutputContract {
  return {
    ...input,
    params: {
      cost: input.params.n,
      blocksize: input.params.r,
      parallelization: input.params.p,
    },
  };
}

export type ScryptPhcInput = z.infer<typeof scryptPHCDeserializeSchema>;

export function scryptDeserializePHC(
  phcString: string,
): ScryptPhcOutputContract {
  return toContractOutput(
    scryptPHCDeserializeSchema.parse(phcFormatter.deserialize(phcString)),
  );
}

export function scryptSerializePHC(input: ScryptPhcInputContract): string {
  return phcFormatter.serialize(fromContractInput(input));
}
