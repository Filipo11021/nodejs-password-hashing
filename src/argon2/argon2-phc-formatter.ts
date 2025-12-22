import z from "zod";
import { bufferSchema } from "../utils/schemas.ts";
import { MAX_UINT24, MAX_UINT32 } from "../utils/numbers.ts";
import phcFormatter from "@phc/format";

const argon2Versions = [16, 19] as const;
type Argon2Version = (typeof argon2Versions)[number];

function isArgon2Version(version: number) {
  return argon2Versions.some((v) => v === version);
}

function isValidMinMemory(params: { memory: number; parallelism: number }) {
  return params.memory >= 8 * params.parallelism;
}

const defaultVersionForBackwardsCompatibility: Argon2Version = 16;

const argon2PHCDeserializeSchema = z.object({
  hash: bufferSchema({ min: 4, max: MAX_UINT32 }),
  salt: bufferSchema({ min: 8, max: 1024 }),
  id: z.literal("argon2id"),
  version: z
    .union(argon2Versions.map((version) => z.literal(version)))
    .default(defaultVersionForBackwardsCompatibility),
  params: z
    .object({
      m: z.number().max(MAX_UINT32),
      t: z.number().int().min(1).max(MAX_UINT32),
      p: z.number().int().min(1).max(MAX_UINT24),
    })
    .refine(
      (params) => isValidMinMemory({ memory: params.m, parallelism: params.p }),
      {
        message: "memory parameter must be at least 8 * parallelism",
      },
    ),
});

function argon2DeserializePHC(phcString: string): PHCOutputContract {
  return toContractOutput(
    argon2PHCDeserializeSchema.parse(phcFormatter.deserialize(phcString)),
  );
}

function argon2SerializePHC(input: PHCInputContract): string {
  return phcFormatter.serialize(fromContractInput(input));
}

type PHCSharedContract = {
  hash: Buffer;
  salt: Buffer;
  id: "argon2id";
  params: {
    memory: number;
    passes: number;
    parallelism: number;
  };
};

type PHCInputContract = PHCSharedContract & {
  version: Extract<Argon2Version, 19>;
};

type PHCOutputContract = PHCSharedContract & {
  version: Argon2Version;
};

function fromContractInput(
  input: PHCInputContract,
): z.infer<typeof argon2PHCDeserializeSchema> {
  return {
    ...input,
    params: {
      m: input.params.memory,
      t: input.params.passes,
      p: input.params.parallelism,
    },
  };
}

function toContractOutput(
  input: z.infer<typeof argon2PHCDeserializeSchema>,
): PHCOutputContract {
  return {
    ...input,
    params: {
      memory: input.params.m,
      passes: input.params.t,
      parallelism: input.params.p,
    },
  };
}

export { argon2DeserializePHC, argon2SerializePHC, isArgon2Version };
