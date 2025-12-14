import formatter, { type PhcInput } from "@phc/format";
import type { StandardSchemaV1 } from "@standard-schema/spec";

type PhcParams = Record<string, string | number>;

export type PhcNode<Id extends string, Params extends PhcParams = PhcParams> = {
  id: Id;
  salt: Buffer;
  hash: Buffer;
  version?: number | undefined;
  params: Params;
};

type PhcFormatter<Id extends string, Params extends PhcParams = PhcParams> = {
  serialize: (
    salt: Buffer<ArrayBufferLike>,
    hash: Buffer<ArrayBufferLike>,
    options: { id: Id; params: Params; version?: number },
  ) => Promise<string>;
  deserialize: (phcString: string) => Promise<PhcNode<Id, Params>>;
};

class InvalidPhcStringError extends Error {
  constructor(message: string) {
    super(`Invalid PHC string - ${message}`);
    this.name = "InvalidPhcStringError";
  }
}

export function createPhcFormatter<Id extends string, Params extends PhcParams>(
  schema: StandardSchemaV1<PhcNode<Id, Params>>,
): PhcFormatter<Id, Params> {
  return {
    serialize: async (salt, hash, options) => {
      const phcInput: PhcInput = {
        id: options.id,
        salt,
        hash,
        params: options.params,
      };

      if (options.version) {
        phcInput.version = options.version;
      }

      const result = await schema["~standard"].validate(phcInput);

      if (result.issues) {
        throw new InvalidPhcStringError(JSON.stringify(result.issues, null, 2));
      }

      return formatter.serialize(result.value as PhcInput);
    },
    deserialize: async (phcString: string) => {
      const phcOutput = formatter.deserialize(phcString);

      const result = await schema["~standard"].validate(phcOutput);

      if (result.issues) {
        throw new InvalidPhcStringError(JSON.stringify(result.issues, null, 2));
      }

      return result.value;
    },
  };
}
