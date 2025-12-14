import formatter, { type PhcInput } from "@phc/format";

type PhcParams = Record<string, string | number>;

export type PhcNode<Params extends PhcParams = PhcParams> = {
  id: string;
  salt: Buffer;
  hash: Buffer;
  version?: number | undefined;
  params: Params;
};

type PhcFormatter = {
  serialize: <Params extends PhcParams = PhcParams>(
    salt: Buffer<ArrayBufferLike>,
    hash: Buffer<ArrayBufferLike>,
    options: { id: string; params?: Params; version?: number },
  ) => string;
  deserialize: (phcString: string) => PhcNode;
};

class InvalidPhcStringError extends Error {
  constructor(message: string) {
    super(`Invalid PHC string - Field: ${message}`);
    this.name = "InvalidPhcStringError";
  }
}

export function createPhcFormatter(): PhcFormatter {
  return {
    serialize: (salt, hash, options) => {
      const phcInput: PhcInput = {
        id: options.id,
        salt,
        hash,
      };
      if (options.params) {
        phcInput.params = options.params;
      }
      if (options.version) {
        phcInput.version = options.version;
      }
      return formatter.serialize(phcInput);
    },
    deserialize: (phcString: string) => {
      const phcOutput = formatter.deserialize(phcString);

      if (!phcOutput.salt) {
        throw new InvalidPhcStringError("salt");
      }
      if (!phcOutput.hash) {
        throw new InvalidPhcStringError("hash");
      }
      if (!phcOutput.params) {
        throw new InvalidPhcStringError("params");
      }

      return {
        id: phcOutput.id,
        salt: phcOutput.salt,
        hash: phcOutput.hash,
        version: phcOutput.version,
        params: phcOutput.params,
      };
    },
  };
}
