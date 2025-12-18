import formatter from "@phc/format";
import type { StandardSchemaV1 } from "@standard-schema/spec";

export type PhcNode = {
  id: string;
  salt: Buffer;
  hash: Buffer;
  version?: number;
  params: Record<string, string | number>;
};

type PhcFormatter<T extends PhcNode> = {
  serialize: (phcNode: T) => Promise<string>;
  deserialize: (phcString: string) => Promise<T>;
};

class InvalidPhcStringError extends Error {
  constructor(message: string) {
    super(`Invalid PHC string - ${message}`);
    this.name = "InvalidPhcStringError";
  }
}

export function createPhcFormatter<T extends PhcNode>(
  schema: StandardSchemaV1<T>,
): PhcFormatter<T> {
  return {
    serialize: async (phcNode) => {
      const result = await schema["~standard"].validate(phcNode);

      if (result.issues) {
        throw new InvalidPhcStringError(JSON.stringify(result.issues, null, 2));
      }

      return formatter.serialize(result.value);
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
