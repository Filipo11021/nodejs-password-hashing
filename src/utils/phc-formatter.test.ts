import { describe, it } from "node:test";
import { createPhcFormatter } from "./phc-formatter.ts";
import assert from "node:assert/strict";
import z from "zod";

void describe("phc formatter", () => {
  void it("should serialize and deserialize a phc string with correct schema", async () => {
    const formatter = createPhcFormatter(
      z.object({
        hash: z.instanceof(Buffer),
        salt: z.instanceof(Buffer),
        id: z.string(),
        params: z.object({
          memory: z.number(),
          passes: z.number(),
          parallelism: z.number(),
        }),
        version: z.number(),
      }),
    );

    const salt = Buffer.from("salt");
    const key = Buffer.from("key");
    const version = 1;
    const params = {
      memory: 1024,
      passes: 1,
      parallelism: 1,
    };
    const hash = await formatter.serialize({
      salt,
      hash: key,
      id: "test",
      version,
      params: params,
    });

    const expectedHash = `$test$v=1$memory=1024,passes=1,parallelism=1$${salt.toString("base64url")}$${key.toString("base64url")}`;
    assert.equal(hash, expectedHash);

    const deserializedHash = await formatter.deserialize(expectedHash);

    assert.deepEqual(deserializedHash, {
      id: "test",
      version,
      params,
      salt,
      hash: key,
    });
  });

  void it("should throw an error if the params are not valid", async () => {
    const formatter = createPhcFormatter(
      z.object({
        hash: z.instanceof(Buffer),
        salt: z.instanceof(Buffer),
        id: z.string(),
        params: z.object({
          memory: z.number(),
          passes: z.number(),
          parallelism: z.number(),
        }),
      }),
    );

    const salt = Buffer.from("salt");
    const key = Buffer.from("key");

    await assert.rejects(async () => {
      await formatter.serialize({
        salt,
        hash: key,
        id: "test",
        // @ts-expect-error - Ensure that throws an error
        params: {
          memory: 1024,
        },
      });
    });
  });

  void it("should throw an error if the params are not lowercase", async () => {
    const formatter = createPhcFormatter(
      z.object({
        hash: z.instanceof(Buffer),
        salt: z.instanceof(Buffer),
        id: z.string(),
        params: z.object({
          TEST: z.number(),
        }),
      }),
    );

    const salt = Buffer.from("salt");
    const key = Buffer.from("key");

    await assert.rejects(async () => {
      await formatter.serialize({
        salt,
        hash: key,
        id: "test",
        params: {
          TEST: 1024,
        },
      });
    });
  });
});
