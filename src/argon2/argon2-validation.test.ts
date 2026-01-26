import { createArgon2Hashing } from "./argon2.ts";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

void describe("Argon2 Parameter Validation - RFC 9106 Compliance", () => {
  void describe("parallelism parameter", () => {
    void it("should accept parallelism = 1 (minimum per RFC 9106)", () => {
      assert.doesNotThrow(() => {
        createArgon2Hashing({
          parallelism: 1,
          memory: 8,
        });
      }, "parallelism = 1 should be valid per RFC 9106");
    });

    void it("should reject parallelism = 0 (below minimum)", () => {
      assert.throws(
        () => {
          createArgon2Hashing({
            parallelism: 0,
            memory: 8,
          });
        },
        {
          name: "ZodError",
        },
        "parallelism must be at least 1",
      );
    });
  });

  void describe("tagLength parameter", () => {
    void it("should accept tagLength = 4 (minimum per RFC 9106)", () => {
      assert.doesNotThrow(() => {
        createArgon2Hashing({
          tagLength: 4,
        });
      }, "tagLength = 4 should be valid per RFC 9106");
    });

    void it("should reject tagLength = 3 (below minimum)", () => {
      assert.throws(
        () => {
          createArgon2Hashing({
            tagLength: 3,
          });
        },
        {
          name: "ZodError",
        },
        "tagLength must be at least 4",
      );
    });
  });

  void describe("memory parameter relative to parallelism", () => {
    void it("should accept memory = 8 * parallelism (minimum per RFC 9106)", () => {
      assert.doesNotThrow(() => {
        createArgon2Hashing({
          parallelism: 2,
          memory: 16, // Exactly 8 * 2
        });
      }, "memory = 8 * parallelism should be valid per RFC 9106");
    });

    void it("should reject memory < 8 * parallelism (below minimum)", () => {
      assert.throws(
        () => {
          createArgon2Hashing({
            parallelism: 2,
            memory: 15, // Less than 8 * 2
          });
        },
        {
          name: "ZodError",
        },
        "memory must be at least 8 * parallelism",
      );
    });
  });

  void describe("passes parameter", () => {
    void it("should accept passes = 1 (minimum per RFC 9106)", () => {
      assert.doesNotThrow(() => {
        createArgon2Hashing({
          passes: 1,
        });
      }, "passes = 1 should be valid per RFC 9106");
    });

    void it("should reject passes = 0 (below minimum)", () => {
      assert.throws(
        () => {
          createArgon2Hashing({
            passes: 0,
          });
        },
        {
          name: "ZodError",
        },
        "passes must be at least 1",
      );
    });
  });

  void describe("edge cases - absolute minimums", () => {
    void it("should accept absolute minimum configuration (parallelism=1, memory=8)", () => {
      assert.doesNotThrow(() => {
        createArgon2Hashing({
          parallelism: 1,
          memory: 8, // Exactly 8 * 1
          passes: 1,
          tagLength: 4,
        });
      }, "absolute minimum configuration should be valid per RFC 9106");
    });

    void it("should reject memory = 7 when parallelism = 1", () => {
      assert.throws(
        () => {
          createArgon2Hashing({
            parallelism: 1,
            memory: 7,
          });
        },
        {
          name: "ZodError",
        },
        "memory = 7 should be rejected when parallelism = 1",
      );
    });
  });

  void describe("edge cases - invalid values", () => {
    void it("should reject negative values", () => {
      assert.throws(
        () => {
          createArgon2Hashing({
            passes: -1,
          });
        },
        {
          name: "ZodError",
        },
        "passes must be positive",
      );
    });
  });
});
