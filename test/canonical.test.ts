import { createHash } from "node:crypto";
import {
  canonicalJson,
  canonicalSha256Base64Url,
  canonicalValuesEqual,
  conformanceInputHash,
  deriveEip3009Nonce,
} from "../src/canonical.js";

describe("canonical AP2 claims integrity helpers", () => {
  it("orders object properties while preserving array order", () => {
    expect(canonicalJson({ z: 1, a: [3, 2, 1] })).toBe('{"a":[3,2,1],"z":1}');
  });

  it("compares values by their canonical representation", () => {
    expect(canonicalValuesEqual({ b: 2, a: 1 }, { a: 1, b: 2 })).toBe(true);
    expect(canonicalValuesEqual({ a: 1 }, { a: 2 })).toBe(false);
  });

  it("returns a canonical base64url SHA-256 digest", () => {
    const expected = createHash("sha256").update('{"a":1}', "utf8").digest("base64url");
    expect(canonicalSha256Base64Url({ a: 1 })).toBe(expected);
  });

  it("rejects values that JSON canonicalization cannot represent", () => {
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
  });

  it("hashes only the pinned verification input and excludes fixture labels and expectations", () => {
    const input = {
      caseVersion: "test/1",
      sourcePins: { ap2: "a", x402: "b" },
      nowEpochSeconds: 1,
      ap2: { mandate: true },
      x402: { payment: true },
      id: "ignored",
      description: "ignored",
      expected: { consistent: true },
    };
    expect(conformanceInputHash(input)).toBe(
      canonicalSha256Base64Url({
        caseVersion: input.caseVersion,
        sourcePins: input.sourcePins,
        nowEpochSeconds: input.nowEpochSeconds,
        ap2: input.ap2,
        x402: input.x402,
      }),
    );
  });
});

describe("AP2 closed-mandate reference nonce binding", () => {
  it("decodes the final base64url reference into the exact 32-byte nonce", () => {
    const bytes = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
    expect(deriveEip3009Nonce(bytes.toString("base64url"))).toBe(`0x${bytes.toString("hex")}`);
  });

  it("rejects references that are not canonical base64url SHA-256 values", () => {
    expect(() => deriveEip3009Nonce("short")).toThrow(TypeError);
    const padded = `${Buffer.alloc(32, 7).toString("base64url")}=`;
    expect(() => deriveEip3009Nonce(padded)).toThrow(TypeError);
  });
});
