import { createHash } from "node:crypto";
import canonicalizeModule from "canonicalize";

const canonicalize = canonicalizeModule as unknown as (input: unknown) => string | undefined;

export function canonicalJson(value: unknown): string {
  const result = canonicalize(value);
  if (result === undefined) {
    throw new TypeError("The value cannot be represented as canonical JSON.");
  }
  return result;
}

export function canonicalSha256Base64Url(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("base64url");
}

export function conformanceInputHash(conformanceCase: {
  caseVersion: unknown;
  sourcePins: unknown;
  nowEpochSeconds: unknown;
  ap2: unknown;
  x402: unknown;
}): string {
  return canonicalSha256Base64Url({
    caseVersion: conformanceCase.caseVersion,
    sourcePins: conformanceCase.sourcePins,
    nowEpochSeconds: conformanceCase.nowEpochSeconds,
    ap2: conformanceCase.ap2,
    x402: conformanceCase.x402,
  });
}

export function deriveEip3009Nonce(closedMandateReference: string): `0x${string}` {
  const bytes = Buffer.from(closedMandateReference, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== closedMandateReference) {
    throw new TypeError(
      "The AP2 closed-mandate reference must be a canonical base64url SHA-256 value.",
    );
  }
  return `0x${bytes.toString("hex")}`;
}

export function canonicalValuesEqual(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}
