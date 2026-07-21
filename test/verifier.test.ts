import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { type Address, type Hex, keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalSha256Base64Url, conformanceInputHash } from "../src/canonical.js";
import type { ConformanceBundle, ConformanceCase } from "../src/types.js";
import { verifyConformanceBundle, verifyConformanceCase } from "../src/verifier.js";

const fixtureUrl = new URL("../fixtures/v0.1/cases.json", import.meta.url);
const fixturePayer = privateKeyToAccount(
  keccak256(stringToHex("pulse-ap2-x402-conformance/public-fixture-payer/v1")),
);
const authorizationTypes = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

async function readBundle(): Promise<ConformanceBundle> {
  return JSON.parse(await readFile(fileURLToPath(fixtureUrl), "utf8")) as ConformanceBundle;
}

async function resignAuthorization(conformanceCase: ConformanceCase): Promise<void> {
  const requirements = conformanceCase.x402.requirements;
  const authorization = conformanceCase.x402.payload.payload.authorization;
  conformanceCase.x402.payload.payload.signature = await fixturePayer.signTypedData({
    domain: {
      name: requirements.extra.name,
      version: requirements.extra.version,
      chainId: Number(requirements.network.slice("eip155:".length)),
      verifyingContract: requirements.asset as Address,
    },
    types: authorizationTypes,
    primaryType: "TransferWithAuthorization",
    message: {
      from: authorization.from as Address,
      to: authorization.to as Address,
      value: BigInt(authorization.value),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
      nonce: authorization.nonce as Hex,
    },
  });
  conformanceCase.inputHash = conformanceInputHash(conformanceCase);
}

describe("the committed conformance corpus", () => {
  it("contains 20 accepted and 60 fail-closed cases whose expectations all match", async () => {
    const bundle = await readBundle();
    expect(bundle.cases).toHaveLength(80);
    expect(
      bundle.cases.filter(
        (item) => (item as { expected: { consistent: boolean } }).expected.consistent,
      ),
    ).toHaveLength(20);

    const report = await verifyConformanceBundle(bundle);
    expect(report).toMatchObject({
      allExpectationsMatched: true,
      total: 80,
      passedExpectations: 80,
      failedExpectations: 0,
    });
    expect(canonicalSha256Base64Url(report)).toBe("Ez8RxrMYy6ySlfosptWynBPpASuxCiebJzjb0I9yn7Q");
  });

  it("recovers the payer for every accepted ECDSA fixture", async () => {
    const bundle = await readBundle();
    const accepted = bundle.cases.filter(
      (item) => (item as { expected: { consistent: boolean } }).expected.consistent,
    );
    for (const item of accepted) {
      const report = await verifyConformanceCase(item);
      expect(report.consistent).toBe(true);
      expect(report.computed.recoveredSigner?.toLowerCase()).toBe(
        (
          item as { x402: { payload: { payload: { authorization: { from: string } } } } }
        ).x402.payload.payload.authorization.from.toLowerCase(),
      );
    }
  });

  it("returns only schema paths and messages for malformed input", async () => {
    const bundle = await readBundle();
    const malformed = structuredClone(bundle.cases[0]) as Record<string, unknown>;
    const secretMarker = "do-not-leak-this-input-value";
    malformed.ap2 = secretMarker;

    const report = await verifyConformanceCase(malformed);
    expect(report.consistent).toBe(false);
    expect(report.failures.map((failure) => failure.code)).toEqual(["INPUT_SCHEMA_INVALID"]);
    expect(JSON.stringify(report)).not.toContain(secretMarker);
  });

  it("handles root-level malformed input without inventing an identifier", async () => {
    const report = await verifyConformanceCase(null);
    expect(report).toMatchObject({
      caseId: null,
      consistent: false,
      failures: [{ code: "INPUT_SCHEMA_INVALID", path: "<schema>" }],
    });
  });

  it("fails closed on a constraint outside the pinned AP2 schema", async () => {
    const bundle = await readBundle();
    const valid = structuredClone(bundle.cases[0]) as {
      ap2: { openMandate: { constraints: unknown[] } };
    };
    valid.ap2.openMandate.constraints.unshift({ type: "different.constraint" });
    const report = await verifyConformanceCase(valid);
    expect(report.consistent).toBe(false);
    expect(report.failures.map((failure) => failure.code)).toEqual(["INPUT_SCHEMA_INVALID"]);
  });

  it.each([
    [
      "closed mandate",
      (changed: ConformanceCase) =>
        Object.assign(changed.ap2.closedMandate, { unknownField: true }),
    ],
    [
      "open mandate",
      (changed: ConformanceCase) => Object.assign(changed.ap2.openMandate, { unknownField: true }),
    ],
    [
      "known constraint",
      (changed: ConformanceCase) =>
        Object.assign(changed.ap2.openMandate.constraints[0] as object, { unknownField: true }),
    ],
    [
      "payment receipt",
      (changed: ConformanceCase) =>
        Object.assign(changed.ap2.paymentReceipt, { unknownField: true }),
    ],
  ] as const)("rejects an unknown field in a signed AP2 %s", async (_label, mutate) => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    mutate(changed);

    const report = await verifyConformanceCase(changed);
    expect(report.consistent).toBe(false);
    expect(report.failures.map((failure) => failure.code)).toEqual(["INPUT_SCHEMA_INVALID"]);
  });

  it("returns a schema failure instead of throwing for a malformed CAIP-2 network", async () => {
    const bundle = await readBundle();
    const malformed = structuredClone(bundle.cases[0]) as ConformanceCase;
    malformed.x402.requirements.network = "eip155:x";

    await expect(verifyConformanceCase(malformed)).resolves.toMatchObject({
      consistent: false,
      failures: [{ code: "INPUT_SCHEMA_INVALID" }],
    });
  });

  it("returns a schema failure instead of throwing for a non-canonical AP2 reference", async () => {
    const bundle = await readBundle();
    const malformed = structuredClone(bundle.cases[0]) as ConformanceCase;
    malformed.ap2.verification.cryptographicEvidence.mandateChain = "no-separator";
    malformed.ap2.verification.closedMandateReference = `${"A".repeat(42)}B`;

    await expect(verifyConformanceCase(malformed)).resolves.toMatchObject({
      consistent: false,
      failures: [{ code: "INPUT_SCHEMA_INVALID" }],
    });
  });

  it.each([
    ["record extension", "extensions"],
    ["strict object", "settlement-extra"],
  ] as const)(
    "rejects a raw JSON __proto__ key inside a %s before schema conversion",
    async (_label, target) => {
      const bundle = await readBundle();
      const rawCase = JSON.parse(JSON.stringify(bundle.cases[0])) as ConformanceCase;
      const unsafeObject = JSON.parse(
        '{"__proto__":{"changesPaymentSemantics":true}}',
      ) as NonNullable<ConformanceCase["x402"]["payload"]["extensions"]>;
      if (target === "extensions") {
        rawCase.x402.payload.extensions = unsafeObject;
      } else {
        Object.defineProperty(rawCase.x402.settlement, "__proto__", {
          enumerable: true,
          value: { changesPaymentSemantics: true },
        });
      }

      const report = await verifyConformanceCase(rawCase);
      expect(report.consistent).toBe(false);
      expect(report.failures).toHaveLength(1);
      expect(report.failures[0]).toMatchObject({ code: "INPUT_SCHEMA_INVALID" });
      expect(report.failures[0]?.path).toContain("__proto__");
    },
  );

  it("rejects a raw JSON __proto__ key anywhere in a bundle before schema conversion", async () => {
    const bundle = JSON.parse(JSON.stringify(await readBundle())) as ConformanceBundle;
    Object.defineProperty(bundle.sourcePins, "__proto__", {
      enumerable: true,
      value: { changesSourceMeaning: true },
    });

    await expect(verifyConformanceBundle(bundle)).rejects.toThrow(
      "Bundle contains a prototype-affecting object key",
    );
  });

  it("reports a well-formed signature recovered from the wrong ECDSA address", async () => {
    const bundle = await readBundle();
    const valid = structuredClone(bundle.cases[0]) as {
      x402: { payload: { payload: { signature: string } } };
    };
    const alternate = bundle.cases.find(
      (item) => (item as { id?: string }).id === "invalid-eip3009-from-mismatch-01",
    ) as { x402: { payload: { payload: { signature: string } } } };
    valid.x402.payload.payload.signature = alternate.x402.payload.payload.signature;
    (valid as ConformanceCase).inputHash = conformanceInputHash(valid as ConformanceCase);

    const report = await verifyConformanceCase(valid);
    expect(report.failures.map((failure) => failure.code)).toEqual(["EIP3009_SIGNATURE_INVALID"]);
    expect(report.computed.recoveredSigner).toBeDefined();
  });

  it("maps a signed Open Mandate checkout-reference mismatch to the public failure code", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    const other = bundle.cases[1] as ConformanceCase;
    changed.ap2.verification.openCheckoutReference = other.ap2.verification.openCheckoutReference;
    changed.inputHash = conformanceInputHash(changed);

    expect(
      (await verifyConformanceCase(changed)).failures.map((failure) => failure.code),
    ).toContain("AP2_CHECKOUT_BINDING_UNVERIFIED");
  });

  it("maps a terminal audience mismatch to the public key-binding failure code", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    changed.ap2.verification.cryptographicEvidence.expectedAudience = "unexpected-verifier";
    changed.inputHash = conformanceInputHash(changed);

    expect(
      (await verifyConformanceCase(changed)).failures.map((failure) => failure.code),
    ).toContain("AP2_KEY_BINDING_UNVERIFIED");
  });

  it("maps a signed Receipt reference mismatch to the public receipt failure code", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    const other = bundle.cases[1] as ConformanceCase;
    changed.ap2.verification.cryptographicEvidence.paymentReceiptJwt =
      other.ap2.verification.cryptographicEvidence.paymentReceiptJwt;
    changed.inputHash = conformanceInputHash(changed);

    expect(
      (await verifyConformanceCase(changed)).failures.map((failure) => failure.code),
    ).toContain("AP2_RECEIPT_REFERENCE_MISMATCH");
  });

  it("rejects a changed verification input when its recorded input hash is stale", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    changed.x402.settlement.amount = String(BigInt(changed.x402.requirements.amount) + 1n);

    const report = await verifyConformanceCase(changed);
    expect(report.failures.map((failure) => failure.code)).toEqual([
      "INPUT_HASH_MISMATCH",
      "SETTLEMENT_AMOUNT_MISMATCH",
    ]);
    expect(report.computed.inputHash).not.toBe(changed.inputHash);
  });

  it("accepts exactly six seconds of remaining x402 authorization and rejects five", async () => {
    const bundle = await readBundle();
    const sixSeconds = structuredClone(bundle.cases[0]) as ConformanceCase;
    sixSeconds.x402.payload.payload.authorization.validBefore = String(
      sixSeconds.nowEpochSeconds + 6,
    );
    await resignAuthorization(sixSeconds);
    expect((await verifyConformanceCase(sixSeconds)).consistent).toBe(true);

    const fiveSeconds = structuredClone(sixSeconds);
    fiveSeconds.x402.payload.payload.authorization.validBefore = String(
      fiveSeconds.nowEpochSeconds + 5,
    );
    await resignAuthorization(fiveSeconds);
    expect(
      (await verifyConformanceCase(fiveSeconds)).failures.map((failure) => failure.code),
    ).toEqual(["EIP3009_VALID_BEFORE_EXPIRED"]);
  });

  it("rejects an EIP-3009 authorization that outlives either AP2 mandate", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    changed.ap2.openMandate.exp = changed.nowEpochSeconds + 10;
    changed.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
      changed.ap2.openMandate,
    );
    changed.x402.payload.payload.authorization.validBefore = String(changed.nowEpochSeconds + 11);
    await resignAuthorization(changed);

    expect((await verifyConformanceCase(changed)).failures.map((failure) => failure.code)).toEqual([
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
    ]);
  });

  it.each([
    [
      "a disallowed payee",
      "AP2_CONSTRAINT_VIOLATION",
      (changed: ConformanceCase) => {
        changed.ap2.openMandate.constraints.push({
          type: "payment.allowed_payees",
          allowed: [{ id: "different-merchant", name: "Different Merchant" }],
        });
      },
    ],
    [
      "an execution date outside the signed window",
      "AP2_CONSTRAINT_VIOLATION",
      (changed: ConformanceCase) => {
        changed.ap2.openMandate.constraints.push({
          type: "payment.execution_date",
          not_before: "2026-07-21T00:00:01.000Z",
        });
      },
    ],
    [
      "a history-dependent budget constraint",
      "AP2_UNSUPPORTED_CONSTRAINT",
      (changed: ConformanceCase) => {
        changed.ap2.openMandate.constraints.push({
          type: "payment.budget",
          max: 1_000,
          currency: "USD",
        });
      },
    ],
    [
      "no allowed-instrument constraint",
      "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED",
      (changed: ConformanceCase) => {
        changed.ap2.openMandate.constraints = changed.ap2.openMandate.constraints.filter(
          (constraint) => constraint.type !== "payment.allowed_payment_instruments",
        );
      },
    ],
    [
      "a conflicting Open Mandate preset",
      "AP2_OPEN_PRESET_MISMATCH",
      (changed: ConformanceCase) => {
        changed.ap2.openMandate.payee = { id: "different-merchant", name: "Different Merchant" };
      },
    ],
    [
      "an unevaluated PISP preset",
      "AP2_UNSUPPORTED_CONSTRAINT",
      (changed: ConformanceCase) => {
        changed.ap2.openMandate.pisp = {
          legal_name: "Example PISP Ltd",
          brand_name: "Example PISP",
          domain_name: "pisp.example",
        };
      },
    ],
  ] as const)("reports %s", async (_label, expectedCode, mutate) => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    mutate(changed);
    changed.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
      changed.ap2.openMandate,
    );
    changed.inputHash = conformanceInputHash(changed);

    const report = await verifyConformanceCase(changed);
    expect(report.failures.map((failure) => failure.code)).toContain(expectedCode);
  });

  it("reports a verification time that differs from the case evaluation time", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    changed.ap2.verification.verifiedAtEpochSeconds += 1;
    changed.inputHash = conformanceInputHash(changed);

    expect(
      (await verifyConformanceCase(changed)).failures.map((failure) => failure.code),
    ).toContain("AP2_VERIFICATION_CONTEXT_MISMATCH");
  });

  it("reports an AP2 mandate that is expired in the recorded verification context", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle.cases[0]) as ConformanceCase;
    changed.ap2.openMandate.exp = changed.nowEpochSeconds - 31;
    changed.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
      changed.ap2.openMandate,
    );
    changed.inputHash = conformanceInputHash(changed);

    expect(
      (await verifyConformanceCase(changed)).failures.map((failure) => failure.code),
    ).toContain("AP2_MANDATE_TIME_INVALID");
  });

  it("marks a malformed case with no expectation as a bundle expectation failure", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle);
    changed.cases[0] = null;

    const report = await verifyConformanceBundle(changed);
    expect(report.allExpectationsMatched).toBe(false);
    expect(report.failedExpectations).toBe(1);
    expect(report.cases[0]).toMatchObject({
      id: null,
      expectationMatched: false,
      expectedConsistent: null,
      expectedFailureCodes: [],
    });
  });

  it("rejects a bundle with an unpinned source revision", async () => {
    const bundle = await readBundle();
    const changed = structuredClone(bundle) as Record<string, unknown>;
    changed.sourcePins = {
      ...(changed.sourcePins as Record<string, unknown>),
      ap2Commit: "0000000000000000000000000000000000000000",
    };
    await expect(verifyConformanceBundle(changed)).rejects.toThrow();
  });
});
