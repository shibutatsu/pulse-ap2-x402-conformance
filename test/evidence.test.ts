import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { type Address, type Hex, keccak256, numberToHex, padHex, stringToHex } from "viem";
import {
  type PublicEvmReader,
  verifyIndependentReproductionRecord,
  verifyIndependentSecurityReviewRecord,
  verifyPublicEvmSettlement,
} from "../src/evidence.js";
import type { ConformanceBundle, ConformanceCase } from "../src/types.js";

const fixtureUrl = new URL("../fixtures/v0.2/cases.json", import.meta.url);
const TRANSFER_TOPIC = keccak256(stringToHex("Transfer(address,address,uint256)"));
const AUTHORIZATION_USED_TOPIC = keccak256(stringToHex("AuthorizationUsed(address,bytes32)"));

async function fixture(): Promise<{ raw: string; bundle: ConformanceBundle }> {
  const raw = await readFile(fileURLToPath(fixtureUrl), "utf8");
  return { raw, bundle: JSON.parse(raw) as ConformanceBundle };
}

function reproductionRecord(raw: string, bundle: ConformanceBundle): Record<string, unknown> {
  return {
    recordVersion: "pulse-independent-reproduction/0.1",
    performedAt: "2026-08-13T10:00:00Z",
    implementation: {
      repositoryUrl: "https://github.com/example/independent-verifier",
      commit: "1".repeat(40),
      language: "Rust",
      runtime: "rustc 1.89.0",
      command: "cargo test --release",
      organization: "Example Independent Lab",
      independentOfPrimeBeat: true,
    },
    fixture: {
      repositoryCommit: "2".repeat(40),
      path: "fixtures/v0.2/cases.json",
      sha256: createHash("sha256").update(raw, "utf8").digest("hex"),
      caseCount: 80,
    },
    environment: {
      operatingSystem: "Linux",
      architecture: "x86_64",
      dependencies: ["serde_json 1.0"],
    },
    results: bundle.cases.map((item) => {
      const conformanceCase = item as ConformanceCase;
      return {
        id: conformanceCase.id,
        decision: conformanceCase.expected.consistent ? "accept" : "reject",
        failureCodes: conformanceCase.expected.failureCodes,
      };
    }),
    publishedUrl: "https://github.com/example/independent-verifier/releases/tag/v0.1",
  };
}

function cloneReproductionRecord(
  raw: string,
  bundle: ConformanceBundle,
): {
  fixture: { sha256: string };
  results: Array<{ id: string; decision: string; failureCodes: string[] }>;
} & Record<string, unknown> {
  return structuredClone(reproductionRecord(raw, bundle)) as ReturnType<
    typeof cloneReproductionRecord
  >;
}

const validReviewRecord = {
  recordVersion: "pulse-independent-security-review/0.1",
  reviewedCommit: "3".repeat(40),
  reviewedAt: "2026-08-13T11:00:00Z",
  reviewer: {
    name: "A. Reviewer",
    organization: "Example Security Lab",
    profileUrl: "https://example.com/reviewer",
    independentOfPrimeBeat: true,
  },
  scope: ["AP2 mandate binding", "EIP-3009 signature and replay resistance"],
  method: ["Manual code review", "Adversarial fixture review"],
  findings: [
    {
      id: "SEC-1",
      severity: "low",
      title: "Example resolved finding",
      status: "resolved",
      publicSummary: "The reviewed boundary is now explicit.",
      remediation: "Documentation and a regression test were added.",
    },
  ],
  remediationSummary: "All reported findings were addressed in the reviewed commit.",
  residualRisk: "The review does not establish production deployment security.",
  publishedUrl: "https://example.com/reviews/pulse-ap2-x402",
};

describe("independent evidence records", () => {
  it("matches an 80-case reproduction record to the exact fixture bytes", async () => {
    const { raw, bundle } = await fixture();
    expect(verifyIndependentReproductionRecord(raw, reproductionRecord(raw, bundle))).toEqual({
      valid: true,
      automatedChecksPassed: true,
      errors: [],
    });
  });

  it("rejects a fixture hash mismatch and a changed independent decision", async () => {
    const { raw, bundle } = await fixture();
    const record = cloneReproductionRecord(raw, bundle);
    record.fixture.sha256 = "0".repeat(64);
    const firstResult = record.results[0];
    if (firstResult === undefined) throw new Error("Expected a reproduction result");
    record.results[0] = { ...firstResult, decision: "reject" };

    const report = verifyIndependentReproductionRecord(raw, record);
    expect(report.automatedChecksPassed).toBe(false);
    expect(report.errors).toEqual(
      expect.arrayContaining([
        "fixture.sha256: Does not match the supplied fixture bytes",
        expect.stringContaining("Decision does not match"),
      ]),
    );
  });

  it("rejects a reproduction record that names a different fixture version", async () => {
    const { raw, bundle } = await fixture();
    const record = reproductionRecord(raw, bundle) as {
      fixture: { path: string };
    } & Record<string, unknown>;
    record.fixture.path = "fixtures/v0.1/cases.json";

    expect(verifyIndependentReproductionRecord(raw, record)).toMatchObject({
      automatedChecksPassed: false,
      errors: [
        "fixture.path: Expected fixtures/v0.2/cases.json for ap2-x402-conformance-bundle/0.2",
      ],
    });
  });

  it("rejects malformed records, malformed bundles, and invalid bundle envelopes", async () => {
    const { raw, bundle } = await fixture();
    expect(verifyIndependentReproductionRecord(raw, {})).toMatchObject({ valid: false });
    expect(
      verifyIndependentReproductionRecord("not json", reproductionRecord(raw, bundle)),
    ).toMatchObject({ errors: ["bundle: Expected valid JSON"] });
    expect(
      verifyIndependentReproductionRecord("{}", reproductionRecord("{}", bundle)),
    ).toMatchObject({ valid: false });

    const changedBundle = structuredClone(bundle);
    changedBundle.cases[0] = {};
    changedBundle.cases[1] = {
      ...(changedBundle.cases[1] as ConformanceCase),
      id: (changedBundle.cases[2] as ConformanceCase).id,
    };
    const changedRaw = JSON.stringify(changedBundle);
    const report = verifyIndependentReproductionRecord(
      changedRaw,
      reproductionRecord(changedRaw, bundle),
    );
    expect(report.errors).toEqual(
      expect.arrayContaining([
        "bundle.cases: A case is missing a valid id or expected result",
        expect.stringContaining("Duplicate case id"),
      ]),
    );
  });

  it("rejects duplicate, unknown, missing, and wrong-code reproduction results", async () => {
    const { raw, bundle } = await fixture();
    const record = cloneReproductionRecord(raw, bundle);
    const first = record.results[0];
    const second = record.results[1];
    const third = record.results[2];
    const fourth = record.results[3];
    if (
      first === undefined ||
      second === undefined ||
      third === undefined ||
      fourth === undefined
    ) {
      throw new Error("Expected reproduction results");
    }
    record.results[1] = { ...second, id: first.id };
    record.results[2] = { ...third, id: "unknown-case", decision: "reject" };
    record.results[3] = { ...fourth, failureCodes: ["INPUT_SCHEMA_INVALID"] };

    const report = verifyIndependentReproductionRecord(raw, record);
    expect(report.errors).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Duplicate case id"),
        expect.stringContaining("Unknown case id"),
        expect.stringContaining("Failure codes do not match"),
        expect.stringContaining("Missing case id"),
      ]),
    );
  });

  it("accepts a complete review record with no unresolved blocking finding", () => {
    expect(verifyIndependentSecurityReviewRecord(validReviewRecord)).toEqual({
      valid: true,
      automatedChecksPassed: true,
      errors: [],
    });
  });

  it("keeps the release gate closed for an unresolved high-severity finding", () => {
    const changed = structuredClone(validReviewRecord);
    const existingFinding = changed.findings[0];
    if (existingFinding === undefined) throw new Error("Expected a review finding");
    changed.findings[0] = {
      ...existingFinding,
      severity: "high",
      status: "open",
    };
    const report = verifyIndependentSecurityReviewRecord(changed);
    expect(report.valid).toBe(true);
    expect(report.automatedChecksPassed).toBe(false);
    expect(report.errors[0]).toContain("high finding is not resolved");
  });

  it("rejects an incomplete security review record", () => {
    expect(verifyIndependentSecurityReviewRecord({})).toMatchObject({
      valid: false,
      automatedChecksPassed: false,
    });
  });
});

describe("public EVM settlement evidence", () => {
  it("matches the receipt chain, Transfer event, and AuthorizationUsed event", async () => {
    const { bundle } = await fixture();
    const conformanceCase = bundle.cases.find(
      (item) => (item as ConformanceCase).id === "valid-base-sepolia-01",
    ) as ConformanceCase;
    const authorization = conformanceCase.x402.payload.payload.authorization;
    const transactionHash = conformanceCase.x402.settlement.transaction as Hex;
    const blockHash = `0x${"4".repeat(64)}` as Hex;
    const blockNumber = 100n;
    const reader: PublicEvmReader = {
      async getChainId() {
        return 84532;
      },
      async getTransaction() {
        return { hash: transactionHash, blockNumber };
      },
      async getTransactionReceipt() {
        return {
          transactionHash,
          blockNumber,
          blockHash,
          status: "success",
          logs: [
            {
              address: conformanceCase.x402.requirements.asset as Address,
              topics: [
                TRANSFER_TOPIC,
                padHex(authorization.from as Hex, { size: 32 }),
                padHex(authorization.to as Hex, { size: 32 }),
              ],
              data: numberToHex(BigInt(authorization.value), { size: 32 }),
              logIndex: 7,
            },
            {
              address: conformanceCase.x402.requirements.asset as Address,
              topics: [
                AUTHORIZATION_USED_TOPIC,
                padHex(authorization.from as Hex, { size: 32 }),
                authorization.nonce as Hex,
              ],
              data: "0x",
              logIndex: 8,
            },
          ],
        };
      },
      async getBlockNumber() {
        return 104n;
      },
    };

    await expect(verifyPublicEvmSettlement(conformanceCase, reader, 5n)).resolves.toMatchObject({
      evidenceVersion: "pulse-public-evm-settlement/0.1",
      caseId: "valid-base-sepolia-01",
      chainId: 84532,
      transactionHash,
      confirmations: "5",
      receiptStatus: "success",
      transfer: {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value,
        logIndex: 7,
      },
      authorizationUsed: {
        authorizer: authorization.from,
        nonce: authorization.nonce,
        logIndex: 8,
      },
    });
  });

  it("rejects a receipt without the fixture-bound authorization event", async () => {
    const { bundle } = await fixture();
    const conformanceCase = bundle.cases[0] as ConformanceCase;
    const transactionHash = conformanceCase.x402.settlement.transaction as Hex;
    const reader: PublicEvmReader = {
      async getChainId() {
        return 84532;
      },
      async getTransaction() {
        return { hash: transactionHash, blockNumber: 1n };
      },
      async getTransactionReceipt() {
        return {
          transactionHash,
          blockNumber: 1n,
          blockHash: `0x${"5".repeat(64)}` as Hex,
          status: "success",
          logs: [],
        };
      },
      async getBlockNumber() {
        return 1n;
      },
    };

    await expect(verifyPublicEvmSettlement(conformanceCase, reader)).rejects.toThrow(
      "No matching ERC-20 Transfer event",
    );
  });

  it.each([
    ["zero confirmations", 0n, undefined, "Minimum confirmations must be at least one"],
    ["malformed case", 1n, null, "selected conformance case is not well formed"],
  ] as const)(
    "rejects %s before making a public read",
    async (_label, confirmations, input, message) => {
      const reader = {} as PublicEvmReader;
      await expect(verifyPublicEvmSettlement(input, reader, confirmations)).rejects.toThrow(
        message,
      );
    },
  );

  it("rejects an offline-invalid case before making a public read", async () => {
    const { bundle } = await fixture();
    const invalidCase = bundle.cases.find(
      (item) => !(item as ConformanceCase).expected.consistent,
    ) as ConformanceCase;
    await expect(verifyPublicEvmSettlement(invalidCase, {} as PublicEvmReader)).rejects.toThrow(
      "requires an accepted offline case",
    );
  });

  it.each([
    ["RPC failure", { rpcFailure: true }, "Unable to read the public transaction"],
    ["wrong chain", { chainId: 1 }, "RPC chain does not match"],
    ["wrong transaction", { transactionHash: `0x${"9".repeat(64)}` }, "identifier does not match"],
    ["missing transaction block", { transactionBlock: null }, "block numbers do not match"],
    ["reverted receipt", { status: "reverted" }, "receipt is not successful"],
    ["future receipt block", { latestBlock: 99n }, "invalid latest block"],
    ["too few confirmations", { latestBlock: 100n, minConfirmations: 2n }, "enough confirmations"],
    ["missing authorization event", { omitAuthorization: true }, "AuthorizationUsed event"],
  ] as const)("rejects a public receipt with %s", async (_label, change, message) => {
    const { bundle } = await fixture();
    const conformanceCase = bundle.cases[0] as ConformanceCase;
    const authorization = conformanceCase.x402.payload.payload.authorization;
    const expectedHash = conformanceCase.x402.settlement.transaction as Hex;
    const returnedHash = (
      "transactionHash" in change ? change.transactionHash : expectedHash
    ) as Hex;
    const transactionBlock = ("transactionBlock" in change ? change.transactionBlock : 100n) as
      | bigint
      | null;
    const latestBlock = ("latestBlock" in change ? change.latestBlock : 100n) as bigint;
    const reader: PublicEvmReader = {
      async getChainId() {
        if ("rpcFailure" in change) throw new Error("secret endpoint must not leak");
        return "chainId" in change ? change.chainId : 84532;
      },
      async getTransaction() {
        return { hash: returnedHash, blockNumber: transactionBlock };
      },
      async getTransactionReceipt() {
        return {
          transactionHash: returnedHash,
          blockNumber: 100n,
          blockHash: `0x${"6".repeat(64)}` as Hex,
          status: ("status" in change ? change.status : "success") as "success" | "reverted",
          logs: [
            {
              address: conformanceCase.x402.requirements.asset as Address,
              topics: [
                TRANSFER_TOPIC,
                padHex(authorization.from as Hex, { size: 32 }),
                padHex(authorization.to as Hex, { size: 32 }),
              ],
              data: numberToHex(BigInt(authorization.value), { size: 32 }),
              logIndex: 1,
            },
            ...("omitAuthorization" in change
              ? []
              : [
                  {
                    address: conformanceCase.x402.requirements.asset as Address,
                    topics: [
                      AUTHORIZATION_USED_TOPIC,
                      padHex(authorization.from as Hex, { size: 32 }),
                      authorization.nonce as Hex,
                    ],
                    data: "0x" as Hex,
                    logIndex: 2,
                  },
                ]),
          ],
        };
      },
      async getBlockNumber() {
        return latestBlock;
      },
    };
    const minConfirmations = "minConfirmations" in change ? change.minConfirmations : 1n;
    await expect(
      verifyPublicEvmSettlement(conformanceCase, reader, minConfirmations),
    ).rejects.toThrow(message);
  });

  it("ignores unrelated and malformed token logs before finding the bound events", async () => {
    const { bundle } = await fixture();
    const conformanceCase = bundle.cases[0] as ConformanceCase;
    const authorization = conformanceCase.x402.payload.payload.authorization;
    const transactionHash = conformanceCase.x402.settlement.transaction as Hex;
    const asset = conformanceCase.x402.requirements.asset as Address;
    const reader: PublicEvmReader = {
      async getChainId() {
        return 84532;
      },
      async getTransaction() {
        return { hash: transactionHash, blockNumber: 1n };
      },
      async getTransactionReceipt() {
        return {
          transactionHash,
          blockNumber: 1n,
          blockHash: `0x${"7".repeat(64)}` as Hex,
          status: "success",
          logs: [
            { address: asset, topics: ["0x"], data: "0x", logIndex: 0 },
            { address: asset, topics: [TRANSFER_TOPIC], data: "0x", logIndex: 1 },
            {
              address: asset,
              topics: [
                TRANSFER_TOPIC,
                padHex(authorization.from as Hex, { size: 32 }),
                padHex(authorization.to as Hex, { size: 32 }),
              ],
              data: numberToHex(BigInt(authorization.value), { size: 32 }),
              logIndex: 2,
            },
            {
              address: asset,
              topics: [AUTHORIZATION_USED_TOPIC, "0x"],
              data: "0x",
              logIndex: 3,
            },
            {
              address: asset,
              topics: [
                AUTHORIZATION_USED_TOPIC,
                padHex(authorization.from as Hex, { size: 32 }),
                authorization.nonce as Hex,
              ],
              data: "0x",
              logIndex: 4,
            },
          ],
        };
      },
      async getBlockNumber() {
        return 1n;
      },
    };

    await expect(verifyPublicEvmSettlement(conformanceCase, reader)).resolves.toMatchObject({
      transfer: { logIndex: 2 },
      authorizationUsed: { logIndex: 4 },
    });
  });
});
