import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { type Address, type Hex, keccak256, numberToHex, padHex, stringToHex } from "viem";
import {
  type PublicEvmConsumerPolicy,
  type PublicEvmHeadTag,
  type PublicEvmSettlementEvidenceV02,
  type PublicEvmSettlementEvidenceV02Body,
  type PublicEvmSettlementVerificationOptions,
  type PublicEvmV02Reader,
  type PublicEvmVerifierProvenance,
  assessPublicEvmSettlementV02,
  publicEvmSettlementEvidenceDigest,
  verifyPublicEvmSettlementRecord,
  verifyPublicEvmSettlementV02,
} from "../src/evidence.js";
import type { ConformanceBundle, ConformanceCase } from "../src/types.js";

const publicEvmCaseUrl = new URL("../fixtures/public-evm/case.json", import.meta.url);
const fixtureUrl = new URL("../fixtures/v0.3/cases.json", import.meta.url);
const TRANSFER_TOPIC = keccak256(stringToHex("Transfer(address,address,uint256)"));
const AUTHORIZATION_USED_TOPIC = keccak256(stringToHex("AuthorizationUsed(address,bytes32)"));
const OBSERVED_AT = new Date("2026-09-04T12:00:00.000Z");
const RECEIPT_BLOCK = 100n;
const OBSERVED_HEAD = 104n;
const RECEIPT_BLOCK_HASH = `0x${"4".repeat(64)}` as Hex;
const OBSERVED_HEAD_HASH = `0x${"5".repeat(64)}` as Hex;

const verifierProvenance: PublicEvmVerifierProvenance = {
  operator: "Example read-only verifier",
  repositoryUrl: "https://github.com/example/public-evm-verifier",
  commit: "1".repeat(40),
  command: "pulse-ap2-x402-evidence evm-v0.2",
};

const verificationOptions: PublicEvmSettlementVerificationOptions = {
  verifierProvenance,
  headTag: "finalized",
  minimumConfirmations: 5n,
};

async function publicEvmCase(): Promise<ConformanceCase> {
  return JSON.parse(await readFile(fileURLToPath(publicEvmCaseUrl), "utf8")) as ConformanceCase;
}

async function invalidOfflineCase(): Promise<ConformanceCase> {
  const bundle = JSON.parse(await readFile(fileURLToPath(fixtureUrl), "utf8")) as ConformanceBundle;
  const result = bundle.cases.find((item) => !(item as ConformanceCase).expected.consistent) as
    | ConformanceCase
    | undefined;
  if (result === undefined) throw new Error("Expected an offline-invalid fixture");
  return result;
}

function readerFor(
  conformanceCase: ConformanceCase,
  changes: {
    chainId?: number;
    transactionHash?: Hex;
    transactionBlock?: bigint | null;
    receiptBlock?: bigint;
    receiptStatus?: "success" | "reverted";
    receiptBlockHash?: Hex;
    observedHead?: bigint | null;
    observedHeadHash?: Hex | null;
    expectedHeadTag?: PublicEvmHeadTag;
    canonicalReceiptBlock?: bigint | null;
    canonicalReceiptBlockHash?: Hex | null;
    canonicalReceiptReadFailure?: boolean;
    canonicalReceiptReadAt?: Date;
    transferLogIndex?: number | null;
    authorizationLogIndex?: number | null;
  } = {},
): PublicEvmV02Reader {
  const authorization = conformanceCase.x402.payload.payload.authorization;
  const transactionHash =
    changes.transactionHash ?? (conformanceCase.x402.settlement.transaction as Hex);
  const receiptBlock = changes.receiptBlock ?? RECEIPT_BLOCK;
  const transactionBlock = "transactionBlock" in changes ? changes.transactionBlock : receiptBlock;
  const transferLogIndex = "transferLogIndex" in changes ? changes.transferLogIndex : 7;
  const authorizationLogIndex =
    "authorizationLogIndex" in changes ? changes.authorizationLogIndex : 8;

  return {
    getChainId: vi.fn(async () => changes.chainId ?? 84532),
    getTransaction: vi.fn(async () => ({
      hash: transactionHash,
      blockNumber: transactionBlock ?? null,
    })),
    getTransactionReceipt: vi.fn(async () => ({
      transactionHash,
      blockNumber: receiptBlock,
      blockHash: changes.receiptBlockHash ?? RECEIPT_BLOCK_HASH,
      status: changes.receiptStatus ?? "success",
      logs: [
        {
          address: conformanceCase.x402.requirements.asset as Address,
          topics: [
            TRANSFER_TOPIC,
            padHex(authorization.from as Hex, { size: 32 }),
            padHex(authorization.to as Hex, { size: 32 }),
          ],
          data: numberToHex(BigInt(authorization.value), { size: 32 }),
          logIndex: transferLogIndex,
        },
        {
          address: conformanceCase.x402.requirements.asset as Address,
          topics: [
            AUTHORIZATION_USED_TOPIC,
            padHex(authorization.from as Hex, { size: 32 }),
            authorization.nonce as Hex,
          ],
          data: "0x" as Hex,
          logIndex: authorizationLogIndex,
        },
      ],
    })),
    getBlock: vi.fn(async (parameters) => {
      if ("blockNumber" in parameters) {
        if (changes.canonicalReceiptReadAt !== undefined) {
          vi.setSystemTime(changes.canonicalReceiptReadAt);
        }
        if (changes.canonicalReceiptReadFailure === true) {
          throw new Error("https://user:secret@example.invalid must not leak");
        }
        return {
          number:
            "canonicalReceiptBlock" in changes
              ? (changes.canonicalReceiptBlock ?? null)
              : parameters.blockNumber,
          hash:
            "canonicalReceiptBlockHash" in changes
              ? (changes.canonicalReceiptBlockHash ?? null)
              : (changes.receiptBlockHash ?? RECEIPT_BLOCK_HASH),
        };
      }
      expect(parameters.blockTag).toBe(changes.expectedHeadTag ?? verificationOptions.headTag);
      return {
        number: "observedHead" in changes ? (changes.observedHead ?? null) : OBSERVED_HEAD,
        hash:
          "observedHeadHash" in changes ? (changes.observedHeadHash ?? null) : OBSERVED_HEAD_HASH,
      };
    }),
  };
}

function unreadableReader(): PublicEvmV02Reader {
  return {
    getChainId: vi.fn(async () => {
      throw new Error("unexpected public RPC read");
    }),
    getTransaction: vi.fn(async () => {
      throw new Error("unexpected public RPC read");
    }),
    getTransactionReceipt: vi.fn(async () => {
      throw new Error("unexpected public RPC read");
    }),
    getBlock: vi.fn(async () => {
      throw new Error("unexpected public RPC read");
    }),
  };
}

function expectNoRpcReads(reader: PublicEvmV02Reader): void {
  expect(reader.getChainId).not.toHaveBeenCalled();
  expect(reader.getTransaction).not.toHaveBeenCalled();
  expect(reader.getTransactionReceipt).not.toHaveBeenCalled();
  expect(reader.getBlock).not.toHaveBeenCalled();
}

function recomputeDigest(evidence: PublicEvmSettlementEvidenceV02): PublicEvmSettlementEvidenceV02 {
  const changed = structuredClone(evidence);
  const { recordDigest: _recordDigest, ...body } = changed;
  changed.recordDigest.value = publicEvmSettlementEvidenceDigest(
    body as PublicEvmSettlementEvidenceV02Body,
  );
  return changed;
}

function consumerPolicy(changes: Partial<PublicEvmConsumerPolicy> = {}): PublicEvmConsumerPolicy {
  return {
    maximumObservationAgeSeconds: 3_600n,
    minimumConfirmations: 5n,
    allowedHeadTags: ["finalized"],
    trustedVerifierProvenance: {
      operator: verifierProvenance.operator,
      repositoryUrl: verifierProvenance.repositoryUrl,
      commit: verifierProvenance.commit,
    },
    reread: "never",
    ...changes,
  };
}

function assessmentContext(
  evidence: PublicEvmSettlementEvidenceV02,
  policy: PublicEvmConsumerPolicy,
  evaluatedAt: Date,
) {
  return {
    evidenceRecordDigest: evidence.recordDigest.value,
    evaluatedAt: evaluatedAt.toISOString(),
    policy: {
      maximumObservationAgeSeconds: policy.maximumObservationAgeSeconds.toString(),
      minimumConfirmations: policy.minimumConfirmations.toString(),
      allowedHeadTags: [...policy.allowedHeadTags],
      trustedVerifierProvenance: policy.trustedVerifierProvenance,
      reread: policy.reread,
    },
  };
}

async function validEvidence(): Promise<{
  conformanceCase: ConformanceCase;
  evidence: PublicEvmSettlementEvidenceV02;
  reader: PublicEvmV02Reader;
}> {
  const conformanceCase = await publicEvmCase();
  const reader = readerFor(conformanceCase);
  const evidence = await verifyPublicEvmSettlementV02(conformanceCase, reader, verificationOptions);
  return { conformanceCase, evidence, reader };
}

describe("public EVM settlement evidence v0.2", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(OBSERVED_AT);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("creates and revalidates a provenance-, head-, and case-bound record", async () => {
    const { conformanceCase, evidence, reader } = await validEvidence();
    const authorization = conformanceCase.x402.payload.payload.authorization;

    expect(reader.getBlock).toHaveBeenNthCalledWith(1, { blockTag: "finalized" });
    expect(reader.getBlock).toHaveBeenNthCalledWith(2, { blockNumber: RECEIPT_BLOCK });
    expect(evidence).toMatchObject({
      evidenceVersion: "pulse-public-evm-settlement/0.2",
      verifierProvenance,
      offlineArtifactAgreement: {
        consistent: true,
        caseId: conformanceCase.id,
        caseVersion: conformanceCase.caseVersion,
        caseInputHash: conformanceCase.inputHash,
        sourcePins: conformanceCase.sourcePins,
      },
      settlementObservation: {
        network: conformanceCase.x402.requirements.network,
        chainId: 84532,
        transactionHash: conformanceCase.x402.settlement.transaction,
        receipt: {
          blockNumber: RECEIPT_BLOCK.toString(),
          blockHash: RECEIPT_BLOCK_HASH,
          status: "success",
        },
        observedHead: {
          blockNumber: OBSERVED_HEAD.toString(),
          blockHash: OBSERVED_HEAD_HASH,
        },
        confirmations: "5",
        asset: conformanceCase.x402.requirements.asset,
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
        observedAt: OBSERVED_AT.toISOString(),
      },
      confirmationPolicy: {
        type: "minimum-confirmations",
        headTag: "finalized",
        minimumConfirmations: "5",
      },
      recordDigest: {
        algorithm: "sha-256",
        canonicalization: "RFC8785",
      },
    });
    const { recordDigest, ...body } = evidence;
    expect(recordDigest.value).toBe(
      publicEvmSettlementEvidenceDigest(body as PublicEvmSettlementEvidenceV02Body),
    );
    await expect(verifyPublicEvmSettlementRecord(conformanceCase, evidence)).resolves.toEqual({
      valid: true,
      automatedChecksPassed: true,
      errors: [],
    });
  });

  it("uses the latest head and one confirmation as the explicit defaults", async () => {
    const conformanceCase = await publicEvmCase();
    const reader = readerFor(conformanceCase, { expectedHeadTag: "latest" });

    const evidence = await verifyPublicEvmSettlementV02(conformanceCase, reader, {
      verifierProvenance,
    });

    expect(evidence.confirmationPolicy).toEqual({
      type: "minimum-confirmations",
      headTag: "latest",
      minimumConfirmations: "1",
    });
    expect(reader.getBlock).toHaveBeenNthCalledWith(1, { blockTag: "latest" });
  });

  it("captures observedAt at the tagged head even if time advances during the receipt-block re-read", async () => {
    const conformanceCase = await publicEvmCase();
    const afterHeadRead = new Date(OBSERVED_AT.getTime() + 60_000);
    const reader = readerFor(conformanceCase, {
      canonicalReceiptReadAt: afterHeadRead,
    });

    const evidence = await verifyPublicEvmSettlementV02(
      conformanceCase,
      reader,
      verificationOptions,
    );

    expect(vi.getMockedSystemTime()).toEqual(afterHeadRead);
    expect(evidence.settlementObservation.observedAt).toBe(OBSERVED_AT.toISOString());
  });

  it("detects a changed body when the record digest is not updated", async () => {
    const { conformanceCase, evidence } = await validEvidence();
    const changed = structuredClone(evidence);
    changed.settlementObservation.observedAt = "2026-09-04T12:00:01.000Z";

    await expect(verifyPublicEvmSettlementRecord(conformanceCase, changed)).resolves.toEqual({
      valid: false,
      automatedChecksPassed: false,
      errors: ["recordDigest.value: Does not match the canonical evidence body"],
    });
    await expect(
      assessPublicEvmSettlementV02(conformanceCase, changed, consumerPolicy(), OBSERVED_AT),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: ["recordDigest.value: Does not match the canonical evidence body"],
    });
  });

  it.each([
    {
      label: "a changed canonical receipt block hash",
      changes: { canonicalReceiptBlockHash: `0x${"9".repeat(64)}` as Hex },
      error: "The receipt block hash does not match the current canonical block",
    },
    {
      label: "a failed canonical receipt block re-read",
      changes: { canonicalReceiptReadFailure: true },
      error: "Unable to re-read the canonical receipt block",
    },
    {
      label: "an incomplete canonical receipt block re-read",
      changes: { canonicalReceiptBlock: null, canonicalReceiptBlockHash: null },
      error: "The canonical receipt block is incomplete",
    },
  ])("rejects $label", async ({ changes, error }) => {
    const conformanceCase = await publicEvmCase();
    const reader = readerFor(conformanceCase, changes);

    await expect(
      verifyPublicEvmSettlementV02(conformanceCase, reader, verificationOptions),
    ).rejects.toThrow(error);
    expect(reader.getBlock).toHaveBeenNthCalledWith(1, { blockTag: "finalized" });
    expect(reader.getBlock).toHaveBeenNthCalledWith(2, { blockNumber: RECEIPT_BLOCK });
  });

  it.each([
    {
      label: "an incomplete selected head",
      changes: { observedHead: null, observedHeadHash: null },
      minimumConfirmations: 1n,
      error: "The selected public EVM head is incomplete",
    },
    {
      label: "a selected head before the receipt",
      changes: { observedHead: RECEIPT_BLOCK - 1n },
      minimumConfirmations: 1n,
      error: "The selected EVM head precedes the receipt block",
    },
    {
      label: "too few confirmations at the selected head",
      changes: { observedHead: RECEIPT_BLOCK },
      minimumConfirmations: 2n,
      error: "The public transaction does not have enough confirmations",
    },
  ])("rejects $label", async ({ changes, minimumConfirmations, error }) => {
    const conformanceCase = await publicEvmCase();
    const reader = readerFor(conformanceCase, changes);

    await expect(
      verifyPublicEvmSettlementV02(conformanceCase, reader, {
        ...verificationOptions,
        minimumConfirmations,
      }),
    ).rejects.toThrow(error);
  });

  it("still rejects case drift after an attacker recomputes the record digest", async () => {
    const { conformanceCase, evidence } = await validEvidence();
    const changed = structuredClone(evidence);
    changed.offlineArtifactAgreement.caseId = "different-public-case";
    const selfConsistentDigest = recomputeDigest(changed);

    const report = await verifyPublicEvmSettlementRecord(conformanceCase, selfConsistentDigest);
    expect(report).toEqual({
      valid: false,
      automatedChecksPassed: false,
      errors: ["offlineArtifactAgreement.caseId: Does not match the supplied conformance case"],
    });
    expect(report.errors).not.toContain(
      "recordDigest.value: Does not match the canonical evidence body",
    );
  });

  it.each([
    {
      label: "a head before the receipt block",
      change: (evidence: PublicEvmSettlementEvidenceV02) => {
        evidence.settlementObservation.observedHead.blockNumber = "99";
        evidence.settlementObservation.confirmations = "1";
        evidence.confirmationPolicy.minimumConfirmations = "1";
      },
      error: "settlementObservation.observedHead.blockNumber: Precedes the receipt block",
    },
    {
      label: "a confirmation count inconsistent with the two block heights",
      change: (evidence: PublicEvmSettlementEvidenceV02) => {
        evidence.settlementObservation.confirmations = "4";
        evidence.confirmationPolicy.minimumConfirmations = "1";
      },
      error:
        "settlementObservation.confirmations: Does not equal observed head minus receipt block plus one",
    },
    {
      label: "fewer confirmations than the record's declared minimum",
      change: (evidence: PublicEvmSettlementEvidenceV02) => {
        evidence.confirmationPolicy.minimumConfirmations = "6";
      },
      error:
        "settlementObservation.confirmations: Does not satisfy confirmationPolicy.minimumConfirmations",
    },
    {
      label: "one log index claimed for both required events",
      change: (evidence: PublicEvmSettlementEvidenceV02) => {
        evidence.settlementObservation.authorizationUsed.logIndex =
          evidence.settlementObservation.transfer.logIndex;
      },
      error: "settlementObservation: Transfer and AuthorizationUsed log indexes must differ",
    },
  ])("rejects $label even with a recomputed digest", async ({ change, error }) => {
    const { conformanceCase, evidence } = await validEvidence();
    const changed = structuredClone(evidence);
    change(changed);

    await expect(
      verifyPublicEvmSettlementRecord(conformanceCase, recomputeDigest(changed)),
    ).resolves.toMatchObject({
      valid: false,
      automatedChecksPassed: false,
      errors: [error],
    });
  });

  it("accepts a fresh observation under a matching consumer policy", async () => {
    const { conformanceCase, evidence } = await validEvidence();
    const policy = consumerPolicy();
    const evaluatedAt = new Date(OBSERVED_AT.getTime() + 30 * 60 * 1_000);

    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, policy, evaluatedAt),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: assessmentContext(evidence, policy, evaluatedAt),
      accepted: true,
      rereadRequired: false,
      errors: [],
    });
  });

  it.each([
    {
      label: "expired",
      evaluatedAt: new Date(OBSERVED_AT.getTime() + 3_601 * 1_000),
      policy: consumerPolicy(),
      error: "settlementObservation.observedAt: Exceeds the maximum observation age",
    },
    {
      label: "from the future",
      evaluatedAt: new Date(OBSERVED_AT.getTime() - 1),
      policy: consumerPolicy(),
      error: "settlementObservation.observedAt: Is later than the policy evaluation time",
    },
    {
      label: "recorded under a disallowed head tag",
      evaluatedAt: OBSERVED_AT,
      policy: consumerPolicy({ allowedHeadTags: ["safe"] }),
      error: "confirmationPolicy.headTag: Is not allowed by the consumer policy",
    },
    {
      label: "below the consumer's confirmation floor",
      evaluatedAt: OBSERVED_AT,
      policy: consumerPolicy({ minimumConfirmations: 6n }),
      error: "settlementObservation.confirmations: Does not satisfy the consumer policy",
    },
  ])("rejects a consumer assessment that is $label", async ({ evaluatedAt, policy, error }) => {
    const { conformanceCase, evidence } = await validEvidence();

    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, policy, evaluatedAt),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: assessmentContext(evidence, policy, evaluatedAt),
      accepted: false,
      rereadRequired: false,
      errors: [error],
    });
  });

  it("requires every trusted provenance identity field to match", async () => {
    const { conformanceCase, evidence } = await validEvidence();
    const policy = consumerPolicy({
      trustedVerifierProvenance: {
        operator: "Different operator",
        repositoryUrl: "https://github.com/example/different-verifier",
        commit: "2".repeat(40),
      },
    });

    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, policy, OBSERVED_AT),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: assessmentContext(evidence, policy, OBSERVED_AT),
      accepted: false,
      rereadRequired: false,
      errors: [
        "verifierProvenance.operator: Does not match the trusted verifier policy",
        "verifierProvenance.repositoryUrl: Does not match the trusted verifier policy",
        "verifierProvenance.commit: Does not match the trusted verifier policy",
      ],
    });
  });

  it("implements always and conditional online reread policies", async () => {
    const { conformanceCase, evidence } = await validEvidence();
    const freshTime = new Date(OBSERVED_AT.getTime() + 30 * 60 * 1_000);
    const expiredTime = new Date(OBSERVED_AT.getTime() + 3_601 * 1_000);
    const alwaysPolicy = consumerPolicy({ reread: "always" });
    const conditionalPolicy = consumerPolicy({ reread: "if-policy-unsatisfied" });

    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, alwaysPolicy, freshTime),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: assessmentContext(evidence, alwaysPolicy, freshTime),
      accepted: false,
      rereadRequired: true,
      errors: [],
    });
    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, conditionalPolicy, freshTime),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: assessmentContext(evidence, conditionalPolicy, freshTime),
      accepted: true,
      rereadRequired: false,
      errors: [],
    });
    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, conditionalPolicy, expiredTime),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: assessmentContext(evidence, conditionalPolicy, expiredTime),
      accepted: false,
      rereadRequired: true,
      errors: ["settlementObservation.observedAt: Exceeds the maximum observation age"],
    });
  });

  it("omits assessment context when the consumer policy or evaluation time is invalid", async () => {
    const { conformanceCase, evidence } = await validEvidence();
    const invalidPolicy = consumerPolicy({ allowedHeadTags: [] });

    await expect(
      assessPublicEvmSettlementV02(conformanceCase, evidence, invalidPolicy, OBSERVED_AT),
    ).resolves.toMatchObject({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: [expect.stringContaining("policy.allowedHeadTags")],
    });
    await expect(
      assessPublicEvmSettlementV02(
        conformanceCase,
        evidence,
        consumerPolicy(),
        new Date(Number.NaN),
      ),
    ).resolves.toEqual({
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: ["evaluatedAt: Expected a valid date"],
    });
  });

  it("fails closed on invalid options, malformed input, and offline rejection before RPC", async () => {
    const conformanceCase = await publicEvmCase();
    const invalidCase = await invalidOfflineCase();
    const cases: Array<{
      input: unknown;
      options: PublicEvmSettlementVerificationOptions;
      message: string;
    }> = [
      {
        input: conformanceCase,
        options: { ...verificationOptions, minimumConfirmations: 0n },
        message: "Minimum confirmations must be at least one",
      },
      {
        input: conformanceCase,
        options: {
          ...verificationOptions,
          headTag: "pending" as PublicEvmHeadTag,
        },
        message: "selected EVM head tag is not supported",
      },
      {
        input: conformanceCase,
        options: {
          ...verificationOptions,
          verifierProvenance: { ...verifierProvenance, operator: " " },
        },
        message: "verifier provenance is not well formed",
      },
      {
        input: conformanceCase,
        options: {
          ...verificationOptions,
          verifierProvenance: {
            ...verifierProvenance,
            repositoryUrl: "not-an-https-url",
          },
        },
        message: "verifier provenance is not well formed",
      },
      {
        input: conformanceCase,
        options: {
          ...verificationOptions,
          verifierProvenance: {
            ...verifierProvenance,
            repositoryUrl: "https://user:secret@example.invalid/verifier",
          },
        },
        message: "verifier provenance is not well formed",
      },
      {
        input: null,
        options: verificationOptions,
        message: "selected conformance case is not well formed",
      },
      {
        input: invalidCase,
        options: verificationOptions,
        message: "requires an accepted offline case",
      },
    ];

    for (const item of cases) {
      const reader = unreadableReader();
      await expect(verifyPublicEvmSettlementV02(item.input, reader, item.options)).rejects.toThrow(
        item.message,
      );
      expectNoRpcReads(reader);
    }
  });

  it("redacts transaction-read RPC failures and does not continue to the head read", async () => {
    const conformanceCase = await publicEvmCase();
    const reader = readerFor(conformanceCase);
    vi.mocked(reader.getChainId).mockRejectedValueOnce(
      new Error("https://user:secret@example.invalid must not leak"),
    );

    await expect(
      verifyPublicEvmSettlementV02(conformanceCase, reader, verificationOptions),
    ).rejects.toThrow("Unable to read the public transaction and receipt");
    expect(reader.getBlock).not.toHaveBeenCalled();
  });

  it("redacts a selected-head RPC failure after validating the receipt", async () => {
    const conformanceCase = await publicEvmCase();
    const reader = readerFor(conformanceCase);
    vi.mocked(reader.getBlock).mockRejectedValueOnce(
      new Error("https://user:secret@example.invalid must not leak"),
    );

    await expect(
      verifyPublicEvmSettlementV02(conformanceCase, reader, verificationOptions),
    ).rejects.toThrow("Unable to read the selected public EVM head");
    expect(reader.getChainId).toHaveBeenCalledTimes(1);
    expect(reader.getTransaction).toHaveBeenCalledTimes(1);
    expect(reader.getTransactionReceipt).toHaveBeenCalledTimes(1);
  });
});
