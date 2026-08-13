import { createHash } from "node:crypto";
import type { Address, Hex } from "viem";
import { keccak256, stringToHex } from "viem";
import { z } from "zod";
import { canonicalValuesEqual } from "./canonical.js";
import { CONFORMANCE_FAILURE_CODES } from "./failures.js";
import {
  ConformanceBundleSchema,
  type ConformanceCase,
  ConformanceCaseSchema,
  ExpectedResultSchema,
} from "./types.js";
import { verifyConformanceCase } from "./verifier.js";

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const gitCommit = z.string().regex(/^[0-9a-f]{40}$/);
const httpsUrl = z
  .string()
  .url()
  .refine((value) => value.startsWith("https://"), {
    message: "Expected an HTTPS URL",
  });

const ReproductionResultSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  decision: z.enum(["accept", "reject"]),
  failureCodes: z.array(z.enum(CONFORMANCE_FAILURE_CODES)),
});

export const IndependentReproductionRecordSchema = z.strictObject({
  recordVersion: z.literal("pulse-independent-reproduction/0.1"),
  performedAt: z.string().datetime({ offset: true }),
  implementation: z.strictObject({
    repositoryUrl: httpsUrl,
    commit: gitCommit,
    language: z.string().min(1),
    runtime: z.string().min(1),
    command: z.string().min(1),
    organization: z.string().min(1),
    independentOfPrimeBeat: z.literal(true),
  }),
  fixture: z.strictObject({
    repositoryCommit: gitCommit,
    path: z.literal("fixtures/v0.1/cases.json"),
    sha256,
    caseCount: z.literal(80),
  }),
  environment: z.strictObject({
    operatingSystem: z.string().min(1),
    architecture: z.string().min(1),
    dependencies: z.array(z.string().min(1)),
  }),
  results: z.array(ReproductionResultSchema).length(80),
  notes: z.string().optional(),
  publishedUrl: httpsUrl,
});

const ReviewFindingSchema = z.strictObject({
  id: z.string().regex(/^[A-Z]+-[0-9]+$/),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]),
  title: z.string().min(1),
  status: z.enum(["open", "resolved", "accepted-risk"]),
  publicSummary: z.string().min(1),
  remediation: z.string().min(1).optional(),
});

export const IndependentSecurityReviewRecordSchema = z.strictObject({
  recordVersion: z.literal("pulse-independent-security-review/0.1"),
  reviewedCommit: gitCommit,
  reviewedAt: z.string().datetime({ offset: true }),
  reviewer: z.strictObject({
    name: z.string().min(1),
    organization: z.string().min(1),
    profileUrl: httpsUrl,
    independentOfPrimeBeat: z.literal(true),
  }),
  scope: z.array(z.string().min(1)).min(1),
  method: z.array(z.string().min(1)).min(1),
  findings: z.array(ReviewFindingSchema),
  remediationSummary: z.string().min(1),
  residualRisk: z.string().min(1),
  publishedUrl: httpsUrl,
});

export interface EvidenceRecordValidationReport {
  valid: boolean;
  automatedChecksPassed: boolean;
  errors: string[];
}

function issueMessages(error: z.ZodError): string[] {
  return error.issues.map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`);
}

function rawSha256(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

export function verifyIndependentReproductionRecord(
  bundleRaw: string,
  recordInput: unknown,
): EvidenceRecordValidationReport {
  const errors: string[] = [];
  const recordResult = IndependentReproductionRecordSchema.safeParse(recordInput);
  if (!recordResult.success) {
    return {
      valid: false,
      automatedChecksPassed: false,
      errors: issueMessages(recordResult.error),
    };
  }

  let bundleInput: unknown;
  try {
    bundleInput = JSON.parse(bundleRaw) as unknown;
  } catch {
    return {
      valid: false,
      automatedChecksPassed: false,
      errors: ["bundle: Expected valid JSON"],
    };
  }
  const bundleResult = ConformanceBundleSchema.safeParse(bundleInput);
  if (!bundleResult.success) {
    return {
      valid: false,
      automatedChecksPassed: false,
      errors: issueMessages(bundleResult.error).map((message) => `bundle.${message}`),
    };
  }

  const record = recordResult.data;
  const actualFixtureHash = rawSha256(bundleRaw);
  if (record.fixture.sha256 !== actualFixtureHash) {
    errors.push("fixture.sha256: Does not match the supplied fixture bytes");
  }

  const expectedById = new Map<string, z.infer<typeof ExpectedResultSchema>>();
  const ExpectedEnvelopeSchema = z.looseObject({
    id: z.string(),
    expected: ExpectedResultSchema,
  });
  for (const rawCase of bundleResult.data.cases) {
    const envelope = ExpectedEnvelopeSchema.safeParse(rawCase);
    if (!envelope.success) {
      errors.push("bundle.cases: A case is missing a valid id or expected result");
      continue;
    }
    if (expectedById.has(envelope.data.id)) {
      errors.push(`bundle.cases: Duplicate case id ${envelope.data.id}`);
    }
    expectedById.set(envelope.data.id, envelope.data.expected);
  }

  const observedIds = new Set<string>();
  for (const result of record.results) {
    if (observedIds.has(result.id)) {
      errors.push(`results: Duplicate case id ${result.id}`);
      continue;
    }
    observedIds.add(result.id);
    const expected = expectedById.get(result.id);
    if (expected === undefined) {
      errors.push(`results: Unknown case id ${result.id}`);
      continue;
    }
    const expectedDecision = expected.consistent ? "accept" : "reject";
    if (result.decision !== expectedDecision) {
      errors.push(`results.${result.id}: Decision does not match the fixture expectation`);
    }
    if (!canonicalValuesEqual(result.failureCodes, expected.failureCodes)) {
      errors.push(`results.${result.id}: Failure codes do not match the fixture expectation`);
    }
  }
  for (const id of expectedById.keys()) {
    if (!observedIds.has(id)) errors.push(`results: Missing case id ${id}`);
  }

  return {
    valid: errors.length === 0,
    automatedChecksPassed: errors.length === 0,
    errors,
  };
}

export function verifyIndependentSecurityReviewRecord(
  recordInput: unknown,
): EvidenceRecordValidationReport {
  const result = IndependentSecurityReviewRecordSchema.safeParse(recordInput);
  if (!result.success) {
    return {
      valid: false,
      automatedChecksPassed: false,
      errors: issueMessages(result.error),
    };
  }
  const unresolvedBlockingFindings = result.data.findings.filter(
    (finding) =>
      (finding.severity === "critical" || finding.severity === "high") &&
      finding.status !== "resolved",
  );
  return {
    valid: true,
    automatedChecksPassed: unresolvedBlockingFindings.length === 0,
    errors: unresolvedBlockingFindings.map(
      (finding) => `${finding.id}: ${finding.severity} finding is not resolved`,
    ),
  };
}

const TRANSFER_TOPIC = keccak256(stringToHex("Transfer(address,address,uint256)"));
const AUTHORIZATION_USED_TOPIC = keccak256(stringToHex("AuthorizationUsed(address,bytes32)"));

interface PublicEvmLog {
  address: Address;
  data: Hex;
  topics: readonly Hex[];
  logIndex: number | null;
}

export interface PublicEvmReader {
  getChainId(): Promise<number>;
  getTransaction(parameters: { hash: Hex }): Promise<{
    hash: Hex;
    blockNumber: bigint | null;
  }>;
  getTransactionReceipt(parameters: { hash: Hex }): Promise<{
    transactionHash: Hex;
    blockNumber: bigint;
    blockHash: Hex;
    status: "success" | "reverted";
    logs: readonly PublicEvmLog[];
  }>;
  getBlockNumber(): Promise<bigint>;
}

export class PublicEvmEvidenceError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "PublicEvmEvidenceError";
  }
}

export interface PublicEvmSettlementEvidence {
  evidenceVersion: "pulse-public-evm-settlement/0.1";
  caseId: string;
  caseInputHash: string;
  network: string;
  chainId: number;
  transactionHash: Hex;
  blockNumber: string;
  blockHash: Hex;
  confirmations: string;
  receiptStatus: "success";
  asset: Address;
  transfer: {
    from: Address;
    to: Address;
    value: string;
    logIndex: number;
  };
  authorizationUsed: {
    authorizer: Address;
    nonce: Hex;
    logIndex: number;
  };
  verifiedAt: string;
}

function topicAddress(topic: Hex | undefined): Address | undefined {
  if (topic === undefined || !/^0x[0-9a-fA-F]{64}$/.test(topic)) return undefined;
  return `0x${topic.slice(-40)}` as Address;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

export async function verifyPublicEvmSettlement(
  caseInput: unknown,
  reader: PublicEvmReader,
  minConfirmations = 1n,
): Promise<PublicEvmSettlementEvidence> {
  if (minConfirmations < 1n) {
    throw new PublicEvmEvidenceError("Minimum confirmations must be at least one.");
  }
  const parsedCase = ConformanceCaseSchema.safeParse(caseInput);
  if (!parsedCase.success) {
    throw new PublicEvmEvidenceError("The selected conformance case is not well formed.");
  }
  const conformanceCase: ConformanceCase = parsedCase.data;
  const offlineReport = await verifyConformanceCase(conformanceCase);
  if (!offlineReport.consistent || !conformanceCase.expected.consistent) {
    throw new PublicEvmEvidenceError(
      "Public settlement evidence requires an accepted offline case.",
    );
  }

  const transactionHash = conformanceCase.x402.settlement.transaction as Hex;
  let chainId: number;
  let transaction: Awaited<ReturnType<PublicEvmReader["getTransaction"]>>;
  let receipt: Awaited<ReturnType<PublicEvmReader["getTransactionReceipt"]>>;
  let latestBlock: bigint;
  try {
    [chainId, transaction, receipt, latestBlock] = await Promise.all([
      reader.getChainId(),
      reader.getTransaction({ hash: transactionHash }),
      reader.getTransactionReceipt({ hash: transactionHash }),
      reader.getBlockNumber(),
    ]);
  } catch {
    throw new PublicEvmEvidenceError("Unable to read the public transaction and receipt.");
  }

  const expectedChainId = Number(conformanceCase.x402.requirements.network.slice("eip155:".length));
  if (chainId !== expectedChainId) {
    throw new PublicEvmEvidenceError("The RPC chain does not match the case network.");
  }
  if (
    !sameHex(transaction.hash, transactionHash) ||
    !sameHex(receipt.transactionHash, transactionHash)
  ) {
    throw new PublicEvmEvidenceError(
      "The returned transaction identifier does not match the case.",
    );
  }
  if (transaction.blockNumber === null || transaction.blockNumber !== receipt.blockNumber) {
    throw new PublicEvmEvidenceError("The transaction and receipt block numbers do not match.");
  }
  if (receipt.status !== "success") {
    throw new PublicEvmEvidenceError("The public transaction receipt is not successful.");
  }
  if (latestBlock < receipt.blockNumber) {
    throw new PublicEvmEvidenceError("The RPC returned an invalid latest block number.");
  }
  const confirmations = latestBlock - receipt.blockNumber + 1n;
  if (confirmations < minConfirmations) {
    throw new PublicEvmEvidenceError("The public transaction does not have enough confirmations.");
  }

  const requirements = conformanceCase.x402.requirements;
  const authorization = conformanceCase.x402.payload.payload.authorization;
  const assetLogs = receipt.logs.filter((log) => sameHex(log.address, requirements.asset));
  const transferLog = assetLogs.find((log) => {
    if (!sameHex(log.topics[0] ?? "", TRANSFER_TOPIC)) return false;
    const from = topicAddress(log.topics[1]);
    const to = topicAddress(log.topics[2]);
    if (from === undefined || to === undefined || !/^0x[0-9a-fA-F]{64}$/.test(log.data)) {
      return false;
    }
    return (
      sameHex(from, authorization.from) &&
      sameHex(to, authorization.to) &&
      BigInt(log.data) === BigInt(authorization.value)
    );
  });
  if (transferLog === undefined || transferLog.logIndex === null) {
    throw new PublicEvmEvidenceError("No matching ERC-20 Transfer event was found.");
  }

  const authorizationUsedLog = assetLogs.find((log) => {
    if (!sameHex(log.topics[0] ?? "", AUTHORIZATION_USED_TOPIC)) return false;
    const authorizer = topicAddress(log.topics[1]);
    const nonce = log.topics[2];
    return (
      authorizer !== undefined &&
      nonce !== undefined &&
      sameHex(authorizer, authorization.from) &&
      sameHex(nonce, authorization.nonce)
    );
  });
  if (authorizationUsedLog === undefined || authorizationUsedLog.logIndex === null) {
    throw new PublicEvmEvidenceError("No matching EIP-3009 AuthorizationUsed event was found.");
  }

  return {
    evidenceVersion: "pulse-public-evm-settlement/0.1",
    caseId: conformanceCase.id,
    caseInputHash: conformanceCase.inputHash,
    network: requirements.network,
    chainId,
    transactionHash,
    blockNumber: receipt.blockNumber.toString(),
    blockHash: receipt.blockHash,
    confirmations: confirmations.toString(),
    receiptStatus: "success",
    asset: requirements.asset as Address,
    transfer: {
      from: authorization.from as Address,
      to: authorization.to as Address,
      value: authorization.value,
      logIndex: transferLog.logIndex,
    },
    authorizationUsed: {
      authorizer: authorization.from as Address,
      nonce: authorization.nonce as Hex,
      logIndex: authorizationUsedLog.logIndex,
    },
    verifiedAt: new Date().toISOString(),
  };
}
