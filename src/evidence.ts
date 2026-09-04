import { createHash } from "node:crypto";
import type { Address, Hex } from "viem";
import { keccak256, stringToHex } from "viem";
import { z } from "zod";
import { canonicalSha256Base64Url, canonicalValuesEqual } from "./canonical.js";
import { CONFORMANCE_FAILURE_CODES } from "./failures.js";
import {
  ConformanceBundleSchema,
  type ConformanceCase,
  ConformanceCaseSchema,
  ExpectedResultSchema,
  SourcePinsSchema,
} from "./types.js";
import { verifyConformanceCase } from "./verifier.js";

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const gitCommit = z.string().regex(/^[0-9a-f]{40}$/);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const hex32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const unsignedDecimal = z.string().regex(/^(0|[1-9][0-9]*)$/);
const positiveDecimal = z.string().regex(/^[1-9][0-9]*$/);
const base64UrlSha256 = z
  .string()
  .regex(/^[A-Za-z0-9_-]{43}$/)
  .refine(
    (value) => {
      const decoded = Buffer.from(value, "base64url");
      return decoded.length === 32 && decoded.toString("base64url") === value;
    },
    { message: "Expected a canonical unpadded base64url-encoded SHA-256 value" },
  );
const httpsUrl = z
  .string()
  .url()
  .refine((value) => value.startsWith("https://"), {
    message: "Expected an HTTPS URL",
  });
const credentialFreeHttpsUrl = httpsUrl.refine(
  (value) => {
    try {
      const parsed = new URL(value);
      return parsed.username.length === 0 && parsed.password.length === 0;
    } catch {
      return false;
    }
  },
  { message: "URL credentials are not allowed" },
);

const FROZEN_PULSE_EVIDENCE_COMMIT = "e06a6cbfe3ddb965c8fc70f50838f5014ec2038e";

const FROZEN_REPRODUCTION_TARGETS = {
  "ap2-x402-conformance-bundle/0.1": [
    {
      repositoryCommit: FROZEN_PULSE_EVIDENCE_COMMIT,
      path: "fixtures/v0.1/cases.json",
      sha256: "4ff061cfa709b043662e67335bf4abd0e8dcf8cb45d32ee333992e3789d95a80",
    },
  ],
  "ap2-x402-conformance-bundle/0.2": [
    {
      repositoryCommit: FROZEN_PULSE_EVIDENCE_COMMIT,
      path: "fixtures/v0.2/cases.json",
      sha256: "1e8168b52c463a5441590b051facb767317a71cadbde3fcab6aee2d40f3fbaa1",
    },
    {
      repositoryCommit: "3ae75963462cd7daf66fac9bba13184d0b036152",
      path: "fixtures/v0.2/cases.json",
      sha256: "326de97fde74636bf4c2b8c6838548cb5f091f754189af2c1a9d25aae92c1ec0",
    },
  ],
  "ap2-x402-conformance-bundle/0.3": [
    {
      repositoryCommit: FROZEN_PULSE_EVIDENCE_COMMIT,
      path: "fixtures/v0.3/cases.json",
      sha256: "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0",
    },
  ],
} as const;

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
    path: z.enum([
      "fixtures/v0.1/cases.json",
      "fixtures/v0.2/cases.json",
      "fixtures/v0.3/cases.json",
    ]),
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
  const frozenTargets = FROZEN_REPRODUCTION_TARGETS[bundleResult.data.bundleVersion];
  const expectedFixturePath = frozenTargets[0].path;
  if (record.fixture.path !== expectedFixturePath) {
    errors.push(
      `fixture.path: Expected ${expectedFixturePath} for ${bundleResult.data.bundleVersion}`,
    );
  }
  const actualFixtureHash = rawSha256(bundleRaw);
  const frozenTarget = frozenTargets.find((target) => target.sha256 === actualFixtureHash);
  if (frozenTarget === undefined) {
    errors.push(
      `bundle.sha256: Does not match the frozen ${bundleResult.data.bundleVersion} fixture`,
    );
  } else if (record.fixture.repositoryCommit !== frozenTarget.repositoryCommit) {
    errors.push(
      `fixture.repositoryCommit: Expected frozen Pulse commit ${frozenTarget.repositoryCommit}`,
    );
  }
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
  const errors: string[] = [];
  if (result.data.reviewedCommit !== FROZEN_PULSE_EVIDENCE_COMMIT) {
    errors.push(`reviewedCommit: Expected frozen Pulse commit ${FROZEN_PULSE_EVIDENCE_COMMIT}`);
  }
  const unresolvedBlockingFindings = result.data.findings.filter(
    (finding) =>
      (finding.severity === "critical" || finding.severity === "high") &&
      finding.status !== "resolved",
  );
  errors.push(
    ...unresolvedBlockingFindings.map(
      (finding) => `${finding.id}: ${finding.severity} finding is not resolved`,
    ),
  );
  return {
    valid: result.data.reviewedCommit === FROZEN_PULSE_EVIDENCE_COMMIT,
    automatedChecksPassed: errors.length === 0,
    errors,
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

export const PublicEvmHeadTagSchema = z.enum(["latest", "safe", "finalized"]);
export type PublicEvmHeadTag = z.infer<typeof PublicEvmHeadTagSchema>;

interface PublicEvmTransactionReader {
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
}

export interface PublicEvmReader extends PublicEvmTransactionReader {
  getBlockNumber(): Promise<bigint>;
}

export interface PublicEvmV02Reader extends PublicEvmTransactionReader {
  getBlock(parameters: { blockTag: PublicEvmHeadTag } | { blockNumber: bigint }): Promise<{
    number: bigint | null;
    hash: Hex | null;
  }>;
}

export class PublicEvmEvidenceError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "PublicEvmEvidenceError";
  }
}

export function selectPublicEvmCase(input: unknown, caseId: string): ConformanceCase {
  const standalone = ConformanceCaseSchema.safeParse(input);
  if (standalone.success) {
    if (standalone.data.id !== caseId) {
      throw new PublicEvmEvidenceError("The requested case id does not match the standalone case.");
    }
    return standalone.data;
  }
  const bundle = ConformanceBundleSchema.safeParse(input);
  if (!bundle.success) {
    throw new PublicEvmEvidenceError(
      "The public EVM input is neither a standalone case nor a valid fixture bundle.",
    );
  }
  const selected = bundle.data.cases.find(
    (item) => typeof item === "object" && item !== null && "id" in item && item.id === caseId,
  );
  if (selected === undefined) {
    throw new PublicEvmEvidenceError("The requested case id was not found.");
  }
  return ConformanceCaseSchema.parse(selected);
}

export interface PublicEvmSettlementEvidenceV01 {
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

export const PublicEvmSettlementEvidenceV01Schema = z.strictObject({
  evidenceVersion: z.literal("pulse-public-evm-settlement/0.1"),
  caseId: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  caseInputHash: z.string().min(1),
  network: z.string().regex(/^eip155:[1-9][0-9]*$/),
  chainId: z.number().int().positive(),
  transactionHash: hex32,
  blockNumber: unsignedDecimal,
  blockHash: hex32,
  confirmations: positiveDecimal,
  receiptStatus: z.literal("success"),
  asset: address,
  transfer: z.strictObject({
    from: address,
    to: address,
    value: unsignedDecimal,
    logIndex: z.number().int().nonnegative(),
  }),
  authorizationUsed: z.strictObject({
    authorizer: address,
    nonce: hex32,
    logIndex: z.number().int().nonnegative(),
  }),
  verifiedAt: z.string().datetime({ offset: true }),
});

export interface PublicEvmVerifierProvenance {
  operator: string;
  repositoryUrl: string;
  commit: string;
  command: "pulse-ap2-x402-evidence evm-v0.2";
}

export interface PublicEvmSettlementEvidenceV02Body {
  evidenceVersion: "pulse-public-evm-settlement/0.2";
  verifierProvenance: PublicEvmVerifierProvenance;
  offlineArtifactAgreement: {
    consistent: true;
    caseId: string;
    caseVersion: ConformanceCase["caseVersion"];
    caseInputHash: string;
    sourcePins: ConformanceCase["sourcePins"];
  };
  settlementObservation: {
    network: string;
    chainId: number;
    transactionHash: Hex;
    receipt: {
      blockNumber: string;
      blockHash: Hex;
      status: "success";
    };
    observedHead: {
      blockNumber: string;
      blockHash: Hex;
    };
    confirmations: string;
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
    observedAt: string;
  };
  confirmationPolicy: {
    type: "minimum-confirmations";
    headTag: PublicEvmHeadTag;
    minimumConfirmations: string;
  };
}

export interface PublicEvmSettlementEvidenceV02 extends PublicEvmSettlementEvidenceV02Body {
  recordDigest: {
    algorithm: "sha-256";
    canonicalization: "RFC8785";
    value: string;
  };
}

// Keep the original public name bound to the 0.1 shape for existing TypeScript consumers.
export type PublicEvmSettlementEvidence = PublicEvmSettlementEvidenceV01;
export type AnyPublicEvmSettlementEvidence =
  | PublicEvmSettlementEvidenceV01
  | PublicEvmSettlementEvidenceV02;

export const PublicEvmVerifierProvenanceSchema = z.strictObject({
  operator: z.string().refine((value) => value.trim().length > 0, {
    message: "Expected a non-blank verifier operator",
  }),
  repositoryUrl: credentialFreeHttpsUrl,
  commit: gitCommit,
  command: z.literal("pulse-ap2-x402-evidence evm-v0.2"),
});

export const PublicEvmSettlementEvidenceV02BodySchema = z.strictObject({
  evidenceVersion: z.literal("pulse-public-evm-settlement/0.2"),
  verifierProvenance: PublicEvmVerifierProvenanceSchema,
  offlineArtifactAgreement: z.strictObject({
    consistent: z.literal(true),
    caseId: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
    caseVersion: z.enum([
      "ap2-x402-conformance/0.1",
      "ap2-x402-conformance/0.2",
      "ap2-x402-conformance/0.3",
    ]),
    caseInputHash: base64UrlSha256,
    sourcePins: SourcePinsSchema,
  }),
  settlementObservation: z.strictObject({
    network: z.string().regex(/^eip155:[1-9][0-9]*$/),
    chainId: z.number().int().positive().safe(),
    transactionHash: hex32,
    receipt: z.strictObject({
      blockNumber: unsignedDecimal,
      blockHash: hex32,
      status: z.literal("success"),
    }),
    observedHead: z.strictObject({
      blockNumber: unsignedDecimal,
      blockHash: hex32,
    }),
    confirmations: positiveDecimal,
    asset: address,
    transfer: z.strictObject({
      from: address,
      to: address,
      value: unsignedDecimal,
      logIndex: z.number().int().nonnegative().safe(),
    }),
    authorizationUsed: z.strictObject({
      authorizer: address,
      nonce: hex32,
      logIndex: z.number().int().nonnegative().safe(),
    }),
    observedAt: z.string().datetime({ offset: true }),
  }),
  confirmationPolicy: z.strictObject({
    type: z.literal("minimum-confirmations"),
    headTag: PublicEvmHeadTagSchema,
    minimumConfirmations: positiveDecimal,
  }),
});

export const PublicEvmSettlementEvidenceV02Schema = PublicEvmSettlementEvidenceV02BodySchema.extend(
  {
    recordDigest: z.strictObject({
      algorithm: z.literal("sha-256"),
      canonicalization: z.literal("RFC8785"),
      value: base64UrlSha256,
    }),
  },
);

export const AnyPublicEvmSettlementEvidenceSchema = z.discriminatedUnion("evidenceVersion", [
  PublicEvmSettlementEvidenceV01Schema,
  PublicEvmSettlementEvidenceV02Schema,
]);

// Preserve the 0.1 schema export; use AnyPublicEvmSettlementEvidenceSchema for version dispatch.
export const PublicEvmSettlementEvidenceSchema = PublicEvmSettlementEvidenceV01Schema;

export interface PublicEvmSettlementVerificationOptions {
  verifierProvenance: PublicEvmVerifierProvenance;
  headTag?: PublicEvmHeadTag;
  minimumConfirmations?: bigint;
}

export interface PublicEvmConsumerPolicy {
  maximumObservationAgeSeconds: bigint;
  minimumConfirmations: bigint;
  allowedHeadTags: readonly PublicEvmHeadTag[];
  trustedVerifierProvenance: Pick<
    PublicEvmVerifierProvenance,
    "operator" | "repositoryUrl" | "commit"
  >;
  reread: "always" | "if-policy-unsatisfied" | "never";
}

export type PublicEvmRecordAcceptancePolicy = PublicEvmConsumerPolicy;

export interface PublicEvmConsumerAssessmentContext {
  evidenceRecordDigest: string;
  evaluatedAt: string;
  policy: {
    maximumObservationAgeSeconds: string;
    minimumConfirmations: string;
    allowedHeadTags: PublicEvmHeadTag[];
    trustedVerifierProvenance: Pick<
      PublicEvmVerifierProvenance,
      "operator" | "repositoryUrl" | "commit"
    >;
    reread: "always" | "if-policy-unsatisfied" | "never";
  };
}

export interface PublicEvmConsumerAssessment {
  assessmentVersion: "pulse-public-evm-consumer-assessment/0.1";
  context: PublicEvmConsumerAssessmentContext | null;
  accepted: boolean;
  rereadRequired: boolean;
  errors: string[];
}

export function publicEvmSettlementEvidenceDigest(
  evidence: PublicEvmSettlementEvidenceV02Body,
): string {
  return canonicalSha256Base64Url(evidence);
}

function topicAddress(topic: Hex | undefined): Address | undefined {
  if (topic === undefined || !/^0x[0-9a-fA-F]{64}$/.test(topic)) return undefined;
  return `0x${topic.slice(-40)}` as Address;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function requireEqual(
  errors: string[],
  path: string,
  actual: string | number,
  expected: string | number,
  hex = false,
): void {
  const matches =
    hex && typeof actual === "string" && typeof expected === "string"
      ? sameHex(actual, expected)
      : actual === expected;
  if (!matches) errors.push(`${path}: Does not match the supplied conformance case`);
}

export async function verifyPublicEvmSettlementRecord(
  caseInput: unknown,
  evidenceInput: unknown,
): Promise<EvidenceRecordValidationReport> {
  const caseResult = ConformanceCaseSchema.safeParse(caseInput);
  if (!caseResult.success) {
    return {
      valid: false,
      automatedChecksPassed: false,
      errors: issueMessages(caseResult.error).map((message) => `case.${message}`),
    };
  }
  const evidenceResult = AnyPublicEvmSettlementEvidenceSchema.safeParse(evidenceInput);
  if (!evidenceResult.success) {
    return {
      valid: false,
      automatedChecksPassed: false,
      errors: issueMessages(evidenceResult.error),
    };
  }

  const conformanceCase = caseResult.data;
  const evidence = evidenceResult.data;
  const report = await verifyConformanceCase(conformanceCase);
  const errors: string[] = [];
  if (!report.consistent || !conformanceCase.expected.consistent) {
    errors.push("case: Public settlement evidence requires an accepted offline case");
  }

  const requirements = conformanceCase.x402.requirements;
  const authorization = conformanceCase.x402.payload.payload.authorization;
  const expectedChainId = Number(requirements.network.slice("eip155:".length));
  if (evidence.evidenceVersion === "pulse-public-evm-settlement/0.1") {
    requireEqual(errors, "caseId", evidence.caseId, conformanceCase.id);
    requireEqual(errors, "caseInputHash", evidence.caseInputHash, conformanceCase.inputHash);
    requireEqual(errors, "network", evidence.network, requirements.network);
    requireEqual(errors, "chainId", evidence.chainId, expectedChainId);
    requireEqual(
      errors,
      "transactionHash",
      evidence.transactionHash,
      conformanceCase.x402.settlement.transaction,
      true,
    );
    requireEqual(errors, "asset", evidence.asset, requirements.asset, true);
    requireEqual(errors, "transfer.from", evidence.transfer.from, authorization.from, true);
    requireEqual(errors, "transfer.to", evidence.transfer.to, authorization.to, true);
    requireEqual(errors, "transfer.value", evidence.transfer.value, authorization.value);
    requireEqual(
      errors,
      "authorizationUsed.authorizer",
      evidence.authorizationUsed.authorizer,
      authorization.from,
      true,
    );
    requireEqual(
      errors,
      "authorizationUsed.nonce",
      evidence.authorizationUsed.nonce,
      authorization.nonce,
      true,
    );
  } else {
    const agreement = evidence.offlineArtifactAgreement;
    const observation = evidence.settlementObservation;
    requireEqual(errors, "offlineArtifactAgreement.caseId", agreement.caseId, conformanceCase.id);
    requireEqual(
      errors,
      "offlineArtifactAgreement.caseVersion",
      agreement.caseVersion,
      conformanceCase.caseVersion,
    );
    requireEqual(
      errors,
      "offlineArtifactAgreement.caseInputHash",
      agreement.caseInputHash,
      conformanceCase.inputHash,
    );
    if (!canonicalValuesEqual(agreement.sourcePins, conformanceCase.sourcePins)) {
      errors.push(
        "offlineArtifactAgreement.sourcePins: Does not match the supplied conformance case",
      );
    }
    requireEqual(
      errors,
      "settlementObservation.network",
      observation.network,
      requirements.network,
    );
    requireEqual(errors, "settlementObservation.chainId", observation.chainId, expectedChainId);
    requireEqual(
      errors,
      "settlementObservation.transactionHash",
      observation.transactionHash,
      conformanceCase.x402.settlement.transaction,
      true,
    );
    requireEqual(
      errors,
      "settlementObservation.asset",
      observation.asset,
      requirements.asset,
      true,
    );
    requireEqual(
      errors,
      "settlementObservation.transfer.from",
      observation.transfer.from,
      authorization.from,
      true,
    );
    requireEqual(
      errors,
      "settlementObservation.transfer.to",
      observation.transfer.to,
      authorization.to,
      true,
    );
    requireEqual(
      errors,
      "settlementObservation.transfer.value",
      observation.transfer.value,
      authorization.value,
    );
    requireEqual(
      errors,
      "settlementObservation.authorizationUsed.authorizer",
      observation.authorizationUsed.authorizer,
      authorization.from,
      true,
    );
    requireEqual(
      errors,
      "settlementObservation.authorizationUsed.nonce",
      observation.authorizationUsed.nonce,
      authorization.nonce,
      true,
    );

    const receiptBlockNumber = BigInt(observation.receipt.blockNumber);
    const observedHeadNumber = BigInt(observation.observedHead.blockNumber);
    const confirmations = BigInt(observation.confirmations);
    const minimumConfirmations = BigInt(evidence.confirmationPolicy.minimumConfirmations);
    if (observedHeadNumber < receiptBlockNumber) {
      errors.push("settlementObservation.observedHead.blockNumber: Precedes the receipt block");
    } else if (confirmations !== observedHeadNumber - receiptBlockNumber + 1n) {
      errors.push(
        "settlementObservation.confirmations: Does not equal observed head minus receipt block plus one",
      );
    }
    if (confirmations < minimumConfirmations) {
      errors.push(
        "settlementObservation.confirmations: Does not satisfy confirmationPolicy.minimumConfirmations",
      );
    }
    if (observation.transfer.logIndex === observation.authorizationUsed.logIndex) {
      errors.push("settlementObservation: Transfer and AuthorizationUsed log indexes must differ");
    }

    const { recordDigest, ...digestInput } = evidence;
    const expectedDigest = publicEvmSettlementEvidenceDigest(
      digestInput as PublicEvmSettlementEvidenceV02Body,
    );
    if (recordDigest.value !== expectedDigest) {
      errors.push("recordDigest.value: Does not match the canonical evidence body");
    }
  }

  return {
    valid: errors.length === 0,
    automatedChecksPassed: errors.length === 0,
    errors,
  };
}

const PublicEvmConsumerPolicySchema = z.strictObject({
  maximumObservationAgeSeconds: z.bigint().nonnegative(),
  minimumConfirmations: z.bigint().positive(),
  allowedHeadTags: z.array(PublicEvmHeadTagSchema).min(1),
  trustedVerifierProvenance: z.strictObject({
    operator: z.string().refine((value) => value.trim().length > 0),
    repositoryUrl: credentialFreeHttpsUrl,
    commit: gitCommit,
  }),
  reread: z.enum(["always", "if-policy-unsatisfied", "never"]),
});

export async function assessPublicEvmSettlementV02(
  caseInput: unknown,
  evidenceInput: unknown,
  policyInput: PublicEvmConsumerPolicy,
  evaluatedAt = new Date(),
): Promise<PublicEvmConsumerAssessment> {
  const recordReport = await verifyPublicEvmSettlementRecord(caseInput, evidenceInput);
  if (!recordReport.automatedChecksPassed) {
    return {
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: recordReport.errors,
    };
  }
  const evidenceResult = PublicEvmSettlementEvidenceV02Schema.safeParse(evidenceInput);
  if (!evidenceResult.success) {
    return {
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: ["evidenceVersion: Consumer assessment requires a 0.2 evidence record"],
    };
  }
  const policyResult = PublicEvmConsumerPolicySchema.safeParse(policyInput);
  if (!policyResult.success) {
    return {
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: issueMessages(policyResult.error).map((message) => `policy.${message}`),
    };
  }
  if (!Number.isFinite(evaluatedAt.getTime())) {
    return {
      assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
      context: null,
      accepted: false,
      rereadRequired: false,
      errors: ["evaluatedAt: Expected a valid date"],
    };
  }

  const evidence = evidenceResult.data;
  const policy = policyResult.data;
  const context: PublicEvmConsumerAssessmentContext = {
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
  const observation = evidence.settlementObservation;
  const errors: string[] = [];
  const observedAtMilliseconds = BigInt(Date.parse(observation.observedAt));
  const evaluatedAtMilliseconds = BigInt(evaluatedAt.getTime());
  if (observedAtMilliseconds > evaluatedAtMilliseconds) {
    errors.push("settlementObservation.observedAt: Is later than the policy evaluation time");
  } else if (
    evaluatedAtMilliseconds - observedAtMilliseconds >
    policy.maximumObservationAgeSeconds * 1000n
  ) {
    errors.push("settlementObservation.observedAt: Exceeds the maximum observation age");
  }
  if (BigInt(observation.confirmations) < policy.minimumConfirmations) {
    errors.push("settlementObservation.confirmations: Does not satisfy the consumer policy");
  }
  if (!policy.allowedHeadTags.includes(evidence.confirmationPolicy.headTag)) {
    errors.push("confirmationPolicy.headTag: Is not allowed by the consumer policy");
  }
  for (const key of ["operator", "repositoryUrl", "commit"] as const) {
    if (evidence.verifierProvenance[key] !== policy.trustedVerifierProvenance[key]) {
      errors.push(`verifierProvenance.${key}: Does not match the trusted verifier policy`);
    }
  }

  const rereadRequired =
    policy.reread === "always" || (policy.reread === "if-policy-unsatisfied" && errors.length > 0);
  return {
    assessmentVersion: "pulse-public-evm-consumer-assessment/0.1",
    context,
    accepted: errors.length === 0 && !rereadRequired,
    rereadRequired,
    errors,
  };
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

export async function verifyPublicEvmSettlementV02(
  caseInput: unknown,
  reader: PublicEvmV02Reader,
  options: PublicEvmSettlementVerificationOptions,
): Promise<PublicEvmSettlementEvidenceV02> {
  const minimumConfirmations = options.minimumConfirmations ?? 1n;
  if (minimumConfirmations < 1n) {
    throw new PublicEvmEvidenceError("Minimum confirmations must be at least one.");
  }
  const headTagResult = PublicEvmHeadTagSchema.safeParse(options.headTag ?? "latest");
  if (!headTagResult.success) {
    throw new PublicEvmEvidenceError("The selected EVM head tag is not supported.");
  }
  const provenanceResult = PublicEvmVerifierProvenanceSchema.safeParse(options.verifierProvenance);
  if (!provenanceResult.success) {
    throw new PublicEvmEvidenceError("The verifier provenance is not well formed.");
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
  let transaction: Awaited<ReturnType<PublicEvmV02Reader["getTransaction"]>>;
  let receipt: Awaited<ReturnType<PublicEvmV02Reader["getTransactionReceipt"]>>;
  try {
    [chainId, transaction, receipt] = await Promise.all([
      reader.getChainId(),
      reader.getTransaction({ hash: transactionHash }),
      reader.getTransactionReceipt({ hash: transactionHash }),
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

  let observedHead: Awaited<ReturnType<PublicEvmV02Reader["getBlock"]>>;
  try {
    observedHead = await reader.getBlock({ blockTag: headTagResult.data });
  } catch {
    throw new PublicEvmEvidenceError("Unable to read the selected public EVM head.");
  }
  const observedAt = new Date().toISOString();
  if (observedHead.number === null || observedHead.hash === null) {
    throw new PublicEvmEvidenceError("The selected public EVM head is incomplete.");
  }
  if (observedHead.number < receipt.blockNumber) {
    throw new PublicEvmEvidenceError("The selected EVM head precedes the receipt block.");
  }

  let canonicalReceiptBlock: Awaited<ReturnType<PublicEvmV02Reader["getBlock"]>>;
  try {
    canonicalReceiptBlock = await reader.getBlock({ blockNumber: receipt.blockNumber });
  } catch {
    throw new PublicEvmEvidenceError("Unable to re-read the canonical receipt block.");
  }
  if (canonicalReceiptBlock.number === null || canonicalReceiptBlock.hash === null) {
    throw new PublicEvmEvidenceError("The canonical receipt block is incomplete.");
  }
  if (
    canonicalReceiptBlock.number !== receipt.blockNumber ||
    !sameHex(canonicalReceiptBlock.hash, receipt.blockHash)
  ) {
    throw new PublicEvmEvidenceError(
      "The receipt block hash does not match the current canonical block.",
    );
  }
  const confirmations = observedHead.number - receipt.blockNumber + 1n;
  if (confirmations < minimumConfirmations) {
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
  if (transferLog.logIndex === authorizationUsedLog.logIndex) {
    throw new PublicEvmEvidenceError(
      "The Transfer and AuthorizationUsed events cannot share a log index.",
    );
  }

  const body: PublicEvmSettlementEvidenceV02Body = {
    evidenceVersion: "pulse-public-evm-settlement/0.2",
    verifierProvenance: provenanceResult.data,
    offlineArtifactAgreement: {
      consistent: true,
      caseId: conformanceCase.id,
      caseVersion: conformanceCase.caseVersion,
      caseInputHash: conformanceCase.inputHash,
      sourcePins: conformanceCase.sourcePins,
    },
    settlementObservation: {
      network: requirements.network,
      chainId,
      transactionHash,
      receipt: {
        blockNumber: receipt.blockNumber.toString(),
        blockHash: receipt.blockHash,
        status: "success",
      },
      observedHead: {
        blockNumber: observedHead.number.toString(),
        blockHash: observedHead.hash,
      },
      confirmations: confirmations.toString(),
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
      observedAt,
    },
    confirmationPolicy: {
      type: "minimum-confirmations",
      headTag: headTagResult.data,
      minimumConfirmations: minimumConfirmations.toString(),
    },
  };
  const result: PublicEvmSettlementEvidenceV02 = {
    ...body,
    recordDigest: {
      algorithm: "sha-256",
      canonicalization: "RFC8785",
      value: publicEvmSettlementEvidenceDigest(body),
    },
  };
  if (!PublicEvmSettlementEvidenceV02Schema.safeParse(result).success) {
    throw new PublicEvmEvidenceError("The public RPC returned malformed settlement evidence.");
  }
  return result;
}
