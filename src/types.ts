import { z } from "zod";
import { CONFORMANCE_FAILURE_CODES, type ConformanceFailure } from "./failures.js";

const evmAddress = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const transactionHash = bytes32;
const signature = z.string().regex(/^0x[0-9a-fA-F]{130}$/);
const unsignedInteger = z.string().regex(/^(0|[1-9][0-9]*)$/);
const caip2EvmNetwork = z.string().superRefine((value, context) => {
  const match = /^eip155:([1-9][0-9]*)$/.exec(value);
  if (match === null) {
    context.addIssue({ code: "custom", message: "Expected a positive decimal eip155 CAIP-2 ID" });
    return;
  }
  const chainId = match[1];
  if (chainId === undefined || BigInt(chainId) > BigInt(Number.MAX_SAFE_INTEGER)) {
    context.addIssue({
      code: "custom",
      message: "EVM chain ID must fit in a JavaScript safe integer",
    });
  }
});
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
type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
const JsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(JsonValueSchema),
    z.record(z.string(), JsonValueSchema),
  ]),
);

export const CommerceAmountSchema = z.strictObject({
  amount: z.number().int().nonnegative().safe(),
  currency: z.string().regex(/^[A-Z]{3}$/),
});

export const PublicEs256JwkSchema = z.strictObject({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
  alg: z.literal("ES256"),
  kid: z.string().min(1),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  y: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

export const Eip712DomainSchema = z.strictObject({
  name: z.string().min(1),
  version: z.string().min(1),
});

export const X402InstrumentExtensionSchema = z.strictObject({
  version: z.literal(2),
  scheme: z.literal("exact"),
  network: caip2EvmNetwork,
  asset: evmAddress,
  amount: unsignedInteger,
  payTo: evmAddress,
  payer: evmAddress,
  ap2PayeeId: z.string().min(1),
  ap2PaymentAmount: CommerceAmountSchema,
  maxTimeoutSeconds: z.number().int().positive().safe(),
  eip712Domain: Eip712DomainSchema,
  nonceBinding: z.literal("base64url-decode-ap2-mandate-reference"),
});

export const PaymentInstrumentSchema = z.strictObject({
  id: z.string().min(1),
  type: z.literal("x402"),
  description: z.string().optional(),
  x402: X402InstrumentExtensionSchema,
});

export const MerchantSchema = z.strictObject({
  id: z.string().min(1),
  name: z.string().min(1),
  website: z.string().url().optional(),
});

export const PispSchema = z.strictObject({
  legal_name: z.string().min(1),
  brand_name: z.string().min(1),
  domain_name: z.string().min(1),
});

export const ClosedPaymentMandateSchema = z.strictObject({
  vct: z.literal("mandate.payment.1"),
  transaction_id: base64UrlSha256,
  payee: MerchantSchema,
  payment_amount: CommerceAmountSchema,
  payment_instrument: PaymentInstrumentSchema,
  pisp: PispSchema.optional(),
  execution_date: z.string().datetime({ offset: true }).optional(),
  risk_data: z.record(z.string(), JsonValueSchema).optional(),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
});

export const AllowedPaymentInstrumentsConstraintSchema = z.strictObject({
  type: z.literal("payment.allowed_payment_instruments"),
  allowed: z
    .array(
      z.strictObject({
        id: z.string().min(1),
        type: z.string().min(1),
        description: z.string().optional(),
        x402: JsonValueSchema.optional(),
      }),
    )
    .min(1),
});

export const PaymentReferenceConstraintSchema = z.strictObject({
  type: z.literal("payment.reference"),
  conditional_transaction_id: base64UrlSha256,
});

export const AmountRangeConstraintSchema = z.strictObject({
  type: z.literal("payment.amount_range"),
  currency: z.string().regex(/^[A-Z]{3}$/),
  max: z.number().int().nonnegative().safe(),
  min: z.number().int().nonnegative().safe().optional(),
});

export const AllowedPayeesConstraintSchema = z.strictObject({
  type: z.literal("payment.allowed_payees"),
  allowed: z.array(MerchantSchema).min(1),
});

const UnsupportedPaymentConstraintSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("payment.agent_recurrence"),
    frequency: z.enum([
      "ON_DEMAND",
      "DAILY",
      "WEEKLY",
      "BIWEEKLY",
      "MONTHLY",
      "QUARTERLY",
      "ANNUALLY",
    ]),
    max_occurrences: z.number().int().nonnegative().optional(),
  }),
  z.strictObject({
    type: z.literal("payment.allowed_pisps"),
    allowed: z.array(PispSchema).min(1),
  }),
  z.strictObject({
    type: z.literal("payment.budget"),
    max: z.number().nonnegative(),
    currency: z.string().regex(/^[A-Z]{3}$/),
  }),
  z
    .strictObject({
      type: z.literal("payment.execution_date"),
      not_before: z.string().datetime({ offset: true }).optional(),
      not_after: z.string().datetime({ offset: true }).optional(),
    })
    .superRefine((constraint, context) => {
      if (
        constraint.not_before !== undefined &&
        constraint.not_after !== undefined &&
        Date.parse(constraint.not_before) > Date.parse(constraint.not_after)
      ) {
        context.addIssue({
          code: "custom",
          path: ["not_after"],
          message: "payment.execution_date not_after must not precede not_before",
        });
      }
    }),
]);

export const OpenPaymentConstraintSchema = z.union([
  PaymentReferenceConstraintSchema,
  AllowedPaymentInstrumentsConstraintSchema,
  AmountRangeConstraintSchema,
  AllowedPayeesConstraintSchema,
  UnsupportedPaymentConstraintSchema,
]);

export const OpenPaymentMandateSchema = z
  .strictObject({
    vct: z.literal("mandate.payment.open.1"),
    constraints: z.array(OpenPaymentConstraintSchema).min(1),
    cnf: z.strictObject({ jwk: PublicEs256JwkSchema }),
    payee: MerchantSchema.optional(),
    payment_amount: CommerceAmountSchema.optional(),
    payment_instrument: PaymentInstrumentSchema.optional(),
    execution_date: z.string().datetime({ offset: true }).optional(),
    pisp: PispSchema.optional(),
    risk_data: z.record(z.string(), JsonValueSchema).optional(),
    iat: z.number().int().nonnegative(),
    exp: z.number().int().positive(),
  })
  .superRefine((mandate, context) => {
    if (!mandate.constraints.some((constraint) => constraint.type === "payment.reference")) {
      context.addIssue({
        code: "custom",
        path: ["constraints"],
        message: "Open Payment Mandate requires a payment.reference constraint",
      });
    }
  });

export const PaymentReceiptSchema = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("Success"),
    iss: z.string().min(1),
    iat: z.number().int().nonnegative(),
    reference: base64UrlSha256,
    payment_id: z.string().min(1),
    psp_confirmation_id: z.string().min(1),
    network_confirmation_id: transactionHash,
    error: z.null().optional(),
    error_description: z.null().optional(),
  }),
  z.strictObject({
    status: z.literal("Error"),
    iss: z.string().min(1),
    iat: z.number().int().nonnegative(),
    reference: base64UrlSha256,
    payment_id: z.string().min(1),
    psp_confirmation_id: z.null().optional(),
    network_confirmation_id: z.null().optional(),
    error: z.string().min(1),
    error_description: z.string().min(1),
  }),
]);

export const Ap2CryptographicEvidenceSchema = z.strictObject({
  mandateChain: z.string().min(1),
  paymentReceiptJwt: z.string().min(1),
  trustedRootPublicJwk: PublicEs256JwkSchema,
  trustedReceiptPublicJwk: PublicEs256JwkSchema,
  expectedAudience: z.string().min(1),
  expectedNonce: z.string().min(1),
});

export const Ap2VerificationRecordSchema = z.strictObject({
  verifier: z.string().min(1),
  verifiedAtEpochSeconds: z.number().int().positive(),
  clockSkewSeconds: z.number().int().nonnegative().max(300),
  openCheckoutReference: base64UrlSha256,
  closedMandateClaimsHash: base64UrlSha256,
  openMandateClaimsHash: base64UrlSha256,
  closedMandateReference: base64UrlSha256,
  cryptographicEvidence: Ap2CryptographicEvidenceSchema,
});

export const Ap2AuthorizationRecordSchema = z.strictObject({
  closedMandate: ClosedPaymentMandateSchema,
  openMandate: OpenPaymentMandateSchema,
  paymentReceipt: PaymentReceiptSchema,
  verification: Ap2VerificationRecordSchema,
});

export const X402ExtraSchema = z.strictObject({
  name: z.string().min(1),
  version: z.string().min(1),
  assetTransferMethod: z.literal("eip3009"),
  ap2MandateReference: base64UrlSha256,
  ap2NonceDerivation: z.literal("base64url-decode-ap2-mandate-reference"),
});

export const X402PaymentRequirementsSchema = z.strictObject({
  scheme: z.string().min(1),
  network: caip2EvmNetwork,
  asset: evmAddress,
  amount: unsignedInteger,
  payTo: evmAddress,
  maxTimeoutSeconds: z.number().int().positive().safe(),
  extra: X402ExtraSchema,
});

export const Eip3009AuthorizationRecordSchema = z.strictObject({
  signature,
  authorization: z.strictObject({
    from: evmAddress,
    to: evmAddress,
    value: unsignedInteger,
    validAfter: unsignedInteger,
    validBefore: unsignedInteger,
    nonce: bytes32,
  }),
});

const printableAscii = /^[\x20-\x7e]+$/;

export const X402ResourceInfoSchema = z.strictObject({
  url: z.string().min(1),
  description: z.string().nullable().optional(),
  mimeType: z.string().nullable().optional(),
  serviceName: z.string().min(1).max(32).regex(printableAscii).nullable().optional(),
  tags: z.array(z.string().min(1).max(32).regex(printableAscii)).max(5).nullable().optional(),
  iconUrl: z.string().max(2048).nullable().optional(),
});

export const X402PaymentPayloadSchema = z.strictObject({
  x402Version: z.literal(2),
  resource: X402ResourceInfoSchema,
  accepted: X402PaymentRequirementsSchema,
  payload: Eip3009AuthorizationRecordSchema,
  extensions: z.record(z.string(), JsonValueSchema).optional(),
});

export const X402SettlementSchema = z.strictObject({
  success: z.boolean(),
  errorReason: z.string().optional(),
  errorMessage: z.string().optional(),
  payer: evmAddress,
  transaction: z.string(),
  network: caip2EvmNetwork,
  amount: unsignedInteger.optional(),
  extensions: z.record(z.string(), JsonValueSchema).optional(),
  extra: z.record(z.string(), JsonValueSchema).optional(),
});

export const X402PaymentRecordSchema = z.strictObject({
  requirements: X402PaymentRequirementsSchema,
  payload: X402PaymentPayloadSchema,
  settlement: X402SettlementSchema,
});

export const ExpectedResultSchema = z.strictObject({
  consistent: z.boolean(),
  failureCodes: z.array(z.enum(CONFORMANCE_FAILURE_CODES)),
});

export const SourcePinsSchema = z.strictObject({
  ap2Commit: z.literal("e1ea56db72a6385bce3e5c1112b3a56ce60acb43"),
  x402Commit: z.literal("67b1ba0a7abbd7907a28fa624670872532e0eae9"),
  x402PackageVersion: z.literal("2.19.0"),
});

export const ConformanceCaseSchema = z.strictObject({
  caseVersion: z.literal("ap2-x402-conformance/0.1"),
  sourcePins: SourcePinsSchema,
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  description: z.string().min(1),
  nowEpochSeconds: z.number().int().positive(),
  ap2: Ap2AuthorizationRecordSchema,
  x402: X402PaymentRecordSchema,
  inputHash: base64UrlSha256,
  expected: ExpectedResultSchema,
});

export const ConformanceBundleSchema = z.strictObject({
  bundleVersion: z.literal("ap2-x402-conformance-bundle/0.1"),
  generatedAt: z.string().datetime({ offset: true }),
  sourcePins: SourcePinsSchema,
  cases: z.array(z.unknown()).length(80),
});

export interface ConformanceReport {
  caseId: string | null;
  consistent: boolean;
  computed: {
    closedMandateClaimsHash?: string;
    openMandateClaimsHash?: string;
    closedMandateReference?: string;
    inputHash?: string;
    expectedNonce?: string;
    recoveredSigner?: string;
  };
  failures: ConformanceFailure[];
}

export interface BundleCaseReport {
  id: string | null;
  expectationMatched: boolean;
  expectedConsistent: boolean | null;
  expectedFailureCodes: string[];
  report: ConformanceReport;
}

export interface BundleVerificationReport {
  allExpectationsMatched: boolean;
  total: number;
  passedExpectations: number;
  failedExpectations: number;
  cases: BundleCaseReport[];
}

export type ConformanceCase = z.infer<typeof ConformanceCaseSchema>;
export type ConformanceBundle = z.infer<typeof ConformanceBundleSchema>;
export type Ap2AuthorizationRecord = z.infer<typeof Ap2AuthorizationRecordSchema>;
export type X402PaymentRecord = z.infer<typeof X402PaymentRecordSchema>;
export type Eip3009AuthorizationRecord = z.infer<typeof Eip3009AuthorizationRecordSchema>;
export type OfflineVerificationBoundary = {
  readsLocalJsonOnly: true;
  usesPrivateKeys: false;
  usesNetwork: false;
  submitsTransactions: false;
};

export const OFFLINE_VERIFICATION_BOUNDARY: OfflineVerificationBoundary = {
  readsLocalJsonOnly: true,
  usesPrivateKeys: false,
  usesNetwork: false,
  submitsTransactions: false,
};
