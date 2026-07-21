import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Address, type Hex, keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";
import { canonicalSha256Base64Url, conformanceInputHash } from "../src/canonical.js";
import type { ConformanceFailureCode } from "../src/failures.js";
import {
  ClosedPaymentMandateSchema,
  type ConformanceBundle,
  ConformanceBundleSchema,
  type ConformanceCase,
  OpenPaymentMandateSchema,
  PaymentReceiptSchema,
  PublicEs256JwkSchema,
  X402PaymentPayloadSchema,
} from "../src/types.js";
import { verifyConformanceBundle, verifyConformanceCase } from "../src/verifier.js";
import { createAp2BoundX402PaymentPayload } from "../src/x402-producer.js";

const GENERATED_AT = "2026-07-21T00:00:00.000Z";
const NOW_EPOCH_SECONDS = Date.parse(GENERATED_AT) / 1_000;
const VALID_CASE_COUNT = 20;
const INVALID_CASE_COUNT = 60;
const MAX_TIMEOUT_SECONDS = 300;
const BASE_SEPOLIA_NETWORK = "eip155:84532";
const LOCAL_NETWORK = "eip155:31337";
const SOURCE_PINS = {
  ap2Commit: "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
  x402Commit: "67b1ba0a7abbd7907a28fa624670872532e0eae9",
  x402PackageVersion: "2.19.0",
} as const;

const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

// These labels intentionally make the fixture-only signing keys public and reproducible.
// Never derive production keys from labels or other public material.
const FIXTURE_PAYER_LABEL = "pulse-ap2-x402-conformance/public-fixture-payer/v1";
const ALTERNATE_PAYER_LABEL = "pulse-ap2-x402-conformance/public-fixture-alternate/v1";
const fixturePayer = privateKeyToAccount(keccak256(stringToHex(FIXTURE_PAYER_LABEL)));
const alternatePayer = privateKeyToAccount(keccak256(stringToHex(ALTERNATE_PAYER_LABEL)));

type FixtureAccount = typeof fixturePayer;

interface MutationDefinition {
  slug: string;
  description: string;
  failureCodes: ConformanceFailureCode[];
  mutate: (draft: ConformanceCase) => Promise<void> | void;
}

type AllowedInstrumentConstraint = Extract<
  ConformanceCase["ap2"]["openMandate"]["constraints"][number],
  { type: "payment.allowed_payment_instruments" }
>;
type AllowedInstrument = AllowedInstrumentConstraint["allowed"][number];

const NormalizedRecordSchema = z.strictObject({
  id: z.string().min(1),
  closedMandate: ClosedPaymentMandateSchema,
  openMandate: OpenPaymentMandateSchema,
  paymentReceipt: PaymentReceiptSchema,
  verification: z.looseObject({
    verifier: z.string().min(1),
    verifiedAtEpochSeconds: z.number().int().positive(),
    clockSkewSeconds: z.number().int().nonnegative(),
    openCheckoutReference: z.string().min(1),
    closedMandateClaimsHash: z.string().min(1),
    openMandateClaimsHash: z.string().min(1),
    closedMandateReference: z.string().min(1),
  }),
});

const NormalizedBundleSchema = z.looseObject({
  records: z.array(NormalizedRecordSchema).length(VALID_CASE_COUNT),
});

const SignedArtifactCaseSchema = z.looseObject({
  id: z.string().min(1),
  nowEpochSeconds: z.number().int().positive(),
  expectedAudience: z.string().min(1),
  expectedNonce: z.string().min(1),
  openCheckoutReference: z.string().min(1),
  artifacts: z.strictObject({
    openPaymentMandateSdJwt: z.string().min(1),
    closedPaymentMandateChain: z.string().min(1),
    closedPaymentMandateLeafJwt: z.string().min(1),
    closedPaymentMandateReference: z.string().min(1),
    paymentReceiptJwt: z.string().min(1),
  }),
});

const SignedArtifactBundleSchema = z.looseObject({
  publicKeys: z.looseObject({
    openMandateIssuer: PublicEs256JwkSchema,
    paymentReceiptIssuer: PublicEs256JwkSchema,
  }),
  cases: z.array(SignedArtifactCaseSchema).length(VALID_CASE_COUNT),
});

type NormalizedRecord = z.infer<typeof NormalizedRecordSchema>;
type SignedArtifactCase = z.infer<typeof SignedArtifactCaseSchema>;
type SignedArtifactBundle = z.infer<typeof SignedArtifactBundleSchema>;

function sha256Base64Url(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

function sha256Hex(value: string): `0x${string}` {
  return `0x${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function corruptJwtSignature(compactSerialization: string): string {
  const firstDot = compactSerialization.indexOf(".");
  const secondDot = compactSerialization.indexOf(".", firstDot + 1);
  const signatureStart = secondDot + 1;
  const signatureEndCandidate = compactSerialization.indexOf("~", signatureStart);
  const signatureEnd =
    signatureEndCandidate === -1 ? compactSerialization.length : signatureEndCandidate;
  if (firstDot <= 0 || secondDot <= firstDot || signatureEnd <= signatureStart) {
    throw new Error("Cannot corrupt malformed compact JWT serialization.");
  }
  const original = compactSerialization[signatureStart];
  const replacement = original === "A" ? "B" : "A";
  return `${compactSerialization.slice(0, signatureStart)}${replacement}${compactSerialization.slice(signatureStart + 1)}`;
}

function corruptRootSignature(mandateChain: string): string {
  const separatorIndex = mandateChain.indexOf("~~");
  if (separatorIndex <= 0) throw new Error("Cannot corrupt malformed AP2 mandate chain.");
  return `${corruptJwtSignature(mandateChain.slice(0, separatorIndex))}${mandateChain.slice(separatorIndex)}`;
}

function addressFromLabel(label: string): Address {
  return `0x${createHash("sha256").update(label, "utf8").digest("hex").slice(-40)}`;
}

function alternateNetwork(network: string): string {
  return network === BASE_SEPOLIA_NETWORK ? LOCAL_NETWORK : BASE_SEPOLIA_NETWORK;
}

function updateAcceptedRequirements(draft: ConformanceCase): void {
  draft.x402.payload.accepted = structuredClone(draft.x402.requirements);
}

function firstAllowedInstrument(draft: ConformanceCase): AllowedInstrument {
  const constraint = draft.ap2.openMandate.constraints.find(
    (candidate): candidate is AllowedInstrumentConstraint =>
      candidate.type === "payment.allowed_payment_instruments",
  );
  const instrument = constraint?.allowed[0];
  if (!instrument) throw new Error("The fixture template has no allowed payment instrument.");
  return instrument;
}

async function signAuthorization(
  draft: ConformanceCase,
  account: FixtureAccount = fixturePayer,
): Promise<void> {
  const { requirements } = draft.x402;
  const { authorization } = draft.x402.payload.payload;
  draft.x402.payload.payload.signature = await account.signTypedData({
    domain: {
      name: requirements.extra.name,
      version: requirements.extra.version,
      chainId: Number(requirements.network.slice("eip155:".length)),
      verifyingContract: requirements.asset as Address,
    },
    types: TRANSFER_WITH_AUTHORIZATION_TYPES,
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
}

async function createValidCase(
  normalized: NormalizedRecord,
  signed: SignedArtifactCase,
  signedBundle: SignedArtifactBundle,
): Promise<ConformanceCase> {
  if (normalized.id !== signed.id) {
    throw new Error(`Signed and normalized AP2 case IDs differ: ${normalized.id}/${signed.id}`);
  }
  const { closedMandate, openMandate, paymentReceipt } = normalized;
  if (paymentReceipt.status !== "Success") {
    throw new Error(`The valid AP2 fixture ${normalized.id} does not contain a success receipt.`);
  }
  const instrument = closedMandate.payment_instrument.x402;
  if (instrument.payer.toLowerCase() !== fixturePayer.address.toLowerCase()) {
    throw new Error(`Fixture payer key does not match signed AP2 case ${normalized.id}.`);
  }
  if (signed.nowEpochSeconds !== normalized.verification.verifiedAtEpochSeconds) {
    throw new Error(`Signed and normalized verification times differ for ${normalized.id}.`);
  }
  if (signed.openCheckoutReference !== normalized.verification.openCheckoutReference) {
    throw new Error(`Signed and normalized Checkout references differ for ${normalized.id}.`);
  }
  if (
    signed.artifacts.closedPaymentMandateReference !==
    normalized.verification.closedMandateReference
  ) {
    throw new Error(`Signed and normalized closed-mandate references differ for ${normalized.id}.`);
  }

  const closedMandateReference = signed.artifacts.closedPaymentMandateReference;
  const requirements = {
    scheme: instrument.scheme,
    network: instrument.network,
    asset: instrument.asset,
    amount: instrument.amount,
    payTo: instrument.payTo,
    maxTimeoutSeconds: instrument.maxTimeoutSeconds,
    extra: {
      name: instrument.eip712Domain.name,
      version: instrument.eip712Domain.version,
      assetTransferMethod: "eip3009" as const,
      ap2MandateReference: closedMandateReference,
      ap2NonceDerivation: "base64url-decode-ap2-mandate-reference" as const,
    },
  };
  const validBefore = Math.min(
    signed.nowEpochSeconds + instrument.maxTimeoutSeconds,
    closedMandate.exp,
    openMandate.exp,
  );
  const payload = X402PaymentPayloadSchema.parse(
    await createAp2BoundX402PaymentPayload({
      paymentRequired: {
        x402Version: 2,
        resource: {
          url: `https://fixtures.example/pulse-ap2-x402/${normalized.id}`,
          description: `Synthetic conformance resource for ${normalized.id}`,
          mimeType: "application/json",
        },
        accepts: [requirements],
      },
      fixtureSigner: fixturePayer,
      closedMandateReference,
      validAfter: String(signed.nowEpochSeconds - 30),
      validBefore: String(validBefore),
    }),
  );

  const conformanceCase: ConformanceCase = {
    caseVersion: "ap2-x402-conformance/0.1",
    sourcePins: SOURCE_PINS,
    id: normalized.id,
    description: `Cryptographically signed AP2 to x402 EIP-3009 consistency fixture ${normalized.id}.`,
    nowEpochSeconds: signed.nowEpochSeconds,
    ap2: {
      closedMandate: structuredClone(closedMandate),
      openMandate: structuredClone(openMandate),
      paymentReceipt: structuredClone(paymentReceipt),
      verification: {
        verifier: normalized.verification.verifier,
        verifiedAtEpochSeconds: normalized.verification.verifiedAtEpochSeconds,
        clockSkewSeconds: normalized.verification.clockSkewSeconds,
        openCheckoutReference: normalized.verification.openCheckoutReference,
        closedMandateClaimsHash: normalized.verification.closedMandateClaimsHash,
        openMandateClaimsHash: normalized.verification.openMandateClaimsHash,
        closedMandateReference: normalized.verification.closedMandateReference,
        cryptographicEvidence: {
          mandateChain: signed.artifacts.closedPaymentMandateChain,
          paymentReceiptJwt: signed.artifacts.paymentReceiptJwt,
          trustedRootPublicJwk: structuredClone(signedBundle.publicKeys.openMandateIssuer),
          trustedReceiptPublicJwk: structuredClone(signedBundle.publicKeys.paymentReceiptIssuer),
          expectedAudience: signed.expectedAudience,
          expectedNonce: signed.expectedNonce,
        },
      },
    },
    x402: {
      requirements,
      payload,
      settlement: {
        success: true,
        payer: instrument.payer,
        transaction: paymentReceipt.network_confirmation_id,
        network: instrument.network,
      },
    },
    inputHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    expected: {
      consistent: true,
      failureCodes: [],
    },
  };
  conformanceCase.inputHash = conformanceInputHash(conformanceCase);
  return conformanceCase;
}

const mutations: MutationDefinition[] = [
  {
    slug: "ap2-open-signature-invalid",
    description: "rejects an invalid Open Payment Mandate SD-JWT signature",
    failureCodes: ["AP2_OPEN_MANDATE_UNVERIFIED"],
    mutate: (draft) => {
      const evidence = draft.ap2.verification.cryptographicEvidence;
      evidence.mandateChain = corruptRootSignature(evidence.mandateChain);
    },
  },
  {
    slug: "ap2-key-binding-invalid",
    description: "rejects a terminal mandate whose nonce differs from the verification context",
    failureCodes: ["AP2_KEY_BINDING_UNVERIFIED"],
    mutate: (draft) => {
      draft.ap2.verification.cryptographicEvidence.expectedNonce = `wrong-${draft.ap2.verification.cryptographicEvidence.expectedNonce}`;
    },
  },
  {
    slug: "ap2-claims-hashes-mismatch",
    description: "rejects closed- and open-mandate claims changed after token extraction",
    failureCodes: [
      "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
    ],
    mutate: (draft) => {
      draft.ap2.verification.closedMandateClaimsHash = sha256Base64Url(
        `wrong-closed-claims-hash:${draft.id}`,
      );
      draft.ap2.verification.openMandateClaimsHash = sha256Base64Url(
        `wrong-open-claims-hash:${draft.id}`,
      );
    },
  },
  {
    slug: "ap2-receipt-signature-invalid",
    description: "rejects an invalid AP2 Payment Receipt JWT signature",
    failureCodes: ["AP2_RECEIPT_UNVERIFIED"],
    mutate: (draft) => {
      const evidence = draft.ap2.verification.cryptographicEvidence;
      evidence.paymentReceiptJwt = corruptJwtSignature(evidence.paymentReceiptJwt);
    },
  },
  {
    slug: "ap2-receipt-reference-mismatch",
    description: "rejects mismatched Open Checkout and Payment Receipt references",
    failureCodes: [
      "AP2_RECEIPT_UNVERIFIED",
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_PAYMENT_REFERENCE_MISMATCH",
      "AP2_RECEIPT_REFERENCE_MISMATCH",
    ],
    mutate: (draft) => {
      draft.ap2.paymentReceipt.reference = sha256Base64Url(`wrong-receipt-reference:${draft.id}`);
      const referenceConstraint = draft.ap2.openMandate.constraints.find(
        (constraint) => constraint.type === "payment.reference",
      );
      if (!referenceConstraint || referenceConstraint.type !== "payment.reference") {
        throw new Error("The fixture template has no payment.reference constraint.");
      }
      referenceConstraint.conditional_transaction_id = sha256Base64Url(
        `wrong-open-checkout-reference:${draft.id}`,
      );
      draft.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.openMandate,
      );
    },
  },
  {
    slug: "ap2-receipt-transaction-mismatch",
    description: "rejects AP2 and x402 records that identify different transactions",
    failureCodes: ["AP2_RECEIPT_UNVERIFIED", "AP2_RECEIPT_TRANSACTION_MISMATCH"],
    mutate: (draft) => {
      if (draft.ap2.paymentReceipt.status !== "Success") {
        throw new Error("The fixture template receipt must be successful.");
      }
      draft.ap2.paymentReceipt.network_confirmation_id = sha256Hex(
        `wrong-receipt-transaction:${draft.id}`,
      );
    },
  },
  {
    slug: "ap2-instrument-type-not-allowed",
    description:
      "requires every amount and instrument constraint and rejects a matching ID/type with no x402 extension",
    failureCodes: [
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_CONSTRAINT_VIOLATION",
      "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED",
    ],
    mutate: (draft) => {
      const rejectedInstrument = structuredClone(firstAllowedInstrument(draft));
      rejectedInstrument.x402 = undefined;
      const commerceAmount = draft.ap2.closedMandate.payment_amount;
      draft.ap2.openMandate.constraints.push(
        {
          type: "payment.allowed_payment_instruments",
          allowed: [rejectedInstrument],
        },
        {
          type: "payment.amount_range",
          currency: commerceAmount.currency,
          min: commerceAmount.amount + 1,
          max: commerceAmount.amount + 100,
        },
      );
      draft.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.openMandate,
      );
    },
  },
  {
    slug: "ap2-instrument-x402-extension-missing",
    description:
      "fails closed when the signed AP2 instrument omits its x402 extension and Payment Receipt",
    failureCodes: ["INPUT_SCHEMA_INVALID"],
    mutate: (draft) => {
      (draft.ap2.closedMandate.payment_instrument as { x402?: unknown }).x402 = undefined;
      (draft.ap2 as { paymentReceipt?: unknown }).paymentReceipt = undefined;
    },
  },
  {
    slug: "ap2-instrument-x402-extension-unknown-field",
    description: "fails closed when the signed AP2 x402 extension has an unknown field",
    failureCodes: ["INPUT_SCHEMA_INVALID"],
    mutate: (draft) => {
      const extension = draft.ap2.closedMandate.payment_instrument.x402 as unknown as Record<
        string,
        unknown
      >;
      extension.recipientFallback = draft.x402.requirements.payTo;
    },
  },
  {
    slug: "ap2-x402-scheme-mismatch",
    description:
      "rejects x402 scheme and EIP-712 domain values different from the signed AP2 instrument",
    failureCodes: ["AP2_X402_SCHEME_MISMATCH", "AP2_X402_EIP712_DOMAIN_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.requirements.scheme = "permit2";
      draft.x402.requirements.extra.name = "Different Synthetic Token";
      updateAcceptedRequirements(draft);
      await signAuthorization(draft);
    },
  },
  {
    slug: "ap2-x402-network-mismatch",
    description:
      "rejects an x402 network different from the signed AP2 instrument and settlement record",
    failureCodes: ["AP2_X402_NETWORK_MISMATCH", "SETTLEMENT_NETWORK_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.requirements.network = alternateNetwork(draft.x402.requirements.network);
      updateAcceptedRequirements(draft);
      await signAuthorization(draft);
    },
  },
  {
    slug: "ap2-x402-asset-mismatch",
    description: "rejects an x402 asset different from the signed AP2 instrument",
    failureCodes: ["AP2_X402_ASSET_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.requirements.asset = addressFromLabel(`wrong-asset:${draft.id}`);
      updateAcceptedRequirements(draft);
      await signAuthorization(draft);
    },
  },
  {
    slug: "ap2-x402-amount-mismatch",
    description: "rejects an x402 amount different from the signed AP2 instrument",
    failureCodes: ["AP2_X402_AMOUNT_MISMATCH"],
    mutate: async (draft) => {
      const wrongAmount = String(BigInt(draft.x402.requirements.amount) + 1n);
      draft.x402.requirements.amount = wrongAmount;
      draft.x402.payload.payload.authorization.value = wrongAmount;
      updateAcceptedRequirements(draft);
      await signAuthorization(draft);
    },
  },
  {
    slug: "ap2-x402-payee-mismatch",
    description: "rejects an x402 recipient mismatch and a broken AP2 merchant binding",
    failureCodes: [
      "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_X402_PAYEE_MISMATCH",
      "AP2_X402_COMMERCE_BINDING_MISMATCH",
    ],
    mutate: async (draft) => {
      const wrongPayee = addressFromLabel(`wrong-payee:${draft.id}`);
      draft.x402.requirements.payTo = wrongPayee;
      draft.x402.payload.payload.authorization.to = wrongPayee;
      draft.ap2.closedMandate.payment_instrument.x402.ap2PayeeId = `wrong-${draft.ap2.closedMandate.payee.id}`;
      firstAllowedInstrument(draft).x402 = structuredClone(
        draft.ap2.closedMandate.payment_instrument.x402,
      );
      draft.ap2.verification.closedMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.closedMandate,
      );
      draft.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.openMandate,
      );
      updateAcceptedRequirements(draft);
      await signAuthorization(draft);
    },
  },
  {
    slug: "ap2-x402-timeout-mismatch",
    description: "rejects a stateful AP2 constraint and x402 timeout mismatch",
    failureCodes: [
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_UNSUPPORTED_CONSTRAINT",
      "AP2_X402_TIMEOUT_MISMATCH",
    ],
    mutate: (draft) => {
      draft.ap2.openMandate.constraints.push({
        type: "payment.budget",
        max: 1000,
        currency: draft.ap2.closedMandate.payment_amount.currency,
      });
      draft.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.openMandate,
      );
      draft.x402.requirements.maxTimeoutSeconds += 60;
      updateAcceptedRequirements(draft);
    },
  },
  {
    slug: "x402-mandate-reference-mismatch",
    description: "rejects x402 requirements that reference a different AP2 mandate",
    failureCodes: ["X402_MANDATE_REFERENCE_MISMATCH"],
    mutate: (draft) => {
      const wrongReference = sha256Base64Url(`wrong-x402-reference:${draft.id}`);
      draft.x402.requirements.extra.ap2MandateReference = wrongReference;
      updateAcceptedRequirements(draft);
    },
  },
  {
    slug: "x402-accepted-requirements-mismatch",
    description: "rejects changed accepted requirements and an unknown payload extension",
    failureCodes: ["X402_ACCEPTED_REQUIREMENTS_MISMATCH", "X402_UNSUPPORTED_EXTENSION"],
    mutate: (draft) => {
      draft.x402.payload.accepted.scheme = "different-exact-profile";
      draft.x402.payload.extensions = { unknownFixtureExtension: true };
    },
  },
  {
    slug: "ap2-receipt-not-successful",
    description: "rejects a mismatched Open Mandate preset and an error Payment Receipt",
    failureCodes: [
      "AP2_RECEIPT_UNVERIFIED",
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "AP2_OPEN_PRESET_MISMATCH",
      "AP2_RECEIPT_NOT_SUCCESSFUL",
    ],
    mutate: (draft) => {
      draft.ap2.openMandate.payee = {
        ...draft.ap2.closedMandate.payee,
        id: `wrong-${draft.ap2.closedMandate.payee.id}`,
      };
      draft.ap2.verification.openMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.openMandate,
      );
      const receipt = draft.ap2.paymentReceipt;
      draft.ap2.paymentReceipt = {
        status: "Error",
        iss: receipt.iss,
        iat: receipt.iat,
        reference: receipt.reference,
        payment_id: receipt.payment_id,
        error: "synthetic_payment_error",
        error_description: "Synthetic fixture-only payment error",
      };
    },
  },
  {
    slug: "eip3009-from-mismatch",
    description: "rejects a valid alternate signature whose payer differs from AP2",
    failureCodes: ["EIP3009_PAYER_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.payload.payload.authorization.from = alternatePayer.address;
      draft.x402.settlement.payer = alternatePayer.address;
      await signAuthorization(draft, alternatePayer);
    },
  },
  {
    slug: "eip3009-recipient-mismatch",
    description: "rejects a signed EIP-3009 recipient different from x402 requirements",
    failureCodes: ["EIP3009_RECIPIENT_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.payload.payload.authorization.to = addressFromLabel(`wrong-auth-to:${draft.id}`);
      await signAuthorization(draft);
    },
  },
  {
    slug: "eip3009-value-mismatch",
    description: "rejects a signed EIP-3009 value different from x402 requirements",
    failureCodes: ["EIP3009_VALUE_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.payload.payload.authorization.value = String(
        BigInt(draft.x402.requirements.amount) + 1n,
      );
      await signAuthorization(draft);
    },
  },
  {
    slug: "eip3009-valid-after-in-future",
    description: "rejects an inactive EIP-3009 authorization whose expiry exceeds the timeout",
    failureCodes: [
      "EIP3009_VALID_AFTER_IN_FUTURE",
      "EIP3009_VALIDITY_EXCEEDS_TIMEOUT",
      "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
    ],
    mutate: async (draft) => {
      draft.x402.payload.payload.authorization.validAfter = String(NOW_EPOCH_SECONDS + 1);
      draft.x402.payload.payload.authorization.validBefore = String(
        NOW_EPOCH_SECONDS + MAX_TIMEOUT_SECONDS + 1,
      );
      await signAuthorization(draft);
    },
  },
  {
    slug: "eip3009-valid-before-expired",
    description: "rejects an EIP-3009 authorization below the x402 six-second safety buffer",
    failureCodes: ["EIP3009_VALID_BEFORE_EXPIRED"],
    mutate: async (draft) => {
      draft.x402.payload.payload.authorization.validBefore = String(NOW_EPOCH_SECONDS + 5);
      await signAuthorization(draft);
    },
  },
  {
    slug: "eip3009-nonce-binding-mismatch",
    description: "rejects a signed nonce different from the decoded AP2 mandate reference",
    failureCodes: ["EIP3009_NONCE_BINDING_MISMATCH"],
    mutate: async (draft) => {
      draft.x402.payload.payload.authorization.nonce = sha256Hex(`wrong-nonce:${draft.id}`);
      await signAuthorization(draft);
    },
  },
  {
    slug: "eip3009-signature-invalid",
    description: "rejects an EIP-3009 authorization with an unrecoverable signature",
    failureCodes: ["EIP3009_SIGNATURE_INVALID"],
    mutate: (draft) => {
      draft.x402.payload.payload.signature = `0x${"0".repeat(130)}`;
    },
  },
  {
    slug: "settlement-failed",
    description: "rejects a facilitator record that reports failed settlement",
    failureCodes: ["SETTLEMENT_FAILED"],
    mutate: (draft) => {
      draft.x402.settlement.success = false;
      draft.x402.settlement.errorReason = "synthetic settlement failure";
    },
  },
  {
    slug: "ap2-closed-transaction-id-mismatch",
    description:
      "rejects a signed closed mandate whose transaction ID differs from the verified Open Checkout reference",
    failureCodes: ["AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH", "AP2_CLOSED_TRANSACTION_ID_MISMATCH"],
    mutate: (draft) => {
      draft.ap2.closedMandate.transaction_id = sha256Base64Url(
        `wrong-closed-transaction-id:${draft.id}`,
      );
      draft.ap2.verification.closedMandateClaimsHash = canonicalSha256Base64Url(
        draft.ap2.closedMandate,
      );
    },
  },
  {
    slug: "settlement-payer-mismatch",
    description: "rejects a settlement payer different from the EIP-3009 payer",
    failureCodes: ["SETTLEMENT_PAYER_MISMATCH"],
    mutate: (draft) => {
      draft.x402.settlement.payer = alternatePayer.address;
    },
  },
  {
    slug: "settlement-amount-mismatch",
    description: "rejects a settlement amount different from x402 requirements",
    failureCodes: ["SETTLEMENT_AMOUNT_MISMATCH"],
    mutate: (draft) => {
      draft.x402.settlement.amount = String(BigInt(draft.x402.requirements.amount) + 1n);
    },
  },
  {
    slug: "settlement-transaction-invalid",
    description: "rejects a non-bytes32 settlement transaction identifier",
    failureCodes: ["AP2_RECEIPT_TRANSACTION_MISMATCH", "SETTLEMENT_TRANSACTION_INVALID"],
    mutate: (draft) => {
      draft.x402.settlement.transaction = "0xdead";
    },
  },
];

function failureCodesEqual(
  actual: readonly ConformanceFailureCode[],
  expected: readonly ConformanceFailureCode[],
): boolean {
  return (
    actual.length === expected.length && actual.every((code, index) => code === expected[index])
  );
}

async function assertExpectedResult(conformanceCase: ConformanceCase): Promise<void> {
  const report = await verifyConformanceCase(conformanceCase);
  const actualFailureCodes = report.failures.map((failure) => failure.code);
  if (
    report.consistent !== conformanceCase.expected.consistent ||
    !failureCodesEqual(actualFailureCodes, conformanceCase.expected.failureCodes)
  ) {
    throw new Error(
      [
        `Fixture expectation mismatch: ${conformanceCase.id}`,
        `expected consistent=${conformanceCase.expected.consistent} codes=${conformanceCase.expected.failureCodes.join(",")}`,
        `actual consistent=${report.consistent} codes=${actualFailureCodes.join(",")}`,
      ].join("\n"),
    );
  }
}

async function createInvalidCases(validCases: ConformanceCase[]): Promise<ConformanceCase[]> {
  if (mutations.length * 2 !== INVALID_CASE_COUNT) {
    throw new Error(`Expected 30 mutation definitions, received ${mutations.length}.`);
  }

  const invalidCases: ConformanceCase[] = [];
  for (const [mutationIndex, mutation] of mutations.entries()) {
    for (let variant = 0; variant < 2; variant += 1) {
      const baseIndex = (mutationIndex * 2 + variant) % validCases.length;
      const base = validCases[baseIndex];
      if (!base) throw new Error(`No valid fixture template at index ${baseIndex}.`);
      const draft = structuredClone(base);
      await mutation.mutate(draft);
      draft.id = `invalid-${mutation.slug}-${String(variant + 1).padStart(2, "0")}`;
      draft.description = `Invalid synthetic fixture ${String(variant + 1).padStart(2, "0")}: ${mutation.description}.`;
      draft.expected = {
        consistent: false,
        failureCodes: [...mutation.failureCodes],
      };
      draft.inputHash = conformanceInputHash(draft);
      await assertExpectedResult(draft);
      invalidCases.push(draft);
    }
  }
  return invalidCases;
}

async function main(): Promise<void> {
  const scriptDirectory = dirname(fileURLToPath(import.meta.url));
  const fixtureDirectory = resolve(scriptDirectory, "../fixtures/v0.1");
  const [normalizedInput, signedInput] = await Promise.all([
    readFile(resolve(fixtureDirectory, "ap2-normalized-records.json"), "utf8"),
    readFile(resolve(fixtureDirectory, "ap2-signed-artifacts.json"), "utf8"),
  ]);
  const normalizedBundle = NormalizedBundleSchema.parse(JSON.parse(normalizedInput));
  const signedBundle = SignedArtifactBundleSchema.parse(JSON.parse(signedInput));
  const signedById = new Map(signedBundle.cases.map((item) => [item.id, item] as const));
  const validCases = await Promise.all(
    normalizedBundle.records.map((normalized) => {
      const signed = signedById.get(normalized.id);
      if (!signed) throw new Error(`Missing signed AP2 artifact for ${normalized.id}.`);
      return createValidCase(normalized, signed, signedBundle);
    }),
  );
  if (signedById.size !== validCases.length) {
    throw new Error("Signed AP2 artifact bundle contains unexpected or duplicate case IDs.");
  }
  for (const validCase of validCases) await assertExpectedResult(validCase);

  const invalidCases = await createInvalidCases(validCases);
  const cases = [...validCases, ...invalidCases];
  const validCount = cases.filter((item) => item.expected.consistent).length;
  const invalidCount = cases.length - validCount;
  if (validCount !== VALID_CASE_COUNT || invalidCount !== INVALID_CASE_COUNT) {
    throw new Error(
      `Expected 20 valid and 60 invalid fixtures; received ${validCount} and ${invalidCount}.`,
    );
  }

  const bundle: ConformanceBundle = ConformanceBundleSchema.parse({
    bundleVersion: "ap2-x402-conformance-bundle/0.1",
    generatedAt: GENERATED_AT,
    sourcePins: SOURCE_PINS,
    cases,
  });
  const bundleReport = await verifyConformanceBundle(bundle);
  if (!bundleReport.allExpectationsMatched || bundleReport.passedExpectations !== cases.length) {
    throw new Error(
      `Generated bundle failed self-verification: ${bundleReport.passedExpectations}/${cases.length} expectations matched.`,
    );
  }

  const outputPath = resolve(scriptDirectory, "../fixtures/v0.1/cases.json");
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  process.stdout.write(
    `Wrote ${cases.length} deterministic fixtures (${validCount} valid, ${invalidCount} invalid) to ${outputPath}\n`,
  );
}

await main();
