import { type Address, type Hex, recoverTypedDataAddress } from "viem";
import { z } from "zod";
import { Ap2CryptoVerificationError, verifyAp2MandateChainAndReceipt } from "./ap2-crypto.js";
import {
  canonicalSha256Base64Url,
  canonicalValuesEqual,
  conformanceInputHash,
  deriveEip3009Nonce,
} from "./canonical.js";
import {
  CONFORMANCE_FAILURE_CODES,
  type ConformanceFailure,
  type ConformanceFailureCode,
} from "./failures.js";
import {
  type BundleCaseReport,
  type BundleVerificationReport,
  ConformanceBundleSchema,
  type ConformanceCase,
  ConformanceCaseSchema,
  type ConformanceReport,
  ExpectedResultSchema,
} from "./types.js";

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

const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

const ExpectedEnvelopeSchema = z.looseObject({
  id: z.string(),
  expected: ExpectedResultSchema,
});

const failureOrder = Object.fromEntries(
  CONFORMANCE_FAILURE_CODES.map((code, index) => [code, index] as const),
) as Record<ConformanceFailureCode, number>;

function addressesEqual(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function addFailure(
  failures: ConformanceFailure[],
  code: ConformanceFailureCode,
  path: string,
  message: string,
  expected?: string | number | boolean | null,
  actual?: string | number | boolean | null,
): void {
  failures.push({
    code,
    path,
    message,
    ...(expected !== undefined ? { expected } : {}),
    ...(actual !== undefined ? { actual } : {}),
  });
}

function addFailureOnce(
  failures: ConformanceFailure[],
  code: ConformanceFailureCode,
  path: string,
  message: string,
  expected?: string | number | boolean | null,
  actual?: string | number | boolean | null,
): void {
  if (!failures.some((failure) => failure.code === code)) {
    addFailure(failures, code, path, message, expected, actual);
  }
}

function compareScalar(
  failures: ConformanceFailure[],
  code: ConformanceFailureCode,
  path: string,
  message: string,
  expected: string | number | boolean,
  actual: string | number | boolean,
  equal: (left: string | number | boolean, right: string | number | boolean) => boolean = (
    left,
    right,
  ) => left === right,
): void {
  if (!equal(expected, actual)) {
    addFailure(failures, code, path, message, expected, actual);
  }
}

function sortFailures(failures: ConformanceFailure[]): ConformanceFailure[] {
  return failures.sort((left, right) => failureOrder[left.code] - failureOrder[right.code]);
}

function findUnsafeObjectKeyPath(input: unknown): string | undefined {
  const visited = new WeakSet<object>();

  function visit(value: unknown, path: string): string | undefined {
    if (typeof value !== "object" || value === null || visited.has(value)) return undefined;
    visited.add(value);
    for (const key of Object.keys(value)) {
      const childPath = path === "<root>" ? key : `${path}.${key}`;
      if (UNSAFE_OBJECT_KEYS.has(key)) return childPath;
      const nested = visit((value as Record<string, unknown>)[key], childPath);
      if (nested !== undefined) return nested;
    }
    return undefined;
  }

  return visit(input, "<root>");
}

function rawCaseId(input: unknown): string | null {
  return typeof input === "object" &&
    input !== null &&
    Object.hasOwn(input, "id") &&
    typeof (input as Record<string, unknown>).id === "string"
    ? ((input as Record<string, unknown>).id as string)
    : null;
}

function unsafeObjectKeyFailure(input: unknown, path: string): ConformanceReport {
  return {
    caseId: rawCaseId(input),
    consistent: false,
    computed: {},
    failures: [
      {
        code: "INPUT_SCHEMA_INVALID",
        path,
        message: "Input contains a prototype-affecting object key.",
      },
    ],
  };
}

function mapAp2CryptoFailure(error: Ap2CryptoVerificationError): ConformanceFailureCode {
  if (error.code === "CHECKOUT_REFERENCE_MISMATCH") {
    return "AP2_CHECKOUT_BINDING_UNVERIFIED";
  }
  if (error.code === "CLOSED_TRANSACTION_ID_MISMATCH") {
    return "AP2_CLOSED_TRANSACTION_ID_MISMATCH";
  }
  if (error.code === "RECEIPT_REFERENCE_MISMATCH") {
    return "AP2_RECEIPT_REFERENCE_MISMATCH";
  }
  if (error.code === "AUD_MISMATCH" || error.code === "NONCE_MISMATCH") {
    return "AP2_KEY_BINDING_UNVERIFIED";
  }
  if (error.code === "SD_HASH_INVALID" || error.code === "CNF_INVALID") {
    return "AP2_KEY_BINDING_UNVERIFIED";
  }
  if (error.code === "IAT_INVALID" || error.code === "EXP_INVALID") {
    return error.stage.startsWith("receipt")
      ? "AP2_RECEIPT_UNVERIFIED"
      : "AP2_MANDATE_TIME_INVALID";
  }
  if (error.stage.startsWith("root")) return "AP2_OPEN_MANDATE_UNVERIFIED";
  if (error.stage === "key-binding" || error.stage === "leaf-binding") {
    return "AP2_KEY_BINDING_UNVERIFIED";
  }
  if (error.stage.startsWith("leaf")) return "AP2_CLOSED_MANDATE_UNVERIFIED";
  if (error.stage.startsWith("receipt")) return "AP2_RECEIPT_UNVERIFIED";
  return "AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID";
}

function schemaFailure(input: unknown, error: z.ZodError): ConformanceReport {
  const rawId = rawCaseId(input);
  const details = error.issues
    .slice(0, 5)
    .map((issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`)
    .join("; ");
  return {
    caseId: rawId,
    consistent: false,
    computed: {},
    failures: [
      {
        code: "INPUT_SCHEMA_INVALID",
        path: "<schema>",
        message: details,
      },
    ],
  };
}

function evaluateOpenMandateConstraints(
  conformanceCase: ConformanceCase,
  failures: ConformanceFailure[],
): void {
  const closedInstrument = conformanceCase.ap2.closedMandate.payment_instrument;
  const closed = conformanceCase.ap2.closedMandate;
  const open = conformanceCase.ap2.openMandate;
  const openCheckoutReference = conformanceCase.ap2.verification.openCheckoutReference;
  let instrumentConstraintCount = 0;

  for (const [index, constraint] of open.constraints.entries()) {
    const path = `ap2.openMandate.constraints.${index}`;
    switch (constraint.type) {
      case "payment.reference":
        if (constraint.conditional_transaction_id !== openCheckoutReference) {
          addFailureOnce(
            failures,
            "AP2_PAYMENT_REFERENCE_MISMATCH",
            path,
            "The payment.reference constraint does not match the verified Open Checkout reference.",
            openCheckoutReference,
            constraint.conditional_transaction_id,
          );
        }
        break;
      case "payment.allowed_payment_instruments": {
        instrumentConstraintCount += 1;
        const match = constraint.allowed.some(
          (candidate) =>
            candidate.id === closedInstrument.id &&
            candidate.type === closedInstrument.type &&
            candidate.x402 !== undefined &&
            canonicalValuesEqual(candidate.x402, closedInstrument.x402),
        );
        if (!match) {
          addFailureOnce(
            failures,
            "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED",
            path,
            "Every allowed-instrument constraint must match the closed instrument by id, type, and x402 extension.",
          );
        }
        break;
      }
      case "payment.amount_range": {
        const amount = closed.payment_amount;
        if (
          amount.currency !== constraint.currency ||
          amount.amount > constraint.max ||
          (constraint.min !== undefined && amount.amount < constraint.min)
        ) {
          addFailureOnce(
            failures,
            "AP2_CONSTRAINT_VIOLATION",
            path,
            "The closed commerce amount violates a signed payment.amount_range constraint.",
          );
        }
        break;
      }
      case "payment.allowed_payees":
        if (!constraint.allowed.some((candidate) => candidate.id === closed.payee.id)) {
          addFailureOnce(
            failures,
            "AP2_CONSTRAINT_VIOLATION",
            path,
            "The closed payee violates a signed payment.allowed_payees constraint.",
          );
        }
        break;
      case "payment.execution_date": {
        const executionTime = closed.execution_date
          ? Date.parse(closed.execution_date)
          : Number.NaN;
        const notBefore = constraint.not_before ? Date.parse(constraint.not_before) : undefined;
        const notAfter = constraint.not_after ? Date.parse(constraint.not_after) : undefined;
        if (
          !Number.isFinite(executionTime) ||
          (notBefore !== undefined && executionTime < notBefore) ||
          (notAfter !== undefined && executionTime > notAfter)
        ) {
          addFailureOnce(
            failures,
            "AP2_CONSTRAINT_VIOLATION",
            path,
            "The closed execution date violates a signed payment.execution_date constraint.",
          );
        }
        break;
      }
      case "payment.agent_recurrence":
      case "payment.allowed_pisps":
      case "payment.budget":
        addFailureOnce(
          failures,
          "AP2_UNSUPPORTED_CONSTRAINT",
          path,
          "This constraint requires history or PISP context that is outside the offline profile.",
        );
        break;
    }
  }

  if (instrumentConstraintCount === 0) {
    addFailureOnce(
      failures,
      "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED",
      "ap2.openMandate.constraints",
      "The profile requires at least one payment.allowed_payment_instruments constraint.",
    );
  }

  const presetMismatch =
    (open.payee !== undefined && !canonicalValuesEqual(open.payee, closed.payee)) ||
    (open.payment_amount !== undefined &&
      !canonicalValuesEqual(open.payment_amount, closed.payment_amount)) ||
    (open.payment_instrument !== undefined &&
      !canonicalValuesEqual(open.payment_instrument, closed.payment_instrument)) ||
    (open.execution_date !== undefined && open.execution_date !== closed.execution_date);
  if (presetMismatch) {
    addFailureOnce(
      failures,
      "AP2_OPEN_PRESET_MISMATCH",
      "ap2.openMandate",
      "A preset Open Payment Mandate value differs from the closed Payment Mandate.",
    );
  }
  if (open.pisp !== undefined || open.risk_data !== undefined) {
    addFailureOnce(
      failures,
      "AP2_UNSUPPORTED_CONSTRAINT",
      "ap2.openMandate",
      "PISP and risk-data presets are not evaluated by this offline profile.",
    );
  }
  if (closed.pisp !== undefined || closed.risk_data !== undefined) {
    addFailureOnce(
      failures,
      "AP2_UNSUPPORTED_CONSTRAINT",
      "ap2.closedMandate",
      "PISP and risk-data values are not evaluated by this offline profile.",
    );
  }
}

export async function verifyConformanceCase(input: unknown): Promise<ConformanceReport> {
  const unsafeObjectKeyPath = findUnsafeObjectKeyPath(input);
  if (unsafeObjectKeyPath !== undefined) {
    return unsafeObjectKeyFailure(input, unsafeObjectKeyPath);
  }
  const parsed = ConformanceCaseSchema.safeParse(input);
  if (!parsed.success) return schemaFailure(input, parsed.error);

  const conformanceCase = parsed.data;
  const { ap2, x402, nowEpochSeconds } = conformanceCase;
  const failures: ConformanceFailure[] = [];
  const closed = ap2.closedMandate;
  const open = ap2.openMandate;
  const verification = ap2.verification;
  const instrument = closed.payment_instrument.x402;
  const requirements = x402.requirements;
  const authorization = x402.payload.payload.authorization;
  const settlement = x402.settlement;
  const inputHash = conformanceInputHash(conformanceCase);
  const closedMandateClaimsHash = canonicalSha256Base64Url(closed);
  const openMandateClaimsHash = canonicalSha256Base64Url(open);
  const evidence = verification.cryptographicEvidence;
  let cryptographicClosedMandateReference: string | undefined;

  compareScalar(
    failures,
    "INPUT_HASH_MISMATCH",
    "inputHash",
    "The recorded fixture input hash does not match the canonical verification input.",
    inputHash,
    conformanceCase.inputHash,
  );

  try {
    const verified = await verifyAp2MandateChainAndReceipt({
      mandateChain: evidence.mandateChain,
      trustedRootPublicJwk: evidence.trustedRootPublicJwk,
      paymentReceiptJwt: evidence.paymentReceiptJwt,
      trustedReceiptPublicJwk: evidence.trustedReceiptPublicJwk,
      expectedAudience: evidence.expectedAudience,
      expectedNonce: evidence.expectedNonce,
      verifiedAtEpochSeconds: verification.verifiedAtEpochSeconds,
      clockSkewSeconds: verification.clockSkewSeconds,
      openCheckoutReference: verification.openCheckoutReference,
    });
    cryptographicClosedMandateReference = verified.closedMandateReference;
    if (!canonicalValuesEqual(verified.closedMandate, closed)) {
      addFailure(
        failures,
        "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
        "ap2.closedMandate",
        "The normalized closed mandate differs from the claims resolved from its signed SD-JWT.",
      );
    }
    if (!canonicalValuesEqual(verified.openMandate, open)) {
      addFailure(
        failures,
        "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
        "ap2.openMandate",
        "The normalized Open Payment Mandate differs from the claims resolved from its signed SD-JWT.",
      );
    }
    if (!canonicalValuesEqual(verified.paymentReceipt, ap2.paymentReceipt)) {
      addFailure(
        failures,
        "AP2_RECEIPT_UNVERIFIED",
        "ap2.paymentReceipt",
        "The normalized Payment Receipt differs from the claims in its signed JWT.",
      );
    }
    compareScalar(
      failures,
      "AP2_CLOSED_MANDATE_REFERENCE_MISMATCH",
      "ap2.verification.closedMandateReference",
      "The recorded closed-mandate reference is not the reference derived from the verified leaf JWT.",
      verified.closedMandateReference,
      verification.closedMandateReference,
    );
  } catch (error) {
    if (error instanceof Ap2CryptoVerificationError) {
      addFailureOnce(
        failures,
        mapAp2CryptoFailure(error),
        `ap2.verification.cryptographicEvidence.${error.stage}`,
        `AP2 cryptographic verification failed (${error.code}): ${error.message}`,
      );
    } else {
      addFailureOnce(
        failures,
        "AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID",
        "ap2.verification.cryptographicEvidence",
        "AP2 cryptographic verification failed unexpectedly.",
      );
    }
  }

  const closedMandateReference =
    cryptographicClosedMandateReference ?? verification.closedMandateReference;
  const expectedNonce = deriveEip3009Nonce(closedMandateReference);
  if (verification.verifiedAtEpochSeconds !== nowEpochSeconds) {
    addFailure(
      failures,
      "AP2_VERIFICATION_CONTEXT_MISMATCH",
      "ap2.verification.verifiedAtEpochSeconds",
      "The AP2 verification time must equal the conformance case evaluation time.",
      nowEpochSeconds,
      verification.verifiedAtEpochSeconds,
    );
  }
  const ap2ClockSkew = verification.clockSkewSeconds;
  if (
    open.iat > verification.verifiedAtEpochSeconds + ap2ClockSkew ||
    closed.iat > verification.verifiedAtEpochSeconds + ap2ClockSkew ||
    open.exp < verification.verifiedAtEpochSeconds - ap2ClockSkew ||
    closed.exp < verification.verifiedAtEpochSeconds - ap2ClockSkew
  ) {
    addFailureOnce(
      failures,
      "AP2_MANDATE_TIME_INVALID",
      "ap2.verification",
      "An AP2 mandate is expired or issued in the future for the recorded verification context.",
    );
  }
  if (closedMandateClaimsHash !== verification.closedMandateClaimsHash) {
    addFailureOnce(
      failures,
      "AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH",
      "ap2.verification.closedMandateClaimsHash",
      "Closed-mandate claims changed after cryptographic extraction.",
      closedMandateClaimsHash,
      verification.closedMandateClaimsHash,
    );
  }
  if (openMandateClaimsHash !== verification.openMandateClaimsHash) {
    addFailureOnce(
      failures,
      "AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH",
      "ap2.verification.openMandateClaimsHash",
      "Open-mandate claims changed after cryptographic extraction.",
      openMandateClaimsHash,
      verification.openMandateClaimsHash,
    );
  }
  evaluateOpenMandateConstraints(conformanceCase, failures);

  if (closed.transaction_id !== verification.openCheckoutReference) {
    addFailureOnce(
      failures,
      "AP2_CLOSED_TRANSACTION_ID_MISMATCH",
      "ap2.closedMandate.transaction_id",
      "The signed closed Payment Mandate does not identify the verified Open Checkout reference.",
      verification.openCheckoutReference,
      closed.transaction_id,
    );
  }

  if (ap2.paymentReceipt.status !== "Success") {
    addFailure(
      failures,
      "AP2_RECEIPT_NOT_SUCCESSFUL",
      "ap2.paymentReceipt.status",
      "The AP2 Payment Receipt is not successful.",
      "Success",
      ap2.paymentReceipt.status,
    );
  }
  if (closedMandateReference !== ap2.paymentReceipt.reference) {
    addFailureOnce(
      failures,
      "AP2_RECEIPT_REFERENCE_MISMATCH",
      "ap2.paymentReceipt.reference",
      "The AP2 receipt does not reference the verified closed mandate.",
      closedMandateReference,
      ap2.paymentReceipt.reference,
    );
  }
  if (
    instrument.ap2PayeeId !== closed.payee.id ||
    !canonicalValuesEqual(instrument.ap2PaymentAmount, closed.payment_amount)
  ) {
    addFailure(
      failures,
      "AP2_X402_COMMERCE_BINDING_MISMATCH",
      "ap2.closedMandate.payment_instrument.x402",
      "The signed x402 extension does not bind the AP2 payee ID and commerce amount unchanged.",
    );
  }
  if (ap2.paymentReceipt.status === "Success") {
    compareScalar(
      failures,
      "AP2_RECEIPT_TRANSACTION_MISMATCH",
      "ap2.paymentReceipt.network_confirmation_id",
      "The AP2 receipt and x402 settlement identify different transactions.",
      settlement.transaction,
      ap2.paymentReceipt.network_confirmation_id,
      (left, right) => String(left).toLowerCase() === String(right).toLowerCase(),
    );
  }

  compareScalar(
    failures,
    "AP2_X402_SCHEME_MISMATCH",
    "x402.requirements.scheme",
    "The x402 scheme differs from the signed AP2 instrument extension.",
    instrument.scheme,
    requirements.scheme,
  );
  compareScalar(
    failures,
    "AP2_X402_NETWORK_MISMATCH",
    "x402.requirements.network",
    "The x402 network differs from the signed AP2 instrument extension.",
    instrument.network,
    requirements.network,
  );
  compareScalar(
    failures,
    "AP2_X402_ASSET_MISMATCH",
    "x402.requirements.asset",
    "The x402 asset differs from the signed AP2 instrument extension.",
    instrument.asset,
    requirements.asset,
    (left, right) => addressesEqual(String(left), String(right)),
  );
  compareScalar(
    failures,
    "AP2_X402_AMOUNT_MISMATCH",
    "x402.requirements.amount",
    "The x402 atomic amount differs from the signed AP2 instrument extension.",
    instrument.amount,
    requirements.amount,
  );
  compareScalar(
    failures,
    "AP2_X402_PAYEE_MISMATCH",
    "x402.requirements.payTo",
    "The x402 recipient differs from the signed AP2 instrument extension.",
    instrument.payTo,
    requirements.payTo,
    (left, right) => addressesEqual(String(left), String(right)),
  );
  compareScalar(
    failures,
    "AP2_X402_TIMEOUT_MISMATCH",
    "x402.requirements.maxTimeoutSeconds",
    "The x402 timeout differs from the signed AP2 instrument extension.",
    instrument.maxTimeoutSeconds,
    requirements.maxTimeoutSeconds,
  );
  if (
    instrument.eip712Domain.name !== requirements.extra.name ||
    instrument.eip712Domain.version !== requirements.extra.version
  ) {
    addFailure(
      failures,
      "AP2_X402_EIP712_DOMAIN_MISMATCH",
      "x402.requirements.extra",
      "The EIP-712 domain name or version differs from the signed AP2 instrument extension.",
    );
  }
  compareScalar(
    failures,
    "X402_MANDATE_REFERENCE_MISMATCH",
    "x402.requirements.extra.ap2MandateReference",
    "The x402 requirements do not reference the verified closed mandate.",
    closedMandateReference,
    requirements.extra.ap2MandateReference,
  );

  if (!canonicalValuesEqual(requirements, x402.payload.accepted)) {
    addFailure(
      failures,
      "X402_ACCEPTED_REQUIREMENTS_MISMATCH",
      "x402.payload.accepted",
      "The signed payload did not accept the supplied PaymentRequirements unchanged.",
    );
  }
  if (x402.payload.extensions && Object.keys(x402.payload.extensions).length > 0) {
    addFailure(
      failures,
      "X402_UNSUPPORTED_EXTENSION",
      "x402.payload.extensions",
      "Unknown x402 payload extensions are not evaluated by this profile.",
    );
  }

  compareScalar(
    failures,
    "EIP3009_PAYER_MISMATCH",
    "x402.payload.payload.authorization.from",
    "The EIP-3009 payer differs from the signed AP2 instrument extension.",
    instrument.payer,
    authorization.from,
    (left, right) => addressesEqual(String(left), String(right)),
  );
  compareScalar(
    failures,
    "EIP3009_RECIPIENT_MISMATCH",
    "x402.payload.payload.authorization.to",
    "The EIP-3009 recipient differs from x402 PaymentRequirements.",
    requirements.payTo,
    authorization.to,
    (left, right) => addressesEqual(String(left), String(right)),
  );
  compareScalar(
    failures,
    "EIP3009_VALUE_MISMATCH",
    "x402.payload.payload.authorization.value",
    "The EIP-3009 value differs from x402 PaymentRequirements.",
    requirements.amount,
    authorization.value,
  );

  const validAfter = BigInt(authorization.validAfter);
  const validBefore = BigInt(authorization.validBefore);
  const now = BigInt(nowEpochSeconds);
  if (validAfter > now) {
    addFailure(
      failures,
      "EIP3009_VALID_AFTER_IN_FUTURE",
      "x402.payload.payload.authorization.validAfter",
      "The EIP-3009 authorization is not active at the fixture time.",
      `<=${now}`,
      authorization.validAfter,
    );
  }
  if (validBefore < now + 6n) {
    addFailure(
      failures,
      "EIP3009_VALID_BEFORE_EXPIRED",
      "x402.payload.payload.authorization.validBefore",
      "The EIP-3009 authorization is expired or has less than the x402 six-second safety buffer.",
      `>=${now + 6n}`,
      authorization.validBefore,
    );
  }
  if (validBefore > now + BigInt(requirements.maxTimeoutSeconds)) {
    addFailure(
      failures,
      "EIP3009_VALIDITY_EXCEEDS_TIMEOUT",
      "x402.payload.payload.authorization.validBefore",
      "The EIP-3009 expiry exceeds the x402 maximum timeout.",
      `<=${now + BigInt(requirements.maxTimeoutSeconds)}`,
      authorization.validBefore,
    );
  }
  const ap2Expiry = BigInt(Math.min(open.exp, closed.exp));
  if (validBefore > ap2Expiry) {
    addFailure(
      failures,
      "EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY",
      "x402.payload.payload.authorization.validBefore",
      "The EIP-3009 authorization remains usable after an AP2 mandate expires.",
      `<=${ap2Expiry}`,
      authorization.validBefore,
    );
  }
  compareScalar(
    failures,
    "EIP3009_NONCE_BINDING_MISMATCH",
    "x402.payload.payload.authorization.nonce",
    "The EIP-3009 nonce is not the 32-byte AP2 closed-mandate reference.",
    expectedNonce,
    authorization.nonce,
    (left, right) => String(left).toLowerCase() === String(right).toLowerCase(),
  );

  let recoveredSigner: string | undefined;
  try {
    const chainId = Number(requirements.network.slice("eip155:".length));
    recoveredSigner = await recoverTypedDataAddress({
      domain: {
        name: requirements.extra.name,
        version: requirements.extra.version,
        chainId,
        verifyingContract: requirements.asset as Address,
      },
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: authorization.from as Address,
        to: authorization.to as Address,
        value: BigInt(authorization.value),
        validAfter,
        validBefore,
        nonce: authorization.nonce as Hex,
      },
      signature: x402.payload.payload.signature as Hex,
    });
    if (!addressesEqual(recoveredSigner, authorization.from)) {
      addFailure(
        failures,
        "EIP3009_SIGNATURE_INVALID",
        "x402.payload.payload.signature",
        "The EIP-712 signature does not recover the EIP-3009 payer.",
        authorization.from,
        recoveredSigner,
      );
    }
  } catch {
    addFailure(
      failures,
      "EIP3009_SIGNATURE_INVALID",
      "x402.payload.payload.signature",
      "The EIP-712 signature could not be recovered.",
    );
  }

  if (!settlement.success) {
    addFailure(
      failures,
      "SETTLEMENT_FAILED",
      "x402.settlement.success",
      "The facilitator reported that settlement failed.",
      true,
      settlement.success,
    );
  }
  compareScalar(
    failures,
    "SETTLEMENT_NETWORK_MISMATCH",
    "x402.settlement.network",
    "The settlement network differs from PaymentRequirements.",
    requirements.network,
    settlement.network,
  );
  compareScalar(
    failures,
    "SETTLEMENT_PAYER_MISMATCH",
    "x402.settlement.payer",
    "The settlement payer differs from the EIP-3009 payer.",
    authorization.from,
    settlement.payer,
    (left, right) => addressesEqual(String(left), String(right)),
  );
  if (settlement.amount !== undefined) {
    compareScalar(
      failures,
      "SETTLEMENT_AMOUNT_MISMATCH",
      "x402.settlement.amount",
      "The optional settlement amount differs from PaymentRequirements.",
      requirements.amount,
      settlement.amount,
    );
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(settlement.transaction)) {
    addFailure(
      failures,
      "SETTLEMENT_TRANSACTION_INVALID",
      "x402.settlement.transaction",
      "The settlement transaction is not a 32-byte EVM transaction identifier.",
    );
  }
  const sortedFailures = sortFailures(failures);
  return {
    caseId: conformanceCase.id,
    consistent: sortedFailures.length === 0,
    computed: {
      closedMandateClaimsHash,
      openMandateClaimsHash,
      closedMandateReference,
      inputHash,
      expectedNonce,
      ...(recoveredSigner ? { recoveredSigner } : {}),
    },
    failures: sortedFailures,
  };
}

export async function verifyConformanceBundle(input: unknown): Promise<BundleVerificationReport> {
  const unsafeObjectKeyPath = findUnsafeObjectKeyPath(input);
  if (unsafeObjectKeyPath !== undefined) {
    throw new TypeError(
      `Bundle contains a prototype-affecting object key at ${unsafeObjectKeyPath}`,
    );
  }
  const bundle = ConformanceBundleSchema.parse(input);
  const cases: BundleCaseReport[] = [];

  for (const rawCase of bundle.cases) {
    const report = await verifyConformanceCase(rawCase);
    const expected = ExpectedEnvelopeSchema.safeParse(rawCase);
    const expectedConsistent = expected.success ? expected.data.expected.consistent : null;
    const expectedFailureCodes = expected.success ? expected.data.expected.failureCodes : [];
    const actualFailureCodes = report.failures.map((failure) => failure.code);
    const expectationMatched =
      expected.success &&
      report.consistent === expectedConsistent &&
      canonicalValuesEqual(actualFailureCodes, expectedFailureCodes);
    cases.push({
      id: expected.success ? expected.data.id : report.caseId,
      expectationMatched,
      expectedConsistent,
      expectedFailureCodes,
      report,
    });
  }

  const passedExpectations = cases.filter((item) => item.expectationMatched).length;
  return {
    allExpectationsMatched: passedExpectations === cases.length,
    total: cases.length,
    passedExpectations,
    failedExpectations: cases.length - passedExpectations,
    cases,
  };
}
