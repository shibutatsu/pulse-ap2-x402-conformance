import { createHash } from "node:crypto";
import { type CompactVerifyResult, type CryptoKey, type JWK, compactVerify, importJWK } from "jose";

const TERMINAL_KB_SD_JWT_TYPES = new Set(["kb+sd-jwt", "kb-sd-jwt"]);
const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const SUPPORTED_SD_ALGORITHMS = new Map([
  ["sha-256", "sha256"],
  ["sha-384", "sha384"],
  ["sha-512", "sha512"],
] as const);

export type Ap2CryptoVerificationStage =
  | "input"
  | "root-header"
  | "root-signature"
  | "root-disclosures"
  | "root-claims"
  | "key-binding"
  | "leaf-header"
  | "leaf-signature"
  | "leaf-disclosures"
  | "leaf-binding"
  | "leaf-claims"
  | "receipt-header"
  | "receipt-signature"
  | "receipt-claims";

export type Ap2CryptoVerificationCode =
  | "CHAIN_MALFORMED"
  | "JWK_INVALID"
  | "ALG_INVALID"
  | "TYP_INVALID"
  | "SIGNATURE_INVALID"
  | "DISCLOSURE_INVALID"
  | "DELEGATE_PAYLOAD_INVALID"
  | "MANDATE_TYPE_INVALID"
  | "CNF_INVALID"
  | "SD_HASH_INVALID"
  | "AUD_MISMATCH"
  | "NONCE_MISMATCH"
  | "IAT_INVALID"
  | "EXP_INVALID"
  | "CHECKOUT_REFERENCE_MISMATCH"
  | "CLOSED_TRANSACTION_ID_MISMATCH"
  | "RECEIPT_CLAIMS_INVALID"
  | "RECEIPT_REFERENCE_MISMATCH";

/** A stable, non-secret-bearing failure returned by the offline AP2 verifier. */
export class Ap2CryptoVerificationError extends Error {
  override readonly name = "Ap2CryptoVerificationError";

  constructor(
    readonly stage: Ap2CryptoVerificationStage,
    readonly code: Ap2CryptoVerificationCode,
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
  }
}

export interface VerifyAp2CryptoInput {
  mandateChain: string;
  trustedRootPublicJwk: JWK;
  paymentReceiptJwt: string;
  trustedReceiptPublicJwk: JWK;
  expectedAudience: string;
  expectedNonce: string;
  verifiedAtEpochSeconds: number;
  clockSkewSeconds: number;
  openCheckoutReference: string;
}

export interface VerifyAp2CryptoResult {
  openMandate: Readonly<Record<string, unknown>>;
  closedMandate: Readonly<Record<string, unknown>>;
  paymentReceipt: Readonly<Record<string, unknown>>;
  closedMandateReference: string;
}

interface ParsedSdJwt {
  issuerJwt: string;
  disclosures: readonly string[];
  sdJwt: string;
}

interface DecodedDisclosure {
  encoded: string;
  decoded: readonly unknown[];
}

interface DisclosureContext {
  stage: "root-disclosures" | "leaf-disclosures";
  byDigest: ReadonlyMap<string, DecodedDisclosure>;
  used: Set<string>;
  resolving: Set<string>;
}

/**
 * Verifies the pinned AP2 one-hop open-to-closed Payment Mandate chain and its
 * signed Payment Receipt without RPC, network, or mutable trust-store access.
 */
export async function verifyAp2MandateChainAndReceipt(
  input: VerifyAp2CryptoInput,
): Promise<VerifyAp2CryptoResult> {
  validateInput(input);
  const [rootSegment, leafSegment] = splitOneHopChain(input.mandateChain);
  const rootToken = parseSdJwt(rootSegment, "root-disclosures");
  const leafToken = parseSdJwt(leafSegment, "leaf-disclosures");

  const trustedRootKey = await importPublicEs256Jwk(input.trustedRootPublicJwk, "root-signature");
  const rootVerified = await verifyCompactJwt(
    rootToken.issuerJwt,
    trustedRootKey,
    "root-signature",
  );
  validateRootHeader(rootVerified.protectedHeader);
  const rootEnvelope = decodeJwtPayload(rootVerified, "root-signature");
  const resolvedRootEnvelope = resolveDisclosures(rootEnvelope, rootToken, "root-disclosures");
  validateTimeClaims(
    resolvedRootEnvelope,
    input.verifiedAtEpochSeconds,
    input.clockSkewSeconds,
    "root-claims",
  );
  const openMandate = extractSingleDelegatePayload(resolvedRootEnvelope, "root-claims");
  validateTimeClaims(
    openMandate,
    input.verifiedAtEpochSeconds,
    input.clockSkewSeconds,
    "root-claims",
  );
  validateOpenPaymentMandate(openMandate, input.openCheckoutReference);

  const holderJwk = extractHolderPublicJwk(openMandate);
  const holderKey = await importPublicEs256Jwk(holderJwk, "key-binding");
  const leafVerified = await verifyCompactJwt(leafToken.issuerJwt, holderKey, "leaf-signature");
  validateLeafHeader(leafVerified.protectedHeader);
  const leafEnvelope = decodeJwtPayload(leafVerified, "leaf-signature");
  validateLeafEnvelopeBinding(leafEnvelope, rootToken, rootEnvelope, input);
  validateTimeClaims(
    leafEnvelope,
    input.verifiedAtEpochSeconds,
    input.clockSkewSeconds,
    "leaf-claims",
  );
  const resolvedLeafEnvelope = resolveDisclosures(leafEnvelope, leafToken, "leaf-disclosures");
  const closedMandate = extractSingleDelegatePayload(resolvedLeafEnvelope, "leaf-claims");
  validateTimeClaims(
    closedMandate,
    input.verifiedAtEpochSeconds,
    input.clockSkewSeconds,
    "leaf-claims",
  );
  validateClosedPaymentMandate(closedMandate, input.openCheckoutReference);

  const closedMandateReference = shaBase64Url(leafToken.issuerJwt, "sha256");
  const trustedReceiptKey = await importPublicEs256Jwk(
    input.trustedReceiptPublicJwk,
    "receipt-signature",
  );
  const receiptVerified = await verifyCompactJwt(
    input.paymentReceiptJwt,
    trustedReceiptKey,
    "receipt-signature",
  );
  validateReceiptHeader(receiptVerified.protectedHeader);
  const paymentReceipt = decodeJwtPayload(receiptVerified, "receipt-signature");
  validatePaymentReceipt(
    paymentReceipt,
    closedMandateReference,
    input.verifiedAtEpochSeconds,
    input.clockSkewSeconds,
  );

  return {
    openMandate,
    closedMandate,
    paymentReceipt,
    closedMandateReference,
  };
}

function validateInput(input: VerifyAp2CryptoInput): void {
  if (
    typeof input.mandateChain !== "string" ||
    input.mandateChain.length === 0 ||
    typeof input.paymentReceiptJwt !== "string" ||
    input.paymentReceiptJwt.length === 0 ||
    typeof input.expectedAudience !== "string" ||
    input.expectedAudience.length === 0 ||
    typeof input.expectedNonce !== "string" ||
    input.expectedNonce.length === 0 ||
    typeof input.openCheckoutReference !== "string" ||
    input.openCheckoutReference.length === 0 ||
    !Number.isSafeInteger(input.verifiedAtEpochSeconds) ||
    input.verifiedAtEpochSeconds < 0 ||
    !Number.isSafeInteger(input.clockSkewSeconds) ||
    input.clockSkewSeconds < 0
  ) {
    throw failure("input", "CHAIN_MALFORMED", "AP2 verification input is malformed");
  }
}

function splitOneHopChain(chain: string): readonly [string, string] {
  const separatorIndex = chain.indexOf("~~");
  if (
    separatorIndex <= 0 ||
    separatorIndex !== chain.lastIndexOf("~~") ||
    separatorIndex + 2 >= chain.length
  ) {
    throw failure(
      "input",
      "CHAIN_MALFORMED",
      "AP2 Payment Mandate chain must contain exactly one delegation hop",
    );
  }
  return [chain.slice(0, separatorIndex), chain.slice(separatorIndex + 2)];
}

function parseSdJwt(
  rawSegment: string,
  stage: "root-disclosures" | "leaf-disclosures",
): ParsedSdJwt {
  const segment = rawSegment.endsWith("~") ? rawSegment : `${rawSegment}~`;
  const parts = segment.split("~");
  const issuerJwt = parts[0];
  const trailing = parts.at(-1);
  const disclosures = parts.slice(1, -1);
  if (
    trailing !== "" ||
    typeof issuerJwt !== "string" ||
    issuerJwt.split(".").length !== 3 ||
    disclosures.some((disclosure) => disclosure.length === 0)
  ) {
    throw failure(stage, "DISCLOSURE_INVALID", "Malformed compact SD-JWT serialization");
  }
  return {
    issuerJwt,
    disclosures,
    sdJwt: `${issuerJwt}~${disclosures.join("~")}${disclosures.length ? "~" : ""}`,
  };
}

async function importPublicEs256Jwk(
  jwk: JWK,
  stage: "root-signature" | "key-binding" | "receipt-signature",
): Promise<CryptoKey | Uint8Array> {
  if (
    !isRecord(jwk) ||
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    "d" in jwk ||
    (jwk.alg !== undefined && jwk.alg !== "ES256")
  ) {
    throw failure(stage, "JWK_INVALID", "Expected a public P-256 JWK for ES256 verification");
  }
  try {
    return await importJWK(jwk, "ES256");
  } catch (cause) {
    throw failure(stage, "JWK_INVALID", "Unable to import the public P-256 JWK", cause);
  }
}

async function verifyCompactJwt(
  jwt: string,
  key: CryptoKey | Uint8Array,
  stage: "root-signature" | "leaf-signature" | "receipt-signature",
): Promise<CompactVerifyResult> {
  try {
    return await compactVerify(jwt, key, { algorithms: ["ES256"] });
  } catch (cause) {
    throw failure(stage, "SIGNATURE_INVALID", "ES256 signature verification failed", cause);
  }
}

function validateRootHeader(header: CompactVerifyResult["protectedHeader"]): void {
  if (header.alg !== "ES256") {
    throw failure("root-header", "ALG_INVALID", "Root SD-JWT must use ES256");
  }
  if (header.typ === undefined) return;
  if (
    typeof header.typ !== "string" ||
    !header.typ.endsWith("+sd-jwt") ||
    TERMINAL_KB_SD_JWT_TYPES.has(header.typ) ||
    header.typ.endsWith("+sd-jwt+kb")
  ) {
    throw failure("root-header", "TYP_INVALID", "Root token typ is not an issuer SD-JWT type");
  }
}

function validateLeafHeader(header: CompactVerifyResult["protectedHeader"]): void {
  if (header.alg !== "ES256") {
    throw failure("leaf-header", "ALG_INVALID", "Closed mandate JWT must use ES256");
  }
  if (typeof header.typ !== "string" || !TERMINAL_KB_SD_JWT_TYPES.has(header.typ)) {
    throw failure("leaf-header", "TYP_INVALID", "Closed mandate JWT must be a terminal KB-SD-JWT");
  }
}

function validateReceiptHeader(header: CompactVerifyResult["protectedHeader"]): void {
  if (header.alg !== "ES256") {
    throw failure("receipt-header", "ALG_INVALID", "Payment Receipt JWT must use ES256");
  }
}

function decodeJwtPayload(
  verified: CompactVerifyResult,
  stage: "root-signature" | "leaf-signature" | "receipt-signature",
): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(verified.payload));
    if (!isRecord(value)) throw new TypeError("JWT payload is not an object");
    return value;
  } catch (cause) {
    throw failure(stage, "SIGNATURE_INVALID", "Signed JWT payload is not a JSON object", cause);
  }
}

function resolveDisclosures(
  envelope: Record<string, unknown>,
  token: ParsedSdJwt,
  stage: "root-disclosures" | "leaf-disclosures",
): Record<string, unknown> {
  const algorithm = sdAlgorithm(envelope._sd_alg, stage);
  const byDigest = new Map<string, DecodedDisclosure>();
  for (const encoded of token.disclosures) {
    const decoded = decodeDisclosure(encoded, stage);
    const digest = shaBase64Url(encoded, algorithm);
    if (byDigest.has(digest)) {
      throw failure(stage, "DISCLOSURE_INVALID", "Duplicate SD-JWT disclosure digest");
    }
    byDigest.set(digest, { encoded, decoded });
  }
  const context: DisclosureContext = {
    stage,
    byDigest,
    used: new Set(),
    resolving: new Set(),
  };
  const resolved = resolveValue(envelope, context, false);
  if (!isRecord(resolved)) {
    throw failure(stage, "DISCLOSURE_INVALID", "Resolved SD-JWT payload is not an object");
  }
  if (context.used.size !== byDigest.size) {
    throw failure(stage, "DISCLOSURE_INVALID", "SD-JWT contains an unbound disclosure");
  }
  return resolved;
}

function decodeDisclosure(
  encoded: string,
  stage: "root-disclosures" | "leaf-disclosures",
): readonly unknown[] {
  try {
    if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1) {
      throw new TypeError("invalid base64url");
    }
    const bytes = Buffer.from(encoded, "base64url");
    if (bytes.toString("base64url") !== encoded) throw new TypeError("non-canonical base64url");
    const decoded: unknown = JSON.parse(bytes.toString("utf8"));
    if (
      !Array.isArray(decoded) ||
      (decoded.length !== 2 && decoded.length !== 3) ||
      typeof decoded[0] !== "string"
    ) {
      throw new TypeError("invalid disclosure array");
    }
    if (decoded.length === 3 && typeof decoded[1] !== "string") {
      throw new TypeError("invalid disclosed claim name");
    }
    return decoded;
  } catch (cause) {
    throw failure(stage, "DISCLOSURE_INVALID", "SD-JWT disclosure is malformed", cause);
  }
}

function resolveValue(
  value: unknown,
  context: DisclosureContext,
  allowDigestString: boolean,
): unknown {
  if (allowDigestString && typeof value === "string" && context.byDigest.has(value)) {
    return resolveDigest(value, context, 2);
  }
  if (Array.isArray(value)) {
    return value.map((item) => resolveValue(item, context, allowDigestString));
  }
  if (!isRecord(value)) return value;

  const placeholder = value["..."];
  if (Object.keys(value).length === 1 && typeof placeholder === "string") {
    if (!context.byDigest.has(placeholder)) return { ...value };
    return resolveDigest(placeholder, context, 2);
  }

  const resolved: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) {
    if (key === "_sd") continue;
    rejectUnsafeObjectKey(key, context);
    resolved[key] = resolveValue(child, context, key === "delegate_payload");
  }
  const selectivelyDisclosed = value._sd;
  if (selectivelyDisclosed !== undefined) {
    if (
      !Array.isArray(selectivelyDisclosed) ||
      selectivelyDisclosed.some((item) => typeof item !== "string")
    ) {
      throw failure(context.stage, "DISCLOSURE_INVALID", "_sd must be an array of digests");
    }
    for (const digest of selectivelyDisclosed as string[]) {
      if (!context.byDigest.has(digest)) continue;
      const disclosed = resolveDigest(digest, context, 3);
      if (!isRecord(disclosed) || typeof disclosed.name !== "string") {
        throw failure(context.stage, "DISCLOSURE_INVALID", "Object disclosure is malformed");
      }
      rejectUnsafeObjectKey(disclosed.name, context);
      if (Object.hasOwn(resolved, disclosed.name)) {
        throw failure(
          context.stage,
          "DISCLOSURE_INVALID",
          "Disclosed claim collides with an existing claim",
        );
      }
      resolved[disclosed.name] = disclosed.value;
    }
  }
  return resolved;
}

function rejectUnsafeObjectKey(key: string, context: DisclosureContext): void {
  if (UNSAFE_OBJECT_KEYS.has(key)) {
    throw failure(
      context.stage,
      "DISCLOSURE_INVALID",
      "SD-JWT object contains a prototype-affecting claim name",
    );
  }
}

function resolveDigest(digest: string, context: DisclosureContext, expectedLength: 2 | 3): unknown {
  const disclosure = context.byDigest.get(digest);
  if (disclosure === undefined || disclosure.decoded.length !== expectedLength) {
    throw failure(
      context.stage,
      "DISCLOSURE_INVALID",
      "Disclosure shape does not match its digest reference",
    );
  }
  if (context.resolving.has(digest)) {
    throw failure(context.stage, "DISCLOSURE_INVALID", "Cyclic SD-JWT disclosure reference");
  }
  context.used.add(digest);
  context.resolving.add(digest);
  try {
    if (expectedLength === 2) {
      return resolveValue(disclosure.decoded[1], context, false);
    }
    return {
      name: disclosure.decoded[1],
      value: resolveValue(disclosure.decoded[2], context, false),
    };
  } finally {
    context.resolving.delete(digest);
  }
}

function extractSingleDelegatePayload(
  envelope: Record<string, unknown>,
  stage: "root-claims" | "leaf-claims",
): Record<string, unknown> {
  const payload = envelope.delegate_payload;
  if (!Array.isArray(payload) || payload.length !== 1 || !isRecord(payload[0])) {
    throw failure(
      stage,
      "DELEGATE_PAYLOAD_INVALID",
      "Payment Mandate token must resolve exactly one delegate payload",
    );
  }
  return payload[0];
}

function validateOpenPaymentMandate(
  mandate: Record<string, unknown>,
  openCheckoutReference: string,
): void {
  if (mandate.vct !== "mandate.payment.open.1" || !Array.isArray(mandate.constraints)) {
    throw failure(
      "root-claims",
      "MANDATE_TYPE_INVALID",
      "Root delegate payload must be an open Payment Mandate",
    );
  }
  const referenceConstraints = mandate.constraints.filter(
    (constraint): constraint is Record<string, unknown> =>
      isRecord(constraint) && constraint.type === "payment.reference",
  );
  if (
    referenceConstraints.length === 0 ||
    referenceConstraints.some(
      (constraint) => constraint.conditional_transaction_id !== openCheckoutReference,
    )
  ) {
    throw failure(
      "root-claims",
      "CHECKOUT_REFERENCE_MISMATCH",
      "Open Payment Mandate does not bind the expected open checkout reference",
    );
  }
}

function extractHolderPublicJwk(mandate: Record<string, unknown>): JWK {
  const cnf = mandate.cnf;
  if (!isRecord(cnf) || !isRecord(cnf.jwk)) {
    throw failure("key-binding", "CNF_INVALID", "Open Payment Mandate is missing cnf.jwk");
  }
  return cnf.jwk as JWK;
}

function validateLeafEnvelopeBinding(
  envelope: Record<string, unknown>,
  rootToken: ParsedSdJwt,
  verifiedRootEnvelope: Record<string, unknown>,
  input: VerifyAp2CryptoInput,
): void {
  if ("issuer_jwt_hash" in envelope || typeof envelope.sd_hash !== "string") {
    throw failure(
      "leaf-binding",
      "SD_HASH_INVALID",
      "Terminal KB-SD-JWT must contain exactly the sd_hash binding mode",
    );
  }
  const expectedHash = shaBase64Url(
    rootToken.sdJwt,
    sdAlgorithm(verifiedRootEnvelope._sd_alg, "leaf-disclosures"),
  );
  if (envelope.sd_hash !== expectedHash) {
    throw failure("leaf-binding", "SD_HASH_INVALID", "Terminal KB-SD-JWT sd_hash mismatch");
  }
  if (envelope.aud !== input.expectedAudience) {
    throw failure("leaf-binding", "AUD_MISMATCH", "Terminal KB-SD-JWT audience mismatch");
  }
  if (envelope.nonce !== input.expectedNonce) {
    throw failure("leaf-binding", "NONCE_MISMATCH", "Terminal KB-SD-JWT nonce mismatch");
  }
  if (envelope.iat === undefined) {
    throw failure("leaf-claims", "IAT_INVALID", "Terminal KB-SD-JWT is missing iat");
  }
}

function validateClosedPaymentMandate(
  mandate: Record<string, unknown>,
  openCheckoutReference: string,
): void {
  if (
    mandate.vct !== "mandate.payment.1" ||
    typeof mandate.transaction_id !== "string" ||
    mandate.transaction_id.length === 0 ||
    !isRecord(mandate.payee) ||
    !isRecord(mandate.payment_amount) ||
    !Number.isSafeInteger(mandate.payment_amount.amount) ||
    typeof mandate.payment_amount.currency !== "string" ||
    !isRecord(mandate.payment_instrument) ||
    typeof mandate.payment_instrument.id !== "string" ||
    typeof mandate.payment_instrument.type !== "string" ||
    "cnf" in mandate
  ) {
    throw failure(
      "leaf-claims",
      "MANDATE_TYPE_INVALID",
      "Leaf delegate payload must be a terminal closed Payment Mandate",
    );
  }
  if (mandate.transaction_id !== openCheckoutReference) {
    throw failure(
      "leaf-claims",
      "CLOSED_TRANSACTION_ID_MISMATCH",
      "Closed Payment Mandate transaction_id does not bind the expected open checkout reference",
    );
  }
}

function validatePaymentReceipt(
  receipt: Record<string, unknown>,
  expectedReference: string,
  verifiedAtEpochSeconds: number,
  clockSkewSeconds: number,
): void {
  validateTimeClaims(receipt, verifiedAtEpochSeconds, clockSkewSeconds, "receipt-claims");
  const commonClaimsValid =
    (receipt.status === "Success" || receipt.status === "Error") &&
    typeof receipt.iss === "string" &&
    Number.isSafeInteger(receipt.iat) &&
    typeof receipt.reference === "string" &&
    typeof receipt.payment_id === "string" &&
    receipt.payment_id.length > 0;
  const variantClaimsValid =
    receipt.status === "Success"
      ? typeof receipt.psp_confirmation_id === "string" &&
        receipt.psp_confirmation_id.length > 0 &&
        typeof receipt.network_confirmation_id === "string" &&
        receipt.network_confirmation_id.length > 0
      : typeof receipt.error === "string" &&
        receipt.error.length > 0 &&
        typeof receipt.error_description === "string" &&
        receipt.error_description.length > 0;
  if (!commonClaimsValid || !variantClaimsValid) {
    throw failure(
      "receipt-claims",
      "RECEIPT_CLAIMS_INVALID",
      "Signed JWT payload is not a valid AP2 Payment Receipt",
    );
  }
  if (receipt.reference !== expectedReference) {
    throw failure(
      "receipt-claims",
      "RECEIPT_REFERENCE_MISMATCH",
      "Payment Receipt reference does not match the closed mandate JWT",
    );
  }
}

function validateTimeClaims(
  claims: Record<string, unknown>,
  now: number,
  clockSkew: number,
  stage: "root-claims" | "leaf-claims" | "receipt-claims",
): void {
  if (claims.iat !== undefined) {
    if (!Number.isSafeInteger(claims.iat) || (claims.iat as number) > now + clockSkew) {
      throw failure(stage, "IAT_INVALID", "JWT iat is invalid or in the future");
    }
  }
  if (claims.exp !== undefined) {
    if (!Number.isSafeInteger(claims.exp) || now > (claims.exp as number) + clockSkew) {
      throw failure(stage, "EXP_INVALID", "JWT exp is invalid or expired");
    }
  }
}

function sdAlgorithm(
  claim: unknown,
  stage: "root-disclosures" | "leaf-disclosures",
): "sha256" | "sha384" | "sha512" {
  const sdAlgorithmName = claim === undefined ? "sha-256" : claim;
  if (typeof sdAlgorithmName !== "string") {
    throw failure(stage, "DISCLOSURE_INVALID", "_sd_alg must be a string");
  }
  const algorithm = SUPPORTED_SD_ALGORITHMS.get(
    sdAlgorithmName as "sha-256" | "sha-384" | "sha-512",
  );
  if (algorithm === undefined) {
    throw failure(stage, "DISCLOSURE_INVALID", "Unsupported _sd_alg value");
  }
  return algorithm;
}

function shaBase64Url(value: string, algorithm: "sha256" | "sha384" | "sha512"): string {
  return createHash(algorithm).update(value, "ascii").digest("base64url");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function failure(
  stage: Ap2CryptoVerificationStage,
  code: Ap2CryptoVerificationCode,
  message: string,
  cause?: unknown,
): Ap2CryptoVerificationError {
  return new Ap2CryptoVerificationError(stage, code, message, cause);
}
