import { createECDH, createHash } from "node:crypto";
import { type CompactJWSHeaderParameters, CompactSign, type JWK, importJWK } from "jose";
import {
  type Ap2CryptoVerificationCode,
  Ap2CryptoVerificationError,
  type Ap2CryptoVerificationStage,
  type VerifyAp2CryptoInput,
  verifyAp2MandateChainAndReceipt,
} from "../src/ap2-crypto.js";

const NOW = 1_800_000_000;
const ROOT_PRIVATE_JWK = deterministicPrivateJwk(1);
const HOLDER_PRIVATE_JWK = deterministicPrivateJwk(2);
const RECEIPT_PRIVATE_JWK = deterministicPrivateJwk(3);
const OTHER_PRIVATE_JWK = deterministicPrivateJwk(4);
const OPEN_CHECKOUT_REFERENCE = sha256Base64Url("open-checkout-mandate");

interface ArtifactOptions {
  rootTyp?: string | null;
  leafTyp?: string;
  rootSigningJwk?: JWK;
  leafSigningJwk?: JWK;
  receiptSigningJwk?: JWK;
  sdHash?: string;
  audience?: string;
  nonce?: string;
  leafIat?: number;
  openCheckoutReferenceInMandate?: string;
  receiptReference?: string;
  receiptStatus?: "Success" | "Error";
  rootSerialization?: SdSerialization;
  rootPropertyName?: string;
  leafSerialization?: SdSerialization;
  rootSdAlgorithm?: string | null;
  leafSdAlgorithm?: string | null;
  mutateOpenMandate?: (mandate: Record<string, unknown>) => void;
  mutateClosedMandate?: (mandate: Record<string, unknown>) => void;
  mutateRootEnvelope?: (envelope: Record<string, unknown>) => void;
  mutateLeafEnvelope?: (envelope: Record<string, unknown>) => void;
  mutateReceipt?: (receipt: Record<string, unknown>) => void;
}

type SdSerialization = "array-disclosure" | "property-disclosure" | "digest-string" | "inline";

interface TestArtifact {
  input: VerifyAp2CryptoInput;
  openMandate: Record<string, unknown>;
  closedMandate: Record<string, unknown>;
  receipt: Record<string, unknown>;
  closedMandateReference: string;
}

describe("verifyAp2MandateChainAndReceipt", () => {
  it("verifies and resolves the pinned one-hop AP2 chain and signed receipt", async () => {
    const artifact = await createArtifact();

    const result = await verifyAp2MandateChainAndReceipt(artifact.input);

    expect(result.openMandate).toEqual(artifact.openMandate);
    expect(result.closedMandate).toEqual(artifact.closedMandate);
    expect(result.paymentReceipt).toEqual(artifact.receipt);
    expect(result.closedMandateReference).toBe(artifact.closedMandateReference);
    expect(result.closedMandateReference).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("accepts the root token with no typ because the pinned SDK omits it", async () => {
    const artifact = await createArtifact({ rootTyp: null });

    await expect(verifyAp2MandateChainAndReceipt(artifact.input)).resolves.toMatchObject({
      closedMandateReference: artifact.closedMandateReference,
    });
  });

  it("reports a stable root-signature failure for an untrusted root signer", async () => {
    const artifact = await createArtifact({ rootSigningJwk: OTHER_PRIVATE_JWK });
    await expectVerificationFailure(artifact.input, "root-signature", "SIGNATURE_INVALID");
  });

  it("reports a stable leaf-signature failure when cnf does not authorize the signer", async () => {
    const artifact = await createArtifact({ leafSigningJwk: OTHER_PRIVATE_JWK });
    await expectVerificationFailure(artifact.input, "leaf-signature", "SIGNATURE_INVALID");
  });

  it("rejects a terminal leaf whose sd_hash does not bind the presented open mandate", async () => {
    const artifact = await createArtifact({ sdHash: "A".repeat(43) });
    await expectVerificationFailure(artifact.input, "leaf-binding", "SD_HASH_INVALID");
  });

  it.each([
    ["wrong audience", { audience: "unexpected-verifier" }, "AUD_MISMATCH"],
    ["wrong nonce", { nonce: "unexpected-nonce" }, "NONCE_MISMATCH"],
  ] as const)("rejects %s", async (_label, options, code) => {
    const artifact = await createArtifact(options);
    await expectVerificationFailure(artifact.input, "leaf-binding", code);
  });

  it("rejects a future terminal iat outside the configured skew", async () => {
    const artifact = await createArtifact({ leafIat: NOW + 31 });
    await expectVerificationFailure(artifact.input, "leaf-claims", "IAT_INVALID");
  });

  it("rejects a root typ that identifies a terminal KB-SD-JWT", async () => {
    const artifact = await createArtifact({ rootTyp: "kb+sd-jwt" });
    await expectVerificationFailure(artifact.input, "root-header", "TYP_INVALID");
  });

  it("rejects an intermediate leaf typ in a terminal one-hop chain", async () => {
    const artifact = await createArtifact({ leafTyp: "kb+sd-jwt+kb" });
    await expectVerificationFailure(artifact.input, "leaf-header", "TYP_INVALID");
  });

  it("rejects an open mandate bound to a different checkout reference", async () => {
    const artifact = await createArtifact({
      openCheckoutReferenceInMandate: sha256Base64Url("another-open-checkout"),
    });
    await expectVerificationFailure(artifact.input, "root-claims", "CHECKOUT_REFERENCE_MISMATCH");
  });

  it("rejects a closed mandate bound to a different checkout reference", async () => {
    const artifact = await createArtifact({
      mutateClosedMandate: (mandate) => {
        mandate.transaction_id = sha256Base64Url("another-closed-checkout");
      },
    });
    await expectVerificationFailure(
      artifact.input,
      "leaf-claims",
      "CLOSED_TRANSACTION_ID_MISMATCH",
    );
  });

  it("rejects a receipt signed by an untrusted receipt issuer", async () => {
    const artifact = await createArtifact({ receiptSigningJwk: OTHER_PRIVATE_JWK });
    await expectVerificationFailure(artifact.input, "receipt-signature", "SIGNATURE_INVALID");
  });

  it("rejects a signed receipt that references a different closed mandate", async () => {
    const artifact = await createArtifact({ receiptReference: sha256Base64Url("another-leaf") });
    await expectVerificationFailure(artifact.input, "receipt-claims", "RECEIPT_REFERENCE_MISMATCH");
  });

  it("accepts the AP2 Error receipt claim variant when its reference is bound", async () => {
    const artifact = await createArtifact({ receiptStatus: "Error" });
    const result = await verifyAp2MandateChainAndReceipt(artifact.input);
    expect(result.paymentReceipt.status).toBe("Error");
  });

  it("rejects a disclosure whose bytes do not match the signed digest", async () => {
    const artifact = await createArtifact();
    const [root, leaf] = artifact.input.mandateChain.split("~~");
    if (root === undefined || leaf === undefined) throw new Error("test artifact chain malformed");
    const rootParts = root.split("~");
    const disclosure = rootParts[1];
    if (disclosure === undefined) throw new Error("test artifact has no root disclosure");
    const decoded = JSON.parse(Buffer.from(disclosure, "base64url").toString("utf8")) as unknown[];
    decoded[0] = "tampered-salt";
    rootParts[1] = Buffer.from(JSON.stringify(decoded)).toString("base64url");
    artifact.input.mandateChain = `${rootParts.join("~")}~~${leaf}`;

    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it.each([
    ["property disclosure", "property-disclosure"],
    ["direct delegate digest", "digest-string"],
    ["inline delegate payload", "inline"],
  ] as const)(
    "resolves the pinned-compatible %s representation",
    async (_label, representation) => {
      const artifact = await createArtifact({
        rootSerialization: representation,
        leafSerialization: representation,
      });
      await expect(verifyAp2MandateChainAndReceipt(artifact.input)).resolves.toMatchObject({
        openMandate: artifact.openMandate,
        closedMandate: artifact.closedMandate,
      });
    },
  );

  it.each(["sha-384", "sha-512"] as const)(
    "uses the root %s algorithm for disclosure and sd_hash binding",
    async (algorithm) => {
      const artifact = await createArtifact({
        rootSdAlgorithm: algorithm,
        leafSdAlgorithm: algorithm,
      });
      await expect(verifyAp2MandateChainAndReceipt(artifact.input)).resolves.toBeDefined();
    },
  );

  it("uses sha-256 when _sd_alg is absent", async () => {
    const artifact = await createArtifact({ rootSdAlgorithm: null, leafSdAlgorithm: null });
    await expect(verifyAp2MandateChainAndReceipt(artifact.input)).resolves.toBeDefined();
  });

  it("rejects an unsupported SD-JWT digest algorithm", async () => {
    const artifact = await createArtifact({ rootSdAlgorithm: "sha-999" });
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it("rejects a missing cnf key binding", async () => {
    const artifact = await createArtifact({
      mutateOpenMandate: (mandate) => {
        mandate.cnf = undefined;
      },
    });
    await expectVerificationFailure(artifact.input, "key-binding", "CNF_INVALID");
  });

  it("rejects an invalid public cnf JWK", async () => {
    const artifact = await createArtifact({
      mutateOpenMandate: (mandate) => {
        mandate.cnf = { jwk: { kty: "RSA" } };
      },
    });
    await expectVerificationFailure(artifact.input, "key-binding", "JWK_INVALID");
  });

  it("rejects issuer_jwt_hash in this sd_hash-bound terminal profile", async () => {
    const artifact = await createArtifact({
      mutateLeafEnvelope: (envelope) => {
        envelope.sd_hash = undefined;
        envelope.issuer_jwt_hash = "A".repeat(43);
      },
    });
    await expectVerificationFailure(artifact.input, "leaf-binding", "SD_HASH_INVALID");
  });

  it("rejects a terminal token with no iat", async () => {
    const artifact = await createArtifact({
      mutateLeafEnvelope: (envelope) => {
        envelope.iat = undefined;
      },
    });
    await expectVerificationFailure(artifact.input, "leaf-claims", "IAT_INVALID");
  });

  it.each([
    [
      "expired open mandate",
      {
        mutateOpenMandate: (mandate: Record<string, unknown>) => {
          mandate.exp = NOW - 31;
        },
      },
      "root-claims",
    ],
    [
      "expired closed mandate",
      {
        mutateClosedMandate: (mandate: Record<string, unknown>) => {
          mandate.exp = NOW - 31;
        },
      },
      "leaf-claims",
    ],
  ] as const)("rejects an %s", async (_label, options, stage) => {
    const artifact = await createArtifact(options);
    await expectVerificationFailure(artifact.input, stage, "EXP_INVALID");
  });

  it("rejects a malformed open delegate payload", async () => {
    const artifact = await createArtifact({
      mutateRootEnvelope: (envelope) => {
        envelope.delegate_payload = [];
        envelope._sd = undefined;
      },
      rootSerialization: "inline",
    });
    await expectVerificationFailure(artifact.input, "root-claims", "DELEGATE_PAYLOAD_INVALID");
  });

  it("rejects a non-payment root delegate payload", async () => {
    const artifact = await createArtifact({
      mutateOpenMandate: (mandate) => {
        mandate.vct = "mandate.checkout.open.1";
      },
    });
    await expectVerificationFailure(artifact.input, "root-claims", "MANDATE_TYPE_INVALID");
  });

  it("rejects a closed mandate missing required payment claims", async () => {
    const artifact = await createArtifact({
      mutateClosedMandate: (mandate) => {
        mandate.payee = undefined;
      },
    });
    await expectVerificationFailure(artifact.input, "leaf-claims", "MANDATE_TYPE_INVALID");
  });

  it("rejects a signed receipt missing status-specific claims", async () => {
    const artifact = await createArtifact({
      mutateReceipt: (receipt) => {
        receipt.network_confirmation_id = undefined;
      },
    });
    await expectVerificationFailure(artifact.input, "receipt-claims", "RECEIPT_CLAIMS_INVALID");
  });

  it("rejects an expired receipt", async () => {
    const artifact = await createArtifact({
      mutateReceipt: (receipt) => {
        receipt.exp = NOW - 31;
      },
    });
    await expectVerificationFailure(artifact.input, "receipt-claims", "EXP_INVALID");
  });

  it.each(["no-separator", "too~~many~~hops"])("rejects malformed chain %s", async (chain) => {
    const artifact = await createArtifact();
    artifact.input.mandateChain = chain;
    await expectVerificationFailure(artifact.input, "input", "CHAIN_MALFORMED");
  });

  it("rejects a private JWK supplied as a trusted public key", async () => {
    const artifact = await createArtifact();
    artifact.input.trustedRootPublicJwk = ROOT_PRIVATE_JWK;
    await expectVerificationFailure(artifact.input, "root-signature", "JWK_INVALID");
  });

  it("rejects an input with an empty expected audience", async () => {
    const artifact = await createArtifact();
    artifact.input.expectedAudience = "";
    await expectVerificationFailure(artifact.input, "input", "CHAIN_MALFORMED");
  });

  it("rejects a malformed issuer JWT before attempting signature verification", async () => {
    const artifact = await createArtifact();
    const leaf = artifact.input.mandateChain.split("~~")[1];
    if (leaf === undefined) throw new Error("test artifact chain malformed");
    artifact.input.mandateChain = `not-a-jwt~disclosure~~${leaf}`;
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it("reports a JWK import failure for malformed P-256 coordinates", async () => {
    const artifact = await createArtifact();
    artifact.input.trustedRootPublicJwk = {
      ...artifact.input.trustedRootPublicJwk,
      x: "A",
    };
    await expectVerificationFailure(artifact.input, "root-signature", "JWK_INVALID");
  });

  it("rejects duplicate disclosures even when both match a signed digest", async () => {
    const artifact = await createArtifact();
    const [root, leaf] = artifact.input.mandateChain.split("~~");
    const disclosure = root?.split("~")[1];
    if (root === undefined || leaf === undefined || disclosure === undefined) {
      throw new Error("test artifact chain malformed");
    }
    artifact.input.mandateChain = `${root}~${disclosure}~~${leaf}`;
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it("rejects a non-base64url disclosure", async () => {
    const artifact = await createArtifact();
    const [root, leaf] = artifact.input.mandateChain.split("~~");
    const issuerJwt = root?.split("~")[0];
    if (issuerJwt === undefined || leaf === undefined)
      throw new Error("test artifact chain malformed");
    artifact.input.mandateChain = `${issuerJwt}~%~~${leaf}`;
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it("rejects a non-string _sd_alg", async () => {
    const artifact = await createArtifact({
      mutateRootEnvelope: (envelope) => {
        envelope._sd_alg = 7;
      },
    });
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it("ignores an undisclosed property digest while resolving presented disclosures", async () => {
    const artifact = await createArtifact({
      rootSerialization: "property-disclosure",
      mutateRootEnvelope: (envelope) => {
        if (!Array.isArray(envelope._sd)) throw new Error("test envelope has no _sd");
        envelope._sd.push("A".repeat(43));
      },
    });
    await expect(verifyAp2MandateChainAndReceipt(artifact.input)).resolves.toBeDefined();
  });

  it("rejects a disclosed property that collides with an existing signed property", async () => {
    const artifact = await createArtifact({
      rootSerialization: "property-disclosure",
      mutateRootEnvelope: (envelope) => {
        envelope.delegate_payload = [];
      },
    });
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });

  it("rejects a property disclosure whose claim name can affect object prototypes", async () => {
    const artifact = await createArtifact({
      rootSerialization: "property-disclosure",
      rootPropertyName: "__proto__",
    });
    await expectVerificationFailure(artifact.input, "root-disclosures", "DISCLOSURE_INVALID");
  });
});

async function createArtifact(options: ArtifactOptions = {}): Promise<TestArtifact> {
  const holderPublicJwk = publicJwk(HOLDER_PRIVATE_JWK);
  const openMandate: Record<string, unknown> = {
    vct: "mandate.payment.open.1",
    constraints: [
      {
        type: "payment.reference",
        conditional_transaction_id:
          options.openCheckoutReferenceInMandate ?? OPEN_CHECKOUT_REFERENCE,
      },
      {
        type: "payment.amount_range",
        currency: "USD",
        min: 1,
        max: 25_000,
      },
    ],
    cnf: { jwk: holderPublicJwk },
    iat: NOW - 60,
    exp: NOW + 600,
  };
  options.mutateOpenMandate?.(openMandate);
  const rootSdAlgorithm =
    options.rootSdAlgorithm === undefined ? "sha-256" : options.rootSdAlgorithm;
  const rootSerialization = serializeDelegatePayload(
    openMandate,
    "root-mandate-salt",
    options.rootSerialization ?? "array-disclosure",
    rootSdAlgorithm,
    options.rootPropertyName,
  );
  const rootPayload = rootSerialization.envelope;
  options.mutateRootEnvelope?.(rootPayload);
  const rootHeader: CompactJWSHeaderParameters = { alg: "ES256", kid: "test-root" };
  if (options.rootTyp !== null) rootHeader.typ = options.rootTyp ?? "ap2+sd-jwt";
  const rootIssuerJwt = await signCompactJwt(
    rootPayload,
    options.rootSigningJwk ?? ROOT_PRIVATE_JWK,
    rootHeader,
  );
  const rootSdJwt = compactSdJwt(rootIssuerJwt, rootSerialization.disclosures);

  const closedMandate: Record<string, unknown> = {
    vct: "mandate.payment.1",
    transaction_id: OPEN_CHECKOUT_REFERENCE,
    payee: { id: "merchant-1", name: "Test Merchant" },
    payment_amount: { amount: 19_900, currency: "USD" },
    payment_instrument: { id: "instrument-1", type: "x402" },
    iat: NOW - 10,
    exp: NOW + 300,
  };
  options.mutateClosedMandate?.(closedMandate);
  const leafSdAlgorithm =
    options.leafSdAlgorithm === undefined ? "sha-256" : options.leafSdAlgorithm;
  const leafSerialization = serializeDelegatePayload(
    closedMandate,
    "closed-mandate-salt",
    options.leafSerialization ?? "array-disclosure",
    leafSdAlgorithm,
  );
  const leafPayload: Record<string, unknown> = {
    ...leafSerialization.envelope,
    iat: options.leafIat ?? NOW - 10,
    aud: options.audience ?? "credential-provider",
    nonce: options.nonce ?? "verifier-nonce-1",
    sd_hash: options.sdHash ?? hashForSdAlgorithm(rootSdJwt, rootSdAlgorithm),
  };
  options.mutateLeafEnvelope?.(leafPayload);
  const leafIssuerJwt = await signCompactJwt(
    leafPayload,
    options.leafSigningJwk ?? HOLDER_PRIVATE_JWK,
    { alg: "ES256", typ: options.leafTyp ?? "kb+sd-jwt" },
  );
  const leafSdJwt = compactSdJwt(leafIssuerJwt, leafSerialization.disclosures);
  const closedMandateReference = sha256Base64Url(leafIssuerJwt);

  const receipt: Record<string, unknown> =
    options.receiptStatus === "Error"
      ? {
          status: "Error",
          iss: "processor.example",
          iat: NOW,
          reference: options.receiptReference ?? closedMandateReference,
          payment_id: "payment-1",
          error: "payment_declined",
          error_description: "The test payment was declined",
        }
      : {
          status: "Success",
          iss: "processor.example",
          iat: NOW,
          reference: options.receiptReference ?? closedMandateReference,
          payment_id: "payment-1",
          psp_confirmation_id: "psp-confirmation-1",
          network_confirmation_id: "network-confirmation-1",
        };
  options.mutateReceipt?.(receipt);
  const paymentReceiptJwt = await signCompactJwt(
    receipt,
    options.receiptSigningJwk ?? RECEIPT_PRIVATE_JWK,
    { alg: "ES256", typ: "JWT", kid: "test-receipt" },
  );

  return {
    input: {
      // MandateClient.present removes the root token's final '~' before '~~'.
      mandateChain: `${rootSdJwt.slice(0, -1)}~~${leafSdJwt}`,
      trustedRootPublicJwk: publicJwk(ROOT_PRIVATE_JWK),
      paymentReceiptJwt,
      trustedReceiptPublicJwk: publicJwk(RECEIPT_PRIVATE_JWK),
      expectedAudience: "credential-provider",
      expectedNonce: "verifier-nonce-1",
      verifiedAtEpochSeconds: NOW,
      clockSkewSeconds: 30,
      openCheckoutReference: OPEN_CHECKOUT_REFERENCE,
    },
    openMandate,
    closedMandate,
    receipt,
    closedMandateReference,
  };
}

async function signCompactJwt(
  payload: Record<string, unknown>,
  privateJwk: JWK,
  protectedHeader: CompactJWSHeaderParameters,
): Promise<string> {
  const key = await importJWK(privateJwk, "ES256");
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader(protectedHeader)
    .sign(key);
}

function disclosure(salt: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, value])).toString("base64url");
}

function propertyDisclosure(salt: string, name: string, value: unknown): string {
  return Buffer.from(JSON.stringify([salt, name, value])).toString("base64url");
}

function serializeDelegatePayload(
  mandate: Record<string, unknown>,
  salt: string,
  style: SdSerialization,
  sdAlgorithm: string | null,
  propertyName = "delegate_payload",
): { envelope: Record<string, unknown>; disclosures: string[] } {
  const envelope: Record<string, unknown> = {};
  if (sdAlgorithm !== null) envelope._sd_alg = sdAlgorithm;
  if (style === "inline") {
    envelope.delegate_payload = [mandate];
    return { envelope, disclosures: [] };
  }
  if (style === "property-disclosure") {
    const encoded = propertyDisclosure(salt, propertyName, [mandate]);
    envelope._sd = [hashForSdAlgorithm(encoded, sdAlgorithm)];
    return { envelope, disclosures: [encoded] };
  }
  const encoded = disclosure(salt, mandate);
  const digest = hashForSdAlgorithm(encoded, sdAlgorithm);
  envelope.delegate_payload = style === "digest-string" ? [digest] : [{ "...": digest }];
  return { envelope, disclosures: [encoded] };
}

function compactSdJwt(issuerJwt: string, disclosures: readonly string[]): string {
  return disclosures.length === 0 ? `${issuerJwt}~` : `${issuerJwt}~${disclosures.join("~")}~`;
}

function hashForSdAlgorithm(value: string, algorithm: string | null): string {
  const nodeAlgorithm =
    algorithm === "sha-384" ? "sha384" : algorithm === "sha-512" ? "sha512" : "sha256";
  return createHash(nodeAlgorithm).update(value, "ascii").digest("base64url");
}

function sha256Base64Url(value: string): string {
  return createHash("sha256").update(value, "ascii").digest("base64url");
}

function deterministicPrivateJwk(scalar: number): JWK {
  const privateKey = Buffer.alloc(32);
  privateKey[31] = scalar;
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  const publicKey = ecdh.getPublicKey(undefined, "uncompressed");
  return {
    kty: "EC",
    crv: "P-256",
    d: privateKey.toString("base64url"),
    x: publicKey.subarray(1, 33).toString("base64url"),
    y: publicKey.subarray(33, 65).toString("base64url"),
    alg: "ES256",
  };
}

function publicJwk(privateKey: JWK): JWK {
  if (
    typeof privateKey.kty !== "string" ||
    typeof privateKey.crv !== "string" ||
    typeof privateKey.x !== "string" ||
    typeof privateKey.y !== "string"
  ) {
    throw new TypeError("deterministic test key is malformed");
  }
  return {
    kty: privateKey.kty,
    crv: privateKey.crv,
    x: privateKey.x,
    y: privateKey.y,
    alg: "ES256",
  };
}

async function expectVerificationFailure(
  input: VerifyAp2CryptoInput,
  stage: Ap2CryptoVerificationStage,
  code: Ap2CryptoVerificationCode,
): Promise<void> {
  try {
    await verifyAp2MandateChainAndReceipt(input);
    throw new Error("Expected AP2 verification to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(Ap2CryptoVerificationError);
    expect(error).toMatchObject({ stage, code });
  }
}
