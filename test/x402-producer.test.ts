import { createHash } from "node:crypto";
import { PaymentPayloadV2Schema, type PaymentRequiredV2 } from "@x402/core/schemas";
import {
  type Address,
  type Hex,
  getAddress,
  keccak256,
  recoverTypedDataAddress,
  stringToHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { deriveEip3009Nonce } from "../src/canonical.js";
import { X402SettlementSchema } from "../src/types.js";
import { createAp2BoundX402PaymentPayload } from "../src/x402-producer.js";

const FIXTURE_SIGNER = privateKeyToAccount(
  keccak256(stringToHex("pulse-ap2-x402-conformance/x402-producer-fixture/v1")),
);
const ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAY_TO = "0x1111111111111111111111111111111111111111";
const NETWORK = "eip155:84532";
const VALID_AFTER = "1750000000";
const VALID_BEFORE = "1750000300";
const CLOSED_MANDATE_REFERENCE = createHash("sha256")
  .update("pulse-public-ap2-closed-mandate-reference-v1", "utf8")
  .digest("base64url");
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

const paymentRequired: PaymentRequiredV2 = {
  x402Version: 2,
  resource: {
    url: "https://example.org/pulse/conformance/resource",
    description: "Public AP2-bound x402 conformance fixture",
    mimeType: "application/json",
    serviceName: "Pulse conformance",
    tags: ["ap2", "x402"],
    iconUrl: "https://example.org/pulse.svg",
  },
  accepts: [
    {
      scheme: "exact",
      network: NETWORK,
      amount: "250000",
      asset: ASSET,
      payTo: PAY_TO,
      maxTimeoutSeconds: 300,
      extra: {
        name: "USDC",
        version: "2",
        assetTransferMethod: "eip3009",
        ap2MandateReference: CLOSED_MANDATE_REFERENCE,
        ap2NonceDerivation: "base64url-decode-ap2-mandate-reference",
      },
    },
  ],
  extensions: {
    "org.ethereum.ap2": {
      closedMandateReference: CLOSED_MANDATE_REFERENCE,
    },
  },
};

interface ProducedAuthorization {
  authorization: {
    from: string;
    to: string;
    value: string;
    validAfter: string;
    validBefore: string;
    nonce: string;
  };
  signature: string;
}

describe("createAp2BoundX402PaymentPayload", () => {
  it("preserves the upstream v2 envelope and re-signs the AP2-bound authorization", async () => {
    const result = await createAp2BoundX402PaymentPayload({
      paymentRequired,
      fixtureSigner: FIXTURE_SIGNER,
      closedMandateReference: CLOSED_MANDATE_REFERENCE,
      validAfter: VALID_AFTER,
      validBefore: VALID_BEFORE,
    });

    expect(PaymentPayloadV2Schema.safeParse(result).success).toBe(true);
    expect(result.resource).toEqual(paymentRequired.resource);
    expect(result.accepted).toEqual(paymentRequired.accepts[0]);
    expect(result.extensions).toEqual(paymentRequired.extensions);

    const produced = result.payload as unknown as ProducedAuthorization;
    expect(produced.authorization).toMatchObject({
      from: FIXTURE_SIGNER.address,
      to: getAddress(PAY_TO),
      value: paymentRequired.accepts[0]?.amount,
      validAfter: VALID_AFTER,
      validBefore: VALID_BEFORE,
      nonce: deriveEip3009Nonce(CLOSED_MANDATE_REFERENCE),
    });

    const recovered = await recoverTypedDataAddress({
      domain: {
        name: "USDC",
        version: "2",
        chainId: 84532,
        verifyingContract: getAddress(ASSET),
      },
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: getAddress(produced.authorization.from) as Address,
        to: getAddress(produced.authorization.to) as Address,
        value: BigInt(produced.authorization.value),
        validAfter: BigInt(produced.authorization.validAfter),
        validBefore: BigInt(produced.authorization.validBefore),
        nonce: produced.authorization.nonce as Hex,
      },
      signature: produced.signature as Hex,
    });
    expect(getAddress(recovered)).toBe(getAddress(FIXTURE_SIGNER.address));
  });

  it.each([
    ["non-canonical validAfter", "01", VALID_BEFORE, TypeError],
    ["validAfter outside uint256", (1n << 256n).toString(), VALID_BEFORE, RangeError],
    ["an inverted validity window", VALID_BEFORE, VALID_AFTER, RangeError],
  ] as const)("rejects %s", async (_label, validAfter, validBefore, errorType) => {
    await expect(
      createAp2BoundX402PaymentPayload({
        paymentRequired,
        fixtureSigner: FIXTURE_SIGNER,
        closedMandateReference: CLOSED_MANDATE_REFERENCE,
        validAfter,
        validBefore,
      }),
    ).rejects.toBeInstanceOf(errorType);
  });

  it("rejects an EVM CAIP-2 chain ID that cannot be represented exactly", async () => {
    const unsafeNetworkRequest = structuredClone(paymentRequired);
    const accepted = unsafeNetworkRequest.accepts[0];
    if (accepted === undefined) throw new Error("The fixture must include payment requirements.");
    accepted.network = "eip155:9007199254740992";

    await expect(
      createAp2BoundX402PaymentPayload({
        paymentRequired: unsafeNetworkRequest,
        fixtureSigner: FIXTURE_SIGNER,
        closedMandateReference: CLOSED_MANDATE_REFERENCE,
        validAfter: VALID_AFTER,
        validBefore: VALID_BEFORE,
      }),
    ).rejects.toThrow();
  });

  it.each(["permit2", "unknown-transfer-method", undefined] as const)(
    "rejects a non-EIP-3009 transfer method (%s)",
    async (assetTransferMethod) => {
      const changedRequest = structuredClone(paymentRequired);
      const accepted = changedRequest.accepts[0];
      if (accepted === undefined) throw new Error("The fixture must include payment requirements.");
      if (accepted.extra === undefined || accepted.extra === null) {
        throw new Error("The fixture must include exact-scheme metadata.");
      }
      if (assetTransferMethod === undefined) {
        Reflect.deleteProperty(accepted.extra, "assetTransferMethod");
      } else {
        accepted.extra.assetTransferMethod = assetTransferMethod;
      }

      await expect(
        createAp2BoundX402PaymentPayload({
          paymentRequired: changedRequest,
          fixtureSigner: FIXTURE_SIGNER,
          closedMandateReference: CLOSED_MANDATE_REFERENCE,
          validAfter: VALID_AFTER,
          validBefore: VALID_BEFORE,
        }),
      ).rejects.toThrow();
    },
  );

  it("rejects an advertised AP2 reference different from the verified reference", async () => {
    const mismatchedRequest = structuredClone(paymentRequired);
    const accepted = mismatchedRequest.accepts[0];
    if (accepted === undefined) throw new Error("The fixture must include payment requirements.");
    if (accepted.extra === undefined || accepted.extra === null) {
      throw new Error("The fixture must include exact-scheme metadata.");
    }
    accepted.extra.ap2MandateReference = createHash("sha256")
      .update("different-valid-ap2-reference", "utf8")
      .digest("base64url");

    await expect(
      createAp2BoundX402PaymentPayload({
        paymentRequired: mismatchedRequest,
        fixtureSigner: FIXTURE_SIGNER,
        closedMandateReference: CLOSED_MANDATE_REFERENCE,
        validAfter: VALID_AFTER,
        validBefore: VALID_BEFORE,
      }),
    ).rejects.toThrow("must reference the supplied AP2 closed mandate");
  });

  it.each(["wrong-derivation", undefined] as const)(
    "rejects a missing or unknown AP2 nonce derivation (%s)",
    async (derivation) => {
      const changedRequest = structuredClone(paymentRequired);
      const accepted = changedRequest.accepts[0];
      if (accepted === undefined) throw new Error("The fixture must include payment requirements.");
      if (accepted.extra === undefined || accepted.extra === null) {
        throw new Error("The fixture must include exact-scheme metadata.");
      }
      if (derivation === undefined) {
        Reflect.deleteProperty(accepted.extra, "ap2NonceDerivation");
      } else {
        accepted.extra.ap2NonceDerivation = derivation;
      }

      await expect(
        createAp2BoundX402PaymentPayload({
          paymentRequired: changedRequest,
          fixtureSigner: FIXTURE_SIGNER,
          closedMandateReference: CLOSED_MANDATE_REFERENCE,
          validAfter: VALID_AFTER,
          validBefore: VALID_BEFORE,
        }),
      ).rejects.toThrow();
    },
  );

  it("requires one unambiguous exact payment requirement", async () => {
    const multiple = structuredClone(paymentRequired);
    const onlyRequirement = multiple.accepts[0];
    if (onlyRequirement === undefined) throw new Error("The fixture must include requirements.");
    multiple.accepts.push(structuredClone(onlyRequirement));

    await expect(
      createAp2BoundX402PaymentPayload({
        paymentRequired: multiple,
        fixtureSigner: FIXTURE_SIGNER,
        closedMandateReference: CLOSED_MANDATE_REFERENCE,
        validAfter: VALID_AFTER,
        validBefore: VALID_BEFORE,
      }),
    ).rejects.toThrow("requires exactly one payment requirement");

    const nonExact = structuredClone(paymentRequired);
    const changedRequirement = nonExact.accepts[0];
    if (changedRequirement === undefined) throw new Error("The fixture must include requirements.");
    changedRequirement.scheme = "upto";
    await expect(
      createAp2BoundX402PaymentPayload({
        paymentRequired: nonExact,
        fixtureSigner: FIXTURE_SIGNER,
        closedMandateReference: CLOSED_MANDATE_REFERENCE,
        validAfter: VALID_AFTER,
        validBefore: VALID_BEFORE,
      }),
    ).rejects.toThrow("payment scheme must be exact");
  });

  it("rejects an unknown raw requirement field before the upstream schema can strip it", async () => {
    const changedRequest = structuredClone(paymentRequired);
    const accepted = changedRequest.accepts[0];
    if (accepted === undefined) throw new Error("The fixture must include requirements.");
    Object.assign(accepted, { unexpectedRecipientFallback: PAY_TO });

    await expect(
      createAp2BoundX402PaymentPayload({
        paymentRequired: changedRequest,
        fixtureSigner: FIXTURE_SIGNER,
        closedMandateReference: CLOSED_MANDATE_REFERENCE,
        validAfter: VALID_AFTER,
        validBefore: VALID_BEFORE,
      }),
    ).rejects.toThrow();
  });

  it("accepts the standard exact settlement response without synthetic amount or extra", () => {
    const settlement = {
      success: true,
      payer: FIXTURE_SIGNER.address,
      transaction: `0x${"ab".repeat(32)}`,
      network: NETWORK,
    };

    expect(X402SettlementSchema.parse(settlement)).toEqual(settlement);
  });
});
