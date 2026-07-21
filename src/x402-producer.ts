import { x402Client } from "@x402/core/client";
import {
  type PaymentPayloadV2,
  PaymentPayloadV2Schema,
  type PaymentRequiredV2,
  PaymentRequiredV2Schema,
} from "@x402/core/schemas";
import type { ClientEvmSigner } from "@x402/evm";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { type Address, getAddress } from "viem";
import { deriveEip3009Nonce } from "./canonical.js";
import {
  Eip3009AuthorizationRecordSchema,
  X402PaymentPayloadSchema,
  X402PaymentRequirementsSchema,
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

const UNSIGNED_INTEGER = /^(0|[1-9][0-9]*)$/;
const MAX_UINT256 = (1n << 256n) - 1n;

export interface CreateAp2BoundX402PaymentPayloadInput {
  paymentRequired: PaymentRequiredV2;
  fixtureSigner: ClientEvmSigner;
  closedMandateReference: string;
  validAfter: string;
  validBefore: string;
}

function parseUnsignedInteger(value: string, field: string): bigint {
  if (!UNSIGNED_INTEGER.test(value)) {
    throw new TypeError(`${field} must be a canonical unsigned decimal integer.`);
  }
  const parsed = BigInt(value);
  if (parsed > MAX_UINT256) {
    throw new RangeError(`${field} must fit in uint256.`);
  }
  return parsed;
}

function parseChainId(network: string): number {
  const match = /^eip155:([1-9][0-9]*)$/.exec(network);
  if (match?.[1] === undefined) {
    throw new TypeError("The selected x402 network must be an EVM CAIP-2 identifier.");
  }
  const chainId = Number(match[1]);
  if (!Number.isSafeInteger(chainId)) {
    throw new RangeError("The selected x402 chain ID must fit in a JavaScript safe integer.");
  }
  return chainId;
}

/**
 * Creates a standard x402 v2 EVM-exact payload and binds its EIP-3009 authorization
 * to the verified AP2 closed-mandate reference at the public client hook boundary.
 */
export async function createAp2BoundX402PaymentPayload({
  paymentRequired,
  fixtureSigner,
  closedMandateReference,
  validAfter,
  validBefore,
}: CreateAp2BoundX402PaymentPayloadInput): Promise<PaymentPayloadV2> {
  if (paymentRequired.accepts.length !== 1) {
    throw new RangeError("The AP2-bound producer requires exactly one payment requirement.");
  }
  const selectedRequirement = X402PaymentRequirementsSchema.parse(paymentRequired.accepts[0]);
  const parsedPaymentRequired = PaymentRequiredV2Schema.parse({
    ...paymentRequired,
    accepts: [selectedRequirement],
  });
  if (selectedRequirement.scheme !== "exact") {
    throw new TypeError("The selected x402 payment scheme must be exact.");
  }
  if (selectedRequirement.extra.ap2MandateReference !== closedMandateReference) {
    throw new TypeError(
      "The selected payment requirement must reference the supplied AP2 closed mandate.",
    );
  }

  const validAfterValue = parseUnsignedInteger(validAfter, "validAfter");
  const validBeforeValue = parseUnsignedInteger(validBefore, "validBefore");
  if (validAfterValue >= validBeforeValue) {
    throw new RangeError("validAfter must precede validBefore.");
  }
  const chainId = parseChainId(selectedRequirement.network);
  const verifyingContract = getAddress(selectedRequirement.asset);
  const nonce = deriveEip3009Nonce(closedMandateReference);

  const client = registerExactEvmScheme(new x402Client(), { signer: fixtureSigner });
  client.onAfterPaymentCreation(async ({ paymentPayload }) => {
    const originalPayload = Eip3009AuthorizationRecordSchema.parse(paymentPayload.payload);
    const originalAuthorization = originalPayload.authorization;
    const reboundAuthorization = {
      ...originalAuthorization,
      validAfter,
      validBefore,
      nonce,
    };
    const signature = await fixtureSigner.signTypedData({
      domain: {
        name: selectedRequirement.extra.name,
        version: selectedRequirement.extra.version,
        chainId,
        verifyingContract,
      },
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: getAddress(reboundAuthorization.from) as Address,
        to: getAddress(reboundAuthorization.to) as Address,
        value: parseUnsignedInteger(reboundAuthorization.value, "authorization.value"),
        validAfter: validAfterValue,
        validBefore: validBeforeValue,
        nonce,
      },
    });

    paymentPayload.payload = {
      authorization: reboundAuthorization,
      signature,
    };
  });

  const paymentPayload = await client.createPaymentPayload(
    parsedPaymentRequired as unknown as Parameters<typeof client.createPaymentPayload>[0],
  );
  const profilePayload = X402PaymentPayloadSchema.parse(paymentPayload);
  return PaymentPayloadV2Schema.parse(profilePayload);
}
