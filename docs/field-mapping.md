# Each AP2 authorization field is matched to the x402 and EVM value it constrains

The `payment_instrument.x402` object is an experimental conformance-profile extension, not a
normative AP2 field. Requiring it prevents the current SDK/sample failure mode where payment-method
extensions disappear and fallback recipient or amount values can replace the signed values.

| AP2 verified claim | x402 record | EIP-3009 or settlement record | Required judgment |
| --- | --- | --- | --- |
| Open Mandate `payment.reference.conditional_transaction_id` and closed Mandate `transaction_id` | none | none | both equal the verification context's Open Checkout reference before any x402 binding is accepted |
| `payment_instrument.type = x402` | `requirements.scheme = exact` | exact EIP-3009 payload | all three select the supported profile |
| `payment_instrument.x402.network` | `requirements.network`, `payload.accepted.network` | `settlement.network`, EIP-712 `chainId` | identical CAIP-2 network and derived chain ID |
| `payment_instrument.x402.asset` | `requirements.asset`, `payload.accepted.asset` | EIP-712 `verifyingContract` | same checksummed EVM address |
| `payment_instrument.x402.amount` | `requirements.amount`, `payload.accepted.amount` | authorization `value`; optional settlement `amount` when present | same atomic integer string for every supplied field |
| `payment_instrument.x402.payTo` | `requirements.payTo`, `payload.accepted.payTo` | authorization `to` | same EVM address |
| none; fixture resource input | `PaymentRequired.resource`, `PaymentPayload.resource` | none | the pinned producer preserves the standard resource object in its output |
| AP2 `payee.id` copied into `payment_instrument.x402.ap2PayeeId` | `payment_instrument.x402.payTo` becomes `requirements.payTo` | authorization `to` | the signed profile mapping binds the AP2 merchant identifier to the EVM recipient |
| AP2 `payment_amount` copied into `payment_instrument.x402.ap2PaymentAmount` | `payment_instrument.x402.amount` becomes `requirements.amount` | authorization `value`; optional settlement `amount` when present | the commerce amount and token atomic amount are both signed; no implicit 1:1 conversion is assumed |
| `payment_instrument.x402.payer` | no direct requirement field | authorization `from`, recovered ECDSA address, settlement `payer` | same EVM address; this does not prove the address is an EOA |
| `payment_instrument.x402.maxTimeoutSeconds` | requirements and accepted timeout | authorization `validBefore` relative to fixture time | not expired and not longer than the authorized timeout |
| `payment_instrument.x402.eip712Domain` | `requirements.extra.name/version` | EIP-712 domain | exact name and version |
| final closed-mandate reference derived as base64url(SHA-256(leaf issuer JWT)) | `requirements.extra.ap2MandateReference` and accepted copy | base64url-decoded EIP-3009 nonce, signed AP2 receipt reference | all bind to the same cryptographically verified closed mandate token; no settlement echo is required |
| local canonical claims hashes | none | none | non-normative integrity checks detect mutation after token extraction; they are not AP2 transaction or mandate references |
| signed AP2 Payment Receipt network confirmation | none | settlement transaction | identical 32-byte transaction identifier; equality is not proof of chain existence |
| case-level pinned source versions and JCS/SHA-256 `inputHash` | AP2 and x402 verification input | none | detects stale or accidentally changed fixture input; never substitutes for a signed mandate reference |

AP2 `payment_amount` remains the commerce amount in ISO-4217 minor units. The verifier does not
assume that fiat minor units convert 1:1 to an ERC-20 atomic amount; the signed x402 instrument
extension carries the exact atomic amount instead.

Fixture generation runs the pinned `@x402/core` `x402Client` and `@x402/evm` `ExactEvmScheme`.
Their standard producer first creates the resource-bearing payload; an explicit
after-payment-creation hook then replaces its random nonce and time window with the AP2-derived
nonce and deterministic fixture times and re-signs the modified EIP-3009 message.

The standard exact/EIP-3009 success response can contain only `success`, `transaction`, `network`,
and `payer`. This profile validates `amount` only when that optional standard field is supplied and
does not synthesize settlement `extra` data. Equality between the signed AP2 receipt transaction
identifier and the settlement transaction identifier is field agreement, not proof that the
transaction exists on-chain.
