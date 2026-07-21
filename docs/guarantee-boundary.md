# The offline verifier guarantees field agreement, not chain existence or legal authorization

| The verifier can establish from local input | The verifier cannot establish offline |
| --- | --- |
| Open SD-JWT root signature, terminal key binding, disclosures, `sd_hash`, audience, nonce, and time claims verify against the supplied keys and context | The supplied root and receipt public JWKs are legitimate production trust anchors |
| The signed Payment Receipt JWT verifies and references the leaf-JWT-derived closed-mandate reference | The receipt corresponds to a payment that occurred on a live network |
| Non-normative canonical AP2 claims hashes match the claims extracted from the verified tokens | A local canonical claims hash is a normative AP2 mandate or transaction reference |
| AP2 instrument extension, x402 requirement, resource-bearing accepted payload, and EIP-3009 message agree; the settlement's standard `network`, `payer`, and `transaction` fields, plus optional `amount` when present, match the corresponding checked values | Equality of transaction identifiers proves that the settlement transaction exists, succeeded on-chain, is final, or emitted the expected token event |
| The EIP-712 signature recovers the expected ECDSA address for the supplied domain and message | Whether that address is an EOA, or whether an ERC-1271/ERC-6492 smart-account signature is valid |
| The EIP-3009 nonce equals the 32 bytes encoded by the verified leaf JWT's final closed-mandate reference | The nonce is unused on-chain or cannot be replayed on another incompatible token implementation |
| The fixture contains no unknown profile field | Future AP2/x402 extensions are safe; unsupported extensions fail closed |
| The case-level JCS/SHA-256 input hash matches the pinned versions and supplied verification input | The input hash authenticates its author; it is an integrity checksum, not a signature or AP2 reference |

The verdict depends on compact signed artifacts and public verification keys, not caller-set
verification booleans. Production integrators must supply authenticated trust anchors and their own
expected audience, nonce, Checkout reference, and verification time. The fixture's synthetic Open
Checkout reference is context input, not a separately verified Checkout Mandate chain.

Fixture-generation tests exercise the pinned `@x402/core` `x402Client` and `@x402/evm`
`ExactEvmScheme`. An explicit after-payment-creation hook replaces the standard producer's random
nonce and time window with the AP2-derived nonce and deterministic fixture times, then re-signs the
modified EIP-3009 message. The resulting `PaymentPayload` retains its standard `resource` field.
This does not prove that an unrelated producer or facilitator will apply the same profile hook.

A standard exact/EIP-3009 success response may contain only `success`, `transaction`, `network`,
and `payer`. The verifier checks `amount` only when supplied and requires no synthetic settlement
`extra` or AP2-reference echo.

The pinned AP2 JSON schemas do not universally forbid additional properties. This conformance
profile intentionally narrows them to the fields it evaluates and rejects the rest. Supporting a
new AP2 field or constraint therefore requires an explicit profile version and verifier change.

The profile deliberately does not treat a locally canonicalized claims hash as an AP2-standard
transaction or mandate reference. AP2 issue #265 discusses canonical hashing as a proposal, but the
profile does not assume that proposal is adopted.
