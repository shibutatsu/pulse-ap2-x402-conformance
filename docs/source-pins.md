# The verifier pins AP2 and x402 inputs so fixture results remain reproducible

| Source | Pinned version | Used for |
| --- | --- | --- |
| [AP2](https://github.com/google-agentic-commerce/AP2/tree/e1ea56db72a6385bce3e5c1112b3a56ce60acb43) | commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`, v0.2-era schemas | Payment Mandate, Open Payment Mandate constraints, Payment Receipt |
| [x402 Foundation](https://github.com/x402-foundation/x402/tree/67b1ba0a7abbd7907a28fa624670872532e0eae9) | commit `67b1ba0a7abbd7907a28fa624670872532e0eae9`, `@x402/core` and `@x402/evm` 2.19.0 | v2 `x402Client`, `ExactEvmScheme`, resource-bearing payload schema, standard settlement fields, and EIP-3009 typed data |
| [AP2 issue #299](https://github.com/google-agentic-commerce/AP2/issues/299) | open issue observed 2026-07-21 | Extension-field loss and ID-only instrument matching regression cases |
| [AP2 issue #265](https://github.com/google-agentic-commerce/AP2/issues/265) | unadopted proposal observed 2026-07-21 | Explicitly not used as a normative JCS/hash rule |

The deterministic Python pipeline uses the pinned AP2 implementation to generate and independently
re-verify 20 signed chains. The TypeScript runtime then verifies the committed compact artifacts
without importing or calling the Python implementation. The JSON fixtures copy no upstream
implementation code; field names and semantics are recorded for interoperability testing. Updating
either pin requires a new fixture version and a changelog entry.

Fixture generation calls the pinned `@x402/core` `x402Client` with the pinned `@x402/evm`
`ExactEvmScheme`; it does not hand-assemble the successful producer output. Before generation, the
profile requires one exact/EIP-3009 requirement and checks that its AP2 reference and nonce
derivation rule match the verified input. An explicit after-payment-creation hook replaces the
producer's random EIP-3009 nonce and time window with that AP2-derived nonce and deterministic
fixture times, re-signs the modified message, and preserves the standard `resource`, `accepted`,
and extension fields. Tests validate the result against both the pinned upstream payload schema and
this profile's narrower schema.

The pinned exact/EIP-3009 success response may contain only `success`, `transaction`, `network`,
and `payer`. The profile therefore checks `amount` only when the optional standard field is present
and does not require a synthetic settlement `extra` or AP2-reference echo. Matching transaction
identifiers are offline field agreement, not proof of an on-chain transaction.
