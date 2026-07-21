# Pulse AP2–x402 conformance verifier

This repository contains an experimental, non-normative conformance profile for checking whether
a verified AP2 v0.2 Payment Mandate still describes the same payment that an x402 v2 EVM payload
authorized and a facilitator reported as settled.

The terms used by the implementation are fixed before the code in
[`referent-table-public-conformance-implementation.md`](referent-table-public-conformance-implementation.md).
In particular:

- **適合試験入力 (`ConformanceCase`) とは**、one AP2 authorization record, x402 payment record,
  EIP-3009 authorization, settlement result, and expected decision bundled as JSON.
- **照合失敗記録 (`ConformanceFailure`) とは**、a stable code, path, expected value, and actual
  value explaining one mismatch or unverifiable condition.
- **オフライン検証境界 (`OfflineVerificationBoundary`) とは**、the rule that the verifier reads
  local JSON only and never needs a private key, RPC endpoint, transfer, customer record, or hosted
  Pulse service.

## What the verifier checks

- The Open Payment Mandate root SD-JWT verifies against the supplied trusted P-256 public JWK.
- The terminal `kb+sd-jwt` verifies against `cnf.jwk`, including `sd_hash`, audience, nonce,
  issuance time, expiry, disclosures, and the Checkout reference.
- The signed Payment Receipt JWT verifies against its supplied trusted public JWK and references the
  final closed-mandate leaf JWT.
- The normalized AP2 claims and local canonical integrity hashes still match the claims extracted
  from those signed artifacts.
- Every case carries the exact AP2/x402 source pins and a non-normative JCS/SHA-256 `inputHash`
  covering the verification inputs; stale hashes fail closed.
- The bounded conformance profile rejects unknown fields in AP2 claims, constraints, receipts, and
  the signed x402 extension instead of silently accepting semantics it does not evaluate.
- Every signed amount, payee, payment-reference, and allowed-instrument constraint is enforced;
  matching one instrument by `id` alone does not bypass another constraint.
- The signed closed mandate `transaction_id` and Open Mandate `payment.reference` both match the
  independently supplied Open Checkout reference.
- The signed `payment_instrument.x402` extension survives parsing and binds `scheme`, CAIP-2
  `network`, `asset`, atomic `amount`, `payTo`, `payer`, timeout, EIP-712 domain, AP2 payee ID, and
  AP2 commerce amount.
- Fixture generation exercises the pinned `@x402/core` `x402Client` with the pinned `@x402/evm`
  `ExactEvmScheme`. The public producer first requires one exact/EIP-3009 requirement whose AP2
  reference and nonce-derivation rule match the verified input. An explicit after-payment-creation
  hook then replaces the producer's random nonce and time window with the AP2-derived nonce and
  deterministic fixture times and re-signs the modified EIP-3009 message.
- The resulting x402 `PaymentPayload` includes the producer-supplied `resource`; its `accepted`
  requirements and EIP-3009 authorization match the checked payment fields.
- A standard exact/EIP-3009 `SettleResponse` may report only `success`, `transaction`, `network`,
  and `payer`. The verifier checks those fields and checks `amount` only when the optional standard
  field is present; it does not require a synthetic settlement `extra` or AP2-reference echo.
- The EIP-3009 nonce is the 32-byte value encoded by the final closed-mandate reference derived from
  the verified leaf JWT, and the EIP-712 signature recovers the expected payer address.
- AP2 Payment Receipt `reference` and network confirmation point to the checked mandate and x402
  transaction. The local canonical claims hashes are separate, non-normative integrity checks.
- The full 80-case verification report has a pinned JCS/SHA-256 regression hash so public failure
  codes, paths, messages, and computed values cannot drift unnoticed. Mutation scoring excludes the
  noisy `StringLiteral` mutator and measures behavioral mutations in conditions, operators, and
  control flow; the configured breaking threshold remains 70%.

## What the verifier does not claim

This is not an AP2 or x402 standard, an audit, a facilitator, a wallet, or proof that an on-chain
transaction actually exists. Equality between the receipt and settlement transaction identifiers
is field agreement, not on-chain proof. The supplied public JWKs are explicit fixture trust inputs;
the verifier does not establish that they belong to a production issuer. It also does not verify
ERC-1271/ERC-6492 signatures, token balances, nonce consumption, chain finality, legal
authorization, or regulatory compliance. Those checks need an online verifier or additional trust
policy. See
[`docs/guarantee-boundary.md`](docs/guarantee-boundary.md).

## Run the committed fixtures from a source checkout

```bash
npm ci
npm run fixtures:generate
npm run fixtures:verify
npm test
```

Recreate the signed AP2 artifacts with the exact pinned Python implementation. This requires
Python 3.12 and exactly `uv 0.10.11`:

```bash
sh scripts/ap2/run-pinned.sh
```

Verify another bundle:

```bash
npx tsx src/cli.ts path/to/cases.json
```

The committed corpus under `fixtures/v0.1` contains 20 cryptographically consistent cases and 60
fail-closed mutation cases spanning Base Sepolia and a local EVM fixture. Here, `v0.1` identifies
the fixture-format revision; it is not a project, package, tag, or grant-ready release. Every case
uses public, deterministic test identities. Runtime verification performs no network request; only
the separate reproduction script downloads the pinned AP2 source when no local checkout is
supplied. The reproduction and `tsx` commands above target a Git source checkout; the private
package preview is not a self-contained source distribution.

## Source pins

The profile is based on AP2 commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` and x402
Foundation commit `67b1ba0a7abbd7907a28fa624670872532e0eae9` / packages `2.19.0`.
See [`docs/source-pins.md`](docs/source-pins.md) and [`docs/field-mapping.md`](docs/field-mapping.md).

## Current maturity

`0.0.0` is an implementation preview. The package remains intentionally marked `private`; a tagged
`v0.1` release requires external implementer feedback, upstream review, an independent security
review, and a sustained green-CI window. Apache-2.0 applies to this repository's original code.
