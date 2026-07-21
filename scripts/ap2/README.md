# Pinned AP2 signed fixture pipeline

This directory creates 20 synthetic AP2 authorization records with actual
ES256 signatures at AP2 commit
`e1ea56db72a6385bce3e5c1112b3a56ce60acb43`.

An Open Payment Mandate artifact is the issuer-signed root SD-JWT and its
disclosures. A Terminal Closed Payment Mandate artifact is the second,
`kb+sd-jwt` hop signed by the holder key named in the root mandate's
`cnf.jwk`. A Payment Receipt artifact is the compact issuer-signed JWT whose
`reference` equals the closed mandate reference.

## Reproduce the signed chains and re-verify every recorded claim

From the repository root, run:

```sh
sh scripts/ap2/run-pinned.sh
```

The wrapper requires exactly `uv 0.10.11`, clones the official AP2 repository
into a temporary cache when no source directory is supplied, checks out the
exact commit, rejects a dirty source tree, and creates a CPython 3.12
environment. It then synchronizes every dependency from the hash-locked
`requirements.lock.txt`, builds AP2 with the pinned build backend, generates
the signed artifacts, and independently re-verifies and extracts them.

To use an already checked-out copy of the exact AP2 commit:

```sh
AP2_SOURCE_DIR=/absolute/path/to/AP2 sh scripts/ap2/run-pinned.sh
```

The two committed outputs are:

- `fixtures/v0.1/ap2-signed-artifacts.json`: compact signed tokens, fixed
  public JWKs, expected audience/nonce/reference values, and 20 cases.
- `fixtures/v0.1/ap2-normalized-records.json`: raw verified mandate claims,
  parsed receipt claims, and verification records suitable for joining to the
  TypeScript x402 cases.

## Preserve the signed x402 extension despite AP2 issue 299

An x402-preserving PaymentInstrument is a fixture-only Pydantic model that
keeps the `x402` object beside AP2's `id`, `type`, and `description` fields.
The generated AP2 model at the pinned commit drops additional fields during
Pydantic validation. The pipeline therefore uses the extra-allow model only
while constructing and extracting the upstream SD-JWT primitives, then also
runs the upstream generated models and `PaymentMandateChain.verify` for the
standard AP2 constraints. The extractor adds exact equality of the signed
open and closed x402 extensions because the pinned SDK's allowed-instrument
evaluator compares only the instrument ID.

## Interpret the closed mandate reference exactly as the pinned SDK does

A closed mandate reference is base64url(SHA-256(leaf issuer JWT)), where the
leaf issuer JWT is the exact string returned by
`MandateClient.get_closed_mandate_jwt`. The 32 bytes obtained by base64url
decoding that reference are recorded as the EIP-3009 nonce. This avoids using
a non-adopted canonical-claims hash as an AP2 protocol reference.

## Keep the evidence boundary narrower than settlement proof

The fixture keys are derived from public labels and are intentionally unsafe
for production. Deterministic salts and RFC 6979 signatures exist only to make
committed test vectors byte-for-byte reproducible.

The verifier proves that the included Open Payment Mandate, terminal closed
Payment Mandate, and Payment Receipt are internally consistent and signed by
the included public fixture keys. Its receipt-store callback checks the
reference against the same artifact bundle. It does not prove that a payment
settled on a live network, that the synthetic Open Checkout reference came
from a separately verified Checkout Mandate, or that any fixture identity is
trusted outside this repository.
