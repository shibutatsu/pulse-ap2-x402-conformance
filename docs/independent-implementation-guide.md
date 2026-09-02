# Independently reproduce the frozen 80-case AP2-x402 corpus

This guide defines the outside implementation and evidence needed by issue
[#17](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/17). It is a profile contract,
not a walkthrough of the reference implementation. A qualifying implementation must be written and
published by a party independent of Prime Beat.

## Frozen target

| Item | Required value |
| --- | --- |
| Frozen fixture commit | `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e` |
| Evidence validator commit | `fe24b304735c8ab1f38118a89d0a204bc7d00fe8` |
| Fixture | `fixtures/v0.3/cases.json` |
| Raw fixture SHA-256 | `8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0` |
| Bundle and case versions | `ap2-x402-conformance-bundle/0.3` and `ap2-x402-conformance/0.3` |
| Required coverage | Every one of the 80 unique case IDs, exactly once |

Use the AP2 and x402 commits recorded in each case's `sourcePins`. The frozen
[`field-mapping.md`](field-mapping.md), [`guarantee-boundary.md`](guarantee-boundary.md), and
[`source-pins.md`](source-pins.md) define this repository's profile where upstream specifications do
not. Do not mix fields or rules from an archived fixture version.

## Independence rules

- Publish the implementation and result in an outside repository or immutable CI record. Pin the
  implementation revision, build instructions, tests, dependencies, organization, and runtime.
- Do not import, call, port, or copy `src/verifier.ts`, `src/ap2-crypto.ts`, `src/canonical.ts`,
  generated `dist` output, fixture generators, or tests from this repository. General-purpose JSON,
  JOSE, JCS, EIP-712, and secp256k1 libraries are allowed and must be versioned.
- Never read `expected` when computing a result. Never branch on a case `id` or `description`; they are
  labels only. Do not create a lookup table or a corpus-specific exception.
- Freeze the implementation commit and the first 80 results before running the repository's evidence
  validator. A validator disagreement is evidence to investigate from the specifications and the
  independent implementation's own tests, not permission to copy the expected value. Preserve and
  disclose reruns and the reason for any implementation change.
- Run offline. No private key, funded account, RPC endpoint, transaction submission, or secret is
  required for the 80-case reproduction.

## Language-neutral evaluation conditions

The implementation may use any language, but it must make these decisions from the case payload:

1. Parse the bundle and each case fail-closed. Require the v0.3 versions and source pins, 80 unique
   IDs, the profile's exact field shapes, safe object keys, and valid encodings and scalar ranges.
   Recompute `inputHash` as base64url SHA-256 of JCS over `caseVersion`, `sourcePins`,
   `nowEpochSeconds`, `ap2`, and `x402` only.
2. Verify the AP2 Open and closed mandate SD-JWT chain, terminal key-binding JWT, disclosures,
   supplied trust keys, audience, nonce, checkout reference, time claims, and signed Payment Receipt.
   Compare the verified claims with the normalized AP2 records; caller-provided booleans are not
   cryptographic evidence.
3. Enforce the signed AP2 constraints and context, including allowed instrument, non-empty matching
   `Merchant.id`, payment reference and transaction ID, amount presets, mandate expiry, receipt
   success, and receipt reference and transaction bindings. Merchant display metadata is not an
   identity equality rule.
4. Require agreement across the signed AP2 x402 extension, x402 requirements, resource-bearing
   accepted payload, EIP-712 domain, EIP-3009 authorization, and settlement for scheme, network,
   asset, atomic amount, payee/recipient, payer, timeout, and AP2 commerce bindings.
5. Derive the EIP-3009 nonce from the cryptographically verified final closed-mandate reference.
   Check the authorization time window against the fixture time, x402 timeout, and AP2 expiry. Verify
   the EIP-712 signature, canonical low-s form, recovery byte, and recovered payer.
6. Require a successful settlement and agreement of its standard network, payer, and transaction
   fields; compare amount only when supplied. Match the signed AP2 receipt to the settlement. Do not
   infer chain existence or finality from equal local fields.
7. Collect every applicable failure code and sort codes by the frozen controlled order in
   [`src/failures.ts`](../src/failures.ts). Accept only when no failure remains. A missing prerequisite
   must fail closed; it must not be replaced by an assumed downstream value.

These conditions state observable judgments and intentionally omit the reference verifier's control
flow. The implementation should add its own positive, negative, parser, and cryptographic unit tests
before evaluating the corpus.

## Result and failure record

Publish one `pulse-independent-reproduction/0.1` JSON record using the exact schema described in
[`external-evidence.md`](external-evidence.md). Each `results` entry is:

```json
{
  "id": "fixture-case-id",
  "decision": "reject",
  "failureCodes": ["CONTROLLED_FAILURE_CODE"]
}
```

Use `decision: "accept"` only with an empty `failureCodes` array. The record must also identify the
outside repository and commit, language/runtime/command, organization and independence, exact frozen
fixture path/commit/SHA/count, OS/architecture/dependencies, execution time, notes, and a stable HTTPS
publication URL. All 80 IDs must occur exactly once.

## Retrieve, blind, run, and validate

Download the exact bytes and verify them before use:

```bash
curl --fail --location --silent --show-error \
  https://raw.githubusercontent.com/shibutatsu/pulse-ap2-x402-conformance/e06a6cbfe3ddb965c8fc70f50838f5014ec2038e/fixtures/v0.3/cases.json \
  --output frozen-cases.json
echo "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0  frozen-cases.json" \
  | sha256sum --check --strict
jq 'del(.cases[].expected)' frozen-cases.json > evaluator-input.json
```

On macOS, compare `shasum -a 256 frozen-cases.json` with the required hash. Give only
`evaluator-input.json` to the evaluator; its parser may treat the omitted `expected` field as
out-of-band evidence metadata. Preserve `frozen-cases.json` unchanged for the post-run validator.

The following external GitHub Actions job keeps the independent run ahead of the reference result
check. Replace only the `Run the independent implementation` command with the outside repository's
documented command.

```yaml
name: Independent AP2-x402 reproduction

on:
  workflow_dispatch:

permissions:
  contents: read

env:
  PULSE_FIXTURE_COMMIT: e06a6cbfe3ddb965c8fc70f50838f5014ec2038e
  PULSE_VALIDATOR_COMMIT: fe24b304735c8ab1f38118a89d0a204bc7d00fe8
  FIXTURE_SHA256: 8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0

jobs:
  reproduce:
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - name: Check out the independent implementation
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Fetch and blind the frozen fixture
        shell: bash
        run: |
          set -euo pipefail
          curl --fail --location --silent --show-error \
            "https://raw.githubusercontent.com/shibutatsu/pulse-ap2-x402-conformance/${PULSE_FIXTURE_COMMIT}/fixtures/v0.3/cases.json" \
            --output frozen-cases.json
          echo "${FIXTURE_SHA256}  frozen-cases.json" | sha256sum --check --strict
          jq 'del(.cases[].expected)' frozen-cases.json > evaluator-input.json

      - name: Run the independent implementation
        run: ./your-verifier --input evaluator-input.json --record reproduction.json

      - name: Check out the evidence validator after results exist
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: shibutatsu/pulse-ap2-x402-conformance
          ref: ${{ env.PULSE_VALIDATOR_COMMIT }}
          path: pulse-reference
          persist-credentials: false

      - name: Set up Node.js for the evidence validator
        uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
        with:
          node-version: "22"
          cache: npm
          cache-dependency-path: pulse-reference/package-lock.json

      - name: Validate fixture binding, coverage, decisions, and failure codes
        run: |
          npm --prefix pulse-reference ci
          npm --prefix pulse-reference run evidence:reproduction -- \
            "$GITHUB_WORKSPACE/frozen-cases.json" \
            "$GITHUB_WORKSPACE/reproduction.json"

      - name: Preserve the independently produced record
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: independent-reproduction-${{ github.sha }}
          path: reproduction.json
          if-no-files-found: error
          retention-days: 30
```

The fixed validator revision checks record shape, the frozen Pulse repository commit and raw fixture
hash, all 80 IDs, decisions, and ordered failure codes. Keeping it separate from the frozen fixture
commit prevents an older checker from accepting self-consistent but unapproved evidence metadata. It
cannot establish the publisher's identity, independence, implementation quality, or absence of
oracle use; those remain human evidence checks.
