# Independent payment and EVM security review packet

This packet fixes the review requested by issue
[#18](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18) to repository commit
`e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`. A qualifying reviewer must be independent of Prime
Beat and publish enough method and findings detail for another person to understand the work. Free
community review is acceptable; automated scanners alone are not a security review.

## Scope and threats

Review the offline decision boundary and its evidence tooling for:

- fail-closed raw JSON schemas, unsafe object keys, unknown fields, source pins, fixture provenance,
  JCS/SHA-256 integrity, and archived/current version separation;
- AP2 SD-JWT signatures and disclosures, key binding, supplied trust anchors, time/audience/nonce and
  checkout context, normalized claims, constraints, Merchant identity, and Payment Receipt binding;
- AP2-to-x402 agreement for scheme, network, asset, amount, payer/payee, recipient, timeout, commerce
  fields, resource, accepted requirements, and unsupported extensions;
- EIP-712 domain/message construction, EIP-3009 nonce and time bounds, signature malleability and payer
  recovery, plus settlement and receipt agreement;
- evidence-record validation and the read-only public EVM receipt path, including chain ID,
  confirmation count, transaction status, `Transfer`, and `AuthorizationUsed` matching; and
- locked dependencies, CI/mutation coverage, local-only operation, secret exclusion, and error paths.

Assume an attacker controls every JSON field and can submit malformed encodings, extra or dangerous
keys, inconsistent cross-layer values, substituted keys/signatures, replayable or expired
authorizations, misleading settlement data, mixed fixture versions, and forged evidence metadata.
Protect the accept/reject decision, failure record, trust context, AP2 mandate/reference bindings,
authorized EVM value/recipient/payer, and evidence provenance. Treat supplied public JWKs, explicit
verification context, pinned upstream sources, locked dependencies, and the local runtime as stated
trust inputs rather than facts authenticated by this repository.

## Files to review

- Core boundary: `src/types.ts`, `src/failures.ts`, `src/canonical.ts`, `src/ap2-crypto.ts`,
  `src/verifier.ts`, and `src/index.ts`.
- x402 and fixtures: `src/x402-producer.ts`, `scripts/generate-fixtures.ts`, and
  `scripts/compose-public-evm-case.ts`.
- Evidence and commands: `src/evidence.ts`, `src/evidence-cli.ts`, `src/cli.ts`,
  `fixtures/public-evm/case.json`, and `evidence/public-evm-base-sepolia.json`.
- Pinned AP2 pipeline: `scripts/ap2/run-pinned.sh`, `scripts/ap2/artifact_common.py`,
  `scripts/ap2/generate_signed_artifacts.py`, `scripts/ap2/generate_public_evm_artifacts.py`,
  `scripts/ap2/verify_extract_artifacts.py`, and `scripts/ap2/requirements.lock.txt`.
- Assurance surface: `test/*.test.ts`, `package.json`, `package-lock.json`, TypeScript/Vitest/Stryker
  configuration, `.github/workflows/*.yml`, and the profile documents under `docs/`.

## Start from the frozen commit

```bash
git clone https://github.com/shibutatsu/pulse-ap2-x402-conformance.git
cd pulse-ap2-x402-conformance
git checkout --detach e06a6cbfe3ddb965c8fc70f50838f5014ec2038e
test "$(shasum -a 256 fixtures/v0.3/cases.json | awk '{print $1}')" = \
  "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"
npm ci
npm run ci
npm run mutation
```

Also inspect negative tests manually. If reproducing the pinned AP2 artifacts, follow
`scripts/ap2/README.md` and run `sh scripts/ap2/run-pinned.sh` with its pinned Python/uv toolchain.
Record every command, tool version, failure, and limitation; a green command is supporting evidence,
not a substitute for manual review.

## Required deliverables

Publish a stable HTTPS report containing:

1. reviewer name, organization, public profile, independence statement, reviewed commit, date, and
   environment;
2. exact scope, exclusions, manual methods, automated tools, tests run, and threat assumptions;
3. findings with stable IDs, `critical`/`high`/`medium`/`low`/`informational` severity, affected code,
   exploit conditions, impact, recommendation, and `open`/`resolved`/`accepted-risk` status;
4. remediation verification, unresolved items, residual risk, and a concise conclusion bounded to the
   reviewed commit; and
5. a machine-readable `pulse-independent-security-review/0.1` record matching
   [`security-review-record.example.json`](evidence/security-review-record.example.json).

Report exploitable details through the repository's
[private vulnerability reporting form](https://github.com/shibutatsu/pulse-ap2-x402-conformance/security/advisories/new)
before public disclosure, then publish a safe summary. Do not request or use production secrets,
customer data, funded wallets, transaction submission, or write-enabled RPC credentials.

Validate the published record from the frozen checkout:

```bash
npm run evidence:review -- /absolute/path/to/security-review.json
```

The command checks the strict record schema and exits unsuccessfully while a critical or high finding
is not `resolved`. It does not authenticate the reviewer, prove independence, judge review depth, or
turn the report into a formal audit. Those are human release decisions.

## Not established by this review

Unless separately commissioned and evidenced, this scope does not establish production issuer or
merchant identity, wallet/key custody, facilitator or token solvency, live-chain finality, balances,
nonce consumption beyond the checked receipt, ERC-1271/ERC-6492 smart-account validity, bridge or
contract security outside the submitted records, legal authorization, regulatory compliance, privacy
compliance, operational incident response, or fitness for handling real funds.
