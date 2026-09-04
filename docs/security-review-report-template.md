# Independent security review report template

This optional template mirrors the fixed review packet for issue
[#18](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18). It does not change the
review target, scope, or qualification rules. A reviewer may use another report format if it
publishes the same information.

Do not publish exploitable details before coordinating through the repository's
[private vulnerability reporting form](https://github.com/shibutatsu/pulse-ap2-x402-conformance/security/advisories/new).
Delete the prompts below and replace every bracketed value before publishing.

## Reviewer and record identity

- Reviewer: `[name or stable pseudonym]`
- Organization: `[organization or independent]`
- Public profile: `[stable HTTPS URL]`
- Independent of Prime Beat: `[true, with any relevant relationship disclosed]`
- Review date: `[ISO 8601 date]`
- Environment: `[OS, architecture, Node/npm/Python/uv versions, and material tool versions]`
- Stable public report URL: `[HTTPS URL]`
- Stable machine-readable record URL: `[HTTPS URL]`

## Frozen target

- Pulse commit: `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`
- Fixture: `fixtures/v0.3/cases.json`
- Fixture SHA-256: `8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0`
- Evidence validator commit: `fe24b304735c8ab1f38118a89d0a204bc7d00fe8`
- Fixed packet: [`security-review-packet.md` at `9940fdb`](https://github.com/shibutatsu/pulse-ap2-x402-conformance/blob/9940fdb08bc326d949c0c7148c5e01c656454b99/docs/security-review-packet.md)

Record the commands used to verify the checkout and fixture hash. Review the frozen target in a
separate checkout from the evidence validator.

## Methods and commands

Describe the manual review method, adversarial cases, automated tools, and tests used. Include each
command and its result. A green test run supports the review but does not replace source inspection.

```text
[exact commands and results]
```

## Full-scope coverage

Mark every row `reviewed` and link the relevant notes, commands, tests, or findings. If an in-scope
row is excluded, explain the exclusion and do not claim completion of the full issue #18 gate.

| Required area | Status | Evidence or notes |
| --- | --- | --- |
| Raw JSON schemas, unsafe keys, unknown fields, source pins, fixture provenance, JCS/SHA-256 integrity, and version separation | `[reviewed/excluded]` | `[links or notes]` |
| Full 80-case corpus, negative tests, failure ordering, and fail-closed prerequisites | `[reviewed/excluded]` | `[links or notes]` |
| AP2 SD-JWT chain, key binding, disclosures, trust inputs, time/audience/nonce, Checkout reference, Payment Receipt, and normalized claims | `[reviewed/excluded]` | `[links or notes]` |
| Signed constraints and AP2-to-x402 agreement for identity, amount, reference, scheme, network, asset, payer, recipient, timeout, and commerce fields | `[reviewed/excluded]` | `[links or notes]` |
| x402 producer, accepted payload, settlement fields, unsupported extensions, and receipt/settlement linkage | `[reviewed/excluded]` | `[links or notes]` |
| EIP-712/EIP-3009 domain and message construction, nonce/time bounds, low-s form, recovery byte, and payer recovery | `[reviewed/excluded]` | `[links or notes]` |
| Evidence validators, evidence generator, read-only public-EVM receipt path, confirmation policy, `Transfer`, and `AuthorizationUsed` checks | `[reviewed/excluded]` | `[links or notes]` |
| Pinned AP2 artifact regeneration and verification pipeline | `[reviewed/excluded]` | `[links or notes]` |
| Locked dependencies, CI, mutation evidence, local-only/no-secret behavior, and error paths | `[reviewed/excluded]` | `[links or notes]` |

## Threat assumptions and exclusions

State how the review treated attacker-controlled JSON, malformed encodings, extra or dangerous
keys, inconsistent cross-layer values, substituted keys or signatures, replay and expiry,
misleading settlement data, mixed fixture versions, and forged evidence metadata.

List every exclusion. Keep the packet's production, custody, live-chain, smart-account, legal,
regulatory, privacy, and operational boundaries explicit.

## Findings

Use stable IDs and one section per finding. An empty finding list is allowed, but the report must
still show the full methods and coverage above.

### `[PULSE-SEC-01]` — `[critical/high/medium/low/informational]` — `[title]`

- Status: `[open/resolved/accepted-risk]`
- Affected code: `[commit-pinned links]`
- Exploit conditions: `[safe public description]`
- Impact: `[bounded impact]`
- Recommendation: `[specific remediation]`
- Remediation: `[commit/PR or reason none]`
- Verification: `[commands, tests, and commit-pinned evidence]`

## Remediation and unresolved items

List the disposition of every finding, the remediation revision reviewed, commands rerun, and any
remaining issue. A critical or high finding must be `resolved` for the fixed validator's automated
check to pass.

## Residual risk and conclusion

State what remains unproved after this review and give a conclusion bounded to the frozen commit.
Do not turn this review into an AP2/x402 endorsement, a production audit, live-settlement proof, or
fitness statement.

## Machine-readable record and validator result

Publish a `pulse-independent-security-review/0.1` JSON record using
[`security-review-record.example.json`](evidence/security-review-record.example.json). From a
checkout fixed at the evidence validator commit, run:

```bash
npm run evidence:review -- /absolute/path/to/security-review.json
```

Record the exit status and complete JSON output here. The validator checks the schema, frozen commit,
and unresolved critical/high findings. It does not authenticate the reviewer, prove independence,
or judge review depth.

