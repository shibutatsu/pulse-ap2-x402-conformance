# How to record external evidence without overstating what it proves

The repository provides three checks for evidence required by issue
[#17](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/17). They validate a record
and its fixture-bound fields. They do not establish who performed the work, make an implementation
independent, turn a review into an audit, or satisfy the other release gates.

## Record an independent reproduction

A qualifying implementer must evaluate all 80 cases without importing this repository's verifier
or compiled output. The published record has this shape:

```json
{
  "recordVersion": "pulse-independent-reproduction/0.1",
  "performedAt": "2026-08-13T10:00:00Z",
  "implementation": {
    "repositoryUrl": "https://github.com/example/independent-verifier",
    "commit": "1111111111111111111111111111111111111111",
    "language": "Rust",
    "runtime": "rustc 1.89.0",
    "command": "cargo test --release",
    "organization": "Example Independent Lab",
    "independentOfPrimeBeat": true
  },
  "fixture": {
    "repositoryCommit": "2222222222222222222222222222222222222222",
    "path": "fixtures/v0.1/cases.json",
    "sha256": "<lowercase SHA-256 of the exact fixture bytes>",
    "caseCount": 80
  },
  "environment": {
    "operatingSystem": "Linux",
    "architecture": "x86_64",
    "dependencies": ["serde_json 1.0"]
  },
  "results": [
    {
      "id": "valid-base-sepolia-01",
      "decision": "accept",
      "failureCodes": []
    }
  ],
  "notes": "Optional notes about disagreements or limitations.",
  "publishedUrl": "https://github.com/example/independent-verifier/releases/tag/v0.1"
}
```

`results` must contain each of the 80 fixture IDs exactly once. For rejected cases, record the
failure codes in fixture order. Validate the published record against the exact fixture checkout:

```bash
npm run evidence:reproduction -- fixtures/v0.1/cases.json path/to/reproduction.json
```

The command checks the raw fixture SHA-256, case coverage, decisions, and failure codes. A successful
result is still subject to human confirmation that the implementation and publisher are genuinely
independent. Two qualifying outside implementations are required by issue #17.

## Record an independent security review

Use [`security-review-record.example.json`](evidence/security-review-record.example.json) as the
field reference. The stable public report should cover the scope in issue
[#18](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18), including method,
findings, remediation state, and residual risk.

```bash
npm run evidence:review -- path/to/security-review.json
```

The command rejects incomplete records and keeps its automated check false while a critical or high
finding is open or accepted as risk. It cannot authenticate the reviewer, confirm independence, or
determine whether the review method was sufficient. Those checks remain human release decisions.

## Verify one fixture against a public EVM receipt

The offline fixtures contain synthetic transaction IDs. Replace the transaction ID of one otherwise
accepted case with a real public settlement transaction, update and re-sign all fields affected by
that change, and verify the updated case offline first. Then run the read-only receipt check:

```bash
PULSE_EVM_RPC_URL="<read-only endpoint>" \
  npm run evidence:evm -- path/to/live-case-bundle.json \
  --case <case-id> \
  --min-confirmations 12 \
  --output path/to/public-evm-evidence.json
```

The checker reads the network, transaction, receipt, and latest block. It requires the selected case
to pass the offline verifier, then matches all of these public facts:

- CAIP-2 chain ID;
- transaction and successful receipt;
- minimum confirmation count;
- token contract address;
- ERC-20 `Transfer` sender, recipient, and atomic value; and
- EIP-3009 `AuthorizationUsed` authorizer and AP2-derived nonce.

The output excludes the RPC URL and contains no key material. The command never signs or submits a
transaction. Do not commit an RPC credential, private key, customer record, or funded test identity.
The resulting JSON proves the listed receipt facts at its observation time; it is not perpetual
finality, token-issuer identity, legal authorization, or production-readiness evidence.

## Release decision

Passing any command above means only that the record passed its automated checks. Keep package
version `0.0.0`, `private: true`, and do not create a `v0.1.0` release while any item in issue #17 is
still open. Evidence URLs and the human independence review should be recorded in that issue.
