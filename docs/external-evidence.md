# How to record external evidence without overstating what it proves

The repository provides three checks for evidence required by issue
[#17](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/17). They validate a record
and its fixture-bound fields. They do not establish who performed the work, make an implementation
independent, turn a review into an audit, or satisfy the other release gates.

The current reproduction and security-review targets are fixed to Pulse commit
`e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`. The reproduction check requires an accepted
version-specific repository commit, path, and raw SHA-256 tuple. It retains the v0.2 tuple expressly
grandfathered in issue #16 for work already underway. Supplying a modified bundle and repeating its
new hash in the record, or mixing values from accepted tuples, does not create qualifying evidence.

## Record an independent reproduction

A qualifying implementer must evaluate all 80 cases without importing this repository's verifier
or compiled output. The language-neutral start-to-finish procedure is in
[`independent-implementation-guide.md`](independent-implementation-guide.md). The published record
has this shape:

```json
{
  "recordVersion": "pulse-independent-reproduction/0.1",
  "performedAt": "2026-08-28T10:00:00Z",
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
    "repositoryCommit": "e06a6cbfe3ddb965c8fc70f50838f5014ec2038e",
    "path": "fixtures/v0.3/cases.json",
    "sha256": "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0",
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
npm run evidence:reproduction -- fixtures/v0.3/cases.json path/to/reproduction.json
```

The command checks the frozen Pulse commit, raw fixture SHA-256, case coverage, decisions, and
failure codes. A successful result is still subject to human confirmation that the implementation
and publisher are genuinely independent. Two qualifying outside implementations are required by
issue #17.

The fixture path must match the bundle version. New reproduction work should use v0.3; v0.1 and v0.2 are
retained only so already-published records can still be checked against their original bytes.

## Record an independent security review

Use [`security-review-record.example.json`](evidence/security-review-record.example.json) as the
field reference. The stable public report should cover the scope in issue
[#18](https://github.com/shibutatsu/pulse-ap2-x402-conformance/issues/18). The frozen scope, threat
model, review commands, and required deliverables are collected in
[`security-review-packet.md`](security-review-packet.md).

```bash
npm run evidence:review -- path/to/security-review.json
```

The command rejects records for a commit other than the frozen review target and keeps its automated
check false while a critical or high finding is open or accepted as risk. It cannot authenticate the
reviewer, confirm independence, or determine whether the review method was sufficient. Those checks
remain human release decisions.

## Verify one fixture against a public EVM receipt

The 80-case corpus intentionally keeps synthetic transaction IDs. A public settlement case is a
separate, standalone case that retains the AP2 and x402 checks while binding them to a successful
public transaction. Do not replace a case inside `fixtures/v0.3/cases.json`; doing so would change
the corpus reproduced by outside implementers.

### Prepare the authorization without sending a transaction

Choose an explicit evaluation time and keep it unchanged through preparation and finalization. The
default authorization window is seven days. Generate the signed AP2 chain with the zero transaction
hash, then compose the standalone case and transaction-ready EIP-3009 arguments:

```bash
sh scripts/ap2/run-pinned.sh --public-evidence \
  --now-epoch-seconds <evaluation-time> \
  --output-directory build/public-evm

npm run public-evm:compose -- \
  --artifact build/public-evm/ap2-signed-artifact.json \
  --normalized build/public-evm/ap2-normalized-record.json \
  --output build/public-evm/prepared-case.json \
  --authorization-output build/public-evm/prepared-authorization.json
```

The preparation uses Circle's Base Sepolia USDC contract and a publicly derived fixture payer. It
does not contact an RPC, fund the payer, or submit a transaction. The zero transaction hash and
`state: prepared` are explicit non-evidence markers. Never publish the prepared case as a completed
settlement.

Funding the fixture payer with testnet USDC and broadcasting the prepared contract call are external
state changes. A person must perform and approve those steps. Do not use the public fixture key for
mainnet assets, customer funds, or any token with value.

### Record the transaction hash without changing the authorization

After the prepared EIP-3009 call succeeds, rerun the pinned generator with the same evaluation time,
timeout, and actual transaction hash. The receipt issue time may be the transaction block timestamp
or a later observation time. It is recorded separately as the AP2 verification time, so the earlier
evaluation time and the resulting EIP-3009 authorization remain unchanged:

```bash
sh scripts/ap2/run-pinned.sh --public-evidence \
  --now-epoch-seconds <same-evaluation-time> \
  --receipt-issued-at <receipt-time> \
  --network-confirmation-id <0x-transaction-hash> \
  --output-directory build/public-evm-recorded

npm run public-evm:compose -- \
  --artifact build/public-evm-recorded/ap2-signed-artifact.json \
  --normalized build/public-evm-recorded/ap2-normalized-record.json \
  --output build/public-evm-recorded/public-case.json \
  --authorization-output build/public-evm-recorded/recorded-authorization.json \
  --prepared-authorization build/public-evm/prepared-authorization.json
```

The composer hashes the network, asset, function arguments, nonce, and signature. Finalization fails
if that hash differs from the prepared authorization. Only the expected transaction hash, AP2
receipt, case input hash, and state may change.

### Match the standalone case to the public receipt

The `evm` command accepts either the versioned 80-case bundle or a standalone public settlement
case. Run the read-only receipt check against the recorded case:

```bash
PULSE_EVM_RPC_URL="<read-only endpoint>" \
  npm run evidence:evm -- build/public-evm-recorded/public-case.json \
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

The repository includes one completed Base Sepolia example in
[`fixtures/public-evm`](../fixtures/public-evm/README.md). Its receipt verification result is
[`evidence/public-evm-base-sepolia.json`](../evidence/public-evm-base-sepolia.json).

Validate a saved receipt result against its standalone case without making an RPC request:

```bash
npm run evidence:evm-record -- \
  fixtures/public-evm/case.json \
  evidence/public-evm-base-sepolia.json
```

This offline check verifies the case first, then binds the saved case ID, input hash, network,
transaction, asset, transfer, and authorization event back to that case. It detects drift between
the two committed JSON files. It does not reread the receipt or refresh its confirmation count.

## Release decision

Passing any command above means only that the record passed its automated checks. Keep package
version `0.0.0`, `private: true`, and do not create a `v0.1.0` release while any item in issue #17 is
still open. Evidence URLs and the human independence review should be recorded in that issue.
