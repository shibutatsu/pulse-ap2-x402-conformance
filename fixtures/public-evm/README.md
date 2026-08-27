# Public Base Sepolia settlement case

This directory contains one standalone AP2-to-x402 case tied to a successful public EVM receipt. It is separate from the versioned 80-case corpus so the corpus reproduced by outside implementers remains unchanged.

## Recorded settlement

- Network: Base Sepolia (`eip155:84532`)
- USDC contract: `0x036CbD53842c5426634e7929541eC2318f3dCF7e`
- Transaction: [`0xb6a16b58ea994c4db07582cbbc590ffdbec0befffd055b1405f6482d966f2cb1`](https://sepolia.basescan.org/tx/0xb6a16b58ea994c4db07582cbbc590ffdbec0befffd055b1405f6482d966f2cb1)
- Block: `45545081`
- Transfer: `1000` atomic units (`0.001 USDC`)
- Authorization hash: `jVLFesDqVtTfEm69TddjR-YI1D33SNLhnOk1RQygg-s`
- Evidence SHA-256: `7abaec474f7d7ccecc39049aa1519189cc977571b1b234bf95add55ebf03b977`

[`case.json`](case.json) is the standalone conformance input. [`authorization.json`](authorization.json) records the exact EIP-3009 arguments and signature used by the transaction. The read-only receipt verification result is stored in [`../../evidence/public-evm-base-sepolia.json`](../../evidence/public-evm-base-sepolia.json).

## Reproduce the generated case

The authorization was prepared at epoch `1786858400`. The AP2 receipt uses the transaction block timestamp, epoch `1786858450`.

```bash
sh scripts/ap2/run-pinned.sh --public-evidence \
  --now-epoch-seconds 1786858400 \
  --output-directory build/public-evm-prepared

npm run public-evm:compose -- \
  --artifact build/public-evm-prepared/ap2-signed-artifact.json \
  --normalized build/public-evm-prepared/ap2-normalized-record.json \
  --output build/public-evm-prepared/case.json \
  --authorization-output build/public-evm-prepared/authorization.json

sh scripts/ap2/run-pinned.sh --public-evidence \
  --now-epoch-seconds 1786858400 \
  --receipt-issued-at 1786858450 \
  --network-confirmation-id 0xb6a16b58ea994c4db07582cbbc590ffdbec0befffd055b1405f6482d966f2cb1 \
  --output-directory build/public-evm-recorded

npm run public-evm:compose -- \
  --artifact build/public-evm-recorded/ap2-signed-artifact.json \
  --normalized build/public-evm-recorded/ap2-normalized-record.json \
  --output build/public-evm-recorded/case.json \
  --authorization-output build/public-evm-recorded/authorization.json \
  --prepared-authorization build/public-evm-prepared/authorization.json
```

Verify the public receipt against a Base Sepolia RPC endpoint:

```bash
PULSE_EVM_RPC_URL="<read-only Base Sepolia endpoint>" \
  npm run evidence:evm -- fixtures/public-evm/case.json \
  --case public-base-sepolia-usdc-01 \
  --min-confirmations 12 \
  --output build/public-evm-evidence.json
```

Check the committed receipt record against the committed case without using an RPC endpoint:

```bash
npm run evidence:evm-record -- \
  fixtures/public-evm/case.json \
  evidence/public-evm-base-sepolia.json
```

The evidence establishes the transaction, successful receipt, matching token transfer, and matching EIP-3009 authorization event at the recorded observation time. It does not satisfy the separate external-implementation, independent-review, or sustained-CI gates in issue #17.
The test suite pins the complete evidence-file SHA-256 so block metadata, log indexes, confirmation count, and verification time cannot drift unnoticed. The offline check still does not re-query the chain or prove current finality.
