# Security policy

## Supported versions

No production version is supported yet. Security fixes are applied to `main` during the preview.

## Reporting

Use this repository's GitHub private vulnerability reporting form. Do not include working secrets
or customer data in a public issue.

## Security boundary

The verifier is a local, read-only JSON processor. It must not accept private keys, call RPC or HTTP
services, sign data, submit transactions, or load environment credentials. A change that adds any
of those capabilities requires a separate security review and is outside this repository's scope.
