# Contributing

Contributions should improve reproducibility or expose a concrete cross-layer mismatch.

1. Open an issue that names the exact AP2/x402 source version and field boundary.
2. Add a minimal failing fixture without private keys, customer identifiers, or live credentials.
3. Add a test that proves the failure is rejected before changing the verifier.
4. Run `npm run ci` and `npm run mutation`.
5. Do not describe this project as a normative AP2 or x402 implementation.

By contributing, you agree that your contribution is licensed under Apache-2.0.
