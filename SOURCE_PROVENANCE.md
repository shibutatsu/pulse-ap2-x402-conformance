# The public implementation is clean-room code informed by pinned protocol sources

No private-repository Git history, customer fixture, private key, HTTP client, broadcaster, routing
implementation, commercial ledger, or private receipt code was copied into this repository.

The field names and EIP-712 shape are interoperability facts from the pinned AP2 and x402 sources
listed in `docs/source-pins.md`. The implementation in `src/` was written specifically for this
repository. Upstream source code is not vendored. Runtime dependencies retain their own licenses in
the npm distribution and lockfile.
