# Corrected bounded VATE-to-Pulse external SUT evidence

This directory records the regenerated solicited three-case VATE-to-Pulse
attempt under worksheet 0.5. It corrects the direct-origin provenance records
identified during the VATE maintainer intake of the earlier PR #53 bundle. The
mapper semantics and frozen Pulse verifier are unchanged.

This remains a candidate-executed bounded external SUT record. It is not
organic adoption, a security review, an audit, endorsement, certification,
production approval, general compatibility, or completion of Pulse issue #18.

## Fixed inputs

- Starter kit: [`04e2cfaaca1843b67d88d558ccbf4e69d4f14179`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/04e2cfaaca1843b67d88d558ccbf4e69d4f14179/examples/external-sut-pulse-starter)
- VATE source: `5a37f87de0190da44e619b1800261637e83dd7ed`
- Frozen Pulse verifier: `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`
- Candidate mapper and worksheet: [`1ee413652f11e720a0da7ffb318e91d87a447d4c`](https://github.com/shibutatsu/pulse-ap2-x402-conformance/commit/1ee413652f11e720a0da7ffb318e91d87a447d4c)
- Candidate runtime: Python 3.14.4, standard library only

The candidate commit changes only the completed worksheet from the earlier
candidate pin. `mapper.py` is byte-identical, with raw SHA-256
`85c87df9a5e4d33c6d68078212a7f94f3271c22b8a69d5c20f526b3879073efb`.

## Provenance correction

Worksheet 0.5 records direct value origin. The regenerated worksheet and all
three generated-record sets now bind:

- `/ap2/closedMandate/execution_date` to VATE admission request `/issued_at`;
- the closed-payee name and website to VATE AP2 mandate `/merchant`; and
- the allowed-payee name and website to the same VATE AP2 mandate `/merchant`.

Each of the five leaves is `vate-derived`. Names are exact copies; websites use
the recorded deterministic `https://` prefix transform. The relevant
`mapping_row:evaluation-time`, `mapping_row:merchant-payee-id`, and
`mapping_row:merchant-allowed-id` dependencies are retained. All worksheet,
generated-record, execution, raw-report, projection, comparison, and bundle
hashes were regenerated together.

## Result

- Official starter run-bundle validator: passed, including 3 cases x 4
  randomized sensitivity probes
- VATE fixture reference run: 75 passed, 0 failed
- Selected external SUT cases: 2 matches, 1 explicit mismatch
- Full comparison: 2 passed, 73 failed, 72 skipped, exit code 1
- Bundle integrity: 27 passed, 0 failed, exit code 0

The amount-overrun case remains the required mismatch: VATE expects
`attenuate`, while frozen Pulse reports `AP2_X402_AMOUNT_MISMATCH` and has no
native attenuate outcome. The record does not normalize that difference into a
pass. The other 72 VATE cases are explicit `skipped` / `out-of-scope` entries.

Frozen Pulse CI was run separately at its fixed commit: 131 tests passed, the
80-case Pulse fixture set verified 80/80, saved public-EVM evidence was valid,
the production dependency audit found no vulnerability, and the pack check
passed. That local Pulse result is not external SUT coverage and does not
expand this three-case record.

The earlier PR #53 evidence should remain available only as the superseded
provenance record. This directory is the candidate-owned correction intended
for a fresh VATE maintainer intake.
