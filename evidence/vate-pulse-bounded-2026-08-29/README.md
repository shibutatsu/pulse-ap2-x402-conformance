# Bounded VATE-to-Pulse external SUT evidence

This is the superseded worksheet 0.4 provenance record retained for auditability. Use the
[worksheet 0.5 correction](../vate-pulse-bounded-2026-08-30/README.md) for the current bounded
result. The mapper semantics and observed Pulse/VATE outcome were unchanged.

This directory records the solicited three-case VATE-to-Pulse attempt delivered
from the immutable starter kit. It is a candidate-executed external SUT record,
not organic adoption, a security review, an audit, endorsement, certification,
production approval, general compatibility, or completion of Pulse issue #18.

## Fixed inputs

- Starter kit: [`3f822d88d843fca17710028a19d7445a28fb9635`](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/tree/3f822d88d843fca17710028a19d7445a28fb9635/examples/external-sut-pulse-starter)
- VATE source: `5a37f87de0190da44e619b1800261637e83dd7ed`
- Frozen Pulse verifier: `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`
- Candidate mapper and worksheet: [`ce125dbada38d45dcde34eeb02197fc5be0e1ad9`](https://github.com/shibutatsu/pulse-ap2-x402-conformance/commit/ce125dbada38d45dcde34eeb02197fc5be0e1ad9)
- Candidate runtime: Python 3.14.4, standard library only

The candidate commit has only `mapper.py` and `mapping-worksheet.json`. The
starter validator executes a fresh regular-file export of that commit for every
map, projection, and randomized sensitivity invocation. No external package,
network call, frozen Pulse helper, VATE expected result, or comparison receipt
is available to the mapper.

## Result

- VATE fixture reference run: 75 passed, 0 failed
- Selected external SUT cases: 2 matches, 1 explicit mismatch
- Full comparison: 2 passed, 73 failed, 72 skipped, exit code 1
- Bundle integrity: 27 passed, 0 failed, exit code 0

The amount-overrun case intentionally remains a mismatch: VATE expects
`attenuate`, while frozen Pulse reports `AP2_X402_AMOUNT_MISMATCH` and has no
native attenuate outcome. The record does not normalize that difference into a
pass. The other 72 VATE cases are explicit `skipped` / `out-of-scope` entries.

## Evidence map

- `pulse-sut-result.json`: closed 75-result record and exact commit/runtime bindings
- `mapping-source/mapper.py`: byte-identical copy of the candidate mapper
- `mapping-worksheet.json`: completed 142-leaf / 42-container mapping contract
- `candidate-execution/`: eligible-input-only map and projection requests plus raw stdout
- `pulse-inputs/`: three generated Pulse inputs
- `raw-pulse-output.json`: unchanged reports from frozen `verifyConformanceCase`
- `generated-records.json`: all 142 primitive values and five generator records per case
- `vate-compare-report.json`: semantic comparison, including the preserved mismatch
- `vate-implementation-report.json`: failing implementation status caused by the bounded scope
- `vate-bundle-verification.json`: independent 27-check digest-chain result

The starter validator also reran all three cases, twelve randomized source
sensitivity probes, and its fail-closed checks before accepting this bundle.
