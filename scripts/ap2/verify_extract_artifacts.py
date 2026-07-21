"""Re-verify AP2 fixture signatures and emit deterministic normalized records."""

from __future__ import annotations

import argparse
import json

from pathlib import Path
from typing import Any

from ap2.sdk.generated.payment_receipt import PaymentReceipt
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.receipt_wrapper import ReceiptClient
from jwcrypto.jwk import JWK

from artifact_common import (
    AP2_COMMIT,
    FIXED_NOW,
    FIXTURE_COUNT,
    GENERATED_AT,
    OPEN_ISSUER_KEY_LABEL,
    RECEIPT_ISSUER_KEY_LABEL,
    TERMINAL_HOLDER_KEY_LABEL,
    ClosedPaymentMandateWithX402,
    OpenPaymentMandateWithX402,
    ap2_source_metadata,
    b64url_decode,
    canonical_json,
    canonical_sha256_b64url,
    fixture_jwk,
    public_jwk,
    sha256_b64url,
    sha256_hex,
    write_json,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT / "fixtures/v0.1/ap2-signed-artifacts.json"
DEFAULT_OUTPUT = ROOT / "fixtures/v0.1/ap2-normalized-records.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def fixture_public_keys(artifact: dict[str, Any]) -> tuple[JWK, JWK, JWK]:
    expected = {
        "openMandateIssuer": public_jwk(
            fixture_jwk(OPEN_ISSUER_KEY_LABEL, "ap2-fixture-open-issuer-v1")
        ),
        "terminalHolder": public_jwk(
            fixture_jwk(
                TERMINAL_HOLDER_KEY_LABEL, "ap2-fixture-terminal-holder-v1"
            )
        ),
        "paymentReceiptIssuer": public_jwk(
            fixture_jwk(
                RECEIPT_ISSUER_KEY_LABEL, "ap2-fixture-receipt-issuer-v1"
            )
        ),
    }
    actual = artifact.get("publicKeys")
    require(
        isinstance(actual, dict) and canonical_json(actual) == canonical_json(expected),
        "Artifact public keys do not match the fixed fixture key derivations",
    )
    return (
        JWK.from_json(json.dumps(expected["openMandateIssuer"])),
        JWK.from_json(json.dumps(expected["terminalHolder"])),
        JWK.from_json(json.dumps(expected["paymentReceiptIssuer"])),
    )


def verify_x402_extension_retained(
    open_mandate: dict[str, Any], closed_mandate: dict[str, Any]
) -> None:
    closed_instrument = closed_mandate.get("payment_instrument")
    require(isinstance(closed_instrument, dict), "Closed payment instrument missing")
    closed_x402 = closed_instrument.get("x402")
    require(isinstance(closed_x402, dict), "Closed x402 extension was dropped")
    require(
        closed_x402.get("nonceBinding")
        == "base64url-decode-ap2-mandate-reference",
        "Closed x402 nonce binding method mismatch",
    )
    constraints = open_mandate.get("constraints")
    require(isinstance(constraints, list), "Open mandate constraints missing")
    allowed: list[dict[str, Any]] = []
    for constraint in constraints:
        if (
            isinstance(constraint, dict)
            and constraint.get("type") == "payment.allowed_payment_instruments"
            and isinstance(constraint.get("allowed"), list)
        ):
            allowed.extend(
                item for item in constraint["allowed"] if isinstance(item, dict)
            )
    require(allowed, "Signed allowed payment instruments constraint missing")
    require(
        any(canonical_json(item) == canonical_json(closed_instrument) for item in allowed),
        "Signed allowed instrument does not retain the exact closed x402 extension",
    )


def verify_case(
    case: dict[str, Any],
    *,
    open_public: JWK,
    terminal_public: JWK,
    receipt_public: JWK,
) -> dict[str, Any]:
    case_id = case.get("id")
    require(isinstance(case_id, str) and case_id, "Case id missing")
    require(case.get("nowEpochSeconds") == FIXED_NOW, f"{case_id}: logical time mismatch")
    artifacts = case.get("artifacts")
    expected = case.get("expected")
    require(isinstance(artifacts, dict), f"{case_id}: artifacts missing")
    require(isinstance(expected, dict), f"{case_id}: expected values missing")

    open_token = artifacts.get("openPaymentMandateSdJwt")
    closed_chain = artifacts.get("closedPaymentMandateChain")
    receipt_jwt = artifacts.get("paymentReceiptJwt")
    require(isinstance(open_token, str), f"{case_id}: open token missing")
    require(isinstance(closed_chain, str), f"{case_id}: closed chain missing")
    require(isinstance(receipt_jwt, str), f"{case_id}: receipt JWT missing")

    client = MandateClient()
    separately_verified_open = client.verify(
        token=open_token,
        key_or_provider=open_public,
        payload_type=OpenPaymentMandateWithX402,
        clock_skew_seconds=0,
        current_time=FIXED_NOW,
    )
    require(
        isinstance(separately_verified_open.mandate_payload, OpenPaymentMandateWithX402),
        f"{case_id}: typed Open Payment Mandate verification failed",
    )

    verified_payloads = client.verify(
        token=closed_chain,
        key_or_provider=lambda _token: open_public,
        expected_aud=case.get("expectedAudience"),
        expected_nonce=case.get("expectedNonce"),
        clock_skew_seconds=0,
        current_time=FIXED_NOW,
    )
    require(
        isinstance(verified_payloads, list) and len(verified_payloads) == 2,
        f"{case_id}: expected a two-hop verified mandate chain",
    )
    open_model = OpenPaymentMandateWithX402.model_validate(verified_payloads[0])
    closed_model = ClosedPaymentMandateWithX402.model_validate(verified_payloads[1])
    open_claims = open_model.model_dump(mode="json", exclude_none=True)
    closed_claims = closed_model.model_dump(mode="json", exclude_none=True)

    cnf = open_claims.get("cnf")
    require(isinstance(cnf, dict), f"{case_id}: Open mandate cnf missing")
    cnf_jwk = cnf.get("jwk")
    require(
        isinstance(cnf_jwk, dict)
        and canonical_json(cnf_jwk) == canonical_json(public_jwk(terminal_public)),
        f"{case_id}: terminal holder key does not match Open mandate cnf.jwk",
    )
    verify_x402_extension_retained(open_claims, closed_claims)

    typed_chain = PaymentMandateChain.parse(verified_payloads)
    open_checkout_reference = case.get("openCheckoutReference")
    require(
        isinstance(open_checkout_reference, str),
        f"{case_id}: Open Checkout reference missing",
    )
    violations = typed_chain.verify(
        expected_transaction_id=expected.get("transactionId"),
        expected_open_checkout_hash=open_checkout_reference,
    )
    require(not violations, f"{case_id}: AP2 constraint violations: {violations}")

    leaf_jwt = client.get_closed_mandate_jwt(closed_chain)
    require(
        leaf_jwt == artifacts.get("closedPaymentMandateLeafJwt"),
        f"{case_id}: stored leaf JWT mismatch",
    )
    closed_reference = sha256_b64url(leaf_jwt.encode("ascii"))
    require(
        closed_reference == artifacts.get("closedPaymentMandateReference"),
        f"{case_id}: closed mandate reference mismatch",
    )
    require(
        expected.get("eip3009Nonce") == "0x" + b64url_decode(closed_reference).hex(),
        f"{case_id}: base64url reference to EIP-3009 nonce mapping mismatch",
    )

    receipt_verification = ReceiptClient().verify_receipt(
        receipt_jwt=receipt_jwt,
        receipt_issuer_public_key=receipt_public,
        has_reference_in_store_cb=lambda value: value == closed_reference,
        is_payment_receipt=True,
    )
    require(
        receipt_verification == {"verified": True},
        f"{case_id}: AP2 receipt verification failed: {receipt_verification}",
    )
    receipt_payload = verify_jwt(receipt_jwt, receipt_public)
    receipt = PaymentReceipt.model_validate(receipt_payload).model_dump(mode="json")
    require(
        receipt.get("reference") == closed_reference,
        f"{case_id}: Payment Receipt reference mismatch",
    )
    require(
        receipt.get("network_confirmation_id") == expected.get("networkConfirmationId"),
        f"{case_id}: Payment Receipt network confirmation mismatch",
    )
    require(
        canonical_json(receipt) == canonical_json(expected.get("paymentReceipt")),
        f"{case_id}: Payment Receipt payload differs from generation expectation",
    )

    return {
        "id": case_id,
        "closedMandate": closed_claims,
        "openMandate": open_claims,
        "paymentReceipt": receipt,
        "verification": {
            "verifier": (
                "google-agentic-commerce/AP2@"
                f"{AP2_COMMIT}+scripts/ap2/verify_extract_artifacts.py/0.1"
            ),
            "closedMandateSignatureVerified": True,
            "openMandateSignatureVerified": True,
            "keyBindingVerified": True,
            "checkoutBindingVerified": True,
            "receiptSignatureVerified": True,
            "verifiedAtEpochSeconds": FIXED_NOW,
            "clockSkewSeconds": 0,
            "openCheckoutReference": open_checkout_reference,
            "closedMandateClaimsHash": canonical_sha256_b64url(closed_claims),
            "openMandateClaimsHash": canonical_sha256_b64url(open_claims),
            "closedMandateReference": closed_reference,
        },
    }


def verify_and_extract(input_path: Path, output_path: Path) -> None:
    source_metadata = ap2_source_metadata()
    artifact = load_json(input_path)
    require(
        artifact.get("artifactVersion") == "ap2-signed-artifacts/0.1",
        "Unsupported artifact version",
    )
    require(
        artifact.get("sourcePins", {}).get("ap2Commit") == AP2_COMMIT,
        "Artifact AP2 commit mismatch",
    )
    require(
        artifact.get("sourcePins", {}).get("mandatePySha256")
        == source_metadata["mandatePySha256"],
        "Artifact AP2 mandate.py source hash mismatch",
    )
    cases = artifact.get("cases")
    require(
        isinstance(cases, list) and len(cases) == FIXTURE_COUNT,
        f"Expected exactly {FIXTURE_COUNT} signed AP2 cases",
    )
    open_public, terminal_public, receipt_public = fixture_public_keys(artifact)
    records = [
        verify_case(
            case,
            open_public=open_public,
            terminal_public=terminal_public,
            receipt_public=receipt_public,
        )
        for case in cases
        if isinstance(case, dict)
    ]
    require(len(records) == FIXTURE_COUNT, "A non-object AP2 case was discarded")
    normalized = {
        "recordVersion": "ap2-normalized-verification-records/0.1",
        "generatedAt": GENERATED_AT,
        "sourcePins": artifact["sourcePins"],
        "sourceArtifactSha256": sha256_hex(input_path.read_bytes()),
        "records": records,
    }
    write_json(output_path, normalized)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    verify_and_extract(args.input.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
