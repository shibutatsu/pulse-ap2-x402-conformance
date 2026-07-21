"""Generate 20 deterministic, actually signed AP2 fixture chains."""

from __future__ import annotations

import argparse
import logging
import random

from pathlib import Path
from typing import Any

from ap2.sdk.generated.payment_receipt import PaymentReceipt
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt import kb_sd_jwt, parse_token
from sd_jwt.common import SDJWTCommon

from artifact_common import (
    AP2_COMMIT,
    EXPECTED_AUDIENCE,
    FIXED_NOW,
    FIXTURE_COUNT,
    GENERATED_AT,
    OPEN_ISSUER_KEY_LABEL,
    RECEIPT_ISSUER_KEY_LABEL,
    TERMINAL_HOLDER_KEY_LABEL,
    AllowedPayeesConstraint,
    AllowedPaymentInstrumentsConstraint,
    Amount,
    AmountRangeConstraint,
    ClosedPaymentMandateWithX402,
    Merchant,
    OpenPaymentMandateWithX402,
    PaymentReferenceConstraint,
    X402Eip712Domain,
    X402InstrumentExtension,
    X402PreservingPaymentInstrument,
    address_from_label,
    ap2_source_metadata,
    b64url_decode,
    fixture_jwk,
    public_jwk,
    resign_compact_jwt,
    resign_sd_jwt,
    sha256_b64url,
    sha256_hex,
    write_json,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "fixtures/v0.1/ap2-signed-artifacts.json"
FIXTURE_PAYER = "0xA3ACaC31a63387e041CB6aC7A5cE8a92554Ef4C7"
MAX_TIMEOUT_SECONDS = 300


def make_models(index: int, holder_public: dict[str, Any]) -> tuple[
    OpenPaymentMandateWithX402,
    ClosedPaymentMandateWithX402,
    dict[str, Any],
]:
    sequence = index + 1
    suffix = f"{sequence:02d}"
    network = "eip155:84532" if index < FIXTURE_COUNT // 2 else "eip155:31337"
    network_label = "base-sepolia" if network == "eip155:84532" else "local-31337"
    amount_minor = 1_000_000 + sequence * 101
    merchant = Merchant(
        id=f"merchant-{suffix}",
        name=f"Synthetic Merchant {suffix}",
        website=f"https://merchant-{suffix}.example",
    )
    amount = Amount(amount=amount_minor, currency="USD")
    open_checkout_reference = sha256_b64url(
        f"synthetic-open-checkout-mandate:v1:{sequence}"
    )
    instrument = X402PreservingPaymentInstrument(
        id=f"x402-eip3009-{network_label}-{suffix}",
        description="Synthetic x402 exact EIP-3009 fixture instrument",
        x402=X402InstrumentExtension(
            network=network,
            asset=address_from_label(f"fixture-asset:{network}:{sequence}"),
            amount=str(amount_minor),
            payTo=address_from_label(f"fixture-payee:{network}:{sequence}"),
            payer=FIXTURE_PAYER,
            ap2PayeeId=merchant.id,
            ap2PaymentAmount=amount.model_dump(),
            maxTimeoutSeconds=MAX_TIMEOUT_SECONDS,
            eip712Domain=X402Eip712Domain(name="Synthetic USD", version="2"),
        ),
    )
    open_mandate = OpenPaymentMandateWithX402(
        constraints=[
            PaymentReferenceConstraint(
                conditional_transaction_id=open_checkout_reference
            ),
            AllowedPaymentInstrumentsConstraint(allowed=[instrument]),
            AmountRangeConstraint(
                currency="USD",
                min=amount_minor,
                max=amount_minor,
            ),
            AllowedPayeesConstraint(allowed=[merchant]),
        ],
        cnf={"jwk": holder_public},
        iat=FIXED_NOW - 180,
        exp=FIXED_NOW + MAX_TIMEOUT_SECONDS,
    )
    closed_mandate = ClosedPaymentMandateWithX402(
        transaction_id=open_checkout_reference,
        payee=merchant,
        payment_amount=amount,
        payment_instrument=instrument,
        execution_date=GENERATED_AT,
        iat=FIXED_NOW - 120,
        exp=FIXED_NOW + MAX_TIMEOUT_SECONDS,
    )
    context = {
        "id": f"valid-{network_label}-{suffix}",
        "expectedAudience": EXPECTED_AUDIENCE,
        "expectedNonce": f"ap2-terminal-nonce-{suffix}",
        "networkConfirmationId": (
            "0x" + sha256_hex(f"synthetic-settlement-transaction:v1:{sequence}")
        ),
        "openCheckoutReference": open_checkout_reference,
        "transactionId": open_checkout_reference,
        "x402InstrumentId": instrument.id,
    }
    return open_mandate, closed_mandate, context


def create_receipt(
    *,
    reference: str,
    case_id: str,
    network_confirmation_id: str,
    receipt_key: Any,
) -> tuple[str, dict[str, Any]]:
    receipt = PaymentReceipt(
        status="Success",
        iss="synthetic-facilitator.example",
        iat=FIXED_NOW,
        reference=reference,
        payment_id=f"payment-{case_id}",
        psp_confirmation_id=f"psp-{case_id}",
        network_confirmation_id=network_confirmation_id,
    )
    receipt_payload = receipt.model_dump(mode="json")
    randomized_jwt = create_jwt(
        {"alg": "ES256", "kid": "ap2-fixture-receipt-issuer-v1", "typ": "JWT"},
        receipt_payload,
        receipt_key,
    )
    return resign_compact_jwt(randomized_jwt, receipt_key), receipt_payload


def generate(output: Path) -> None:
    source_metadata = ap2_source_metadata()
    open_issuer_key = fixture_jwk(
        OPEN_ISSUER_KEY_LABEL, "ap2-fixture-open-issuer-v1"
    )
    terminal_holder_key = fixture_jwk(
        TERMINAL_HOLDER_KEY_LABEL, "ap2-fixture-terminal-holder-v1"
    )
    receipt_issuer_key = fixture_jwk(
        RECEIPT_ISSUER_KEY_LABEL, "ap2-fixture-receipt-issuer-v1"
    )
    holder_public = public_jwk(terminal_holder_key)

    # py-sd-jwt exposes deterministic salts for examples through this explicit
    # unsafe switch. The published keys and seed make this unsuitable for any
    # production credential; it is enabled only in this fixture process.
    SDJWTCommon.unsafe_randomness = True
    logging.getLogger("sd_jwt").setLevel(logging.ERROR)
    random.seed(0xA2_402_01)
    original_time = kb_sd_jwt.time.time
    kb_sd_jwt.time.time = lambda: FIXED_NOW - 120

    client = MandateClient()
    cases: list[dict[str, Any]] = []
    try:
        for index in range(FIXTURE_COUNT):
            open_model, closed_model, context = make_models(index, holder_public)
            randomized_open = client.create(
                payloads=[open_model], issuer_key=open_issuer_key
            )
            open_token = resign_sd_jwt(randomized_open, open_issuer_key)

            randomized_chain = client.present(
                holder_key=terminal_holder_key,
                mandate_token=open_token,
                payloads=[closed_model],
                aud=context["expectedAudience"],
                nonce=context["expectedNonce"],
            )
            root_segment, leaf_segment = randomized_chain.rsplit("~~", 1)
            closed_leaf_segment = resign_sd_jwt(
                leaf_segment, terminal_holder_key
            )
            closed_chain = f"{root_segment}~~{closed_leaf_segment}"
            closed_leaf_jwt = client.get_closed_mandate_jwt(closed_chain)
            closed_reference = sha256_b64url(closed_leaf_jwt.encode("ascii"))
            # The reference is base64url(SHA-256(leaf JWT)); decoding it is the
            # exact 32-byte x402 EIP-3009 nonce used by the TypeScript profile.
            eip3009_nonce = "0x" + b64url_decode(closed_reference).hex()

            receipt_jwt, receipt_payload = create_receipt(
                reference=closed_reference,
                case_id=context["id"],
                network_confirmation_id=context["networkConfirmationId"],
                receipt_key=receipt_issuer_key,
            )
            open_parsed = parse_token(open_token)
            closed_parsed = parse_token(closed_leaf_segment)
            if not open_parsed.disclosures or not closed_parsed.disclosures:
                raise RuntimeError("Expected disclosures in both AP2 SD-JWT hops")
            if closed_parsed.typ != "kb+sd-jwt":
                raise RuntimeError(
                    f"Expected terminal typ kb+sd-jwt, got {closed_parsed.typ}"
                )

            cases.append(
                {
                    "id": context["id"],
                    "nowEpochSeconds": FIXED_NOW,
                    "expectedAudience": context["expectedAudience"],
                    "expectedNonce": context["expectedNonce"],
                    "openCheckoutReference": context["openCheckoutReference"],
                    "artifacts": {
                        "openPaymentMandateSdJwt": open_token,
                        "closedPaymentMandateChain": closed_chain,
                        "closedPaymentMandateLeafJwt": closed_leaf_jwt,
                        "closedPaymentMandateReference": closed_reference,
                        "paymentReceiptJwt": receipt_jwt,
                    },
                    "expected": {
                        "eip3009Nonce": eip3009_nonce,
                        "networkConfirmationId": context["networkConfirmationId"],
                        "paymentReceipt": receipt_payload,
                        "transactionId": context["transactionId"],
                        "x402InstrumentId": context["x402InstrumentId"],
                    },
                }
            )
    finally:
        kb_sd_jwt.time.time = original_time

    artifact = {
        "artifactVersion": "ap2-signed-artifacts/0.1",
        "generatedAt": GENERATED_AT,
        "sourcePins": {
            **source_metadata,
            "ap2PackageVersion": "0.1",
        },
        "determinism": {
            "scope": "Byte-for-byte reproducible committed fixture artifacts",
            "disclosureSalts": "py-sd-jwt unsafe example randomness with fixed seed",
            "es256Signatures": "RFC 6979 HMAC-SHA256 with low-S normalization",
            "warning": "All fixture private keys are publicly derivable and unsafe for production",
            "keyDerivationLabels": {
                "openMandateIssuer": OPEN_ISSUER_KEY_LABEL,
                "terminalHolder": TERMINAL_HOLDER_KEY_LABEL,
                "paymentReceiptIssuer": RECEIPT_ISSUER_KEY_LABEL,
            },
        },
        "publicKeys": {
            "openMandateIssuer": public_jwk(open_issuer_key),
            "terminalHolder": holder_public,
            "paymentReceiptIssuer": public_jwk(receipt_issuer_key),
        },
        "cases": cases,
    }
    if artifact["sourcePins"]["ap2Commit"] != AP2_COMMIT:
        raise RuntimeError("AP2 source pin was not retained in output")
    write_json(output, artifact)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    generate(args.output.resolve())


if __name__ == "__main__":
    main()
