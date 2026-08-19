"""Generate one transaction-ready AP2 artifact for public Base Sepolia evidence.

The fixture keys are publicly derived test keys. This script signs fixture data only; it
does not fund an account, submit a transaction, or contact an RPC endpoint.
"""

from __future__ import annotations

import argparse
import logging
import random

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ap2.sdk.mandate import MandateClient
from ap2.sdk.sdjwt import kb_sd_jwt, parse_token
from sd_jwt.common import SDJWTCommon

from artifact_common import (
    AP2_COMMIT,
    EXPECTED_AUDIENCE,
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
    resign_sd_jwt,
    sha256_b64url,
    sha256_hex,
    write_json,
)
from generate_signed_artifacts import create_receipt
from verify_extract_artifacts import fixture_public_keys, verify_case


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIRECTORY = ROOT / "build/public-evm"
CASE_ID = "public-base-sepolia-usdc-01"
NETWORK = "eip155:84532"
ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
PAYER = "0xA3ACaC31a63387e041CB6aC7A5cE8a92554Ef4C7"
PAYEE = address_from_label("pulse-public-evm/payee/base-sepolia-usdc/v1")
AMOUNT = 1_000
DEFAULT_MAX_TIMEOUT_SECONDS = 7 * 24 * 60 * 60
PLACEHOLDER_TRANSACTION_HASH = "0x" + "0" * 64


def positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def transaction_hash(value: str) -> str:
    if len(value) != 66 or not value.startswith("0x"):
        raise argparse.ArgumentTypeError("expected a 32-byte 0x-prefixed transaction hash")
    try:
        int(value[2:], 16)
    except ValueError as error:
        raise argparse.ArgumentTypeError("transaction hash must be hexadecimal") from error
    return value.lower()


def iso8601(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def create_models(
    *, now_epoch_seconds: int, max_timeout_seconds: int, holder_public: dict[str, Any]
) -> tuple[OpenPaymentMandateWithX402, ClosedPaymentMandateWithX402, str]:
    merchant = Merchant(
        id="merchant-public-base-sepolia-usdc-01",
        name="Public Base Sepolia Fixture Merchant",
        website="https://github.com/shibutatsu/pulse-ap2-x402-conformance",
    )
    amount = Amount(amount=AMOUNT, currency="USD")
    open_checkout_reference = sha256_b64url(
        f"pulse-public-evm-open-checkout:v1:{now_epoch_seconds}"
    )
    instrument = X402PreservingPaymentInstrument(
        id="x402-eip3009-base-sepolia-usdc-public-01",
        description="Public Base Sepolia USDC EIP-3009 evidence instrument",
        x402=X402InstrumentExtension(
            network=NETWORK,
            asset=ASSET,
            amount=str(AMOUNT),
            payTo=PAYEE,
            payer=PAYER,
            ap2PayeeId=merchant.id,
            ap2PaymentAmount=amount.model_dump(),
            maxTimeoutSeconds=max_timeout_seconds,
            eip712Domain=X402Eip712Domain(name="USDC", version="2"),
        ),
    )
    open_mandate = OpenPaymentMandateWithX402(
        constraints=[
            PaymentReferenceConstraint(
                conditional_transaction_id=open_checkout_reference
            ),
            AllowedPaymentInstrumentsConstraint(allowed=[instrument]),
            AmountRangeConstraint(currency="USD", min=AMOUNT, max=AMOUNT),
            AllowedPayeesConstraint(allowed=[merchant]),
        ],
        cnf={"jwk": holder_public},
        iat=now_epoch_seconds - 180,
        exp=now_epoch_seconds + max_timeout_seconds,
    )
    closed_mandate = ClosedPaymentMandateWithX402(
        transaction_id=open_checkout_reference,
        payee=merchant,
        payment_amount=amount,
        payment_instrument=instrument,
        execution_date=iso8601(now_epoch_seconds),
        iat=now_epoch_seconds - 120,
        exp=now_epoch_seconds + max_timeout_seconds,
    )
    return open_mandate, closed_mandate, open_checkout_reference


def generate(
    *,
    now_epoch_seconds: int,
    receipt_issued_at: int,
    max_timeout_seconds: int,
    network_confirmation_id: str,
    output_directory: Path,
) -> None:
    if max_timeout_seconds < 60:
        raise ValueError("max timeout must be at least 60 seconds")
    if receipt_issued_at < now_epoch_seconds:
        raise ValueError("receipt issue time must not precede the case evaluation time")

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
    open_model, closed_model, open_checkout_reference = create_models(
        now_epoch_seconds=now_epoch_seconds,
        max_timeout_seconds=max_timeout_seconds,
        holder_public=holder_public,
    )

    SDJWTCommon.unsafe_randomness = True
    logging.getLogger("sd_jwt").setLevel(logging.ERROR)
    random.seed(0xA240202)
    original_time = kb_sd_jwt.time.time
    kb_sd_jwt.time.time = lambda: now_epoch_seconds - 120
    client = MandateClient()
    try:
        randomized_open = client.create(
            payloads=[open_model], issuer_key=open_issuer_key
        )
        open_token = resign_sd_jwt(randomized_open, open_issuer_key)
        randomized_chain = client.present(
            holder_key=terminal_holder_key,
            mandate_token=open_token,
            payloads=[closed_model],
            aud=EXPECTED_AUDIENCE,
            nonce="ap2-public-evm-terminal-nonce-01",
        )
        root_segment, leaf_segment = randomized_chain.rsplit("~~", 1)
        closed_leaf_segment = resign_sd_jwt(leaf_segment, terminal_holder_key)
        closed_chain = f"{root_segment}~~{closed_leaf_segment}"
        closed_leaf_jwt = client.get_closed_mandate_jwt(closed_chain)
        closed_reference = sha256_b64url(closed_leaf_jwt.encode("ascii"))
        eip3009_nonce = "0x" + b64url_decode(closed_reference).hex()
        receipt_jwt, receipt_payload = create_receipt(
            reference=closed_reference,
            case_id=CASE_ID,
            network_confirmation_id=network_confirmation_id,
            receipt_key=receipt_issuer_key,
            issued_at=receipt_issued_at,
        )
        open_parsed = parse_token(open_token)
        closed_parsed = parse_token(closed_leaf_segment)
        if not open_parsed.disclosures or not closed_parsed.disclosures:
            raise RuntimeError("Expected disclosures in both AP2 SD-JWT hops")
        if closed_parsed.typ != "kb+sd-jwt":
            raise RuntimeError(
                f"Expected terminal typ kb+sd-jwt, got {closed_parsed.typ}"
            )
    finally:
        kb_sd_jwt.time.time = original_time

    generated_at = iso8601(now_epoch_seconds)
    artifact = {
        "artifactVersion": "ap2-signed-artifacts/0.1",
        "generatedAt": generated_at,
        "sourcePins": {
            **source_metadata,
            "ap2PackageVersion": "0.1",
        },
        "settlementState": (
            "prepared"
            if network_confirmation_id == PLACEHOLDER_TRANSACTION_HASH
            else "recorded"
        ),
        "publicSettlementProfile": {
            "network": NETWORK,
            "chainId": 84532,
            "asset": ASSET,
            "payer": PAYER,
            "payTo": PAYEE,
            "amount": str(AMOUNT),
            "maxTimeoutSeconds": max_timeout_seconds,
            "eip712Domain": {"name": "USDC", "version": "2"},
        },
        "determinism": {
            "scope": "Transaction-ready public testnet evidence fixture",
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
        "cases": [
            {
                "id": CASE_ID,
                "nowEpochSeconds": now_epoch_seconds,
                "verificationTimeEpochSeconds": receipt_issued_at,
                "expectedAudience": EXPECTED_AUDIENCE,
                "expectedNonce": "ap2-public-evm-terminal-nonce-01",
                "openCheckoutReference": open_checkout_reference,
                "artifacts": {
                    "openPaymentMandateSdJwt": open_token,
                    "closedPaymentMandateChain": closed_chain,
                    "closedPaymentMandateLeafJwt": closed_leaf_jwt,
                    "closedPaymentMandateReference": closed_reference,
                    "paymentReceiptJwt": receipt_jwt,
                },
                "expected": {
                    "eip3009Nonce": eip3009_nonce,
                    "networkConfirmationId": network_confirmation_id,
                    "paymentReceipt": receipt_payload,
                    "transactionId": open_checkout_reference,
                    "x402InstrumentId": "x402-eip3009-base-sepolia-usdc-public-01",
                },
            }
        ],
    }
    if artifact["sourcePins"]["ap2Commit"] != AP2_COMMIT:
        raise RuntimeError("AP2 source pin was not retained in output")

    output_directory.mkdir(parents=True, exist_ok=True)
    artifact_path = output_directory / "ap2-signed-artifact.json"
    normalized_path = output_directory / "ap2-normalized-record.json"
    write_json(artifact_path, artifact)

    open_public, terminal_public, receipt_public = fixture_public_keys(artifact)
    record = verify_case(
        artifact["cases"][0],
        open_public=open_public,
        terminal_public=terminal_public,
        receipt_public=receipt_public,
    )
    normalized = {
        "recordVersion": "ap2-normalized-verification-records/0.1",
        "generatedAt": generated_at,
        "sourcePins": artifact["sourcePins"],
        "sourceArtifactSha256": sha256_hex(artifact_path.read_bytes()),
        "records": [record],
    }
    write_json(normalized_path, normalized)
    print(f"Wrote transaction-ready AP2 artifacts to {output_directory}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--now-epoch-seconds", required=True, type=positive_integer)
    parser.add_argument("--receipt-issued-at", type=positive_integer)
    parser.add_argument(
        "--max-timeout-seconds",
        type=positive_integer,
        default=DEFAULT_MAX_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--network-confirmation-id",
        type=transaction_hash,
        default=PLACEHOLDER_TRANSACTION_HASH,
    )
    parser.add_argument(
        "--output-directory", type=Path, default=DEFAULT_OUTPUT_DIRECTORY
    )
    args = parser.parse_args()
    generate(
        now_epoch_seconds=args.now_epoch_seconds,
        receipt_issued_at=args.receipt_issued_at or args.now_epoch_seconds,
        max_timeout_seconds=args.max_timeout_seconds,
        network_confirmation_id=args.network_confirmation_id,
        output_directory=args.output_directory.resolve(),
    )


if __name__ == "__main__":
    main()
