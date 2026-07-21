"""Shared fixture-only AP2 models and deterministic cryptographic helpers.

The signing keys in this module are derived from public labels. They are not
secrets and MUST NOT be reused outside committed conformance fixtures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess

from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto.jwk import JWK
from pydantic import BaseModel, ConfigDict, Field


AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
FIXED_NOW = 1_784_592_000
GENERATED_AT = "2026-07-21T00:00:00Z"
FIXTURE_COUNT = 20
EXPECTED_AUDIENCE = "https://synthetic-facilitator.example/ap2"
P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    16,
)

OPEN_ISSUER_KEY_LABEL = "pulse-ap2-conformance/open-issuer/public-fixture/v1"
TERMINAL_HOLDER_KEY_LABEL = (
    "pulse-ap2-conformance/terminal-holder/public-fixture/v1"
)
RECEIPT_ISSUER_KEY_LABEL = (
    "pulse-ap2-conformance/receipt-issuer/public-fixture/v1"
)


class X402Eip712Domain(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str


class X402InstrumentExtension(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[2] = 2
    scheme: Literal["exact"] = "exact"
    network: str
    asset: str
    amount: str
    payTo: str
    payer: str
    ap2PayeeId: str
    ap2PaymentAmount: dict[str, Any]
    maxTimeoutSeconds: int
    eip712Domain: X402Eip712Domain
    nonceBinding: Literal["base64url-decode-ap2-mandate-reference"] = (
        "base64url-decode-ap2-mandate-reference"
    )


class X402PreservingPaymentInstrument(BaseModel):
    """Fixture profile for AP2 issue #299.

    The generated AP2 ``PaymentInstrument`` at the pinned commit accepts only
    ``id``, ``type``, and ``description`` and silently drops extension fields
    during Pydantic validation. This extra-allow model is passed to the
    upstream SD-JWT primitives so ``x402`` remains inside the signed raw
    claims. Upstream generated models are still used later for AP2 constraint
    evaluation of the standardized fields.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    type: Literal["x402"] = "x402"
    description: str | None = None
    x402: X402InstrumentExtension


class Merchant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    website: str | None = None


class Amount(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: int
    currency: str


class PaymentReferenceConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["payment.reference"] = "payment.reference"
    conditional_transaction_id: str


class AllowedPaymentInstrumentsConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["payment.allowed_payment_instruments"] = (
        "payment.allowed_payment_instruments"
    )
    allowed: list[X402PreservingPaymentInstrument] = Field(
        json_schema_extra={"x-selectively-disclosable-array": True}
    )


class AmountRangeConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["payment.amount_range"] = "payment.amount_range"
    currency: str
    max: int
    min: int | None = None


class AllowedPayeesConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["payment.allowed_payees"] = "payment.allowed_payees"
    allowed: list[Merchant] = Field(
        json_schema_extra={"x-selectively-disclosable-array": True}
    )


class OpenPaymentMandateWithX402(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vct: Literal["mandate.payment.open.1"] = "mandate.payment.open.1"
    constraints: list[
        PaymentReferenceConstraint
        | AllowedPaymentInstrumentsConstraint
        | AmountRangeConstraint
        | AllowedPayeesConstraint
    ]
    cnf: dict[str, Any]
    iat: int
    exp: int


class ClosedPaymentMandateWithX402(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vct: Literal["mandate.payment.1"] = "mandate.payment.1"
    transaction_id: str
    payee: Merchant
    payment_amount: Amount
    payment_instrument: X402PreservingPaymentInstrument
    execution_date: str
    iat: int
    exp: int


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sha256_b64url(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return b64url(hashlib.sha256(raw).digest())


def sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value: Any) -> str:
    """Canonicalize this ASCII-keyed, integer-only fixture JSON profile."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_sha256_b64url(value: Any) -> str:
    return sha256_b64url(canonical_json(value))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def deterministic_scalar(label: str) -> int:
    return int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest(), "big") % (
        P256_ORDER - 1
    ) + 1


def fixture_jwk(label: str, kid: str) -> JWK:
    private_key = ec.derive_private_key(deterministic_scalar(label), ec.SECP256R1())
    as_dict = json.loads(JWK.from_pyca(private_key).export())
    # Do not add ``use`` at this SDK revision. Its generated JsonWebKey turns
    # that value into an Enum and then passes the Enum to jwcrypto, which makes
    # cnf.jwk reconstruction fail before key-binding verification.
    as_dict.update({"alg": "ES256", "kid": kid})
    return JWK.from_json(json.dumps(as_dict))


def public_jwk(key: JWK) -> dict[str, Any]:
    return json.loads(key.export_public())


def _bits2octets(digest: bytes) -> bytes:
    reduced = int.from_bytes(digest, "big") % P256_ORDER
    return reduced.to_bytes(32, "big")


def _rfc6979_k(private_scalar: int, digest: bytes) -> int:
    """Return RFC 6979 HMAC-SHA256 nonce for fixture-only ES256 signing."""
    x = private_scalar.to_bytes(32, "big")
    h1 = _bits2octets(digest)
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < P256_ORDER:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def deterministic_es256_signature(signing_input: bytes, key: JWK) -> bytes:
    digest = hashlib.sha256(signing_input).digest()
    private_data = json.loads(key.export())
    private_scalar = int.from_bytes(b64url_decode(private_data["d"]), "big")
    nonce = _rfc6979_k(private_scalar, digest)
    ephemeral = ec.derive_private_key(nonce, ec.SECP256R1())
    r = ephemeral.public_key().public_numbers().x % P256_ORDER
    z = int.from_bytes(digest, "big")
    s = (pow(nonce, -1, P256_ORDER) * (z + r * private_scalar)) % P256_ORDER
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def resign_compact_jwt(token: str, key: JWK) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Expected a compact JWT with exactly three parts")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = deterministic_es256_signature(signing_input, key)
    return f"{parts[0]}.{parts[1]}.{b64url(signature)}"


def resign_sd_jwt(token: str, key: JWK) -> str:
    issuer_jwt, separator, remainder = token.partition("~")
    if not separator:
        raise ValueError("Expected compact SD-JWT serialization")
    return f"{resign_compact_jwt(issuer_jwt, key)}~{remainder}"


def address_from_label(label: str) -> str:
    return f"0x{hashlib.sha256(label.encode('utf-8')).hexdigest()[-40:]}"


def ap2_source_metadata() -> dict[str, str]:
    source_env = os.environ.get("AP2_SOURCE_DIR")
    if not source_env:
        raise RuntimeError(
            "AP2_SOURCE_DIR is required; use scripts/ap2/run-pinned.sh"
        )
    source_dir = Path(source_env).resolve()
    result = subprocess.run(
        ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    actual_commit = result.stdout.strip()
    if actual_commit != AP2_COMMIT:
        raise RuntimeError(
            f"AP2 source pin mismatch: expected {AP2_COMMIT}, got {actual_commit}"
        )
    mandate_source = source_dir / "code/sdk/python/ap2/sdk/mandate.py"
    if not mandate_source.is_file():
        raise RuntimeError(f"Pinned AP2 mandate.py not found: {mandate_source}")
    return {
        "ap2Commit": actual_commit,
        "mandatePySha256": sha256_hex(mandate_source.read_bytes()),
    }
