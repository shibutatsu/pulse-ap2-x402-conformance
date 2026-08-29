#!/usr/bin/env python3
"""Deterministic VATE eligible-input to frozen Pulse case mapper.

This fixture-only executable uses Python's standard library and public labels.
It reads one canonical request from stdin and writes one canonical response to
stdout. It performs no file, network, subprocess, or environment access.
"""

import base64
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation


INTERFACE_VERSION = "vate-pulse-candidate-executable-0.2"
CASE_VERSION = "ap2-x402-conformance/0.3"
SOURCE_PINS = {
    "ap2Commit": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
    "x402Commit": "17d319fab5c17a6b4873eb41197894db924f59ed",
    "x402PackageVersion": "2.23.0",
}

NETWORK = "eip155:84532"
CHAIN_ID = 84532
ASSET = "0xb95de892c9463d5187a03c1fe18904d9724fd50f"
PAY_TO = "0x4c9ac5336ef07b88ad149ec5eb5cf1d7ce37cf17"
ASSET_DECIMALS = 2
ASSET_UNITS_PER_USD = Decimal("1")
MAX_TIMEOUT_SECONDS = 300
DOMAIN_NAME = "VATE Pulse Synthetic USD"
DOMAIN_VERSION = "1"
EXPECTED_AUDIENCE = "https://synthetic-facilitator.example/ap2"
VERIFIER_LABEL = "candidate-stdlib/vate-pulse-mapper/0.1+Pulse@e06a6cb"

OPEN_LABEL = "pulse-ap2-conformance/open-issuer/public-fixture/v1"
HOLDER_LABEL = "pulse-ap2-conformance/terminal-holder/public-fixture/v1"
RECEIPT_LABEL = "pulse-ap2-conformance/receipt-issuer/public-fixture/v1"
PAYER_LABEL = "pulse-ap2-x402-conformance/public-fixture-payer/v1"

OPEN_KID = "ap2-fixture-open-issuer-v1"
HOLDER_KID = "ap2-fixture-terminal-holder-v1"
RECEIPT_KID = "ap2-fixture-receipt-issuer-v1"

P256_P = int("ffffffff000000010000000000000000" "00000000ffffffffffffffffffffffff", 16)
P256_A = P256_P - 3
P256_B = int("5ac635d8aa3a93e7b3ebbd55769886bc" "651d06b0cc53b0f63bce3c3e27d2604b", 16)
P256_G = (
    int("6b17d1f2e12c4247f8bce6e563a440f" "277037d812deb33a0f4a13945d898c296", 16),
    int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e1" "62bce33576b315ececbb6406837bf51f5", 16),
)
P256_N = int("ffffffff00000000ffffffffffffffff" "bce6faada7179e84f3b9cac2fc632551", 16)

K1_P = int("ffffffffffffffffffffffffffffffff" "fffffffffffffffffffffffefffffc2f", 16)
K1_A = 0
K1_G = (
    int("79be667ef9dcbbac55a06295ce870b070" "29bfcdb2dce28d959f2815b16f81798", 16),
    int("483ada7726a3c4655da4fbfc0e1108a8" "fd17b448a68554199c47d08ffb10d4b8", 16),
)
K1_N = int("fffffffffffffffffffffffffffffffe" "baaedce6af48a03bbfd25e8cd0364141", 16)

MASK64 = (1 << 64) - 1
KECCAK_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)
KECCAK_ROUNDS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

USD_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$")
TIME_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MERCHANT_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")


def canonical_json(value):
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha256_b64url(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return b64url(hashlib.sha256(raw).digest())


def canonical_hash(value):
    return sha256_b64url(canonical_json(value))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_keys(value, keys, label):
    require(isinstance(value, dict), label + " must be an object")
    require(set(value) == set(keys), label + " has an invalid field set")
    return value


def parse_time(value, label):
    require(isinstance(value, str) and TIME_PATTERN.fullmatch(value), label + " must be exact RFC 3339 Z seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(label + " is invalid") from exc
    return int(parsed.timestamp())


def parse_usd(value, label):
    require(isinstance(value, str) and USD_PATTERN.fullmatch(value), label + " must be an exact USD decimal")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(label + " is invalid") from exc
    require(parsed.is_finite() and parsed >= 0, label + " is invalid")
    return parsed


def exact_integer(value, label):
    require(value.is_finite() and value >= 0 and value == value.to_integral_value(), label + " is not integral")
    result = int(value)
    require(result < 1 << 256, label + " exceeds uint256")
    return result


def rotate64(value, count):
    if count == 0:
        return value & MASK64
    return ((value << count) | (value >> (64 - count))) & MASK64


def keccak_permute(state):
    for round_value in KECCAK_ROUNDS:
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [columns[(x - 1) % 5] ^ rotate64(columns[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]
        shifted = [0] * 25
        for y in range(5):
            for x in range(5):
                shifted[y + 5 * ((2 * x + 3 * y) % 5)] = rotate64(
                    state[x + 5 * y], KECCAK_ROTATIONS[x + 5 * y]
                )
        for y in range(5):
            row = shifted[5 * y : 5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                state[x + 5 * y] &= MASK64
        state[0] ^= round_value


def keccak256(raw):
    rate = 136
    padded = bytearray(raw)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[lane * 8 : lane * 8 + 8], "little")
        keccak_permute(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def point_add(left, right, prime, curve_a):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % prime == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + curve_a) * pow(2 * y1, -1, prime)) % prime
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % prime, -1, prime)) % prime
    x3 = (slope * slope - x1 - x2) % prime
    y3 = (slope * (x1 - x3) - y1) % prime
    return x3, y3


def scalar_multiply(scalar, point, prime, curve_a):
    require(scalar > 0, "fixture scalar must be positive")
    result = None
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = point_add(result, addend, prime, curve_a)
        addend = point_add(addend, addend, prime, curve_a)
        value >>= 1
    require(result is not None, "fixture scalar produced the point at infinity")
    return result


def public_label_scalar(label, order, digest_function):
    material = digest_function(label.encode("utf-8"))
    return int.from_bytes(material, "big") % (order - 1) + 1


def rfc6979_candidates(scalar, digest, order):
    value = b"\x01" * 32
    key = b"\x00" * 32
    scalar_bytes = scalar.to_bytes(32, "big")
    reduced_digest = (int.from_bytes(digest, "big") % order).to_bytes(32, "big")
    key = hmac.new(key, value + b"\x00" + scalar_bytes + reduced_digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + scalar_bytes + reduced_digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < order:
            yield candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign_digest(scalar, digest, order, point, prime, curve_a, with_recovery):
    z_value = int.from_bytes(digest, "big")
    for nonce_scalar in rfc6979_candidates(scalar, digest, order):
        rx, ry = scalar_multiply(nonce_scalar, point, prime, curve_a)
        r_value = rx % order
        if r_value == 0:
            continue
        s_value = (pow(nonce_scalar, -1, order) * (z_value + r_value * scalar)) % order
        if s_value == 0:
            continue
        recovery = (ry & 1) | (2 if rx >= order else 0)
        if with_recovery and recovery > 1:
            continue
        if s_value > order // 2:
            s_value = order - s_value
            recovery ^= 1
        signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        if with_recovery:
            signature += bytes([27 + recovery])
        return signature
    raise ValueError("unable to create deterministic signature")


def p256_scalar(label):
    return public_label_scalar(label, P256_N, lambda raw: hashlib.sha256(raw).digest())


def public_jwk(label, kid):
    x_value, y_value = scalar_multiply(p256_scalar(label), P256_G, P256_P, P256_A)
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": kid,
        "x": b64url(x_value.to_bytes(32, "big")),
        "y": b64url(y_value.to_bytes(32, "big")),
    }


def compact_es256(header, payload, label):
    encoded_header = b64url(canonical_json(header).encode("utf-8"))
    encoded_payload = b64url(canonical_json(payload).encode("utf-8"))
    signing_input = (encoded_header + "." + encoded_payload).encode("ascii")
    signature = sign_digest(
        p256_scalar(label),
        hashlib.sha256(signing_input).digest(),
        P256_N,
        P256_G,
        P256_P,
        P256_A,
        False,
    )
    return encoded_header + "." + encoded_payload + "." + b64url(signature)


def payer_identity():
    scalar = int.from_bytes(keccak256(PAYER_LABEL.encode("utf-8")), "big")
    require(1 <= scalar < K1_N, "public payer label did not derive a valid scalar")
    x_value, y_value = scalar_multiply(scalar, K1_G, K1_P, K1_A)
    address = "0x" + keccak256(x_value.to_bytes(32, "big") + y_value.to_bytes(32, "big"))[-20:].hex()
    return scalar, address


def uint256(value):
    require(isinstance(value, int) and 0 <= value < 1 << 256, "invalid uint256")
    return value.to_bytes(32, "big")


def address_word(value):
    require(isinstance(value, str) and ADDRESS_PATTERN.fullmatch(value), "invalid EVM address")
    return bytes.fromhex(value[2:]).rjust(32, b"\x00")


def eip3009_digest(name, version, asset, sender, recipient, amount, valid_after, valid_before, nonce):
    domain_type = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    transfer_type = keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    )
    domain_hash = keccak256(
        domain_type
        + keccak256(name.encode("utf-8"))
        + keccak256(version.encode("utf-8"))
        + uint256(CHAIN_ID)
        + address_word(asset)
    )
    message_hash = keccak256(
        transfer_type
        + address_word(sender)
        + address_word(recipient)
        + uint256(amount)
        + uint256(valid_after)
        + uint256(valid_before)
        + nonce
    )
    return keccak256(b"\x19\x01" + domain_hash + message_hash)


def eip3009_signature(sender_scalar, sender, amount, valid_after, valid_before, nonce):
    digest = eip3009_digest(
        DOMAIN_NAME,
        DOMAIN_VERSION,
        ASSET,
        sender,
        PAY_TO,
        amount,
        valid_after,
        valid_before,
        nonce,
    )
    raw = sign_digest(sender_scalar, digest, K1_N, K1_G, K1_P, K1_A, True)
    return "0x" + raw.hex()


def source_values(eligible):
    exact_keys(eligible, {"admissionRequest", "ap2Mandate"}, "eligibleInput")
    admission = eligible["admissionRequest"]
    mandate = eligible["ap2Mandate"]
    require(isinstance(admission, dict) and isinstance(mandate, dict), "eligible documents must be objects")

    request_currency = admission.get("constraints", {}).get("max_amount", {}).get("currency")
    limit_currency = mandate.get("constraints", {}).get("max_amount", {}).get("currency")
    require(request_currency == "USD" and limit_currency == "USD", "only matching USD sources are supported")
    request_amount = parse_usd(admission["constraints"]["max_amount"]["value"], "request amount")
    limit_amount = parse_usd(mandate["constraints"]["max_amount"]["value"], "mandate amount")
    permitted_amount = min(request_amount, limit_amount)

    merchant = mandate.get("merchant")
    require(isinstance(merchant, str) and MERCHANT_PATTERN.fullmatch(merchant), "merchant is invalid")
    require(admission.get("constraints", {}).get("payment", {}).get("merchant") == merchant, "admission merchant differs")
    require(mandate.get("constraints", {}).get("allowed_merchant") == merchant, "allowed merchant differs")

    evaluation_text = admission.get("issued_at")
    evaluation = parse_time(evaluation_text, "evaluation time")
    request_expiry = parse_time(admission.get("expires_at"), "request expiry")
    mandate_issued = parse_time(mandate.get("issued_at"), "mandate issued time")
    mandate_expiry = parse_time(mandate.get("expires_at"), "mandate expiry")
    window = mandate.get("constraints", {}).get("execution_window", {})
    window_start = parse_time(window.get("not_before"), "window start")
    window_end = parse_time(window.get("not_after"), "window end")
    require(window_start < window_end, "execution window is empty")

    replay_nonce = mandate.get("constraints", {}).get("replay_nonce")
    require(isinstance(replay_nonce, str) and replay_nonce, "replay nonce is invalid")
    transaction_id = admission.get("transaction_id")
    require(isinstance(transaction_id, str) and transaction_id, "transaction id is invalid")
    resource = admission.get("target", {}).get("resource")
    require(isinstance(resource, str) and resource.startswith("https://"), "resource must be HTTPS")

    requested_minor = exact_integer(request_amount * 100, "requested minor units")
    permitted_minor = exact_integer(permitted_amount * 100, "permitted minor units")
    limit_minor = exact_integer(limit_amount * 100, "limit minor units")
    scale = Decimal(10) ** ASSET_DECIMALS
    requested_atomic = exact_integer(request_amount * ASSET_UNITS_PER_USD * scale, "requested atomic units")
    permitted_atomic = exact_integer(permitted_amount * ASSET_UNITS_PER_USD * scale, "permitted atomic units")

    closed_expiry = min(request_expiry, mandate_expiry, window_end)
    open_expiry = min(mandate_expiry, window_end)
    valid_before = min(request_expiry, mandate_expiry, window_end, evaluation + MAX_TIMEOUT_SECONDS)
    source_class = "overrun" if request_amount > limit_amount else "stale" if evaluation > window_end else "allow"
    require(not (request_amount > limit_amount and evaluation > window_end), "combined overrun and stale source is unsupported")

    return {
        "admission": admission,
        "mandate": mandate,
        "request_amount": request_amount,
        "request_minor": requested_minor,
        "permitted_minor": permitted_minor,
        "limit_minor": limit_minor,
        "requested_atomic": requested_atomic,
        "permitted_atomic": permitted_atomic,
        "merchant": merchant,
        "evaluation_text": evaluation_text,
        "evaluation": evaluation,
        "mandate_issued": mandate_issued,
        "closed_expiry": closed_expiry,
        "open_expiry": open_expiry,
        "valid_after": window_start,
        "valid_before": valid_before,
        "replay_nonce": replay_nonce,
        "transaction_id": transaction_id,
        "resource": resource,
        "source_class": source_class,
    }


def map_item(item):
    exact_keys(item, {"workItemId", "eligibleInput"}, "map item")
    work_item = item["workItemId"]
    require(isinstance(work_item, str) and work_item, "workItemId is invalid")
    values = source_values(item["eligibleInput"])
    merchant = values["merchant"]
    now = values["evaluation"]
    payer_scalar, payer = payer_identity()

    checkout_reference = sha256_b64url(
        "vate-pulse-open-checkout-v1:" + values["transaction_id"]
    )
    merchant_record = {
        "id": merchant,
        "name": merchant,
        "website": "https://" + merchant,
    }
    amount_record = {"amount": values["permitted_minor"], "currency": "USD"}
    x402_extension = {
        "version": 2,
        "scheme": "exact",
        "network": NETWORK,
        "asset": ASSET,
        "amount": str(values["permitted_atomic"]),
        "payTo": PAY_TO,
        "payer": payer,
        "ap2PayeeId": merchant,
        "ap2PaymentAmount": amount_record,
        "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "eip712Domain": {"name": DOMAIN_NAME, "version": DOMAIN_VERSION},
        "nonceBinding": "base64url-decode-ap2-mandate-reference",
    }
    instrument = {
        "id": "vate-pulse-eip3009-v1",
        "type": "x402",
        "description": "Synthetic exact EIP-3009 fixture instrument",
        "x402": x402_extension,
    }
    open_mandate = {
        "vct": "mandate.payment.open.1",
        "constraints": [
            {
                "type": "payment.reference",
                "conditional_transaction_id": checkout_reference,
            },
            {
                "type": "payment.allowed_payment_instruments",
                "allowed": [json.loads(canonical_json(instrument))],
            },
            {
                "type": "payment.amount_range",
                "currency": "USD",
                "max": values["limit_minor"],
                "min": 0,
            },
            {
                "type": "payment.allowed_payees",
                "allowed": [json.loads(canonical_json(merchant_record))],
            },
        ],
        "cnf": {"jwk": public_jwk(HOLDER_LABEL, HOLDER_KID)},
        "iat": values["mandate_issued"],
        "exp": values["open_expiry"],
    }
    closed_mandate = {
        "vct": "mandate.payment.1",
        "transaction_id": checkout_reference,
        "payee": merchant_record,
        "payment_amount": amount_record,
        "payment_instrument": instrument,
        "execution_date": values["evaluation_text"],
        "iat": now,
        "exp": values["closed_expiry"],
    }

    root_header = {"alg": "ES256", "kid": OPEN_KID, "typ": "example+sd-jwt"}
    root_payload = {"delegate_payload": [open_mandate], "_sd_alg": "sha-256"}
    root_jwt = compact_es256(root_header, root_payload, OPEN_LABEL)
    root_sd_jwt = root_jwt + "~"
    leaf_payload = {
        "delegate_payload": [closed_mandate],
        "iat": now,
        "aud": EXPECTED_AUDIENCE,
        "nonce": values["replay_nonce"],
        "sd_hash": sha256_b64url(root_sd_jwt.encode("ascii")),
        "_sd_alg": "sha-256",
    }
    leaf_header = {"alg": "ES256", "kid": HOLDER_KID, "typ": "kb+sd-jwt"}
    leaf_jwt = compact_es256(leaf_header, leaf_payload, HOLDER_LABEL)
    mandate_chain = root_jwt + "~~" + leaf_jwt + "~"
    closed_reference = sha256_b64url(leaf_jwt.encode("ascii"))
    nonce_bytes = base64.urlsafe_b64decode(closed_reference + "=")
    require(len(nonce_bytes) == 32, "closed mandate reference did not decode to 32 bytes")
    nonce_hex = "0x" + nonce_bytes.hex()

    transaction_hash = "0x" + hashlib.sha256(
        ("vate-pulse-settlement-v1:" + values["transaction_id"] + ":" + values["replay_nonce"]).encode("utf-8")
    ).hexdigest()
    payment_suffix = hashlib.sha256(values["transaction_id"].encode("utf-8")).hexdigest()[:20]
    payment_receipt = {
        "status": "Success",
        "iss": "synthetic-facilitator.example",
        "iat": now,
        "reference": closed_reference,
        "payment_id": "payment-" + payment_suffix,
        "psp_confirmation_id": "psp-" + payment_suffix,
        "network_confirmation_id": transaction_hash,
        "error": None,
        "error_description": None,
    }
    receipt_jwt = compact_es256(
        {"alg": "ES256", "kid": RECEIPT_KID, "typ": "JWT"},
        payment_receipt,
        RECEIPT_LABEL,
    )

    requirements = {
        "scheme": "exact",
        "network": NETWORK,
        "asset": ASSET,
        "amount": str(values["requested_atomic"]),
        "payTo": PAY_TO,
        "maxTimeoutSeconds": MAX_TIMEOUT_SECONDS,
        "extra": {
            "name": DOMAIN_NAME,
            "version": DOMAIN_VERSION,
            "assetTransferMethod": "eip3009",
            "ap2MandateReference": closed_reference,
            "ap2NonceDerivation": "base64url-decode-ap2-mandate-reference",
        },
    }
    authorization = {
        "from": payer,
        "to": PAY_TO,
        "value": str(values["requested_atomic"]),
        "validAfter": str(values["valid_after"]),
        "validBefore": str(values["valid_before"]),
        "nonce": nonce_hex,
    }
    signature = eip3009_signature(
        payer_scalar,
        payer,
        values["requested_atomic"],
        values["valid_after"],
        values["valid_before"],
        nonce_bytes,
    )

    pulse_case = {
        "caseVersion": CASE_VERSION,
        "sourcePins": SOURCE_PINS,
        "id": "vate-pulse-" + work_item,
        "description": "Candidate-owned VATE eligible-input projection into frozen Pulse.",
        "nowEpochSeconds": now,
        "ap2": {
            "closedMandate": closed_mandate,
            "openMandate": open_mandate,
            "paymentReceipt": payment_receipt,
            "verification": {
                "verifier": VERIFIER_LABEL,
                "verifiedAtEpochSeconds": now,
                "clockSkewSeconds": 0,
                "openCheckoutReference": checkout_reference,
                "closedMandateClaimsHash": canonical_hash(closed_mandate),
                "openMandateClaimsHash": canonical_hash(open_mandate),
                "closedMandateReference": closed_reference,
                "cryptographicEvidence": {
                    "mandateChain": mandate_chain,
                    "paymentReceiptJwt": receipt_jwt,
                    "trustedRootPublicJwk": public_jwk(OPEN_LABEL, OPEN_KID),
                    "trustedReceiptPublicJwk": public_jwk(RECEIPT_LABEL, RECEIPT_KID),
                    "expectedAudience": EXPECTED_AUDIENCE,
                    "expectedNonce": values["replay_nonce"],
                },
            },
        },
        "x402": {
            "requirements": requirements,
            "payload": {
                "x402Version": 2,
                "resource": {
                    "url": values["resource"],
                    "description": "Synthetic VATE-to-Pulse conformance resource",
                    "mimeType": "application/json",
                },
                "accepted": json.loads(canonical_json(requirements)),
                "payload": {
                    "signature": signature,
                    "authorization": authorization,
                },
            },
            "settlement": {
                "success": True,
                "payer": payer,
                "transaction": transaction_hash,
                "network": NETWORK,
            },
        },
        "inputHash": "",
        "expected": {"consistent": True, "failureCodes": []},
    }
    pulse_case["inputHash"] = canonical_hash(
        {
            "caseVersion": pulse_case["caseVersion"],
            "sourcePins": pulse_case["sourcePins"],
            "nowEpochSeconds": pulse_case["nowEpochSeconds"],
            "ap2": pulse_case["ap2"],
            "x402": pulse_case["x402"],
        }
    )
    return {
        "workItemId": work_item,
        "pulseInputRaw": canonical_json(pulse_case),
    }


def failure_codes(report):
    failures = report.get("failures")
    require(isinstance(failures, list), "raw Pulse report failures must be an array")
    codes = []
    for failure in failures:
        require(isinstance(failure, dict) and isinstance(failure.get("code"), str), "raw Pulse failure is invalid")
        codes.append(failure["code"])
    return codes


def check(name, passed, details):
    return {"name": name, "pass": bool(passed), "details": details}


def project_item(item):
    exact_keys(item, {"workItemId", "eligibleInput", "rawPulseReport"}, "project item")
    work_item = item["workItemId"]
    require(isinstance(work_item, str) and work_item, "workItemId is invalid")
    values = source_values(item["eligibleInput"])
    report = item["rawPulseReport"]
    require(isinstance(report, dict) and isinstance(report.get("consistent"), bool), "raw Pulse report is invalid")
    codes = failure_codes(report)
    source_class = values["source_class"]

    if source_class == "allow" and report["consistent"] and not codes:
        admission = values["admission"]
        evidence = admission.get("evidence_refs", [])
        checks = [
            check("decision.outcome", True, "Pulse accepted the generated input with no failures."),
            check(
                "request.audience",
                admission.get("audience") == admission.get("target", {}).get("audience"),
                "The request audience equals the target audience.",
            ),
            check(
                "evidence[0].protocol_hint",
                bool(evidence) and evidence[0].get("protocol_hint") == "ap2_human_not_present",
                "The eligible evidence declares the AP2 human-not-present protocol.",
            ),
            check("evidence.verification.result", True, "The frozen Pulse report is consistent."),
        ]
        projection = {
            "observed_relation_to_vate": "match",
            "pulse_outcome_class": "accept",
            "projected_vate_outcome": "allow",
            "projected_should_execute": True,
            "projected_reason_codes": ["EVIDENCE_VERIFIED", "POLICY_MATCH"],
            "projected_checks": checks,
        }
    elif source_class == "overrun" and not report["consistent"] and codes == ["AP2_X402_AMOUNT_MISMATCH"]:
        projection = {
            "observed_relation_to_vate": "mismatch",
            "pulse_outcome_class": "non-attenuate",
            "projected_vate_outcome": "deny",
            "projected_should_execute": False,
            "projected_reason_codes": ["AP2_X402_AMOUNT_MISMATCH"],
            "projected_checks": [],
        }
    elif (
        source_class == "stale"
        and not report["consistent"]
        and "EIP3009_VALID_BEFORE_EXPIRED" in codes
        and set(codes).issubset({"AP2_MANDATE_TIME_INVALID", "EIP3009_VALID_BEFORE_EXPIRED"})
    ):
        projection = {
            "observed_relation_to_vate": "match",
            "pulse_outcome_class": "reject",
            "projected_vate_outcome": "deny",
            "projected_should_execute": False,
            "projected_reason_codes": ["PERMIT_EXPIRED", "FAIL_CLOSED"],
            "projected_checks": [
                check("decision.outcome", True, "Pulse rejected the expired authorization."),
                check(
                    "evidence.verification.failure_reason",
                    True,
                    "The raw report includes the EIP-3009 expiry failure.",
                ),
            ],
        }
    else:
        projection = {
            "observed_relation_to_vate": "unsupported",
            "pulse_outcome_class": "unsupported",
            "projected_vate_outcome": "deny",
            "projected_should_execute": False,
            "projected_reason_codes": codes or ["UNMAPPED_PULSE_RESULT"],
            "projected_checks": [],
        }
    return {"workItemId": work_item, "projection": projection}


def execute(request):
    exact_keys(request, {"interfaceVersion", "operation", "items"}, "request")
    require(request["interfaceVersion"] == INTERFACE_VERSION, "interface version mismatch")
    items = request["items"]
    require(isinstance(items, list) and items, "request items must be a non-empty array")
    work_items = [item.get("workItemId") if isinstance(item, dict) else None for item in items]
    require(all(isinstance(value, str) and value for value in work_items), "workItemId is invalid")
    require(len(set(work_items)) == len(work_items), "workItemId values must be unique")
    operation = request["operation"]
    if operation == "map":
        outputs = [map_item(item) for item in items]
    elif operation == "project":
        outputs = [project_item(item) for item in items]
    else:
        raise ValueError("unsupported operation")
    return {
        "interfaceVersion": INTERFACE_VERSION,
        "operation": operation,
        "items": outputs,
    }


def main():
    try:
        request = json.load(sys.stdin)
        response = execute(request)
        sys.stdout.write(canonical_json(response))
        sys.stdout.write("\n")
    except Exception as exc:
        sys.stderr.write("mapper error: " + str(exc) + "\n")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
