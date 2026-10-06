"""Offline PolicyBundle signatures under independently pinned operator approval.

Every unsigned field, public key and original issuance interval is supplied by
the approving operator. This software-key component neither generates authority
nor enrolls, stages or publishes it. The interval bounds this signing invocation,
not policy runtime validity; no new policy metadata or expiry semantics are
invented. Consumer compilation, authorization and current trust remain separate.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware.policy_bundle import (
    _admit_policy_json_object, canonical_json, compile_policy_bundle,
    policy_signature_bytes, strict_json_loads,
)

API = "serverware.policyBundleAuthorityInput/v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 8 * 1024 * 1024  # Existing portal/artifact original bound.
KEY_FIELDS = {"publicKeyBase64url", "signingKeyId", "signingKeySpkiSha256"}


def _require(condition):
    if not condition:
        raise ValueError("policy bundle issuer refused")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    return value


def _canonical(value):
    return canonical_json(value).encode("ascii")


def _document(raw, maximum):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = strict_json_loads(raw)
    _require(type(value) is dict and _canonical(value) == raw)
    return value


def _encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _key(authority):
    _require(type(authority) is dict and set(authority) == KEY_FIELDS)
    text = authority["publicKeyBase64url"]
    _require(type(text) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", text))
    raw = base64.b64decode(text + "=", altchars=b"-_", validate=True)
    _require(len(raw) == 32 and _encoded(raw) == text)
    public = Ed25519PublicKey.from_public_bytes(raw)
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _require(_sha(spki) == _digest(authority["signingKeyId"]) == _digest(authority["signingKeySpkiSha256"]))
    return public


def _current(value, now):
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    _require(type(issued) is int and type(expires) is int and type(now) is int
        and 0 <= issued <= now < expires <= (1 << 63) - 1)


def _unsigned(value):
    text = value["unsignedPolicyBundleOriginal"]
    _require(type(text) is str and text.isascii() and 0 < len(text) <= MAX_BUNDLE_BYTES)
    bundle = _document(text.encode("ascii"), MAX_BUNDLE_BYTES)
    _admit_policy_json_object(bundle)
    _require(bundle.get("apiVersion") in {"serverware.policy/v1", "serverware.policy/v2"}
        and bundle.get("kind") == "PolicyBundle" and type(bundle.get("metadata")) is dict)
    metadata = bundle["metadata"]
    _require("signature" not in metadata)
    _require("signingKeyId" not in metadata or metadata["signingKeyId"] == value["authority"]["signingKeyId"])
    # Preserve the existing sign_policy_bundle v2 route-authority admission.
    if bundle["apiVersion"] == "serverware.policy/v2":
        from serverware.policy_route_authority import admit
        admit(bundle)
    return bundle


def prepare_input(input_original: bytes, *, input_sha256: str, now_epoch_ns: int) -> dict:
    """Check the exact approved public input before reading private key bytes."""
    _require(type(input_original) is bytes and 0 < len(input_original) <= MAX_INPUT_BYTES)
    _require(_sha(input_original) == _digest(input_sha256))
    value = _document(input_original, MAX_INPUT_BYTES)
    _require(set(value) == {"apiVersion", "unsignedPolicyBundleOriginal", "authority",
        "issuedAtEpochNs", "expiresAtEpochNs"} and value["apiVersion"] == API)
    _current(value, now_epoch_ns)
    _key(value["authority"])
    bundle = _unsigned(value)
    # Pure semantic/schema admission under the real signed-policy constraints;
    # this neither loads signing trust nor turns compilation into approval.
    compile_policy_bundle(bundle, verify_signature=False, validate_schema=True,
        enforce_signed_policy_constraints=True)
    bundle["metadata"]["signingKeyId"] = value["authority"]["signingKeyId"]
    policy_signature_bytes(bundle)  # Check actual v1/v2 encoding before key access.
    # Preflight the exact fixed signature-string overhead; no signature is made.
    bundle["metadata"]["signature"] = ""
    _require(len(_canonical(bundle)) + 94 <= MAX_BUNDLE_BYTES)
    return value


def sign(*, input_original: bytes, input_sha256: str, signing_key: Ed25519PrivateKey, check=None) -> bytes:
    """Issue one signature without an application key loader or trust mutation."""
    _require(check is None or callable(check))
    if check is not None:
        check()
    before_boot, before_wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    value = prepare_input(input_original, input_sha256=input_sha256, now_epoch_ns=before_wall)
    deadline = before_boot + value["expiresAtEpochNs"] - before_wall
    public = _key(value["authority"])
    _require(isinstance(signing_key, Ed25519PrivateKey))
    _require(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    bundle = _unsigned(value)
    bundle["metadata"]["signingKeyId"] = value["authority"]["signingKeyId"]
    message = policy_signature_bytes(bundle)

    def current():
        if check is not None:
            check()
        now_boot, now_wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        _require(before_boot <= now_boot < deadline and before_wall <= now_wall)
        _current(value, now_wall)

    current()
    signature = signing_key.sign(message)
    public.verify(signature, message)
    bundle["metadata"]["signature"] = "ed25519:" + _encoded(signature)
    output = _canonical(bundle)
    _require(len(output) <= MAX_BUNDLE_BYTES)
    current()
    return output
