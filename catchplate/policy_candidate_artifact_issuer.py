"""Fixed candidate-artifact encoding/signing under external operator approval.

The separately pinned input supplies every business fact, original interval,
build identity and public key. Their presence does not approve them or prove a
build, current database predecessor, enrollment, publication or native custody.
This issuer verifies the supplied bundle signature, not compiler execution.
Only envelope/signature/digest projections are derived. Production intake must
still authenticate the actual current signing-key head and active predecessor.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

API = "catchplate.policyCandidateArtifactAuthorityInput/v1"
DOMAIN = "catchplate.policyCandidateArtifact/v2"
PROFILE = "catchplate.canonicalJson/ascii-integer-v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ORIGINAL_BYTES = 8 * 1024 * 1024
RECORD_FIELDS = frozenset({
    "candidate_id", "scope", "policy_id", "policy_sequence", "rollback_epoch", "policy_hash",
    "predecessor_policy_sequence", "predecessor_rollback_epoch", "predecessor_policy_hash",
    "compiler_digest", "compiler_config_digest", "policy_schema_digest", "semantic_model_digest",
    "evaluator_abi_digest", "policy_bundle_digest", "runtime_digest", "staged_by",
})
BUILD_FIELDS = {
    "compilerDigest": "compiler_digest", "compilerConfigDigest": "compiler_config_digest",
    "policySchemaDigest": "policy_schema_digest", "semanticModelDigest": "semantic_model_digest",
    "evaluatorAbiDigest": "evaluator_abi_digest", "runtimeDigest": "runtime_digest",
}
KEY_FIELDS = {"publicKeyBase64url", "signingKeyId", "signingKeySpkiSha256"}


def _require(condition):
    if not condition:
        raise ValueError("policy candidate artifact issuer refused")


def _fields(value, names):
    _require(type(value) is dict and set(value) == set(names))
    return value


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    return value


def _integer(value, *, minimum=1):
    _require(type(value) is int and minimum <= value <= (1 << 63) - 1)
    return value


def _text(value, maximum):
    _require(type(value) is str and 0 < len(value.encode("utf-8")) <= maximum)


def _canonical(value):
    # Exact existing db.dumps / portal record encoding, including ASCII DEL.
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def _pairs(items):
    result = {}
    for name, value in items:
        _require(name not in result)
        result[name] = value
    return result


def _reject(_value):
    raise ValueError("noncanonical policy candidate input")


def _document(raw, maximum, *, bundle=False):
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
        parse_constant=_reject, **({} if bundle else {"parse_float": _reject}))
    _require(type(value) is dict and _canonical(value) == raw)
    return value


def _original(text, *, bundle=False):
    _text(text, MAX_ORIGINAL_BYTES)
    _require(text.isascii())
    raw = text.encode("ascii")
    return raw, _document(raw, MAX_ORIGINAL_BYTES, bundle=bundle)


def _encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decoded(value, size):
    _require(type(value) is str and len(value) == (size * 8 + 5) // 6
        and re.fullmatch(r"[A-Za-z0-9_-]+", value))
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    _require(len(raw) == size and _encoded(raw) == value)
    return raw


def _key(value):
    raw = _decoded(value["publicKeyBase64url"], 32)
    key = Ed25519PublicKey.from_public_bytes(raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _require(_sha(spki) == _digest(value["signingKeyId"])
        == _digest(value["signingKeySpkiSha256"]))
    return key, raw


def _current(payload, now):
    issued = _integer(payload["issuedAtEpochNs"], minimum=0)
    expires = _integer(payload["expiresAtEpochNs"])
    _require(issued <= _integer(now) < expires)


def prepare_input(input_original: bytes, *, input_sha256: str, now_epoch_ns: int) -> dict:
    """Verify pinned public originals before any private-key access.

    The returned parsed data is not approval or an input capability to sign().
    No public/private key discovery or application signing-key loader is used.
    """
    _require(type(input_original) is bytes and 0 < len(input_original) <= MAX_INPUT_BYTES)
    _require(_sha(input_original) == _digest(input_sha256))
    value = _fields(_document(input_original, MAX_INPUT_BYTES), {
        "apiVersion", "payloadOriginal", "signedPolicyBundleOriginal",
        "policySigningAuthority", "authority", "buildIdentity",
    })
    _require(value["apiVersion"] == API)
    _, payload = _original(value["payloadOriginal"])
    _fields(payload, {"issuedAtEpochNs", "expiresAtEpochNs", "record"})
    _current(payload, now_epoch_ns)
    record = _fields(payload["record"], RECORD_FIELDS)
    _require(record["scope"] == "active")
    for name in ("candidate_id", "policy_id"):
        _text(record[name], 256)
    _text(record["staged_by"], 1024)
    # db._candidate_authority_signed_record also applies its ASCII/integer
    # canonical-profile check after the business fields' UTF-8 byte bounds.
    _require(all(record[name].isascii() for name in ("candidate_id", "policy_id", "staged_by")))
    for name in ("policy_sequence", "rollback_epoch", "predecessor_policy_sequence", "predecessor_rollback_epoch"):
        _integer(record[name])
    for name in ("policy_hash", "predecessor_policy_hash", "policy_bundle_digest", *BUILD_FIELDS.values()):
        _digest(record[name])
    _require(record["policy_sequence"] > record["predecessor_policy_sequence"]
        and record["rollback_epoch"] >= record["predecessor_rollback_epoch"]
        and record["policy_hash"] != record["predecessor_policy_hash"])
    build = _fields(value["buildIdentity"], BUILD_FIELDS)
    for public_name, record_name in BUILD_FIELDS.items():
        _require(_digest(build[public_name]) == record[record_name])
    authority = _fields(value["authority"], KEY_FIELDS | {"evidenceKind", "signatureDomain"})
    _require(authority["evidenceKind"] == "candidate_artifact" and authority["signatureDomain"] == DOMAIN)
    _key(authority)
    bundle_authority = _fields(value["policySigningAuthority"], KEY_FIELDS)
    public, _ = _key(bundle_authority)
    bundle_raw, bundle = _original(value["signedPolicyBundleOriginal"], bundle=True)
    _require(bundle.get("apiVersion") in {"catchplate.policy/v1", "catchplate.policy/v2"}
        and bundle.get("kind") == "PolicyBundle" and type(bundle.get("metadata")) is dict)
    metadata = bundle["metadata"]
    _require(metadata.get("signingKeyId") == bundle_authority["signingKeyId"]
        and metadata.get("id") == record["policy_id"]
        and type(metadata.get("sequence")) is int and metadata["sequence"] == record["policy_sequence"]
        and type(metadata.get("rollbackEpoch")) is int and metadata["rollbackEpoch"] == record["rollback_epoch"])
    signature = metadata.get("signature")
    _require(type(signature) is str and signature.startswith("ed25519:"))
    signature_raw = _decoded(signature[8:], 64)
    # Actual v1/v2 framing only; this pure helper never loads application keys.
    from catchplate.policy_bundle import policy_signature_bytes
    message = policy_signature_bytes(bundle)
    public.verify(signature_raw, message)
    _require(record["policy_hash"] == _sha(message) and record["policy_bundle_digest"] == _sha(bundle_raw))
    return value


def sign(*, input_original: bytes, input_sha256: str, signing_key: Ed25519PrivateKey, check=None) -> bytes:
    """Sign once; caller owns approved originals, key custody and IO lifetime."""
    _require(check is None or callable(check))
    if check is not None:
        check()
    before_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    before_wall = time.time_ns()
    value = prepare_input(input_original, input_sha256=input_sha256, now_epoch_ns=before_wall)
    payload_raw, payload = _original(value["payloadOriginal"])
    deadline = before_boot + payload["expiresAtEpochNs"] - before_wall
    expected, _ = _key(value["authority"])
    _require(isinstance(signing_key, Ed25519PrivateKey))
    _require(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == expected.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def current():
        if check is not None:
            check()
        now_wall, now_boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _require(before_wall <= now_wall and before_boot <= now_boot < deadline)
        _current(payload, now_wall)

    current()
    message = b"\0".join((b"catchplate.signedEnvelope/v1", DOMAIN.encode("ascii"),
        PROFILE.encode("ascii"), payload_raw))
    signature_raw = signing_key.sign(message)
    expected.verify(signature_raw, message)
    signature = _encoded(signature_raw)
    key_id = value["authority"]["signingKeyId"]
    envelope = {"apiVersion": DOMAIN, "kind": "PolicyCandidateArtifact", "canonicalProfile": PROFILE,
        "signatureDomain": DOMAIN, "payload": payload, "payloadSha256": _sha(payload_raw),
        "signatureAlgorithm": "Ed25519", "signingKeyId": key_id, "signingKeySpkiSha256": key_id,
        "signature": signature}
    envelope_raw = _canonical(envelope)
    record = {**payload["record"], "artifact_envelope_digest": _sha(envelope_raw),
        "artifact_payload_digest": _sha(payload_raw), "artifact_envelope_json": envelope_raw.decode("ascii"),
        "artifact_payload_json": value["payloadOriginal"], "signature_algorithm": "Ed25519",
        "signing_key_id": key_id, "signature": signature, "signature_digest": _sha(signature_raw)}
    output = _canonical({"kind": "artifact", "record": record})
    _require(len(output) <= MAX_ORIGINAL_BYTES)
    current()
    return output
