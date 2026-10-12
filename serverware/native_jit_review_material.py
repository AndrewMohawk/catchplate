"""Private, purpose-fixed JIT review encryption; never custody admission.

The owner supplies its real KEK and independently validates the exact public
request, configured policy, source, identity and original lifetime. This leaf
checks byte commitments, not a signature, quote, current policy or permission.
It neither loads keys nor exposes a transport. ``open_pair`` is private material
readback, NOT authorization to disclose a review. Randomized ciphertext must be
retained by the owner; resealing is not recovery of an uncertain operation.
Python allocations do not provide a complete plaintext-erasure guarantee.
"""
from __future__ import annotations

import base64
from functools import wraps
import hashlib
import json
import math
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCOPE_SCHEMA = "serverware.nativeJitReviewScope/v1"
PAIR_SCHEMA = "serverware.nativeJitReviewPair/v1"
CANONICAL_SCHEMA = "serverware.jitCanonicalReviewPayload/v1"
MAX_PRIVATE_BYTES = 64 * 1024
MAX_PLAINTEXT_BYTES = 4 * MAX_PRIVATE_BYTES  # ASCII escaping of the UTF-8 URL.
MAX_SCOPE_BYTES = 4 * 1024 * 1024
MAX_PAIR_BYTES = 5 * 1024 * 1024
SCOPE_FIELDS = frozenset({"schema", "publicRequest", "sourceContractDigest",
    "controlPlaneConfigurationDigest", "ownerScopeDigest", "issuedAtEpochNs",
    "sealExpiresAtEpochNs", "documentExpiresAtEpochNs"})
PAIR_FIELDS = frozenset({"schema", "scope", "keyId", "items"})
ITEM_FIELDS = frozenset({"opaqueId", "valueKind", "plaintextSha256", "plaintextBytes",
    "wrappedKeyNonce", "wrappedKey", "ciphertextNonce", "ciphertext"})
PRIVATE_FIELDS = frozenset({"url", "canonical_request", "redacted_display"})
_METADATA_FIELDS = frozenset({"route_id", "method", "principal_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest",
    "pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses",
    "required_approver_roles", "allowed_approver_ids", "require_approver_webauthn",
    "approval_threshold", "approver_credential_policy"})
_COMMITMENTS = frozenset({"url_commitment", "canonical_request_digest",
    "redacted_display_digest", "original_arguments_digest"})
_REQUEST_FIELDS = frozenset({"schema", "operation", "operationId", "requestDigest",
    "handler", "operationManifestDigest", "arguments"})
_KINDS = ("approval-secret-json/v1", "approval-review-json/v1")
_PURPOSES = ("jit-canonical-request", "jit-redacted-display")


class MaterialError(ValueError):
    def __init__(self):
        super().__init__("native JIT review material is invalid")


def _require(condition):
    if not condition:
        raise MaterialError()


def _checked(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise MaterialError() from None
    return checked


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        separators=(",", ":"), sort_keys=True).encode("ascii")


def sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _copy(value, maximum, *, depth_limit=32):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _require(depth <= depth_limit and count <= 131072)
        if type(item) is dict:
            _require(all(type(key) is str for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        else:
            _require(item is None or type(item) in (bool, int, str)
                or (type(item) is float and math.isfinite(item)))
    raw = canonical(value)
    _require(len(raw) <= maximum)
    return json.loads(raw)


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)


def _integer(value, minimum, maximum):
    _require(type(value) is int and minimum <= value <= maximum)


def _framed(domain, *frames):
    raw = domain.encode("ascii") + b"\0"
    return sha256(raw + b"".join(len(frame).to_bytes(8, "big") + frame for frame in frames))


def _identity(request_digest, purpose):
    # Exact existing policyAuthorityDeterministicIdentity/v1 byte formula.
    digest = hashlib.sha256(canonical({
        "schema": "serverware.policyAuthorityDeterministicIdentity/v1",
        "operation": "jit.request", "requestDigest": request_digest,
        "purpose": purpose})).hexdigest()
    value = list(digest[:32])
    value[12], value[16] = "5", format((int(value[16], 16) & 3) | 8, "x")
    value = "".join(value)
    return "-".join((value[:8], value[8:12], value[12:16], value[16:20], value[20:]))


@_checked
def validate_scope(scope):
    """Own and check commitment grammar; the caller still pins real authority."""
    scope = _copy(scope, MAX_SCOPE_BYTES)
    _require(type(scope) is dict and set(scope) == SCOPE_FIELDS and scope["schema"] == SCOPE_SCHEMA)
    request = scope["publicRequest"]
    _require(type(request) is dict and set(request) == _REQUEST_FIELDS
        and request["schema"] == "serverware.policyAuthorityV9Request/v1"
        and request["operation"] == "jit.request" and request["handler"] == "ensure_jit_approval_request")
    for name in ("sourceContractDigest", "controlPlaneConfigurationDigest", "ownerScopeDigest"):
        _digest(scope[name])
    _require(scope["sourceContractDigest"] == request["operationManifestDigest"])
    arguments = request["arguments"]
    _require(type(arguments) is dict
        and set(arguments) == _METADATA_FIELDS | _COMMITMENTS | {"schema", "businessIntent"}
        and arguments["schema"] == "serverware.jitRequestCommitments/v2")
    for name in _COMMITMENTS | {"policy_hash", "request_digest"}:
        _digest(arguments[name])
    if arguments["operation_digest"] is not None:
        _digest(arguments["operation_digest"])
    intent = arguments["businessIntent"]
    _require(type(intent) is dict and set(intent) == {"schema", "operation", "planningAdapterId", "arguments"}
        and intent["schema"] == "serverware.policyAuthorityBusinessIntent/v2"
        and intent["operation"] == "jit.request" and type(intent["planningAdapterId"]) is str
        and 0 < len(intent["planningAdapterId"]) <= 128
        and canonical(intent["arguments"]) == canonical({key: value for key, value in arguments.items()
            if key != "businessIntent"}))
    authorization = {"schema": "serverware.policyAuthorityV9Authorization/v1",
        "operation": "jit.request", "handler": request["handler"],
        "operationManifestDigest": request["operationManifestDigest"], "arguments": arguments}
    digest = _framed("serverware.policyAuthorityV9Request/v1", canonical(authorization))
    _require(request["requestDigest"] == digest and request["operationId"] == _framed(
        "serverware.policyAuthorityOperation/v2", b"jit.request", digest.encode("ascii")))
    _integer(arguments["pending_ttl_seconds"], 1, 3600)
    for name in ("issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs"):
        _integer(scope[name], 1, 2**63 - 1)
    issued, seal, expires = (scope[name] for name in (
        "issuedAtEpochNs", "sealExpiresAtEpochNs", "documentExpiresAtEpochNs"))
    _require(issued < seal <= expires <= issued + arguments["pending_ttl_seconds"] * 1_000_000_000
        and seal - issued <= 30_000_000_000)
    return scope


def _private(scope, private):
    _require(type(private) is dict and set(private) == PRIVATE_FIELDS
        and type(private["url"]) is str and bool(private["url"])
        and type(private["canonical_request"]) is dict and type(private["redacted_display"]) is dict)
    private = {key: _copy(value, MAX_PLAINTEXT_BYTES, depth_limit=16) for key, value in private.items()}
    url = private["url"].encode("utf-8")
    documents = [canonical(private[key]) for key in ("canonical_request", "redacted_display")]
    # Necessary private subset of the original aggregate bound. The owner also
    # validates metadata + normalized policy in the real private-v2 validator.
    _require(len(url) + sum(map(len, documents)) <= MAX_PRIVATE_BYTES)
    arguments = scope["publicRequest"]["arguments"]
    _require(arguments["url_commitment"] == sha256(url)
        and arguments["canonical_request_digest"] == sha256(documents[0])
        and arguments["redacted_display_digest"] == sha256(documents[1]))
    original = {key: arguments[key] for key in _METADATA_FIELDS}
    original.update(private)
    _require(arguments["original_arguments_digest"] == sha256(canonical(original)))
    return private, (canonical({"schema": CANONICAL_SCHEMA, "url": private["url"],
        "canonical_request": private["canonical_request"]}), documents[1])


def _key(key_id, kek):
    _require(type(key_id) is str and re.fullmatch(r"attested-memory-kek:[0-9a-f]{24}", key_id) is not None
        and type(kek) is AESGCM)


def _time(scope, now, *, sealing):
    _integer(now, 1, 2**63 - 1)
    _require(scope["issuedAtEpochNs"] <= now < scope[
        "sealExpiresAtEpochNs" if sealing else "documentExpiresAtEpochNs"])


def _encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decoded(value, maximum, exact=None):
    _require(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3))
    raw = base64.b64decode(value, altchars=b"-_", validate=True)
    _require(_encoded(raw) == value and len(raw) <= maximum and (exact is None or len(raw) == exact))
    return raw


def _aad(scope, key_id, item, purpose):
    return canonical({"schema": "serverware.nativeJitReviewAad/v1", "purpose": purpose,
        "scope": scope, "keyId": key_id,
        "approvalRequestId": _identity(scope["publicRequest"]["requestDigest"], "jit-approval-request"),
        **{key: item[key] for key in ("opaqueId", "valueKind", "plaintextSha256", "plaintextBytes")}})


@_checked
def seal_pair(scope, private_documents, *, key_id, kek, now_epoch_ns):
    """Encrypt both actual originals with fresh keys/nonces, then read back both."""
    scope = validate_scope(scope)
    _key(key_id, kek)
    _time(scope, now_epoch_ns, sealing=True)
    private, plaintexts = _private(scope, private_documents)
    items = []
    for index, raw in enumerate(plaintexts):
        _require(0 < len(raw) <= MAX_PLAINTEXT_BYTES)
        item = {"opaqueId": _identity(scope["publicRequest"]["requestDigest"], _PURPOSES[index]),
            "valueKind": _KINDS[index], "plaintextSha256": sha256(raw), "plaintextBytes": len(raw)}
        dek, wrap_nonce, nonce = os.urandom(32), os.urandom(12), os.urandom(12)
        wrapped = kek.encrypt(wrap_nonce, dek, _aad(scope, key_id, item, "wrap-dek"))
        ciphertext = AESGCM(dek).encrypt(nonce, raw, _aad(scope, key_id, item, "encrypt-document"))
        item.update(wrappedKeyNonce=_encoded(wrap_nonce), wrappedKey=_encoded(wrapped),
            ciphertextNonce=_encoded(nonce), ciphertext=_encoded(ciphertext))
        items.append(item)
    pair = {"schema": PAIR_SCHEMA, "scope": scope, "keyId": key_id, "items": items}
    _require(canonical(open_pair(pair, expected_scope=scope, key_id=key_id,
        kek=kek, now_epoch_ns=now_epoch_ns)) == canonical(private))
    return pair


@_checked
def open_pair(pair, *, expected_scope, key_id, kek, now_epoch_ns):
    """Private readback only; no review session or release authority is implied."""
    scope = validate_scope(expected_scope)
    _key(key_id, kek)
    _time(scope, now_epoch_ns, sealing=False)
    pair = _copy(pair, MAX_PAIR_BYTES)
    _require(type(pair) is dict and set(pair) == PAIR_FIELDS and pair["schema"] == PAIR_SCHEMA
        and canonical(pair["scope"]) == canonical(scope) and pair["keyId"] == key_id
        and type(pair["items"]) is list and len(pair["items"]) == 2)
    decoded = []
    for index, item in enumerate(pair["items"]):
        _require(type(item) is dict and set(item) == ITEM_FIELDS
            and item["opaqueId"] == _identity(scope["publicRequest"]["requestDigest"], _PURPOSES[index])
            and item["valueKind"] == _KINDS[index])
        _digest(item["plaintextSha256"])
        _integer(item["plaintextBytes"], 1, MAX_PLAINTEXT_BYTES)
        decoded.append((_decoded(item["wrappedKeyNonce"], 12, 12), _decoded(item["wrappedKey"], 48, 48),
            _decoded(item["ciphertextNonce"], 12, 12),
            _decoded(item["ciphertext"], MAX_PLAINTEXT_BYTES + 16, item["plaintextBytes"] + 16)))
    plaintexts = []
    for item, (wrap_nonce, wrapped, nonce, ciphertext) in zip(pair["items"], decoded):
        dek = kek.decrypt(wrap_nonce, wrapped, _aad(scope, key_id, item, "wrap-dek"))
        _require(len(dek) == 32)
        raw = AESGCM(dek).decrypt(nonce, ciphertext, _aad(scope, key_id, item, "encrypt-document"))
        _require(len(raw) == item["plaintextBytes"] and sha256(raw) == item["plaintextSha256"])
        value = json.loads(raw)
        _require(canonical(value) == raw)
        plaintexts.append(value)
    first, display = plaintexts
    _require(type(first) is dict and set(first) == {"schema", "url", "canonical_request"}
        and first["schema"] == CANONICAL_SCHEMA)
    private, _ = _private(scope, {"url": first["url"], "canonical_request": first["canonical_request"],
        "redacted_display": display})
    return private
