"""Closed encrypted internal-service tokens, not a general decryption format.

The provisioner owns original tokens and KEK. Only the measured broker opens
this envelope; the image/configuration carries ciphertext and public scope.
Local format checks are not release admission or independent rollback proof.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE = "catchplate.nativeServiceTokensEnvelope/v1"
BINDING = "catchplate.nativeServiceTokensBinding/v1"
PLAINTEXT = "catchplate.nativeServiceTokens/v1"
DOMAIN = b"catchplate/native-service-tokens-envelope/v1\0"
PADDED_BYTES = 32768
MAX_PLAINTEXT = 24576
SLOTS = ("credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken",
         "releaseAuthorizationToken", "managementToken")
ENDPOINTS = {
    "credentialLeaseUrl": "/api/data-plane/credential-leases",
    "grantConsumeUrl": "/api/data-plane/grants/consume",
    "rateLimitConsumeUrl": "/api/data-plane/rate-limits/consume",
    "releaseAuthorizationBaseUrl": "/api/data-plane/release-authorizations",
}
TOKEN_ENDPOINTS = {
    "credentialLeaseToken": "credentialLeaseUrl",
    "grantConsumeToken": "grantConsumeUrl",
    "rateLimitConsumeToken": "rateLimitConsumeUrl",
    "releaseAuthorizationToken": "releaseAuthorizationBaseUrl",
}


def require(value):
    if not value:
        raise ValueError("native service-token material unavailable")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def document(raw, maximum):
    require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_float=lambda _: require(False),
                       parse_constant=lambda _: require(False))
    require(type(value) is dict and canonical(value) == raw)
    return value


def digest(value):
    require(type(value) is str and len(value) == 71 and value.startswith("sha256:")
            and all(item in "0123456789abcdef" for item in value[7:])
            and value[7:] != "0" * 64)
    return value


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decoded(value, size):
    require(type(value) is str and len(value) == (size * 4 + 2) // 3)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(len(raw) == size and encoded(raw) == value)
    return raw


def binding(value):
    require(type(value) is dict and set(value) == {"apiVersion", "instanceId",
        "dataPlaneBinaryDigest", "policyHash", "atomicReleaseAuthorizationEnabled", *ENDPOINTS}
        and value["apiVersion"] == BINDING)
    instance = value["instanceId"]
    require(type(instance) is str and 1 <= len(instance) <= 4096 and instance.isascii()
            and all(32 < ord(item) < 127 for item in instance))
    uri = urlsplit(instance)
    require(uri.scheme == "spiffe" and uri.hostname and not uri.username and not uri.password
            and uri.port is None and uri.path.startswith("/") and not uri.query and not uri.fragment)
    digest(value["dataPlaneBinaryDigest"])
    digest(value["policyHash"])
    require(type(value["atomicReleaseAuthorizationEnabled"]) is bool)
    for name, path in ENDPOINTS.items():
        endpoint = value[name]
        if endpoint is None:
            continue
        require(type(endpoint) is str and 1 <= len(endpoint) <= 4096 and endpoint.isascii()
                and all(32 < ord(item) < 127 for item in endpoint))
        uri = urlsplit(endpoint)
        require(uri.scheme == "https" and uri.hostname and not uri.username and not uri.password
                and uri.path == path and not uri.query and not uri.fragment
                and (uri.port is None or 1 <= uri.port <= 65535))
    require(value["credentialLeaseUrl"] is not None)
    if value["atomicReleaseAuthorizationEnabled"]:
        require(value["releaseAuthorizationBaseUrl"] is not None)
    else:
        require(value["grantConsumeUrl"] is not None and value["rateLimitConsumeUrl"] is not None)
    require(len(canonical(value)) <= 24576)
    return value


def tokens(value, scope):
    binding(scope)
    require(type(value) is dict and set(value) == set(SLOTS))
    seen = set()
    for name in SLOTS:
        required = name == "managementToken" or scope[TOKEN_ENDPOINTS[name]] is not None
        token = value[name]
        if not required:
            require(token is None)
            continue
        require(type(token) is str and 32 <= len(token) <= 4096 and token.isascii()
                and all(32 < ord(item) < 127 for item in token) and len(set(token)) >= 8
                and token not in seen)
        seen.add(token)
    return value


def header(value, expected_binding, secret_kek_id):
    require(type(value) is dict and set(value) == {
        "apiVersion", "binding", "secretKekId", "nonce", "ciphertext"}
        and value["apiVersion"] == ENVELOPE and value["secretKekId"] == secret_kek_id
        and binding(value["binding"]) == binding(expected_binding))
    require(type(secret_kek_id) is str and secret_kek_id.startswith("attested-memory-kek:")
            and len(secret_kek_id) == len("attested-memory-kek:") + 24
            and all(item in "0123456789abcdef" for item in secret_kek_id[-24:]))
    return {name: value[name] for name in ("apiVersion", "binding", "secretKekId")}


def seal(value, scope, kek, expected_kek_sha256):
    require(type(kek) is bytes and len(kek) == 32 and hmac.compare_digest(
        "sha256:" + hashlib.sha256(kek).hexdigest(), digest(expected_kek_sha256)))
    scope = binding(scope)
    raw = canonical({"apiVersion": PLAINTEXT, "tokens": tokens(value, scope)})
    require(len(raw) <= MAX_PLAINTEXT)
    result = {"apiVersion": ENVELOPE, "binding": scope,
              "secretKekId": "attested-memory-kek:" + expected_kek_sha256[7:31]}
    nonce = os.urandom(12)
    padded = len(raw).to_bytes(4, "big") + raw + bytes(PADDED_BYTES - 4 - len(raw))
    ciphertext = AESGCM(kek).encrypt(nonce, padded, DOMAIN + canonical(result))
    return {**result, "nonce": encoded(nonce), "ciphertext": encoded(ciphertext)}


def open_for_broker(value, expected_binding, secret_kek_id, kek_aead):
    aad = DOMAIN + canonical(header(value, expected_binding, secret_kek_id))
    padded = kek_aead.decrypt(decoded(value["nonce"], 12),
                              decoded(value["ciphertext"], PADDED_BYTES + 16), aad)
    require(len(padded) == PADDED_BYTES)
    length = int.from_bytes(padded[:4], "big")
    require(1 <= length <= MAX_PLAINTEXT and not any(padded[4 + length:]))
    raw = padded[4:4 + length]
    result = document(raw, MAX_PLAINTEXT)
    require(set(result) == {"apiVersion", "tokens"} and result["apiVersion"] == PLAINTEXT)
    tokens(result["tokens"], expected_binding)
    return raw
