"""Purpose-specific root authorization of the cold ciphertext lease profile.

The public verifier receives its key only from the actual custody runtime
admission. Neither a request nor this document supplies its own trust root.
"""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


SCHEMA = "catchplate.controlPlaneCustodyStartup/v2"
PROFILE = "enclave-ciphertext-rows-v1"
DOMAIN = b"catchplate/control-plane-broker-startup/v1\0"
BASE_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "directoryFd",
    "device", "inode", "uid", "gid", "quotaBytes", "maximumRecords"})
FIELDS = BASE_FIELDS | {"credentialBrokerProfile", "signature"}
MAX_BYTES = 16384


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
        allow_nan=False, separators=(",", ":")).encode("ascii")


def _require(value):
    if not value:
        raise ValueError("control-plane broker startup authorization is invalid")


def _unsigned(document):
    _require(type(document) is dict and set(document) == FIELDS
        and document["schema"] == SCHEMA and document["credentialBrokerProfile"] == PROFILE)
    unsigned = {name: value for name, value in document.items() if name != "signature"}
    revision, digest = unsigned["sourceRevision"], unsigned["configurationDigest"]
    _require(type(revision) is str and 1 <= len(revision) <= 256 and revision.isascii()
        and revision[0].isalnum()
        and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-" for char in revision))
    _require(type(digest) is str and len(digest) == 71 and digest.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in digest[7:]))
    for name, minimum, maximum in (
        ("directoryFd", 32, 1023), ("device", 0, 2**64 - 1), ("inode", 1, 2**64 - 1),
        ("uid", 0, 2**32 - 2), ("gid", 0, 2**32 - 2),
        ("quotaBytes", 1, 8 * 1024**3), ("maximumRecords", 1, 4096),
    ):
        _require(type(unsigned[name]) is int and minimum <= unsigned[name] <= maximum)
    _require(len(canonical(document)) <= MAX_BYTES)
    return unsigned


def verify(document, *, runtime_root_public_key, configuration_digest, source_revision):
    unsigned = _unsigned(document)
    _require(isinstance(runtime_root_public_key, Ed25519PublicKey)
        and unsigned["configurationDigest"] == configuration_digest
        and unsigned["sourceRevision"] == source_revision)
    signature = document["signature"]
    _require(type(signature) is str and signature.startswith("ed25519:") and len(signature) == 94)
    raw = base64.b64decode((signature[8:] + "==").encode("ascii"), altchars=b"-_", validate=True)
    _require(len(raw) == 64 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == signature[8:])
    runtime_root_public_key.verify(raw, DOMAIN + canonical(unsigned))
    return PROFILE


def sign_configuration(configuration, *, runtime_root_private_key):
    """Offline producer; never called by HTTP, cold startup or the enclave."""
    _require(type(configuration) is dict and set(configuration) == BASE_FIELDS
        and configuration["schema"] == "catchplate.controlPlaneCustodyStartup/v1"
        and isinstance(runtime_root_private_key, Ed25519PrivateKey))
    document = {**configuration, "schema": SCHEMA, "credentialBrokerProfile": PROFILE,
        "signature": "ed25519:" + "A" * 86}
    unsigned = _unsigned(document)
    signature = runtime_root_private_key.sign(DOMAIN + canonical(unsigned))
    document["signature"] = "ed25519:" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    verify(document, runtime_root_public_key=runtime_root_private_key.public_key(),
        configuration_digest=configuration["configurationDigest"], source_revision=configuration["sourceRevision"])
    return document
