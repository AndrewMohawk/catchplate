"""Explicit-key X application-secret encryption, with no storage or selection.

This is not configured/activated OAuth, key ownership proof, or native custody.
The caller must independently admit the real development owner, select an
existing app-only key, and eventually join persistence to its durable lifecycle.
No tables, key files, settings, fallback readers, or network actions exist here.
Google's closed binding, AAD and retained store are intentionally unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware.operator_provider_custody import DevelopmentOwner
from serverware import operator_x_oauth_profile as profile

SCHEMA = "serverware.operatorXProviderCustody/v1"
AAD_SCHEMA = "serverware.operatorXProviderCustodyAAD/v1"
MAX_VERSIONS = 16
MAX_SECRET_BYTES = profile.MAX_SECRET_BYTES
MAX_PROFILE_BYTES = profile.MAX_PROFILE_BYTES
_ERROR = "operator X provider custody refused"


class CustodyError(RuntimeError):
    """Fixed failure, with no secret or caller-controlled diagnostics."""


def _require(condition):
    if not condition:
        raise CustodyError(_ERROR)


def _owner(owner):
    try:
        _require(type(owner) is DevelopmentOwner and type(owner.owner_id) is str
            and str(uuid.UUID(owner.owner_id)) == owner.owner_id
            and type(owner.uid) is int and owner.uid == os.geteuid()
            and type(owner.pid) is int and owner.pid == os.getpid())
    except (ValueError, AttributeError, TypeError):
        raise CustodyError(_ERROR) from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class XBinding:
    owner_id: str
    config_version: int
    profile_json: str


def bind_x(owner: DevelopmentOwner, *, config_version: int, public_profile: dict) -> XBinding:
    _owner(owner)
    _require(type(config_version) is int and 1 <= config_version <= MAX_VERSIONS)
    try:
        value = profile.public_record(profile.parse_profile(public_profile))
        raw = _canonical(value)
        _require(len(raw.encode("ascii")) <= MAX_PROFILE_BYTES)
        return XBinding(owner.owner_id, config_version, raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CustodyError(_ERROR) from None


def _binding(owner, binding):
    _owner(owner)
    try:
        _require(type(binding) is XBinding and binding.owner_id == owner.owner_id
            and type(binding.profile_json) is str and len(binding.profile_json) <= MAX_PROFILE_BYTES)
        expected = bind_x(owner, config_version=binding.config_version,
            public_profile=json.loads(binding.profile_json))
        _require(binding == expected)
    except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError):
        raise CustodyError(_ERROR) from None


def _aad(binding):
    return _canonical({"schema": AAD_SCHEMA, "owner_id": binding.owner_id,
        "config_version": binding.config_version,
        "public_profile": json.loads(binding.profile_json)}).encode("ascii")


def _key(key):
    _require(type(key) is bytes and len(key) == 32)


@dataclass(frozen=True)
class XPrivateEnvelope:
    binding: XBinding
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)


@dataclass(frozen=True)
class XSecretMaterial:
    binding: XBinding
    secret: str = field(repr=False)

    def public_view(self) -> dict:
        return {"schema": SCHEMA, "owner_id": self.binding.owner_id,
            "config_version": self.binding.config_version,
            "public_profile": json.loads(self.binding.profile_json), "secret_present": True}


def seal_x(owner: DevelopmentOwner, binding: XBinding, *, key: bytes, secret: str) -> XPrivateEnvelope:
    _binding(owner, binding)
    _key(key)
    try:
        plaintext = profile.validate_client_secret(secret).encode("utf-8")
        nonce = os.urandom(12)
        return XPrivateEnvelope(binding, nonce, AESGCM(key).encrypt(nonce, plaintext, _aad(binding)))
    except (ValueError, TypeError, UnicodeError, OSError):
        raise CustodyError(_ERROR) from None


def open_x(owner: DevelopmentOwner, envelope: XPrivateEnvelope, *, key: bytes) -> XSecretMaterial:
    _require(type(envelope) is XPrivateEnvelope)
    _binding(owner, envelope.binding)
    _key(key)
    _require(type(envelope.nonce) is bytes and len(envelope.nonce) == 12
        and type(envelope.ciphertext) is bytes and 17 <= len(envelope.ciphertext) <= MAX_SECRET_BYTES + 16)
    try:
        raw = AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, _aad(envelope.binding))
        secret = profile.validate_client_secret(raw.decode("utf-8"))
        return XSecretMaterial(envelope.binding, secret)
    except (InvalidTag, ValueError, TypeError, UnicodeError):
        raise CustodyError(_ERROR) from None
