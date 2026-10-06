"""Private static-credential envelope bytes for a native broker owner.

These primitives do not load keys, accept network requests, authenticate a
caller, or establish native provenance. The purpose-bound owner must provide
its actual provisioned KEK and authenticate intake before calling them. They
retain the existing static-secret 1 MiB UTF-8 limit without widening OAuth's
smaller limits. No plaintext commitment is emitted into public metadata.
"""
import base64
from datetime import datetime, timezone
import json
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_SECRET_BYTES = 1024 * 1024
ENVELOPE_FIELDS = frozenset({"encrypted_secret", "encrypted_dek", "secret_nonce",
    "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at"})


def require(value):
    if not value:
        raise ValueError("Static credential envelope or scope is invalid")


def secret_bytes(value):
    """Preserve the actual nonempty UTF-8 secret; never trim or normalize it."""
    require(type(value) is bytes and 0 < len(value) <= MAX_SECRET_BYTES)
    try:
        value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("Static credential must contain valid UTF-8") from None
    return value


def _scope(item_id, version, secret_kek_id, kek):
    require(type(item_id) is str and len(item_id) == 36 and str(uuid.UUID(item_id)) == item_id
        and type(version) is int and 1 <= version <= 2**63 - 1
        and type(secret_kek_id) is str and secret_kek_id.startswith("attested-memory-kek:")
        and len(secret_kek_id) == 44
        and all(char in "0123456789abcdef" for char in secret_kek_id[-24:])
        and type(kek) is AESGCM)


def _decode(value, *, maximum, exact=None):
    require(type(value) is str and 0 < len(value) <= 4 * ((maximum + 2) // 3))
    decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    require(base64.urlsafe_b64encode(decoded).decode("ascii") == value
        and len(decoded) <= maximum and (exact is None or len(decoded) == exact))
    return decoded


def _stamp(epoch_ns):
    require(type(epoch_ns) is int and 0 < epoch_ns <= 2**63 - 1)
    return datetime.fromtimestamp(epoch_ns // 1_000_000_000, timezone.utc).replace(
        microsecond=epoch_ns % 1_000_000_000 // 1000).isoformat()


def envelope_fields(envelope):
    """Validate bounded public ciphertext fields, never their provenance."""
    require(type(envelope) is dict and type(envelope.get("credential_version")) is int
        and envelope["credential_version"] == 1)
    return _envelope_fields(envelope)


def _envelope_fields(envelope):
    """Shared private codec; public purpose wrappers constrain the generation."""
    require(type(envelope) is dict and set(envelope) == ENVELOPE_FIELDS
        and envelope["encrypted_secret"] == "envelope:v2"
        and type(envelope["credential_version"]) is int
        and 1 <= envelope["credential_version"] <= 2**63 - 1)
    kek_id = envelope["secret_kek_id"]
    require(type(kek_id) is str and kek_id.startswith("attested-memory-kek:") and len(kek_id) == 44
        and all(char in "0123456789abcdef" for char in kek_id[-24:]))
    for field, maximum in (("encrypted_dek", 84), ("secret_nonce", 19),
            ("secret_ciphertext", 3 + 4 * ((MAX_SECRET_BYTES + 18) // 3)), ("secret_updated_at", 64)):
        require(type(envelope[field]) is str and 0 < len(envelope[field]) <= maximum)
    stamp = envelope["secret_updated_at"]
    require(0 < len(stamp) <= 64)
    parsed = datetime.fromisoformat(stamp)
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0
        and parsed.isoformat() == stamp)
    wrapped = envelope["encrypted_dek"].split(":")
    nonce = envelope["secret_nonce"].split(":")
    ciphertext = envelope["secret_ciphertext"].split(":")
    require(len(wrapped) == 3 and len(nonce) == len(ciphertext) == 2
        and wrapped[0] == nonce[0] == ciphertext[0] == "v1")
    # Decode every bounded component before invoking either decrypt operation.
    key_nonce = _decode(wrapped[1], maximum=12, exact=12)
    encrypted_key = _decode(wrapped[2], maximum=48, exact=48)
    secret_nonce = _decode(nonce[1], maximum=12, exact=12)
    secret_ciphertext = _decode(ciphertext[1], maximum=MAX_SECRET_BYTES + 16)
    require(len(secret_ciphertext) > 16)
    return key_nonce, encrypted_key, secret_nonce, secret_ciphertext


def open_original(item_id, envelope, version, secret_kek_id, kek):
    """Private readback only; this function is not a release authority."""
    require(type(version) is int and version == 1)
    return _open_original(item_id, envelope, version, secret_kek_id, kek)


def _open_original(item_id, envelope, version, secret_kek_id, kek):
    _scope(item_id, version, secret_kek_id, kek)
    key_nonce, encrypted_key, secret_nonce, secret_ciphertext = _envelope_fields(envelope)
    require(envelope["credential_version"] == version and envelope["secret_kek_id"] == secret_kek_id)
    dek = kek.decrypt(key_nonce, encrypted_key, f"serverware:dek:{item_id}:v{version}".encode("utf-8"))
    require(len(dek) == 32)
    return secret_bytes(AESGCM(dek).decrypt(secret_nonce, secret_ciphertext,
        f"serverware:secret:{item_id}:v{version}".encode("utf-8")))


def seal_original(item_id, raw, version, secret_kek_id, kek, epoch_ns):
    """Seal once with fresh entropy and verify the exact private readback."""
    require(type(version) is int and version == 1)
    return _seal_original(item_id, raw, version, secret_kek_id, kek, epoch_ns)


def _seal_original(item_id, raw, version, secret_kek_id, kek, epoch_ns):
    _scope(item_id, version, secret_kek_id, kek)
    secret_bytes(raw)
    stamp = _stamp(epoch_ns)
    dek, key_nonce, secret_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
    wrapped = kek.encrypt(key_nonce, dek, f"serverware:dek:{item_id}:v{version}".encode("utf-8"))
    ciphertext = AESGCM(dek).encrypt(secret_nonce, raw, f"serverware:secret:{item_id}:v{version}".encode("utf-8"))
    encoded = lambda value: base64.urlsafe_b64encode(value).decode("ascii")
    result = {"encrypted_secret": "envelope:v2", "encrypted_dek": "v1:" + encoded(key_nonce) + ":" + encoded(wrapped),
        "secret_nonce": "v1:" + encoded(secret_nonce), "secret_ciphertext": "v1:" + encoded(ciphertext),
        "secret_kek_id": secret_kek_id, "credential_version": version, "secret_updated_at": stamp}
    require(_open_original(item_id, result, version, secret_kek_id, kek) == raw)
    return result


def seal_generation_original(*, actor_id, configuration_digest, credential_policy,
        intent, raw, secret_kek_id, kek, epoch_ns):
    """Construct the literal candidate from actual sealing, not supplied ciphertext.

    This is still private material, NOT signed evidence or permission to insert
    it. The broker owner and independent native proof verifier remain required.
    Retained intent time does not extend any execution authorization deadline.
    """
    from serverware import authority_static_credential_create as profile

    original = profile.intent_original(actor_id=actor_id, configuration_digest=configuration_digest,
        credential_policy=credential_policy, request=intent)
    owned = json.loads(original)
    request = owned["request"]
    require(type(epoch_ns) is int and request["issuedAtEpochNs"] <= epoch_ns < request["expiresAtEpochNs"])
    envelope = seal_original(request["credentialId"], raw, request["credentialVersion"], secret_kek_id, kek, epoch_ns)
    result = {"apiVersion": profile.GENERATION_SCHEMA, "purpose": profile.OPERATION,
        "actorId": owned["actorId"], "controlPlaneConfigurationDigest": owned["controlPlaneConfigurationDigest"],
        "intentSha256": profile.sha256(original), "credentialId": request["credentialId"],
        "credentialVersion": request["credentialVersion"], "envelope": envelope}
    encoded = profile.canonical(result).decode("ascii")
    profile.generation(encoded)
    return encoded
