"""Private N+1 static envelopes for the retained native rotation owner.

These material primitives neither authenticate a predecessor nor authorize an
update. Only the purpose-bound native owner supplies its actual provisioned
KEK. The independent authority must authenticate the committed predecessor,
consume its currentness drain barrier, and atomically install the successor.
Create-v1 APIs remain version-one-only. There is no plaintext commitment,
key loading, historical secret opening, or release permission in this module.
"""
import json

from catchplate import native_static_credential as _material

MAX_SECRET_BYTES = _material.MAX_SECRET_BYTES
ENVELOPE_FIELDS = _material.ENVELOPE_FIELDS


def _version(value):
    _material.require(type(value) is int and 2 <= value <= 2**63 - 1)


def envelope_fields(envelope):
    """Validate only the bounded public successor ciphertext format."""
    _material.require(type(envelope) is dict)
    _version(envelope.get("credential_version"))
    return _material._envelope_fields(envelope)


def open_original(item_id, envelope, version, secret_kek_id, kek):
    """Private successor readback, never a secret-release authorization."""
    _version(version)
    return _material._open_original(item_id, envelope, version, secret_kek_id, kek)


def seal_original(item_id, raw, version, secret_kek_id, kek, epoch_ns):
    """Seal an exact successor with fresh entropy and version-bound AAD."""
    _version(version)
    return _material._seal_original(item_id, raw, version, secret_kek_id, kek, epoch_ns)


def seal_generation_original(*, actor_id, configuration_digest, credential_policy,
        intent, raw, secret_kek_id, kek, epoch_ns):
    """Seal actual native intake into the distinct rotation generation wire.

    The immutable intent carries its exact predecessor identity and historical
    provenance. Parsing those fields is not independent provenance admission.
    Fresh execution and drain-barrier authority are required after approval.
    """
    from catchplate import authority_static_credential_rotate as profile

    original = profile.intent_original(actor_id=actor_id, configuration_digest=configuration_digest,
        credential_policy=credential_policy, request=intent)
    owned = json.loads(original)
    request = owned["request"]
    _material.require(type(epoch_ns) is int
        and request["issuedAtEpochNs"] <= epoch_ns < request["expiresAtEpochNs"])
    envelope = seal_original(request["credentialId"], raw, request["credentialVersion"],
        secret_kek_id, kek, epoch_ns)
    result = {"apiVersion": profile.GENERATION_SCHEMA, "purpose": profile.OPERATION,
        "actorId": owned["actorId"], "controlPlaneConfigurationDigest": owned["controlPlaneConfigurationDigest"],
        "intentSha256": profile.sha256(original), "credentialId": request["credentialId"],
        "credentialVersion": request["credentialVersion"], "envelope": envelope}
    encoded = profile.canonical(result).decode("ascii")
    profile.generation(encoded)
    return encoded
