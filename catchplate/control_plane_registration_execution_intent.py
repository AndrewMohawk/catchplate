"""Public-action display binding for actual retained registration originals.

The authenticated handler must separately admit its current actor/session and
this execution purpose. This bounded ordinary request is for the existing
canonical payload hash and approval display, not a permission or replay token.
It neither interprets the old enrollment authorization nor turns that recipe
into consent to execute. No separate raw-byte, clock, expected-digest or root
override is accepted. Raw originals and bootstrap tokens are never returned.
"""
from __future__ import annotations

import hashlib

from catchplate import webauthn_attestation_core as attestation


PURPOSE = "authorize-registration-evidence-execution"
ACTION = "webauthn.registration.execution.prepare"
SCHEMA = "catchplate.webAuthnRegistrationExecutionIntent/v1"
_ORIGINAL_DOMAIN = b"catchplate.webAuthnRegistrationExecutionIntentOriginal/v1\x00"
_MAX_TRANSPORTS = 16


class RegistrationExecutionIntentError(ValueError):
    pass


def _text(value, maximum, *, empty=False):
    # Exact strings exclude caller-controlled encoding methods. Check the
    # character ceiling before allocating their bounded UTF-8 representation.
    if (type(value) is not str or len(value) > maximum
            or (not empty and not value)):
        raise RegistrationExecutionIntentError("registration intent text is invalid or oversized")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise RegistrationExecutionIntentError("registration intent text is not valid UTF-8") from None
    if size > maximum:
        raise RegistrationExecutionIntentError("registration intent text is invalid or oversized")


def _bytes(value, maximum):
    if type(value) is not bytes or not 1 <= len(value) <= maximum:
        raise RegistrationExecutionIntentError("registration intent original is invalid or oversized")


def _original_digest(field, original):
    # These labels are source-fixed ASCII bytes, not caller-provided domains.
    # The length framing commits to both field identity and exact original
    # bytes. This is deliberately not a bare file hash or authority signature.
    digest = hashlib.sha256()
    digest.update(_ORIGINAL_DOMAIN)
    digest.update(len(field).to_bytes(2, "big"))
    digest.update(field)
    digest.update(len(original).to_bytes(8, "big"))
    digest.update(original)
    return "sha256:" + digest.hexdigest()


def request_binding(originals):
    """Return a deterministic ordinary request after the handler's real auth.

    The exact source types and per-field bounds apply; transport order and
    duplicates are retained. Every original, scope scalar and tuple member is
    held before the first hashlib call. The returned graph contains only fixed
    fields, bounded exact strings/integers and one owned transport list.
    """
    from catchplate import webauthn

    if type(originals) is not webauthn._RegistrationOriginals:
        raise RegistrationExecutionIntentError("registration intent requires actual original inputs")
    client = originals.client_data_json
    credential_attestation = originals.attestation_object
    credential_id, transports = originals.credential_id, originals.transports
    scope, rp_id, origin = originals.scope, originals.rp_id, originals.origin
    if type(scope) is not attestation.CeremonyScope:
        raise RegistrationExecutionIntentError("registration intent requires the actual ceremony scope")
    user_id, challenge_id, challenge, label, authorization = (
        scope.user_id, scope.challenge_id, scope.challenge, scope.label,
        scope.authorization_json)

    _bytes(client, attestation.MAX_CLIENT_DATA_JSON_BYTES)
    _bytes(credential_attestation, attestation.MAX_ATTESTATION_OBJECT_BYTES)
    _bytes(authorization, attestation.MAX_AUTHORIZATION_BYTES)
    for value, maximum, empty in (
        (user_id, 4096, False), (challenge_id, 4096, False),
        (challenge, 4096, False), (label, 4096, True),
        (rp_id, 4096, False), (origin, 8192, False),
        (credential_id, 2048, False),
    ):
        _text(value, maximum, empty=empty)
    if type(transports) is not tuple or len(transports) > _MAX_TRANSPORTS:
        raise RegistrationExecutionIntentError("registration intent transports are invalid or oversized")
    for transport in transports:
        _text(transport, 2048, empty=True)

    # No carrier or scope attribute is reread after this owned graph exists.
    # The authorization original is hashed opaquely, never parsed or exposed.
    request = {"schema": SCHEMA, "purpose": PURPOSE, "action": ACTION,
        "userId": user_id, "challengeId": challenge_id, "challenge": challenge,
        "label": label, "rpId": rp_id, "origin": origin,
        "credentialId": credential_id, "transports": list(transports),
        "clientDataJsonByteCount": len(client),
        "attestationObjectByteCount": len(credential_attestation),
        "authorizationJsonByteCount": len(authorization)}
    request["clientDataJsonBytesDigest"] = _original_digest(b"clientDataJson", client)
    request["attestationObjectBytesDigest"] = _original_digest(
        b"attestationObject", credential_attestation)
    request["authorizationJsonBytesDigest"] = _original_digest(b"authorizationJson", authorization)
    return request
