"""Separate public-action display binding for registration reservation.

The actual handler must authenticate its present actor/session and permission
for this new reserve purpose. This ordinary bounded projection is only input
to the existing canonical payload hash and approval display; it is not caller
authorization, a reservation, a current-state witness or permission for SQL.
Neither the old prepare intent nor the old enrollment authorization supplies
reserve consent. Raw originals and bootstrap tokens are never returned.
"""
from __future__ import annotations

import hashlib

from serverware import control_plane_registration_execution_intent as preparing


PURPOSE = "reserve-registration-evidence-execution"
ACTION = "webauthn.registration.execution.reserve"
SCHEMA = "serverware.webAuthnRegistrationReservationIntent/v1"
_ORIGINAL_DOMAIN = b"serverware.webAuthnRegistrationReservationIntentOriginal/v1\x00"


class RegistrationReservationIntentError(ValueError):
    pass


def _original_digest(field, original):
    # Fixed field labels and a separate domain prevent prepare intent digests
    # from being substituted for this distinct public reserve action.
    digest = hashlib.sha256()
    digest.update(_ORIGINAL_DOMAIN)
    digest.update(len(field).to_bytes(2, "big"))
    digest.update(field)
    digest.update(len(original).to_bytes(8, "big"))
    digest.update(original)
    return "sha256:" + digest.hexdigest()


def request_binding(originals):
    """Bind genuine originals and full ceremony scope, not action authority.

    Apply the existing prepare projection's exact types and source bounds;
    preserve transport ordering and duplicates. Hold every original/scalar
    before hashing so no carrier attribute is reread after a native callback.
    No caller-selected root, digest, time or alternate original is accepted.
    """
    from serverware import webauthn

    if type(originals) is not webauthn._RegistrationOriginals:
        raise RegistrationReservationIntentError("reservation intent requires actual original inputs")
    client = originals.client_data_json
    credential_attestation = originals.attestation_object
    credential_id, transports = originals.credential_id, originals.transports
    scope, rp_id, origin = originals.scope, originals.rp_id, originals.origin
    if type(scope) is not preparing.attestation.CeremonyScope:
        raise RegistrationReservationIntentError("reservation intent requires the actual ceremony scope")
    user_id, challenge_id, challenge, label, authorization = (
        scope.user_id, scope.challenge_id, scope.challenge, scope.label,
        scope.authorization_json)

    try:
        preparing._bytes(client, preparing.attestation.MAX_CLIENT_DATA_JSON_BYTES)
        preparing._bytes(credential_attestation, preparing.attestation.MAX_ATTESTATION_OBJECT_BYTES)
        preparing._bytes(authorization, preparing.attestation.MAX_AUTHORIZATION_BYTES)
        for value, maximum, empty in (
            (user_id, 4096, False), (challenge_id, 4096, False),
            (challenge, 4096, False), (label, 4096, True),
            (rp_id, 4096, False), (origin, 8192, False),
            (credential_id, 2048, False),
        ):
            preparing._text(value, maximum, empty=empty)
        if type(transports) is not tuple or len(transports) > preparing._MAX_TRANSPORTS:
            raise RegistrationReservationIntentError("reservation intent transports are invalid or oversized")
        for transport in transports:
            preparing._text(transport, 2048, empty=True)
    except preparing.RegistrationExecutionIntentError as exc:
        raise RegistrationReservationIntentError("reservation intent inputs exceed their exact source bounds") from exc

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
