"""Derive an ordinary ceremony scope from originals and admitted enrollment data.

The caller supplies independently authenticated user/label, enrollment
authorization, challenge-row membership and configured RP/origin. This module
joins those inputs; it cannot establish their provenance. The actual original
client-data parser checks ceremony type, origin and challenge. The returned
scope and bytes are not successful attestation evidence or an admission token.

Full attestation parsing/cryptography, trust-root admission, challenge/session
freshness and credential-reuse checks remain with their genuine consumers.
There is no caller scope, parsed-result input, root, signer, clock, SQL or new
work allowance. All ownership and core operations use the supplied work.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_transition_webauthn_registration as registration
from serverware import webauthn_attestation_core as attestation


class WebAuthnRegistrationCeremonyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _RegistrationCeremony:
    client_data_json: bytes
    attestation_object: bytes
    credential_id: str
    transports: tuple[str, ...]
    scope: attestation.CeremonyScope


def _derive_on_work(*, client_data_json, attestation_object, credential_id,
        transports, challenge_row, user_id, label, expected_authorization,
        rp_id, origin, work):
    """Return owned originals and a genuinely derived scope, not verification.

    ``challenge_row`` is the exact raw source row with ``payload_json``, not
    an HTTP challenge DTO. Expected authorization must match the entire stored
    authorization canonically; neither a matching subset nor a supplied scope
    replaces independently admitted enrollment authority.
    """
    ledger = registration.capture._SharedLedger(work)
    for raw, maximum in ((client_data_json, attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (attestation_object, attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnRegistrationCeremonyError("ceremony originals are not bounded exact bytes")
    original_client, original_attestation = client_data_json, attestation_object
    if (type(transports) is not tuple or len(transports) > 16
            or any(type(value) is not str for value in transports)
            or any(type(value) is not str for value in (credential_id, user_id, label, rp_id, origin))
            or type(challenge_row) is not dict or type(expected_authorization) is not dict):
        raise WebAuthnRegistrationCeremonyError("ceremony inputs are not exact source data")
    work.prepare_copy(transports)
    owned = registration.capture._JSONCapture(ledger).visit({
        "challenge": challenge_row, "credentialId": credential_id,
        "transports": list(transports), "userId": user_id, "label": label,
        "rpId": rp_id, "origin": origin,
    })
    expected = registration.capture._JSONCapture(ledger,
        maximum_bytes=attestation.MAX_AUTHORIZATION_BYTES).visit(expected_authorization)
    # No caller graph or attribute is consulted after this ownership boundary.
    challenge = owned["challenge"]
    registration._closed(challenge, registration._CHALLENGE_FIELDS, "ceremony challenge row")
    for name, maximum, empty in (("credentialId", 2048, False), ("userId", 4096, False),
            ("label", 4096, True), ("rpId", 4096, False), ("origin", 8192, False)):
        attestation._text(owned[name], name, maximum, empty=empty, _work=work)
    for value in owned["transports"]:
        attestation._text(value, "transport", 2048, empty=True, _work=work)
    for name in ("id", "challenge"):
        attestation._text(challenge[name], "ceremony challenge " + name, 4096, _work=work)
    registration._same((challenge["challenge_type"], challenge["user_id"],
        challenge["approval_request_id"], challenge["used_at"]),
        ("registration", owned["userId"], None, None), work, "admitted ceremony challenge")

    # Preserve the source's stored-JSON interpretation: row text need not use
    # canonical whitespace. Only the derived authorization bytes are canonical.
    payload = registration._stored_json(challenge["payload_json"], work)
    if type(payload) is not dict:
        raise WebAuthnRegistrationCeremonyError("ceremony challenge payload is not an object")
    registration._same((payload.get("type"), payload.get("user_id"), payload.get("label")),
        ("registration", owned["userId"], owned["label"]), work, "admitted ceremony payload")
    authorization = registration.capture._JSONCapture(ledger,
        maximum_bytes=attestation.MAX_AUTHORIZATION_BYTES).visit(payload.get("authorization"))
    if (type(authorization) is not dict or type(authorization.get("mode")) is not str
            or authorization["mode"] not in registration._MODES):
        raise WebAuthnRegistrationCeremonyError("ceremony has no supported enrollment authorization")
    registration._digest(authorization.get("payload_digest"))
    expected_bytes = attestation._canonical(expected, _work=work)
    authorization_bytes = attestation._canonical(authorization, _work=work)
    attestation._bytes(expected_bytes, "expected enrollment authorization",
        attestation.MAX_AUTHORIZATION_BYTES, _work=work)
    attestation._bytes(authorization_bytes, "stored enrollment authorization",
        attestation.MAX_AUTHORIZATION_BYTES, _work=work)
    work.charge(input_bytes=len(expected_bytes) + len(authorization_bytes))
    if expected_bytes != authorization_bytes:
        raise WebAuthnRegistrationCeremonyError("ceremony enrollment authorization differs from admitted data")

    attestation._bytes(original_attestation, "attestation object",
        attestation.MAX_ATTESTATION_OBJECT_BYTES, _work=work)
    client = attestation.parse_client_data(original_client, "webauthn.create",
        origin=owned["origin"], _work=work)
    if type(client.get("challenge")) is not str:
        raise WebAuthnRegistrationCeremonyError("original ceremony client challenge is not exact text")
    registration._same(client["challenge"], challenge["challenge"], work,
        "original client challenge and admitted row")
    scope = attestation.CeremonyScope(challenge_id=challenge["id"],
        challenge=challenge["challenge"], user_id=owned["userId"], label=owned["label"],
        authorization_json=authorization_bytes, _work=work)
    work.prepare_copy(owned["transports"])
    return _RegistrationCeremony(original_client, original_attestation, owned["credentialId"],
        tuple(owned["transports"]), scope)
