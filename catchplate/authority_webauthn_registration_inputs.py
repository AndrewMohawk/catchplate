"""Original registration-input retention, not verification or admission.

This closed record preserves the original evidence/client/attestation bytes,
ceremony authorization bytes, credential/transports, expected authorization,
historical UTC time and every actual trust-root DER input. It contains no
successful claims, key/configuration authority, selected rows or fresh clock.
The decoder reconstructs genuine core types only after owning the whole graph;
the eventual consumer must still run real registration/evidence verification.

All copies, codecs and core reconstruction use the supplied work. The shared
wire ceiling is not an extra allowance or a promise that all local maxima fit
one complete replay. No database, active registry, signer or clock is used.
"""
from __future__ import annotations

from catchplate import authority_webauthn_evidence_input_wire as wire
from catchplate import authority_webauthn_registration_production as production


attestation, evidence = production.attestation, production.evidence
SCHEMA = "catchplate.policyAuthorityWebAuthnRegistrationInputs/v1"
OPERATION = "webauthn.registration.evidence.admit"
_FIELDS = frozenset({"schema", "sourceRevision", "operation", "envelope", "clientData",
    "attestationObject", "credentialId", "transports", "scope", "verificationContext",
    "expectedAuthorization"})
_RAW_FIELDS = frozenset({"base64Url", "byteCount"})
_SCOPE_FIELDS = frozenset({"challengeId", "challenge", "userId", "label", "authorizationJson"})
_CONTEXT_FIELDS = frozenset({"rpId", "origin", "verifiedAtEpochUs", "trustRoots"})
_ROOT_FIELDS = frozenset({"certificateDer", "certificateSha256", "authenticatorClass", "aaguids",
    "bundleDigest", "bundleSequence", "bundleRollbackEpoch"})


class WebAuthnRegistrationInputsError(ValueError):
    pass


def _raw(value, minimum, maximum):
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise WebAuthnRegistrationInputsError("registration input is not bounded original bytes")
    return value


def _raw_shape(value, minimum, maximum):
    shape = evidence.plan.contract
    shape._object(value, _RAW_FIELDS, "registration original transport")
    shape._integer(value["byteCount"], maximum, minimum=minimum)
    count = value["byteCount"]
    shape._text(value["base64Url"], (4 * count + 2) // 3, minimum=(4 * count + 2) // 3)


def _sorted_aaguids(values, work):
    # _hold_context already requires an exact bounded frozenset of exact
    # strings. Pay the canonical-sized measurement/copy before normalizing
    # that set; root order and transport order are never sorted here.
    work.charge(input_bytes=2 * (2 + max(0, len(values) - 1)), json_nodes=2)
    for value in values:
        size, nodes = work.measure(value)
        work.charge(input_bytes=size, json_nodes=nodes)
    return sorted(values)


def _verified_time(epoch_us):
    instant = wire._from_epoch_us(epoch_us)
    # Preserve registration's positive I64 nanosecond range inside the
    # shared codec's wider representable positive I64 microsecond range.
    if production.registration._now(instant) != epoch_us * 1000:
        raise WebAuthnRegistrationInputsError("registration verification time did not round-trip")
    return instant


def _shape(document, work):
    shape = evidence.plan.contract
    shape._object(document, _FIELDS, "registration input record")
    shape._literal(document["schema"], SCHEMA)
    shape._literal(document["sourceRevision"], production.authority.SOURCE_REVISION)
    shape._literal(document["operation"], OPERATION)
    _raw_shape(document["envelope"], 2, evidence.MAX_EVIDENCE_BYTES)
    _raw_shape(document["clientData"], 1, attestation.MAX_CLIENT_DATA_JSON_BYTES)
    _raw_shape(document["attestationObject"], 1, attestation.MAX_ATTESTATION_OBJECT_BYTES)
    attestation._text(document["credentialId"], "retained credential ID", 2048, _work=work)
    shape._array(document["transports"], 16, "registration original transports")
    for value in document["transports"]:
        attestation._text(value, "retained transport", 2048, empty=True, _work=work)
    if type(document["expectedAuthorization"]) is not dict:
        raise WebAuthnRegistrationInputsError("registration authorization is not an exact object")
    scope, context = document["scope"], document["verificationContext"]
    shape._object(scope, _SCOPE_FIELDS, "registration original ceremony")
    for name in ("challengeId", "challenge", "userId", "label"):
        attestation._text(scope[name], name, 4096, empty=name == "label", _work=work)
    _raw_shape(scope["authorizationJson"], 1, attestation.MAX_AUTHORIZATION_BYTES)
    shape._object(context, _CONTEXT_FIELDS, "registration original verification context")
    attestation._text(context["rpId"], "retained RP ID", 4096, _work=work)
    attestation._text(context["origin"], "retained origin", 8192, _work=work)
    _verified_time(context["verifiedAtEpochUs"])
    shape._array(context["trustRoots"], attestation.MAX_TRUST_ROOTS, "registration original trust roots")
    total_der = 0
    for root in context["trustRoots"]:
        shape._object(root, _ROOT_FIELDS, "registration original trust root")
        _raw_shape(root["certificateDer"], 1, attestation.MAX_ATTESTATION_CERTIFICATE_BYTES)
        total_der += root["certificateDer"]["byteCount"]
        if total_der > attestation.MAX_TRUST_SNAPSHOT_BYTES:
            raise WebAuthnRegistrationInputsError("registration original DER inventory exceeds its source bound")
        shape._digest(root["certificateSha256"])
        if root["authenticatorClass"] is not None:
            attestation._text(root["authenticatorClass"], "retained trust root class", 128, _work=work)
        if root["bundleDigest"] is not None:
            shape._digest(root["bundleDigest"])
        for name in ("bundleSequence", "bundleRollbackEpoch"):
            if root[name] is not None:
                shape._integer(root[name])
        aaguids = root["aaguids"]
        shape._array(aaguids, 1024, "registration original AAGUID set")
        work.prepare_scan(aaguids)
        previous = None
        for value in aaguids:
            attestation._text(value, "retained root AAGUID", 128, _work=work)
            if previous is not None and previous >= value:
                raise WebAuthnRegistrationInputsError("retained root AAGUID set is not sorted and unique")
            previous = value


def _encode_on_work(*, envelope_bytes, client_data_json, attestation_object,
        credential_id, transports, scope, verification_context, expected_authorization, work):
    """Retain the exact eight original inputs; do not infer their authority."""
    evidence.capture._SharedLedger(work)
    raw = (_raw(envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
        _raw(client_data_json, 1, attestation.MAX_CLIENT_DATA_JSON_BYTES),
        _raw(attestation_object, 1, attestation.MAX_ATTESTATION_OBJECT_BYTES))
    if type(transports) is not tuple or len(transports) > 16:
        raise WebAuthnRegistrationInputsError("registration transports are not an exact bounded tuple")
    scope_fields, context_fields, roots = production._hold_context(scope, verification_context, work)
    authorization_raw = _raw(scope_fields[4], 1, attestation.MAX_AUTHORIZATION_BYTES)
    verified_at_us = wire._to_epoch_us(context_fields[2])
    _verified_time(verified_at_us)
    work.prepare_copy(transports)
    # Raw byte references and all held context fields are exact immutable
    # values. Own the remaining entire caller graph before any codec/native
    # reconstruction can run; no later lookup consults the caller's objects.
    owned = wire._capture({"credentialId": credential_id, "transports": list(transports),
        "expectedAuthorization": expected_authorization,
        "scope": {"challengeId": scope_fields[0], "challenge": scope_fields[1],
            "userId": scope_fields[2], "label": scope_fields[3]},
        "verificationContext": {"rpId": context_fields[0], "origin": context_fields[1],
            "verifiedAtEpochUs": verified_at_us,
            "trustRoots": [{"certificateSha256": root[1], "authenticatorClass": root[2],
                "aaguids": _sorted_aaguids(root[3], work), "bundleDigest": root[4],
                "bundleSequence": root[5], "bundleRollbackEpoch": root[6]} for root in roots]}}, work)
    owned["schema"], owned["sourceRevision"], owned["operation"] = SCHEMA, production.authority.SOURCE_REVISION, OPERATION
    for name, value, minimum, maximum in (("envelope", raw[0], 2, evidence.MAX_EVIDENCE_BYTES),
            ("clientData", raw[1], 1, attestation.MAX_CLIENT_DATA_JSON_BYTES),
            ("attestationObject", raw[2], 1, attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        owned[name] = wire._pack_raw(value, minimum=minimum, maximum=maximum, work=work)
    owned["scope"]["authorizationJson"] = wire._pack_raw(authorization_raw,
        minimum=1, maximum=attestation.MAX_AUTHORIZATION_BYTES, work=work)
    for root, fields in zip(owned["verificationContext"]["trustRoots"], roots):
        root["certificateDer"] = wire._pack_raw(fields[0],
            minimum=1, maximum=attestation.MAX_ATTESTATION_CERTIFICATE_BYTES, work=work)
    _shape(owned, work)
    return wire._encode_document(owned, work)


def _decode_on_work(raw, *, work):
    """Return ordinary original-input kwargs, with genuine core reconstruction.

    Reconstructing the source core types checks their byte/metadata and total
    DER-plus-descriptor bounds; it does not verify the retained attestation or
    evidence signature and cannot make these caller-supplied roots current.
    """
    document = wire._decode_document(raw, work)
    _shape(document, work)
    envelope = wire._unpack_raw(document["envelope"], minimum=2, maximum=evidence.MAX_EVIDENCE_BYTES, work=work)
    client = wire._unpack_raw(document["clientData"], minimum=1,
        maximum=attestation.MAX_CLIENT_DATA_JSON_BYTES, work=work)
    attestation_bytes = wire._unpack_raw(document["attestationObject"], minimum=1,
        maximum=attestation.MAX_ATTESTATION_OBJECT_BYTES, work=work)
    original_scope, context = document["scope"], document["verificationContext"]
    authorization = wire._unpack_raw(original_scope["authorizationJson"], minimum=1,
        maximum=attestation.MAX_AUTHORIZATION_BYTES, work=work)
    held_roots = []
    for root in context["trustRoots"]:
        der = wire._unpack_raw(root["certificateDer"], minimum=1,
            maximum=attestation.MAX_ATTESTATION_CERTIFICATE_BYTES, work=work)
        work.prepare_copy(root["aaguids"])
        held_roots.append((der, root["certificateSha256"], root["authenticatorClass"],
            frozenset(root["aaguids"]), root["bundleDigest"], root["bundleSequence"], root["bundleRollbackEpoch"]))
    work.prepare_copy(document["transports"])
    transports = tuple(document["transports"])
    instant = _verified_time(context["verifiedAtEpochUs"])
    # The entire canonical record and all original decoded bytes are now
    # detached. These are the real core constructors, on the original meter.
    scope = attestation.CeremonyScope(original_scope["challengeId"], original_scope["challenge"],
        original_scope["userId"], original_scope["label"], authorization, _work=work)
    roots = tuple(attestation.TrustRootSnapshot(*fields, _work=work) for fields in held_roots)
    verification_context = attestation.VerificationContext(context["rpId"], context["origin"], instant, roots, _work=work)
    return {"envelope_bytes": envelope, "client_data_json": client, "attestation_object": attestation_bytes,
        "credential_id": document["credentialId"], "transports": transports, "scope": scope,
        "verification_context": verification_context, "expected_authorization": document["expectedAuthorization"]}
