"""Dedicated live control-plane authorization for exact registration originals.

The issuer must independently admit the actor/enrollment context and configured
key, audience, generation and policy. This primitive binds that context to the
original browser bytes and evaluation instant without an evidence/source digest
back-edge. It authenticates a bounded live grant, not a completed attestation or
registration, row/root admission, or proof of the issuer's upstream decisions.

This module does NOT implement one-use enforcement. The real owning signer must
durably consume the actual verified authorization_digest through its fixed
replay ledger before signing. Neither a returned container nor possession of
the original grant permits resetting, retrying or bypassing that composition.
All ownership, randomness, canonical framing, signatures and original dual-clock
freshness use the supplied work. No SQL, filesystem, transport or new allowance
is introduced here.
"""
from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass

from catchplate import authority_transition_webauthn_registration as registration
from catchplate import authority_webauthn_evidence_custody_wire as wire
from catchplate import webauthn_attestation_core as attestation


evidence, authority, retention, clock = wire.evidence, wire.authority, wire.retention, wire.clock
plan = retention.plan
OPERATION = "webauthn.registration.evidence.admit"
SCHEMA = "catchplate.signedPolicyAuthorityWebAuthnEnrollmentAuthorization/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityWebAuthnEnrollmentAuthorizationIdentity/v1"
PURPOSE = "authorize-webauthn-registration"
MAX_BYTES = attestation.MAX_AUTHORIZATION_BYTES
MAX_NODES = evidence.MAX_EVIDENCE_NODES
MAX_DEPTH = evidence.MAX_EVIDENCE_DEPTH
_ISSUER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "operation",
    "configurationDigest", "generationSequence", "generationDigest", "issuerId",
    "audienceSpkiDigest", "authorizationId", "context", "issuedAtEpochNs",
    "expiresAtEpochNs", "signatureBase64Url"})
_CONTEXT_FIELDS = frozenset({"userId", "label", "registrationChallengeId", "oidcSessionId",
    "rpId", "origin", "expectedAuthorization", "clientDataJsonBytesDigest",
    "clientDataJsonByteCount", "attestationObjectBytesDigest", "attestationObjectByteCount",
    "credentialId", "transports", "verifiedAtEpochNs"})
_TEXT_FIELDS = (("userId", 4096, False), ("label", 4096, True),
    ("registrationChallengeId", 4096, False), ("rpId", 4096, False),
    ("origin", 8192, False), ("credentialId", 2048, False))


class WebAuthnEnrollmentAuthorizationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _VerifiedAuthorization:
    """Ordinary owned same-call data; one-use enforcement remains mandatory."""

    context: dict
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    authorization_digest: str


class _Capture(evidence.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise WebAuthnEnrollmentAuthorizationError("enrollment grant exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise WebAuthnEnrollmentAuthorizationError("enrollment grant exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(evidence.capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _originals(client_data_json, attestation_object, transports):
    for raw, maximum in ((client_data_json, attestation.MAX_CLIENT_DATA_JSON_BYTES),
            (attestation_object, attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
            raise WebAuthnEnrollmentAuthorizationError("enrollment requires bounded exact browser originals")
    if type(transports) is not tuple or len(transports) > 16:
        raise WebAuthnEnrollmentAuthorizationError("enrollment transports are not a bounded exact tuple")
    return client_data_json, attestation_object, transports


def _context_shape(value):
    shape = evidence.plan.contract
    shape._object(value, _CONTEXT_FIELDS, "enrollment authorization context")
    for name, maximum, empty in _TEXT_FIELDS:
        shape._text(value[name], maximum, minimum=0 if empty else 1)
    if value["oidcSessionId"] is not None:
        shape._text(value["oidcSessionId"], 4096)
    shape._array(value["transports"], 16, "enrollment transports")
    for transport in value["transports"]:
        shape._text(transport, 2048, minimum=0)
    for prefix, maximum in (("clientDataJson", attestation.MAX_CLIENT_DATA_JSON_BYTES),
            ("attestationObject", attestation.MAX_ATTESTATION_OBJECT_BYTES)):
        shape._digest(value[prefix + "BytesDigest"])
        shape._integer(value[prefix + "ByteCount"], maximum, minimum=1)
    shape._integer(value["verifiedAtEpochNs"], minimum=1)
    authorization = value["expectedAuthorization"]
    if (type(authorization) is not dict or type(authorization.get("mode")) is not str
            or authorization["mode"] not in registration._MODES):
        raise WebAuthnEnrollmentAuthorizationError("enrollment authorization mode is not source fixed")
    shape._digest(authorization.get("payload_digest"))
    if authorization["mode"] == "oidc-session-first-enrollment":
        if (value["oidcSessionId"] is None
                or type(authorization.get("session_id")) is not str
                or type(authorization.get("user_id")) is not str
                or authorization["session_id"] != value["oidcSessionId"]
                or authorization["user_id"] != value["userId"]):
            raise WebAuthnEnrollmentAuthorizationError("enrollment OIDC authorization differs from its user/session")
    elif value["oidcSessionId"] is not None:
        raise WebAuthnEnrollmentAuthorizationError("non-OIDC enrollment cannot acquire a session selector")


def _context_on_owned_work(value, work):
    _context_shape(value)
    for name, maximum, empty in _TEXT_FIELDS:
        attestation._text(value[name], name, maximum, empty=empty, _work=work)
    if value["oidcSessionId"] is not None:
        attestation._text(value["oidcSessionId"], "OIDC session", 4096, _work=work)
    for transport in value["transports"]:
        attestation._text(transport, "transport", 2048, empty=True, _work=work)
    # Encoding the entire admitted authorization preserves exact nested fields,
    # without re-consuming options-time MFA/approval or inferring permission.
    authorization = attestation._canonical(value["expectedAuthorization"], _work=work)
    attestation._bytes(authorization, "expected enrollment authorization", MAX_BYTES, _work=work)


def _context_on_work(*, client_data_json, attestation_object, credential_id, transports,
        user_id, label, expected_authorization, registration_challenge_id, oidc_session_id,
        rp_id, origin, verified_at_epoch_ns, work):
    """Bind original bytes to independently admitted enrollment data, not proof."""
    evidence.capture._SharedLedger(work)
    client, attestation_original, held_transports = _originals(client_data_json, attestation_object, transports)
    work.prepare_copy(held_transports)
    # Every caller graph is detached before either actual original-byte hash
    # is computed; no caller-provided body digest is accepted.
    owned = _capture({"userId": user_id, "label": label,
        "registrationChallengeId": registration_challenge_id, "oidcSessionId": oidc_session_id,
        "rpId": rp_id, "origin": origin, "expectedAuthorization": expected_authorization,
        "credentialId": credential_id, "transports": list(held_transports),
        "verifiedAtEpochNs": verified_at_epoch_ns}, work)
    owned["clientDataJsonBytesDigest"] = retention._bytes_digest(client, work)
    owned["clientDataJsonByteCount"] = len(client)
    owned["attestationObjectBytesDigest"] = retention._bytes_digest(attestation_original, work)
    owned["attestationObjectByteCount"] = len(attestation_original)
    _context_on_owned_work(owned, work)
    # Account and enforce the complete returned context, including the four
    # derived fields, rather than relying on the smaller initial capture.
    evidence.capability._wire(owned, evidence.capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _bind_originals_on_work(*, context, client_data_json, attestation_object,
        credential_id, transports, verified_at_epoch_ns, work):
    """Rejoin exact raw bytes and metadata; this is not grant admission."""
    evidence.capture._SharedLedger(work)
    client, attestation_original, held_transports = _originals(client_data_json, attestation_object, transports)
    work.prepare_copy(held_transports)
    owned = _capture({"context": context, "credentialId": credential_id,
        "transports": list(held_transports), "verifiedAtEpochNs": verified_at_epoch_ns}, work)
    claimed = owned["context"]
    _context_on_owned_work(claimed, work)
    actual = (retention._bytes_digest(client, work), len(client),
        retention._bytes_digest(attestation_original, work), len(attestation_original),
        owned["credentialId"], owned["transports"], owned["verifiedAtEpochNs"])
    expected = (claimed["clientDataJsonBytesDigest"], claimed["clientDataJsonByteCount"],
        claimed["attestationObjectBytesDigest"], claimed["attestationObjectByteCount"],
        claimed["credentialId"], claimed["transports"], claimed["verifiedAtEpochNs"])
    evidence.plan._same(actual, expected, work, "enrollment grant differs from exact browser originals or evaluation time")


def _scope(configuration_digest, generation_sequence, generation_digest, issuer_id,
        audience_spki_digest, maximum_age_ns, maximum_clock_skew_ns):
    shape = evidence.plan.contract
    wire._pins(configuration_digest, generation_sequence, generation_digest, OPERATION)
    if type(issuer_id) is not str or _ISSUER.fullmatch(issuer_id) is None:
        raise WebAuthnEnrollmentAuthorizationError("enrollment issuer ID is not a bounded ASCII token")
    shape._digest(audience_spki_digest)
    shape._integer(maximum_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(maximum_clock_skew_ns, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    return configuration_digest, generation_sequence, generation_digest, issuer_id, audience_spki_digest


def _shape(value, *, signed=True):
    shape = evidence.plan.contract
    shape._object(value, _FIELDS if signed else _FIELDS - {"signatureBase64Url"}, "enrollment authorization")
    for name, expected in (("schema", SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("operation", OPERATION)):
        shape._literal(value[name], expected)
    _scope(value["configurationDigest"], value["generationSequence"], value["generationDigest"],
        value["issuerId"], value["audienceSpkiDigest"], authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    shape._text(value["authorizationId"], 43, minimum=43)
    shape._base64url(value["authorizationId"])
    _context_shape(value["context"])
    wire._time_pins({"issuedAtEpochNs": value["issuedAtEpochNs"], "expiresAtEpochNs": value["expiresAtEpochNs"]},
        authority.VERIFIER_RESPONSE_MAX_AGE_NS, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _fresh(context, timing, *, window, maximum_age_ns, maximum_clock_skew_ns, work):
    evaluated = context["verifiedAtEpochNs"]
    evidence.plan.contract._integer(evaluated, minimum=1)
    issued, expires = wire._time_pins(timing, maximum_age_ns, maximum_clock_skew_ns)
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    if (abs(evaluated - issued) > maximum_clock_skew_ns
            or evaluated >= expires or evaluated > now + maximum_clock_skew_ns):
        raise WebAuthnEnrollmentAuthorizationError("original enrollment evaluation time exceeds its live grant interval")
    return now


def _sign(unsigned, *, private_key, public_key, work):
    ledger = evidence.capture._SharedLedger(work)
    owned = _capture(unsigned, work)
    _shape(owned, signed=False)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        raise WebAuthnEnrollmentAuthorizationError("signed enrollment authorization exceeds its bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnEnrollmentAuthorizationError("enrollment grant cannot reserve its signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnEnrollmentAuthorizationError("enrollment grant size changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(SCHEMA, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if (work.measure(owned) != (unsigned_size, unsigned_nodes)
            or evidence.plan.core.canonical_bytes(owned) != original):
        raise WebAuthnEnrollmentAuthorizationError("enrollment grant changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnEnrollmentAuthorizationError("enrollment signature output changed after measurement")
    return result


def _produce_on_work(*, context, configuration_digest, generation_sequence, generation_digest,
        issuer_id, issuer_private_key, issuer_public_key, audience_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, deadline_epoch_ns, work):
    evidence.capture._SharedLedger(work)
    owned = _capture(context, work)
    scope = _scope(configuration_digest, generation_sequence, generation_digest, issuer_id,
        audience_spki_digest, maximum_age_ns, maximum_clock_skew_ns)
    private_key, public_key = issuer_private_key, issuer_public_key
    if (not isinstance(private_key, plan.Ed25519PrivateKey)
            or not isinstance(public_key, plan.Ed25519PublicKey)):
        raise WebAuthnEnrollmentAuthorizationError("enrollment issuance requires the actual Ed25519 key pair")
    evidence.plan.contract._integer(deadline_epoch_ns, minimum=1)
    deadline = deadline_epoch_ns
    _context_on_owned_work(owned, work)
    evidence.keys._pair_on_work(private_key, public_key, work)
    work.charge(input_bytes=32 + 44 + 43)
    nonce = evidence.production._callback(work, lambda: os.urandom(32))
    if type(nonce) is not bytes or len(nonce) != 32:
        raise WebAuthnEnrollmentAuthorizationError("enrollment authorization ID is not fresh raw32")
    authorization_id = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    window = clock._open_on_work(deadline_epoch_ns=deadline, maximum_lifetime_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    issued, expires = window[0], clock._deadline_epoch_ns(window)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    unsigned = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": PURPOSE, "operation": OPERATION, "configurationDigest": scope[0],
        "generationSequence": scope[1], "generationDigest": scope[2], "issuerId": scope[3],
        "audienceSpkiDigest": scope[4], "authorizationId": authorization_id,
        "context": owned, "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _fresh(owned, timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    original = _sign(unsigned, private_key=private_key, public_key=public_key, work=work)
    _fresh(owned, timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    return original


def _verify_on_work(*, authorization_bytes, configuration_digest, generation_sequence,
        generation_digest, issuer_id, issuer_public_key, audience_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, work):
    ledger = evidence.capture._SharedLedger(work)
    if type(authorization_bytes) is not bytes or not 2 <= len(authorization_bytes) <= MAX_BYTES:
        raise WebAuthnEnrollmentAuthorizationError("enrollment grant is not bounded original bytes")
    original, public_key = authorization_bytes, issuer_public_key
    scope = _scope(configuration_digest, generation_sequence, generation_digest, issuer_id,
        audience_spki_digest, maximum_age_ns, maximum_clock_skew_ns)
    if not isinstance(public_key, plan.Ed25519PublicKey):
        raise WebAuthnEnrollmentAuthorizationError("enrollment verification requires its configured Ed25519 key")
    value = evidence.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    value = _capture(value, work)
    _shape(value)
    evidence.capability._canonical(original, value, ledger, MAX_BYTES, MAX_NODES)
    work.prepare_copy(value)
    unsigned = value.copy()
    signature = unsigned.pop("signatureBase64Url")
    unsigned_bytes = evidence.capability._wire(unsigned, ledger, MAX_BYTES, MAX_NODES)
    evidence.capability._signature(public_key, signature, SCHEMA, unsigned_bytes, ledger)
    evidence.capability._canonical(original, value, ledger, MAX_BYTES, MAX_NODES)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["issuerId"], value["audienceSpkiDigest"]), scope, work,
        "enrollment authorization differs from independently admitted issuer/audience/configuration")
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    context = value["context"]
    _context_on_owned_work(context, work)
    timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    window = wire._open_control_window_on_work(timing, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    _fresh(context, timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    authorization_digest = evidence.plan._frame(IDENTITY_DOMAIN, (original,), work)
    _fresh(context, timing, window=window, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    evidence.capability._canonical(original, value, ledger, MAX_BYTES, MAX_NODES)
    return _VerifiedAuthorization(context, issued, expires, window, authorization_digest)
