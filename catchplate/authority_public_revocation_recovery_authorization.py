"""Present, separately signed read permission; never renewed execution rights.

The actual HTTP owner authenticates its present caller before signing. This
distinct purpose authorizes only original-byte lookup/committed-state readback
and completion delivery for one exact previously retained attempt. It has no
SQL execution, reserve, retry, absence-as-noncommit or approval-consumption API.
"""
from __future__ import annotations

import base64
import time

from catchplate import authority_public_revocation_caller_authorization as caller
from catchplate import authority_public_webauthn_revocation as aggregate


SCHEMA = "catchplate.signedPublicWebAuthnRevocationRecoveryAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.publicWebAuthnRevocationRecoveryAuthorization/v1"
PURPOSE = "observe-public-webauthn-revocation"
MAX_BYTES = 64 * 1024
FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "authorizationEnrollmentDigest", "requestAuthorizationDigest", "pendingDecisionDigest",
    "packetDigest", "actor", "issuedAtEpochNs", "expiresAtEpochNs"})


def _shape(value):
    caller.shape._object(value, FIELDS, "public revocation recovery authorization")
    caller.shape._literal(value["schema"], PAYLOAD_SCHEMA)
    caller.shape._literal(value["sourceRevision"], caller.grants.authority.SOURCE_REVISION)
    caller.shape._literal(value["purpose"], PURPOSE)
    for field in ("configurationDigest", "authorizationEnrollmentDigest", "requestAuthorizationDigest",
            "pendingDecisionDigest", "packetDigest"):
        caller.shape._digest(value[field])
    aggregate._object(value["actor"], aggregate.ACTOR_FIELDS)
    aggregate._text(value["actor"]["userId"])
    aggregate._text(value["actor"]["authMethod"], 128)
    caller.shape._digest(value["actor"]["requestSha256"])
    roles = value["actor"]["roles"]
    aggregate._require(type(roles) is list and 1 <= len(roles) <= 32
        and all(type(role) is str and 1 <= len(role) <= 128 for role in roles)
        and roles == sorted(set(roles)) and bool(set(roles) & {"admin", "approver"}))
    caller.authorization._interval(value, aggregate.MAX_AGE_NS)


def sign_on_owner(owner, *, actor, request_authorization_digest, pending_decision_digest,
        packet_digest, live_window, transport_deadline_ns, work):
    from catchplate import control_plane_enrollment_startup as startup
    if type(owner) is not startup._EnrollmentOwner:
        raise aggregate.PublicRevocationError("public recovery signer is not the actual cold owner")
    startup._live(owner, work=work)
    material = owner._material.public_revocation
    if material is None or owner._revocation_key is None:
        raise aggregate.PublicRevocationError("public revocation recovery is not cold enabled")
    from catchplate import authority_revocation_verifier as configured
    verifier = configured._verifier_from_configuration_on_work(payload=owner._material.configuration_payload,
        configuration_digest=owner._material.configuration_digest, generation=owner._material.generation,
        runtime_role_identities=owner._material.runtime_role_identities, work=work)
    pins = configured.RevocationPlanVerifier._snapshot_configuration(verifier)
    enrollment = caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=material.authorization_enrollment_bytes,
        current_root_enrollment_bytes=material.current_root_enrollment_bytes,
        grant_enrollment_bytes=material.grant_enrollment_bytes,
        root_public_key=owner._binding.runtime_root_public_key,
        configuration_digest=owner._material.configuration_digest,
        planner_public_key=pins[0], evidence_public_key=pins[1], work=work)
    window = caller.clock._validate(live_window)
    issued = caller.clock._check_on_work(window, work=work)
    if caller.production._callback(work, time.monotonic_ns) >= min(window[4], transport_deadline_ns):
        raise aggregate.PublicRevocationError("public recovery authorization original deadline expired")
    payload = {"schema": PAYLOAD_SCHEMA, "sourceRevision": caller.grants.authority.SOURCE_REVISION,
        "purpose": PURPOSE, "configurationDigest": owner._material.configuration_digest,
        "authorizationEnrollmentDigest": enrollment.enrollment_digest,
        "requestAuthorizationDigest": request_authorization_digest,
        "pendingDecisionDigest": pending_decision_digest, "packetDigest": packet_digest,
        "actor": caller.capture._JSONCapture(caller.capture._SharedLedger(work), maximum_bytes=8192).visit(actor),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": min(window[3], issued + aggregate.MAX_AGE_NS)}
    _shape(payload)
    caller.keys._pair_on_work(owner._revocation_key, enrollment.caller_public_key, work)
    unsigned = caller.authorization.capability._wire(payload, caller.capture._SharedLedger(work), MAX_BYTES, 4096)
    message = caller.plan._frame(SCHEMA, (unsigned,), work).encode("ascii")
    signature = caller.production._sign_and_verify(owner._revocation_key, enrollment.caller_public_key, message, work)
    work.charge(input_bytes=64 + 88 + 86)
    original = caller.authorization.capability._wire({"schema": SCHEMA, "payload": payload,
        "signatureBase64Url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
        caller.capture._SharedLedger(work), MAX_BYTES, 4096)
    startup._live(owner, work=work)
    caller.clock._check_on_work(window, work=work)
    return original


def verify(original, *, enrollment, configuration_digest, request_authorization_digest,
        pending_decision_digest, packet_digest, original_actor_id, live_window,
        transport_deadline_ns, work):
    value = caller.authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=4096, maximum_depth=6)
    caller.shape._object(value, frozenset({"schema", "payload", "signatureBase64Url"}), "public recovery original")
    caller.shape._literal(value["schema"], SCHEMA)
    _shape(value["payload"])
    caller.authorization._verify_signature(value, SCHEMA, enrollment.caller_public_key, MAX_BYTES, work)
    caller.primitives._unchanged(original, value, MAX_BYTES, work)
    payload = value["payload"]
    for field, expected in (("configurationDigest", configuration_digest),
            ("authorizationEnrollmentDigest", enrollment.enrollment_digest),
            ("requestAuthorizationDigest", request_authorization_digest),
            ("pendingDecisionDigest", pending_decision_digest), ("packetDigest", packet_digest)):
        caller.plan._same(payload[field], expected, work, "public recovery original scope " + field)
    actor = payload["actor"]
    if actor["userId"] != original_actor_id and "admin" not in actor["roles"]:
        raise aggregate.PublicRevocationError("public recovery lacks present original-owner/admin permission")
    window = caller.clock._validate(live_window)
    now = caller.clock._check_on_work(window, work=work)
    if (not payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"]
            or caller.production._callback(work, time.monotonic_ns) >= min(window[4], transport_deadline_ns)):
        raise aggregate.PublicRevocationError("public recovery authority expired or its original clock changed")
    return payload
