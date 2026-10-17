"""Original-window role signatures for raw maintenance-page custody only.

These controls authorize no business mutation, current root, grant or proof
result. The fixed service owner independently admits the role key and peer.
Only a planner can request persistence; a verifier can sign a read intent for
the existing planner-forward topology. The writer accepts planner controls
only. Returned page bytes still require whole parent/manifest proof replay.

No method opens a clock window, connection, allowance or retry. In particular,
forwarding preserves the source request's original deadline and interval.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import authority_challenge_page_control as control
from catchplate import authority_challenge_plan as parent


SCHEMA = "catchplate.policyAuthorityChallengeMaintenancePageAuthorization/v1"
ENVELOPE_SCHEMA = "catchplate.signedPolicyAuthorityChallengeMaintenancePageAuthorization/v1"
SIGNATURE_DOMAIN = "catchplate.policyAuthorityChallengeMaintenancePageAuthorizationSignature/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityChallengeMaintenancePageAuthorizationIdentity/v1"
CONTROL_DOMAIN = "catchplate.policyAuthorityChallengeMaintenancePageControlIdentity/v1"
MAX_BYTES, MAX_NODES, MAX_DEPTH = 8192, 256, 4
FIELDS = frozenset({"schema", "sourceRevision", "role", "identity", "spkiDigest",
    "configurationDigest", "controlDigest", "controlByteCount", "issuedAtEpochNs",
    "expiresAtEpochNs", "originalDeadlineNs"})
evidence, clock = parent.evidence, parent.clock


class ChallengePageAuthorizationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PageAuthorizationObservation:
    """Ordinary same-call claims; no store/issuer accepts this as authority."""

    control: dict
    authorization_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    original_deadline_ns: int


def _require(value):
    if not value:
        raise ChallengePageAuthorizationError("maintenance page role control differs from its original custody")


def _identity(value, work):
    evidence._identity(value)
    return evidence.capture._JSONCapture(evidence.capture._SharedLedger(work)).visit(value)


def _pins(role, identity, spki, configuration, work):
    _require(type(role) is str and role in ("planner", "verifier"))
    for value in (spki, configuration):
        evidence.plan.contract._digest(value)
    return role, _identity(identity, work), spki, configuration


def _shape(value):
    parent._object(value, FIELDS)
    evidence.plan.contract._literal(value["schema"], SCHEMA)
    evidence.plan.contract._literal(value["sourceRevision"], evidence.authority.SOURCE_REVISION)
    _require(type(value["role"]) is str and value["role"] in ("planner", "verifier"))
    evidence._identity(value["identity"])
    for field in ("spkiDigest", "configurationDigest", "controlDigest"):
        evidence.plan.contract._digest(value[field])
    evidence.plan.contract._integer(value["controlByteCount"], control.MAX_CONTROL_BYTES, minimum=2)
    for field in ("issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs"):
        evidence.plan.contract._integer(value[field], minimum=1)


def _bind(payload, raw_control, owned_control, pins, window, work):
    _shape(payload)
    role, identity, spki, configuration = pins
    _require(role == "planner" or owned_control["action"] == "read")
    for name, expected in (("role", role), ("identity", identity), ("spkiDigest", spki),
            ("configurationDigest", configuration), ("controlByteCount", len(raw_control)),
            ("originalDeadlineNs", owned_control["context"]["originalDeadlineNs"])):
        parent._same(payload[name], expected, work)
    parent._same(configuration, owned_control["context"]["configurationDigest"], work)
    parent._same(payload["controlDigest"], evidence.plan._frame(CONTROL_DOMAIN, (raw_control,), work), work)
    now = clock._check_on_work(window, work=work)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    # A receiving/forwarding owner may only narrow its original window. It
    # cannot change the held page context's monotonic deadline or revive an
    # expired page operation with a newly sampled opening.
    _require(0 < issued < expires and expires - issued <= window[5]
        and issued <= now + window[6] and now - issued <= window[5]
        and now < expires)
    current = evidence.production._callback(work, time.monotonic_ns)
    _require(type(current) is int
        and window[2] <= current < min(payload["originalDeadlineNs"], window[4]))


def _sign(payload, private, public, work):
    _shape(payload)
    ledger = evidence.capture._SharedLedger(work)
    unsigned = evidence.capability._wire(payload, ledger, MAX_BYTES, MAX_NODES)
    message = evidence.plan._ascii(evidence.plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    placeholder = {"schema": ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    _require(size <= MAX_BYTES and nodes <= MAX_NODES and payload_size == len(unsigned))
    # Reserve the original-size comparison encodings and complete envelope
    # before signing. Leave room for one independently bounded measurement of
    # the graph after the native callback; never encode a changed graph first.
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    _require(work.limits.max_input_bytes - work.input_bytes >= payload_size
        and work.limits.max_json_nodes - work.json_nodes >= payload_nodes)
    signature = evidence.production._sign_and_verify(private, public, message, work)
    # The exact owned payload must not be changed by the actual key callback.
    _shape(payload)
    _require(work.measure(payload) == (payload_size, payload_nodes)
        and evidence.plan.core.canonical_bytes(payload) == unsigned)
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({"schema": ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    _require(len(result) == size)
    return result


def sign_control(*, control_bytes, action, signer_role, signer_identity, signer_spki_digest,
        signer_private_key, signer_public_key, configuration_digest, live_window, work):
    _require(isinstance(signer_private_key, Ed25519PrivateKey)
        and isinstance(signer_public_key, Ed25519PublicKey))
    raw = control_bytes
    # Decode owns and checks the exact canonical control before native key or
    # clock callbacks; no parallel mutable caller context is retained.
    owned = control.decode_control(raw, expected_action=action, work=work)
    pins = _pins(signer_role, signer_identity, signer_spki_digest, configuration_digest, work)
    window = clock._validate(live_window)
    evidence.keys._public_binding(signer_public_key, signer_spki_digest, work)
    evidence.keys._pair_on_work(signer_private_key, signer_public_key, work)
    payload = {"schema": SCHEMA, "sourceRevision": evidence.authority.SOURCE_REVISION,
        "role": pins[0], "identity": pins[1], "spkiDigest": pins[2], "configurationDigest": pins[3],
        "controlDigest": evidence.plan._frame(CONTROL_DOMAIN, (raw,), work), "controlByteCount": len(raw),
        "issuedAtEpochNs": window[0], "expiresAtEpochNs": window[3],
        "originalDeadlineNs": owned["context"]["originalDeadlineNs"]}
    _bind(payload, raw, owned, pins, window, work)
    result = _sign(payload, signer_private_key, signer_public_key, work)
    _bind(payload, raw, owned, pins, window, work)
    return result


def verify_control(*, authorization_bytes, control_bytes, action, expected_role,
        expected_identity, expected_spki_digest, public_key, configuration_digest, live_window, work):
    _require(isinstance(public_key, Ed25519PublicKey))
    owned_control = control.decode_control(control_bytes, expected_action=action, work=work)
    pins = _pins(expected_role, expected_identity, expected_spki_digest, configuration_digest, work)
    window = clock._validate(live_window)
    envelope = evidence.wire._decode_object(authorization_bytes, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    parent._object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    evidence.plan.contract._literal(envelope["schema"], ENVELOPE_SCHEMA)
    payload = envelope["payload"]
    _bind(payload, control_bytes, owned_control, pins, window, work)
    ledger = evidence.capture._SharedLedger(work)
    evidence.capability._canonical(authorization_bytes, envelope, ledger, MAX_BYTES, MAX_NODES)
    unsigned = evidence.capability._wire(payload, ledger, MAX_BYTES, MAX_NODES)
    evidence.keys._public_binding(public_key, expected_spki_digest, work)
    evidence.capability._signature(public_key, envelope["signatureBase64Url"], SIGNATURE_DOMAIN, unsigned, ledger)
    _bind(payload, control_bytes, owned_control, pins, window, work)
    digest = evidence.plan._frame(IDENTITY_DOMAIN, (authorization_bytes,), work)
    return PageAuthorizationObservation(owned_control, digest, payload["issuedAtEpochNs"],
        payload["expiresAtEpochNs"], payload["originalDeadlineNs"])
