"""Root-delegated static resources for one live activation issuance chain.

No current vector, pending row, packet, SQL result or completion is embedded.
The fixed producer must acquire those originals at their genuine lifecycle
points. This policy authenticates resource selection, not resource custody,
native measurement, present permission or a successful browser login.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from catchplate import oidc_session_activation_planner_bootstrap as planner
from catchplate import authority_oidc_session_activation_execution_authorization as caller
from catchplate import authority_attestation_cohort as cohort
from catchplate.authority_local_limits import LOCAL_SESSION_MAX_NS


authority, configuration, capture = planner.authority, planner.configuration, planner.capture
shape, plan, capability = planner.shape, planner.plan, planner.capability
authorization, clock, keys = planner.authorization, planner.clock, planner.keys
production = configuration.production
SCHEMA = "catchplate.signedOidcSessionActivationRequestIssuancePolicy/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationRequestIssuancePolicy/v1"
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationRequestIssuancePolicyIdentity/v1"
PURPOSE = "issue-oidc-session-activation-request-workers"
MAX_BYTES = planner.MAX_BYTES
# This is prospective runtime delegation, not a request launch. Its genuine
# cohort and independently retained cold-owner window may only narrow it.
MAX_POLICY_AGE_NS = LOCAL_SESSION_MAX_NS
RESOURCE_FIELDS = planner._PAYLOAD_FIELDS - frozenset({
    "completeRootVector", "issuedAtEpochNs", "expiresAtEpochNs"})
RECEIVERS = ("grant", "reserve", "sql-issuer")
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "plannerResources", "authorizationEnrollment", "grantEnrollment",
    "receiverIdentities", "runtimeCohort", "artifactPackageDigest",
    "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class RequestIssuancePolicyError(ValueError):
    pass


def _fail(message):
    raise RequestIssuancePolicyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Policy:
    """Private same-call facts. No producer accepts this in place of originals."""

    original: bytes
    digest: str
    payload: dict
    resource_facts: tuple
    authorization_enrollment: bytes
    grant_enrollment: bytes
    caller: object
    live: object


def _capture(value, work):
    # Service6 admits finite floats; use its exact capture and encoding rules.
    return configuration._ConfigurationCapture(
        capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "activation request issuance policy")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    resources = payload["plannerResources"]
    shape._object(resources, RESOURCE_FIELDS, "activation static planner resources")
    planner._resource_shape(resources, work)
    for name, maximum in (("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES),
            ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES)):
        planner._original_shape(payload[name], maximum, name)
    shape._object(payload["receiverIdentities"], frozenset(RECEIVERS),
        "activation dedicated receiving identities")
    for name in RECEIVERS:
        shape.validate_identity_shape(payload["receiverIdentities"][name])
    shape._digest(payload["artifactPackageDigest"])
    original = payload["runtimeCohort"]
    shape._object(original, frozenset({"base64Url", "byteCount", "bytesDigest"}), "issuance runtime cohort")
    authorization.transport._transport_shape(original["base64Url"], original["byteCount"], cohort.MAX_BYTES)
    shape._digest(original["bytesDigest"])
    authorization._interval(payload, MAX_POLICY_AGE_NS)


def _enrollment(payload, name, maximum, identity_domain, work, current):
    record = payload[name]
    current()
    raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
    work.charge(hashes=1, input_bytes=len(raw))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    plan._same(digest, record["bytesDigest"], work,
        "issuance exact " + name + " bytes")
    plan._same(plan._frame(identity_domain, (raw,), work), record["identityDigest"], work,
        "issuance exact " + name + " identity")
    current()
    return raw


def _join(payload, root, work, current):
    resources = payload["plannerResources"]
    facts = planner._resource_material(resources, root, work, current)
    configured, generation, runtime, public, state_raw, _state_digest, _reader = facts
    _runtime_scope(payload, configured, generation, runtime, root, work, current)
    grant_raw = _enrollment(payload, "grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES,
        caller.grants.ENROLLMENT_IDENTITY_DOMAIN, work, current)
    caller_raw = _enrollment(payload, "authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES,
        caller.ENROLLMENT_IDENTITY_DOMAIN, work, current)
    current()
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=state_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=resources["configurationDigest"],
        planner_public_key=public, operation_public_key=root, work=work)
    current()
    return facts, caller_raw, grant_raw, enrolled


def _runtime_scope(payload, configured, generation, runtime, root, work, current):
    """Actual root-signed cohort bounds delegation before any private access."""
    record = payload["runtimeCohort"]
    raw = authorization.transport._decode(record["base64Url"], record["byteCount"], cohort.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(raw))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    plan._same(digest, record["bytesDigest"], work, "issuance exact runtime cohort original")
    # The unchanged cohort helper predates H/B/N. Reserve its six signature
    # message serializations, six receipt/cohort identity hashes, five runtime
    # closure hashes, JSON ownership/canonical copies and bounded inventory
    # walks here. Package data are visited five times by the closure frames.
    # This does not grant a new meter or promise every source maximum fits.
    configured_raw = configuration._configuration_wire(configured, capture._SharedLedger(work))
    work.charge(hashes=17, input_bytes=20 * len(raw) + 16 * len(configured_raw) + 65536,
        json_nodes=16 * 1024 + 16 * 4096)
    now = current()
    admitted, _body, receipts = production._callback(work, lambda: cohort._verify_cohort_against_scope(
        held_bytes=raw, held_digest=payload["plannerResources"]["configurationDigest"], held_key=root,
        static_configuration=cohort._static_configuration(configured),
        generation_sequence=generation["sequence"], generation_digest=generation["digest"],
        package_digest=payload["artifactPackageDigest"], local_binding=None, evaluation_epoch_ns=now))
    current()
    if not (admitted.valid_from_epoch_ns <= payload["issuedAtEpochNs"]
            < payload["expiresAtEpochNs"] <= admitted.valid_until_epoch_ns):
        _fail("issuance policy exceeds its actual signed runtime cohort")
    work.charge(input_bytes=8192, json_nodes=128)
    receipt_digests = {role: pin for role, _original, pin in admitted.receipts}
    projected = {"schema": configuration.RUNTIME_ROLE_IDENTITIES_SCHEMA,
        "configurationDigest": payload["plannerResources"]["configurationDigest"],
        "generationSequence": admitted.generation_sequence, "generationDigest": admitted.generation_digest,
        "cohortDigest": admitted.cohort_digest,
        "roles": {row["role"]: {"measurementDigest": row["measurementDigest"],
            "responseSigningSpkiDigest": row["responseSigningSpkiDigest"],
            "attestationReceiptDigest": receipt_digests[row["role"]]} for row in receipts}}
    plan._same(projected, runtime, work, "issuance actual runtime receipt projection")
    current()


def _clock(payload, window, deadline, work, continuity):
    inherited = planner._processing(window, deadline, work, _continuity=continuity)
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    inherited()
    opening = planner._fresh(interval, work)
    guarded = planner._launch_guard(interval, opening, inherited, work, _continuity=continuity)
    if continuity is not None:
        return guarded

    def current():
        observed = guarded()
        final = inherited()
        if final < observed or not interval[0] <= final < interval[1]:
            _fail("issuance cold admission crossed its original policy interval")
        return final

    return current


def _verify_on_work(*, policy_bytes, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None):
    """Authenticate signed static originals before any native resource access."""
    raw = authorization._original(policy_bytes, MAX_BYTES, "activation request issuance policy")
    root = root_public_key
    authorization._public(root)
    if (live_window is None) != (transport_deadline_ns is None):
        _fail("issuance policy requires the complete original processing pair")
    window = None if live_window is None else clock._validate(live_window)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    deadline = None if window is None else min(window[4], transport_deadline_ns)
    inherited = planner._processing(window, deadline, work, _continuity=_continuity)
    inherited()
    envelope = _capture(planner.codec._decode(raw, work), work)
    shape._object(envelope, _ENVELOPE_FIELDS, "signed activation request issuance policy")
    shape._literal(envelope["schema"], SCHEMA)
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    payload = envelope["payload"]
    _shape(payload, work)
    planner.codec._canonical(raw, envelope, work)
    unsigned = configuration._configuration_wire(payload, capture._SharedLedger(work))
    inherited()
    capability._signature(root, envelope["signatureBase64Url"], SCHEMA,
        unsigned, capture._SharedLedger(work))
    inherited()
    planner.codec._canonical(raw, envelope, work)
    current = _clock(payload, window, deadline, work, _continuity)
    facts, caller_raw, grant_raw, enrolled = _join(payload, root, work, current)
    digest = plan._frame(IDENTITY_DOMAIN, (raw,), work)
    current()
    return _Policy(raw, digest, payload, facts, caller_raw, grant_raw, enrolled, current)


def _produce_on_work(*, payload, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Independent provisioner signs static resources; no worker is started."""
    private, root = root_private_key, root_public_key
    authorization._private(private)
    authorization._public(root)
    owned = _capture(payload, work)
    _shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    current = _clock(owned, window, min(window[4], transport_deadline_ns), work, _continuity)
    _join(owned, root, work, current)
    unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
    current()
    raw = planner.signing._sign(owned, SCHEMA, MAX_BYTES, private, root, work)
    planner.codec._canonical(unsigned, owned, work)
    current()
    return raw
