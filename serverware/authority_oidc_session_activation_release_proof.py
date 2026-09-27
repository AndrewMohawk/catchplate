"""Independent original release-proof admission, never plaintext authority.

The caller must genuinely admit fresh intent and old-token possession in the
same composition. This verifier authenticates a distinct root-enrolled proof
against independent bindings; it neither replays history nor accepts a proof
result object, historical keys, a signer, SQL or a plaintext-opening callback.
The separate historical entrypoint authenticates old evidence under current
processing and live delivery bounds, never present release permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import oidc_session_activation_release_proof as contract
from serverware import oidc_session_activation_release_proof_enrollment as enrollments
from serverware import authority_successor_execution_window as processing


authorization, shape, plan = contract.authorization, contract.shape, contract.plan
capture, production, clock = contract.capture, contract.production, contract.clock
bootstrap, delivery = contract.bootstrap, contract.delivery
registration = delivery.registration
evidence = registration.evidence
SCOPE_FIELDS, RELEASE_FIELDS = contract.SCOPE_FIELDS, contract.RELEASE_FIELDS
EVIDENCE_FIELDS = frozenset({"releaseCustodyDigest", "releaseIntentDigest", "stateReceiptDigest"})
MAX_BYTES = contract.MAX_BYTES
MAX_ORIGINAL_BYTES = contract.MAX_BYTES + enrollments.MAX_BYTES


class OidcSessionActivationReleaseProofAdmissionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseProofAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedProof:
    """Ordinary same-call output; no entrypoint accepts it as authority."""
    payload: dict
    proof_digest: str
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalProofEvidence:
    """Original evidence only; current guard does not renew the signed proof."""
    payload: dict
    proof_digest: str
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Held:
    proof: bytes
    enrollment: bytes
    root: object
    forbidden: tuple
    scope: dict
    release: dict
    evidence: dict
    intent_interval: tuple
    window: tuple
    deadline_ns: int


def _closed(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(name) is not str or name not in fields for name in value)):
        _fail(label + " is not a closed exact object")


def _scalars(value, limits, label):
    """Detach bounded scalar maps without native work or caller coercion."""
    _closed(value, frozenset(limits), label)
    owned = {}
    for name, maximum in limits.items():
        item = value[name]
        if type(item) is not str or not 1 <= len(item) <= maximum:
            _fail(label + " contains an invalid scalar")
        owned[name] = item
    return owned


def _graphs(scope, release, evidence_values):
    # Joint non-coercing ownership precedes every cryptographic/native callback.
    _closed(scope, SCOPE_FIELDS, "release proof independent scope")
    _closed(release, RELEASE_FIELDS, "release proof independent release")
    scalar_scope = {name: scope[name] for name in SCOPE_FIELDS
        if name not in ("producerIdentity", "receiverIdentity")}
    owned_scope = _scalars(scalar_scope,
        {name: (128 if name in ("producerId", "databaseId") else 71) for name in scalar_scope},
        "release proof scope scalars")
    for name in ("producerIdentity", "receiverIdentity"):
        owned_scope[name] = _scalars(scope[name],
            {field: 71 for field in bootstrap.planner_bootstrap._IDENTITY_FIELDS},
            "release proof " + name)
    scalar_release = {name: release[name] for name in RELEASE_FIELDS
        if name not in ("deliveryScope", "consumeBinding")}
    owned_release = _scalars(scalar_release, {name: 71 for name in scalar_release},
        "release proof release scalars")
    owned_release["deliveryScope"] = _scalars(release["deliveryScope"], delivery._SCOPE_LIMITS,
        "release proof delivery scope")
    owned_release["consumeBinding"] = _scalars(release["consumeBinding"],
        {name: 71 for name in contract.CONSUME_BINDING_FIELDS}, "release proof consume identities")
    owned_evidence = _scalars(evidence_values, {name: 71 for name in EVIDENCE_FIELDS},
        "release proof original evidence identities")
    return owned_scope, owned_release, owned_evidence


def _hold(*, proof_bytes, enrollment_bytes, root_public_key, forbidden_public_keys,
        expected_scope, expected_release, expected_evidence, expected_intent_interval,
        live_window, transport_deadline_ns, work):
    capture._SharedLedger(work)
    original = authorization._original(proof_bytes, contract.MAX_BYTES, "release proof original")
    enrolled = authorization._original(enrollment_bytes, enrollments.MAX_BYTES,
        "release proof enrollment original")
    root, forbidden = root_public_key, forbidden_public_keys
    if type(forbidden) is not tuple or not 1 <= len(forbidden) <= enrollments.MAX_FORBIDDEN_PUBLIC_KEYS:
        _fail("release proof requires the bounded independent role-key tuple")
    interval = expected_intent_interval
    if type(interval) is not tuple or len(interval) != 2:
        _fail("release proof requires the original admitted intent interval")
    issued, expires = interval
    shape._integer(issued, minimum=1)
    shape._integer(expires, minimum=1)
    if issued >= expires:
        _fail("release proof expected intent interval is empty")
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    scope, release, evidence_values = _graphs(expected_scope, expected_release, expected_evidence)
    # Native key references and immutable originals are held alongside all
    # detached external graphs before the first enrolled-key admission.
    authorization._public(root)
    for key in forbidden:
        authorization._public(key)
    total = len(original) + len(enrolled)
    if total > MAX_ORIGINAL_BYTES:
        _fail("release proof originals exceed their fixed aggregate bound")
    work.charge(input_bytes=total)
    copier = contract._Capture(capture._SharedLedger(work), maximum_bytes=contract.MAX_BYTES)
    scope, release, evidence_values = copier.visit(scope), copier.visit(release), copier.visit(evidence_values)
    return _Held(original, enrolled, root, forbidden, scope, release, evidence_values,
        interval, window, bound)


def _clock(held, work):
    window, bound = held.window, held.deadline_ns
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("release proof original processing clocks expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    def narrow(expiry, age, skew):
        nonlocal window, bound
        window = processing._narrow(window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
        bound = min(bound, window[4])
        return window

    return current, narrow


def _release(held, current, work):
    for name in RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}:
        shape._digest(held.release[name])
    for value in held.release["consumeBinding"].values():
        shape._digest(value)
    for value in held.evidence.values():
        shape._digest(value)
    created, expires = bootstrap._scope(held.release["deliveryScope"], work)
    current()
    operation = plan._frame("serverware.policyAuthorityOperation/v2",
        (plan._ascii(bootstrap.ACTIVATION_OPERATION, work),
         plan._ascii(held.release["activationRequestDigest"], work)), work)
    current()
    plan._same(operation, held.release["activationOperationId"], work,
        "release proof independent activation operation")
    delivery_id = registration.core._deterministic_uuid(operation=bootstrap.ACTIVATION_OPERATION,
        request_digest=held.release["activationRequestDigest"], purpose="activation-delivery", work=work)
    current()
    plan._same(delivery_id, held.release["deliveryScope"]["deliveryId"], work,
        "release proof independent deterministic delivery")
    return created, expires


def _authenticate_original(held, enrolled, current, created, delivery_expiry, skew, work):
    """Shared exact signature/bindings and algebra, never a freshness bypass."""
    policy = enrolled.payload
    age = policy["maximumAgeNs"]
    intent_issued, intent_expires = held.intent_interval
    envelope = contract._read(held.proof, work)
    current()
    contract._signature(envelope, enrolled.proof_public_key, work)
    current()
    payload = envelope["payload"]
    for fields, expected in ((SCOPE_FIELDS, held.scope), (RELEASE_FIELDS, held.release),
            (EVIDENCE_FIELDS, held.evidence)):
        for name in fields:
            plan._same(payload[name], expected[name], work, "release proof independent " + name)
    plan._same(payload["enrollmentDigest"], enrolled.enrollment_digest, work,
        "release proof original producer enrollment")
    measurement = policy["proofKey"]["measurementDigest"]
    plan._same(payload["producerMeasurementDigest"], measurement, work,
        "release proof enrolled producer measurement")
    plan._same(measurement, held.scope["producerIdentity"]["measurementDigest"], work,
        "release proof independent producer measurement")
    authorization._interval(payload, age)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if (expires > min(intent_expires, delivery_expiry) or issued >= intent_expires
            or issued + skew < intent_issued or issued + skew < created):
        _fail("release proof escapes the original intent/delivery interval")
    return payload, issued, expires


def _verify_on_work(*, proof_bytes, enrollment_bytes, root_public_key, forbidden_public_keys,
        expected_scope, expected_release, expected_evidence, expected_intent_interval,
        live_window, transport_deadline_ns, work):
    """Authenticate a proof original; caller separately admits intent/possession."""
    held = _hold(proof_bytes=proof_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, forbidden_public_keys=forbidden_public_keys,
        expected_scope=expected_scope, expected_release=expected_release, expected_evidence=expected_evidence,
        expected_intent_interval=expected_intent_interval, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    current, narrow = _clock(held, work)
    current()
    enrolled = enrollments._admit_on_work(enrollment_bytes=held.enrollment,
        root_public_key=held.root, expected_scope=held.scope,
        forbidden_public_keys=held.forbidden, work=work)
    current()
    created, delivery_expiry = _release(held, current, work)
    policy = enrolled.payload
    age, skew = policy["maximumAgeNs"], min(policy["maximumClockSkewNs"], held.window[6])
    intent_issued, intent_expires = held.intent_interval
    narrow(min(delivery_expiry, intent_expires), age, skew)
    now = current()
    if created > now + skew or intent_issued > now + skew or now >= min(delivery_expiry, intent_expires):
        _fail("release proof delivery or original intent is future-dated or expired")
    payload, issued, expires = _authenticate_original(held, enrolled, current,
        created, delivery_expiry, skew, work)
    narrow(expires, age, skew)
    # The live closure retains private immutable lifetime scalars, not the
    # returned mutable diagnostics; changing output cannot extend its guard.
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}

    def live():
        now = current()
        evidence._fresh(interval, now, age, skew)
        if created > now + skew or intent_issued > now + skew or now >= min(delivery_expiry, intent_expires):
            _fail("release proof original intent/delivery is no longer live")
        return now

    live()
    digest = contract._digest(held.proof, work)
    live()
    owned = contract._capture(payload, work)
    live()
    return _AdmittedProof(owned, digest, live)


def _verify_historical_on_work(*, proof_bytes, enrollment_bytes, root_public_key,
        forbidden_public_keys, expected_scope, expected_release, expected_evidence,
        expected_intent_interval, live_window, transport_deadline_ns, work):
    """Authenticate original proof evidence, not a fresh intent or permission.

    The surrounding recovery composition genuinely admits the original intent,
    current old-token possession and a separate fresh root recovery purpose.
    Expired intent/proof intervals never clip or renew this processing window.
    """
    held = _hold(proof_bytes=proof_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, forbidden_public_keys=forbidden_public_keys,
        expected_scope=expected_scope, expected_release=expected_release, expected_evidence=expected_evidence,
        expected_intent_interval=expected_intent_interval, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    current, narrow = _clock(held, work)
    current()
    enrolled = enrollments._admit_on_work(enrollment_bytes=held.enrollment,
        root_public_key=held.root, expected_scope=held.scope,
        forbidden_public_keys=held.forbidden, work=work)
    current()
    created, delivery_expiry = _release(held, current, work)
    policy = enrolled.payload
    age, original_skew = policy["maximumAgeNs"], policy["maximumClockSkewNs"]
    processing_skew = min(original_skew, held.window[6])
    intent_issued, _intent_expires = held.intent_interval
    narrow(delivery_expiry, age, processing_skew)
    now = current()
    if created > now + processing_skew or intent_issued > now + processing_skew or now >= delivery_expiry:
        _fail("historical release proof evidence or live delivery is future-dated or expired")
    payload, issued, _expires = _authenticate_original(held, enrolled, current,
        created, delivery_expiry, original_skew, work)

    def live():
        now = current()
        if (issued > now + processing_skew or intent_issued > now + processing_skew
                or created > now + processing_skew or now >= delivery_expiry):
            _fail("historical release proof evidence or live delivery is no longer current")
        return now

    live()
    digest = contract._digest(held.proof, work)
    live()
    owned = contract._capture(payload, work)
    live()
    return _HistoricalProofEvidence(owned, digest, live)
