"""Original release intent and possession, never committed release proof.

Actual root enrollment and caller signatures are checked against independent
scope. The five consumption identities remain expected bindings, not evidence
of SQL, completion or current session state. The distinct historical entrypoint
authenticates evidence only, never present permission. No token opening occurs.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import secrets
import time

from catchplate import oidc_session_activation_release_intent as contract
from catchplate import oidc_session_activation_release_intent_enrollment as enrollments
from catchplate import authority_successor_execution_window as processing


authorization, shape, plan = contract.authorization, contract.shape, contract.plan
capture, production, clock = contract.capture, contract.production, contract.clock
bootstrap, delivery = contract.bootstrap, contract.delivery
evidence, registration = delivery.registration.evidence, delivery.registration
SCOPE_FIELDS = enrollments.SCOPE_FIELDS
RELEASE_FIELDS = frozenset({"activationRequestDigest", "activationOperationId",
    "consumeRequestDigest", "deliveryEnvelopeDigest", "deliveryScope", "consumeBinding"})
MAX_BYTES = contract.MAX_BYTES
MAX_ORIGINAL_BYTES = contract.MAX_BYTES + enrollments.MAX_BYTES + delivery.TOKEN_BYTES


class OidcSessionActivationReleaseIntentAdmissionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseIntentAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedIntent:
    """Ordinary output only; no API accepts it as release authority."""
    payload: dict
    intent_digest: str
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalIntentEvidence:
    """Original evidence only; current guard does not renew caller permission."""
    payload: dict
    intent_digest: str
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalIntentTarget:
    """Authenticated target/possession only, never full release admission."""

    intent_digest: str
    delivery_scope: dict
    old_token_digest: str
    live_window: tuple
    deadline_ns: int
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _TargetClock:
    # No token reference is retained by the returned lifetime closure.
    window: tuple
    deadline_ns: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Held:
    intent: bytes | None
    enrollment: bytes
    root: object
    forbidden: tuple
    scope: dict
    release: dict
    old_token: bytes
    window: tuple
    deadline_ns: int


def _closed(value, fields, label):
    if type(value) is not dict or len(value) != len(fields):
        _fail(label + " is not a closed exact object")
    if any(type(name) is not str or name not in fields for name in value):
        _fail(label + " contains an unknown field")


def _scalars(value, limits, label):
    """Detach fixed scalar maps without native callbacks or user coercion."""
    _closed(value, frozenset(limits), label)
    owned = {}
    for name, maximum in limits.items():
        scalar = value[name]
        if type(scalar) is not str or not 1 <= len(scalar) <= maximum:
            _fail(label + " contains an invalid scalar")
        owned[name] = scalar
    return owned


def _graphs(scope, release):
    # Both whole graphs must be detached before the first metered capture can
    # reach canonical hashing/native callbacks. No external nested reference
    # survives these fixed, non-coercing copies.
    _closed(scope, SCOPE_FIELDS, "release intent independent scope")
    _closed(release, RELEASE_FIELDS, "release intent independent release")
    scope_scalars = {name: scope[name] for name in SCOPE_FIELDS if name != "receiverIdentity"}
    owned_scope = _scalars(scope_scalars, {name: (128 if name in ("callerId", "databaseId") else 71)
        for name in scope_scalars}, "release intent scope scalars")
    owned_scope["receiverIdentity"] = _scalars(scope["receiverIdentity"],
        {name: 71 for name in bootstrap.planner_bootstrap._IDENTITY_FIELDS}, "release intent receiver")
    release_scalars = {name: release[name] for name in RELEASE_FIELDS
        if name not in ("deliveryScope", "consumeBinding")}
    owned_release = _scalars(release_scalars, {name: 71 for name in release_scalars},
        "release intent release scalars")
    owned_release["deliveryScope"] = _scalars(release["deliveryScope"], delivery._SCOPE_LIMITS,
        "release intent delivery scope")
    owned_release["consumeBinding"] = _scalars(release["consumeBinding"],
        {name: 71 for name in contract.CONSUME_BINDING_FIELDS}, "release intent consume binding")
    return owned_scope, owned_release


def _hold(*, intent_bytes, enrollment_bytes, root_public_key, forbidden_public_keys,
        expected_scope, expected_release, old_token_bytes, live_window, transport_deadline_ns, work):
    capture._SharedLedger(work)
    original = (None if intent_bytes is None else authorization._original(
        intent_bytes, contract.MAX_BYTES, "release intent original"))
    enrolled = authorization._original(enrollment_bytes, enrollments.MAX_BYTES,
        "release intent enrollment original")
    root, forbidden = root_public_key, forbidden_public_keys
    authorization._public(root)
    if type(forbidden) is not tuple or not 1 <= len(forbidden) <= enrollments.MAX_FORBIDDEN_PUBLIC_KEYS:
        _fail("release intent requires the fixed bounded tuple of independent role keys")
    for key in forbidden:
        authorization._public(key)
    token = delivery._token(old_token_bytes, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    scope, release = _graphs(expected_scope, expected_release)
    total = len(enrolled) + len(token) + (0 if original is None else len(original))
    if total > MAX_ORIGINAL_BYTES:
        _fail("release intent originals exceed the fixed aggregate bound")
    work.charge(input_bytes=total)
    copier = contract._Capture(capture._SharedLedger(work), maximum_bytes=contract.MAX_BYTES)
    scope, release = copier.visit(scope), copier.visit(release)
    return _Held(original, enrolled, root, forbidden, scope, release, token, window, bound)


def _clock(held, work, continuity=None):
    window, bound = held.window, held.deadline_ns
    last_epoch, last_monotonic = window[0], window[2]
    if continuity is not None and not callable(continuity):
        _fail("release intent restrictive continuity is not callable")

    def continue_owner():
        nonlocal last_epoch, last_monotonic
        if continuity is None:
            return
        limits, before = work.limits, work.metrics
        ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
        observed = continuity(last_epoch, last_monotonic)
        capture._SharedLedger(work)
        after = work.metrics
        if (work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                or after.json_nodes < before.json_nodes):
            _fail("release intent continuity reset the original work")
        if (type(observed) is not tuple or len(observed) != 2
                or any(type(value) is not int or value < 1 for value in observed)
                or observed[0] < last_epoch or observed[1] < last_monotonic):
            _fail("release intent continuity lowered its actual clock floors")
        if observed[0] >= window[3] or observed[1] >= bound:
            _fail("release intent continuity crossed the current narrowed deadline")
        last_epoch, last_monotonic = observed

    def current():
        nonlocal last_epoch, last_monotonic
        continue_owner()
        now = clock._check_on_work(window, work=work)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("release intent original processing clocks expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        continue_owner()
        return last_epoch

    def narrow(expiry, age, skew):
        nonlocal window, bound
        window = processing._narrow(window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
        bound = min(bound, window[4])
        return window

    return current, narrow


def _release(held, current, work):
    """Validate independent identities, not the consumption they identify."""
    release = held.release
    for name in RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}:
        shape._digest(release[name])
    for value in release["consumeBinding"].values():
        shape._digest(value)
    created, expires = bootstrap._scope(release["deliveryScope"], work)
    current()
    operation = plan._frame("catchplate.policyAuthorityOperation/v2",
        (plan._ascii(bootstrap.ACTIVATION_OPERATION, work),
            plan._ascii(release["activationRequestDigest"], work)), work)
    current()
    plan._same(operation, release["activationOperationId"], work,
        "release intent independently expected activation operation")
    delivery_id = registration.core._deterministic_uuid(operation=bootstrap.ACTIVATION_OPERATION,
        request_digest=release["activationRequestDigest"], purpose="activation-delivery", work=work)
    current()
    plan._same(delivery_id, release["deliveryScope"]["deliveryId"], work,
        "release intent independently expected deterministic delivery")
    return created, expires


def _admit(held, work, continuity=None):
    current, narrow = _clock(held, work, continuity=continuity)
    current()
    enrolled = enrollments._admit_on_work(enrollment_bytes=held.enrollment,
        root_public_key=held.root, expected_scope=held.scope,
        forbidden_public_keys=held.forbidden, work=work)
    current()
    created, expires = _release(held, current, work)
    age, skew = enrolled.payload["maximumAgeNs"], enrolled.payload["maximumClockSkewNs"]
    window = narrow(expires, age, skew)
    now = current()
    if created > now + window[6] or now >= expires:
        _fail("release intent delivery is future-created or expired")
    observed_token = delivery._token_digest(held.old_token, work, current)
    plan._same(observed_token, held.release["deliveryScope"]["oldTokenDigest"], work,
        "release intent requires the actual old-token original")
    current()
    return enrolled, current, narrow, created, expires, window


def _authenticate_original(held, original, enrolled, current, created, delivery_expiry, work):
    """Shared original signature, exact bindings and original interval algebra."""
    current()
    envelope = contract._read(original, work)
    current()
    contract._signature(envelope, enrolled.caller_public_key, work)
    current()
    payload, policy = envelope["payload"], enrolled.payload
    for name in SCOPE_FIELDS:
        plan._same(payload[name], held.scope[name], work, "release intent independent " + name)
    for name in RELEASE_FIELDS:
        plan._same(payload[name], held.release[name], work, "release intent exact " + name)
    plan._same(payload["enrollmentDigest"], enrolled.enrollment_digest, work,
        "release intent original caller enrollment")
    plan._same(payload["callerMeasurementDigest"], policy["callerKey"]["measurementDigest"], work,
        "release intent enrolled caller measurement")
    age, skew = policy["maximumAgeNs"], policy["maximumClockSkewNs"]
    authorization._interval(payload, age)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if expires > delivery_expiry or issued + skew < created:
        _fail("release intent escapes the original delivery interval")
    return payload, age, skew, issued, expires


def _verify_original(held, original, enrolled, current, narrow, created, delivery_expiry, work):
    payload, age, skew, issued, expires = _authenticate_original(held, original,
        enrolled, current, created, delivery_expiry, work)
    narrow(expires, age, skew)
    # Keep the guard's lifetime private and detached from the ordinary mutable
    # output payload. Mutating returned diagnostics cannot renew authority.
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}

    def live():
        now = current()
        evidence._fresh(interval, now, age, skew)
        if created > now + min(skew, held.window[6]) or now >= delivery_expiry:
            _fail("release intent original delivery is not live")
        return now

    live()
    identity = contract._digest(original, work)
    live()
    owned = contract._capture(payload, work)
    live()
    return _AdmittedIntent(owned, identity, live)


def _verify_on_work(*, intent_bytes, enrollment_bytes, root_public_key, forbidden_public_keys,
        expected_scope, expected_release, old_token_bytes, live_window, transport_deadline_ns, work,
        _continuity=None):
    """Authenticate fresh intent and possession, not committed consumption."""
    held = _hold(intent_bytes=intent_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, forbidden_public_keys=forbidden_public_keys,
        expected_scope=expected_scope, expected_release=expected_release, old_token_bytes=old_token_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    if held.intent is None:
        _fail("release intent requires its actual signed original")
    enrolled, current, narrow, created, expires, _window = _admit(held, work, continuity=_continuity)
    return _verify_original(held, held.intent, enrolled, current, narrow, created, expires, work)


def _verify_historical_on_work(*, intent_bytes, enrollment_bytes, root_public_key,
        forbidden_public_keys, expected_scope, expected_release, old_token_bytes,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Authenticate old intent evidence and current possession, not permission.

    A separate fresh root recovery purpose must admit the unchanged outcome.
    Original intent expiry/age are authenticated algebra, never a replacement
    processing clock or current deadline. Delivery itself must remain live.
    """
    held = _hold(intent_bytes=intent_bytes, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, forbidden_public_keys=forbidden_public_keys,
        expected_scope=expected_scope, expected_release=expected_release, old_token_bytes=old_token_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    if held.intent is None:
        _fail("historical release intent requires its actual signed original")
    enrolled, current, _narrow, created, delivery_expiry, _window = _admit(
        held, work, continuity=_continuity)
    payload, _age, original_skew, issued, _expires = _authenticate_original(
        held, held.intent, enrolled, current, created, delivery_expiry, work)
    processing_skew = min(original_skew, held.window[6])

    def live():
        now = current()
        if (issued > now + processing_skew or created > now + processing_skew
                or now >= delivery_expiry):
            _fail("historical release intent evidence or live delivery is future-dated or expired")
        return now

    live()
    identity = contract._digest(held.intent, work)
    live()
    owned = contract._capture(payload, work)
    live()
    return _HistoricalIntentEvidence(owned, identity, live)


def _inspect_historical_target_on_work(*, intent_bytes, enrollment_bytes,
        root_public_key, forbidden_public_keys, expected_scope, expected_target,
        expected_caller_public_key, expected_enrollment_digest, old_token_bytes,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Authenticate one historical target, not expected release/consume claims.

    The independent target comes from genuine finalization replay. The other
    signed release fields are deliberately NOT supplied back as expectations
    to the full intent verifier. Fresh recovery permission and full original
    outcome admission remain separate obligations.
    """
    capture._SharedLedger(work)
    original = authorization._original(intent_bytes, MAX_BYTES, "historical target intent")
    enrollment = authorization._original(enrollment_bytes, enrollments.MAX_BYTES,
        "historical target independent intent enrollment")
    root, caller, forbidden = root_public_key, expected_caller_public_key, forbidden_public_keys
    authorization._public(root)
    authorization._public(caller)
    if type(forbidden) is not tuple or not 1 <= len(forbidden) <= enrollments.MAX_FORBIDDEN_PUBLIC_KEYS:
        _fail("historical target requires independently held purpose keys")
    for key in forbidden:
        authorization._public(key)
    enrollment_digest = expected_enrollment_digest
    shape._digest(enrollment_digest)
    _closed(expected_target, frozenset({"userId", "sessionId", "credentialId"}),
        "historical target independent finalization subject")
    target = _scalars(expected_target,
        {"userId": 1024, "sessionId": 128, "credentialId": 1366}, "historical target subject")
    scope = enrollments._scope(expected_scope, work)
    token = delivery._token(old_token_bytes, work)
    if len(original) + len(enrollment) + len(token) > MAX_ORIGINAL_BYTES:
        _fail("historical target originals exceed their fixed bound")
    work.charge(input_bytes=len(original) + len(enrollment) + len(token))
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, narrow = _clock(_TargetClock(window, bound), work, continuity=_continuity)
    current()
    enrolled = enrollments._admit_on_work(enrollment_bytes=enrollment,
        root_public_key=root, expected_scope=scope, forbidden_public_keys=forbidden, work=work)
    current()
    plan._same(enrolled.enrollment_digest, enrollment_digest, work,
        "historical target actual cold enrollment original")
    plan._same(enrollments.keys._spki_on_work(enrolled.caller_public_key, work),
        enrollments.keys._spki_on_work(caller, work), work,
        "historical target actual cold intent public key")
    current()
    envelope = contract._read(original, work)
    current()
    contract._signature(envelope, enrolled.caller_public_key, work)
    current()
    payload, policy = envelope["payload"], enrolled.payload
    for name in SCOPE_FIELDS:
        plan._same(payload[name], scope[name], work, "historical target independent " + name)
    plan._same(payload["enrollmentDigest"], enrolled.enrollment_digest, work,
        "historical target signed enrollment")
    plan._same(payload["callerMeasurementDigest"], policy["callerKey"]["measurementDigest"], work,
        "historical target signed caller measurement")
    delivery_scope = _scalars(payload["deliveryScope"], delivery._SCOPE_LIMITS,
        "historical target authenticated delivery scope")
    created, expires = bootstrap._scope(delivery_scope, work)
    for name in target:
        plan._same(delivery_scope[name], target[name], work,
            "historical target independently replayed " + name)
    # These are consistency checks over authenticated historical claims, not
    # independently proven activation/consume execution or release authority.
    operation = plan._frame("catchplate.policyAuthorityOperation/v2",
        (plan._ascii(bootstrap.ACTIVATION_OPERATION, work),
            plan._ascii(payload["activationRequestDigest"], work)), work)
    plan._same(operation, payload["activationOperationId"], work,
        "historical target activation operation consistency")
    delivery_id = registration.core._deterministic_uuid(operation=bootstrap.ACTIVATION_OPERATION,
        request_digest=payload["activationRequestDigest"], purpose="activation-delivery", work=work)
    plan._same(delivery_id, delivery_scope["deliveryId"], work,
        "historical target deterministic delivery consistency")
    age, skew = policy["maximumAgeNs"], policy["maximumClockSkewNs"]
    authorization._interval(payload, age)
    issued, intent_expiry = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if intent_expiry > expires or issued + skew < created:
        _fail("historical target intent escapes its original delivery interval")
    window = narrow(expires, age, skew)
    bound = min(bound, window[4])
    current()
    token_digest = delivery._token_digest(token, work, current)
    plan._same(token_digest, delivery_scope["oldTokenDigest"], work,
        "historical target original old-token possession")
    del token
    identity = contract._digest(original, work)
    fields = tuple(sorted(delivery._SCOPE_LIMITS))
    sealed_scope = tuple(delivery_scope[name] for name in fields)

    def live():
        if (type(delivery_scope) is not dict or set(delivery_scope) != set(fields)
                or tuple(delivery_scope[name] for name in fields) != sealed_scope):
            _fail("historical target returned delivery scope changed")
        now = current()
        if issued > now + window[6] or created > now + window[6] or now >= expires:
            _fail("historical target evidence is future-dated or original delivery expired")
        return now

    live()
    return _HistoricalIntentTarget(identity, delivery_scope, token_digest, window, bound, live)


def _produce_on_work(*, enrollment_bytes, root_public_key, forbidden_public_keys,
        expected_scope, expected_release, old_token_bytes, caller_private_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Sign one fresh nonce after genuine enrollment, bindings and possession.

    Independent present permission is a caller obligation. This constructs no
    commit/completion proof and accepts no caller-selected nonce or issue time.
    """
    signer = caller_private_key
    authorization._private(signer)
    held = _hold(intent_bytes=None, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, forbidden_public_keys=forbidden_public_keys,
        expected_scope=expected_scope, expected_release=expected_release, old_token_bytes=old_token_bytes,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    enrolled, current, narrow, created, delivery_expiry, window = _admit(held, work, continuity=_continuity)
    enrollments.keys._pair_on_work(signer, enrolled.caller_public_key, work)
    current()
    work.charge(input_bytes=contract.NONCE_BYTES + 44 + 43)
    nonce = production._callback(work, lambda: secrets.token_bytes(contract.NONCE_BYTES))
    current()
    if type(nonce) is not bytes or len(nonce) != contract.NONCE_BYTES or nonce == bytes(contract.NONCE_BYTES):
        _fail("release intent nonce generation failed")
    encoded_nonce = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    issued = current()
    policy = enrolled.payload
    expires = min(window[3], delivery_expiry, issued + policy["maximumAgeNs"])
    if issued >= expires:
        _fail("release intent has no remaining original lifetime")
    payload = {"schema": contract.PAYLOAD_SCHEMA, "sourceRevision": contract.authority.SOURCE_REVISION,
        "purpose": contract.PURPOSE, "enrollmentDigest": enrolled.enrollment_digest,
        "callerMeasurementDigest": policy["callerKey"]["measurementDigest"],
        **held.scope, **held.release, "intentNonce": encoded_nonce,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    original = contract._sign(payload, private_key=signer, public_key=enrolled.caller_public_key, work=work)
    current()
    if len(original) + len(held.enrollment) + len(held.old_token) > MAX_ORIGINAL_BYTES:
        _fail("release intent signed originals exceed their aggregate bound")
    # Genuine fixed signature/readback and exact joins share this invocation's
    # original sticky guard and admitted enrollment; no new clock or allowance.
    result = _verify_original(held, original, enrolled, current, narrow, created, delivery_expiry, work)
    result.live()
    return original
