"""Original-consuming private release response verification, without AES.

Fresh independent client authority pins the original server bootstrap, request
and outcome. Actual intent/proof admission authenticates the token commitment;
recovery uses separately authorized historical evidence, never renewed intent.
No socket, store, successful material input or durable-delivery claim exists.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time

from serverware import oidc_session_activation_release_client_authorization as clients
from serverware import oidc_session_activation_release_transport as transport
from serverware import authority_oidc_session_activation_release_intent as intents
from serverware import authority_oidc_session_activation_release_proof as proofs
from serverware import oidc_session_activation_release_outcome as outcomes


authorization, shape, plan = clients.authorization, clients.shape, clients.plan
capture, production, clock = clients.capture, clients.production, clients.clock
delivery, processing, server = clients.delivery, clients.processing, clients.server
intent_keys, proof_keys = intents.enrollments, proofs.enrollments
MAX_ORIGINAL_BYTES = clients.authority.MAX_RESULT_BYTES


class OidcSessionActivationReleaseResponseError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseResponseError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Held:
    """Detached ordinary inputs, never an accepted verification result."""

    response: tuple
    request: tuple
    client_authorization: bytes
    server_bootstrap: bytes
    root_public_key: object
    scope: dict
    window: tuple
    deadline_ns: int


def _hold(*, response_originals, request_originals, client_authorization_bytes,
        server_bootstrap_bytes, root_public_key, expected_client_scope,
        live_window, transport_deadline_ns, work):
    capture._SharedLedger(work)
    response = transport._originals(response_originals, response=True)
    # Hold a bounded immutable inventory before capturing the one mutable scope.
    # Its count does not select permission; the independently pinned profile is
    # joined below before any authentication or request identity computation.
    if type(request_originals) is not tuple or len(request_originals) not in (7, 8):
        _fail("release response requires the complete original raw7 or raw8 request")
    request = request_originals
    maxima = transport.RECOVERY_REQUEST_LIMITS
    for index, raw in enumerate(request):
        if type(raw) is not bytes or not 2 <= len(raw) <= maxima[index]:
            _fail("release response request original exceeds its fixed field bound")
    if len(request[5]) != delivery.TOKEN_BYTES or len(request[6]) != delivery.ENVELOPE_BYTES:
        _fail("release response requires exact old-token and ciphertext originals")
    client = authorization._original(client_authorization_bytes, clients.MAX_BYTES,
        "release client authorization original")
    bootstrap = authorization._original(server_bootstrap_bytes, clients.MAX_SERVER_BOOTSTRAP_BYTES,
        "release server bootstrap original")
    root = root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    header_bytes = 8 + 8 * len(request) + transport.RESPONSE_HEADER_BYTES
    total = sum(len(raw) for raw in (*request, *response, client, bootstrap)) + header_bytes
    if total > MAX_ORIGINAL_BYTES:
        _fail("release response complete original inventory exceeds its aggregate bound")
    work.charge(input_bytes=total)
    # Every other external original, key reference and lifetime scalar is held
    # before this whole-graph capture or any subsequent native/hash callback.
    scope = clients._scope(expected_client_scope, work)
    request = transport._originals(request, response=False, profile=scope["profile"])
    return _Held(response, request, client, bootstrap, root, scope, window, bound)


def _lifetime(held, work, continuity=None):
    window, bound = held.window, held.deadline_ns
    _original, original_current = delivery._window(window, bound, work)
    guards = [original_current]
    last_epoch, last_monotonic = window[0], window[2]
    if continuity is not None and not callable(continuity):
        _fail("release response restrictive owner continuity is not callable")

    def continue_owner():
        nonlocal last_epoch, last_monotonic
        if continuity is None:
            return
        limits, before = work.limits, work.metrics
        ceiling = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
        # This can only add a restriction. No result is consumed as authority;
        # all mandatory original guards and admission paths still run below.
        observed = continuity(last_epoch, last_monotonic)
        capture._SharedLedger(work)
        after = work.metrics
        if (work.limits is not limits
                or ceiling != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                or after.json_nodes < before.json_nodes):
            _fail("release response owner continuity reset its original work")
        if (type(observed) is not tuple or len(observed) != 2
                or any(type(value) is not int or value < 1 for value in observed)
                or observed[0] < last_epoch or observed[1] < last_monotonic):
            _fail("release response owner continuity lowered its retained clock floors")
        if observed[0] >= window[3] or observed[1] >= bound:
            _fail("release response owner continuity exceeded its narrowed deadline")
        last_epoch, last_monotonic = observed

    def current():
        nonlocal last_epoch, last_monotonic
        capture._SharedLedger(work)
        continue_owner()
        # Keep cross-stage maxima; a newly attached guard cannot hide a rollback
        # behind its own older original opening or a different guard's sample.
        for guard in (*guards, original_current):
            observed = guard()
            shape._integer(observed, minimum=1)
            monotonic = production._callback(work, time.monotonic_ns)
            shape._integer(monotonic, minimum=1)
            if observed < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                _fail("release response original clocks expired or reversed across admission")
            last_epoch, last_monotonic = observed, monotonic
            continue_owner()
        return last_epoch

    def attach(guard):
        current()
        if not callable(guard):
            _fail("release response genuine original admission lacks its live guard")
        guards.append(guard)
        current()

    def narrow(candidate, deadline):
        nonlocal window, bound
        actual = clock._validate(candidate)
        shape._integer(deadline, minimum=1)
        if (actual[:3] != window[:3]
                or any(value > prior for prior, value in zip(window[3:], actual[3:]))
                or deadline > bound or deadline > actual[4]):
            _fail("release response cannot renew its original processing allowance")
        current()
        window, bound = actual, deadline
        _narrowed, check = delivery._window(window, bound, work)
        guards.append(check)
        current()
        return window, bound

    current()
    return current, attach, narrow


def _same_bytes(observed, expected, work, label):
    if type(observed) is not bytes or type(expected) is not bytes:
        _fail(label + " requires exact original bytes")
    work.charge(input_bytes=len(observed) + len(expected))
    if observed != expected:
        _fail(label + " differs")


def _state_keys(held, material, current, work):
    original = material.custody_material.planner
    current()
    # Limited root-enrollment readback obtains actual exclusion keys. It does
    # not repeat the original planner/history, intent or proof admission.
    state = authorization._admit_enrollment_on_work(
        enrollment_bytes=original.state_enrollment_bytes,
        root_public_key=held.root_public_key, work=work)
    current()
    for observed, expected in ((state.enrollment_digest, original.state_enrollment_digest),
            (state.payload["databaseId"], held.scope["databaseId"]),
            (state.payload["generationDigest"], held.scope["generationDigest"])):
        plan._same(observed, expected, work, "release response original state enrollment")
    current()
    return (original.planner_public_key, state.computation_public_key,
        state.completion_public_key, state.state_public_key)


def _verify_on_work(*, response_originals, request_originals,
        client_authorization_bytes, server_bootstrap_bytes, root_public_key,
        expected_client_scope, live_window, transport_deadline_ns, work, _continuity=None):
    """Return exact token64 only after genuine same-call public-original checks.

    This is standalone receiving verification, not a transport/caller owner.
    The request echo alone authenticates nothing, and even a correct token does
    not prove storage, service execution, recipient acknowledgment or one egress.
    """
    held = _hold(response_originals=response_originals, request_originals=request_originals,
        client_authorization_bytes=client_authorization_bytes,
        server_bootstrap_bytes=server_bootstrap_bytes, root_public_key=root_public_key,
        expected_client_scope=expected_client_scope, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    current, attach, narrow = _lifetime(held, work, _continuity)
    current()
    client = clients._verify_on_work(authorization_bytes=held.client_authorization,
        server_bootstrap_bytes=held.server_bootstrap, root_public_key=held.root_public_key,
        expected_scope=held.scope, live_window=held.window,
        transport_deadline_ns=held.deadline_ns, work=work)
    if type(client) is not clients._ClientAuthorization:
        _fail("release response requires the actual same-call client original admission")
    attach(client.live)
    window, bound = narrow(client.live_window, client.deadline_ns)
    material = client.server_material
    if type(material) is not server._ReleaseMaterial:
        _fail("release response lacks its genuinely admitted server originals")
    scope, request = held.scope, held.request
    profile = scope["profile"]
    historical = profile == server.RECOVERY_PROFILE
    plan._same(material.profile, profile, work, "release response independently selected profile")
    identity = transport._request_identity_on_work(request, profile=profile,
        deadline_ns=bound, work=work, current=current)
    expected_identity = plan._ascii(scope["requestIdentity"], work)
    _same_bytes(identity, expected_identity, work, "release response independently pinned request identity")
    _same_bytes(held.response[0], identity, work, "release response exact request echo")
    current()

    forbidden = _state_keys(held, material, current, work)
    expected_release = scope["expectedRelease"]
    intent_scope = {name: scope[name] for name in intent_keys.SCOPE_FIELDS}
    proof_scope = {name: scope[name] for name in proof_keys.SCOPE_FIELDS}
    custody_digest = plan._frame(proofs.contract.CUSTODY_IDENTITY_DOMAIN,
        (material.custody_bytes,), work)
    plan._same(custody_digest, material.storage_scope["releaseCustodyDigest"], work,
        "release response exact original custody")
    envelope = delivery._envelope(request[6], work)
    work.charge(hashes=1, input_bytes=len(envelope))
    current()
    envelope_digest = production._callback(work,
        lambda: "sha256:" + hashlib.sha256(envelope).hexdigest())
    current()
    plan._same(envelope_digest, expected_release["deliveryEnvelopeDigest"], work,
        "release response exact original ciphertext")

    verify_intent = intents._verify_historical_on_work if historical else intents._verify_on_work
    current()
    intent = verify_intent(intent_bytes=request[3], enrollment_bytes=request[4],
        root_public_key=held.root_public_key, forbidden_public_keys=forbidden,
        expected_scope=intent_scope, expected_release=expected_release,
        old_token_bytes=request[5], live_window=window, transport_deadline_ns=bound, work=work)
    expected_intent_type = intents._HistoricalIntentEvidence if historical else intents._AdmittedIntent
    if type(intent) is not expected_intent_type:
        _fail("release response requires genuine original intent and possession admission")
    attach(intent.live)
    plan._same(intent.intent_digest, material.custody_material.release_intent_digest, work,
        "release response root-pinned original intent")
    current()
    enrolled_intent = intent_keys._admit_on_work(enrollment_bytes=request[4],
        root_public_key=held.root_public_key, expected_scope=intent_scope,
        forbidden_public_keys=forbidden, work=work)
    current()
    plan._same(enrolled_intent.enrollment_digest, intent.payload["enrollmentDigest"], work,
        "release response actual intent public-key enrollment")
    # Live execution clips to the fresh original intent. Historical recovery
    # deliberately does not use the expired intent/proof interval as permission.
    if not historical:
        candidate = processing._narrow(window, deadline_epoch_ns=intent.payload["expiresAtEpochNs"],
            maximum_lifetime_ns=enrolled_intent.payload["maximumAgeNs"],
            maximum_clock_skew_ns=enrolled_intent.payload["maximumClockSkewNs"])
        window, bound = narrow(candidate, min(bound, candidate[4]))
    evidence = {"releaseCustodyDigest": custody_digest, "releaseIntentDigest": intent.intent_digest,
        "stateReceiptDigest": scope["stateReceiptDigest"]}
    verify_proof = proofs._verify_historical_on_work if historical else proofs._verify_on_work
    current()
    proof = verify_proof(proof_bytes=request[1], enrollment_bytes=request[2],
        root_public_key=held.root_public_key,
        forbidden_public_keys=(*forbidden, enrolled_intent.caller_public_key),
        expected_scope=proof_scope, expected_release=expected_release, expected_evidence=evidence,
        expected_intent_interval=(intent.payload["issuedAtEpochNs"], intent.payload["expiresAtEpochNs"]),
        live_window=window, transport_deadline_ns=bound, work=work)
    expected_proof_type = proofs._HistoricalProofEvidence if historical else proofs._AdmittedProof
    if type(proof) is not expected_proof_type:
        _fail("release response requires genuine original proof admission")
    attach(proof.live)
    if not historical:
        candidate = processing._narrow(window, deadline_epoch_ns=proof.payload["expiresAtEpochNs"],
            maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
        window, bound = narrow(candidate, min(bound, candidate[4]))

    current()
    record = outcomes._encode_on_work(
        scope={name: proof.payload[name] for name in outcomes.SCOPE_FIELDS},
        release_binding={name: proof.payload[name] for name in outcomes.RELEASE_FIELDS},
        evidence_binding={**evidence, "releaseProofDigest": proof.proof_digest,
            "proofEnrollmentDigest": proof.payload["enrollmentDigest"],
            "intentEnrollmentDigest": intent.payload["enrollmentDigest"]},
        caller_id=intent.payload["callerId"], work=work)
    current()
    outcome_digest = outcomes._digest_on_work(record, work)
    current()
    plan._same(outcome_digest, scope["expectedOutcomeDigest"], work,
        "release response independently pinned original-derived outcome")
    if historical:
        if material.recovery_scope is None:
            _fail("release response recovery lacks its separate fresh root purpose")
        plan._same(outcome_digest, material.recovery_scope["outcomeDigest"], work,
            "release response fresh recovery exact outcome")
        plan._same(material.storage_scope["checkpoint"],
            {"recordCount": 1, "outcomeDigest": outcome_digest}, work,
            "release response independently authorized recovery checkpoint")
        _same_bytes(request[7], record, work, "release response original-derived recovery record")
    current()
    token = delivery._token(held.response[1], work)
    token_digest = delivery._token_digest(token, work, current)
    plan._same(token_digest, expected_release["deliveryScope"]["newTokenDigest"], work,
        "release response authenticated exact token commitment")
    current()
    return token
