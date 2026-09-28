"""Original-only production of a distinct committed-release proof.

Fresh root custody and intent originals precede one genuine committed-original
verification. Only those same-call facts can be signed. No successful carrier,
payload override, release AES key, token opening or durable outcome is accepted.
"""
from __future__ import annotations

import time

from serverware import authority_oidc_session_activation_release_committed as committed
from serverware import authority_oidc_session_activation_release_intent as intent
from serverware import authority_oidc_session_activation_release_proof as verification
from serverware import authority_successor_execution_window as processing
from serverware import oidc_session_activation_release_custody_bootstrap as bootstrap
from serverware import oidc_session_activation_release_proof as contract
from serverware import oidc_session_activation_release_proof_enrollment as enrollments


inputs, custody, reader = committed.inputs, committed.custody, committed.reader
authorization, shape, plan = contract.authorization, contract.shape, contract.plan
capture, delivery, keys = contract.capture, contract.delivery, authorization.keys
MAX_ORIGINAL_BYTES = inputs.MAX_ORIGINAL_BYTES
MAX_GRAPH_BYTES = inputs.MAX_GRAPH_BYTES + enrollments.MAX_BYTES
MAX_GRAPH_NODES = inputs.MAX_GRAPH_NODES + enrollments.MAX_NODES + 8
MAX_GRAPH_DEPTH = inputs.MAX_GRAPH_DEPTH + 1


class ReleaseProofProductionError(ValueError):
    pass


def _fail(message):
    raise ReleaseProofProductionError(message)


class _Graphs(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_GRAPH_DEPTH or self.nodes >= MAX_GRAPH_NODES:
            _fail("release proof production graphs exceed their fixed bounds")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_GRAPH_NODES:
            _fail("release proof production graphs exceed their node bound")
        return owned


def _bytes_equal(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        _fail(label + " requires actual original bytes")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label + " differs")


def _unique_keys(values, work):
    """Deduplicate only these source-selected, actually held role keys."""
    held, digests = [], []
    for key in values:
        authorization._public(key)
        observed = keys._spki_on_work(key, work)
        duplicate = False
        for previous in digests:
            work.prepare_comparison(observed, previous)
            if observed == previous:
                duplicate = True
        if not duplicate:
            held.append(key)
            digests.append(observed)
    return tuple(held)


def _produce_on_work(*, packet_bytes, completion_request_bytes, state_receipt_bytes,
        expected_consume_binding, expected_release, expectations, planner_public_key,
        operation_public_key, root_public_key, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        configuration_digest, expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, historical_custody, commit_reader, live_window, transport_deadline_ns,
        release_custody_bytes, intent_bytes, intent_enrollment_bytes, proof_enrollment_bytes,
        proof_private_key, expected_proof_scope, expected_caller_id, old_token_bytes, work,
        _continuity=None):
    """Authenticate originals, replay once, then sign only derived facts."""
    signer = proof_private_key
    capture._SharedLedger(work)
    authorization._private(signer)
    # Hold every immutable original/key/owner reference before structural
    # ownership, and bound the complete input plus possible proof output.
    raw7 = tuple(authorization._original(raw, maximum, label) for raw, maximum, label in (
        (packet_bytes, inputs.packet.MAX_BYTES, "release proof consume packet"),
        (completion_request_bytes, inputs.records.MAX_REQUEST_BYTES, "release proof completion"),
        (state_receipt_bytes, inputs.records.MAX_RECEIPT_BYTES, "release proof state ACK"),
        (authorization_bytes, inputs.caller.MAX_AUTHORIZATION_BYTES, "release proof consume caller"),
        (authorization_enrollment_bytes, inputs.caller.MAX_ENROLLMENT_BYTES, "release proof caller enrollment"),
        (grant_enrollment_bytes, inputs.enrollments.MAX_ENROLLMENT_BYTES, "release proof grant enrollment"),
        (current_root_enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES, "release proof current-root enrollment")))
    extra = tuple(authorization._original(raw, maximum, label) for raw, maximum, label in (
        (release_custody_bytes, bootstrap.MAX_BYTES, "release proof root custody"),
        (intent_bytes, intent.contract.MAX_BYTES, "release proof intent"),
        (intent_enrollment_bytes, intent.enrollments.MAX_BYTES, "release proof intent enrollment"),
        (proof_enrollment_bytes, enrollments.MAX_BYTES, "release proof signer enrollment")))
    old_token = delivery._token(old_token_bytes, work)
    if sum(map(len, (*raw7, *extra, old_token))) + contract.MAX_BYTES > MAX_ORIGINAL_BYTES:
        _fail("release proof originals and reserved proof exceed the complete 64 MiB inventory")
    planner, operation_key, root = planner_public_key, operation_public_key, root_public_key
    owner, observer, caller_id = historical_custody, commit_reader, expected_caller_id
    authorization._token(caller_id)
    for key in (planner, operation_key, root):
        authorization._public(key)
    work.charge(input_bytes=sum(map(len, extra)))
    # One structural, callback-free pass owns ALL four mutable graphs. In
    # particular the proof scope is detached before committed capture hashes
    # any typed request. No separately opened work allowance is involved.
    graphs = _Graphs(capture._SharedLedger(work), maximum_bytes=MAX_GRAPH_BYTES).visit({
        "expectations": expectations, "release": expected_release,
        "binding": expected_consume_binding, "proofScope": expected_proof_scope})
    proof_scope = enrollments._scope(graphs["proofScope"], work)
    held = inputs._capture_on_work(packet_bytes=raw7[0], completion_request_bytes=raw7[1],
        state_receipt_bytes=raw7[2], expected_consume_binding=graphs["binding"],
        expected_release=graphs["release"], expectations=graphs["expectations"],
        planner_public_key=planner, operation_public_key=operation_key, root_public_key=root,
        authorization_bytes=raw7[3], authorization_enrollment_bytes=raw7[4],
        grant_enrollment_bytes=raw7[5], current_root_enrollment_bytes=raw7[6],
        configuration_digest=configuration_digest, expected_authorization_digest=expected_authorization_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, historical_custody=owner, commit_reader=observer,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    owner_type = custody.OidcSessionActivationDeliveryCompletionCustody
    owner_configuration = owner_type._snapshot_configuration(owner)
    window, bound = held.live_window, held.transport_deadline_ns
    _window, original_current = delivery._window(window, bound, work)
    guards = [original_current]
    last_epoch, last_monotonic = window[0], window[2]
    if _continuity is not None and not callable(_continuity):
        _fail("release proof producer restrictive continuity is not callable")

    def continue_owner():
        nonlocal last_epoch, last_monotonic
        if _continuity is None:
            return
        limits, before = work.limits, work.metrics
        ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
        observed = _continuity(last_epoch, last_monotonic)
        capture._SharedLedger(work)
        after = work.metrics
        if (work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                or after.json_nodes < before.json_nodes):
            _fail("release proof producer continuity reset its original allowance")
        if (type(observed) is not tuple or len(observed) != 2
                or any(type(value) is not int or value < 1 for value in observed)
                or observed[0] < last_epoch or observed[1] < last_monotonic
                or observed[0] >= window[3] or observed[1] >= bound):
            _fail("release proof producer continuity reversed or expired its narrowed clocks")
        last_epoch, last_monotonic = observed

    def identities():
        if owner_type._snapshot_configuration(owner) is not owner_configuration:
            _fail("release proof completion custody changed")
        if reader.CurrentRootCommitReader._snapshot_configuration(observer) is not held.reader_configuration:
            _fail("release proof commit reader changed")

    def current():
        nonlocal last_epoch, last_monotonic
        continue_owner()
        identities()
        for guard in (*guards, original_current):
            epoch = guard()
            shape._integer(epoch, minimum=1)
            if epoch < last_epoch:
                _fail("release proof processing clocks reversed across original authority")
            last_epoch = epoch
            if _continuity is not None:
                monotonic = contract.production._callback(work, time.monotonic_ns)
                shape._integer(monotonic, minimum=1)
                if monotonic < last_monotonic or monotonic >= bound:
                    _fail("release proof producer monotonic observations reversed or expired")
                last_monotonic = monotonic
        identities()
        continue_owner()
        return last_epoch

    def narrow(expiry, age, skew):
        nonlocal window, bound
        window = processing._narrow(window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
        bound = min(bound, window[4])
        _window, guarded = delivery._window(window, bound, work)
        guards.append(guarded)
        current()

    current()
    owner_type.require_completion_on_work(owner, work=work)
    current()
    owner_type.bind_context_on_work(owner, root_public_key=root,
        current_root_enrollment_bytes=held.current_root_enrollment_bytes, work=work)
    current()
    window, bound = owner_type.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    narrow(window[3], window[5], window[6])
    owner_live = owner_type.check_on_work(owner, live_window=window,
        transport_deadline_ns=bound, work=work)
    guards.append(owner_live)
    current()
    _bytes_equal(custody.neutral._identity(proof_scope["producerIdentity"], work),
        owner_configuration.receiver_identity_bytes, work, "release proof actual producer identity")
    current()
    material = bootstrap._verify_on_work(custody_bytes=extra[0], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    guards.append(bootstrap.planner_bootstrap._launch_guard(material.attestation_interval,
        material.opening_sample, original_current, work))
    narrow(material.attestation_interval[1], material.planner.maximum_plan_age_ns,
        material.planner.maximum_clock_skew_ns)
    _bytes_equal(material.planner.state_enrollment_bytes, held.current_root_enrollment_bytes,
        work, "release proof original planner/current-root enrollment")
    current()
    state = authorization._admit_enrollment_on_work(enrollment_bytes=held.current_root_enrollment_bytes,
        root_public_key=root, work=work)
    current()
    for actual, expected, label in (
            (state.enrollment_digest, material.planner.state_enrollment_digest, "state enrollment identity"),
            (material.planner.configuration_digest, held.configuration_digest, "configuration"),
            (material.planner.generation["digest"], held.expected_generation_digest, "planner generation"),
            (state.payload["generationDigest"], held.expected_generation_digest, "state generation"),
            (state.payload["databaseId"], held.expected_database_id, "database"),
            (proof_scope["configurationDigest"], held.configuration_digest, "proof configuration"),
            (proof_scope["databaseId"], held.expected_database_id, "proof database"),
            (proof_scope["generationDigest"], held.expected_generation_digest, "proof generation"),
            (proof_scope["runtimeClosureDigest"], material.planner.runtime_closure_digest, "runtime closure"),
            (proof_scope["receiverIdentity"], material.receiver_identity, "release receiver")):
        plan._same(actual, expected, work, "release proof independent " + label)
    root_release = {"activationRequestDigest": material.activation_request_digest,
        "activationOperationId": material.activation_operation_id,
        "consumeRequestDigest": material.consume_request_digest,
        "deliveryEnvelopeDigest": material.delivery_envelope_digest,
        "deliveryScope": material.delivery_scope, "consumeBinding": held.expected_consume_binding}
    plan._same(root_release, held.expected_release, work, "release proof root-pinned release target")
    intent_digest = intent.contract._digest(extra[1], work)
    plan._same(intent_digest, material.release_intent_digest, work, "release proof root-pinned intent")
    current()
    intent_scope = {"configurationDigest": material.planner.configuration_digest,
        "databaseId": state.payload["databaseId"], "generationDigest": material.planner.generation["digest"],
        "runtimeClosureDigest": material.planner.runtime_closure_digest, "callerId": caller_id,
        "receiverIdentity": material.receiver_identity}
    base_keys = (material.planner.planner_public_key, state.computation_public_key,
        state.completion_public_key, state.state_public_key)
    admitted_intent = intent._verify_on_work(intent_bytes=extra[1], enrollment_bytes=extra[2],
        root_public_key=root, forbidden_public_keys=base_keys, expected_scope=intent_scope,
        expected_release=held.expected_release, old_token_bytes=old_token,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=_continuity)
    if type(admitted_intent) is not intent._AdmittedIntent:
        _fail("release proof intent verification did not return genuine same-call facts")
    guards.append(admitted_intent.live)
    current()
    plan._same(admitted_intent.intent_digest, intent_digest, work, "release proof admitted intent original")
    # Obtain the actual caller key from the same immutable root enrollment.
    # This small enrollment admission does not repeat historical plan replay.
    intent_enrollment = intent.enrollments._admit_on_work(enrollment_bytes=extra[2],
        root_public_key=root, expected_scope=intent_scope, forbidden_public_keys=base_keys, work=work)
    current()
    forbidden = _unique_keys((*base_keys, intent_enrollment.caller_public_key, planner, operation_key), work)
    current()
    enrolled = enrollments._admit_on_work(enrollment_bytes=extra[3], root_public_key=root,
        expected_scope=proof_scope, forbidden_public_keys=forbidden, work=work)
    current()
    plan._same(enrolled.payload["proofKey"]["measurementDigest"],
        proof_scope["producerIdentity"]["measurementDigest"], work, "release proof actual producer measurement")
    keys._pair_on_work(signer, enrolled.proof_public_key, work)
    current()
    intent_interval = (admitted_intent.payload["issuedAtEpochNs"], admitted_intent.payload["expiresAtEpochNs"])
    _created, delivery_expiry = bootstrap._scope(material.delivery_scope, work)
    narrow(min(intent_interval[1], delivery_expiry),
        min(enrolled.payload["maximumAgeNs"], intent_enrollment.payload["maximumAgeNs"]),
        min(enrolled.payload["maximumClockSkewNs"], intent_enrollment.payload["maximumClockSkewNs"]))
    # This is the sole historical committed-original replay. All controls and
    # independent pins still come from originals, not a caller-supplied result.
    verified = committed._verify_on_work(packet_bytes=held.packet_bytes,
        completion_request_bytes=held.completion_request_bytes, state_receipt_bytes=held.state_receipt_bytes,
        expected_consume_binding=held.expected_consume_binding, expected_release=held.expected_release,
        expectations=held.expectations, planner_public_key=planner, operation_public_key=operation_key,
        root_public_key=root, authorization_bytes=held.authorization_bytes,
        authorization_enrollment_bytes=held.authorization_enrollment_bytes,
        grant_enrollment_bytes=held.grant_enrollment_bytes,
        current_root_enrollment_bytes=held.current_root_enrollment_bytes,
        configuration_digest=held.configuration_digest, expected_authorization_digest=held.expected_authorization_digest,
        expected_database_id=held.expected_database_id, expected_generation_digest=held.expected_generation_digest,
        expected_pending_sequence=held.expected_pending_sequence, expected_pending_head_digest=held.expected_pending_head_digest,
        expected_fence=held.expected_fence, historical_custody=owner, commit_reader=observer,
        live_window=window, transport_deadline_ns=bound, work=work)
    if type(verified) is not committed._CommittedOriginals:
        _fail("release proof requires genuine same-call committed-original facts")
    guards.append(verified.live)
    current()
    plan._same(verified.release_binding, held.expected_release, work, "release proof actual committed target")
    plan._same(verified.consume_binding, held.expected_consume_binding, work, "release proof actual consume identities")
    evidence = {"releaseCustodyDigest": plan._frame(contract.CUSTODY_IDENTITY_DOMAIN, (extra[0],), work),
        "releaseIntentDigest": admitted_intent.intent_digest, "stateReceiptDigest": verified.state_receipt_digest}
    issued = current()
    expires = min(window[3], material.attestation_interval[1], intent_interval[1],
        delivery_expiry, issued + enrolled.payload["maximumAgeNs"])
    if issued >= expires:
        _fail("release proof has no remaining original authority lifetime")
    payload = {"schema": contract.PAYLOAD_SCHEMA, "sourceRevision": contract.authority.SOURCE_REVISION,
        "purpose": contract.PURPOSE, "enrollmentDigest": enrolled.enrollment_digest,
        "producerMeasurementDigest": enrolled.payload["proofKey"]["measurementDigest"],
        **proof_scope, **verified.release_binding, **evidence,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    current()
    original = contract._sign(payload, private_key=signer, public_key=enrolled.proof_public_key, work=work)
    current()
    received = verification._verify_on_work(proof_bytes=original, enrollment_bytes=extra[3],
        root_public_key=root, forbidden_public_keys=forbidden, expected_scope=proof_scope,
        expected_release=verified.release_binding, expected_evidence=evidence,
        expected_intent_interval=intent_interval, live_window=window, transport_deadline_ns=bound,
        work=work, _continuity=_continuity)
    if type(received) is not verification._AdmittedProof:
        _fail("release proof signed output did not pass genuine receiving verification")
    guards.append(received.live)
    current()
    plan._same(received.payload, payload, work, "release proof signed output differs from derived facts")
    current()
    return original
