"""Root-original release-proof setup derivation, not private proof or replay.

The consume packet must come from a separately authorized private acquisition.
It is never a public request field. Exact root-pinned packet data and signed
completion/ACK/intent originals derive the new custody and proof bootstrap.
No old token, private history key, resource observation or successful DTO enters.
"""
from __future__ import annotations

from serverware import authority_current_root_delivery_records as records
from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import authority_oidc_session_activation_delivery_recovery_packet as packets
from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import authority_registration_completion_response as response
from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap
from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer


authorization, shape, plan = bootstrap.authorization, bootstrap.shape, bootstrap.plan
capture, clock, authority = bootstrap.capture, bootstrap.clock, bootstrap.authority
custody, intent = bootstrap.release_bootstrap, bootstrap.intent
consumption, registration = hints.consume, hints.registration
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
REQUEST_LIMITS = (records.MAX_REQUEST_BYTES, records.MAX_RECEIPT_BYTES, intent.MAX_BYTES)
_Lifetime = bookkeeping._Lifetime
_EMPTY_DIGEST = "sha256:" + "0" * 64


class ReleaseProofInputProductionError(ValueError):
    pass


def _fail(message):
    raise ReleaseProofInputProductionError(message)


def _same_bytes(actual, expected, work, label):
    bookkeeping._same_bytes(actual, expected, work, label)


def _placeholder(size):
    return {"base64Url": "", "byteCount": size, "bytesDigest": _EMPTY_DIGEST}


def _expanded(size):
    return (4 * size + 2) // 3


def _signed_size(payload, schema, wrapper_sizes, work):
    envelope = {"schema": schema, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(envelope)
    return size + sum(_expanded(size) for size in wrapper_sizes), nodes


def _completed(packet, complete_raw, receipt_raw, material, root, current, work):
    """Authenticate public controls against the independently pinned packet."""
    for actual, expected, label in (
            (packet.enrollment_bytes, material.current_root_enrollment_bytes, "state enrollment"),
            (packet.grant_enrollment_bytes, material.grant_enrollment_bytes, "grant enrollment"),
            (packet.authorization_enrollment_bytes, material.authorization_enrollment_bytes, "caller enrollment"),
            (packet.authorization_bytes, material.authorization_bytes, "caller authorization")):
        _same_bytes(actual, expected, work, "proof setup exact " + label)
    payload, marker = packet.payload, packet.payload["marker"]
    wanted_request = material.expectations["request"]
    for actual, expected in ((payload["authorizationDigest"], material.authorization_digest),
            (payload["requestDigest"], wanted_request["requestDigest"]),
            (payload["operationId"], wanted_request["operationId"]),
            (marker["database_id"], material.database_id),
            (marker["generation_digest"], material.generation_digest),
            (marker["enrollment_digest"], material.enrollment_digest),
            (marker["pending_sequence"], material.current_pending[0]),
            (marker["pending_decision_digest"], material.current_pending[1]),
            (marker["fence"], material.current_pending[2])):
        plan._same(actual, expected, work, "proof setup independent packet/consume binding")
    current()
    acknowledged = records._verify_ack_on_work(request_bytes=complete_raw, receipt_bytes=receipt_raw,
        enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=root,
        expected_pending_sequence=material.current_pending[0],
        expected_pending_head_digest=material.current_pending[1], work=work)
    current()
    complete = acknowledged.request_payload
    for field, column in response._REQUEST_MARKER_JOINS:
        plan._same(complete[field], marker[column], work, "proof setup signed completion " + field)
    after = records.authorization.vector._encode_on_work(payload["afterVector"], work=work)
    bookkeeping._observation(complete, marker, after, work)
    current()
    return acknowledged, after


def _release(packet, material, acknowledged, after, work):
    planned = material.custody_material.planner.payload
    activated = planned["activationExpectations"]["request"]
    consumed = material.expectations["request"]
    activation_args = consumption.activation._arguments(activated["arguments"], work)
    arguments = consumption._arguments(consumed["arguments"], work)
    for name in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        plan._same(arguments[name], activation_args[name], work, "proof setup activation/consume " + name)
    expected_delivery = consumption.core._deterministic_uuid(operation=custody.ACTIVATION_OPERATION,
        request_digest=activated["requestDigest"], purpose=consumption.activation.DELIVERY_PURPOSE, work=work)
    plan._same(arguments["delivery_id"], expected_delivery, work, "proof setup activation delivery identity")
    projected = hints._from_packet_on_work(packet_payload=packet.payload,
        packet_digest=material.packet_digest, work=work)
    packet_digest, effects, envelope, created, expires = hints._decode_on_work(projected, work=work)
    work.prepare_scan(packet.payload["selectedRows"])
    matches = [item for item in packet.payload["selectedRows"]
        if item["table"] == "oidc_session_activation_deliveries"]
    if len(matches) != 1:
        _fail("proof setup packet does not select exactly one delivery")
    row = matches[0]["row"]
    for actual, expected in ((row["id"], expected_delivery), (row["session_id"], arguments["session_id"]),
            (row["credential_record_id"], arguments["credential_record_id"]),
            (row["challenge_id"], arguments["challenge_id"]), (row["assertion_digest"], arguments["assertion_digest"]),
            (row["old_token_digest"], arguments["old_token_digest"]),
            (row["new_token_digest"], arguments["new_token_digest"]), (row["consumed_at"], None)):
        plan._same(actual, expected, work, "proof setup packet delivery subject")
    scope = {"deliveryId": expected_delivery, "userId": arguments["user_id"],
        "sessionId": arguments["session_id"], "credentialId": arguments["credential_id"],
        "credentialRecordId": arguments["credential_record_id"], "challengeId": arguments["challenge_id"],
        "assertionDigest": arguments["assertion_digest"], "oldTokenDigest": arguments["old_token_digest"],
        "newTokenDigest": arguments["new_token_digest"], "createdAt": created, "expiresAt": expires}
    custody._scope(scope, work)
    return {"activationRequestDigest": activated["requestDigest"], "activationOperationId": activated["operationId"],
        "consumeRequestDigest": consumed["requestDigest"],
        "deliveryEnvelopeDigest": consumption.assertion._digest(envelope, work), "deliveryScope": scope,
        "consumeBinding": {"packetDigest": packet_digest, "pendingDecisionDigest": material.current_pending[1],
            "completionRequestDigest": acknowledged.request_digest, "effectsDigest": effects,
            "afterVectorDigest": records.authorization.vector._digest_on_work(after, work=work)}}


def _derive_on_work(*, request_originals, consume_packet_bytes, issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None,
        maximum_original_bytes=None):
    """Derive ordinary same-call payloads from originals, never caller targets."""
    maximum = MAX_ORIGINAL_BYTES if maximum_original_bytes is None else maximum_original_bytes
    if type(maximum) is not int or not 2 <= maximum <= MAX_ORIGINAL_BYTES:
        _fail("proof setup inventory capacity may only tighten its source bound")
    if type(request_originals) is not tuple or len(request_originals) != 3:
        _fail("proof setup requires exact complete/ACK/intent raw3")
    request = tuple(authorization._original(raw, maximum, "proof setup request original")
        for raw, maximum in zip(request_originals, REQUEST_LIMITS))
    policy_raw = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES, "proof setup policy")
    completed_raw = authorization._original(completion_bootstrap_bytes, bootstrap.completion.MAX_BYTES,
        "proof setup independent completion bootstrap")
    proof_enrolled = authorization._original(proof_enrollment_bytes, bootstrap.proof_enrollments.MAX_BYTES,
        "proof setup independent proof enrollment")
    intent_enrolled = authorization._original(intent_enrollment_bytes, bootstrap.intent_enrollments.MAX_BYTES,
        "proof setup independent intent enrollment")
    packet_raw = authorization._original(consume_packet_bytes, packets.MAX_BYTES, "proof setup private packet")
    root, continuation = root_public_key, _continuity
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    total = sum(map(len, (*request, policy_raw, completed_raw, proof_enrolled, intent_enrolled, packet_raw)))
    # Reserve decoded packet controls and nested cold originals before either
    # decoder allocates. Later exact output sizing can only tighten this bound.
    if total + 3 * len(completed_raw) + 2 * len(packet_raw) > maximum:
        _fail("proof setup input and decoded-original reservation exceeds 64 MiB")
    capture._SharedLedger(work)
    work.charge(input_bytes=total)
    authorization._public(root)
    lifetime = _Lifetime(window, bound, work, continuation)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_raw, completion_bootstrap_bytes=completed_raw,
        proof_enrollment_bytes=proof_enrolled, intent_enrollment_bytes=intent_enrolled, root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("proof setup requires genuine original issuer policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    material = policy.completion_material
    packet = packets._decode_on_work(packet_raw, expected_packet_digest=material.packet_digest,
        expected_pending_decision_digest=material.current_pending[1], work=work)
    current()
    acknowledged, after = _completed(packet, request[0], request[1], material, root, current, work)
    release = _release(packet, material, acknowledged, after, work)
    current()
    signed_intent = intent._read(request[2], work)
    intent._signature(signed_intent, policy.intent_public_key, work)
    enrollment = bootstrap.intent_enrollments._read(intent_enrolled, work)["payload"]
    intent_scope = {name: policy.proof_scope[name] for name in
        ("configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest", "receiverIdentity")}
    intent_scope["callerId"] = policy.caller_id
    for name, expected in {**intent_scope, **release,
            "enrollmentDigest": policy.payload["intentEnrollmentDigest"],
            "callerMeasurementDigest": enrollment["callerKey"]["measurementDigest"]}.items():
        plan._same(signed_intent["payload"][name], expected, work, "proof setup authenticated intent " + name)
    intent_payload = signed_intent["payload"]
    authorization._interval(intent_payload, enrollment["maximumAgeNs"])
    if (intent_payload["issuedAtEpochNs"] > current() + enrollment["maximumClockSkewNs"]
            or current() >= intent_payload["expiresAtEpochNs"]):
        _fail("proof setup original intent is future-issued or expired")
    _created, delivery_expiry = custody._scope(release["deliveryScope"], work)
    issued = max(policy.payload["issuedAtEpochNs"], intent_payload["issuedAtEpochNs"])
    expires = min(policy.payload["expiresAtEpochNs"], intent_payload["expiresAtEpochNs"], delivery_expiry,
        issued + bootstrap.completion.MAX_RECEIPT_AGE_NS)
    if issued >= expires:
        _fail("proof setup output has no common original interval")
    lifetime.narrow(expires, enrollment["maximumAgeNs"], enrollment["maximumClockSkewNs"])
    activation = material.custody_material.history.planner
    common = {"sourceRevision": authority.SOURCE_REVISION, "trustMode": "trusted-host-local",
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    custody_payload = {**common, "schema": custody.PAYLOAD_SCHEMA, "consumerRole": custody.CONSUMER_ROLE,
        "processMode": custody.PROCESS_MODE, "serviceUid": custody.SERVICE_UID, "serviceGid": custody.SERVICE_GID,
        "receiverIdentity": policy.proof_scope["receiverIdentity"],
        "configurationDigest": material.configuration_digest, "generationDigest": material.generation_digest,
        "runtimeClosureDigest": material.runtime_closure_digest, "deliveryKeyDigest": activation.delivery_key_digest,
        "plannerBootstrap": _placeholder(len(activation.bootstrap_bytes)),
        **{name: release[name] for name in ("activationRequestDigest", "activationOperationId",
            "deliveryEnvelopeDigest", "deliveryScope", "consumeRequestDigest")},
        "releaseIntentDigest": intent._digest(request[2], work), "consumeOperation": custody.CONSUME_OPERATION,
        **{name: False for name in custody._FALSE_FIELDS}}
    custody_size, custody_nodes = _signed_size(custody_payload, custody.SCHEMA,
        (len(activation.bootstrap_bytes),), work)
    originals = (completed_raw, proof_enrolled, None, request[2], intent_enrolled, request[0], request[1])
    sizes = tuple(custody_size if raw is None else len(raw) for raw in originals)
    proof_payload = {**common, "schema": bootstrap.PAYLOAD_SCHEMA, "purpose": bootstrap.PURPOSE,
        "role": bootstrap.ROLE, "proofScope": policy.proof_scope, "expectedRelease": release,
        "callerId": policy.caller_id, "launch": policy.proof_launch,
        **{name: _placeholder(size) for (name, _maximum), size in zip(bootstrap._ORIGINAL_LIMITS, sizes)}}
    proof_size, proof_nodes = _signed_size(proof_payload, bootstrap.SCHEMA, sizes, work)
    nested = (material.custody_bytes, material.planner_bootstrap_bytes, material.planner_history_custody_bytes,
        material.receiving_history_custody_bytes, material.authorization_bytes, material.current_root_enrollment_bytes,
        material.grant_enrollment_bytes, material.authorization_enrollment_bytes, activation.bootstrap_bytes,
        *packet.originals, packet.enrollment_bytes, packet.grant_enrollment_bytes, packet.grant_bytes,
        packet.reserve_request_bytes, packet.reserve_receipt_bytes, packet.snapshot_bytes,
        packet.authorization_enrollment_bytes, packet.authorization_bytes)
    held = total + sum(map(len, nested)) + len(after)
    if (custody_size > custody.MAX_BYTES or custody_nodes > custody.MAX_NODES
            or proof_size > bootstrap.MAX_BYTES or proof_nodes > bootstrap.MAX_NODES
            or held + 3 * (custody_size + proof_size) + sum(sizes) > maximum):
        _fail("proof setup exact wrapped output and readback reservation exceeds the source inventory")
    current()
    custody_payload["plannerBootstrap"] = bookkeeping._wrapped(activation.bootstrap_bytes, work, current)
    for (name, _maximum), raw in zip(bootstrap._ORIGINAL_LIMITS, originals):
        if raw is not None:
            proof_payload[name] = bookkeeping._wrapped(raw, work, current)
    current()
    return policy, lifetime, custody_payload, proof_payload, custody_size, proof_size


def _produce_on_work(*, request_originals, consume_packet_bytes, issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity=None,
        maximum_original_bytes=None):
    """Return only the root-signed proof bootstrap raw1, with custody embedded."""
    private, root = root_private_key, root_public_key
    authorization._private(private)
    authorization._public(root)
    policy, lifetime, custody_payload, proof_payload, custody_size, proof_size = _derive_on_work(
        request_originals=request_originals, consume_packet_bytes=consume_packet_bytes,
        issuer_policy_bytes=issuer_policy_bytes, completion_bootstrap_bytes=completion_bootstrap_bytes,
        proof_enrollment_bytes=proof_enrollment_bytes, intent_enrollment_bytes=intent_enrollment_bytes,
        root_public_key=root, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity, maximum_original_bytes=maximum_original_bytes)
    current = lifetime.current
    current()
    authorization.keys._pair_on_work(private, root, work)
    current()
    custody_raw = custody._produce_on_work(payload=custody_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _current=lifetime.base)
    if len(custody_raw) != custody_size:
        _fail("proof setup custody differs from its exact output reservation")
    current()
    proof_payload["releaseCustody"] = bookkeeping._wrapped(custody_raw, work, current)
    original = bootstrap._produce_on_work(payload=proof_payload, root_private_key=private,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _current=lifetime.base)
    if len(original) != proof_size:
        _fail("proof setup bootstrap differs from its exact output reservation")
    current()
    admitted = bootstrap._verify_on_work(bootstrap_bytes=original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work, _current=lifetime.base)
    if type(admitted) is not bootstrap._ProofMaterial:
        _fail("proof setup output requires genuine original bootstrap readback")
    _same_bytes(admitted.completion_bootstrap_bytes, policy.completion_bootstrap_bytes, work,
        "proof setup exact independent completion bootstrap")
    _same_bytes(admitted.release_custody_bytes, custody_raw, work, "proof setup exact signed custody")
    plan._same(admitted.expected_release, proof_payload["expectedRelease"], work, "proof setup derived release")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    current()
    return (original,)
