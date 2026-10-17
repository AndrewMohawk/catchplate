"""Root-owned OIDC first-registration worker issuance from actual originals.

The existing V24 parent admits configuration and dedicated registration keys.
Each late request is independently replayed and joined to a fresh nonce-bound
observation by the actual current-root owner. Only existing bootstrap originals
and an existing local context approval return; neither is an execution result.
Resource provenance, one-cycle publication and child ownership remain with the
private provisioner. No stored predecessor, caller-created verdict, replacement
allowance, browser identity claim or activation-labelled head is accepted.
"""
from __future__ import annotations

import importlib
import secrets

from catchplate import control_plane_enrollment_bootstrap as parent
from catchplate import authority_local_registration_context as contexts
from catchplate import authority_current_root_authorization as roots
from catchplate import authority_current_root_transport as state_transport
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate import oidc_session_activation_request_issuance_policy as runtime_policy

configuration, capture, plan = parent.configuration, parent.capture, parent.plan
_PURPOSES = ("execution", "finalization")
_ROLES = ("authorizer", "reserver", "sql", "completion")
_MODE = "oidc-session-first-enrollment"


def _require(value):
    if not value:
        raise ValueError("OIDC registration request issuance refused")


def _module(purpose, role):
    _require(type(purpose) is str and purpose in _PURPOSES
        and type(role) is str and role in _ROLES)
    return importlib.import_module("catchplate.registration_" + purpose + "_" + role + "_bootstrap")


def _capture(value, work):
    return configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=parent.MAX_BYTES).visit(value)


def _encode(value, maximum, work):
    raw = configuration._configuration_wire(value, capture._SharedLedger(work))
    _require(2 <= len(raw) <= maximum)
    return raw


def _decode(raw, maximum, work):
    roots._original(raw, maximum, "registration issuance original")
    value = parent._decode(raw, work)
    parent._canonical(raw, value, work)
    return value


def _same_configuration(actual, expected, work):
    left, right = (_encode(value, parent.MAX_BYTES, work) for value in (actual, expected))
    work.charge(input_bytes=len(left) + len(right))
    _require(left == right)


def _admit_parent(original, digest, purpose, root, window, deadline, work, continuity):
    _require(type(purpose) is str and purpose in _PURPOSES)
    roots._original(original, parent.MAX_BYTES, "registration parent")
    processing = runtime_policy.planner._processing(window, deadline, work, _continuity=continuity)
    processing()
    envelope = _decode(original, parent.MAX_BYTES, work)
    _require(envelope["schema"] == parent.V24_SCHEMA)
    admitted = parent._admit_on_work(bootstrap_bytes=original, runtime_root_public_key=root,
        expected_configuration_digest=digest, work=work, _history_live_window=window,
        _history_transport_deadline_ns=deadline)
    processing()
    contexts._cold_profile(admitted, original)
    nested = getattr(admitted, purpose)
    _require(nested.context_directory is not None and nested.reservation_predecessor is None
        and nested.current_pending is None)
    # This policy contributes only the authenticated ORIGINAL runtime interval.
    # Registration authority remains the independently admitted parent children.
    runtime = runtime_policy._verify_on_work(policy_bytes=admitted.activation_planning.policy_bytes,
        root_public_key=root, live_window=window, transport_deadline_ns=deadline,
        work=work, _continuity=continuity)
    common = dict(payload=admitted.configuration_payload, configuration_digest=admitted.configuration_digest,
        generation=admitted.generation, runtime_role_identities=admitted.runtime_role_identities,
        current_root_enrollment_bytes=nested.current_root_enrollment_bytes,
        grant_enrollment_bytes=nested.grant_enrollment_bytes,
        authorization_enrollment_bytes=nested.authorization_enrollment_bytes, root_public_key=root)
    enrolled = roots._admit_enrollment_on_work(enrollment_bytes=nested.current_root_enrollment_bytes,
        root_public_key=root, work=work)
    interval = runtime.payload["issuedAtEpochNs"], runtime.payload["expiresAtEpochNs"]

    def current():
        first = processing()
        now = runtime.live()
        _require(first <= now and interval[0] <= now < interval[1])
        return now

    current()
    return admitted, nested, common, enrolled, interval, current


def _base(module, common, enrolled, interval, resource, work):
    wrapped = {}
    for field, name, domain in (
            ("currentRootEnrollment", "current_root", roots.ENROLLMENT_IDENTITY_DOMAIN),
            ("grantEnrollment", "grant", module.grants.ENROLLMENT_IDENTITY_DOMAIN),
            ("authorizationEnrollment", "authorization", module.caller.ENROLLMENT_IDENTITY_DOMAIN)):
        raw = common[name + "_enrollment_bytes"]
        wrapped[field] = dict(base64Url=roots.transport._encode(raw, work), byteCount=len(raw),
            bytesDigest=_digest(raw, work), identityDigest=plan._frame(domain, (raw,), work))
    return dict(schema=module.PAYLOAD_SCHEMA, sourceRevision=parent.authority.SOURCE_REVISION,
        role=module.ROLE, configurationPayload=common["payload"],
        configurationDigest=common["configuration_digest"], generation=common["generation"],
        runtimeRoleIdentities=common["runtime_role_identities"], databaseId=enrolled.payload["databaseId"],
        generationDigest=enrolled.payload["generationDigest"], runtimeClosureDigest=resource["runtimeClosureDigest"],
        issuedAtEpochNs=interval[0], expiresAtEpochNs=interval[1], trustMode="trusted-host-local",
        launch=resource["launch"], **wrapped, **{name: False for name in module._FALSE_FIELDS})


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return contexts.sha(raw)


def _produce(module, payload, private, public, work, current):
    current()
    raw = module._produce_on_work(payload=payload, root_private_key=private,
        root_public_key=public, work=work)
    current()
    return raw


def _produce_initial_on_work(*, parent_bootstrap_bytes, configuration_digest, purpose,
        projection, root_private_key, root_public_key, live_window, transport_deadline_ns,
        work, _continuity=None):
    """One runtime-bound authorizer; never pin it to a processing-only window."""
    resource = _capture(projection, work)
    window = clock._validate(live_window)
    roots.shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    module = _module(purpose, "authorizer")
    _admitted, _nested, common, enrolled, interval, current = _admit_parent(
        parent_bootstrap_bytes, configuration_digest, purpose, root_public_key,
        window, bound, work, _continuity)
    _require(set(resource) == {"launch", "runtimeClosureDigest", "authorizerSpkiDigest", "authorizerMeasurementDigest"})
    payload = _base(module, common, enrolled, interval, resource, work)
    payload.update({field: resource[field] for field in ("authorizerSpkiDigest", "authorizerMeasurementDigest")})
    return _produce(module, payload, root_private_key, root_public_key, work, current)


def _request(raw, common, nested, purpose, expected_user, work):
    selected = _decode(raw, contexts.MAX_REQUEST, work)
    _require(type(selected) is dict and set(selected) == contexts._REQUEST_FIELDS
        and selected["schema"] == contexts.REQUEST_SCHEMA and selected["purpose"] == purpose
        and selected["stage"] in contexts.STAGES
        and type(expected_user) is str and expected_user.startswith("oidc:") and len(expected_user) > 5)
    _require(contexts.directory(selected["directory"]) == nested.context_directory)
    work.charge(input_bytes=sum(len(value) for value in common.values() if type(value) is bytes),
        json_nodes=2 * len(common))
    expected = {name: value.decode("ascii") if type(value) is bytes else value
        for name, value in common.items() if name != "root_public_key"}
    _same_configuration(selected["common"], expected, work)
    from cryptography.hazmat.primitives import serialization

    work.charge(input_bytes=256)
    public = parent.production._callback(work, lambda: nested.caller_public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    _require(selected["callerPublicKeyBase64Url"] == contexts.local.spec.strict_base64url_encode(public))
    _require(type(selected["originals"]) is list and len(selected["originals"]) == 10
        and all(type(item) is str and item.isascii() for item in selected["originals"]))
    work.charge(input_bytes=sum(map(len, selected["originals"])))
    originals = tuple(item.encode("ascii") for item in selected["originals"])
    if purpose == "execution":
        from catchplate import authority_registration_reservation_transport as transport
    else:
        from catchplate import authority_registration_finalization_reservation_transport as transport
    transport._originals(originals, response=False)
    reserved = None
    if selected["stage"] == "reserve":
        _require(selected["reservationOriginals"] is selected["priorContextOriginal"] is None)
    else:
        values = selected["reservationOriginals"]
        _require(type(values) is list and len(values) == 3
            and all(type(item) is str and item.isascii() for item in values))
        work.charge(input_bytes=sum(map(len, values)))
        reserved = transport._originals(tuple(item.encode("ascii") for item in values), response=True)
    roots.shape._integer(selected["deadlineMonotonicNs"], minimum=1)
    roots.shape._integer(selected["expiresAtUnixNanos"], minimum=1)
    _require(type(selected["subject"]) is dict and set(selected["subject"]) == contexts._SUBJECT
        and selected["subject"]["userId"] == expected_user
        and selected["subject"]["mode"] == _MODE
        and type(selected["subject"]["sessionId"]) is str and selected["subject"]["sessionId"])
    return selected, originals, reserved


def _replay_subject(purpose, common, raw, selected, window, bound, work, current):
    """Project subject only from these same-call fully authenticated originals."""
    current()
    if purpose == "execution":
        from catchplate import authority_registration_execution_response as receiving
        from catchplate import authority_webauthn_evidence_input_wire as inputs

        returned = receiving._verify_on_configuration(**common, authorization_bytes=raw[0],
            request_originals=raw[1:4], response_originals=raw[4:8], before_vector_bytes=raw[8],
            grant_bytes=raw[9], deadline_epoch_ns=window[3], transport_deadline_ns=bound, work=work)
        _require(returned == raw[9])
        request = _decode(raw[2], receiving.exchange.request_wire.MAX_CONTEXT_BYTES, work)["request"]
        original = inputs._decode_document(raw[3], work)
        scope, authorization = original["scope"], original["expectedAuthorization"]
        result = dict(userId=scope["userId"], challengeId=scope["challengeId"],
            sessionId=request["arguments"]["oidc_session_id"], mode=authorization["mode"])
        grant = receiving.grants._read(raw[9], enrollment=False, work=work)["payload"]
    else:
        from catchplate import authority_registration_finalization_execution_admission as receiving

        verified = receiving._admit_on_configuration(**common, authorization_bytes=raw[0],
            originals=raw[1:8], before_vector_bytes=raw[8], grant_bytes=raw[9],
            live_window=window, transport_deadline_ns=bound, work=work)
        verified.live()
        request = verified.verified_grant.replayed.request
        arguments = request["arguments"]
        intent = arguments["semantic_intent"]
        result = dict(userId=intent["userId"], challengeId=intent["challengeId"],
            sessionId=arguments["oidc_session_id"], mode=intent["authorizationMode"])
        grant = verified.verified_grant.payload
    # The legacy local locator codec allocates its complete framed raw10.
    work.charge(input_bytes=2 * sum(map(len, raw)) + 4096, hashes=1, json_nodes=32)
    result.update(localDigest=contexts._record(purpose, raw), requestDigest=request["requestDigest"],
        operationId=request["operationId"])
    plan._same(result, selected["subject"], work, "registration request actual subject")
    plan._same(result["localDigest"], selected["localDigest"], work, "registration request actual locator")
    plan._same(roots.vector._digest_on_work(raw[8], work=work), grant["beforeVectorDigest"], work,
        "registration request genuine before vector")
    _require(current() < grant["expiresAtEpochNs"])
    return grant


def _current_head(purpose, raw, original_request, enrolled, common, resource, work, bound, current):
    from catchplate import authority_registration_current_root_head as head

    context = plan._frame("catchplate.registrationRequestIssuanceHeadContext/v1", (original_request,), work)
    vector = roots.vector._digest_on_work(raw[8], work=work)
    work.charge(input_bytes=96)
    nonce = parent.production._callback(work, lambda: secrets.token_hex(32))
    query = head._encode_query_on_work(enrollment_digest=enrolled.enrollment_digest,
        context_digest=context, expected_vector_digest=vector, challenge=nonce, work=work, purpose=purpose)
    module = _module(purpose, "reserver")
    endpoint = module._state_endpoint(resource["stateEndpoint"])
    current()
    observed = state_transport._registration_head_on_work(endpoint, query_bytes=query,
        deadline_ns=bound, work=work, current=current, purpose=purpose)
    current()
    actual = head._verify_on_work(observation_bytes=observed, query_bytes=query,
        enrollment_bytes=common["current_root_enrollment_bytes"], root_public_key=common["root_public_key"],
        now_epoch_ns=current(), work=work, purpose=purpose)
    return actual


def _produce_request_on_work(*, parent_bootstrap_bytes, configuration_digest, purpose,
        request_bytes, expected_user_id, projections, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Return approval + fresh workers after genuine replay/current-head joins."""
    resources = _capture(projections, work)
    roots._original(request_bytes, contexts.MAX_REQUEST, "registration context request")
    window = clock._validate(live_window)
    roots.shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    _admitted, nested, common, enrolled, interval, inherited = _admit_parent(
        parent_bootstrap_bytes, configuration_digest, purpose, root_public_key,
        window, bound, work, _continuity)
    selected, raw, reserved = _request(request_bytes, common, nested, purpose, expected_user_id, work)
    _require(selected["expiresAtUnixNanos"] <= interval[1])
    bound = min(bound, selected["deadlineMonotonicNs"])
    expiry = min(window[3], selected["expiresAtUnixNanos"])
    narrowed = clock._validate((window[0], window[1], window[2], expiry,
        min(window[4], window[1] + expiry - window[0]), window[5], window[6]))
    processing = runtime_policy.planner._processing(narrowed, bound, work, _continuity=_continuity)
    actual = grant = None

    def current():
        first, now = inherited(), processing()
        _require(first <= now)
        if grant is not None:
            _require(now < grant["expiresAtEpochNs"])
        if actual is not None:
            _require(now < actual["expiresAtEpochNs"])
        return now

    current()
    grant = _replay_subject(purpose, common, raw, selected, narrowed, bound, work, current)
    reserve = selected["stage"] == "reserve"
    roles = ("reserver",) if reserve else ("sql", "completion")
    _require(type(resources) is dict and set(resources) == set(roles))
    state_resource = resources["reserver" if reserve else "completion"]
    actual = _current_head(purpose, raw, request_bytes, enrolled, common, state_resource, work, bound, current)
    if reserve:
        _require(actual["pendingRequestDigest"] is actual["pendingDecisionDigest"] is None
            and actual["sequence"] + 2 <= enrolled.payload["maxRecords"])
        scope = dict(sequence=actual["sequence"], headDigest=actual["headDigest"], nextFence=actual["fence"] + 1)
        issued_mono, issued_epoch, _after = clock._sample_on_work(work)
    else:
        _require(actual["pendingRequestDigest"] is not None and actual["pendingDecisionDigest"] is not None)
        _require(type(selected["priorContextOriginal"]) is str and selected["priorContextOriginal"].isascii())
        work.charge(input_bytes=len(selected["priorContextOriginal"]))
        prior_raw = selected["priorContextOriginal"].encode("ascii")
        prior = contexts._read(prior_raw, root_public_key, work)
        if purpose == "execution":
            from catchplate import authority_registration_reservation_records as records
        else:
            from catchplate import authority_registration_finalization_reservation_records as records
        predecessor = prior["scope"]
        request, request_digest, receipt, receipt_digest = records._verify_on_work(
            request_bytes=reserved[0], snapshot_bytes=reserved[1], receipt_bytes=reserved[2],
            enrollment_bytes=common["current_root_enrollment_bytes"], root_public_key=root_public_key,
            expected_predecessor_sequence=predecessor["sequence"],
            expected_predecessor_head_digest=predecessor["headDigest"], expected_fence=predecessor["nextFence"], work=work)
        _require(receipt is not None and actual["sequence"] == predecessor["sequence"] + 1
            and actual["fence"] == predecessor["nextFence"]
            and actual["headDigest"] == actual["pendingDecisionDigest"] == receipt_digest
            and actual["pendingRequestDigest"] == request_digest)
        scope = dict(sequence=actual["sequence"], headDigest=actual["headDigest"], fence=actual["fence"])
        issued_mono, issued_epoch = prior["issuedAtMonotonicNs"], prior["issuedAtUnixNanos"]
    current()
    work.charge(input_bytes=len(request_bytes), json_nodes=32)
    approval = dict(schema=contexts.APPROVAL_SCHEMA, directory=selected["directory"],
        requestOriginal=request_bytes.decode("ascii"), requestSha256=_digest(request_bytes, work), scope=scope,
        issuedAtMonotonicNs=issued_mono, issuedAtUnixNanos=issued_epoch)
    approval_raw = _encode(approval, contexts.io.MAX_PUBLIC, work)
    prepared = contexts.prepare(approval_raw, root_public_key=root_public_key, work=work)
    value = prepared["context"]
    bound = min(bound, prepared["deadline"])
    interval = (value["issuedAtUnixNanos"], min(value["expiresAtUnixNanos"], interval[1], grant["expiresAtEpochNs"]))
    checked = None
    if not reserve:
        if purpose == "execution":
            from catchplate import authority_registration_execution_sql_admission as admission
            timing = dict(deadline_epoch_ns=narrowed[3])
        else:
            from catchplate import authority_registration_finalization_sql_admission as admission
            timing = dict(live_window=narrowed)
        checked = admission._admit_on_configuration(**common, originals=raw, reservation_originals=reserved,
            expected_pending_sequence=scope["sequence"], expected_pending_head_digest=scope["headDigest"],
            expected_fence=scope["fence"], transport_deadline_ns=bound, work=work, **timing)
        checked.live()
    outputs = []
    for role in roles:
        current()
        contexts._fresh(value)
        module, resource = _module(purpose, role), resources[role]
        fields = {"launch", "runtimeClosureDigest", "checkpoint"}
        if role == "reserver":
            fields.update(("stateEndpoint", "computationSpkiDigest", "computationMeasurementDigest"))
        else:
            fields.update(("databaseEndpoint", "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles"))
            if role == "completion":
                fields.update(("stateEndpoint", "completionSpkiDigest", "completionMeasurementDigest"))
        _require(type(resource) is dict and set(resource) == fields)
        payload = _base(module, common, enrolled, interval, resource, work)
        if role == "reserver":
            payload.update(statePredecessor=scope, reservationCheckpoint=resource["checkpoint"],
                stateEndpoint=resource["stateEndpoint"], computationSpkiDigest=resource["computationSpkiDigest"],
                computationMeasurementDigest=resource["computationMeasurementDigest"])
        else:
            payload.update(currentPending=scope, **{name: resource[name] for name in (
                "databaseEndpoint", "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles")})
            if role == "sql":
                payload["attemptCheckpoint"] = resource["checkpoint"]
            else:
                payload.update(completionCheckpoint=resource["checkpoint"], stateEndpoint=resource["stateEndpoint"],
                    completionSpkiDigest=resource["completionSpkiDigest"],
                    completionMeasurementDigest=resource["completionMeasurementDigest"],
                    packetDigest=value["completionPacketDigest"], authorizationDigest=value["completionAuthorizationDigest"],
                    replayExpectations=checked.issue_arguments["expectations"])
        original = _produce(module, payload, root_private_key, root_public_key, work, current)
        outputs.append((role, original))
        if checked is not None:
            checked.live()
    work.charge(input_bytes=256, json_nodes=16)
    result = approval_raw, tuple(outputs)
    contexts._fresh(value)
    current()
    return result
