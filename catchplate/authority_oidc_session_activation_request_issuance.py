"""Actual vector/head acquisition and original-only activation launch issuance.

The independently cold-admitted issuer supplies its runtime root and retained
resource continuity. The app supplies only a purpose-signed request commitment;
it cannot supply a successful vector, current head, custody or planner DTO.
This phase does not authorize SQL, grant execution, complete a pending session
or release a token. The later genuine workers still replay all originals.
"""
from __future__ import annotations

import base64
import hashlib
import secrets

from catchplate import authority_current_root_head as head
from catchplate import authority_current_root_reader as roots
from catchplate import authority_current_root_transport as state_transport
from catchplate import authority_oidc_session_activation_planner_transport as planner_transport
from catchplate import oidc_session_activation_execution_custody_bootstrap as receiving
from catchplate import oidc_session_activation_request_issuance_policy as policy


planner, authorization = policy.planner, policy.authorization
plan, shape, capture, production = policy.plan, policy.shape, policy.capture, policy.production
REQUEST_SCHEMA = "catchplate.signedOidcSessionActivationRequestIssuance/v1"
REQUEST_PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationRequestIssuance/v1"
REQUEST_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationRequestIssuanceIdentity/v1"
PLANNER_REQUEST_DOMAIN = "catchplate.oidcSessionActivationRequestIssuancePlannerRequest/v1"
MAX_REQUEST_BYTES = 4096
REQUEST_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "operation",
    "policyDigest", "plannerRequestDigest", "requestId", "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class RequestIssuanceError(ValueError):
    pass


def _fail(message):
    raise RequestIssuanceError(message)


def _request_shape(payload):
    shape._object(payload, REQUEST_FIELDS, "activation request issuance")
    for field, expected in (("schema", REQUEST_PAYLOAD_SCHEMA),
            ("sourceRevision", policy.authority.SOURCE_REVISION), ("purpose", policy.PURPOSE),
            ("operation", planner.OPERATION)):
        shape._literal(payload[field], expected)
    for field in ("policyDigest", "plannerRequestDigest"):
        shape._digest(payload[field])
    head._challenge(payload["requestId"])
    authorization._interval(payload, policy.authority.VERIFIER_RESPONSE_MAX_AGE_NS)


def _read_request(raw, work):
    original = authorization._original(raw, MAX_REQUEST_BYTES, "activation issuance request")
    envelope = policy.capability.wire._decode_object(original, work=work,
        maximum_bytes=MAX_REQUEST_BYTES, maximum_nodes=64, maximum_depth=3)
    shape._object(envelope, _ENVELOPE_FIELDS, "signed activation issuance request")
    shape._literal(envelope["schema"], REQUEST_SCHEMA)
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    _request_shape(envelope["payload"])
    policy.capability._canonical(original, envelope,
        capture._SharedLedger(work), MAX_REQUEST_BYTES, 64)
    return envelope


def _verify_request(raw, admitted, work, current):
    envelope = _read_request(raw, work)
    payload = envelope["payload"]
    plan._same(payload["policyDigest"], admitted.digest, work,
        "issuance request differs from independent root-delegated policy")
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if not (admitted.payload["issuedAtEpochNs"] <= issued < expires
            <= admitted.payload["expiresAtEpochNs"]):
        _fail("issuance request escapes the original policy interval")
    unsigned = policy.capability._wire(payload, capture._SharedLedger(work), MAX_REQUEST_BYTES, 64)
    current()
    policy.capability._signature(admitted.caller.caller_public_key,
        envelope["signatureBase64Url"], REQUEST_SCHEMA, unsigned, capture._SharedLedger(work))
    now = current()
    if not issued <= now < expires:
        _fail("issuance request is not currently live")
    policy.capability._canonical(raw, envelope, capture._SharedLedger(work), MAX_REQUEST_BYTES, 64)
    if not issued <= current() < expires:
        _fail("issuance request expired during final original canonicalization")
    return payload


def _sign_request_on_work(*, policy_bytes, planner_originals, caller_private_key,
        root_public_key, live_window, transport_deadline_ns, work, _continuity):
    """Called only by the live permission owner after genuine subject checks."""
    if not callable(_continuity):
        _fail("issuance signing requires the original owner's continuity")
    originals = planner_transport._originals(planner_originals, response=False)
    admitted = policy._verify_on_work(policy_bytes=policy_bytes, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity)
    window = policy.clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    issued = window[0]
    expires = min(window[3], window[0] + min(window[4], transport_deadline_ns) - window[1],
        admitted.payload["expiresAtEpochNs"])
    if not admitted.payload["issuedAtEpochNs"] <= issued < expires:
        _fail("issuance caller has no original request interval")
    work.charge(input_bytes=96)
    nonce = production._callback(work, lambda: secrets.token_hex(32))
    current = admitted.live
    current()
    payload = {"schema": REQUEST_PAYLOAD_SCHEMA, "sourceRevision": policy.authority.SOURCE_REVISION,
        "purpose": policy.PURPOSE, "operation": planner.OPERATION, "policyDigest": admitted.digest,
        "plannerRequestDigest": plan._frame(PLANNER_REQUEST_DOMAIN, originals, work),
        "requestId": nonce, "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _request_shape(payload)
    raw = planner.signing._sign(payload, REQUEST_SCHEMA, MAX_REQUEST_BYTES,
        caller_private_key, admitted.caller.caller_public_key, work)
    _verify_request(raw, admitted, work, current)
    return raw


def _wrapped(raw, work, identity_domain=None):
    if type(raw) is not bytes:
        _fail("issuance output requires an actual immutable original")
    size = (4 * len(raw) + 2) // 3
    work.charge(hashes=1, input_bytes=2 * len(raw) + size)
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    encoded = production._callback(work, lambda: base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="))
    if len(encoded) != size:
        _fail("issuance original wrapper exceeds its measured size")
    result = {"base64Url": encoded, "byteCount": len(raw), "bytesDigest": digest}
    if identity_domain is not None:
        result["identityDigest"] = plan._frame(identity_domain, (raw,), work)
    return result


def _issue_planning_on_work(*, policy_bytes, request_bytes, root_private_key,
        root_public_key, live_window, transport_deadline_ns, work, _continuity):
    """Read the real database and locked current-root owner, then sign raw4.

    Native acquisition remains before/after guarded; this is not a hard native
    interruption watchdog. No injected read/query/signature result is accepted.
    The cold caller must retain real TLS/public-file/key/process custody in the
    supplied restrictive continuity callback throughout this original work.
    """
    private, root = root_private_key, root_public_key
    request_bytes = authorization._original(request_bytes, MAX_REQUEST_BYTES, "activation issuance request")
    if not callable(_continuity):
        _fail("native issuance requires the actual cold owner's continuity")
    authorization._private(private)
    authorization._public(root)
    window = policy.clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    admitted = policy._verify_on_work(policy_bytes=policy_bytes, root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=_continuity)
    base_current = admitted.live
    request = _verify_request(request_bytes, admitted, work, base_current)
    issued, expires = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    bound = min(bound, window[1] + expires - window[0])
    bound_current = planner._processing(window, bound, work, _continuity=_continuity)

    def current():
        now = base_current()
        if not issued <= now < expires:
            _fail("issuance exhausted the caller's unchanged original interval")
        # Retain the receiver bracket; never map expiry from a later now.
        final = bound_current()
        if final < now or not issued <= final < expires:
            _fail("issuance crossed the unchanged request interval during final continuity")
        return final

    current()
    resources = admitted.payload["plannerResources"]
    configured, _generation, _runtime, _public, enrollment, enrollment_digest, reader = admitted.resource_facts
    dsn, timeout, identity, _skew = reader
    native = roots.CurrentRootReader(dsn=dsn, connect_timeout_seconds=timeout,
        database_role=identity[0], tls_client_dn=identity[1], tls_client_serial=identity[2],
        tls_issuer_dn=identity[3], query_manifest_digest=configured["queryManifestDigest"])
    current()
    vector_raw = roots.CurrentRootReader.read(native, work=work)
    current()
    vector_digest = planner.vector._digest_on_work(vector_raw, work=work)
    context_digest = plan._frame(REQUEST_IDENTITY_DOMAIN, (request_bytes,), work)
    work.charge(input_bytes=96)
    nonce = production._callback(work, lambda: secrets.token_hex(32))
    query = head._encode_query_on_work(enrollment_digest=enrollment_digest,
        context_digest=context_digest, expected_vector_digest=vector_digest, challenge=nonce, work=work)
    current()
    endpoint = planner._state_endpoint(resources["stateEndpoint"])
    # This fixed native exchange returns untrusted bytes. Its full bounded copy
    # reservation precedes native I/O; no callback can replace work or results.
    work.charge(input_bytes=2 * len(query) + 2 * head.MAX_BYTES + 32)
    observed = production._callback(work, lambda: state_transport._head_on_configuration(endpoint,
        query_bytes=query, deadline_ns=bound))
    current()
    actual = head._verify_on_work(observation_bytes=observed, query_bytes=query,
        enrollment_bytes=enrollment, root_public_key=root, now_epoch_ns=current(), work=work)
    if actual["pendingRequestDigest"] is not None or actual["pendingDecisionDigest"] is not None:
        _fail("activation issuance cannot plan over an observed pending transition")
    current()
    payload = policy._capture(resources, work)
    wrapped_vector = _wrapped(vector_raw, work)
    wrapped_vector["identityDigest"] = vector_digest
    payload.update({"completeRootVector": wrapped_vector,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires})
    planner_original = planner._produce_on_work(payload=payload,
        root_private_key=private, root_public_key=root, work=work,
        live_window=window, transport_deadline_ns=bound)
    current()
    wrapped_planner = _wrapped(planner_original, work)
    originals = [planner_original]
    for consumer in policy.RECEIVERS:
        mode, uid, gid = receiving._consumer(consumer)
        custody = {"schema": receiving.PAYLOAD_SCHEMA, "sourceRevision": policy.authority.SOURCE_REVISION,
            "operation": planner.OPERATION, "consumerRole": consumer,
            "processMode": mode, "serviceUid": uid, "serviceGid": gid,
            "receiverIdentity": admitted.payload["receiverIdentities"][consumer],
            "configurationDigest": resources["configurationDigest"],
            "generationDigest": resources["generation"]["digest"],
            "runtimeClosureDigest": resources["runtimeClosureDigest"],
            "bundleKeyDigest": resources["bundleKeyDigest"], "deliveryKeyDigest": resources["deliveryKeyDigest"],
            "plannerBootstrap": wrapped_planner, "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
            "trustMode": "trusted-host-local", **{name: False for name in receiving._FALSE_FIELDS}}
        current()
        originals.append(receiving._produce_on_work(payload=custody, root_private_key=private,
            root_public_key=root, work=work, live_window=window, transport_deadline_ns=bound))
        current()
    # Keep the authenticated query/observation too; staging must commit these
    # same originals rather than turn a reconstructed head DTO into authority.
    result = (request_bytes, query, observed, *originals)
    if sum(map(len, result)) > policy.authority.MAX_RESULT_BYTES:
        _fail("activation issued originals exceed their unchanged aggregate ceiling")
    work.charge(input_bytes=8 * len(result), json_nodes=len(result))
    current()
    return result


def _verify_planning_on_work(*, policy_bytes, request_bytes, originals,
        root_public_key, live_window, transport_deadline_ns, work, _continuity):
    """Re-admit raw7 on the live requester; never accept issuer observations."""
    if (type(originals) is not tuple or len(originals) != 7
            or any(type(raw) is not bytes for raw in originals)):
        _fail("activation issuance requires exact raw7 originals")
    limits = (MAX_REQUEST_BYTES, head.MAX_QUERY_BYTES, head.MAX_BYTES,
        planner.MAX_BYTES, receiving.MAX_BYTES, receiving.MAX_BYTES, receiving.MAX_BYTES)
    for raw, maximum in zip(originals, limits, strict=True):
        authorization._original(raw, maximum, "activation issuance response frame")
    if sum(map(len, originals)) > policy.authority.MAX_RESULT_BYTES:
        _fail("activation issuance response exceeds its aggregate original ceiling")
    held_request = authorization._original(request_bytes, MAX_REQUEST_BYTES, "activation issuance request")
    work.charge(input_bytes=len(originals[0]) + len(held_request))
    if originals[0] != held_request:
        _fail("activation issuance response changed the actual caller request")
    admitted = policy._verify_on_work(policy_bytes=policy_bytes, root_public_key=root_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, _continuity=_continuity)
    request = _verify_request(held_request, admitted, work, admitted.live)
    window = policy.clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    issued, expires = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    bound = min(window[4], transport_deadline_ns, window[1] + expires - window[0])
    bound_current = planner._processing(window, bound, work, _continuity=_continuity)

    def current():
        before = admitted.live()
        final = bound_current()
        if final < before or not issued <= final < expires:
            _fail("issuance response crossed its unchanged original request interval")
        return final

    current()
    planned = planner._verify_on_work(bootstrap_bytes=originals[3], root_public_key=root_public_key,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    envelope = planner.codec._decode(originals[3], work)
    payload = envelope["payload"]
    # Canonical Service6 comparison preserves its finite-float domain. It does
    # not use Python bool/int equality or a caller-selected root inventory.
    work.charge(input_bytes=128 * len(policy.RESOURCE_FIELDS), json_nodes=len(policy.RESOURCE_FIELDS))
    resources = {name: payload[name] for name in policy.RESOURCE_FIELDS}
    actual_resources = policy.configuration._configuration_wire(resources, capture._SharedLedger(work))
    expected_resources = policy.configuration._configuration_wire(
        admitted.payload["plannerResources"], capture._SharedLedger(work))
    work.charge(input_bytes=len(actual_resources) + len(expected_resources))
    if actual_resources != expected_resources:
        _fail("activation issued planner changed an independently pinned resource")
    plan._same(planned.attestation_interval,
        (request["issuedAtEpochNs"], request["expiresAtEpochNs"]), work,
        "activation issued planner retimed its request")
    query = head._decode_query_on_work(originals[1], work=work)
    plan._same(query["contextDigest"], plan._frame(REQUEST_IDENTITY_DOMAIN, (held_request,), work),
        work, "activation issued head query belongs to another request")
    plan._same(query["expectedVectorDigest"], planned.complete_root_vector_digest, work,
        "activation issued planner differs from observed current vector")
    observed = head._verify_on_work(observation_bytes=originals[2], query_bytes=originals[1],
        enrollment_bytes=planned.state_enrollment_bytes, root_public_key=root_public_key,
        now_epoch_ns=current(), work=work)
    if observed["pendingRequestDigest"] is not None or observed["pendingDecisionDigest"] is not None:
        _fail("activation issued planner observed a pending transition")
    for consumer, raw in zip(policy.RECEIVERS, originals[4:], strict=True):
        material = receiving._verify_on_work(custody_bytes=raw, root_public_key=root_public_key,
            expected_consumer_role=consumer, work=work, live_window=window,
            transport_deadline_ns=bound)
        plan._same(material.receiver_identity, admitted.payload["receiverIdentities"][consumer],
            work, "activation issued receiver differs from its independent pin")
        work.charge(input_bytes=len(material.planner.bootstrap_bytes) + len(originals[3]))
        if material.planner.bootstrap_bytes != originals[3]:
            _fail("activation issued receiving custody changed the actual planner original")
        plan._same(material.attestation_interval, planned.attestation_interval, work,
            "activation issued receiving custody retimed its planner")
        current()
    _verify_request(held_request, admitted, work, current)
    current()
    return originals
