"""Root-original consume inputs derived from exact historical activation controls.

Fresh issuer policy and original old-token possession govern this issuance.
Historical signatures do not renew activation permission or replace private
replay/current-row checks in the genuine consume planner. No resource is
provisioned, private history opened, token retained or state changed here.
"""
from __future__ import annotations

import base64
import hashlib
import time

from serverware import authority_current_root_authorization as state
from serverware import authority_current_root_completion as observations
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_delivery_records as acknowledgments
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_oidc_session_activation_consume_input_transport as transport
from serverware import authority_oidc_session_activation_delivery_plan as consumption
from serverware import authority_oidc_session_activation_execution_authorization as caller
from serverware import authority_oidc_session_activation_reservation_records as reservations
from serverware import authority_registration_completion_response as neutral
from serverware import oidc_session_activation_consume_input_issuer_policy as issuer


history, bootstrap, activation = issuer.history, issuer.consume, issuer.activation
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, clock, keys = issuer.capture, issuer.clock, issuer.keys
production, processing, authority = issuer.production, issuer.processing, issuer.authority
assertion, registration = consumption.assertion, consumption.registration
expectations_wire = caller.expectations_wire
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
_OUTPUT_RESERVATION = (2 * (history.MAX_BYTES + bootstrap.MAX_BYTES)
    + 2 * history.MAX_CONSUME_REQUEST_BYTES + 2 * state.vector.MAX_BYTES)


class OidcSessionActivationConsumeInputProductionError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationConsumeInputProductionError(message)


class _Lifetime:
    """Same-call restrictive bookkeeping; never accepted as original authority."""

    def __init__(self, window, bound, work, continuity):
        self.window, self.bound, self.work = window, bound, work
        self.epoch, self.monotonic = window[0], window[2]
        self.guards, self.continuation = [], continuity
        self.limits, self.metrics = work.limits, work.metrics
        self.ceilings = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        if continuity is not None and not callable(continuity):
            _fail("consume input continuity is not callable")

    def _ledger(self):
        capture._SharedLedger(self.work)
        limits, metrics = self.work.limits, self.work.metrics
        if (limits is not self.limits
                or self.ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or metrics.hash_work < self.metrics.hash_work
                or metrics.input_bytes < self.metrics.input_bytes
                or metrics.json_nodes < self.metrics.json_nodes):
            _fail("consume input issuance reset its original work allowance")
        self.metrics = metrics

    def _floors(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self.epoch or monotonic < self.monotonic
                or epoch >= self.window[3] or monotonic >= self.bound):
            _fail("consume input clocks reversed or exceeded the narrowed allowance")
        self.epoch, self.monotonic = epoch, monotonic

    def _owner(self):
        self._ledger()
        if self.continuation is not None:
            observed = self.continuation(self.epoch, self.monotonic)
            self._ledger()
            if type(observed) is not tuple or len(observed) != 2:
                _fail("consume input continuity must return only two clock floors")
            self._floors(*observed)

    def base(self):
        self._owner()
        epoch = clock._check_on_work(self.window, work=self.work)
        monotonic = production._callback(self.work, time.monotonic_ns)
        self._floors(epoch, monotonic)
        self._owner()
        return self.epoch

    def continuity(self, epoch, monotonic):
        self._floors(max(self.epoch, epoch), max(self.monotonic, monotonic))
        self.base()
        return self.epoch, self.monotonic

    def current(self):
        self.base()
        for guard in self.guards:
            observed = guard()
            if type(observed) is not int or observed < self.epoch or observed >= self.window[3]:
                _fail("consume input original guard reversed or expired")
            self.epoch = observed
            self.base()
        return self.epoch

    def attach(self, guard):
        if not callable(guard):
            _fail("consume input admission lacks its actual original guard")
        self.guards.append(guard)
        self.current()

    def adopt(self, window, bound):
        selected = clock._validate(window)
        shape._integer(bound, minimum=1)
        if (selected[:3] != self.window[:3] or bound > self.bound or bound > selected[4]
                or any(value > old for value, old in zip(selected[3:], self.window[3:]))):
            _fail("consume input admission widened the original allowance")
        self.current()
        self.window, self.bound = selected, bound
        self.current()

    def narrow(self, expiry, age, skew):
        selected = processing._narrow(self.window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=min(age, self.window[5]),
            maximum_clock_skew_ns=min(skew, self.window[6]))
        self.adopt(selected, min(self.bound, selected[4]))


def _same_bytes(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        _fail(label + " requires immutable originals")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label + " differs")


def _bytes_digest(original, work, current):
    work.charge(hashes=1, input_bytes=len(original))
    current()
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    return digest


def _wrapped(original, work, current):
    size = (4 * len(original) + 2) // 3
    work.charge(input_bytes=len(original) + size)
    digest = _bytes_digest(original, work, current)
    current()
    encoded = production._callback(work,
        lambda: base64.urlsafe_b64encode(original).decode("ascii").rstrip("="))
    current()
    if len(encoded) != size:
        _fail("consume input wrapper changed its reserved size")
    return {"base64Url": encoded, "byteCount": len(original), "bytesDigest": digest}


def _observation(complete, marker, after, work):
    raw = state.transport._decode(complete["writerReceiptBase64Url"],
        complete["writerReceiptByteCount"], observations.MAX_OBSERVATION_BYTES, work)
    document = state.wire._decode_object(raw, work=work,
        maximum_bytes=observations.MAX_OBSERVATION_BYTES,
        maximum_nodes=observations.MAX_OBSERVATION_NODES, maximum_depth=3)
    shape._object(document, neutral._OBSERVATION_FIELDS, "consume input activation observation")
    shape._literal(document["schema"], observations.OBSERVATION_SCHEMA)
    shape._literal(document["sourceRevision"], authority.SOURCE_REVISION)
    shape._object(document["marker"], frozenset(pending._MARKER_COLUMNS), "activation marker")
    plan._same(document["marker"], marker, work, "consume input exact signed activation marker")
    digest = state.vector._digest_on_work(after, work=work)
    for value in (marker["after_vector_digest"], complete["afterVectorDigest"], document["afterVectorDigest"]):
        plan._same(value, digest, work, "consume input complete after-vector")
    observed = document["observedAtEpochNs"]
    shape._integer(observed, minimum=1)
    if not complete["issuedAtEpochNs"] <= observed < complete["expiresAtEpochNs"]:
        _fail("consume input completion observation escapes its original interval")
    _same_bytes(raw, observations._observation_bytes(marker, digest, observed, work),
        work, "consume input canonical completion observation")


def _activation_controls(raw, expected, before, policy, root, lifetime, work):
    """Genuine historical public controls, not private plan/SQL replay."""
    current, material = lifetime.current, policy.activation_planner
    enrollment, planner_key = material.state_enrollment_bytes, material.planner_public_key
    source = expected["request"]
    arguments = caller.activation.plan.transition._arguments(source["arguments"], work)
    scope = expected["scope"]
    for name, value in (("configurationDigest", material.configuration_digest),
            ("plannerIdentity", material.planner_identity), ("plannerSpkiDigest", material.planner_spki_digest),
            ("rpId", material.rp_id), ("origin", material.origin),
            ("authenticationPolicy", material.authn_policy), ("trustPolicy", material.trust_policy),
            ("maximumPlanAgeNs", material.maximum_plan_age_ns),
            ("maximumClockSkewNs", material.maximum_clock_skew_ns),
            ("userId", arguments["user_id"]), ("sessionId", arguments["session_id"]),
            ("credentialId", arguments["credential_id"]),
            ("credentialRecordId", arguments["credential_record_id"]),
            ("challengeId", arguments["challenge_id"])):
        plan._same(scope[name], value, work, "consume input independently bound activation " + name)
    plan._same(arguments["delivery_ttl_seconds"], material.delivery_ttl_seconds, work,
        "consume input original activation delivery lifetime")
    _same_bytes(before, material.complete_root_vector_bytes, work, "consume input original activation vector")
    current()
    authorized = caller._verify_historical_on_work(authorization_bytes=raw[9],
        authorization_enrollment_bytes=raw[11], current_root_enrollment_bytes=enrollment,
        grant_enrollment_bytes=raw[12], root_public_key=root,
        configuration_digest=material.configuration_digest, planner_public_key=planner_key,
        operation_public_key=root, originals=(raw[4], raw[5]), expectations=expected,
        before_vector_bytes=before, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    lifetime.continuity(authorized.last_epoch_ns, authorized.last_monotonic_ns)
    lifetime.attach(authorized.live)
    current()
    grant, grant_digest = caller.grants._verify_historical_control_on_work(grant_bytes=raw[10],
        grant_enrollment_bytes=raw[12], current_root_enrollment_bytes=enrollment,
        root_public_key=root, planner_public_key=planner_key, operation_public_key=root,
        expected_authorization_digest=authorized.authorization_digest, work=work)
    original_plan = caller.activation.contract._decode_on_work(raw[4], envelope=True, work=work)["payload"]
    for name, value in (("operation", caller.OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("planDigest", authorized.plan_digest),
            ("retainedRecordDigest", authorized.retained_record_digest),
            ("beforeVectorDigest", authorized.before_vector_digest),
            ("grantEnrollmentDigest", authorized.grant_enrollment_digest),
            ("currentRootEnrollmentDigest", authorized.current_root_enrollment_digest),
            ("databaseId", authorized.database_id), ("generationDigest", authorized.generation_digest),
            ("originalIssuedAtEpochNs", original_plan["issuedAtEpochNs"]),
            ("originalExpiresAtEpochNs", original_plan["expiresAtEpochNs"])):
        plan._same(grant[name], value, work, "consume input historical grant " + name)
    frames = [{"position": index, "byteCount": len(original),
        "bytesDigest": _bytes_digest(original, work, current)} for index, original in enumerate(raw[4:6])]
    plan._same(grant["originalFrames"], frames, work, "consume input exact grant frames")
    if not (grant["issuedAtEpochNs"] <= authorized.issued_at_epoch_ns
            < authorized.expires_at_epoch_ns <= grant["originalExpiresAtEpochNs"]
            and grant["expiresAtEpochNs"] <= authorized.expires_at_epoch_ns):
        _fail("consume input grant retimes original caller authority")
    current()
    state_material, reserve, reserve_digest = state._verify_historical_request_on_work(
        request_bytes=raw[6], enrollment_bytes=enrollment, root_public_key=root, work=work)
    predecessor = reservations._predecessor_scope(*policy.activation_predecessor)
    for name, value in (("action", "reserve"), ("operation", caller.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("capabilityDigest", grant_digest), ("predecessorSequence", predecessor[0]),
            ("predecessorHeadDigest", predecessor[1]), ("fence", predecessor[2]),
            ("enrollmentDigest", grant["currentRootEnrollmentDigest"]),
            ("databaseId", grant["databaseId"]), ("generationDigest", grant["generationDigest"])):
        plan._same(reserve[name], value, work, "consume input independent reserve " + name)
    if (reserve["issuedAtEpochNs"] != grant["issuedAtEpochNs"]
            or reserve["expiresAtEpochNs"] > grant["expiresAtEpochNs"]):
        _fail("consume input reserve retimes its historical grant")
    _same_bytes(state.vector._encode_on_work(reserve["beforeVector"], work=work), before,
        work, "consume input signed reserve before-vector")
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    for name, original in (("beforeVectorDigest", before), ("afterVectorDigest", after)):
        plan._same(state.vector._digest_on_work(original, work=work), grant[name], work,
            "consume input reserve/grant " + name)
    snapshot = computation._decode_snapshot_on_work(raw[8], work=work)
    for name in ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
            "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest", "afterVectorDigest",
            "resultDigest", "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs",
            "signedSnapshotDigest", "signedCapabilityId"):
        plan._same(snapshot[name], grant[name], work, "consume input snapshot/grant " + name)
    plan._same(snapshot["capabilityDigest"], grant_digest, work, "consume input snapshot grant identity")
    checked, checked_digest, receipt, pending_digest = reservations._verify_on_work(
        request_bytes=raw[6], snapshot_bytes=raw[8], receipt_bytes=raw[7],
        enrollment_bytes=enrollment, root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    plan._same(checked, reserve, work, "consume input reserve original readback")
    plan._same(checked_digest, reserve_digest, work, "consume input reserve original identity")
    if receipt is None or pending_digest is None:
        _fail("consume input lacks an authenticated original reserve acknowledgment")
    marker = pending._marker(state_material, reserve, reserve_digest, receipt, pending_digest, snapshot, work)
    current()
    if raw[0] != b"acknowledged":
        _fail("consume input requires the signed acknowledged activation completion originals")
    completed_material, complete, complete_digest = state._verify_historical_request_on_work(
        request_bytes=raw[2], enrollment_bytes=enrollment, root_public_key=root, work=work)
    acknowledged = acknowledgments._verify_ack_on_work(request_bytes=raw[2], receipt_bytes=raw[3],
        enrollment_bytes=enrollment, root_public_key=root,
        expected_pending_sequence=predecessor[0] + 1, expected_pending_head_digest=pending_digest, work=work)
    plan._same(acknowledged.request_payload, complete, work, "consume input COMPLETE readback")
    plan._same(acknowledged.request_digest, complete_digest, work, "consume input COMPLETE identity")
    _same_bytes(raw[1], plan._ascii(complete_digest, work), work, "consume input returned completion identity")
    plan._same(complete["action"], "complete", work, "consume input fixed completion action")
    for name, column in neutral._REQUEST_MARKER_JOINS:
        plan._same(complete[name], marker[column], work, "consume input signed completion " + name)
    _observation(complete, marker, after, work)
    if complete["issuedAtEpochNs"] > current() + completed_material.payload["maxClockSkewNs"]:
        _fail("consume input completion is issued in the current future")
    current()
    activation_scope = {"authorizationDigest": authorized.authorization_digest,
        "databaseId": authorized.database_id, "generationDigest": authorized.generation_digest,
        "pendingSequence": predecessor[0] + 1, "pendingHeadDigest": pending_digest, "fence": predecessor[2]}
    return arguments, activation_scope, after


def _derive_on_work(*, request_originals, issuer_policy_bytes, activation_planner_bootstrap_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Re-admit originals and derive payloads; no signing key or result ingress.

    The returned private lifetime and payload data are same-call outputs only.
    The planner payload lacks solely historyCustody, bound to an actual signed
    history original by _bind_history_on_work after issuance or receiving.
    """
    if type(request_originals) is not tuple or len(request_originals) != 16:
        _fail("consume input issuance requires exact raw16 original suffix")
    request = transport._originals((transport.PURPOSE, *request_originals), response=False)[1:]
    policy_raw = authorization._original(issuer_policy_bytes, issuer.MAX_BYTES, "consume input policy")
    activation_raw = authorization._original(activation_planner_bootstrap_bytes,
        issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "historical activation planner")
    root, continuation = root_public_key, _continuity
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    total = sum(map(len, request)) + len(policy_raw) + len(activation_raw)
    if total + _OUTPUT_RESERVATION + transport.REQUEST_HEADER_BYTES > MAX_ORIGINAL_BYTES:
        _fail("consume input complete originals and derived output inventory exceeds 64 MiB")
    capture._SharedLedger(work)
    work.charge(input_bytes=total + transport.REQUEST_HEADER_BYTES)
    authorization._public(root)
    lifetime = _Lifetime(window, bound, work, continuation)
    current = lifetime.current
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_raw,
        activation_planner_bootstrap_bytes=activation_raw, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("consume input policy requires genuine original admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    material = policy.activation_planner
    embedded = len(material.complete_root_vector_bytes) + len(material.state_enrollment_bytes)
    if total + embedded + _OUTPUT_RESERVATION + 2 * len(activation_raw) > MAX_ORIGINAL_BYTES:
        _fail("consume input decoded and wrapped originals exceed the held inventory")
    work.charge(input_bytes=embedded)
    issued = policy.payload["issuedAtEpochNs"]
    expires = min(policy.payload["expiresAtEpochNs"],
        issued + min(material.maximum_plan_age_ns, activation.MAX_RECEIPT_AGE_NS))
    if issued >= expires:
        _fail("consume input deterministic output interval is empty")
    lifetime.narrow(expires, material.maximum_plan_age_ns, material.maximum_clock_skew_ns)
    raw = consumption._activation_originals(request[:13], work)
    before = authorization._original(request[14], state.vector.MAX_BYTES, "activation before-vector")
    decoded = issuer.capability.wire._decode_object(request[13], work=work,
        maximum_bytes=expectations_wire.MAX_BYTES, maximum_nodes=expectations_wire.MAX_NODES,
        maximum_depth=12)
    expected = expectations_wire._capture_on_work(decoded, work=work)
    _same_bytes(request[13], registration._wire(expected, work), work, "canonical activation expectations")
    arguments, activation_scope, after = _activation_controls(raw, expected, before, policy, root, lifetime, work)
    old_token = assertion._token(request[15], work)
    plan._same(_bytes_digest(old_token, work, current), arguments["old_token_digest"], work,
        "consume input actual old-token possession")
    semantic = {name: arguments[name] for name in consumption.transition._ARGUMENT_FIELDS
        if name not in ("delivery_id", "businessIntent")}
    semantic["delivery_id"] = consumption.core._deterministic_uuid(operation=caller.OPERATION,
        request_digest=expected["request"]["requestDigest"],
        purpose=consumption.transition.activation.DELIVERY_PURPOSE, work=work)
    intent = registration.authority._synthesize_business_intent(consumption.transition.OPERATION, semantic, work=work)
    consume_request = {"schema": "serverware.policyAuthorityV9Request/v1",
        "operation": consumption.transition.OPERATION, "operationId": "sha256:" + "0" * 64,
        "requestDigest": "sha256:" + "0" * 64,
        "handler": authority.operation_spec(consumption.transition.OPERATION)["handler"],
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "arguments": {**semantic, "businessIntent": intent}}
    digest = consumption.commitment._typed_request_digest(consume_request, work=work)
    consume_request["requestDigest"] = digest
    consume_request["operationId"] = plan._frame("serverware.policyAuthorityOperation/v2",
        (plan._ascii(consumption.transition.OPERATION, work), plan._ascii(digest, work)), work)
    consume_bytes = history._consume_request_on_work(consume_request, work)
    current()
    common = {"sourceRevision": authority.SOURCE_REVISION, "trustMode": "trusted-host-local",
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
        **{name: False for name in activation._FALSE_FIELDS}}
    history_payload = {**common, "schema": history.CONSUME_PAYLOAD_SCHEMA,
        "operation": history.CONSUME_OPERATION, "consumerRole": history.CONSUME_CONSUMER_ROLE,
        "processMode": history.CONSUME_PROCESS_MODE, "serviceUid": history.CONSUME_SERVICE_UID,
        "serviceGid": history.CONSUME_SERVICE_GID, **policy.history,
        "configurationDigest": material.configuration_digest,
        "generationDigest": material.generation["digest"], "runtimeClosureDigest": material.runtime_closure_digest,
        "plannerBootstrap": _wrapped(activation_raw, work, current),
        "consumeRequest": _wrapped(consume_bytes, work, current)}
    vector = _wrapped(after, work, current)
    vector["identityDigest"] = state.vector._digest_on_work(after, work=work)
    enrollment = _wrapped(material.state_enrollment_bytes, work, current)
    enrollment["identityDigest"] = material.state_enrollment_digest
    planner_payload = {**common, "schema": bootstrap.PAYLOAD_SCHEMA, "role": bootstrap.ROLE,
        "operation": bootstrap.OPERATION, **policy.consume_planner,
        "configurationPayload": material.configuration_payload, "configurationDigest": material.configuration_digest,
        "generation": material.generation, "runtimeRoleIdentities": material.runtime_role_identities,
        "runtimeClosureDigest": material.runtime_closure_digest, "authenticationPolicy": material.authn_policy,
        "trustPolicy": material.trust_policy, "maximumPlanAgeNs": material.maximum_plan_age_ns,
        "maximumClockSkewNs": material.maximum_clock_skew_ns,
        "consumeRequest": consume_request, "activationExpectations": expected, "activationScope": activation_scope,
        "historyReceiverIdentity": policy.history["receiverIdentity"],
        "queryManifestDigest": material.configuration_payload["queryManifestDigest"],
        "completeRootVector": vector, "databaseId": activation_scope["databaseId"], "stateEnrollment": enrollment}
    current()
    return policy, lifetime, history_payload, planner_payload


def _bind_history_on_work(planner_payload, history_custody_bytes, work, current):
    """Bind an actual original; no signature or authority is inferred here."""
    original = authorization._original(history_custody_bytes, history.MAX_BYTES, "consume history output")
    if type(planner_payload) is not dict or "historyCustody" in planner_payload:
        _fail("consume input derived planner payload has an unexpected history selector")
    owned = issuer.configuration._ConfigurationCapture(capture._SharedLedger(work),
        maximum_bytes=bootstrap.MAX_BYTES).visit(planner_payload)
    owned["historyCustody"] = {"byteCount": len(original), "bytesDigest": _bytes_digest(original, work, current)}
    return owned


def _produce_on_work(*, request_originals, issuer_policy_bytes, activation_planner_bootstrap_bytes,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    """Return only (consume planner bootstrap, history custody) root originals."""
    private, root = root_private_key, root_public_key
    authorization._private(private)
    authorization._public(root)
    policy, lifetime, history_payload, planner_payload = _derive_on_work(
        request_originals=request_originals, issuer_policy_bytes=issuer_policy_bytes,
        activation_planner_bootstrap_bytes=activation_planner_bootstrap_bytes, root_public_key=root,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity)
    current = lifetime.current
    current()
    keys._pair_on_work(private, root, work)
    current()
    custody = history._produce_consume_on_work(payload=history_payload, root_private_key=private,
        root_public_key=root, work=work, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, _continuity=lifetime.continuity)
    current()
    admitted_history = history._verify_consume_on_work(custody_bytes=custody, root_public_key=root,
        work=work, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        _continuity=lifetime.continuity)
    actual_history = history._decode(custody, work)["payload"]
    plan._same(actual_history, history_payload, work, "consume input exact signed history payload")
    _same_bytes(admitted_history.planner.bootstrap_bytes, policy.activation_planner_bootstrap_bytes,
        work, "consume input history exact activation bootstrap")
    current()
    expected_planner = _bind_history_on_work(planner_payload, custody, work, current)
    planner = bootstrap._produce_on_work(payload=expected_planner, history_custody_bytes=custody,
        root_private_key=private, root_public_key=root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    current()
    admitted = bootstrap._verify_on_work(bootstrap_bytes=planner, history_custody_bytes=custody,
        root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    # Configuration alone permits finite fractional timeout values. Preserve
    # its genuine canonical serializer instead of proof-JSON scalar grammar.
    actual_payload = issuer.configuration._configuration_wire(admitted.payload, capture._SharedLedger(work))
    expected_payload = issuer.configuration._configuration_wire(expected_planner, capture._SharedLedger(work))
    _same_bytes(actual_payload, expected_payload, work, "consume input exact signed planner payload")
    _same_bytes(admitted.history_custody_bytes, custody, work, "consume input exact history readback")
    _same_bytes(admitted.consume_request_bytes, admitted_history.consume_request_bytes,
        work, "consume input exact typed consume readback")
    response = transport._originals((planner, custody), response=True)
    current()
    return response
