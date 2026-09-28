"""Historical public completion controls on the exact fresh actor context.

Root-pinned caller originals, genuine enrollments, signed plans/grants and the
original acknowledged reserve are admitted here. Ciphertext stays opaque;
these public controls neither replay private proofs nor establish SQL commit.
No old issue/expiry is replaced by the current processing window.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_current_root_authorization as state
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import authority_oidc_session_activation_delivery_execution_authorization as consume
from serverware import authority_oidc_session_activation_reservation_records as activation_reservations
from serverware import control_plane_oidc_session_activation_completion_recovery_actor as actors
from serverware import control_plane_oidc_session_activation_consume_dispatch as consume_dispatch
from serverware import control_plane_oidc_session_activation_consume_records as consume_records
from serverware import control_plane_oidc_session_activation_records as activation_records


execution, history = actors.execution, actors.history
caller, plan, shape = execution.caller, execution.plan, execution.shape
MAX_ORIGINAL_BYTES = caller.grants.replay.MAX_ORIGINAL_BYTES
_CONSTRUCTION = object()
_METADATA_BYTES = 16 * 1024


class CompletionRecoveryControlsError(ValueError):
    pass


def _fail(message):
    raise CompletionRecoveryControlsError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionControls:
    """Private same-actor observations, never an external authority argument."""

    _construction: object
    _actor: object
    profile: str
    originals: tuple
    before_bytes: bytes
    after_bytes: bytes
    marker: dict
    enrollment_bytes: bytes
    root_public_key: object
    current_pending: tuple
    endpoint: tuple
    packet_digest: str
    authorization_digest: str
    finalization_digest: str
    work: object
    window: tuple
    deadline_ns: int
    original_reservation_bytes: int
    prior_response: tuple | None
    prior_completion: tuple | None
    authority: object
    _live: object
    _seal: tuple | None = None

    def current(self):
        _identity(self)
        epoch = self._live()
        _identity(self)
        return epoch


_SEALED_FIELDS = ("_actor", "profile", "originals", "before_bytes", "after_bytes", "marker",
    "enrollment_bytes", "root_public_key", "current_pending", "endpoint", "packet_digest",
    "authorization_digest", "finalization_digest", "work", "window", "deadline_ns",
    "original_reservation_bytes", "prior_response", "prior_completion", "authority", "_live")


def _identity(value):
    if (type(value) is not _CompletionControls or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != 2
            or type(value._seal[0]) is not tuple or len(value._seal[0]) != len(_SEALED_FIELDS)
            or type(value._seal[1]) is not tuple or len(value._seal[1]) != len(pending._MARKER_COLUMNS)
            or any(getattr(value, name) is not held for name, held in zip(_SEALED_FIELDS, value._seal[0]))
            or type(value.marker) is not dict or tuple(value.marker) != pending._MARKER_COLUMNS):
        _fail("completion controls are not the source-owned original continuation")
    for name, expected in zip(pending._MARKER_COLUMNS, value._seal[1]):
        actual = value.marker[name]
        if type(actual) is not type(expected) or actual != expected:
            _fail("completion controls changed their authenticated marker")
    actor = value._actor
    if (type(actor) is not actors._CompletionActorScope or actor._active is not True
            or actor._authorized is not True or actor._completion_recovery_spent is not True
            or actor._work is not value.work or actor._profile != value.profile
            or actor._target.authority is not value.authority):
        _fail("completion controls outlived their exact fresh actor")


def _require_controls(value):
    """Only the actual source-owned same-call context reaches the exchange."""
    _identity(value)
    value.current()
    return value


def _same_bytes(actual, expected, work, label):
    bookkeeping._same_bytes(actual, expected, work, "completion recovery " + label)


def _record(record, kind, phase, finalization, activation_digest, work):
    codec = activation_records if phase == "activation" else consume_records
    expected_type = codec.ActivationRecord if phase == "activation" else codec.ConsumeRecord
    if (type(record) is not expected_type or record.kind != kind
            or record.source_revision != state.authority.SOURCE_REVISION
            or record.finalization_digest != finalization):
        _fail("completion recovery retained record has a different source or association")
    if phase == "consume":
        plan._same(record.activation_authorization_digest, activation_digest, work,
            "completion recovery consume association to genuine activation")
        plan._same(record.slot_digest, consume_records._slot_digest(finalization, activation_digest), work,
            "completion recovery exact consume slot")
    return codec._originals(codec.KINDS.index(kind), record.originals)


def _target_arguments(expected, target, phase, work):
    request, scope = expected["request"], expected["scope"]
    transition = caller.history.plan.transition if phase == "activation" else consume.consume.transition
    arguments = transition._arguments(request["arguments"], work)
    for field, value in (("user_id", target.subject["userId"]),
            ("session_id", target.subject["sessionId"]), ("credential_id", target.subject["credentialId"]),
            ("credential_record_id", target.credential_record_id), ("challenge_id", target.challenge_id),
            ("old_token_digest", target.old_token_digest), ("new_token_digest", target.new_token_digest)):
        plan._same(arguments[field], value, work, "completion recovery original target " + field)
    for field, name in (("user_id", "userId"), ("session_id", "sessionId"),
            ("credential_id", "credentialId"), ("credential_record_id", "credentialRecordId"),
            ("challenge_id", "challengeId")):
        plan._same(scope[name], arguments[field], work, "completion recovery request/scope " + name)
    if phase == "consume":
        plan._same(scope["deliveryId"], arguments["delivery_id"], work,
            "completion recovery exact signed consume delivery")


def _consume_authorization(original, raw2, before, expected, policy, root, config,
        lifetime, work):
    """Historical public signatures only; deliberately no live/private replay mode."""
    current = lifetime.base
    current()
    enrolled = consume._admit_enrollment_on_work(
        authorization_enrollment_bytes=policy.authorization_enrollment_bytes,
        current_root_enrollment_bytes=policy.current_root_enrollment_bytes,
        grant_enrollment_bytes=policy.grant_enrollment_bytes, root_public_key=root,
        configuration_digest=config, planner_public_key=policy.planner_public_key,
        operation_public_key=policy.operation_public_key, work=work)
    envelope = consume._read(original, enrollment=False, work=work)
    payload, delegated = envelope["payload"], enrolled.payload
    lifetime.narrow(lifetime.window[3], delegated["maximumAgeNs"], delegated["maximumClockSkewNs"])
    consume.primitives._signature(envelope, enrolled.caller_public_key, consume.MAX_AUTHORIZATION_BYTES, work)
    for field in consume._SCOPE_FIELDS:
        plan._same(payload[field], delegated[field], work, "historical consume caller " + field)
    plan._same(payload["authorizationEnrollmentDigest"], enrolled.enrollment_digest, work,
        "historical consume caller enrollment")
    plan._same(payload["callerMeasurementDigest"], delegated["callerKey"]["measurementDigest"], work,
        "historical consume caller measurement")
    state._interval(payload, delegated["maximumAgeNs"])
    if payload["issuedAtEpochNs"] > current() + delegated["maximumClockSkewNs"]:
        _fail("historical consume caller is issued in the current future")
    signed = consume.contract._decode_on_work(raw2[0], envelope=True, work=work)
    actual, scope, request = signed["payload"], expected["scope"], expected["request"]
    for field in ("requestDigest", "operationId"):
        plan._same(actual[field], request[field], work, "historical consume plan " + field)
    plan._same(scope["configurationDigest"], config, work, "historical consume parent configuration")
    for field in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        plan._same(actual[field], scope[field], work, "historical consume signed scope " + field)
    consume.evidence.keys._public_binding(policy.planner_public_key, scope["plannerSpkiDigest"], work)
    unsigned = consume.contract._encode_on_work(actual, work=work)
    consume.evidence.capability._signature(policy.planner_public_key, signed["signatureBase64Url"],
        consume.contract.SIGNATURE_DOMAIN, unsigned, consume.capture._SharedLedger(work))
    for name, maximum, minimum in (("maximumPlanAgeNs", state.authority.VERIFIER_RESPONSE_MAX_AGE_NS, 1),
            ("maximumClockSkewNs", state.authority.VERIFIER_MAX_CLOCK_SKEW_NS, 0),
            ("deadlineEpochNs", 2**63 - 1, 1)):
        shape._integer(scope[name], maximum, minimum=minimum)
    lifetime.narrow(lifetime.window[3], scope["maximumPlanAgeNs"], scope["maximumClockSkewNs"])
    if (actual["expiresAtEpochNs"] - actual["issuedAtEpochNs"] > scope["maximumPlanAgeNs"]
            or actual["expiresAtEpochNs"] > scope["deadlineEpochNs"]
            or actual["issuedAtEpochNs"] > current() + scope["maximumClockSkewNs"]
            or not actual["issuedAtEpochNs"] <= payload["issuedAtEpochNs"]
                < payload["expiresAtEpochNs"] <= actual["expiresAtEpochNs"]):
        _fail("historical consume intervals escape original policy")
    facts = {name: request[name] for name in ("requestDigest", "operationId")}
    facts.update({"planDigest": plan._frame(consume.contract.IDENTITY_DOMAIN, (raw2[0],), work),
        "retainedRecordDigest": plan._frame(consume.bundle.RECORD_IDENTITY_DOMAIN, raw2, work),
        "journalDigest": expected["journalDigest"],
        "beforeVectorDigest": state.vector._digest_on_work(before, work=work)})
    for field in consume._FACT_FIELDS:
        plan._same(payload[field], facts[field], work, "historical consume exact original " + field)
    consume.primitives._unchanged(original, envelope, consume.MAX_AUTHORIZATION_BYTES, work)
    current()
    return payload, actual, facts


def _admit_on_actor(actor, *, _additional_original_bytes=0):
    """Load and authenticate fixed original controls, never posted result data."""
    if (type(actor) is not actors._CompletionActorScope or actor._active is not True
            or actor._authorized is not True or actor._completion_recovery_spent is not True
            or type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES):
        _fail("completion controls require the spent, freshly authorized actual actor")
    actor.current()
    work, owner, target = actor._work, actor._owner, actor._target
    parent, binding, custody, configured = owner._material, owner._binding, owner._custody, actor._configuration
    phase, finalization = actor._profile, target.subject["localDigest"]
    authority = target.authority
    if type(authority) is not history.historical._SelectedActivationHistory:
        _fail("completion controls lack their original authenticated historical authority")
    authority.live()
    policy = authority.activation_execution if phase == "activation" else authority.consume_execution
    policy_type = (execution.configured._ActivationExecutionMaterial if phase == "activation"
        else consume_dispatch.configured._ConsumeExecutionMaterial)
    if type(policy) is not policy_type:
        _fail("completion controls lack the selected historical execution lane")
    recovery = authority.completion_recovery
    if type(recovery) is not actors.configured._CompletionRecoveryMaterial:
        _fail("completion controls have no independently configured historical completion pins")
    recovery_scope = recovery.activation if phase == "activation" else recovery.consume
    if type(recovery_scope) is not actors.configured._CompletionRecoveryScope:
        _fail("completion controls historical completion profile is disabled")
    # Routing remains the current actor's independently enabled endpoint. Only
    # these original authority pins are supplied by the selected archived lane.
    for name in ("packet_digest", "authorization_digest", "current_pending"):
        plan._same(getattr(configured, name), getattr(recovery_scope, name), work,
            "completion recovery exact selected historical " + name)
    root, configuration_digest = authority.root_public_key, authority.configuration_digest
    authority_interval = authority.authority_interval
    if type(authority_interval) is not tuple or len(authority_interval) != 2:
        _fail("completion controls lack their original historical interval")
    for value in authority_interval:
        shape._integer(value, minimum=1)
    if authority_interval[0] >= authority_interval[1]:
        _fail("completion controls historical interval is empty")
    enrollment_originals = (policy.authorization_enrollment_bytes,
        policy.current_root_enrollment_bytes, policy.grant_enrollment_bytes)
    cold = 4 * sum(map(len, enrollment_originals))
    # Eight selected-original footprints cover the loader's three plus the
    # bounded canonical/signature/control captures below; fixed outputs are
    # reserved before any selected body is read. This is not a heap estimate.
    held = (target.original_reservation_bytes + _additional_original_bytes + cold
        + 8 * _METADATA_BYTES + 4 * state.vector.MAX_BYTES
        + 4 * max(caller.expectations_wire.MAX_BYTES, consume.expectations_wire.MAX_BYTES))
    if held >= MAX_ORIGINAL_BYTES:
        _fail("completion controls have no remaining original admission capacity")
    keys_pin = (root, policy.planner_public_key, policy.operation_public_key, policy.caller_public_key)
    for key in keys_pin:
        state._public(key)
    window, bound = caller.clock._validate(actor._window), min(actor._bound, actor._window[4])

    def identity():
        if (actor._owner is not owner or actor._work is not work or actor._target is not target
                or actor._configuration is not configured or actor._profile != phase
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or target.authority is not authority or authority.completion_recovery is not recovery
                or authority.authority_interval is not authority_interval
                or authority.configuration_digest is not configuration_digest
                or (recovery.activation if phase == "activation" else recovery.consume) is not recovery_scope
                or (authority.activation_execution if phase == "activation" else authority.consume_execution) is not policy
                or any(actual is not expected for actual, expected in zip((authority.root_public_key,
                    policy.planner_public_key, policy.operation_public_key, policy.caller_public_key), keys_pin))
                or any(actual is not expected for actual, expected in zip((policy.authorization_enrollment_bytes,
                    policy.current_root_enrollment_bytes, policy.grant_enrollment_bytes), enrollment_originals))):
            _fail("completion controls changed their actual cold owner or originals")

    def ancestor(epoch, monotonic):
        identity()
        authority.live()
        now = actor.current()
        mono = caller.production._callback(work, time.monotonic_ns)
        if type(now) is not int or now < epoch or type(mono) is not int or mono < monotonic:
            _fail("completion controls ancestor clocks reversed")
        identity()
        return now, mono

    lifetime = bookkeeping._Lifetime(window, bound, work, ancestor)
    lifetime.narrow(lifetime.window[3], policy.maximum_age_ns, policy.maximum_clock_skew_ns)
    lifetime.current()
    selected = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_controls(
        custody, finalization, phase=phase, work=work, current=lifetime.base,
        maximum_original_bytes=3 * ((MAX_ORIGINAL_BYTES - held) // 8))
    lifetime.current()
    if selected is None:
        _fail("completion recovery has no complete retained dispatched control prefix")
    if type(selected) is not tuple or len(selected) != 10:
        _fail("completion recovery control inventory differs from the fixed source")
    activation_claim, consume_claim, prepared, exported, authorized, granted, reserved, completed, hints, sql_claim = selected
    if (type(activation_claim) is not activation_records.attempts.ActivationDispatchAttemptRecord
            or activation_claim.finalization_digest != finalization
            or activation_claim.source_revision != state.authority.SOURCE_REVISION):
        _fail("completion controls lack the original activation association")
    activation_digest = target.activation_authorization_digest
    if phase == "activation":
        if any(value is not None for value in (consume_claim, exported, authorized, hints)):
            _fail("activation controls contain consume-only originals")
    else:
        _record(consume_claim, "claimed", phase, finalization, activation_digest, work)
    _record(sql_claim, "sql-claimed", phase, finalization, activation_digest, work)
    prepared_raw = _record(prepared, "prepared", phase, finalization, activation_digest, work)
    original = (prepared_raw[0] if phase == "activation" else
        _record(authorized, "authorized", phase, finalization, activation_digest, work)[0])
    selected_caller = caller if phase == "activation" else consume
    plan._same(plan._frame(selected_caller.REQUEST_IDENTITY_DOMAIN, (original,), work),
        configured.authorization_digest, work, "independently pinned exact caller original")
    plan._same(activation_claim.authorization_enrollment_digest,
        authority.activation_execution.authorization_enrollment_digest, work,
        "completion recovery original activation enrollment association")
    grant_raw = _record(granted, "grant", phase, finalization, activation_digest, work)[0]
    reserve_raw = _record(reserved, "reserved", phase, finalization, activation_digest, work)
    prior_completion = (None if completed is None else
        _record(completed, "completion-outcome", phase, finalization, activation_digest, work))
    hints_raw = None if hints is None else _record(hints, "completion-hints", phase, finalization, activation_digest, work)
    if hints_raw is not None and prior_completion is None:
        _fail("consume hints have no retained completion association")
    prior_response = (prior_completion if phase == "activation" else
        None if prior_completion is None or hints_raw is None else (*prior_completion, *hints_raw))
    total = sum(len(raw) for record in selected[1:] if record is not None for raw in record.originals)
    reservation = held + 8 * total
    if reservation > MAX_ORIGINAL_BYTES:
        _fail("completion retained originals exceed the reserved admission footprint")
    # Reserve/ACK admission uses genuine historical entrypoints, never a fake
    # old current sample. These signatures do not prove a current pending head.
    material, reserve, reserve_digest = state._verify_historical_request_on_work(
        request_bytes=reserve_raw[0], enrollment_bytes=enrollment_originals[1], root_public_key=root, work=work)
    lifetime.narrow(lifetime.window[3], material.payload["maxControlAgeNs"], material.payload["maxClockSkewNs"])
    grant_enrollments = caller.grants if phase == "activation" else consume.enrollments
    enrolled_grant = grant_enrollments._admit_enrollment_on_work(grant_enrollment_bytes=enrollment_originals[2],
        current_root_enrollment_bytes=enrollment_originals[1], root_public_key=root, work=work)
    lifetime.narrow(lifetime.window[3], enrolled_grant.payload["maximumGrantAgeNs"],
        enrolled_grant.payload["maximumClockSkewNs"])
    reservations = activation_reservations if phase == "activation" else consume_dispatch.reservations
    predecessor = reservations._predecessor_scope(*policy.reservation_predecessor)
    checked, checked_digest, receipt, receipt_digest = reservations._verify_on_work(
        request_bytes=reserve_raw[0], snapshot_bytes=reserve_raw[1], receipt_bytes=reserve_raw[2],
        enrollment_bytes=enrollment_originals[1], root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    plan._same(checked, reserve, work, "historical reserve exact signed readback")
    plan._same(checked_digest, reserve_digest, work, "historical reserve exact identity")
    if receipt is None or receipt_digest is None:
        _fail("completion recovery has no genuine original reserve acknowledgment")
    plan._same((receipt["sequence"], receipt_digest, receipt["fence"]), configured.current_pending, work,
        "completion recovery independently configured pending tuple")
    before = state.vector._encode_on_work(reserve["beforeVector"], work=work)
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    lifetime.current()
    common = dict(authorization_enrollment_bytes=enrollment_originals[0],
        current_root_enrollment_bytes=enrollment_originals[1], grant_enrollment_bytes=enrollment_originals[2],
        root_public_key=root, configuration_digest=configuration_digest,
        planner_public_key=policy.planner_public_key, operation_public_key=policy.operation_public_key)
    if phase == "activation":
        original, signed, encrypted, expectation_bytes, original_before = prepared_raw
        _same_bytes(original_before, before, work, "independent activation before-vector")
        expected = caller.expectations_wire._capture_on_work(
            history.planning._object(expectation_bytes, caller.expectations_wire.MAX_BYTES, work), work=work)
        _target_arguments(expected, target, phase, work)
        for name, maximum, minimum in (("maximumPlanAgeNs", state.authority.VERIFIER_RESPONSE_MAX_AGE_NS, 1),
                ("maximumClockSkewNs", state.authority.VERIFIER_MAX_CLOCK_SKEW_NS, 0)):
            shape._integer(expected["scope"][name], maximum, minimum=minimum)
        lifetime.narrow(lifetime.window[3], expected["scope"]["maximumPlanAgeNs"],
            expected["scope"]["maximumClockSkewNs"])
        authenticated = caller._verify_historical_on_work(**common, authorization_bytes=original,
            originals=(signed, encrypted), expectations=expected, before_vector_bytes=before,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=lifetime.continuity)
        lifetime.narrow(lifetime.window[3], authenticated.maximum_age_ns, authenticated.maximum_clock_skew_ns)
        lifetime.attach(authenticated.live)
        facts = {field: getattr(authenticated, attribute) for field, attribute in (
            ("requestDigest", "request_digest"), ("operationId", "operation_id"),
            ("planDigest", "plan_digest"), ("retainedRecordDigest", "retained_record_digest"),
            ("journalDigest", "journal_digest"), ("beforeVectorDigest", "before_vector_digest"))}
        auth_payload = {"issuedAtEpochNs": authenticated.issued_at_epoch_ns,
            "expiresAtEpochNs": authenticated.expires_at_epoch_ns}
        signed_payload, _ = caller.history._authenticate(signed, expected["request"], expected["scope"],
            policy.planner_public_key, lifetime.base, work)
        authorization_digest = authenticated.authorization_digest
        plan._same(authorization_digest, activation_digest, work, "completion actor exact activation caller")
        grant, grant_digest = caller.grants._verify_historical_control_on_work(grant_bytes=grant_raw,
            grant_enrollment_bytes=enrollment_originals[2], current_root_enrollment_bytes=enrollment_originals[1],
            root_public_key=root, planner_public_key=policy.planner_public_key,
            operation_public_key=policy.operation_public_key,
            expected_authorization_digest=configured.authorization_digest, work=work)
        snapshot = computation._decode_snapshot_on_work(reserve_raw[1], work=work)
    else:
        exported_raw = _record(exported, "exported", phase, finalization, activation_digest, work)
        original = _record(authorized, "authorized", phase, finalization, activation_digest, work)[0]
        if prepared_raw[0] != b"prepared" or exported_raw[0] != b"exported":
            _fail("consume completion has only an uncertain planning observation")
        for actual, expected_original in zip((exported_raw[1], exported_raw[2], exported_raw[3],
                exported_raw[5], exported_raw[6]), prepared_raw[1:]):
            _same_bytes(actual, expected_original, work, "consume prepare/export exact correspondence")
        signed, encrypted = exported_raw[3:5]
        consume.bundle._bounded_frame(encrypted)
        expected = consume.expectations_wire._capture_on_work({
            "request": history.planning._object(exported_raw[1], consume.expectations_wire.MAX_BYTES, work),
            "scope": history.planning._object(exported_raw[2], consume.expectations_wire.MAX_BYTES, work),
            "journalDigest": exported_raw[6].decode("ascii")}, work=work)
        _target_arguments(expected, target, phase, work)
        expectation_bytes = consume.registration._wire(expected, work)
        auth_payload, signed_payload, facts = _consume_authorization(original, (signed, encrypted), before,
            expected, policy, root, configuration_digest, lifetime, work)
        authorization_digest = plan._frame(consume.REQUEST_IDENTITY_DOMAIN, (original,), work)
        _same_bytes(exported_raw[5], facts["planDigest"].encode("ascii"), work, "consume signed plan identity")
        enrolled = enrolled_grant
        for other in (policy.planner_public_key, policy.operation_public_key):
            if consume.keys._spki_on_work(enrolled.authorizer_public_key, work) == consume.keys._spki_on_work(other, work):
                _fail("consume grant authorizer reused a planner or operation key")
        grant, grant_digest = consume_dispatch.grants._verify_signature_on_work(grant_raw, enrolled.authorizer_public_key, work)
        for field, value in (("grantEnrollmentDigest", enrolled.enrollment_digest),
                ("currentRootEnrollmentDigest", enrolled.payload["currentRootEnrollmentDigest"]),
                ("databaseId", enrolled.payload["databaseId"]), ("generationDigest", enrolled.payload["generationDigest"]),
                ("authorizerMeasurementDigest", enrolled.payload["authorizer"]["measurementDigest"]),
                ("configurationDigest", configuration_digest),
                ("requestAuthorizationDigest", configured.authorization_digest)):
            plan._same(grant[field], value, work, "historical consume grant " + field)
        if grant["expiresAtEpochNs"] - grant["issuedAtEpochNs"] > enrolled.payload["maximumGrantAgeNs"]:
            _fail("historical consume grant exceeds its enrolled original lifetime")
        snapshot = consume_dispatch.computation._decode_snapshot_on_work(reserve_raw[1], work=work)
    plan._same(authorization_digest, configured.authorization_digest, work, "independent original caller identity")
    operation = caller.OPERATION if phase == "activation" else consume.OPERATION
    grant_facts = tuple((field, value) for field, value in facts.items()
        if phase == "consume" or field != "journalDigest")
    for field, value in (("operation", operation), *grant_facts,
            ("originalIssuedAtEpochNs", signed_payload["issuedAtEpochNs"]),
            ("originalExpiresAtEpochNs", signed_payload["expiresAtEpochNs"])):
        plan._same(grant[field], value, work, "historical grant exact original " + field)
    frames = [{"position": position, "bytesDigest": history.assertion._digest(raw, work), "byteCount": len(raw)}
        for position, raw in enumerate((signed, encrypted))]
    plan._same(grant["originalFrames"], frames, work, "historical grant original frames")
    for field, value in (("action", "reserve"), ("operation", operation),
            ("requestDigest", facts["requestDigest"]), ("operationId", facts["operationId"]),
            ("capabilityDigest", grant_digest), ("databaseId", grant["databaseId"]),
            ("generationDigest", grant["generationDigest"]),
            ("enrollmentDigest", grant["currentRootEnrollmentDigest"])):
        plan._same(reserve[field], value, work, "historical reserve exact original " + field)
    if (grant["issuedAtEpochNs"] != signed_payload["issuedAtEpochNs"]
            or reserve["issuedAtEpochNs"] != grant["issuedAtEpochNs"]
            or not signed_payload["issuedAtEpochNs"] <= auth_payload["issuedAtEpochNs"]
                < auth_payload["expiresAtEpochNs"] <= signed_payload["expiresAtEpochNs"]
            or grant["expiresAtEpochNs"] > auth_payload["expiresAtEpochNs"]
            or reserve["expiresAtEpochNs"] > grant["expiresAtEpochNs"]):
        _fail("completion historical controls retime or renew original authority")
    current_ceiling = lifetime.current() + lifetime.window[6]
    for value in (signed_payload, auth_payload, grant, reserve):
        if not authority_interval[0] <= value["issuedAtEpochNs"] < value["expiresAtEpochNs"] <= authority_interval[1]:
            _fail("completion original controls escape the selected historical authority interval")
        if value["issuedAtEpochNs"] > current_ceiling:
            _fail("completion historical controls are future-issued beyond the narrowed skew")
    snapshot_fields = ("sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
        "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest", "afterVectorDigest",
        "resultDigest", "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs")
    if phase == "activation":
        snapshot_fields += ("signedSnapshotDigest", "signedCapabilityId")
    for field in snapshot_fields:
        plan._same(snapshot[field], grant[field], work, "historical snapshot/grant " + field)
    plan._same(snapshot["capabilityDigest"], grant_digest, work, "historical snapshot actual grant")
    for field, raw in (("beforeVectorDigest", before), ("afterVectorDigest", after)):
        plan._same(state.vector._digest_on_work(raw, work=work), grant[field], work,
            "historical original full " + field)
    marker = pending._marker(material, reserve, reserve_digest, receipt, receipt_digest, snapshot, work)
    originals = (original, signed, encrypted, expectation_bytes, grant_raw, *reserve_raw)
    lifetime.current()
    result = _CompletionControls(_CONSTRUCTION, actor, phase, originals, before, after, marker,
        enrollment_originals[1], root, configured.current_pending, configured.endpoint, configured.packet_digest,
        configured.authorization_digest, finalization, work, lifetime.window, lifetime.bound, reservation, prior_response,
        prior_completion, authority, lifetime.current)
    object.__setattr__(result, "_seal", (tuple(getattr(result, name) for name in _SEALED_FIELDS),
        tuple(marker[name] for name in pending._MARKER_COLUMNS)))
    return _require_controls(result)
