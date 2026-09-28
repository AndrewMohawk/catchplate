"""Dedicated release-intent caller custody inside explicit parent v9.

Root originals admit this key and its independent scope, not a future target,
completion proof, hint or present permission. No request allowance is opened.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation
from serverware import control_plane_oidc_session_activation_planning_bootstrap as planning
from serverware import oidc_session_activation_release_intent_enrollment as enrollment


SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseIntent/v1"
CALLER_KEY_FD = 207
MAX_BYTES = enrollment.authorization.authority.MAX_REQUEST_BYTES
_FIELDS = frozenset({"schema", "callerPrivateKeyFd", "intentEnrollment", "expectedScope"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
configuration = activation.configuration
shape, capture, plan = enrollment.shape, enrollment.capture, enrollment.plan


class OidcSessionActivationReleaseIntentBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseIntentMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    enrollment_bytes: bytes
    enrollment_digest: str
    expected_scope_bytes: bytes
    forbidden_public_keys: tuple


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane release intent configuration")
    shape._literal(value["schema"], SCHEMA)
    shape._integer(value["callerPrivateKeyFd"], 1023, minimum=32)
    if value["callerPrivateKeyFd"] != CALLER_KEY_FD:
        raise OidcSessionActivationReleaseIntentBootstrapError("release intent requires dedicated FD207")
    enrollment._scope_shape(value["expectedScope"])
    original = value["intentEnrollment"]
    shape._object(original, _ORIGINAL_FIELDS, "release intent enrollment original")
    shape._integer(original["byteCount"], enrollment.MAX_BYTES, minimum=2)
    enrollment.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], enrollment.MAX_BYTES)


def _scope_on_work(scope_bytes, work):
    original = enrollment.authorization._original(scope_bytes, enrollment.MAX_BYTES,
        "independent cold intent scope")
    decoded = enrollment.wire._decode_object(original, work=work,
        maximum_bytes=enrollment.MAX_BYTES, maximum_nodes=enrollment.MAX_NODES,
        maximum_depth=enrollment.MAX_DEPTH)
    owned = enrollment._scope(decoded, work)
    enrollment.capability._canonical(original, owned, capture._SharedLedger(work),
        enrollment.MAX_BYTES, enrollment.MAX_NODES)
    return owned


def _unique_keys(values, work):
    result, pins = [], []
    for key in values:
        if key is None:
            continue
        enrollment.authorization._public(key)
        pin = enrollment.keys._spki_on_work(key, work)
        work.prepare_scan(pins)
        duplicate = False
        for previous in pins:
            work.prepare_comparison(pin, previous)
            duplicate = duplicate or pin == previous
        if not duplicate:
            result.append(key)
            pins.append(pin)
    return enrollment._forbidden(tuple(result))


def _admit_on_work(*, release_intent, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        activation_execution, activation_planning, consume_execution,
        issuer_public_key, execution_caller_public_key, finalization_caller_public_key, work):
    return _admit(release_intent=release_intent, configuration_payload=configuration_payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, runtime_root_public_key=runtime_root_public_key,
        activation_execution=activation_execution, activation_planning=activation_planning,
        consume_execution=consume_execution, issuer_public_key=issuer_public_key,
        execution_caller_public_key=execution_caller_public_key,
        finalization_caller_public_key=finalization_caller_public_key, work=work)


def _admit_historical_on_work(*, release_intent, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        activation_execution, activation_planning, consume_execution,
        issuer_public_key, execution_caller_public_key, finalization_caller_public_key,
        historical_interval, live_window, transport_deadline_ns, work, _continuity=None):
    """Admit original intent scope with genuine historical planner verification."""
    if type(historical_interval) is not tuple or len(historical_interval) != 2:
        raise OidcSessionActivationReleaseIntentBootstrapError("historical intent interval is not exact")
    for value in historical_interval:
        shape._integer(value, minimum=1)
    if historical_interval[0] >= historical_interval[1] or live_window is None:
        raise OidcSessionActivationReleaseIntentBootstrapError("historical intent processing bounds are invalid")
    return _admit(release_intent=release_intent, configuration_payload=configuration_payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, runtime_root_public_key=runtime_root_public_key,
        activation_execution=activation_execution, activation_planning=activation_planning,
        consume_execution=consume_execution, issuer_public_key=issuer_public_key,
        execution_caller_public_key=execution_caller_public_key,
        finalization_caller_public_key=finalization_caller_public_key, work=work,
        historical_interval=historical_interval, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, _continuity=_continuity)


def _admit(*, release_intent, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        activation_execution, activation_planning, consume_execution,
        issuer_public_key, execution_caller_public_key, finalization_caller_public_key, work,
        historical_interval=None, live_window=None, transport_deadline_ns=None, _continuity=None):
    try:
        ledger = capture._SharedLedger(work)
        root, digest = runtime_root_public_key, configuration_digest
        activated, planned, consumed = activation_execution, activation_planning, consume_execution
        other_keys = issuer_public_key, execution_caller_public_key, finalization_caller_public_key
        _shape(release_intent)
        if release_intent is None:
            return None
        processing = None
        if historical_interval is not None:
            processing = planning.planner._processing(live_window, transport_deadline_ns, work,
                _continuity=_continuity)
            processing()
        if (type(activated) is not activation._ActivationExecutionMaterial
                or type(planned) is not planning._PlanningMaterial
                or type(consumed) is not consume._ConsumeExecutionMaterial
                or consumed.release_hints is not True or consumed.completion_endpoint is None):
            raise OidcSessionActivationReleaseIntentBootstrapError(
                "release intent requires actual activation planning and consume v4")
        current_raw, grant_raw = consumed.current_root_enrollment_bytes, consumed.grant_enrollment_bytes
        planner_raw = planned.planner_bootstrap_bytes
        held_keys = (activated.planner_public_key, consumed.planner_public_key,
            activated.caller_public_key, consumed.caller_public_key, *other_keys)
        enrollment.authorization._public(root)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "release intent parent generation")
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "intent": release_intent, "configuration": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtime": runtime_role_identities})
        value = owned["intent"]
        _shape(value)
        expected = enrollment._scope(value["expectedScope"], work)
        configured, launch = configuration._capture_configuration_on_work(
            payload=owned["configuration"], configuration_digest=digest,
            generation=owned["generation"], work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=digest, launch=launch, work=work)
        current = enrollment.authorization._admit_enrollment_on_work(
            enrollment_bytes=current_raw, root_public_key=root, work=work)
        granted = consume.caller.enrollments._admit_enrollment_on_work(
            grant_enrollment_bytes=grant_raw, current_root_enrollment_bytes=current_raw,
            root_public_key=root, work=work)
        # This repeats genuine cold planner-original admission on the same work;
        # its static freshness is not a request-time permission or new allowance.
        if historical_interval is None:
            planner = planning.planner._verify_on_work(
                bootstrap_bytes=planner_raw, root_public_key=root, work=work)
        else:
            planner = planning.planner._verify_historical_on_work(
                bootstrap_bytes=planner_raw, root_public_key=root, live_window=live_window,
                transport_deadline_ns=transport_deadline_ns, work=work, _continuity=_continuity)
            if (planner.attestation_interval[0] < historical_interval[0]
                    or planner.attestation_interval[1] > historical_interval[1]):
                raise OidcSessionActivationReleaseIntentBootstrapError(
                    "historical intent planner exceeds its independently admitted snapshot")
            processing()
        for actual, wanted in ((planner.configuration_payload, configured),
                (planner.generation, launch), (planner.runtime_role_identities, identities)):
            planning._same_configuration(actual, wanted, work, "release intent parent planner cohort")
        for actual, wanted in ((expected["configurationDigest"], digest),
                (expected["generationDigest"], launch["digest"]),
                (expected["databaseId"], current.payload["databaseId"]),
                (current.payload["generationDigest"], launch["digest"]),
                (expected["runtimeClosureDigest"], planner.runtime_closure_digest)):
            plan._same(actual, wanted, work, "release intent independent parent scope")
        forbidden = _unique_keys((*held_keys, current.computation_public_key,
            current.completion_public_key, current.state_public_key, granted.authorizer_public_key), work)
        record = value["intentEnrollment"]
        raw = enrollment.authorization.transport._decode(
            record["base64Url"], record["byteCount"], enrollment.MAX_BYTES, work)
        admitted = enrollment._admit_on_work(enrollment_bytes=raw, root_public_key=root,
            expected_scope=expected, forbidden_public_keys=forbidden, work=work)
        pin = admitted.payload["callerKey"]["spkiDigest"]
        pins = activation._purpose_pins(configured, root, forbidden, work)
        work.prepare_scan(pins)
        for previous in pins:
            work.prepare_comparison(pin, previous)
            if pin == previous:
                raise OidcSessionActivationReleaseIntentBootstrapError(
                    "release intent key reuses another configured purpose")
        scope_bytes = enrollment.capability._wire(expected, ledger, enrollment.MAX_BYTES, enrollment.MAX_NODES)
        _scope_on_work(scope_bytes, work)
        if processing is not None:
            processing()
        return _ReleaseIntentMaterial(CALLER_KEY_FD, admitted.caller_public_key, raw,
            admitted.enrollment_digest, scope_bytes, forbidden)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseIntentBootstrapError):
            raise
        raise OidcSessionActivationReleaseIntentBootstrapError("release intent cold admission failed") from exc
