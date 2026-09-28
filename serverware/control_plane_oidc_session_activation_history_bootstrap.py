"""Original-only activation history on the existing parent history archive.

These cold inputs enable historical signature replay, not live activation,
consume or token release. Old signed intervals never become processing clocks.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_historical_archive as archive
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import control_plane_registration_history_bootstrap as registration
from serverware import control_plane_registration_finalization_history_bootstrap as finalization
from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation
from serverware import control_plane_oidc_session_activation_planning_bootstrap as planning
from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from serverware import control_plane_oidc_session_activation_completion_recovery_bootstrap as completion


SCHEMA = "serverware.controlPlaneOidcSessionActivationHistory/v1"
V2_SCHEMA = "serverware.controlPlaneOidcSessionActivationHistory/v2"
MAX_BYTES = registration.MAX_BYTES
_FIELDS = frozenset({"schema", "activations"})
_SCOPE_FIELDS = frozenset({"configurationDigest", "plannerAttestationReceiptDigest",
    "activationExecution", "activationPlanning", "consumeExecution", "releaseIntent"})
_V2_SCOPE_FIELDS = _SCOPE_FIELDS | frozenset({"completionRecovery"})
shape, capture, plan, clock = planning.shape, planning.capture, planning.plan, planning.planner.clock


class OidcSessionActivationHistoryBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ActivationHistoryScope:
    configuration_digest: str
    generation_digest: str
    planner_attestation_receipt_digest: str
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    root_public_key: object
    activation_execution: object
    activation_planning: object
    consume_execution: object
    release_intent: object
    planner_attestation_interval: tuple
    original_bytes: bytes
    completion_recovery: completion._CompletionRecoveryMaterial | None = None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ActivationHistoryMaterial:
    archive: archive.HistoryArchive
    registration_history: registration._RegistrationHistoryMaterial
    finalization_history: finalization._FinalizationHistoryMaterial
    scopes: tuple
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int
    original_bytes: bytes


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "activation history")
    if type(value["schema"]) is not str or value["schema"] not in (SCHEMA, V2_SCHEMA):
        raise OidcSessionActivationHistoryBootstrapError("activation history schema is not supported")
    is_v2 = value["schema"] == V2_SCHEMA
    values = value["activations"]
    if type(values) is not list or not 1 <= len(values) <= archive.MAX_ENTRIES + 1:
        raise OidcSessionActivationHistoryBootstrapError("activation history inventory exceeds its fixed bound")
    previous = None
    for selected in values:
        shape._object(selected, _V2_SCOPE_FIELDS if is_v2 else _SCOPE_FIELDS,
            "activation historical scope")
        shape._digest(selected["configurationDigest"])
        shape._digest(selected["plannerAttestationReceiptDigest"])
        selector = selected["configurationDigest"], selected["plannerAttestationReceiptDigest"]
        if previous is not None and selector <= previous:
            raise OidcSessionActivationHistoryBootstrapError("activation history selectors must be sorted and unique")
        previous = selector
        for name, module, schema in (("activationExecution", activation, activation.V4_SCHEMA),
                ("activationPlanning", planning, planning.SCHEMA),
                ("consumeExecution", consume, consume.V4_SCHEMA),
                ("releaseIntent", intent, intent.SCHEMA)):
            child = selected[name]
            module._shape(child)
            if child is None or child["schema"] != schema:
                raise OidcSessionActivationHistoryBootstrapError("activation history requires its exact original child profiles")
        if is_v2:
            completion._shape(selected["completionRecovery"])


def _histories(registrations, finalized):
    if (type(registrations) is not registration._RegistrationHistoryMaterial
            or type(finalized) is not finalization._FinalizationHistoryMaterial
            or type(registrations.archive) is not archive.HistoryArchive
            or finalized.registration_history is not registrations
            or finalized.archive is not registrations.archive
            or finalized.valid_from_epoch_ns != registrations.valid_from_epoch_ns
            or finalized.valid_until_epoch_ns != registrations.valid_until_epoch_ns):
        raise OidcSessionActivationHistoryBootstrapError("activation history requires the actual shared historical owners")


def _processing(history, live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    end = min(window[3], history.valid_until_epoch_ns)
    window = clock._validate((*window[:3], end, window[1] + end - window[0], window[5], window[6]))
    bound = min(window[4], transport_deadline_ns)
    floors = [window[0], window[2]]

    def continuity(epoch, monotonic):
        capture._SharedLedger(work)
        shape._integer(epoch, minimum=1)
        shape._integer(monotonic, minimum=1)
        if (epoch < window[0] or monotonic < window[2]
                or epoch >= window[3] or monotonic >= bound):
            raise OidcSessionActivationHistoryBootstrapError("activation history inherited floors expired or reversed")
        floors[0], floors[1] = max(floors[0], epoch), max(floors[1], monotonic)
        now = clock._check_on_work(window, work=work)
        sampled = configuration.production._callback(work, planning.planner.time.monotonic_ns)
        if (now < floors[0] or sampled < floors[1] or sampled >= bound
                or not history.valid_from_epoch_ns <= now < history.valid_until_epoch_ns):
            raise OidcSessionActivationHistoryBootstrapError("activation historical cold processing expired or reversed")
        floors[0], floors[1] = now, sampled
        return now, sampled

    def current():
        return continuity(*floors)[0]

    current()
    return window, bound, current, continuity


def _admit_on_work(*, activation_history, registration_history, finalization_history,
        live_window, transport_deadline_ns, work):
    """Signed parents supply independently authenticated originals and live bounds."""
    try:
        _shape(activation_history)
        if activation_history is None:
            return None
        _histories(registration_history, finalization_history)
        window, bound, current, continuity = _processing(
            registration_history, live_window, transport_deadline_ns, work)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work),
            maximum_bytes=MAX_BYTES).visit(activation_history)
        _shape(owned)
        original = configuration._configuration_wire(owned, capture._SharedLedger(work))
        work.charge(input_bytes=8 * len(original))
        current()
        captured = archive._capture_on_work(registration_history.archive, work=work)
        scopes = []
        for selected in owned["activations"]:
            current()
            chosen = None
            for record in captured.records:
                work.charge(input_bytes=2 * 71, json_nodes=1)
                if (selected["configurationDigest"], selected["plannerAttestationReceiptDigest"]) == (
                        record.configuration_digest, record.planner_receipt_digest):
                    if chosen is not None:
                        raise OidcSessionActivationHistoryBootstrapError("activation historical selector is ambiguous")
                    chosen = record
            if chosen is None:
                raise OidcSessionActivationHistoryBootstrapError("activation history is absent from the shared archive")
            snapshot = archive._lookup_on_work(captured,
                configuration_digest=chosen.configuration_digest,
                planner_attestation_receipt_digest=chosen.planner_receipt_digest,
                evaluation_epoch_ns=chosen.valid_from_epoch_ns, work=work)
            registered = registration._scope_on_work(registration_history, snapshot=snapshot, work=work)
            finalized = finalization._scope_on_work(finalization_history, snapshot=snapshot, work=work)
            issuer = enrollment_policy._capture_on_work(payload=snapshot.payload,
                configuration_digest=snapshot.configuration_digest, generation=snapshot.generation,
                runtime_role_identities=snapshot.runtime_role_identities, work=work)
            common = {"configuration_payload": snapshot.payload,
                "configuration_digest": snapshot.configuration_digest, "generation": snapshot.generation,
                "runtime_role_identities": snapshot.runtime_role_identities,
                "runtime_root_public_key": registered.root_public_key, "work": work}
            exclusions = {"issuer_public_key": issuer.issuer_public_key,
                "execution_caller_public_key": registered.caller_public_key,
                "finalization_caller_public_key": finalized.caller_public_key}
            activated = activation._admit_on_work(activation_execution=selected["activationExecution"],
                **common, **exclusions)
            current()
            interval = chosen.valid_from_epoch_ns, chosen.valid_until_epoch_ns
            planned, planner_interval = planning._admit_historical_on_work(
                planning=selected["activationPlanning"], activation_execution=activated,
                historical_interval=interval, live_window=window, transport_deadline_ns=bound,
                _continuity=continuity, **common)
            current()
            consumed = consume._admit_on_work(consume_execution=selected["consumeExecution"],
                activation_execution=activated, activation_planning=planned, **common, **exclusions)
            current()
            intended = intent._admit_historical_on_work(release_intent=selected["releaseIntent"],
                activation_execution=activated, activation_planning=planned, consume_execution=consumed,
                historical_interval=interval, live_window=window, transport_deadline_ns=bound,
                _continuity=continuity, **common, **exclusions)
            current()
            # These archived endpoints establish the historical execution join
            # only. A current enabled endpoint must independently authorize any
            # later contact; no old endpoint becomes a current routing grant.
            completed = completion._admit_on_work(
                completion_recovery=(selected["completionRecovery"]
                    if owned["schema"] == V2_SCHEMA else None),
                activation_execution=activated, consume_execution=consumed,
                runtime_root_public_key=registered.root_public_key,
                configuration_digest=chosen.configuration_digest,
                generation_digest=chosen.generation_digest, work=work)
            current()
            scope_raw = configuration._configuration_wire(selected, capture._SharedLedger(work))
            scopes.append(_ActivationHistoryScope(chosen.configuration_digest, chosen.generation_digest,
                chosen.planner_receipt_digest, chosen.valid_from_epoch_ns, chosen.valid_until_epoch_ns,
                registered.root_public_key, activated, planned, consumed, intended, planner_interval, scope_raw,
                completed))
        plan._same(configuration._configuration_wire(owned, capture._SharedLedger(work)), original, work,
            "activation history changed during cold admission")
        current()
        return _ActivationHistoryMaterial(registration_history.archive, registration_history,
            finalization_history, tuple(scopes), registration_history.valid_from_epoch_ns,
            registration_history.valid_until_epoch_ns, original)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationHistoryBootstrapError):
            raise
        raise OidcSessionActivationHistoryBootstrapError("activation historical cold admission failed") from exc


def _scopes(material, work):
    if type(material) is not _ActivationHistoryMaterial:
        raise OidcSessionActivationHistoryBootstrapError("activation history is not actual cold material")
    _histories(material.registration_history, material.finalization_history)
    if (material.archive is not material.registration_history.archive
            or material.valid_from_epoch_ns != material.registration_history.valid_from_epoch_ns
            or material.valid_until_epoch_ns != material.registration_history.valid_until_epoch_ns
            or type(material.scopes) is not tuple or not 1 <= len(material.scopes) <= archive.MAX_ENTRIES + 1):
        raise OidcSessionActivationHistoryBootstrapError("activation history shared identity or inventory changed")
    for scope in material.scopes:
        work.charge(input_bytes=3 * 71 + 32, json_nodes=1)
        if (type(scope) is not _ActivationHistoryScope
                or type(scope.activation_execution) is not activation._ActivationExecutionMaterial
                or type(scope.activation_planning) is not planning._PlanningMaterial
                or type(scope.consume_execution) is not consume._ConsumeExecutionMaterial
                or type(scope.release_intent) is not intent._ReleaseIntentMaterial
                or (scope.completion_recovery is not None
                    and type(scope.completion_recovery) is not completion._CompletionRecoveryMaterial)):
            raise OidcSessionActivationHistoryBootstrapError("activation historical child inventory changed")
    return material.scopes


def _lookup(material, configuration_digest, generation_digest, enrollment_digest, *, intent_lane, work):
    for value in (configuration_digest, generation_digest, enrollment_digest):
        shape._digest(value)
    selected = None
    for scope in _scopes(material, work):
        enrolled = (scope.release_intent.enrollment_digest if intent_lane else
            scope.activation_execution.authorization_enrollment_digest)
        if (scope.configuration_digest, scope.generation_digest, enrolled) == (
                configuration_digest, generation_digest, enrollment_digest):
            if selected is not None:
                raise OidcSessionActivationHistoryBootstrapError("activation original locator is ambiguous")
            selected = scope
    if selected is None:
        raise OidcSessionActivationHistoryBootstrapError("activation original locator is not independently configured")
    return selected


def _lookup_execution_on_work(material, *, configuration_digest, generation_digest,
        authorization_enrollment_digest, work):
    """Untrusted locators select a cold key only, never a successful original."""
    return _lookup(material, configuration_digest, generation_digest,
        authorization_enrollment_digest, intent_lane=False, work=work)


def _lookup_intent_on_work(material, *, configuration_digest, generation_digest, enrollment_digest, work):
    return _lookup(material, configuration_digest, generation_digest,
        enrollment_digest, intent_lane=True, work=work)


def _scope_on_work(material, *, snapshot, work):
    values = _scopes(material, work)
    prior = finalization._scope_on_work(material.finalization_history, snapshot=snapshot, work=work)
    selected = None
    for scope in values:
        if (scope.configuration_digest, scope.generation_digest, scope.planner_attestation_receipt_digest,
                scope.valid_from_epoch_ns, scope.valid_until_epoch_ns) == (
                prior.configuration_digest, prior.generation_digest, prior.planner_attestation_receipt_digest,
                prior.valid_from_epoch_ns, prior.valid_until_epoch_ns):
            if selected is not None or scope.root_public_key is not prior.root_public_key:
                raise OidcSessionActivationHistoryBootstrapError("activation historical selector or shared root differs")
            selected = scope
    if selected is None:
        raise OidcSessionActivationHistoryBootstrapError("activation historical operation is not independently configured")
    return selected
