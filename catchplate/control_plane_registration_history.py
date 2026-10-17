"""Source-owned historical registration resolution, never execution permission.

Retained controls locate only an independently cold-admitted archive. Original
signatures precede final cohort selection, and genuine signer/exchange replay
precedes the subject projection. Unknown source versions have no adapter here.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_historical_archive as archive
from catchplate import authority_registration_completion_transport as completion_wire
from catchplate import authority_registration_history_exchange as exchange
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_webauthn_registration_signer_history as signer_history
from catchplate import control_plane_registration_handoff_subject as source
from catchplate import control_plane_registration_history_bootstrap as bootstrap
from catchplate import control_plane_registration_outcome_records as outcomes


evidence, clock = exchange.evidence, exchange.clock
MAX_ORIGINAL_BYTES = evidence.authority.MAX_RESULT_BYTES
_REPRESENTATIONS = 8
_REPLAY_BYTES = 2 * evidence.authority.MAX_REQUEST_BYTES + 2 * 8192
_RESPONSE_BYTES = 4 * completion_wire.MAX_RESPONSE_BYTES + 64 * 1024
_COMMON_FIELDS = frozenset({"payload", "configuration_digest", "generation",
    "runtime_role_identities", "authorization_enrollment_bytes", "grant_enrollment_bytes",
    "current_root_enrollment_bytes", "root_public_key"})
_GRAPH_FIELDS = ("payload", "generation", "runtime_role_identities")
_ENROLLMENT_FIELDS = ("authorization_enrollment_bytes", "grant_enrollment_bytes",
    "current_root_enrollment_bytes")
_OUTCOME_FIELDS = ("reservation", "sql_attempt", "sql_outcome",
    "completion_outcome", "completion_reconciled")


class RegistrationHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RegistrationHistory:
    """Only this call's held observations; no verifier accepts this as authority."""

    subject: dict
    common: dict
    current_pending: tuple
    completion_packet_digest: str
    originals: tuple
    observed: object
    original_bytes: int
    original_reservation_bytes: int
    window: tuple
    deadline_ns: int
    _guard: object

    def current(self):
        return self._guard(self)


def _graph_bytes(value, work):
    # Configuration permits finite floats; the integer-only proof codec is
    # deliberately not used for configuration capture or its continuity pin.
    return configuration._configuration_wire(value, evidence.capture._SharedLedger(work))


def _enrollments(common):
    if type(common) is not dict or frozenset(common) != _COMMON_FIELDS:
        raise RegistrationHistoryError("historical registration common scope changed")
    originals = tuple(common[name] for name in _ENROLLMENT_FIELDS)
    maxima = (exchange.authorization.MAX_ENROLLMENT_BYTES,
        exchange.grants.MAX_ENROLLMENT_BYTES, exchange.current_root.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(originals, maxima)):
        raise RegistrationHistoryError("historical registration enrollments are not bounded originals")
    return originals


def _observed_originals(observed, digest, revision):
    if observed is None:
        return ()
    if (type(observed) is not outcomes.RegistrationOutcomes
            or observed.local_digest != digest or observed.source_revision != revision):
        raise RegistrationHistoryError("historical registration outcomes have another association")
    held = []
    for profile, name in enumerate(_OUTCOME_FIELDS):
        record = getattr(observed, name)
        if record is None:
            continue
        if (type(record) is not outcomes.RegistrationOutcomeRecord
                or record.local_digest != digest or record.source_revision != revision
                or record.kind != outcomes.KINDS[profile]):
            raise RegistrationHistoryError("historical registration outcome kind or source changed")
        held.extend(outcomes._originals(profile, record.originals))
    return tuple(held)


def _interval(snapshot, issued, expires):
    if not snapshot.valid_from_epoch_ns <= issued < expires <= snapshot.valid_until_epoch_ns:
        raise RegistrationHistoryError("original registration control escapes its archived cohort interval")


def _select_on_work(material, held, *, window, bound, work, current):
    """Authenticate controls before selecting their exact archived cohort."""
    current()
    captured = archive._capture_on_work(material.archive, work=work)
    locator, _signature, _unsigned = exchange.exchange.request_wire._read_control(held[1], work)
    initial = archive._lookup_control_on_work(captured,
        configuration_digest=locator["configurationDigest"],
        generation_digest=locator["generationDigest"],
        issued_at_epoch_ns=locator["issuedAtEpochNs"], work=work)
    current()
    configured = exchange.exchange.configuration._capture_on_work(purpose="registration",
        payload=initial.payload, configuration_digest=initial.configuration_digest,
        generation=initial.generation, runtime_role_identities=initial.runtime_role_identities, work=work)
    current()
    request = exchange.request_history._verify_on_work(control_bytes=held[1],
        context_bytes=held[2], inputs_bytes=held[3], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    response = exchange.response_history._verify_on_work(control_bytes=held[4],
        request_control_bytes=held[1], envelope_bytes=held[5], inputs_bytes=held[6],
        evaluation_context_bytes=held[7], pins=configured.pins,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        verifier_public_key=configured.verifier_public_key,
        request_issued_at_epoch_ns=request.issued_at_epoch_ns,
        request_expires_at_epoch_ns=request.expires_at_epoch_ns,
        maximum_control_age_ns=configured.maximum_control_age_ns,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    # The planner signature has now authenticated this exact context original.
    # Its locators still select only independently admitted archive entries;
    # the complete context is replayed against independently derived pins below.
    context = exchange.plan_history.retention.context_wire._decode_on_work(held[7], work=work)
    selected = archive._lookup_on_work(captured,
        configuration_digest=context["configurationDigest"],
        planner_attestation_receipt_digest=context["plannerIdentity"]["attestationReceiptDigest"],
        evaluation_epoch_ns=context["nowEpochNs"], work=work)
    evidence.plan._same((selected.configuration_digest, selected.generation["digest"]),
        (initial.configuration_digest, initial.generation["digest"]), work,
        "authenticated planner context changed its independently selected configuration")
    _interval(selected, request.issued_at_epoch_ns, request.expires_at_epoch_ns)
    _interval(selected, response.issued_at_epoch_ns, response.expires_at_epoch_ns)
    scope = bootstrap._scope_on_work(material, snapshot=selected, work=work)
    current()
    common = {"payload": selected.payload, "configuration_digest": selected.configuration_digest,
        "generation": selected.generation, "runtime_role_identities": selected.runtime_role_identities,
        "authorization_enrollment_bytes": scope.authorization_enrollment_bytes,
        "grant_enrollment_bytes": scope.grant_enrollment_bytes,
        "current_root_enrollment_bytes": scope.current_root_enrollment_bytes,
        "root_public_key": scope.root_public_key}
    return common, scope, selected


def _replay_on_owner(owner, local_digest, *, live_window, work, transport_deadline_ns=None,
        _additional_original_bytes=0, _include_outcomes=False):
    """Bounded original-only resolution under the actual current cold owner."""
    # Lazy imports preserve the existing subject facade without a module cycle.
    from catchplate import control_plane_registration_recovery_subject as subjects
    from catchplate import control_plane_registration_finalization_completion_subject as parent_size

    if (type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES
            or type(_include_outcomes) is not bool):
        raise RegistrationHistoryError("registration history capacity or selector is not source bounded")
    digest = source.journal._digest(local_digest)
    common, _endpoint, window, bound, owner_current = subjects._scope_on_owner(owner,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
    parent, binding, custody = owner._material, owner._binding, owner._custody
    configured = parent.execution
    material = parent.registration_history
    archive_bytes = 0
    if material is not None:
        if (type(material) is not bootstrap._RegistrationHistoryMaterial
                or type(material.original_bytes) is not bytes
                or not 2 <= len(material.original_bytes) <= bootstrap.MAX_BYTES):
            raise RegistrationHistoryError("registration history is not an actual bounded cold original")
        archive_bytes = len(material.original_bytes)
        deadline = min(window[3], material.valid_until_epoch_ns)
        window = clock._validate((*window[:3], deadline, window[1] + deadline - window[0],
            window[5], window[6]))
        bound = min(bound, window[4])
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        owner_current()
        if (owner._material is not parent or owner._binding is not binding
                or owner._custody is not custody or parent.execution is not configured
                or parent.registration_history is not material):
            raise RegistrationHistoryError("registration historical cold owner changed")
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        evidence.plan.contract._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or material is not None
                and not material.valid_from_epoch_ns <= now < material.valid_until_epoch_ns):
            raise RegistrationHistoryError("registration historical processing expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        owner_current()
        return now

    current()
    parent_bytes = parent_size._parent_representation_bytes_on_owner(owner, work=work, current=current)
    cold_enrollments = _enrollments(common)
    base = (_additional_original_bytes + parent_bytes + 8 * archive_bytes
        + 4 * sum(map(len, cold_enrollments)) + _REPLAY_BYTES + _RESPONSE_BYTES
        + source.journal.REGISTRATION_PREPARATION_METADATA_BYTES)
    remaining = MAX_ORIGINAL_BYTES - base
    # The loader owns 3*encoded + metadata before body1. Its 3/8 share
    # leaves eight selected original representations for later genuine replay.
    maximum = 3 * (remaining // _REPRESENTATIONS)
    if maximum <= source.journal.REGISTRATION_PREPARATION_METADATA_BYTES:
        raise RegistrationHistoryError("registration historical replay has no remaining original capacity")
    if _include_outcomes:
        pair, observed = source.custody_client.ControlPlaneCustodyClient.load_registration_recovery_history(
            custody, digest, maximum_original_bytes=maximum, work=work, current=current)
    else:
        pair = source.custody_client.ControlPlaneCustodyClient.load_registration_preparation(
            custody, digest, maximum_original_bytes=maximum, work=work, current=current)
        observed = None
    current()
    if (type(pair) is not tuple or len(pair) != 2
            or any(type(record) is not source.records.PreparedRecord for record in pair)):
        raise RegistrationHistoryError("registration history is not the actual immutable preparation pair")
    execution_record, signer_record = pair
    if (execution_record.digest != digest
            or execution_record.family != source.execution_records.FAMILY
            or execution_record.selector != source.execution_records.OPERATION
            or signer_record.family != source.signer_records.FAMILY
            or signer_record.selector != source.signer_records.OPERATION
            or execution_record.source_revision != evidence.authority.SOURCE_REVISION
            or signer_record.source_revision != execution_record.source_revision):
        raise RegistrationHistoryError("registration history has no source-supported family adapter")
    held = source.reservation_wire._originals(execution_record.originals, response=False)
    signer = source.signer_wire._request_originals(signer_record.originals)
    observed_raw = _observed_originals(observed, digest, execution_record.source_revision)
    selected_bytes = sum(map(len, (*held, *signer, *observed_raw)))
    reservation = base + _REPRESENTATIONS * selected_bytes
    if reservation > MAX_ORIGINAL_BYTES:
        raise RegistrationHistoryError("registration historical representations exceed the original ceiling")
    selected = None
    if material is None:
        pending, packet = configured.current_pending, configured.completion_packet_digest
    else:
        common, scope, selected = _select_on_work(material, held,
            window=window, bound=bound, work=work, current=current)
        pending, packet = scope.current_pending, scope.completion_packet_digest
    enrollments = _enrollments(common)
    if type(pending) is not tuple or len(pending) != 3:
        raise RegistrationHistoryError("registration recovery pending scope is not independently configured")
    evidence.plan.contract._digest(packet)
    original_bytes = parent_bytes // 8 + archive_bytes + selected_bytes + sum(map(len, enrollments))
    if original_bytes > MAX_ORIGINAL_BYTES:
        raise RegistrationHistoryError("registration historical original inventory exceeds its ceiling")
    current()
    subject = signer_history._verify_subject_on_configuration(payload=common["payload"],
        configuration_digest=common["configuration_digest"], generation=common["generation"],
        runtime_role_identities=common["runtime_role_identities"], request_originals=signer[:8],
        response_originals=signer[8:], live_window=window, work=work, transport_deadline_ns=bound)
    result = {"localDigest": digest, "userId": subject["userId"], "challengeId": subject["challengeId"],
        "sessionId": subject["sessionId"], "mode": subject["mode"],
        "requestDigest": subject["requestDigest"], "operationId": subject["operationId"]}
    current()
    exchanged = exchange._verify_on_configuration(**common, originals=held,
        live_window=window, work=work, transport_deadline_ns=bound)
    evidence.plan._same(exchanged.request_digest, result["requestDigest"], work,
        "historical exchange differs from the genuinely replayed signer request")
    evidence.plan._same(exchanged.operation_id, result["operationId"], work,
        "historical exchange differs from the genuinely replayed signer operation")
    current()
    if selected is not None:
        # These exact originals have all been genuinely authenticated above.
        # Reading only their signed times now adds archive containment; it
        # does not treat unsigned/decoded controls as a substitute for replay.
        for raw in (held[0], held[9], signer[0], signer[2], signer[4], signer[8]):
            value = evidence.wire._decode_object(raw, work=work, maximum_bytes=len(raw))
            _interval(selected, value["issuedAtEpochNs"], value["expiresAtEpochNs"])
            current()
    graph_pins = tuple(_graph_bytes(common[name], work) for name in _GRAPH_FIELDS)
    common_refs = tuple(common[name] for name in _COMMON_FIELDS)
    subject_pin = tuple(result.items())
    current()

    def guarded(value):
        current()
        if (type(value) is not _RegistrationHistory or value._guard is not guarded
                or value.subject is not result or value.common is not common
                or value.current_pending is not pending or value.completion_packet_digest != packet
                or value.originals is not held or value.observed is not observed
                or value.original_bytes != original_bytes or value.original_reservation_bytes != reservation
                or value.window is not window or value.deadline_ns != bound
                or type(common) is not dict or frozenset(common) != _COMMON_FIELDS
                or any(common[name] is not original for name, original in zip(_COMMON_FIELDS, common_refs))):
            raise RegistrationHistoryError("registration historical same-call result changed")
        work.prepare_comparison(tuple(result.items()), subject_pin)
        if tuple(result.items()) != subject_pin:
            raise RegistrationHistoryError("registration historical subject projection changed")
        for name, pin in zip(_GRAPH_FIELDS, graph_pins):
            actual = _graph_bytes(common[name], work)
            work.charge(input_bytes=len(actual) + len(pin))
            if actual != pin:
                raise RegistrationHistoryError("registration historical independent configuration changed")
        return current()

    resolved = _RegistrationHistory(result, common, pending, packet, held, observed,
        original_bytes, reservation, window, bound, guarded)
    resolved.current()
    return resolved
