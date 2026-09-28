"""Cold-archive finalization selection and guarded same-call replay results.

Neither a record locator nor a decoded context appoints configuration or keys.
The genuine original intent authenticates its detached context before archive
selection. Registration evidence is selected independently by its own controls.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_registration_finalization_history_exchange as history
from serverware import control_plane_registration_history as registration
from serverware import control_plane_registration_finalization_history_bootstrap as bootstrap


archive, evidence, clock = registration.archive, history.evidence, history.clock


class FinalizationHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _FinalizationHistory:
    """Actual same-call originals and pins, never an incoming proof carrier."""

    subject: dict
    originals: tuple
    reservation_originals: tuple
    observed: object
    common: dict
    endpoint: tuple
    current_pending: tuple
    completion_packet_digest: str
    completion_authorization_digest: str
    window: tuple
    deadline_ns: int
    original_bytes: int
    original_reservation_bytes: int
    continuity: object
    _guard: object

    def current(self):
        return self._guard(self)


def _lifetime_on_owner(owner, *, window, bound, work, current):
    """Return a cold-only ancestor: never capture loaded records or results."""
    parent, binding, custody = owner._material, owner._binding, owner._custody
    finalization, registrations = parent.finalization_history, parent.registration_history
    if registrations is not None and type(registrations) is not registration.bootstrap._RegistrationHistoryMaterial:
        raise FinalizationHistoryError("registration history is not the exact cold material")
    if finalization is not None and (
            type(finalization) is not bootstrap._FinalizationHistoryMaterial
            or type(registrations) is not registration.bootstrap._RegistrationHistoryMaterial
            or finalization.registration_history is not registrations
            or finalization.archive is not registrations.archive):
        raise FinalizationHistoryError("finalization history is not bound to its cold registration archive")
    materials = tuple(value for value in (registrations, finalization) if value is not None)
    original_bytes = 0
    for value in materials:
        if (type(value.original_bytes) is not bytes
                or not 2 <= len(value.original_bytes) <= bootstrap.MAX_BYTES):
            raise FinalizationHistoryError("historical cold original exceeds its source bound")
        original_bytes += len(value.original_bytes)
    deadline = min((window[3], *(value.valid_until_epoch_ns for value in materials)))
    window = clock._validate((*window[:3], deadline, window[1] + deadline - window[0],
        window[5], window[6]))
    bound = min(bound, window[4])
    last_epoch, last_monotonic = window[0], window[2]

    def continuity():
        nonlocal last_epoch, last_monotonic
        current()
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.finalization_history is not finalization
                or parent.registration_history is not registrations):
            raise FinalizationHistoryError("historical finalization cold owner changed")
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        history.shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or any(not value.valid_from_epoch_ns <= now < value.valid_until_epoch_ns
                    for value in materials)):
            raise FinalizationHistoryError("historical finalization processing expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        current()
        return now

    continuity()
    return window, bound, continuity, original_bytes


def _select_finalization_on_owner(owner, originals, *, window, bound, work, current):
    """Authenticate the ORIGINAL verifier intent before its context selects history."""
    material = owner._material.finalization_history
    if type(material) is not bootstrap._FinalizationHistoryMaterial:
        raise FinalizationHistoryError("finalization archive selection is not cold enabled")
    current()
    held = history.reservation_wire._originals(originals, response=False)
    captured = archive._capture_on_work(material.archive, work=work)
    wire = history.wire
    intent, signature, unsigned = wire._read_control(held[1], relay=False, work=work)
    initial = archive._lookup_control_on_work(captured,
        configuration_digest=intent["configurationDigest"],
        generation_digest=intent["generationDigest"],
        issued_at_epoch_ns=intent["issuedAtEpochNs"], work=work)
    configured = history.custody.configuration._capture_on_work(operation=history.OPERATION,
        payload=initial.payload, configuration_digest=initial.configuration_digest,
        generation=initial.generation, runtime_role_identities=initial.runtime_role_identities, work=work)
    current()
    pins = history.custody.relay._hold_on_work((held[1], held[2]), held[3:8], configured.pins,
        configured.generation_sequence, configured.generation_digest,
        configured.verifier_public_key, configured.maximum_control_age_ns, work)
    wire._signature(signature, unsigned, relay=False, public_key=configured.verifier_public_key, work=work)
    evidence.capability._canonical(held[1], intent, evidence.capture._SharedLedger(work),
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(intent, configuration_digest=initial.configuration_digest,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        operation=history.OPERATION, work=work)
    actual = wire._body_commitments_on_work(envelope_bytes=held[3], proof_bytes=held[4],
        inputs_bytes=held[5], context_bytes=held[6], historical_expectations_bytes=held[7], work=work)
    evidence.plan._same(actual, {name: intent[name] for name in history.custody.intent._BODY_FIELDS},
        work, "historical finalization intent differs from its complete original bodies")
    issued, expires = wire._time_pins({"issuedAtEpochNs": intent["issuedAtEpochNs"],
        "expiresAtEpochNs": intent["expiresAtEpochNs"]}, configured.maximum_control_age_ns, pins[6][1])
    if issued > current() + pins[6][1]:
        raise FinalizationHistoryError("historical finalization intent is future issued")
    context = history.custody.intent.context_wire._decode_on_work(held[7], work=work)
    evidence.plan._same(context["proofExpectations"]["request"]["operation"], history.OPERATION,
        work, "historical context changed finalization purpose")
    snapshot = archive._lookup_on_work(captured,
        configuration_digest=context["configurationDigest"],
        planner_attestation_receipt_digest=context["plannerIdentity"]["attestationReceiptDigest"],
        evaluation_epoch_ns=context["proofExpectations"]["policy"]["nowEpochNs"], work=work)
    evidence.plan._same((snapshot.configuration_digest, snapshot.generation["digest"]),
        (initial.configuration_digest, initial.generation["digest"]), work,
        "authenticated finalization context changed its original configuration")
    registration._interval(snapshot, issued, expires)
    selected = bootstrap._scope_on_work(material, snapshot=snapshot, work=work)
    common = {"payload": snapshot.payload, "configuration_digest": snapshot.configuration_digest,
        "generation": snapshot.generation, "runtime_role_identities": snapshot.runtime_role_identities,
        "authorization_enrollment_bytes": selected.authorization_enrollment_bytes,
        "grant_enrollment_bytes": selected.grant_enrollment_bytes,
        "current_root_enrollment_bytes": selected.current_root_enrollment_bytes,
        "root_public_key": selected.root_public_key}
    current()
    return common, selected, snapshot


def _authenticated_intervals(snapshot, originals, *, work, current):
    """Only after genuine replay: constrain exact authenticated flat controls."""
    if snapshot is None:
        return
    for raw in originals:
        current()
        value = evidence.wire._decode_object(raw, work=work, maximum_bytes=len(raw))
        registration._interval(snapshot, value["issuedAtEpochNs"], value["expiresAtEpochNs"])
    current()


def _result_on_work(*, subject, originals, reservation_originals, observed, common, evidence_common,
        endpoint, current_pending, completion_packet_digest, completion_authorization_digest,
        window, deadline_ns, original_bytes, original_reservation_bytes, continuity, work,
        retained_originals):
    """Seal the two independently selected graph inventories and actual result."""
    for value in (common, evidence_common):
        if type(value) is not dict or frozenset(value) != registration._COMMON_FIELDS:
            raise FinalizationHistoryError("finalization replay common fields changed")
    fields = tuple(sorted(registration._COMMON_FIELDS))
    common_refs = tuple(tuple(value[name] for name in fields) for value in (common, evidence_common))
    graph_pins = tuple(tuple(registration._graph_bytes(value[name], work)
        for name in registration._GRAPH_FIELDS) for value in (common, evidence_common))
    subject_pin = tuple(subject.items())
    scalar_pin = (completion_packet_digest, completion_authorization_digest,
        deadline_ns, original_bytes, original_reservation_bytes)
    continuity()

    def guarded(value):
        continuity()
        if (type(value) is not _FinalizationHistory or value._guard is not guarded
                or value.subject is not subject or value.originals is not originals
                or value.reservation_originals is not reservation_originals or value.observed is not observed
                or value.common is not common or value.endpoint is not endpoint
                or value.current_pending is not current_pending or value.window is not window
                or value.continuity is not continuity
                or (value.completion_packet_digest, value.completion_authorization_digest,
                    value.deadline_ns, value.original_bytes, value.original_reservation_bytes) != scalar_pin):
            raise FinalizationHistoryError("historical finalization same-call result changed")
        # This full guard intentionally retains all selected originals. Only
        # the separately returned cold-only continuity can outlive their use.
        if type(retained_originals) is not tuple:
            raise FinalizationHistoryError("historical finalization inventory changed")
        work.prepare_comparison(tuple(subject.items()), subject_pin)
        if tuple(subject.items()) != subject_pin:
            raise FinalizationHistoryError("historical finalization subject changed")
        for configured, refs, pins in zip((common, evidence_common), common_refs, graph_pins):
            if (frozenset(configured) != registration._COMMON_FIELDS
                    or any(configured[name] is not original for name, original in zip(fields, refs))):
                raise FinalizationHistoryError("historical finalization original authority changed")
            for name, pin in zip(registration._GRAPH_FIELDS, pins):
                actual = registration._graph_bytes(configured[name], work)
                work.charge(input_bytes=len(actual) + len(pin))
                if actual != pin:
                    raise FinalizationHistoryError("historical finalization configuration changed")
        return continuity()

    result = _FinalizationHistory(subject, originals, reservation_originals, observed, common,
        endpoint, current_pending, completion_packet_digest, completion_authorization_digest,
        window, deadline_ns, original_bytes, original_reservation_bytes, continuity, guarded)
    result.current()
    return result
