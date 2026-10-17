"""Original intent authority selected before the fresh proof-preparation actor.

The bounded three-record journal prefix supplies locators, never trust. The
independent cold archive authenticates the original intent and pins its proof
enrollment. Retired authority permits readmission only, not signing or contact.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import control_plane_oidc_session_activation_completion_recovery_consume_selection as consumes
from catchplate import control_plane_oidc_session_activation_history as history
from catchplate import control_plane_oidc_session_activation_release_proof_bootstrap as proof_configuration


execution, records, attempts = consumes.execution, consumes.records, consumes.attempts
bookkeeping, clock, plan = consumes.bookkeeping, consumes.clock, consumes.plan
MAX_ORIGINAL_BYTES = consumes.MAX_ORIGINAL_BYTES
_CONSTRUCTION = object()


class RetainedIntentSelectionError(ValueError):
    pass


def _fail(message):
    raise RetainedIntentSelectionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RetainedIntentSelection:
    _construction: object
    owner: object
    target: object
    work: object
    consume_selection: object
    authority: object
    retained_only: bool
    window: tuple
    deadline_ns: int
    original_reservation_bytes: int
    prefix_pins: tuple | None
    live: object
    _seal: tuple | None = None


_FIELDS = ("owner", "target", "work", "consume_selection", "authority", "retained_only",
    "window", "deadline_ns", "original_reservation_bytes", "prefix_pins", "live")


def _identity(value):
    if (type(value) is not _RetainedIntentSelection or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != len(_FIELDS)
            or any(getattr(value, name) is not held for name, held in zip(_FIELDS, value._seal))
            or type(value.retained_only) is not bool
            or (value.authority is not None
                and type(value.authority) is not history._SelectedActivationHistory)
            or (value.retained_only and value.authority is None)):
        _fail("retained intent selection lost its original source-owned identity")


def _require_selection(value, *, owner, target, work):
    _identity(value)
    if value.owner is not owner or value.target is not target or value.work is not work:
        _fail("retained intent selection belongs to another owner, target or allowance")
    value.live()
    _identity(value)
    return value


def _capture_reservation(owner):
    """Extra projected captures only; target already counts cold archive bytes."""
    parent, archived = history._cold_on_owner(owner)
    candidates = [parent]
    if archived is not None:
        if type(archived.scopes) is not tuple or not 1 <= len(archived.scopes) <= history.archive.MAX_ENTRIES + 1:
            _fail("retained intent cold inventory exceeds its admitted archive bound")
        candidates.extend(archived.scopes)
    sizes = []
    for candidate in candidates:
        intended, proved, planned = candidate.release_intent, candidate.release_proof, candidate.activation_planning
        if intended is None or planned is None:
            _fail("retained intent candidate lacks its independently admitted originals")
        originals = (intended.enrollment_bytes, intended.expected_scope_bytes,
            planned.planner_bootstrap_bytes, candidate.consume_execution.current_root_enrollment_bytes)
        if proved is not None:
            if type(proved) is not proof_configuration._ReleaseProofMaterial:
                _fail("retained intent candidate proof scope changed its cold type")
            originals += (proved.enrollment_bytes, proved.expected_scope_bytes)
        if any(type(raw) is not bytes or not 2 <= len(raw) <= history.evidence.authority.MAX_REQUEST_BYTES
                for raw in originals):
            _fail("retained intent cold projection exceeds its fixed original bounds")
        sizes.append(sum(map(len, originals)))
    reserved = 8 * max(sizes) + 128 * 1024
    if reserved >= MAX_ORIGINAL_BYTES:
        _fail("retained intent cold captures exhaust the unchanged aggregate bound")
    return reserved


def _prefix_pins(prefix, selected, work):
    if type(prefix) is not tuple or len(prefix) != 3:
        _fail("retained intent selection requires the exact three-record prefix")
    activation, claim, original = prefix
    target = selected.target
    if type(activation) is not attempts.ActivationDispatchAttemptRecord:
        _fail("retained intent selection lacks its original activation claim")
    activation_pin = (activation.source_revision, activation.finalization_digest,
        activation.request_binding_digest, activation.authorization_enrollment_digest)
    if activation_pin != selected.prefix_pins[0]:
        _fail("retained intent activation differs from the original consume preselection")
    slot = records._slot_digest(target.subject["localDigest"], target.activation_authorization_digest)
    for value, kind, count in ((claim, "claimed", 0), (original, "release-intent", 1)):
        if (type(value) is not records.ConsumeRecord or value.kind != kind
                or value.source_revision != records.authority.SOURCE_REVISION
                or value.finalization_digest != target.subject["localDigest"]
                or value.activation_authorization_digest != target.activation_authorization_digest
                or value.slot_digest != slot or type(value.originals) is not tuple
                or len(value.originals) != count):
            _fail("retained intent prefix changed its immutable target association")
        records._originals(records.KINDS.index(kind), value.originals)
        attempts._digest_bytes(value.digest)
    plan._same(claim.digest, selected.prefix_pins[1], work,
        "retained intent exact original consume claim")
    return activation_pin, claim.digest, original.digest


def _current_authority(owner, selected, work):
    """Explicit same-current originals, never substitution after a failed lookup."""
    parent = owner._material
    if selected.configuration_digest != parent.configuration_digest:
        return False
    old, current = selected.release_proof, parent.release_proof
    if old is None or current is None:
        return False
    actual = (selected.release_intent.enrollment_bytes, selected.release_intent.expected_scope_bytes,
        old.enrollment_bytes, old.expected_scope_bytes, selected.activation_planning.planner_bootstrap_bytes)
    wanted = (parent.release_intent.enrollment_bytes, parent.release_intent.expected_scope_bytes,
        current.enrollment_bytes, current.expected_scope_bytes, parent.activation_planning.planner_bootstrap_bytes)
    work.charge(input_bytes=sum(map(len, (*actual, *wanted))))
    keys = history.intent.enrollments.keys
    return (actual == wanted and selected.generation["digest"] == parent.generation["digest"]
        and keys._spki_on_work(selected.root_public_key, work)
            == keys._spki_on_work(owner._binding.runtime_root_public_key, work))


def _match_release_records(value, held):
    _require_selection(value, owner=value.owner, target=value.target, work=value.work)
    if type(held) is not tuple or len(held) != 5:
        _fail("retained intent reread changed its fixed release inventory")
    original = held[1]
    if value.prefix_pins is None:
        if original is not None:
            _fail("release intent appeared after its pre-actor prefix selection")
    elif (type(original) is not records.ConsumeRecord or original.kind != "release-intent"
            or original.digest != value.prefix_pins[2]):
        _fail("release intent reread differs from its pre-actor original commitment")
    value.live()


def _select_on_owner(owner, *, target, consume_selection, work, current):
    consumes._require_selection(consume_selection, owner=owner, target=target, work=work)
    if not callable(current):
        _fail("retained intent selection lacks its original base guard")

    def ancestor(epoch, monotonic):
        consumes._require_selection(consume_selection, owner=owner, target=target, work=work)
        observed = current()
        sampled = execution.production._callback(work, time.monotonic_ns)
        if type(observed) is not int or observed < epoch or type(sampled) is not int or sampled < monotonic:
            _fail("retained intent selection original clocks reversed")
        return observed, sampled

    lifetime = bookkeeping._Lifetime(consume_selection.window, consume_selection.deadline_ns, work, ancestor)
    lifetime.current()
    held = consume_selection.original_reservation_bytes + _capture_reservation(owner) + 128 * 1024
    if held >= MAX_ORIGINAL_BYTES:
        _fail("retained intent selection has no remaining pre-read capacity")
    prefix = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_recovery_target(
        owner._custody, target.subject["localDigest"], work=work, current=lifetime.base,
        maximum_original_bytes=3 * ((MAX_ORIGINAL_BYTES - held) // 8))
    lifetime.current()
    authority, pins, retained_only = None, None, False
    if prefix is not None:
        pins = _prefix_pins(prefix, consume_selection, work)
        activation, claim, original = prefix
        encoded = attempts._PREFIX_BYTES + len(activation.source_revision) + attempts._DIGEST_BYTES
        encoded += sum(records._PREFIX_BYTES + len(record.source_revision) + 64
            + 8 * len(record.originals) + sum(map(len, record.originals)) for record in (claim, original))
        held += 8 * encoded
        if held > MAX_ORIGINAL_BYTES:
            _fail("retained intent selected originals exceed the unchanged representation bound")
        authority = history._intent_scope_on_owner(owner, intent_bytes=original.originals[0],
            window=lifetime.window, bound=lifetime.bound, work=work, current=lifetime.base)
        if type(authority.release_proof) is not proof_configuration._ReleaseProofMaterial:
            _fail("retained intent authority has no independently archived proof enrollment")
        retained_only = not _current_authority(owner, authority, work)
        authority.live()
    result = None

    def live():
        if result is not None:
            _identity(result)
        if authority is not None:
            authority.live()
        return lifetime.current()

    result = _RetainedIntentSelection(_CONSTRUCTION, owner, target, work, consume_selection,
        authority, retained_only, lifetime.window, lifetime.bound, held, pins, live)
    object.__setattr__(result, "_seal", tuple(getattr(result, name) for name in _FIELDS))
    live()
    return result
