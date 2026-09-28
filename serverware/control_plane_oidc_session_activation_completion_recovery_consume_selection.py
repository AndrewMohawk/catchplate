"""Read-only selection of original consume authority before fresh binding.

The R0 activation target is not the R1 consume authority. Only an original
signed caller and plan may select the latter; immutable journal commitments
join this small prefix to the later genuine full-control admission.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import control_plane_oidc_session_activation_completion_recovery_history as targets
from serverware import control_plane_oidc_session_activation_consume_history as historical
from serverware import control_plane_oidc_session_activation_consume_records as records
from serverware.authority_query_read_work import _ValidationWork


execution, clock, plan = targets.execution, targets.clock, targets.plan
attempts = records.activation
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_METADATA_BYTES = records.COMPLETION_RECOVERY_METADATA_BYTES
_CONSTRUCTION = object()


class ConsumeRecoverySelectionError(ValueError):
    pass


def _fail(message):
    raise ConsumeRecoverySelectionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumeRecoverySelection:
    """Private same-owner selection, not a received permission or outcome."""

    _construction: object
    owner: object
    target: object
    work: object
    authority: object
    window: tuple
    deadline_ns: int
    original_bytes: int
    original_reservation_bytes: int
    prefix_pins: tuple
    live: object
    _seal: tuple | None = None


_FIELDS = ("owner", "target", "work", "authority", "window", "deadline_ns",
    "original_bytes", "original_reservation_bytes", "prefix_pins", "live")


def _identity(value):
    if (type(value) is not _ConsumeRecoverySelection or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != len(_FIELDS)
            or any(getattr(value, name) is not held for name, held in zip(_FIELDS, value._seal))
            or type(value.authority) is not historical._SelectedConsumeHistory):
        _fail("consume recovery selection is not the original source-owned continuation")


def _require_selection(value, *, owner, target, work):
    _identity(value)
    if value.owner is not owner or value.target is not target or value.work is not work:
        _fail("consume recovery selection belongs to another original owner, target or work")
    value.live()
    _identity(value)
    return value


def _prefix_pins(prefix, target, work):
    if type(prefix) is not tuple or len(prefix) != 4:
        _fail("consume recovery prefix differs from its four-record source inventory")
    activation, claim, prepared, authorized = prefix
    finalization = target.subject["localDigest"]
    if (type(activation) is not attempts.ActivationDispatchAttemptRecord
            or activation.finalization_digest != finalization
            or activation.source_revision != records.authority.SOURCE_REVISION):
        _fail("consume recovery prefix lacks its supported original activation claim")
    plan._same(activation.authorization_enrollment_digest,
        target.authority.activation_execution.authorization_enrollment_digest, work,
        "consume recovery original R0 activation enrollment")
    expected_slot = records._slot_digest(finalization, target.activation_authorization_digest)
    for record, kind, count in ((claim, "claimed", 0), (prepared, "prepared", 6),
            (authorized, "authorized", 1)):
        if (type(record) is not records.ConsumeRecord or record.kind != kind
                or record.source_revision != activation.source_revision
                or record.finalization_digest != finalization
                or record.activation_authorization_digest != target.activation_authorization_digest
                or record.slot_digest != expected_slot
                or type(record.originals) is not tuple or len(record.originals) != count):
            _fail("consume recovery prefix changed its original target or consume association")
        records._originals(records.KINDS.index(kind), record.originals)
        attempts._digest_bytes(record.digest)
    return ((activation.source_revision, activation.finalization_digest,
        activation.request_binding_digest, activation.authorization_enrollment_digest),
        claim.digest, prepared.digest, authorized.digest)


def _match_controls_on_selection(value, selected):
    """Join later bounded DATA; this does not replace any signature admission."""
    _identity(value)
    _require_selection(value, owner=value.owner, target=value.target, work=value.work)
    if type(selected) is not tuple or len(selected) != 10:
        _fail("consume recovery controls differ from the fixed original inventory")
    actual = _prefix_pins(tuple(selected[index] for index in (0, 1, 2, 4)), value.target, value.work)
    if actual != value.prefix_pins:
        _fail("consume recovery controls differ from the pre-actor original commitments")
    value.live()


def _select_on_owner(owner, *, target, live_window, transport_deadline_ns,
        work, current, _additional_original_bytes=0):
    """Select genuine R1 originals on the unchanged owner allowance.

    The returned reservation INCLUDES the target's complete reservation and
    the additional tightening once. Callers replace, not add, that target
    reservation. The original-byte count also includes the target originals.
    """
    if (type(owner) is not execution.startup._EnrollmentOwner
            or type(target) is not targets._CompletionRecoveryTarget
            or type(work) is not _ValidationWork or not callable(current)
            or type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES):
        _fail("consume recovery selection requires the actual original owner and target")
    parent, binding, custody = owner._material, owner._binding, owner._custody
    if parent is None or binding is None or custody is None:
        _fail("consume recovery selection lacks its original cold owner")
    for value in (target.original_bytes, target.original_reservation_bytes):
        if type(value) is not int or not 0 <= value < MAX_ORIGINAL_BYTES:
            _fail("consume recovery target reservation is not bounded")
    window = clock._validate(live_window)
    if (window[:3] != target.live_window[:3]
            or any(new > old for new, old in zip(window[3:], target.live_window[3:]))
            or type(transport_deadline_ns) is not int
            or not window[2] < transport_deadline_ns <= min(window[4], target.deadline_ns)):
        _fail("consume recovery selection cannot widen the original target lifetime")
    bound = transport_deadline_ns
    pid, thread = os.getpid(), threading.get_ident()
    limits = work.limits
    ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    target_pin = (target.authority, target.live, target.live_window, target.deadline_ns,
        target.original_bytes, target.original_reservation_bytes, target.activation_authorization_digest)
    subject_pin = tuple(sorted(target.subject.items()))

    def identity():
        if (os.getpid() != pid or threading.get_ident() != thread
                or execution.startup._owner is not owner
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or any(actual is not held for actual, held in zip((target.authority, target.live,
                    target.live_window, target.deadline_ns, target.original_bytes,
                    target.original_reservation_bytes, target.activation_authorization_digest), target_pin))
                or tuple(sorted(target.subject.items())) != subject_pin):
            _fail("consume recovery selection changed its original owner, target or work")

    def ancestor(epoch, monotonic):
        identity()
        observed = current()
        if type(observed) is not int or observed < epoch:
            _fail("consume recovery selection original epoch reversed")
        target.live()
        now = current()
        sampled = execution.production._callback(work, time.monotonic_ns)
        if (type(now) is not int or now < observed or type(sampled) is not int
                or sampled < monotonic):
            _fail("consume recovery selection original clocks reversed")
        identity()
        return now, sampled

    lifetime = bookkeeping._Lifetime(window, bound, work, ancestor)
    lifetime.current()
    extra = historical._capture_reservation_on_owner(owner)
    if type(extra) is not int or not 0 <= extra < MAX_ORIGINAL_BYTES:
        _fail("consume history capture reservation differs from its fixed source")
    held = target.original_reservation_bytes + _additional_original_bytes + extra + 8 * _METADATA_BYTES
    if held >= MAX_ORIGINAL_BYTES:
        _fail("consume recovery cold captures exhaust the original representation bound")
    prefix = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_consume_prefix(
        custody, target.subject["localDigest"], work=work, current=lifetime.base,
        maximum_original_bytes=3 * ((MAX_ORIGINAL_BYTES - held) // 8))
    lifetime.current()
    if prefix is None:
        _fail("consume recovery has no complete retained dispatched evidence prefix")
    pins = _prefix_pins(prefix, target, work)
    activation, claim, prepared, authorized = prefix
    originals_size = sum(len(raw) for record in (claim, prepared, authorized) for raw in record.originals)
    # Length-only exact framing, not a fresh encode or a source-label rewrite.
    encoded_size = attempts._PREFIX_BYTES + len(activation.source_revision) + attempts._DIGEST_BYTES
    encoded_size += sum(records._PREFIX_BYTES + len(record.source_revision) + 64
        + 8 * len(record.originals) + sum(map(len, record.originals))
        for record in (claim, prepared, authorized))
    reservation = held + 8 * encoded_size
    original_bytes = target.original_bytes + originals_size
    if reservation > MAX_ORIGINAL_BYTES or original_bytes > MAX_ORIGINAL_BYTES:
        _fail("consume recovery selected originals exceed the unchanged representation bound")
    authority = historical._scope_on_owner(owner,
        authorization_bytes=authorized.originals[0], plan_bytes=prepared.originals[3],
        window=lifetime.window, bound=lifetime.bound, work=work, current=lifetime.base)
    if type(authority) is not historical._SelectedConsumeHistory:
        _fail("consume recovery requires genuine original consume authority")
    lifetime.adopt(authority.window, authority.deadline_ns)
    authority.live()
    lifetime.current()
    result = None

    def live():
        identity()
        if result is not None:
            _identity(result)
        authority.live()
        lifetime.current()
        epoch = authority.live()
        identity()
        return epoch

    result = _ConsumeRecoverySelection(_CONSTRUCTION, owner, target, work, authority,
        lifetime.window, lifetime.bound, original_bytes, reservation, pins, live)
    object.__setattr__(result, "_seal", tuple(getattr(result, name) for name in _FIELDS))
    live()
    return result
