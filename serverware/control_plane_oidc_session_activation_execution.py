"""Actual cold activation caller scope, separate from present permission.

The dedicated root-enrolled key stays in the real control-plane owner. A
configuration or scope result is never accepted by a public action as user
permission. Fixed private continuations retain the original allowance through
planning, signed control admission and one isolated protected SQL exchange.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from serverware import authority_oidc_session_activation_execution_authorization as caller
from serverware import control_plane_oidc_session_activation_execution_bootstrap as configured
from serverware import control_plane_enrollment_startup as startup
from serverware import control_plane_custody_client as custody


clock, capture, production = caller.clock, caller.capture, caller.production
shape, plan = caller.shape, caller.plan


def _fail(message):
    raise startup.EnrollmentStartupError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Scope:
    common: dict
    private: object
    window: tuple
    deadline_ns: int
    current: object
    continuity: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PermissionInputs:
    owner: object
    request: object
    original: bytes
    window: tuple
    deadline_ns: int
    work: object
    pid: int
    thread: int


def _open_on_work(work):
    """The options entry opens one bracket before native owner/key checks."""
    capture._SharedLedger(work)
    owner = startup._owner
    if type(owner) is not startup._EnrollmentOwner:
        _fail("activation permission requires an actual cold enrollment owner")
    material, binding = owner._material, owner._binding
    if (material is None or type(binding) is not custody._Binding
            or type(material.activation_execution) is not configured._ActivationExecutionMaterial):
        _fail("activation caller purpose is not independently configured")
    policy = material.activation_execution
    skew = policy.maximum_clock_skew_ns
    if material.issuer_policy is not None:
        skew = min(skew, material.issuer_policy["maximumClockSkewNs"])
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, policy.maximum_age_ns),
        maximum_clock_skew_ns=skew, work=work)
    return owner, window


def _scope_on_owner(owner, *, live_window, transport_deadline_ns, work):
    """Hold real key/resources before callbacks and retain all clock maxima."""
    capture._SharedLedger(work)
    if type(owner) is not startup._EnrollmentOwner:
        _fail("activation signing requires the actual cold owner")
    material, binding, custody_owner = owner._material, owner._binding, owner._custody
    private, descriptor, descriptor_identity = (
        owner._activation_key, owner._activation_key_fd, owner._activation_key_identity)
    response_path, response_pin = owner._response_path, owner._response_pin
    if (material is None or type(binding) is not custody._Binding
            or type(custody_owner) is not custody.ControlPlaneCustodyClient):
        _fail("activation caller lacks actual root/custody configuration")
    policy = material.activation_execution
    if (type(policy) is not configured._ActivationExecutionMaterial or private is None
            or descriptor != configured.CALLER_KEY_FD or descriptor != policy.caller_private_key_fd
            or descriptor_identity is None or type(response_path) is not str
            or response_pin is None or binding.caller_uid != 65532 or binding.caller_gid != 65532
            or material.configuration_digest != binding.configuration_digest):
        _fail("activation caller key and fixed cold identity are not enabled")
    caller.authorization._private(private)
    shape._digest(response_pin)
    window = caller.window_policy._narrow(live_window,
        deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, policy.maximum_age_ns),
        maximum_clock_skew_ns=policy.maximum_clock_skew_ns)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    common = {"authorization_enrollment_bytes": policy.authorization_enrollment_bytes,
        "current_root_enrollment_bytes": policy.current_root_enrollment_bytes,
        "grant_enrollment_bytes": policy.grant_enrollment_bytes,
        "root_public_key": binding.runtime_root_public_key,
        "configuration_digest": material.configuration_digest,
        "planner_public_key": policy.planner_public_key,
        "operation_public_key": policy.operation_public_key}
    last_epoch, last_monotonic = window[0], window[2]

    def identity():
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody_owner or material.activation_execution is not policy
                or owner._activation_key is not private or owner._activation_key_fd != descriptor
                or owner._activation_key_identity is not descriptor_identity
                or owner._response_path != response_path or owner._response_pin != response_pin):
            _fail("activation caller original resources changed")

    def sample(epoch):
        nonlocal last_epoch, last_monotonic
        shape._integer(epoch, minimum=1)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (epoch < last_epoch or monotonic < last_monotonic
                or epoch >= window[3] or monotonic >= bound):
            _fail("activation caller original clocks expired or reversed")
        last_epoch, last_monotonic = epoch, monotonic

    def current(epoch_floor=None, monotonic_floor=None):
        nonlocal last_epoch, last_monotonic
        capture._SharedLedger(work)
        if epoch_floor is not None or monotonic_floor is not None:
            shape._integer(epoch_floor, minimum=1)
            shape._integer(monotonic_floor, minimum=1)
            last_epoch, last_monotonic = max(last_epoch, epoch_floor), max(last_monotonic, monotonic_floor)
        identity()
        # Metadata for the sealed inherited originals, then the
        # actual bounded provisioned HTTP key. This key is not borrowed to sign.
        work.charge(input_bytes=4096)
        sample(production._callback(work, lambda: startup._continuity(owner)))
        work.charge(input_bytes=4096)
        actual_response_pin = startup._response_spki(response_path, binding.caller_uid, work)
        if actual_response_pin != response_pin:
            _fail("activation caller HTTP response-key identity drifted")
        sample(production._callback(work, lambda: startup._continuity(owner)))
        sample(clock._check_on_work(window, work=work))
        identity()
        return last_epoch

    def continuity(epoch_floor, monotonic_floor):
        current(epoch_floor, monotonic_floor)
        return last_epoch, last_monotonic

    current()
    caller.keys._pair_on_work(private, policy.caller_public_key, work)
    signing_pin = caller.keys._spki_on_work(policy.caller_public_key, work)
    if signing_pin == response_pin:
        _fail("activation caller reuses the actual HTTP response key")
    current()
    return _Scope(common, private, window, bound, current, continuity)


class _ActivationPermission:
    """Live parent-owned context, never accepted as an input proof object."""

    __slots__ = ("_owner", "_request", "_original", "_window", "_deadline", "_work",
        "_pid", "_thread", "_state", "_locked", "_trust", "_scope", "_target", "_spent",
        "_permission_epoch", "_session_expiry", "_inputs", "_seal", "_normal_exit",
        "_planning_spent", "_planning_bounds", "_planning_observed",
        "_request_issuance_spent", "_request_issuance",
        "_dispatch_phase", "_sql_originals", "_sql_seal", "_completion_originals", "_completion_seal",
        "_completion_context", "_completion_context_seal", "_consume_spent",
        "_consume_claim", "_consume_claim_seal",
        "_consume_lifetimes", "_consume_lifetimes_seal",
        "_consume_originals", "_consume_originals_seal", "_consume_context", "_consume_context_seal",
        "_consume_possession", "_consume_possession_seal", "_consume_authorization_spent",
        "_consume_signing", "_consume_signing_seal", "_consume_authorization", "_consume_authorization_seal",
        "_consume_dispatch_spent", "_consume_sql_originals", "_consume_sql_seal",
        "_consume_sql_context", "_consume_sql_context_seal", "_consume_sql_outcome", "_consume_sql_outcome_seal",
        "_consume_completion_spent", "_consume_completion_originals", "_consume_completion_seal",
        "_consume_completion_context", "_consume_completion_context_seal",
        "_consume_completion_hints", "_consume_completion_hints_seal", "_release_intent_spent",
        "_release_intent_signing", "_release_intent_signing_seal", "_release_intent_original", "_release_intent_seal",
        "_release_intent_context", "_release_intent_context_seal", "_release_proof_spent",
        "_release_proof_originals", "_release_proof_seal", "_release_proof_context", "_release_proof_context_seal",
        "_release_handoff_spent")

    def __init__(self, owner, request, permission_bytes, live_window, transport_deadline_ns, work):
        from serverware import control_plane_oidc_session_activation_permission as permission

        capture._SharedLedger(work)
        if type(owner) is not startup._EnrollmentOwner:
            _fail("activation permission requires the actual cold owner")
        self._owner, self._request = owner, request
        self._original = permission._request_original(request, permission_bytes, work)
        self._window, self._deadline = clock._validate(live_window), transport_deadline_ns
        shape._integer(self._deadline, minimum=1)
        self._work, self._pid, self._thread = work, os.getpid(), threading.get_ident()
        self._state, self._locked, self._trust = "new", False, None
        self._normal_exit = False
        self._scope, self._target, self._spent = None, None, False
        self._permission_epoch = None
        self._session_expiry = None
        self._planning_spent, self._planning_bounds = False, None
        self._planning_observed = None
        self._request_issuance_spent, self._request_issuance = False, None
        self._dispatch_phase, self._sql_originals, self._sql_seal = "new", None, None
        self._completion_originals = self._completion_seal = None
        self._completion_context = self._completion_context_seal = None
        self._consume_spent = False
        self._consume_claim = self._consume_claim_seal = None
        self._consume_lifetimes = self._consume_lifetimes_seal = None
        self._consume_originals = self._consume_originals_seal = None
        self._consume_context = self._consume_context_seal = None
        self._consume_possession = self._consume_possession_seal = None
        self._consume_authorization_spent = False
        self._consume_signing = self._consume_signing_seal = None
        self._consume_authorization = self._consume_authorization_seal = None
        self._consume_dispatch_spent = False
        self._consume_sql_originals = self._consume_sql_seal = None
        self._consume_sql_context = self._consume_sql_context_seal = None
        self._consume_sql_outcome = self._consume_sql_outcome_seal = None
        self._consume_completion_spent = False
        self._consume_completion_originals = self._consume_completion_seal = None
        self._consume_completion_context = self._consume_completion_context_seal = None
        self._consume_completion_hints = self._consume_completion_hints_seal = None
        self._release_intent_spent = False
        self._release_proof_spent = False
        self._release_handoff_spent = False
        self._release_proof_originals = self._release_proof_seal = None
        self._release_proof_context = self._release_proof_context_seal = None
        self._release_intent_signing = self._release_intent_signing_seal = None
        self._release_intent_original = self._release_intent_seal = None
        self._release_intent_context = self._release_intent_context_seal = None
        self._inputs = _PermissionInputs(owner, request, self._original, self._window,
            self._deadline, work, self._pid, self._thread)
        self._seal = self._inputs

    def _inputs_unchanged(self):
        held = self._inputs
        if (type(held) is not _PermissionInputs or held is not self._seal
                or self._owner is not held.owner or self._request is not held.request
                or self._original is not held.original or self._window is not held.window
                or self._deadline != held.deadline_ns or self._work is not held.work
                or self._pid != held.pid or self._thread != held.thread):
            _fail("activation permission replaced its original inputs or allowance")

    def _identity(self):
        self._inputs_unchanged()
        if (self._state not in ("entering", "active") or os.getpid() != self._pid
                or threading.get_ident() != self._thread
                or type(self._owner) is not startup._EnrollmentOwner
                or self._owner._activation_permission is not self or not self._locked):
            _fail("activation permission context is no longer the active parent-owned call")
        # Proof and handoff phases retain every intent/predecessor invariant.
        phase = ("release-intent-authorized" if self._dispatch_phase in (
            "release-proof-requesting", "release-proof-verified", "release-handoff-requesting") else self._dispatch_phase)
        if phase not in ("new", "preparing", "preparing-completion",
                "sql", "sql-completion", "completed", "consume-planning", "consume-planned",
                "consume-authorizing", "consume-authorized", "consume-dispatching", "consume-sql", "consume-dispatched",
                "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized", "closed"):
            _fail("activation permission dispatch phase is not source fixed")
        if phase in ("sql", "sql-completion", "completed", "consume-planning", "consume-planned",
                "consume-authorizing", "consume-authorized", "consume-dispatching", "consume-sql", "consume-dispatched",
                "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized") and (
                self._spent is not True or self._planning_spent is not True
                or type(self._sql_originals) is not tuple or len(self._sql_originals) != 8
                or self._sql_originals is not self._sql_seal
                or any(type(raw) is not bytes for raw in self._sql_originals)):
            _fail("activation SQL continuation replaced its exact admitted originals")
        if phase in ("completed", "consume-planning", "consume-planned",
                "consume-authorizing", "consume-authorized", "consume-dispatching", "consume-sql", "consume-dispatched",
                "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized") and (
                type(self._completion_originals) is not tuple or len(self._completion_originals) != 4
                or self._completion_originals is not self._completion_seal
                or self._completion_originals[0] != b"acknowledged"
                or any(type(raw) is not bytes for raw in self._completion_originals)
                or type(self._completion_context) is not tuple or len(self._completion_context) != 3
                or self._completion_context is not self._completion_context_seal
                or type(self._completion_context[0]) is not bytes):
            _fail("consume planning lost the actual same-call completion continuation")
        if self._consume_lifetimes is not self._consume_lifetimes_seal:
            _fail("consume planning replaced its admitted root-original lifetimes")
        if (self._consume_claim is not self._consume_claim_seal
                or self._consume_claim is not None and (
                    type(self._consume_claim) is not tuple or len(self._consume_claim) != 3
                    or any(type(value) is not str for value in self._consume_claim))):
            _fail("consume planning replaced its original same-call durable claim")
        if phase in ("consume-planned", "consume-authorizing", "consume-authorized",
                "consume-dispatching", "consume-sql", "consume-dispatched", "consume-completing", "consume-completion-observed",
                "release-intent-signing", "release-intent-authorized"):
            if (self._consume_spent is not True or self._consume_claim is None
                    or type(self._consume_originals) is not tuple
                    or len(self._consume_originals) != 2 or self._consume_originals is not self._consume_originals_seal
                    or any(type(raw) is not tuple or len(raw) != count
                        or any(type(value) is not bytes for value in raw)
                        for raw, count in zip(self._consume_originals, (6, 7)))
                    or self._consume_originals[0][0] != b"prepared" or self._consume_originals[1][0] != b"exported"
                    or type(self._consume_context) is not tuple or len(self._consume_context) != 4
                    or self._consume_context is not self._consume_context_seal
                    or type(self._consume_context[0]) is not bytes
                    or type(self._consume_context[3]) is not int or self._consume_context[3] < 1
                    or type(self._consume_possession) is not tuple or len(self._consume_possession) != 2
                    or self._consume_possession is not self._consume_possession_seal
                    or self._request.cookies.get(self._consume_possession[0]) != self._consume_possession[1]):
                _fail("consume authorization lost its actual retained planning or possession originals")
        if self._consume_signing is not self._consume_signing_seal:
            _fail("consume signing replaced its original key custody")
        if self._consume_signing is not None:
            policy, private, descriptor, identity = self._consume_signing
            if (self._owner._material.consume_execution is not policy or self._owner._consume_key is not private
                    or self._owner._consume_key_fd != descriptor or self._owner._consume_key_identity is not identity):
                _fail("consume signing original cold resources changed")
        if phase in ("consume-authorizing", "consume-authorized", "consume-dispatching",
                "consume-sql", "consume-dispatched", "consume-completing", "consume-completion-observed",
                "release-intent-signing", "release-intent-authorized") and self._consume_authorization_spent is not True:
            _fail("consume authorization did not spend its one-use signing latch")
        if phase in ("consume-authorized", "consume-dispatching", "consume-sql", "consume-dispatched",
                "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized") and (
                type(self._consume_authorization) is not bytes
                or self._consume_authorization is not self._consume_authorization_seal
                or self._consume_signing is None):
            _fail("consume authorization lost its exact retained signed original")
        if phase in ("consume-dispatching", "consume-sql", "consume-dispatched",
                "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized") and self._consume_dispatch_spent is not True:
            _fail("consume dispatch did not spend its one-use continuation")
        if phase in ("consume-sql", "consume-dispatched", "consume-completing", "consume-completion-observed",
                "release-intent-signing", "release-intent-authorized") and (
                type(self._consume_sql_originals) is not tuple or len(self._consume_sql_originals) != 8
                or self._consume_sql_originals is not self._consume_sql_seal
                or any(type(raw) is not bytes for raw in self._consume_sql_originals)
                or type(self._consume_sql_context) is not tuple or len(self._consume_sql_context) != 4
                or self._consume_sql_context is not self._consume_sql_context_seal
                or type(self._consume_sql_context[0]) is not bytes
                or type(self._consume_sql_context[3]) is not int or self._consume_sql_context[3] < 1):
            _fail("consume SQL continuation lost its exact admitted originals")
        if phase in ("consume-dispatched", "consume-completing", "consume-completion-observed",
                "release-intent-signing", "release-intent-authorized") and (
                type(self._consume_sql_outcome) is not tuple or len(self._consume_sql_outcome) != 4
                or self._consume_sql_outcome is not self._consume_sql_outcome_seal
                or any(type(raw) is not bytes for raw in self._consume_sql_outcome)):
            _fail("consume SQL continuation lost its retained unsigned outcome")
        if phase in ("consume-completing", "consume-completion-observed",
                "release-intent-signing", "release-intent-authorized") and self._consume_completion_spent is not True:
            _fail("consume completion did not spend its one-use continuation")
        if phase in ("consume-completion-observed", "release-intent-signing", "release-intent-authorized") and (
                type(self._consume_completion_originals) is not tuple or len(self._consume_completion_originals) != 4
                or self._consume_completion_originals is not self._consume_completion_seal
                or any(type(raw) is not bytes for raw in self._consume_completion_originals)
                or type(self._consume_completion_context) is not tuple or len(self._consume_completion_context) != 4
                or self._consume_completion_context is not self._consume_completion_context_seal
                or type(self._consume_completion_context[0]) is not bytes
                or type(self._consume_completion_context[3]) is not int or self._consume_completion_context[3] < 1):
            _fail("consume completion lost its exact original observation or live continuation")
        if self._consume_completion_hints is not self._consume_completion_hints_seal:
            _fail("consume completion replaced its retained untrusted release hints")
        if self._release_intent_signing is not self._release_intent_signing_seal:
            _fail("release intent replaced its original dedicated key custody")
        if self._release_intent_signing is not None:
            policy, private, descriptor, identity = self._release_intent_signing
            if (self._owner._material.release_intent is not policy or self._owner._intent_key is not private
                    or self._owner._intent_key_fd != descriptor or self._owner._intent_key_identity is not identity):
                _fail("release intent original cold resources changed")
        if phase in ("release-intent-signing", "release-intent-authorized") and (
                self._release_intent_spent is not True or self._consume_completion_originals[0] != b"acknowledged"
                or type(self._consume_completion_hints) is not tuple or len(self._consume_completion_hints) != 2
                or any(type(raw) is not bytes or not raw for raw in self._consume_completion_hints)):
            _fail("release intent lacks its actual acknowledged completion and retained hints")
        if phase == "release-intent-authorized" and (
                type(self._release_intent_original) is not bytes or self._release_intent_original is not self._release_intent_seal
                or self._release_intent_signing is None
                or type(self._release_intent_context) is not tuple or len(self._release_intent_context) != 4
                or self._release_intent_context is not self._release_intent_context_seal
                or type(self._release_intent_context[0]) is not bytes
                or type(self._release_intent_context[3]) is not int or self._release_intent_context[3] < 1):
            _fail("release intent lost its exact retained original or live continuation")
        if self._dispatch_phase in ("release-proof-requesting", "release-proof-verified", "release-handoff-requesting") and self._release_proof_spent is not True:
            _fail("release proof did not spend its one-use continuation")
        if self._release_proof_originals is not self._release_proof_seal:
            _fail("release proof replaced its retained response originals")
        if self._dispatch_phase in ("release-proof-verified", "release-handoff-requesting") and (
                type(self._release_proof_originals) is not tuple or len(self._release_proof_originals) != 4
                or any(type(raw) is not bytes for raw in self._release_proof_originals)
                or self._release_proof_originals[0] != b"proved"
                or type(self._release_proof_context) is not tuple or len(self._release_proof_context) != 4
                or self._release_proof_context is not self._release_proof_context_seal
                or type(self._release_proof_context[0]) is not bytes
                or type(self._release_proof_context[3]) is not int or self._release_proof_context[3] < 1):
            _fail("release proof lost its exact admitted originals or live continuation")
        if self._dispatch_phase == "release-handoff-requesting" and self._release_handoff_spent is not True:
            _fail("release handoff did not spend its one-use continuation")

    def _current(self, epoch_floor=None, monotonic_floor=None):
        self._identity()
        scope = self._scope
        if type(scope) is not _Scope:
            _fail("activation permission lacks its actual same-call cold scope")
        if epoch_floor is not None or monotonic_floor is not None:
            shape._integer(epoch_floor, minimum=1)
            shape._integer(monotonic_floor, minimum=1)
        if self._planning_observed is not None:
            epoch_floor = max(self._planning_observed[0], epoch_floor or 0)
            monotonic_floor = max(self._planning_observed[1], monotonic_floor or 0)
        scope.current(epoch_floor, monotonic_floor)
        if self._target is not None and self._dispatch_phase not in (
                "sql", "sql-completion", "completed", "consume-planning", "consume-planned",
                "consume-authorizing", "consume-authorized", "consume-dispatching", "consume-sql", "consume-dispatched",
                "consume-completing", "consume-completion-observed", "release-intent-signing", "release-intent-authorized",
                "release-proof-requesting", "release-proof-verified", "release-handoff-requesting"):
            from serverware import control_plane_registration_finalization_completion_pending as pending

            application, session_scope, binding, credential, count = self._target
            production._callback(self._work, lambda: pending._recheck(application,
                self._request, binding, session_scope, credential, count))
            scope.current()
        self._identity()
        now = scope.current()
        if self._session_expiry is not None and now >= self._session_expiry:
            _fail("activation permission pending session expired")
        if self._consume_lifetimes is not None:
            from serverware import oidc_session_activation_delivery_planner_bootstrap as consume_bootstrap

            # These exact immutable brackets were obtained by genuine root
            # admission in this call. Keep their stricter launch clocks even
            # through context exit; the final narrowed clock check stays last.
            for interval, opening in self._consume_lifetimes:
                prior = scope.continuity(now, self._planning_observed[1])
                sampled = consume_bootstrap.shared._fresh(interval, self._work, opening=opening)
                if sampled[0] < prior[1] or sampled[1] < prior[0]:
                    _fail("consume root-original clock reversed across the actual owner")
                now, _monotonic = scope.continuity(sampled[1], sampled[2])
        if self._planning_bounds is not None:
            window, bound = self._planning_bounds
            observed = scope.continuity(now, self._planning_observed[1])
            # The last real clock check uses the narrowed policy, including
            # skew. Keep its newer floors for the next owner call; do not
            # append a weaker original-window native suffix after this check.
            now = clock._check_on_work(window, work=self._work)
            monotonic = production._callback(self._work, time.monotonic_ns)
            shape._integer(monotonic, minimum=1)
            if (now < observed[0] or monotonic < observed[1]
                    or now >= window[3] or monotonic >= bound):
                _fail("activation permission planning clocks expired or reversed")
            self._planning_observed = now, monotonic
            self._identity()
        return now

    def _continuity(self, epoch_floor, monotonic_floor):
        self._current(epoch_floor, monotonic_floor)
        if self._planning_bounds is not None:
            return self._planning_observed
        # The final cold check absorbs this context's actual observations; no
        # independent time sample or renewed allowance is manufactured here.
        observed = self._scope.continuity(epoch_floor, monotonic_floor)
        if self._session_expiry is not None and observed[0] >= self._session_expiry:
            _fail("activation permission pending session expired")
        return observed

    def _narrow_planning(self, window, deadline_ns):
        """Keep the same opening and only reduce this active call's limits."""
        self._identity()
        narrowed = clock._validate(window)
        shape._integer(deadline_ns, minimum=1)
        prior, prior_deadline = (self._planning_bounds if self._planning_bounds is not None
            else (self._scope.window, self._scope.deadline_ns))
        if (narrowed[:3] != prior[:3] or any(narrowed[index] > prior[index] for index in (3, 4, 5, 6))
                or deadline_ns > prior_deadline or deadline_ns > narrowed[4]):
            _fail("activation planning replaced or widened the original allowance")
        self._planning_bounds = narrowed, deadline_ns
        if self._planning_observed is None:
            self._planning_observed = narrowed[0], narrowed[2]

    def _revoke(self):
        self._normal_exit = False
        self._state, self._spent, self._planning_spent = "closed", True, True
        if self._owner._activation_permission is self:
            self._owner._activation_permission = None
        trust, locked = self._trust, self._locked
        self._trust, self._locked = None, False
        self._target, self._scope = None, None
        self._planning_bounds = None
        self._planning_observed = None
        self._request_issuance_spent = True
        if self._request_issuance is not None:
            from serverware import control_plane_oidc_session_activation_request_issuance as issuance
            if type(self._request_issuance) is issuance._Continuation:
                issuance._Continuation._close(self._request_issuance)
            self._request_issuance = None
        self._dispatch_phase, self._sql_originals, self._sql_seal = "closed", None, None
        self._completion_originals = self._completion_seal = None
        self._completion_context = self._completion_context_seal = None
        self._consume_spent = True
        self._consume_claim = self._consume_claim_seal = None
        self._consume_lifetimes = self._consume_lifetimes_seal = None
        self._consume_originals = self._consume_originals_seal = None
        self._consume_context = self._consume_context_seal = None
        self._consume_possession = self._consume_possession_seal = None
        self._consume_authorization_spent = True
        self._consume_signing = self._consume_signing_seal = None
        self._consume_authorization = self._consume_authorization_seal = None
        self._consume_dispatch_spent = True
        self._consume_sql_originals = self._consume_sql_seal = None
        self._consume_sql_context = self._consume_sql_context_seal = None
        self._consume_sql_outcome = self._consume_sql_outcome_seal = None
        self._consume_completion_spent = True
        self._consume_completion_originals = self._consume_completion_seal = None
        self._consume_completion_context = self._consume_completion_context_seal = None
        self._consume_completion_hints = self._consume_completion_hints_seal = None
        self._release_intent_spent = True
        self._release_proof_spent = True
        self._release_handoff_spent = True
        self._release_proof_originals = self._release_proof_seal = None
        self._release_proof_context = self._release_proof_context_seal = None
        self._release_intent_signing = self._release_intent_signing_seal = None
        self._release_intent_original = self._release_intent_seal = None
        self._release_intent_context = self._release_intent_context_seal = None
        try:
            if trust is not None:
                trust.__exit__(None, None, None)
        finally:
            if locked:
                startup._LOCK.release()

    def __enter__(self):
        from serverware import app as application
        from serverware import control_plane_oidc_session_activation_permission as permission
        from serverware import control_plane_registration_finalization_completion_pending as pending

        self._inputs_unchanged()
        if self._state != "new" or os.getpid() != self._pid or threading.get_ident() != self._thread:
            _fail("activation permission context cannot be reentered or transferred")
        self._state = "entering"
        try:
            # Do not wait/retry for another active control-plane operation.
            if not startup._LOCK.acquire(blocking=False):
                _fail("activation permission owner is busy")
            self._locked = True
            if self._owner._activation_permission is not None:
                _fail("activation permission owner already has an active call")
            self._owner._activation_permission = self
            payload = permission.contract.parse_request(self._original, options=False)
            self._work.prepare_scan(payload)
            self._scope = _scope_on_owner(self._owner, live_window=self._window,
                transport_deadline_ns=self._deadline, work=self._work)
            self._current()
            trust = application.trust_bundle_lock(exclusive=False)
            trust.__enter__()
            self._trust = trust
            self._current()
            _app, session, _identity, session_scope, binding, credential, digest = permission._target_on_owner(
                self._owner, request=self._request, payload=payload, live_window=self._scope.window,
                transport_deadline_ns=self._scope.deadline_ns, work=self._work, current=self._current)
            self._session_expiry = permission._session_deadline(session, self._work)
            self._work.prepare_scan(payload)
            self._work.charge(hashes=4)
            count = permission._native(self._current, self._work,
                lambda: pending._assertion(application, payload, binding, credential, digest))
            identity = permission._native(self._current, self._work,
                lambda: pending._recheck(application, self._request, binding, session_scope, credential, count))
            permission._native(self._current, self._work,
                lambda: application._require_control_plane_two_person(action=binding["action"],
                    resource_id=binding["challengeId"], payload_digest=digest,
                    mfa=payload.get("mfa"), identity=identity, request=binding))
            self._target = application, session_scope, binding, credential, count
            self._state = "active"
            self._permission_epoch = self._current()
            return self
        except BaseException:
            self._revoke()
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        if os.getpid() != self._pid or threading.get_ident() != self._thread:
            _fail("activation permission cleanup belongs to its original process and thread")
        if self._state == "closed":
            return False
        try:
            if exc_type is None:
                self._current()
        finally:
            self._revoke()
        if exc_type is None:
            # Only a successful final live check AND completed per-call
            # cleanup can enable the source-owned HTTP delivery continuation.
            self._normal_exit = True
        return False

    def authorize(self, *, originals, expectations, before_vector_bytes):
        """Sign once after a plan is produced inside this post-permission call."""
        try:
            self._identity()
            if self._state != "active" or self._spent is not False:
                _fail("activation permission signing has already been spent")
            self._spent = True
            work, scope = self._work, self._scope
            # Hold all raw originals and the complete only mutable graph before
            # the first owner/native/hash callback in this signing phase.
            held, before = caller.grants.replay._originals(caller.OPERATION, originals, before_vector_bytes)
            raw_enrollments = tuple(scope.common[name] for name in (
                "authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"))
            if (sum(len(raw) for raw in (*held, before, *raw_enrollments, self._original))
                    + caller.MAX_AUTHORIZATION_BYTES > caller.grants.replay.MAX_ORIGINAL_BYTES):
                _fail("activation permission complete signing originals exceed their aggregate bound")
            owned = caller.expectations_wire._capture_on_work(expectations, work=work)
            self._current()
            application, session_scope, binding, credential, count = self._target
            from serverware import control_plane_registration_finalization_completion_pending as pending

            session, _identity, actual_scope = production._callback(work,
                lambda: pending._session(application, self._request))
            if actual_scope != session_scope:
                _fail("activation permission session changed before plan signing")
            arguments = caller.expectations_wire.plan.transition._arguments(owned["request"]["arguments"], work)
            for name, expected in (("session_id", binding["sessionId"]), ("user_id", binding["userId"]),
                    ("credential_id", binding["credentialId"]), ("credential_record_id", credential[0]),
                    ("old_token_digest", session["token_digest"])):
                plan._same(arguments[name], expected, work, "activation permission exact retained target " + name)
            self._current()
            actual_plan, _plan_digest = caller.activation._authenticate(held[0],
                owned["request"], owned["scope"], scope.common["planner_public_key"], self._current, work)
            if actual_plan["issuedAtEpochNs"] < self._permission_epoch:
                _fail("activation plan predates this call's fresh permission and counter update")
            self._current()
            # Fresh permission has already changed the credential counter.
            # The caller must obtain its genuine new plan inside this context;
            # no pre-permission plan is acquired, renewed or dispatched here.
            selected_window, selected_deadline = (self._planning_bounds
                if self._planning_bounds is not None else (scope.window, scope.deadline_ns))
            signing_window = caller.window_policy._narrow(selected_window,
                deadline_epoch_ns=self._session_expiry, maximum_lifetime_ns=selected_window[5],
                maximum_clock_skew_ns=selected_window[6])
            return caller._produce_on_work(**scope.common, caller_private_key=scope.private,
                originals=held, expectations=owned, before_vector_bytes=before,
                live_window=signing_window, transport_deadline_ns=min(selected_deadline, signing_window[4]),
                work=work, _continuity=self._continuity)
        except BaseException:
            # A rejected foreign thread cannot close the creating thread's
            # locks; the real thread still owns mandatory context cleanup.
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def prepare_authorization(self, *, assertion_bytes, expected_challenge_id):
        """Claim once, obtain a real post-permission plan, then sign originals."""
        from serverware import control_plane_oidc_session_activation_planning as planning

        try:
            self._identity()
            if self._state != "active" or self._spent is not False or self._planning_spent is not False:
                _fail("activation permission preparation has already been spent")
            original, challenge = planning._planning_inputs(assertion_bytes, expected_challenge_id)
            self._planning_spent = True
            return planning._prepare_on_permission(self,
                assertion_bytes=original, expected_challenge_id=challenge)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def dispatch(self, *, assertion_bytes, expected_challenge_id):
        """One original-bound planner/grant/reserve/SQL continuation, no retry."""
        from serverware import control_plane_oidc_session_activation_dispatch as dispatch
        from serverware import control_plane_oidc_session_activation_planning as planning

        try:
            self._identity()
            if (self._state != "active" or self._spent is not False
                    or self._planning_spent is not False or self._dispatch_phase != "new"):
                _fail("activation permission dispatch has already been spent")
            original, challenge = planning._planning_inputs(assertion_bytes, expected_challenge_id)
            self._dispatch_phase = "preparing"
            return dispatch._dispatch_on_permission(self,
                assertion_bytes=original, expected_challenge_id=challenge)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def dispatch_completion(self, *, assertion_bytes, expected_challenge_id):
        """One fixed SQL/completion continuation returning only original raw4s."""
        from serverware import control_plane_oidc_session_activation_dispatch as dispatch
        from serverware import control_plane_oidc_session_activation_planning as planning

        try:
            self._identity()
            if (self._state != "active" or self._spent is not False
                    or self._planning_spent is not False or self._dispatch_phase != "new"):
                _fail("activation completion dispatch has already been spent")
            original, challenge = planning._planning_inputs(assertion_bytes, expected_challenge_id)
            self._dispatch_phase = "preparing-completion"
            return dispatch._dispatch_completion_on_permission(self,
                assertion_bytes=original, expected_challenge_id=challenge)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def prepare_consume(self, *, planner_bootstrap_bytes, history_custody_bytes):
        """Consume only new root originals on this still-active completed call."""
        from serverware import control_plane_oidc_session_activation_consume_planning as consume

        try:
            self._identity()
            if self._state != "active" or self._dispatch_phase != "completed" or self._consume_spent:
                _fail("consume preparation requires the unspent same-call acknowledged completion")
            originals = consume._inputs(planner_bootstrap_bytes, history_custody_bytes)
            self._consume_spent = True
            self._dispatch_phase = "consume-planning"
            result = consume._prepare_on_permission(self,
                planner_bootstrap_bytes=originals[0], history_custody_bytes=originals[1])
            self._dispatch_phase = "consume-planned"
            return result
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def acquire_and_prepare_consume(self):
        """Acquire root inputs once, on this actual acknowledged continuation."""
        from serverware import control_plane_oidc_session_activation_consume_input_acquisition as acquisition

        try:
            self._identity()
            if self._state != "active" or self._dispatch_phase != "completed" or self._consume_spent:
                _fail("consume input acquisition requires the unspent same-call completion")
            self._consume_spent = True
            self._dispatch_phase = "consume-planning"
            result = acquisition._acquire_on_permission(self)
            self._dispatch_phase = "consume-planned"
            return result
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def authorize_consume(self):
        """Sign and retain once using only this call's sealed consume originals."""
        from serverware import control_plane_oidc_session_activation_consume_authorization as consume

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "consume-planned"
                    or self._consume_authorization_spent is not False):
                _fail("consume authorization requires the unspent actual planning continuation")
            self._consume_authorization_spent = True
            self._dispatch_phase = "consume-authorizing"
            original = consume._authorize_on_permission(self)
            self._consume_authorization = self._consume_authorization_seal = original
            self._dispatch_phase = "consume-authorized"
            return original
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def dispatch_consume(self):
        """Dispatch the same call's exact consume originals once; return raw4."""
        from serverware import control_plane_oidc_session_activation_consume_dispatch as consume

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "consume-authorized"
                    or self._consume_dispatch_spent is not False):
                _fail("consume dispatch requires the unspent actual signed continuation")
            self._consume_dispatch_spent = True
            self._dispatch_phase = "consume-dispatching"
            return consume._dispatch_on_permission(self)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def complete_consume(self):
        """Ask once for original completion controls on this exact SQL call."""
        from serverware import control_plane_oidc_session_activation_consume_completion as consume

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "consume-dispatched"
                    or self._consume_completion_spent is not False):
                _fail("consume completion requires the unspent actual SQL continuation")
            self._consume_completion_spent = True
            self._dispatch_phase = "consume-completing"
            return consume._complete_on_permission(self)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def authorize_release_intent(self):
        """Sign and retain one intent on this still-active completed target."""
        from serverware import control_plane_oidc_session_activation_release_intent as release

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "consume-completion-observed"
                    or self._release_intent_spent is not False
                    or self._consume_completion_originals[0] != b"acknowledged"
                    or self._consume_completion_hints is None):
                _fail("release intent requires the unspent actual acknowledged continuation")
            self._release_intent_spent = True
            self._dispatch_phase = "release-intent-signing"
            return release._authorize_on_permission(self)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise


    def prove_release(self):
        """One private proof attempt after this call's retained signed intent."""
        from serverware import control_plane_oidc_session_activation_release_proof as release

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "release-intent-authorized"
                    or self._release_proof_spent is not False):
                _fail("release proof requires the unspent actual intent continuation")
            self._release_proof_spent = True
            self._dispatch_phase = "release-proof-requesting"
            return release._prove_on_permission(self)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise


    def acquire_and_release_token(self, *, _delivery=None):
        """Acquire one fresh grant pair and hand off on this same live call."""
        from serverware import control_plane_oidc_session_activation_release_grant_acquisition as acquisition

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "release-proof-verified"
                    or self._release_handoff_spent is not False):
                _fail("release grant acquisition requires the unspent actual proof continuation")
            # The already-durable proof attempt cannot be reentered after
            # recovery. Spend this shared handoff latch before any issuer I/O.
            self._release_handoff_spent = True
            self._dispatch_phase = "release-handoff-requesting"
            return acquisition._acquire_on_permission(self, _delivery=_delivery)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise

    def release_token(self, *, client_authorization_bytes, server_bootstrap_bytes):
        """One original-bound token handoff on this call's verified proof lane."""
        from serverware import control_plane_oidc_session_activation_release_handoff as release

        try:
            self._identity()
            if (self._state != "active" or self._dispatch_phase != "release-proof-verified"
                    or self._release_handoff_spent is not False):
                _fail("release handoff requires the unspent actual proof continuation")
            # Even rejected or uncertain grants spend this in-memory call.
            # Durable original retention and the existing grant claim are
            # enforced by the continuation before its only socket exchange.
            self._release_handoff_spent = True
            self._dispatch_phase = "release-handoff-requesting"
            return release._release_on_permission(self,
                client_authorization_bytes=client_authorization_bytes,
                server_bootstrap_bytes=server_bootstrap_bytes)
        except BaseException:
            if os.getpid() == self._pid and threading.get_ident() == self._thread:
                self._revoke()
            raise


def _permission_on_owner(owner, *, request, permission_bytes, live_window, transport_deadline_ns, work):
    """Construct only a one-entry live continuation on the actual parent owner."""
    return _ActivationPermission(owner, request, permission_bytes, live_window, transport_deadline_ns, work)
