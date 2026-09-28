"""Fresh actor-owned recovery originals, not a recovery release permission.

One independently authorized policy slot is durably claimed before issuer
contact. Only genuinely admitted client/server/outcome bytes are retained and
exposed inside this context. No token, assertion or request is journaled.
"""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
import threading
import time

from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import control_plane_enrollment_bootstrap as parent_bootstrap
from serverware import control_plane_oidc_session_activation_consume_records as consume
from serverware import control_plane_oidc_session_activation_recovery_actor as actor
from serverware import control_plane_oidc_session_activation_recovery_records as records
from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition as client
from serverware import control_plane_oidc_session_activation_release_recovery_grant_acquisition_bootstrap as configured


execution, startup = actor.execution, actor.startup
custody, issuer, production = execution.custody, client.issuer, client.production
MAX_ORIGINAL_BYTES = client.MAX_ORIGINAL_BYTES
_CONSTRUCTION = object()
_ACTIVE = None
_SELECTED_RESERVATION = 3 * (consume.activation.MAX_RECORD_BYTES + consume.MAX_CLAIM_BYTES
    + consume.MAX_RELEASE_INTENT_BYTES + consume.MAX_RELEASE_PROOF_BYTES
    + consume.MAX_COMPLETION_HINTS_BYTES)


def _fail(message):
    execution._fail(message)


def _actor_bytes(scope, work):
    """Measure only the fixed owned actor graph table, without serializing it."""
    total, nodes = 0, 0

    def visit(value, depth=0):
        nonlocal total, nodes
        nodes += 1
        if depth > 12 or nodes > 8192:
            _fail("recovery actor held graphs exceed their acquisition bound")
        work.charge(json_nodes=1)
        if value is None or type(value) is bool:
            size = 5
        elif type(value) is int:
            if not -(1 << 63) <= value < (1 << 64):
                _fail("recovery actor held integer exceeds its source bound")
            size = 32
        elif type(value) is float and math.isfinite(value):
            size = 32
        elif type(value) is str:
            size = 4 * len(value)
        elif type(value) is bytes:
            size = len(value)
        elif type(value) in (tuple, list, frozenset, dict):
            if len(value) > 8192:
                _fail("recovery actor held collection exceeds its source bound")
            size = 2 + 16 * len(value)
        else:
            _fail("recovery actor held graph has an unexpected source type")
        total += size
        if total > MAX_ORIGINAL_BYTES // 4:
            _fail("recovery actor held graphs exhaust acquisition capacity")
        work.charge(input_bytes=size)
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    _fail("recovery actor held graph keys differ")
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif type(value) in (tuple, list, frozenset):
            for item in value:
                visit(item, depth + 1)

    # No arbitrary object traversal, incoming metadata carrier or private key.
    for graph in (scope._original, scope._payload, scope._policy, scope._policy_pin,
            scope._request_pin, scope._target.subject, scope._target.delivery_scope,
            scope._target_pin, scope._binding, scope._binding_pin, scope._credential,
            scope._roles, scope._rbac_pin, scope._session_pin, scope._trust_pin):
        visit(graph)
    return total


class _RecoveryAcquisition:
    """Actual active context with byte-only access, never accepted as authority."""

    __slots__ = ("_scope", "_owner", "_parent", "_binding", "_custody", "_config",
        "_config_pin", "_root", "_work", "_pid", "_thread", "_lifetime",
        "_closed", "_originals", "_result", "_selected", "_selected_pin")

    def __init__(self, construction, scope):
        if construction is not _CONSTRUCTION or type(scope) is not actor._ActorScope:
            _fail("recovery acquisition requires its actual private construction")
        self._scope, self._owner, self._work = scope, scope._owner, scope._work
        self._parent, self._binding, self._custody = (
            self._owner._material, self._owner._binding, self._owner._custody)
        self._config = self._parent.release_recovery_grant_acquisition
        if type(self._config) is not configured._RecoveryGrantAcquisitionMaterial:
            _fail("recovery acquisition has no independent configured issuer originals")
        self._config_pin = (self._config.endpoint, self._config.issuer_policy_bytes,
            self._config.release_custody_bytes, self._config.proof_enrollment_bytes,
            self._config.intent_enrollment_bytes)
        self._root = self._binding.runtime_root_public_key
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._closed, self._originals, self._result = False, None, None
        self._selected, self._selected_pin = None, None
        self._lifetime = production._Lifetime(scope._window, scope._bound,
            self._work, self._ancestor)

    def _ancestor(self, epoch_floor, monotonic_floor):
        scope, owner, config = self._scope, self._owner, self._config
        if (self._closed is not False or _ACTIVE is not self
                or actor._ACTIVE is not scope or scope._active is not True
                or scope._authorized is not True or scope._recovery_acquisition_spent is not True
                or os.getpid() != self._pid or threading.get_ident() != self._thread
                or startup._owner is not owner or owner._material is not self._parent
                or owner._binding is not self._binding or owner._custody is not self._custody
                or self._parent.release_recovery_grant_acquisition is not config
                or self._binding.runtime_root_public_key is not self._root
                or scope._work is not self._work):
            _fail("recovery acquisition original actor or cold owner changed")
        actual = (config.endpoint, config.issuer_policy_bytes, config.release_custody_bytes,
            config.proof_enrollment_bytes, config.intent_enrollment_bytes)
        if any(value is not held for value, held in zip(actual, self._config_pin)):
            _fail("recovery acquisition independent original configuration changed")
        if self._selected is not None:
            for record, pin in zip(self._selected[1:], self._selected_pin):
                if (record.kind, record.digest) != pin[:2] or record.originals is not pin[2]:
                    _fail("recovery acquisition selected original identity changed")
        epoch = scope.current()
        monotonic = execution.production._callback(self._work, time.monotonic_ns)
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < epoch_floor or monotonic < monotonic_floor):
            _fail("recovery acquisition original clock floors reversed")
        lifetime = self._lifetime
        window = (*lifetime.window[:3], *(min(a, b)
            for a, b in zip(lifetime.window[3:], scope._window[3:])))
        # adopt() calls current(), so it must never be invoked from this
        # lifetime's own ancestor callback. These fixed minima preserve the
        # opening and only narrow; the outer _owner/_floors checks the sample.
        lifetime.window = issuer.clock._validate(window)
        lifetime.bound = min(lifetime.bound, scope._bound, window[4])
        return epoch, monotonic

    def current(self):
        return self._lifetime.current()

    @property
    def originals(self):
        self.current()
        result = self._result
        if self._originals is None or type(result) is not client.receiving._RecoveryGrantMaterial:
            _fail("recovery acquired originals are not durably available")
        if any(raw is not held for raw, held in zip((result.client_authorization_bytes,
                result.server_bootstrap_bytes, result.outcome_bytes), self._originals)):
            _fail("recovery admitted originals changed after retention")
        self.current()
        return self._originals

    def _close(self):
        global _ACTIVE

        self._closed = True
        self._originals, self._result, self._selected, self._selected_pin = None, None, None, None
        self._lifetime.guards.clear()
        self._scope = None
        if _ACTIVE is self:
            _ACTIVE = None


def _acquire(active):
    scope, work, config, lifetime = active._scope, active._work, active._config, active._lifetime
    active.current()
    # This begins AFTER the existing actor/history admission. It does not fix
    # the earlier finalization loader's separate preallocation gap.
    held = 8 * parent_bootstrap.MAX_BYTES + 4 * _actor_bytes(scope, work)
    held += 8 * len(scope._target.intent_bytes) + 8 * startup.MAX_PRIVATE_KEY_BYTES
    if (MAX_ORIGINAL_BYTES != 64 * 1024 * 1024
            or held + _SELECTED_RESERVATION > MAX_ORIGINAL_BYTES):
        _fail("recovery held parent and actor leave no bounded selector capacity")
    target = scope._target
    local = target.subject["localDigest"]
    # This call meters actual metadata sizes directly before reads. The guard
    # checks existing actor/resources, never recursively selects journal data.
    selected = custody.ControlPlaneCustodyClient.load_oidc_session_activation_recovery_inputs(
        active._custody, local, work=work, current=active.current)
    active.current()
    if selected is None:
        _fail("recovery proof or encrypted envelope is unavailable")
    if (type(selected) is not tuple or len(selected) != 5
            or type(selected[0]) is not consume.activation.ActivationDispatchAttemptRecord
            or any(type(record) is not consume.ConsumeRecord for record in selected[1:])):
        _fail("recovery selected original inventory differs")
    activation, claim, intent, proof, descriptor = selected
    if (activation.finalization_digest != local or claim.kind != "claimed" or claim.originals != ()
            or (intent.kind, proof.kind, descriptor.kind) != ("release-intent", "release-proof", "completion-hints")
            or tuple(map(len, (intent.originals, proof.originals, descriptor.originals))) != (1, 4, 2)
            or any(record.finalization_digest != local
                or record.activation_authorization_digest != target.activation_authorization_digest
                or record.slot_digest != claim.slot_digest for record in selected[1:])):
        _fail("recovery inputs do not match the freshly authorized target")
    active._selected = selected
    active._selected_pin = tuple((record.kind, record.digest, record.originals) for record in selected[1:])
    raw_inputs = (*intent.originals, *proof.originals, *descriptor.originals)
    held += 3 * client.receiving._unique_bytes(raw_inputs) + 8192
    production.shared._same_bytes(intent.originals[0], target.intent_bytes, work,
        "recovery freshly admitted target intent")
    if proof.originals[0] != b"proved":
        _fail("recovery has no bounded proof response; status is not proof authority")
    production.shared._same_bytes(proof.originals[1], config.release_custody_bytes, work,
        "recovery independently configured custody original")
    production.shared._same_bytes(proof.originals[3], config.proof_enrollment_bytes, work,
        "recovery independently configured proof enrollment")
    policy_reservation = (8 * len(config.release_custody_bytes)
        + 4 * sum(map(len, (config.issuer_policy_bytes, config.proof_enrollment_bytes,
            config.intent_enrollment_bytes))))
    held += policy_reservation + 8 * hints.MAX_DESCRIPTOR_BYTES
    if held >= MAX_ORIGINAL_BYTES:
        _fail("recovery selected originals leave no policy admission capacity")
    active.current()
    _packet, _effects, envelope, _created, _expires = hints._decode_on_work(descriptor.originals, work=work)
    request = production._request_originals((production.transport.RECOVERY_PURPOSE,
        proof.originals[2], config.proof_enrollment_bytes, intent.originals[0],
        config.intent_enrollment_bytes, scope._old_token, envelope))
    policy = issuer._verify_on_work(policy_bytes=config.issuer_policy_bytes,
        release_custody_bytes=config.release_custody_bytes,
        proof_enrollment_bytes=config.proof_enrollment_bytes, intent_enrollment_bytes=config.intent_enrollment_bytes,
        root_public_key=active._root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
        work=work, _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("recovery attempt requires genuine independent root policy admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    issuer.plan._same(policy.payload["expectedRelease"]["deliveryScope"], target.delivery_scope,
        work, "recovery policy matches the freshly authenticated actor target")
    issuer.plan._same(policy.payload["expectedEvidence"]["releaseIntentDigest"], target.intent_digest,
        work, "recovery policy matches the exact retained intent")
    identifiers = dict(finalization_digest=local,
        activation_authorization_digest=target.activation_authorization_digest,
        release_intent_digest=target.intent_digest, issuer_policy_digest=policy.policy_digest)
    work.charge(input_bytes=records.MAX_CLAIM_IO_BYTES, hashes=16)
    active.current()
    slot = execution.production._callback(work, lambda:
        custody.ControlPlaneCustodyClient.claim_oidc_session_activation_recovery_grant_attempt(
            active._custody, **identifiers))
    custody.journal._digest(slot)
    active.current()
    admitted = client._acquire_on_work(request_originals=request,
        issuer_policy_bytes=config.issuer_policy_bytes, release_custody_bytes=config.release_custody_bytes,
        proof_enrollment_bytes=config.proof_enrollment_bytes, intent_enrollment_bytes=config.intent_enrollment_bytes,
        root_public_key=active._root, endpoint=config.endpoint, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity,
        _additional_original_bytes=held)
    # No request/old-token field escapes in the original-admission result.
    del request, envelope
    if type(admitted) is not client.receiving._RecoveryGrantMaterial:
        _fail("recovery acquisition requires the genuine triple-original result")
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    response = client.receiving._originals((admitted.client_authorization_bytes,
        admitted.server_bootstrap_bytes, admitted.outcome_bytes))
    # The client reserved eight reply footprints before its read. Its completed
    # wire buffers are gone; retain that same conservative allowance for codec
    # construction, exact durable publication and readback, never a larger cap.
    if held + 8 * sum(map(len, response)) > MAX_ORIGINAL_BYTES:
        _fail("recovery durable response exceeds its existing held capacity")
    work.charge(input_bytes=records._append_io_bytes(response), hashes=16)
    active.current()
    digest = execution.production._callback(work, lambda:
        custody.ControlPlaneCustodyClient.append_oidc_session_activation_recovery_grants(
            active._custody, **identifiers, originals=response))
    custody.journal._digest(digest)
    active.current()
    active._result, active._originals = admitted, response


@contextmanager
def _acquire_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Authorize one fresh actor; expose only same-context retained originals."""
    global _ACTIVE

    if type(owner) is not startup._EnrollmentOwner or _ACTIVE is not None:
        _fail("recovery acquisition requires the non-overlapping actual owner")
    with actor._authorize_on_owner(owner, request=request, recovery_bytes=recovery_bytes,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns,
            work=work, current=current) as scope:
        if (type(scope) is not actor._ActorScope or actor._ACTIVE is not scope
                or scope._authorized is not True or scope._recovery_acquisition_spent is not False):
            _fail("recovery acquisition requires one unspent actual authorized actor")
        scope._recovery_acquisition_spent = True
        active = _RecoveryAcquisition(_CONSTRUCTION, scope)
        _ACTIVE = active
        try:
            _acquire(active)
            active.current()
            yield active
            active.current()
        finally:
            active._close()
