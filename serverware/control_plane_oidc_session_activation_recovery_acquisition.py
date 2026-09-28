"""Fresh actor-owned recovery originals, not a recovery release permission.

One independently authorized policy slot is durably claimed before issuer
contact. Only genuinely admitted client/server/outcome bytes are retained and
exposed inside this context. No token, assertion or request is journaled.
The acquisition context stages the exact retained server original once; its
ACK establishes neither worker readiness nor protected token delivery. A
separate recovery context performs one protected exchange before yielding.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import threading
import time

from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import authority_oidc_session_activation_release_recovery_delivery_transport as staging
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
    # No arbitrary object traversal, incoming metadata carrier or private key.
    return actor._owned_capture_bytes((scope._original, scope._payload, scope._policy, scope._policy_pin,
            scope._request_pin, scope._target.subject, scope._target.delivery_scope,
            scope._target_pin, scope._binding, scope._binding_pin, scope._credential,
            scope._roles, scope._rbac_pin, scope._session_pin, scope._trust_pin), work)


class _RecoveryAcquisition:
    """Actual active context with byte-only access, never accepted as authority."""

    __slots__ = ("_scope", "_owner", "_parent", "_binding", "_custody", "_config",
        "_config_pin", "_root", "_work", "_pid", "_thread", "_lifetime",
        "_closed", "_originals", "_result", "_selected", "_selected_pin",
        "_stage_spent", "_staged", "_capacity", "_capacity_seal",
        "_scope_seal", "_lifetime_seal", "_exchange_spent", "_exchange_in_progress",
        "_exchange_complete", "_exchange_failed", "_receiving_current", "_receiving_seal",
        "_token", "_token_seal", "_delivery", "_delivery_seal", "_normal_exit")

    def __init__(self, construction, scope):
        if construction is not _CONSTRUCTION or type(scope) is not actor._ActorScope:
            _fail("recovery acquisition requires its actual private construction")
        self._scope, self._owner, self._work = scope, scope._owner, scope._work
        self._scope_seal = scope
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
        self._stage_spent, self._capacity, self._capacity_seal = False, None, None
        self._staged = False
        self._exchange_spent, self._exchange_in_progress = False, False
        self._exchange_complete, self._exchange_failed = False, False
        self._receiving_current, self._receiving_seal = None, None
        self._token, self._token_seal = None, None
        self._delivery, self._delivery_seal = None, None
        self._normal_exit = False
        self._lifetime = production._Lifetime(scope._window, scope._bound,
            self._work, self._ancestor)
        self._lifetime_seal = self._lifetime

    def _ancestor(self, epoch_floor, monotonic_floor):
        scope, owner, config = self._scope, self._owner, self._config
        if (self._closed is not False or self._exchange_failed is not False or _ACTIVE is not self
                or scope is not self._scope_seal or self._lifetime is not self._lifetime_seal
                or self._receiving_current is not self._receiving_seal
                or self._token is not self._token_seal
                or self._delivery is not self._delivery_seal
                or actor._ACTIVE is not scope or scope._active is not True
                or scope._authorized is not True or scope._recovery_acquisition_spent is not True
                or os.getpid() != self._pid or threading.get_ident() != self._thread
                or startup._owner is not owner or owner._material is not self._parent
                or owner._binding is not self._binding or owner._custody is not self._custody
                or self._parent.release_recovery_grant_acquisition is not config
                or self._binding.runtime_root_public_key is not self._root
                or scope._work is not self._work or self._capacity is not self._capacity_seal):
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

    def _parent_current(self):
        """Actual actor/grant ancestors only, never the response's child guard."""
        return self._lifetime.current()

    def _parent_continuity(self, epoch, monotonic):
        lifetime = self._lifetime
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        self._parent_current()
        return lifetime.epoch, lifetime.monotonic

    def _invalidate_exchange(self):
        self._normal_exit = False
        self._exchange_failed = True
        self._exchange_complete = False
        self._token, self._token_seal = None, None
        self._receiving_current, self._receiving_seal = None, None

    def current(self):
        try:
            epoch = self._parent_current()
            guard = self._receiving_current
            if guard is not None:
                observed = guard()
                if (type(observed) is not int or observed < epoch
                        or observed >= self._lifetime.window[3]):
                    _fail("recovery retained response clock reversed or expired")
                self._lifetime.epoch = observed
                epoch = self._parent_current()
            return epoch
        except BaseException:
            self._invalidate_exchange()
            raise

    def _retain_receiving_current(self, current, window, bound):
        """Keep only the genuine receiver's final guard during this exchange."""
        self._parent_current()
        if (self._exchange_spent is not True or self._exchange_in_progress is not True
                or self._exchange_complete is not False or self._receiving_current is not None
                or not callable(current)):
            _fail("recovery response guard requires the one active exchange")
        # This lifetime contains ancestors only: adopting the receiver's
        # narrower bounds cannot call that same receiver back through itself.
        self._lifetime.adopt(window, bound)
        self._receiving_current, self._receiving_seal = current, current
        self._parent_current()

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

    def stage_release_worker(self):
        """Stage only this context's durable server bytes once; return no proof."""
        self.current()
        originals = self.originals
        if self._stage_spent is not False:
            _fail("recovery worker staging cannot be repeated or resumed")
        self._stage_spent = True
        capacity = self._capacity
        if (type(capacity) is not tuple or len(capacity) != 2
                or type(capacity[0]) is not int or capacity[1] is not originals
                or not 0 <= capacity[0] < MAX_ORIGINAL_BYTES):
            _fail("recovery staging lost its original retained-capacity reservation")
        work, lifetime, result = self._work, self._lifetime, self._result
        # Reserve the already-held graphs/triple plus staging hash/chunk copies,
        # exact framing and every ACK buffer before hashing or socket contact.
        staging_bytes = (2 * len(originals[1]) + 4096 + len(staging.PURPOSE)
            + 4 * staging.REQUEST_HEADER_BYTES + 3 * staging.RESPONSE_HEADER_BYTES
            + 3 * staging.MAX_RESPONSE_BYTES + 2 * 71)
        if capacity[0] + staging_bytes > MAX_ORIGINAL_BYTES:
            _fail("recovery staging exceeds the same held-original aggregate")
        if result.client_material.server_material.profile != staging.server.RECOVERY_PROFILE:
            _fail("recovery staging requires the actual admitted recovery server")
        timeout = result.issuer_policy_material.release_launch["requestTimeoutSeconds"]
        endpoint = staging._endpoint((staging.LISTENER_PATH, timeout,
            staging.EXPECTED_PEER_UID, staging.EXPECTED_PEER_GID))
        self.current()
        identity = staging._bootstrap_identity_on_work(originals[1],
            deadline_ns=lifetime.bound, work=work, current=self.current)
        response = staging._socket_request_on_work(endpoint,
            originals=(staging.PURPOSE, originals[1]), deadline_ns=lifetime.bound,
            work=work, current=self.current)
        acknowledgment = staging._originals(response, response=True)
        work.charge(input_bytes=2 * len(identity))
        if acknowledgment[1] != identity:
            _fail("recovery staging ACK differs from this context's exact retained original")
        self.current()
        self._staged = True
        # Deliberately no readiness flag, permission carrier or ACK result.
        return None

    def exchange_token(self, *, _delivery=None):
        """One private protected exchange; expose no token in the method result."""
        from serverware import control_plane_oidc_session_activation_recovery_exchange as exchange

        self.current()
        if (self._staged is not True or self._stage_spent is not True
                or self._exchange_spent is not False or self._exchange_in_progress is not False
                or self._delivery is not None or self._delivery_seal is not None):
            self._invalidate_exchange()
            _fail("recovery exchange requires one successfully staged, unspent context")
        if _delivery is not None:
            from serverware import control_plane_oidc_session_activation_recovery_delivery as delivery

            if type(_delivery) is not delivery._StagedRecoveryResponse or _delivery._active is not self:
                self._invalidate_exchange()
                _fail("recovery exchange terminal differs from its actual source-owned context")
            # Select the exact source-owned terminal before any exchange
            # derivation. Plain private callers keep the original None path.
            self._delivery, self._delivery_seal = _delivery, _delivery
        self._exchange_spent = True
        self._exchange_in_progress = True
        try:
            token = exchange._exchange_on_active(self, _delivery=_delivery)
            if (type(token) is not bytes or len(token) != 64
                    or self._receiving_current is None
                    or self._receiving_current is not self._receiving_seal):
                _fail("recovery exchange lacks its genuine token and final receiving guard")
            self.current()
            self._token, self._token_seal = token, token
            self._exchange_complete = True
            self.current()
        except BaseException:
            self._invalidate_exchange()
            raise
        finally:
            self._exchange_in_progress = False
        return None

    @property
    def token_bytes(self):
        self.current()
        token = self._token
        if (self._exchange_complete is not True or self._exchange_spent is not True
                or self._exchange_in_progress is not False or self._receiving_current is None
                or type(token) is not bytes or len(token) != 64 or token is not self._token_seal):
            _fail("recovery token is unavailable outside its completed active exchange")
        self.current()
        return token

    def _close(self):
        global _ACTIVE

        self._closed = True
        self._invalidate_exchange()
        self._exchange_in_progress = False
        self._originals, self._result, self._selected, self._selected_pin = None, None, None, None
        self._lifetime.guards.clear()
        self._scope = None
        self._scope_seal, self._lifetime_seal = None, None
        self._capacity, self._capacity_seal = None, None
        # Keep only the exact terminal association for its normal-exit proof.
        # This does not retain the revoked live scope, token or receiving guard.
        if _ACTIVE is self:
            _ACTIVE = None


def _acquire(active):
    scope, work, config, lifetime = active._scope, active._work, active._config, active._lifetime
    active.current()
    # Historical admission preflights its own selected inventory before body
    # reads. This later phase reserves the actor result and its new originals.
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
    # Preserve the finite client's actual input/capture reservation for later
    # same-context staging. This is the same fixed .204 reservation, not a new
    # allowance after the response arrives or an incoming capacity quote.
    client_held = (held + 16 * len(config.release_custody_bytes)
        + 8 * client.receiving._unique_bytes((*request, config.issuer_policy_bytes,
            config.proof_enrollment_bytes, config.intent_enrollment_bytes))
        + 4096 + 4 * client.transport.REQUEST_HEADER_BYTES
        + 4 * client.transport.RESPONSE_HEADER_BYTES + len(client.transport.PURPOSE))
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
    capacity = (client_held + 8 * sum(map(len, response)), response)
    if capacity[0] >= MAX_ORIGINAL_BYTES:
        _fail("recovery admitted originals leave no bounded staging capacity")
    active._capacity, active._capacity_seal = capacity, capacity


@contextmanager
def _acquire_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Authorize, durably acquire and stage once; expose no ready permission."""
    global _ACTIVE

    if type(owner) is not startup._EnrollmentOwner or _ACTIVE is not None:
        _fail("recovery acquisition requires the non-overlapping actual owner")
    active = None
    completed = False
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
            active.stage_release_worker()
            active.current()
            yield active
            active.current()
            completed = True
        finally:
            active._close()
    # Both contexts have now exited normally, including the actor's trust and
    # startup locks. Any failure before here leaves this marker False.
    if (active is None or completed is not True or scope._normal_exit is not True
            or active._closed is not True):
        _fail("recovery acquisition lacks its normal original cleanup")
    active._normal_exit = True


@contextmanager
def _recover_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Yield the actual live context only after one genuinely verified exchange."""
    with _acquire_on_owner(owner, request=request, recovery_bytes=recovery_bytes,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns,
            work=work, current=current) as active:
        active.exchange_token()
        active.current()
        yield active
        active.current()
