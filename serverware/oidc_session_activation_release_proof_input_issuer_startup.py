"""One original-bound proof-input issue, private packet read and exact staging.

Eight inherited resources belong to one permanently dropped PID. Only the
actual fixed recovery reader owns transient database descriptors; the full
inventory is checked on either side of that read. No packet, key or success
carrier enters from the public request, and no failed exchange can repeat.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import socket
import threading
from types import MethodType

from serverware import authority_successor_execution_owner as packets
from serverware import authority_oidc_session_activation_release_proof_input_transport as transport
from serverware import authority_oidc_session_activation_release_proof_input_delivery_transport as staging
from serverware import authority_oidc_session_activation_release_grant_input_delivery_transport as grant_staging
from serverware import oidc_session_activation_release_proof_input_issuer_bootstrap as bootstrap
from serverware import oidc_session_activation_release_proof_input_issuer_entrypoint as delivery
from serverware import oidc_session_activation_release_proof_input_production as producer


capture, clock, production = bootstrap.capture, bootstrap.clock, bootstrap.production
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner = "new", None
_owned, _cleanup_failed, _listener_object = {}, False, None
_quarantined = []
_WIRE_RESERVATION = (transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
    + staging.REQUEST_HEADER_BYTES + staging.RESPONSE_HEADER_BYTES
    + len(staging.PURPOSE) + staging.MAX_RESPONSE_BYTES)
_GRANT_WIRE_RESERVATION = (grant_staging.REQUEST_HEADER_BYTES + grant_staging.RESPONSE_HEADER_BYTES
    + len(grant_staging.PURPOSE) + grant_staging.MAX_RESPONSE_BYTES)


class ReleaseProofInputIssuerStartupError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseProofInputIssuerStartupError(message)


def _pid():
    if os.getpid() != _PID:
        _fail("proof input issuer cannot continue in a different PID")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    _pid()
    if (_environment() != namespace or namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (bootstrap.SERVICE_UID,) * 3
            or os.getresgid() != (bootstrap.SERVICE_GID,) * 3 or os.getgroups()):
        _fail("proof input issuer process or closed environment changed")
    delivery._require_unprivileged_process()


def _fd_identity(descriptor):
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_rdev


def _cleanup_inherited():
    global _cleanup_failed, _listener_object
    _pid()
    for descriptor, identity in tuple(_owned.items()):
        del _owned[descriptor]
        try:
            if _fd_identity(descriptor) != identity:
                _fail("proof issuer cannot close a replacement inherited descriptor")
            if descriptor == delivery.LISTENER_FD and _listener_object is not None:
                if _listener_object.fileno() != descriptor:
                    _fail("proof issuer lost its actual listener owner")
                _listener_object.close()
                if _listener_object.fileno() != -1:
                    _fail("proof issuer listener closure is indeterminate")
                _listener_object = None
            else:
                os.close(descriptor)
        except BaseException:
            _cleanup_failed = True
    if _cleanup_failed:
        _fail("proof input issuer inherited cleanup is not established")


@dataclass(slots=True, repr=False, eq=False)
class _SocketSlot:
    connection: object = None
    identity: tuple | None = None
    peer: tuple | None = None
    close_attempted: bool = False


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    material: object
    root: object
    key: object
    work: object
    limits: object
    ceilings: tuple
    lifetime: object
    guards: tuple
    window: tuple
    deadline_ns: int
    namespace: tuple
    sealed: tuple
    listener: object
    listener_pins: tuple
    tls: tuple
    reader: object
    reader_configuration: tuple
    packet_scope: tuple
    delivery_current: object
    delivery_retained_bytes: int
    input_bytes: int
    maximum_request_bytes: int
    delivery_endpoint: tuple
    grant_delivery_endpoint: tuple | None
    wire_reservation: int


class _DeliveryChannel:
    """One source-owned outgoing socket; never an arbitrary descriptor list."""

    __slots__ = ("_owner", "_opened", "_closed")

    def __init__(self):
        _fail("proof staging requires the actual issuer-owned channel")

    def _identity(self):
        owner = self._owner
        if (type(self) is not _DeliveryChannel or type(owner) is not _IssuerOwner
                or owner is not _owner or owner._delivery_channel is not self
                or not owner._delivery_spent or self._closed):
            _fail("proof staging changed its actual issuer channel")
        return owner

    def check(self, *, endpoint, deadline_ns, work, current):
        owner = self._identity()
        if (type(endpoint) is not tuple or endpoint != owner._configured.delivery_endpoint
                or work is not owner._configured.work or type(deadline_ns) is not int
                or not 0 < deadline_ns <= owner._configured.lifetime.bound
                or type(current) is not MethodType or current.__self__ is not owner
                or current.__func__ is not _IssuerOwner._current):
            _fail("proof staging changed its endpoint or original allowance")
        owner._current()

    def open(self):
        owner = self._identity()
        slot, work = owner._sockets[1], owner._configured.work
        if self._opened or slot.connection is not None or slot.close_attempted:
            _fail("proof staging socket cannot be reopened")
        self._opened = True
        owner._current()
        work.charge(input_bytes=4096)

        def opening():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            slot.connection = connection
            descriptor = connection.fileno()
            slot.identity = connection, descriptor, _fd_identity(descriptor)
            connection.setblocking(False)
            connection.set_inheritable(False)

        production._callback(work, opening)
        owner._current()
        return slot.connection

    def connected(self):
        owner = self._identity()
        slot, work = owner._sockets[1], owner._configured.work
        if not self._opened or slot.connection is None or slot.peer is not None:
            _fail("proof staging cannot replace its connected peer")
        owner._current()
        work.charge(input_bytes=12)
        peer = production._callback(work, lambda: transport.authority_transport._peer_identity(slot.connection))
        if peer[:2] != (0, 0):
            _fail("proof staging receiver is not the actual root peer")
        slot.peer = peer
        owner._current()

    def close(self):
        owner = self._identity()
        owner._close_socket(1, guarded=True)
        self._closed = True


class _GrantDeliveryChannel:
    """The v2 owner's distinct second destination, never a caller-selected FD."""

    __slots__ = ("_owner", "_opened", "_closed")

    def __init__(self):
        _fail("grant staging requires the actual proof-input issuer channel")

    def _identity(self):
        owner = self._owner
        if (type(self) is not _GrantDeliveryChannel or type(owner) is not _IssuerOwner
                or owner is not _owner or owner._grant_delivery_channel is not self
                or not owner._grant_delivery_spent or self._closed
                or owner._configured.grant_delivery_endpoint is None
                or type(owner._delivery_channel) is not _DeliveryChannel
                or not owner._delivery_channel._closed or owner._sockets[1].connection is not None):
            _fail("grant staging changed its actual issuer channel or predecessor")
        return owner

    def check(self, *, endpoint, deadline_ns, work, current):
        owner = self._identity()
        if (type(endpoint) is not tuple or endpoint != owner._configured.grant_delivery_endpoint
                or work is not owner._configured.work or type(deadline_ns) is not int
                or not 0 < deadline_ns <= owner._configured.lifetime.bound
                or type(current) is not MethodType or current.__self__ is not owner
                or current.__func__ is not _IssuerOwner._current):
            _fail("grant staging changed its endpoint or original allowance")
        owner._current()

    def open(self):
        owner = self._identity()
        slot, work = owner._sockets[2], owner._configured.work
        if self._opened or slot.connection is not None or slot.close_attempted:
            _fail("grant staging socket cannot be reopened")
        self._opened = True
        owner._current()
        work.charge(input_bytes=4096)

        def opening():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            slot.connection = connection
            descriptor = connection.fileno()
            slot.identity = connection, descriptor, _fd_identity(descriptor)
            connection.setblocking(False)
            connection.set_inheritable(False)

        production._callback(work, opening)
        owner._current()
        return slot.connection

    def connected(self):
        owner = self._identity()
        slot, work = owner._sockets[2], owner._configured.work
        if not self._opened or slot.connection is None or slot.peer is not None:
            _fail("grant staging cannot replace its connected peer")
        owner._current()
        work.charge(input_bytes=12)
        peer = production._callback(work, lambda: transport.authority_transport._peer_identity(slot.connection))
        if peer[:2] != (0, 0):
            _fail("grant staging receiver is not the actual root peer")
        slot.peer = peer
        owner._current()

    def close(self):
        owner = self._identity()
        owner._close_socket(2, guarded=True)
        self._closed = True


class _IssuerOwner:
    __slots__ = ("_configured", "_seal", "_window_seal", "_bound_seal", "_spent",
        "_failed", "_closed", "_sockets", "_socket_seals", "_packet_spent",
        "_delivery_channel", "_delivery_spent", "_grant_delivery_channel", "_grant_delivery_spent",
        "_response_material", "_response_seal")

    def __init__(self):
        _fail("proof input issuer requires genuine original cold construction")

    def _resource_identity(self):
        _pid()
        configured = self._configured
        if (type(self) is not _IssuerOwner or self is not _owner or _state != "started"
                or self._failed or self._closed or configured is not self._seal
                or type(configured) is not _Configuration or self._sockets is not self._socket_seals
                or len(self._sockets) != (2 if configured.grant_delivery_endpoint is None else 3)
                or any(type(slot) is not _SocketSlot for slot in self._sockets)
                or self._response_material is not self._response_seal):
            _fail("proof input issuer owner changed")
        lifetime, material = configured.lifetime, configured.material
        if (type(lifetime) is not producer._Lifetime or lifetime.work is not configured.work
                or lifetime.limits is not configured.limits or lifetime.ceilings != configured.ceilings
                or lifetime.continuation is not None or tuple(lifetime.guards) != configured.guards
                or lifetime.window is not self._window_seal or lifetime.bound != self._bound_seal
                or lifetime.window[:3] != configured.window[:3]
                or any(new > old for new, old in zip(lifetime.window[3:], configured.window[3:]))
                or lifetime.bound > min(configured.deadline_ns, lifetime.window[4])
                or material.delivery_endpoint is not configured.delivery_endpoint
                or material.grant_delivery_endpoint is not configured.grant_delivery_endpoint
                or (configured.grant_delivery_endpoint is None
                    and (self._grant_delivery_channel is not None or self._grant_delivery_spent))):
            _fail("proof input issuer changed its original lifetime or staging endpoint")
        _process(configured.namespace)
        for descriptor, maximum, private, identity in configured.sealed:
            if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                _fail("proof issuer inherited original changed")
        if (configured.listener is not _listener_object
                or configured.listener.fileno() != delivery.LISTENER_FD
                or delivery._listener(delivery.LISTENER_FD) != configured.listener_pins
                or packets.SuccessorExecutionRecoveryReader._snapshot_configuration(configured.reader)
                    is not configured.reader_configuration):
            _fail("proof issuer listener or actual private reader changed")
        completion, packet_digest, pending, reader_configuration = configured.packet_scope
        if (material.policy_material.completion_material is not completion
                or completion.packet_digest != packet_digest or completion.current_pending is not pending
                or completion.custody_configuration is not reader_configuration):
            _fail("proof issuer independent packet selectors changed")
        delivery._tls_unchanged(configured.tls)
        for index, slot in enumerate(self._sockets):
            if slot.connection is None:
                if slot.identity is not None or slot.peer is not None:
                    _fail("proof issuer lost an owned socket")
                continue
            if slot.identity is None or slot.close_attempted:
                _fail("proof issuer socket ownership is incomplete or closing")
            connection, descriptor, identity = slot.identity
            if (slot.connection is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity or connection.family != socket.AF_UNIX
                    or connection.type != socket.SOCK_STREAM or connection.gettimeout() != 0.0
                    or connection.get_inheritable()):
                _fail("proof issuer owned socket changed")
            if index == 0 and slot.peer is None:
                _fail("proof issuer request peer is not established")
            if index == 1:
                channel = self._delivery_channel
                if (type(channel) is not _DeliveryChannel or channel._owner is not self
                        or not channel._opened or channel._closed or not self._delivery_spent):
                    _fail("proof issuer staging socket lacks its actual owned channel")
            if index == 2:
                channel = self._grant_delivery_channel
                if (type(channel) is not _GrantDeliveryChannel or channel._owner is not self
                        or not channel._opened or channel._closed or not self._grant_delivery_spent
                        or type(self._delivery_channel) is not _DeliveryChannel
                        or not self._delivery_channel._closed or self._sockets[1].connection is not None):
                    _fail("proof issuer grant staging lacks its actual channel or closed predecessor")
            if slot.peer is not None:
                expected = (65532, 65532) if index == 0 else (0, 0)
                if (slot.peer[:2] != expected
                        or transport.authority_transport._peer_identity(connection) != slot.peer):
                    _fail("proof issuer owned peer changed")

    def _base_current(self):
        """Original resource/lifetime guard, also safe inside child admission."""
        configured = self._configured
        try:
            capture._SharedLedger(configured.work)
            configured.work.charge(input_bytes=4096)
            production._callback(configured.work, self._resource_identity)
            if delivery._retained_bytes_on_work(configured.delivery_current, configured.work) != configured.delivery_retained_bytes:
                _fail("proof issuer replaced its actual delivered originals")
            return configured.lifetime.current()
        except BaseException:
            self._failed = True
            raise

    def _resource_current(self):
        """Only the actual reader receives this non-enumerating resource guard."""
        epoch = self._base_current()
        if self._response_material is not None:
            observed = self._response_material.live()
            epoch = self._base_current()
            if observed > epoch:
                _fail("proof issuer output admission reversed its original clock")
        return epoch

    def _current(self):
        try:
            self._resource_current()
            configured = self._configured
            inventory = delivery.INHERITED_DESCRIPTORS + tuple(
                slot.identity[1] for slot in self._sockets if slot.connection is not None)
            configured.work.charge(input_bytes=4096)
            production._callback(configured.work, lambda: delivery._require_inventory(inventory))
            return configured.lifetime.current()
        except BaseException:
            self._failed = True
            raise

    def _continuity(self, epoch, monotonic):
        lifetime = self._configured.lifetime
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        self._current()
        return lifetime.epoch, lifetime.monotonic

    def _close_socket(self, index, *, guarded):
        global _cleanup_failed
        if type(index) is not int or index not in (0, 1, 2) or index >= len(self._sockets):
            _fail("proof issuer cleanup requires an actual source-owned socket slot")
        slot = self._sockets[index]
        if slot.connection is None:
            if guarded:
                self._current()
            return
        if slot.close_attempted:
            _cleanup_failed = True
            _fail("proof issuer cannot retry indeterminate socket cleanup")
        if guarded:
            self._current()
        slot.close_attempted = True
        try:
            if slot.identity is None:
                _fail("proof issuer cleanup lacks the original socket identity")
            connection, descriptor, identity = slot.identity
            if (slot.connection is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity):
                _fail("proof issuer will not close a replacement socket")
            if guarded:
                self._configured.work.charge(input_bytes=1)
                production._callback(self._configured.work, connection.close)
            else:
                connection.close()
            if connection.fileno() != -1:
                _fail("proof issuer socket closure is indeterminate")
        except BaseException:
            _cleanup_failed = True
            _quarantined.append(slot.connection)
            raise
        slot.connection = slot.identity = slot.peer = None
        if guarded:
            self._current()

    def _produce(self, originals):
        configured, work = self._configured, self._configured.work
        material, lifetime = configured.material, configured.lifetime
        self._current()
        if self._packet_spent or sum(map(len, originals)) > configured.maximum_request_bytes:
            _fail("proof issuer cannot repeat or enlarge its independent packet acquisition")
        self._packet_spent = True
        available = bootstrap.MAX_ORIGINAL_BYTES - configured.input_bytes - configured.wire_reservation
        repeated_cold = bootstrap.issuer._cold_reservation_bytes(len(material.issuer_policy_bytes),
            len(material.completion_bootstrap_bytes), len(material.proof_enrollment_bytes),
            len(material.intent_enrollment_bytes))
        maximum_packet = min(packets.packet.MAX_BYTES,
            (available - repeated_cold - 8 * sum(map(len, originals))) // 8)
        if maximum_packet < 2:
            _fail("proof issuer has no bounded packet-read capacity")
        completion, packet_digest, pending, _reader_configuration = configured.packet_scope
        # No caller selectors or FD exemptions enter this exact typed reader.
        # Its own source owns DB descriptors; full inventory brackets the read.
        packet = packets.SuccessorExecutionRecoveryReader.read(configured.reader,
            pending_decision_digest=pending[1], packet_digest=packet_digest,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _current=self._resource_current, maximum_packet_bytes=maximum_packet)
        self._current()
        if type(packet) is not bytes or not 2 <= len(packet) <= maximum_packet:
            _fail("proof issuer actual packet read exceeded its reservation")
        response = producer._produce_on_work(request_originals=originals[1:], consume_packet_bytes=packet,
            issuer_policy_bytes=material.issuer_policy_bytes,
            completion_bootstrap_bytes=material.completion_bootstrap_bytes,
            proof_enrollment_bytes=material.proof_enrollment_bytes,
            intent_enrollment_bytes=material.intent_enrollment_bytes,
            root_private_key=configured.key, root_public_key=configured.root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=self._continuity, maximum_original_bytes=available)
        self._current()
        response = transport._originals(response, response=True)
        del packet
        if configured.input_bytes + sum(map(len, originals)) + 8 * len(response[0]) + configured.wire_reservation > bootstrap.MAX_ORIGINAL_BYTES:
            _fail("proof issuer output admission exceeds its complete held inventory")
        checked = producer.bootstrap._verify_on_work(bootstrap_bytes=response[0], root_public_key=configured.root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _current=self._base_current)
        if type(checked) is not producer.bootstrap._ProofMaterial:
            _fail("proof issuer output lacks actual root-original admission")
        self._response_material = self._response_seal = checked
        lifetime.adopt(checked.live_window, checked.deadline_ns)
        self._window_seal, self._bound_seal = lifetime.window, lifetime.bound
        self._current()
        return response

    def _stage_response(self, response):
        configured, work = self._configured, self._configured.work
        self._current()
        if self._delivery_spent or self._delivery_channel is not None:
            _fail("proof issuer cannot repeat bootstrap staging")
        self._delivery_spent = True
        if configured.input_bytes + 8 * len(response[0]) + configured.wire_reservation > bootstrap.MAX_ORIGINAL_BYTES:
            _fail("proof issuer staging exceeds the original held inventory")
        lifetime = configured.lifetime
        expected = staging._bootstrap_identity_on_work(response[0], deadline_ns=lifetime.bound,
            work=work, current=self._current)
        channel = object.__new__(_DeliveryChannel)
        channel._owner, channel._opened, channel._closed = self, False, False
        self._delivery_channel = channel
        acknowledged = staging._socket_request_on_work(configured.delivery_endpoint,
            originals=(staging.PURPOSE, response[0]), deadline_ns=lifetime.bound,
            work=work, current=self._current, channel=channel)
        self._current()
        acknowledged = staging._originals(acknowledged, response=True)
        if not channel._closed or self._sockets[1].connection is not None or acknowledged[0] != staging.ACK_STATUS:
            _fail("proof issuer staging and normal close are not established")
        producer._same_bytes(acknowledged[1], expected, work, "proof issuer exact staged bootstrap identity")
        self._current()

    def _stage_grant_response(self, response):
        configured, work = self._configured, self._configured.work
        self._current()
        if (configured.grant_delivery_endpoint is None or self._grant_delivery_spent
                or self._grant_delivery_channel is not None
                or type(self._delivery_channel) is not _DeliveryChannel
                or not self._delivery_channel._closed or self._sockets[1].connection is not None):
            _fail("proof issuer cannot omit, reorder or repeat grant staging")
        self._grant_delivery_spent = True
        if configured.input_bytes + 8 * len(response[0]) + configured.wire_reservation > bootstrap.MAX_ORIGINAL_BYTES:
            _fail("proof issuer grant staging exceeds the original held inventory")
        lifetime = configured.lifetime
        expected = grant_staging._bootstrap_identity_on_work(response[0], deadline_ns=lifetime.bound,
            work=work, current=self._current)
        channel = object.__new__(_GrantDeliveryChannel)
        channel._owner, channel._opened, channel._closed = self, False, False
        self._grant_delivery_channel = channel
        acknowledged = grant_staging._socket_request_on_work(configured.grant_delivery_endpoint,
            originals=(grant_staging.PURPOSE, response[0]), deadline_ns=lifetime.bound,
            work=work, current=self._current, channel=channel)
        self._current()
        acknowledged = grant_staging._originals(acknowledged, response=True)
        if not channel._closed or self._sockets[2].connection is not None or acknowledged[0] != grant_staging.ACK_STATUS:
            _fail("proof issuer grant staging and normal close are not established")
        producer._same_bytes(acknowledged[1], expected, work, "proof issuer exact grant-staged bootstrap identity")
        self._current()

    def serve_once(self):
        """One peer-bound exchange, latched before accept or request bytes."""
        global _state
        with _LOCK:
            self._current()
            if self._spent or self._sockets[0].connection is not None:
                _fail("proof input issuer cannot repeat its exchange")
            self._spent = True
            configured, work = self._configured, self._configured.work
            lifetime, slot = configured.lifetime, self._sockets[0]
            try:
                work.charge(input_bytes=4096)
                self._current()
                remaining = transport.io._check_deadline(lifetime.bound) / 1_000_000_000
                ready, _writers, exceptional = production._callback(work,
                    lambda: select.select((configured.listener,), (), (configured.listener,), remaining))
                self._current()
                if not ready or exceptional:
                    _fail("proof input issuer readiness was not established")

                def accept():
                    connection, _address = configured.listener.accept()
                    slot.connection = connection
                    descriptor = connection.fileno()
                    slot.identity = connection, descriptor, _fd_identity(descriptor)
                    connection.setblocking(False)
                    connection.set_inheritable(False)
                    slot.peer = transport.authority_transport._peer_identity(connection)
                    if slot.peer[:2] != (transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID):
                        _fail("proof issuer peer is not the fixed control-plane caller")

                production._callback(work, accept)
                self._current()
                originals = transport._recv_request(slot.connection, deadline_ns=lifetime.bound,
                    work=work, current=self._current, maximum_request_bytes=configured.maximum_request_bytes)
                response = self._produce(originals)
                del originals
                self._stage_response(response)
                if configured.grant_delivery_endpoint is not None:
                    self._stage_grant_response(response)
                transport._send_response(slot.connection, response, deadline_ns=lifetime.bound,
                    work=work, current=self._current)
                self._close_socket(0, guarded=True)
                self._current()
                _state = "spent"
                return True
            except BaseException:
                self._failed, _state = True, "failed"
                for index in reversed(range(len(self._sockets))):
                    try:
                        self._close_socket(index, guarded=False)
                    except BaseException:
                        pass
                raise ReleaseProofInputIssuerStartupError(
                    "proof input issuance is not established; automatic retry is prohibited") from None

    def close(self):
        if self is not _owner:
            _fail("proof input issuer cleanup requires its actual owner")
        close()


def initialize_from_environment(*, work, live_window, transport_deadline_ns, delivery_current):
    """Continue the actual eight-resource delivery after permanent same-PID drop."""
    global _state, _owner, _listener_object
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware.authority_query_read_work import _ValidationWork

    _pid()
    with _LOCK:
        if _state != "new":
            _fail("proof input issuer startup cannot restart")
        _state = "initializing"
        namespace = _environment()
        try:
            if type(work) is not _ValidationWork:
                _fail("proof input issuer requires actual original validation work")
            capture._SharedLedger(work)
            window = clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            delivered = delivery._retained_bytes_on_work(delivery_current, work,
                live_window=window, transport_deadline_ns=transport_deadline_ns)
            lifetime = producer._Lifetime(window, min(window[4], transport_deadline_ns), work, None)
            lifetime.attach(delivery_current)
            sealed, listener_pins = (), None

            def resource_current():
                work.charge(input_bytes=4096)
                production._callback(work, lambda: _process(namespace))
                for descriptor, maximum, private, identity in sealed:
                    if production._callback(work, lambda: delivery._sealed_identity(
                            descriptor, maximum, private=private)) != identity:
                        _fail("proof issuer construction original changed")
                if listener_pins is not None and production._callback(work,
                        lambda: delivery._listener(delivery.LISTENER_FD)) != listener_pins:
                    _fail("proof issuer construction listener changed")
                if delivery._retained_bytes_on_work(delivery_current, work) != delivered:
                    _fail("proof issuer construction delivery changed")
                return lifetime.base()

            def continuity(epoch, monotonic):
                lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
                resource_current()
                return lifetime.epoch, lifetime.monotonic

            def current():
                resource_current()
                work.charge(input_bytes=4096)
                production._callback(work, lambda: delivery._require_inventory(delivery.INHERITED_DESCRIPTORS))
                return lifetime.current()

            current()
            work.charge(input_bytes=4096)
            for descriptor in delivery.INHERITED_DESCRIPTORS:
                _owned[descriptor] = production._callback(work, lambda: _fd_identity(descriptor))
            descriptions = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False),
                (delivery.POLICY_FD, delivery.MAX_POLICY_BYTES, False),
                (delivery.COMPLETION_BOOTSTRAP_FD, delivery.MAX_COMPLETION_BOOTSTRAP_BYTES, False),
                (delivery.PROOF_ENROLLMENT_FD, delivery.MAX_PROOF_ENROLLMENT_BYTES, False),
                (delivery.INTENT_ENROLLMENT_FD, delivery.MAX_INTENT_ENROLLMENT_BYTES, False),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True))
            sealed = tuple((descriptor, maximum, private, production._callback(work,
                lambda: delivery._sealed_identity(descriptor, maximum, private=private)))
                for descriptor, maximum, private in descriptions)
            sizes = production._callback(work, lambda: tuple(os.fstat(descriptor).st_size
                for descriptor, _maximum, _private in descriptions))
            admission_reservation = (bootstrap.issuer._cold_reservation_bytes(*sizes[2:6])
                + 4 * (sizes[0] + sizes[1] + sizes[6]))
            if delivered + sum(sizes) + admission_reservation + _WIRE_RESERVATION >= bootstrap.MAX_ORIGINAL_BYTES:
                _fail("proof issuer cold originals leave no bounded decoded inventory")
            raws = []
            for descriptor, maximum, _private, identity in sealed[:-1]:
                current()
                raw, observed = delivery._read_on_work(descriptor, maximum, work)
                current()
                if observed != identity:
                    _fail("proof issuer original changed during inherited read")
                raws.append(raw)
            root_raw, launch_raw, policy_raw, completion_raw, proof_raw, intent_raw = raws
            work.charge(input_bytes=len(root_raw))
            root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                _fail("proof input issuer requires the original Ed25519 root")
            current()
            material = bootstrap._verify_on_work(bootstrap_bytes=launch_raw, issuer_policy_bytes=policy_raw,
                completion_bootstrap_bytes=completion_raw, proof_enrollment_bytes=proof_raw,
                intent_enrollment_bytes=intent_raw, root_public_key=root, live_window=lifetime.window,
                transport_deadline_ns=lifetime.bound, work=work, _continuity=continuity)
            if type(material) is not bootstrap._IssuerMaterial:
                _fail("proof input issuer requires genuine original launch admission")
            lifetime.attach(material.live)
            lifetime.adopt(material.live_window, material.deadline_ns)
            launch = material.launch
            if (tuple(launch[name] for name, _fd in bootstrap._FD_FIELDS) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS
                    or (launch["listenerPath"], launch["peerUid"], launch["peerGid"])
                        != (transport.LISTENER_PATH, transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("proof input issuer launch changed its fixed inventory or caller")
            timeout_ns = launch["requestTimeoutSeconds"] * 1_000_000_000
            lifetime.narrow(min(material.attestation_interval[1], lifetime.window[0] + timeout_ns),
                min(lifetime.window[5], timeout_ns), lifetime.window[6])
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            current()
            material_bytes = delivery._material_bytes_on_work(material, work, resource_current)
            held_bytes = delivered + sum(sizes) + material_bytes + sum(item[2] for item in delivery._TLS_FILES)
            wire_reservation = _WIRE_RESERVATION
            if material.grant_delivery_endpoint is not None:
                wire_reservation += _GRANT_WIRE_RESERVATION
            repeated_cold = bootstrap.issuer._cold_reservation_bytes(len(policy_raw), len(completion_raw),
                len(proof_raw), len(intent_raw))
            maximum_request = min(transport.MAX_REQUEST_BYTES,
                (bootstrap.MAX_ORIGINAL_BYTES - held_bytes - wire_reservation - repeated_cold - 16) // 8)
            if maximum_request < len(transport.PURPOSE) + 6:
                _fail("proof issuer decoded originals leave no bounded request")
            key = delivery._key_on_work(material, root, work, current=resource_current)
            current()
            completion = material.policy_material.completion_material
            tls = delivery._tls_identity(completion.tls_files, work=work, current=resource_current)
            current()
            dsn, timeout, _role, client_dn, serial, issuer_dn, query, structure = completion.custody_configuration
            if _role != packets.authority.SUCCESSOR_RECOVERY_ROLE:
                _fail("proof issuer packet reader differs from the fixed recovery role")
            reader = packets.SuccessorExecutionRecoveryReader(dsn=dsn, connect_timeout_seconds=timeout,
                tls_client_dn=client_dn, tls_client_serial=serial, tls_issuer_dn=issuer_dn,
                query_manifest_digest=query, expected_structure_manifest_digest=structure)
            current()

            def wrap_listener():
                global _listener_object
                _listener_object = socket.socket(fileno=delivery.LISTENER_FD)

            work.charge(input_bytes=4096)
            production._callback(work, wrap_listener)
            current()
            configured = _Configuration(material, root, key, work, work.limits, lifetime.ceilings,
                lifetime, tuple(lifetime.guards),
                lifetime.window, lifetime.bound, namespace, sealed, _listener_object, listener_pins, tls,
                reader, packets.SuccessorExecutionRecoveryReader._snapshot_configuration(reader),
                (completion, completion.packet_digest, completion.current_pending, completion.custody_configuration),
                delivery_current, delivered, held_bytes, maximum_request, material.delivery_endpoint,
                material.grant_delivery_endpoint, wire_reservation)
            owner = object.__new__(_IssuerOwner)
            owner._configured = owner._seal = configured
            owner._window_seal, owner._bound_seal = lifetime.window, lifetime.bound
            owner._spent = owner._failed = owner._closed = owner._packet_spent = owner._delivery_spent = False
            owner._grant_delivery_spent = False
            owner._sockets = owner._socket_seals = tuple(_SocketSlot()
                for _ in range(2 if material.grant_delivery_endpoint is None else 3))
            owner._delivery_channel = owner._response_material = owner._response_seal = None
            owner._grant_delivery_channel = None
            _owner, _state = owner, "started"
            owner._current()
            return owner
        except BaseException:
            _state = "failed"
            try:
                _cleanup_inherited()
            except BaseException:
                pass
            raise ReleaseProofInputIssuerStartupError("proof input issuer cold construction failed") from None


def require_started():
    _pid()
    with _LOCK:
        if type(_owner) is not _IssuerOwner:
            _fail("proof input issuer has not genuinely started")
        _owner._current()
        return _owner


def close():
    """Close actual owned resources once; earlier uncertainty remains terminal."""
    global _state, _cleanup_failed
    _pid()
    with _LOCK:
        if _owner is not None and not _owner._closed:
            _owner._closed = _owner._failed = True
            for index in reversed(range(len(_owner._sockets))):
                try:
                    _owner._close_socket(index, guarded=False)
                except BaseException:
                    _cleanup_failed = True
        _state = "closed"
        _cleanup_inherited()
