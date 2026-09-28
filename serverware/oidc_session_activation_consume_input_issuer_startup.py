"""One original-bound consume-input issuance on six inherited resources.

The private root signer is retained only by this one-shot owner. Launch v2
stages the exact issued pair through one owned socket before returning it.
No history AES, token retention, state mutation or retry is introduced.
Signed resource pins authorize a configuration; they do not provision it.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import socket
import threading
from types import MethodType

from serverware import oidc_session_activation_consume_input_issuer_bootstrap as bootstrap
from serverware import oidc_session_activation_consume_input_issuer_entrypoint as delivery
from serverware import authority_oidc_session_activation_consume_input_production as producer
from serverware import authority_oidc_session_activation_consume_input_transport as transport
from serverware import authority_oidc_session_activation_consume_input_delivery_transport as staging


capture, clock, production = bootstrap.capture, bootstrap.clock, bootstrap.production
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner = "new", None
_owned, _cleanup_failed = {}, False
_listener_object = None
_quarantined = []


class ConsumeInputIssuerStartupError(RuntimeError):
    pass


def _fail(message):
    raise ConsumeInputIssuerStartupError(message)


def _pid():
    if os.getpid() != _PID:
        _fail("consume input issuer cannot continue in a different PID")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    _pid()
    if (_environment() != namespace or namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (bootstrap.SERVICE_UID,) * 3
            or os.getresgid() != (bootstrap.SERVICE_GID,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != bootstrap.PROCESS_MODE):
        _fail("consume input issuer process or closed environment changed")
    delivery._require_unprivileged_process()


def _fd_identity(descriptor):
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_rdev


def _cleanup_inherited():
    """Never retry a close or close an FD whose original identity changed."""
    global _cleanup_failed, _listener_object
    _pid()
    for descriptor, identity in tuple(_owned.items()):
        del _owned[descriptor]
        try:
            if _fd_identity(descriptor) != identity:
                _cleanup_failed = True
                continue
            if descriptor == delivery.LISTENER_FD and _listener_object is not None:
                listener = _listener_object
                if listener.fileno() != descriptor:
                    _cleanup_failed = True
                    continue
                listener.close()
                if listener.fileno() != -1:
                    _fail("consume input issuer listener closure is indeterminate")
                _listener_object = None
            else:
                os.close(descriptor)
        except BaseException:
            _cleanup_failed = True
    if _cleanup_failed:
        _fail("consume input issuer inherited cleanup is not established")


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
    input_bytes: int
    maximum_request_bytes: int
    delivery_endpoint: tuple | None


class _DeliveryChannel:
    """One issuer-owned staging socket, never an arbitrary FD allowance."""

    __slots__ = ("_owner", "_opened", "_closed")

    def __init__(self):
        _fail("consume staging requires the actual issuer-owned channel")

    def _identity(self):
        owner = self._owner
        if (type(self) is not _DeliveryChannel or type(owner) is not _IssuerOwner
                or owner is not _owner or owner._delivery_channel is not self
                or not owner._delivery_spent or owner._configured.delivery_endpoint is None or self._closed):
            _fail("consume staging channel changed its actual issuer owner")
        return owner

    def check(self, *, endpoint, deadline_ns, work, current):
        owner = self._identity()
        if (type(endpoint) is not tuple or endpoint != owner._configured.delivery_endpoint
                or work is not owner._configured.work or type(deadline_ns) is not int
                or not 0 < deadline_ns <= owner._configured.lifetime.bound
                or type(current) is not MethodType or current.__self__ is not owner
                or current.__func__ is not _IssuerOwner._current):
            _fail("consume staging changed its fixed endpoint or original allowance")
        owner._current()

    def open(self):
        owner = self._identity()
        if self._opened or owner._delivery_socket is not None:
            _fail("consume staging socket cannot be reopened")
        self._opened = True
        work = owner._configured.work
        owner._current()
        work.charge(input_bytes=4096)

        def opening():
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            owner._delivery_socket = connection
            descriptor = connection.fileno()
            owner._delivery_identity = connection, descriptor, _fd_identity(descriptor)
            connection.setblocking(False)
            connection.set_inheritable(False)

        production._callback(work, opening)
        owner._current()
        return owner._delivery_socket

    def connected(self):
        owner = self._identity()
        if not self._opened or owner._delivery_socket is None or owner._delivery_peer is not None:
            _fail("consume staging connection cannot replace its peer")
        work = owner._configured.work
        owner._current()
        work.charge(input_bytes=12)
        peer = production._callback(work,
            lambda: transport.authority_transport._peer_identity(owner._delivery_socket))
        if peer[:2] != (0, 0):
            _fail("consume staging receiver is not the actual root peer")
        owner._delivery_peer = peer
        owner._current()

    def close(self):
        owner = self._identity()
        owner._close_delivery(guarded=True)
        self._closed = True


class _IssuerOwner:
    __slots__ = ("_configured", "_seal", "_window_seal", "_bound_seal",
        "_spent", "_failed", "_closed", "_connection", "_connection_identity",
        "_connection_peer", "_connection_close_attempted", "_delivery_channel",
        "_delivery_spent", "_delivery_socket", "_delivery_identity", "_delivery_peer",
        "_delivery_close_attempted")

    def __init__(self):
        _fail("consume input issuer requires actual original cold construction")

    def _identity(self):
        _pid()
        configured = self._configured
        if (type(self) is not _IssuerOwner or self is not _owner or _state != "started"
                or self._closed or self._failed or configured is not self._seal
                or type(configured) is not _Configuration):
            _fail("consume input issuer owner identity changed")
        lifetime = configured.lifetime
        if (type(lifetime) is not producer._Lifetime or lifetime.work is not configured.work
                or lifetime.limits is not configured.limits or lifetime.ceilings != configured.ceilings
                or lifetime.continuation is not None or tuple(lifetime.guards) != configured.guards
                or lifetime.window is not self._window_seal or lifetime.bound != self._bound_seal
                or lifetime.window[:3] != configured.window[:3]
                or any(new > old for new, old in zip(lifetime.window[3:], configured.window[3:]))
                or lifetime.bound > min(configured.deadline_ns, lifetime.window[4])):
            _fail("consume input issuer replaced its original clock or work lifetime")
        if configured.material.delivery_endpoint is not configured.delivery_endpoint:
            _fail("consume input issuer replaced its admitted staging endpoint")
        _process(configured.namespace)
        for descriptor, maximum, private, identity in configured.sealed:
            if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                _fail("consume input issuer inherited original identity changed")
        if (configured.listener is not _listener_object
                or configured.listener.fileno() != delivery.LISTENER_FD
                or delivery._listener(delivery.LISTENER_FD) != configured.listener_pins):
            _fail("consume input issuer root-created listener changed")
        inventory = delivery.INHERITED_DESCRIPTORS
        if self._connection is not None:
            if self._connection_identity is None or self._connection_peer is None:
                _fail("consume input issuer accepted socket identity is incomplete")
            connection, descriptor, identity = self._connection_identity
            if (self._connection is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity or connection.family != socket.AF_UNIX
                    or connection.type != socket.SOCK_STREAM or connection.gettimeout() != 0.0
                    or connection.get_inheritable()
                    or transport.authority_transport._peer_identity(connection) != self._connection_peer
                    or self._connection_peer[:2] != (transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("consume input issuer accepted socket ownership or peer changed")
            inventory += (descriptor,)
        elif self._connection_identity is not None or self._connection_peer is not None:
            _fail("consume input issuer lost its accepted socket")
        if self._delivery_socket is not None:
            channel = self._delivery_channel
            if (type(channel) is not _DeliveryChannel or channel._owner is not self
                    or not channel._opened or channel._closed or not self._delivery_spent
                    or configured.delivery_endpoint is None or self._delivery_identity is None):
                _fail("consume issuer staging socket lacks its exact owned channel")
            connection, descriptor, identity = self._delivery_identity
            if (self._delivery_socket is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity or connection.family != socket.AF_UNIX
                    or connection.type != socket.SOCK_STREAM or connection.gettimeout() != 0.0
                    or connection.get_inheritable()):
                _fail("consume issuer staging socket ownership changed")
            if self._delivery_peer is not None:
                if (self._delivery_peer[:2] != (0, 0)
                        or transport.authority_transport._peer_identity(connection) != self._delivery_peer):
                    _fail("consume issuer staging root peer changed")
            inventory += (descriptor,)
        elif self._delivery_identity is not None or self._delivery_peer is not None:
            _fail("consume issuer lost its owned staging socket")
        delivery._require_inventory(inventory)

    def _current(self):
        configured = self._configured
        try:
            capture._SharedLedger(configured.work)
            configured.work.charge(input_bytes=4096)
            production._callback(configured.work, self._identity)
            return configured.lifetime.current()
        except BaseException:
            self._failed = True
            raise

    def _continuity(self, epoch, monotonic):
        if type(epoch) is not int or type(monotonic) is not int or epoch < 1 or monotonic < 1:
            _fail("consume input issuer producer supplied invalid restrictive clock floors")
        lifetime = self._configured.lifetime
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        self._current()
        return lifetime.epoch, lifetime.monotonic

    def _close_connection(self, *, guarded):
        global _cleanup_failed
        connection = self._connection
        if connection is None:
            return
        if self._connection_close_attempted:
            _cleanup_failed = True
            _fail("consume input issuer cannot retry indeterminate socket cleanup")
        if guarded:
            self._current()
        self._connection_close_attempted = True
        try:
            if self._connection_identity is None:
                _fail("consume input issuer accepted socket identity was not established")
            held, descriptor, identity = self._connection_identity
            if (connection is not held or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity):
                _fail("consume input issuer socket cleanup identity changed")
            if guarded:
                self._configured.work.charge(input_bytes=1)
                production._callback(self._configured.work, connection.close)
            else:
                connection.close()
            if connection.fileno() != -1:
                _fail("consume input issuer socket closure is indeterminate")
        except BaseException:
            _cleanup_failed = True
            _quarantined.append(connection)
            raise
        self._connection = self._connection_identity = self._connection_peer = None
        if guarded:
            self._current()

    def _produce(self, originals):
        configured, work = self._configured, self._configured.work
        material, lifetime = configured.material, configured.lifetime
        self._current()
        if sum(map(len, originals)) > configured.maximum_request_bytes:
            _fail("consume input issuer request exceeds the complete held inventory")
        response = producer._produce_on_work(request_originals=originals[1:],
            issuer_policy_bytes=material.issuer_policy_bytes,
            activation_planner_bootstrap_bytes=material.activation_planner_bootstrap_bytes,
            root_private_key=configured.key, root_public_key=configured.root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=self._continuity)
        self._current()
        response = transport._originals(response, response=True)
        # Output expiry is deterministic from the actual cold policy, not a
        # received result. It already bounds production, send and normal close.
        if (configured.input_bytes + sum(map(len, originals)) + sum(map(len, response))
                + transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
                > bootstrap.MAX_ORIGINAL_BYTES):
            _fail("consume input issuer returned originals exceed the held inventory")
        self._current()
        return response

    def serve_once(self):
        """One peer-checked exchange; the latch is spent before select/accept."""
        global _state
        with _LOCK:
            self._current()
            if self._spent or self._connection is not None:
                _fail("consume input issuer cannot repeat its exchange")
            self._spent = True
            configured, work = self._configured, self._configured.work
            lifetime = configured.lifetime
            try:
                def accept():
                    connection, _address = configured.listener.accept()
                    self._connection = connection
                    descriptor = connection.fileno()
                    self._connection_identity = connection, descriptor, _fd_identity(descriptor)
                    connection.setblocking(False)
                    connection.set_inheritable(False)
                    self._connection_peer = transport.authority_transport._peer_identity(connection)
                    if self._connection_peer[:2] != (transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID):
                        _fail("consume input issuer peer is not the fixed control-plane caller")

                work.charge(input_bytes=4096)
                self._current()
                remaining = transport.io._check_deadline(lifetime.bound) / 1_000_000_000
                ready, _writers, exceptional = production._callback(work,
                    lambda: select.select((configured.listener,), (), (configured.listener,), remaining))
                self._current()
                if not ready or exceptional:
                    _fail("consume input issuer readiness was not established")
                production._callback(work, accept)
                self._current()
                originals = transport._recv_request(self._connection, deadline_ns=lifetime.bound,
                    work=work, current=self._current, maximum_request_bytes=configured.maximum_request_bytes)
                response = self._produce(originals)
                del originals
                self._stage_response(response)
                self._current()
                transport._send_response(self._connection, response, deadline_ns=lifetime.bound,
                    work=work, current=self._current)
                self._close_connection(guarded=True)
                self._current()
                _state = "spent"
                return True
            except BaseException:
                self._failed = True
                _state = "failed"
                try:
                    self._close_delivery(guarded=False)
                except BaseException:
                    pass
                try:
                    self._close_connection(guarded=False)
                except BaseException:
                    pass
                raise ConsumeInputIssuerStartupError(
                    "consume input issuance is not established; automatic retry is prohibited") from None

    def close(self):
        if self is not _owner:
            _fail("consume input issuer cleanup requires its actual owner")
        close()

    def _close_delivery(self, *, guarded):
        global _cleanup_failed
        connection = self._delivery_socket
        if connection is None:
            if guarded:
                self._current()
            return
        if self._delivery_close_attempted:
            _cleanup_failed = True
            _fail("consume issuer cannot retry indeterminate staging cleanup")
        if guarded:
            self._current()
        self._delivery_close_attempted = True
        try:
            if self._delivery_identity is None:
                _fail("consume issuer staging socket identity was not established")
            held, descriptor, identity = self._delivery_identity
            if (connection is not held or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity):
                _fail("consume issuer staging cleanup identity changed")
            if guarded:
                self._configured.work.charge(input_bytes=1)
                production._callback(self._configured.work, connection.close)
            else:
                connection.close()
            if connection.fileno() != -1:
                _fail("consume issuer staging closure is indeterminate")
        except BaseException:
            _cleanup_failed = True
            _quarantined.append(connection)
            raise
        self._delivery_socket = self._delivery_identity = self._delivery_peer = None
        if guarded:
            self._current()

    def _stage_response(self, response):
        configured, work = self._configured, self._configured.work
        endpoint = configured.delivery_endpoint
        if endpoint is None:
            return
        self._current()
        if self._delivery_spent or self._delivery_channel is not None:
            _fail("consume issuer cannot repeat bootstrap staging")
        self._delivery_spent = True
        # Request originals have been dropped. Reserve both retained response
        # and outgoing wire copies, framing and ACK before opening a channel.
        if (configured.input_bytes + 2 * sum(map(len, response)) + len(staging.PURPOSE)
                + transport.RESPONSE_HEADER_BYTES + staging.REQUEST_HEADER_BYTES
                + staging.RESPONSE_HEADER_BYTES + staging.MAX_RESPONSE_BYTES > bootstrap.MAX_ORIGINAL_BYTES):
            _fail("consume issuer staging exceeds the complete held inventory")
        lifetime = configured.lifetime
        identities = staging._pair_identities_on_work(*response,
            deadline_ns=lifetime.bound, work=work, current=self._current)
        channel = object.__new__(_DeliveryChannel)
        channel._owner, channel._opened, channel._closed = self, False, False
        self._delivery_channel = channel
        self._current()
        acknowledged = staging._socket_request_on_work(endpoint,
            originals=(staging.PURPOSE, *response), deadline_ns=lifetime.bound,
            work=work, current=self._current, channel=channel)
        self._current()
        acknowledged = staging._originals(acknowledged, response=True)
        if (not channel._closed or self._delivery_socket is not None
                or acknowledged[0] != staging.ACK_STATUS):
            _fail("consume issuer staging acknowledgment is not established")
        for observed, expected in zip(acknowledged[1:], identities):
            producer._same_bytes(observed, expected, work, "consume issuer exact staged original identity")
        self._current()


def initialize_from_environment(*, work, live_window, transport_deadline_ns, delivery_current):
    """Continue actual same-PID delivery after its permanent privilege drop."""
    global _state, _owner, _listener_object
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware.authority_query_read_work import _ValidationWork

    _pid()
    with _LOCK:
        if _state != "new":
            _fail("consume input issuer startup cannot restart")
        _state = "initializing"
        namespace = _environment()
        try:
            if type(work) is not _ValidationWork or not callable(delivery_current):
                _fail("consume input issuer requires original work and delivery continuity")
            capture._SharedLedger(work)
            window = clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            lifetime = producer._Lifetime(window, min(window[4], transport_deadline_ns), work, None)
            lifetime.attach(delivery_current)
            sealed, listener_pins = (), None

            def current():
                work.charge(input_bytes=4096)
                production._callback(work, lambda: _process(namespace))
                for descriptor, maximum, private, identity in sealed:
                    if production._callback(work, lambda: delivery._sealed_identity(
                            descriptor, maximum, private=private)) != identity:
                        _fail("consume input issuer construction original FD changed")
                if listener_pins is not None:
                    if production._callback(work,
                            lambda: delivery._listener(delivery.LISTENER_FD)) != listener_pins:
                        _fail("consume input issuer construction listener changed")
                production._callback(work, lambda: delivery._require_inventory(delivery.INHERITED_DESCRIPTORS))
                return lifetime.current()

            current()
            work.charge(input_bytes=4096)
            for descriptor in delivery.INHERITED_DESCRIPTORS:
                _owned[descriptor] = production._callback(work, lambda: _fd_identity(descriptor))
            descriptions = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False),
                (delivery.POLICY_FD, delivery.MAX_POLICY_BYTES, False),
                (delivery.ACTIVATION_PLANNER_BOOTSTRAP_FD, delivery.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, False),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True))
            sealed = tuple((descriptor, maximum, private, production._callback(work,
                lambda: delivery._sealed_identity(descriptor, maximum, private=private)))
                for descriptor, maximum, private in descriptions)
            current()
            sizes = production._callback(work, lambda: tuple(os.fstat(descriptor).st_size
                for descriptor, _maximum, _private in descriptions))
            # Reject before any original body read. Request-specific intake is
            # bounded again after authenticating the actual decoded inventory.
            cold_reservation = sum(sizes) + producer._OUTPUT_RESERVATION
            if cold_reservation + transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES >= bootstrap.MAX_ORIGINAL_BYTES:
                _fail("consume input issuer cold inventory leaves no bounded exchange")
            raws = []
            for descriptor, maximum, _private, identity in sealed[:-1]:
                current()
                raw, observed = delivery._read_on_work(descriptor, maximum, work)
                current()
                if observed != identity:
                    _fail("consume input issuer original changed during inherited read")
                raws.append(raw)
            root_raw, bootstrap_raw, policy_raw, activation_raw = raws
            work.charge(input_bytes=len(root_raw))
            current()
            root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                _fail("consume input issuer requires the actual Ed25519 runtime root")
            current()
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, issuer_policy_bytes=policy_raw,
                activation_planner_bootstrap_bytes=activation_raw, root_public_key=root,
                live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
                work=work, _continuity=lifetime.continuity)
            if type(material) is not bootstrap._IssuerMaterial:
                _fail("consume input issuer requires actual original launch admission")
            lifetime.attach(material.live)
            lifetime.adopt(material.live_window, material.deadline_ns)
            launch = material.launch
            if (tuple(launch[name] for name, _fd in bootstrap._FD_FIELDS) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS
                    or (launch["listenerPath"], launch["peerUid"], launch["peerGid"])
                        != (transport.LISTENER_PATH, transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("consume input issuer launch changed the fixed inventory or peer")
            policy = material.policy_material
            historical = policy.activation_planner
            issued = policy.payload["issuedAtEpochNs"]
            expiry = min(policy.payload["expiresAtEpochNs"],
                issued + min(historical.maximum_plan_age_ns, producer.activation.MAX_RECEIPT_AGE_NS))
            timeout_ns = launch["requestTimeoutSeconds"] * 1_000_000_000
            lifetime.narrow(min(expiry, lifetime.window[0] + timeout_ns),
                min(historical.maximum_plan_age_ns, timeout_ns), historical.maximum_clock_skew_ns)
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            decoded = len(historical.complete_root_vector_bytes) + len(historical.state_enrollment_bytes)
            held_bytes = sum(sizes) + decoded + 2 * len(activation_raw)
            maximum_request_bytes = min(transport.MAX_REQUEST_BYTES,
                bootstrap.MAX_ORIGINAL_BYTES - held_bytes - producer._OUTPUT_RESERVATION
                - transport.REQUEST_HEADER_BYTES - transport.RESPONSE_HEADER_BYTES)
            if maximum_request_bytes <= 0:
                _fail("consume input issuer decoded inventory leaves no bounded request")
            current()
            key = delivery._key_on_work(material, root, work, current=current)
            current()

            def wrap_listener():
                global _listener_object
                _listener_object = socket.socket(fileno=delivery.LISTENER_FD)

            work.charge(input_bytes=4096)
            production._callback(work, wrap_listener)
            current()
            configured = _Configuration(material, root, key, work, work.limits, lifetime.ceilings,
                lifetime, tuple(lifetime.guards), lifetime.window, lifetime.bound, namespace, sealed,
                _listener_object, listener_pins, held_bytes, maximum_request_bytes, material.delivery_endpoint)
            owner = object.__new__(_IssuerOwner)
            owner._configured = owner._seal = configured
            owner._window_seal, owner._bound_seal = lifetime.window, lifetime.bound
            owner._spent = owner._failed = owner._closed = owner._connection_close_attempted = False
            owner._connection = owner._connection_identity = owner._connection_peer = None
            owner._delivery_spent = owner._delivery_close_attempted = False
            owner._delivery_channel = owner._delivery_socket = owner._delivery_identity = owner._delivery_peer = None
            _owner, _state = owner, "started"
            owner._current()
            return owner
        except BaseException:
            _state = "failed"
            try:
                _cleanup_inherited()
            except BaseException:
                pass
            raise ConsumeInputIssuerStartupError("consume input issuer cold construction failed") from None


def require_started():
    _pid()
    with _LOCK:
        if type(_owner) is not _IssuerOwner:
            _fail("consume input issuer has not genuinely started")
        _owner._current()
        return _owner


def close():
    """One-attempt cleanup; an earlier uncertain closure stays failed."""
    global _state, _cleanup_failed
    _pid()
    with _LOCK:
        owner = _owner
        if owner is not None and not owner._closed:
            owner._closed = owner._failed = True
            try:
                owner._close_delivery(guarded=False)
            except BaseException:
                _cleanup_failed = True
            try:
                owner._close_connection(guarded=False)
            except BaseException:
                _cleanup_failed = True
        _state = "closed"
        _cleanup_inherited()
