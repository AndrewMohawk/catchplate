"""One original-bound recovery grant issuance on eight inherited resources.

This owner retains the independently delivered root signer after the permanent
same-PID drop. It never stages a recovery worker, reads an outcome store, opens
delivery ciphertext or retries an exchange whose outcome is uncertain.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import socket
import threading

from catchplate import oidc_session_activation_release_recovery_issuer_bootstrap as bootstrap
from catchplate import oidc_session_activation_release_recovery_issuer_entrypoint as delivery
from catchplate import authority_oidc_session_activation_release_recovery_grant_production as producer
from catchplate import authority_oidc_session_activation_release_recovery_grant_transport as transport


capture, clock, production = bootstrap.capture, bootstrap.clock, bootstrap.production
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner = "new", None
_owned, _cleanup_failed, _listener_object = {}, False, None
_quarantined = []
_WIRE_RESERVATION = transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES


class ReleaseRecoveryIssuerStartupError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseRecoveryIssuerStartupError(message)


def _pid():
    if os.getpid() != _PID:
        _fail("recovery issuer cannot continue in a different PID")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    _pid()
    if (_environment() != namespace or namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (bootstrap.SERVICE_UID,) * 3
            or os.getresgid() != (bootstrap.SERVICE_GID,) * 3 or os.getgroups()
            or os.environ.get("CATCHPLATE_PROCESS_MODE") != bootstrap.PROCESS_MODE):
        _fail("recovery issuer process or closed environment changed")
    delivery._require_unprivileged_process()


def _fd_identity(descriptor):
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_rdev


def _cleanup_inherited():
    """Remove custody before a sole close attempt; never close a replacement."""
    global _cleanup_failed, _listener_object
    _pid()
    for descriptor, identity in tuple(_owned.items()):
        del _owned[descriptor]
        try:
            if _fd_identity(descriptor) != identity:
                _fail("recovery issuer inherited cleanup identity changed")
            if descriptor == delivery.LISTENER_FD and _listener_object is not None:
                if _listener_object.fileno() != descriptor:
                    _fail("recovery issuer lost its actual listener owner")
                _listener_object.close()
                if _listener_object.fileno() != -1:
                    _fail("recovery issuer listener closure is indeterminate")
                _listener_object = None
            else:
                os.close(descriptor)
        except BaseException:
            _cleanup_failed = True
    if _cleanup_failed:
        _fail("recovery issuer inherited cleanup is not established")


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
    delivery_current: object
    delivery_retained_bytes: int
    input_bytes: int
    maximum_request_bytes: int
    thread_id: int


class _IssuerOwner:
    __slots__ = ("_configured", "_seal", "_window_seal", "_bound_seal", "_spent",
        "_failed", "_closed", "_connection", "_connection_identity", "_connection_peer",
        "_connection_close_attempted")

    def __init__(self):
        _fail("recovery issuer requires genuine original cold construction")

    def _identity(self):
        _pid()
        configured = self._configured
        if (type(self) is not _IssuerOwner or self is not _owner or _state != "started"
                or self._closed or self._failed or type(configured) is not _Configuration
                or configured is not self._seal or threading.get_ident() != configured.thread_id):
            _fail("recovery issuer owner identity changed")
        lifetime = configured.lifetime
        if (type(lifetime) is not producer._Lifetime or lifetime.work is not configured.work
                or lifetime.limits is not configured.limits or lifetime.ceilings != configured.ceilings
                or lifetime.continuation is not None or tuple(lifetime.guards) != configured.guards
                or lifetime.window is not self._window_seal or lifetime.bound != self._bound_seal
                or lifetime.window[:3] != configured.window[:3]
                or any(new > old for new, old in zip(lifetime.window[3:], configured.window[3:]))
                or lifetime.bound > min(configured.deadline_ns, lifetime.window[4])):
            _fail("recovery issuer changed its original work or clock allowance")
        _process(configured.namespace)
        for descriptor, maximum, private, identity in configured.sealed:
            if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                _fail("recovery issuer inherited original changed")
        if (configured.listener is not _listener_object
                or configured.listener.fileno() != delivery.LISTENER_FD
                or delivery._listener(delivery.LISTENER_FD) != configured.listener_pins):
            _fail("recovery issuer root-created listener changed")
        inventory = delivery.INHERITED_DESCRIPTORS
        if self._connection is not None:
            if self._connection_identity is None or self._connection_peer is None:
                _fail("recovery issuer accepted socket identity is incomplete")
            connection, descriptor, identity = self._connection_identity
            if (self._connection is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity or connection.family != socket.AF_UNIX
                    or connection.type != socket.SOCK_STREAM or connection.gettimeout() != 0.0
                    or connection.get_inheritable()
                    or transport.authority_transport._peer_identity(connection) != self._connection_peer
                    or self._connection_peer[:2] != (transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("recovery issuer accepted socket ownership or peer changed")
            inventory += (descriptor,)
        elif self._connection_identity is not None or self._connection_peer is not None:
            _fail("recovery issuer lost its accepted socket")
        delivery._require_inventory(inventory)

    def _current(self):
        configured = self._configured
        try:
            capture._SharedLedger(configured.work)
            configured.work.charge(input_bytes=4096)
            production._callback(configured.work, self._identity)
            if delivery._retained_bytes_on_work(configured.delivery_current,
                    configured.work) != configured.delivery_retained_bytes:
                _fail("recovery issuer changed its actual delivered originals")
            return configured.lifetime.current()
        except BaseException:
            self._failed = True
            raise

    def _continuity(self, epoch, monotonic):
        if type(epoch) is not int or type(monotonic) is not int or epoch < 1 or monotonic < 1:
            _fail("recovery issuer producer supplied invalid restrictive clock floors")
        lifetime = self._configured.lifetime
        lifetime._floors(max(lifetime.epoch, epoch), max(lifetime.monotonic, monotonic))
        self._current()
        return lifetime.epoch, lifetime.monotonic

    def _narrow(self, expiry):
        lifetime = self._configured.lifetime
        lifetime.narrow(expiry, lifetime.window[5], lifetime.window[6])
        self._window_seal, self._bound_seal = lifetime.window, lifetime.bound
        self._current()

    def _close_connection(self, *, guarded):
        global _cleanup_failed
        connection = self._connection
        if connection is None:
            return
        if self._connection_close_attempted:
            _cleanup_failed = True
            _fail("recovery issuer cannot retry indeterminate socket cleanup")
        if guarded:
            self._current()
        self._connection_close_attempted = True
        try:
            if self._connection_identity is None:
                _fail("recovery issuer accepted socket identity was not established")
            held, descriptor, identity = self._connection_identity
            if (connection is not held or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity):
                _fail("recovery issuer socket cleanup identity changed")
            if guarded:
                self._configured.work.charge(input_bytes=1)
                production._callback(self._configured.work, connection.close)
            else:
                connection.close()
            if connection.fileno() != -1:
                _fail("recovery issuer socket closure is indeterminate")
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
            _fail("recovery issuer request exceeds its complete held inventory")
        response = producer._produce_on_work(request_originals=originals[1:],
            issuer_policy_bytes=material.issuer_policy_bytes,
            release_custody_bytes=material.release_custody_bytes,
            proof_enrollment_bytes=material.proof_enrollment_bytes,
            intent_enrollment_bytes=material.intent_enrollment_bytes,
            root_private_key=configured.key, root_public_key=configured.root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=self._continuity)
        self._current()
        response = transport._originals(response, response=True)
        if (configured.input_bytes + sum(map(len, originals)) + sum(map(len, response))
                + _WIRE_RESERVATION > bootstrap.MAX_ORIGINAL_BYTES):
            _fail("recovery issuer response exceeds its complete held inventory")
        # Only the actual local producer can reach this read. It grants no new
        # authority: expiry data can only tighten send and normal-close bounds.
        payload = producer.clients._read(response[0], work)["payload"]
        self._narrow(payload["expiresAtEpochNs"])
        return response

    def serve_once(self):
        """Spend before waiting; authenticate the fixed peer before any body."""
        global _state
        with _LOCK:
            self._current()
            if self._spent or self._connection is not None:
                _fail("recovery issuer cannot repeat its exchange")
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
                        _fail("recovery issuer peer is not the fixed control-plane caller")

                self._current()
                remaining = transport.io._check_deadline(lifetime.bound) / 1_000_000_000
                work.charge(input_bytes=4096)
                ready, _writers, exceptional = production._callback(work,
                    lambda: select.select((configured.listener,), (), (configured.listener,), remaining))
                self._current()
                if not ready or exceptional:
                    _fail("recovery issuer readiness was not established")
                work.charge(input_bytes=4096)
                production._callback(work, accept)
                self._current()
                originals = transport._recv_request(self._connection, deadline_ns=lifetime.bound,
                    work=work, current=self._current, maximum_request_bytes=configured.maximum_request_bytes)
                response = self._produce(originals)
                del originals
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
                    self._close_connection(guarded=False)
                except BaseException:
                    pass
                raise ReleaseRecoveryIssuerStartupError("recovery grant issuance is not established") from None

    def close(self):
        if self is not _owner:
            _fail("recovery issuer close requires the actual owner")
        close()


def initialize_from_environment(*, work, live_window, transport_deadline_ns, delivery_current):
    """Continue the genuine eight-resource delivery after same-PID drop."""
    global _state, _owner, _listener_object
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from catchplate.authority_query_read_work import _ValidationWork

    _pid()
    with _LOCK:
        if _state != "new":
            _fail("recovery issuer startup cannot restart")
        _state = "initializing"
        namespace = _environment()
        try:
            if type(work) is not _ValidationWork:
                _fail("recovery issuer requires the actual original validation work")
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
                        _fail("recovery issuer construction original changed")
                if listener_pins is not None and production._callback(work,
                        lambda: delivery._listener(delivery.LISTENER_FD)) != listener_pins:
                    _fail("recovery issuer construction listener changed")
                if delivery._retained_bytes_on_work(delivery_current, work) != delivered:
                    _fail("recovery issuer construction delivery changed")
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
                (delivery.RELEASE_CUSTODY_FD, delivery.MAX_RELEASE_CUSTODY_BYTES, False),
                (delivery.PROOF_ENROLLMENT_FD, delivery.MAX_PROOF_ENROLLMENT_BYTES, False),
                (delivery.INTENT_ENROLLMENT_FD, delivery.MAX_INTENT_ENROLLMENT_BYTES, False),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True))
            sealed = tuple((descriptor, maximum, private, production._callback(work,
                lambda: delivery._sealed_identity(descriptor, maximum, private=private)))
                for descriptor, maximum, private in descriptions)
            current()
            sizes = production._callback(work, lambda: tuple(os.fstat(descriptor).st_size
                for descriptor, _maximum, _private in descriptions))
            cold = (delivered + sum(sizes) + 8 * sizes[3]
                + 4 * sum(sizes[:3] + sizes[4:6]) + producer._OUTPUT_RESERVATION + _WIRE_RESERVATION)
            if cold >= bootstrap.MAX_ORIGINAL_BYTES:
                _fail("recovery issuer cold originals leave no bounded decoded inventory")
            raws = []
            for descriptor, maximum, _private, identity in sealed[:-1]:
                current()
                raw, observed = delivery._read_on_work(descriptor, maximum, work)
                current()
                if observed != identity:
                    _fail("recovery issuer original changed during inherited read")
                raws.append(raw)
            root_raw, launch_raw, policy_raw, custody_raw, proof_raw, intent_raw = raws
            work.charge(input_bytes=len(root_raw))
            root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                _fail("recovery issuer requires the original Ed25519 root")
            current()
            material = bootstrap._verify_on_work(bootstrap_bytes=launch_raw, issuer_policy_bytes=policy_raw,
                release_custody_bytes=custody_raw, proof_enrollment_bytes=proof_raw,
                intent_enrollment_bytes=intent_raw, root_public_key=root, live_window=lifetime.window,
                transport_deadline_ns=lifetime.bound, work=work, _continuity=continuity)
            if type(material) is not bootstrap._IssuerMaterial:
                _fail("recovery issuer requires genuine original launch admission")
            lifetime.attach(material.live)
            lifetime.adopt(material.live_window, material.deadline_ns)
            launch = material.launch
            if (tuple(launch[name] for name, _fd in bootstrap._FD_FIELDS) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS
                    or (launch["listenerPath"], launch["peerUid"], launch["peerGid"])
                        != (transport.LISTENER_PATH, transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("recovery issuer launch changed its fixed inventory or caller")
            timeout_ns = launch["requestTimeoutSeconds"] * 1_000_000_000
            lifetime.narrow(min(material.attestation_interval[1], lifetime.window[0] + timeout_ns),
                min(lifetime.window[5], timeout_ns), lifetime.window[6])
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            current()
            material_bytes = delivery._material_bytes_on_work(material, work, resource_current)
            held_bytes = delivered + sum(sizes) + material_bytes
            fixed = (held_bytes + 8 * len(custody_raw)
                + 4 * sum(map(len, (policy_raw, proof_raw, intent_raw)))
                + producer._OUTPUT_RESERVATION + _WIRE_RESERVATION
                + producer.transport.RECOVERY_REQUEST_HEADER_BYTES)
            maximum_request = min(transport.MAX_REQUEST_BYTES,
                (bootstrap.MAX_ORIGINAL_BYTES - fixed) // 4)
            if maximum_request <= 0:
                _fail("recovery issuer decoded originals leave no bounded request")
            key = delivery._key_on_work(material, root, work, current=resource_current)
            current()

            def wrap_listener():
                global _listener_object
                _listener_object = socket.socket(fileno=delivery.LISTENER_FD)

            work.charge(input_bytes=4096)
            production._callback(work, wrap_listener)
            current()
            configured = _Configuration(material, root, key, work, work.limits, lifetime.ceilings,
                lifetime, tuple(lifetime.guards), lifetime.window, lifetime.bound, namespace,
                sealed, _listener_object, listener_pins, delivery_current, delivered,
                held_bytes, maximum_request, threading.get_ident())
            owner = object.__new__(_IssuerOwner)
            owner._configured = owner._seal = configured
            owner._window_seal, owner._bound_seal = lifetime.window, lifetime.bound
            owner._spent = owner._failed = owner._closed = owner._connection_close_attempted = False
            owner._connection = owner._connection_identity = owner._connection_peer = None
            _owner, _state = owner, "started"
            owner._current()
            return owner
        except BaseException:
            _state = "failed"
            try:
                _cleanup_inherited()
            except BaseException:
                pass
            raise ReleaseRecoveryIssuerStartupError("recovery issuer cold construction failed") from None


def require_started():
    _pid()
    with _LOCK:
        if type(_owner) is not _IssuerOwner:
            _fail("recovery issuer has not genuinely started")
        _owner._current()
        return _owner


def close():
    """Close actual owned resources once; uncertainty remains terminal."""
    global _state, _cleanup_failed
    _pid()
    with _LOCK:
        if _owner is not None and not _owner._closed:
            _owner._closed = _owner._failed = True
            try:
                _owner._close_connection(guarded=False)
            except BaseException:
                _cleanup_failed = True
        _state = "closed"
        _cleanup_inherited()
