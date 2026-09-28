"""One-shot private root grant issuer with six original inherited resources.

This owner continues the actual root-delivery work and clock history. It never
opens delivery ciphertext, replays private history, mutates SQL/state, retains
tokens or retries an exchange. Resource authorization is not provisioning proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_release_grant_issuer_entrypoint as delivery
from serverware import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap
from serverware import authority_oidc_session_activation_release_grant_production as producer
from serverware import authority_oidc_session_activation_release_grant_transport as transport


capture, clock, production = bootstrap.capture, bootstrap.clock, bootstrap.production
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner = "new", None
_owned, _cleanup_failed = {}, False
_listener_object = None
_quarantined = []


class ReleaseGrantIssuerStartupError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseGrantIssuerStartupError(message)


def _pid():
    if os.getpid() != _PID:
        _fail("release grant issuer cannot continue in a different PID")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    _pid()
    if (_environment() != namespace or namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (bootstrap.SERVICE_UID,) * 3
            or os.getresgid() != (bootstrap.SERVICE_GID,) * 3 or os.getgroups()
            or os.environ.get("SERVERWARE_PROCESS_MODE") != bootstrap.PROCESS_MODE):
        _fail("release grant issuer process or closed environment changed")
    delivery._require_unprivileged_process()


def _fd_identity(descriptor):
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_rdev


def _cleanup_inherited():
    """One attempt per original identity; never close a replacement FD."""
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
                    _fail("release grant issuer listener closure is indeterminate")
                _listener_object = None
            else:
                os.close(descriptor)
        except BaseException:
            _cleanup_failed = True
    if _cleanup_failed:
        _fail("release grant issuer inherited cleanup is not established")


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Configuration:
    material: object
    root: object
    key: object
    work: object
    limits: object
    ceilings: tuple
    window: tuple
    deadline_ns: int
    delivery_current: object
    namespace: tuple
    sealed: tuple
    listener: object
    listener_pins: tuple
    input_bytes: int
    control_age: int
    control_skew: int


class _IssuerOwner:
    __slots__ = ("_configured", "_seal", "_window", "_window_seal", "_bound", "_bound_seal",
        "_last_epoch", "_last_monotonic", "_metrics", "_spent", "_failed", "_closed",
        "_connection", "_connection_identity", "_connection_peer", "_connection_close_attempted")

    def __init__(self):
        _fail("release grant issuer requires actual original cold construction")

    def _identity(self):
        _pid()
        configured = self._configured
        if (type(self) is not _IssuerOwner or self is not _owner or _state != "started"
                or self._closed or self._failed or configured is not self._seal
                or type(configured) is not _Configuration
                or self._window is not self._window_seal or self._bound != self._bound_seal
                or self._window[:3] != configured.window[:3]
                or any(new > old for new, old in zip(self._window[3:], configured.window[3:]))
                or self._bound > min(configured.deadline_ns, self._window[4])):
            _fail("release grant issuer owner or original lifetime changed")
        _process(configured.namespace)
        for descriptor, maximum, private, identity in configured.sealed:
            if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                _fail("release grant issuer inherited original identity changed")
        if (configured.listener is not _listener_object
                or configured.listener.fileno() != delivery.LISTENER_FD
                or delivery._listener(delivery.LISTENER_FD) != configured.listener_pins):
            _fail("release grant issuer root-created listener changed")
        inventory = delivery.INHERITED_DESCRIPTORS
        if self._connection is not None:
            if self._connection_identity is None or self._connection_peer is None:
                _fail("release grant issuer accepted connection identity is incomplete")
            connection, descriptor, identity = self._connection_identity
            if (self._connection is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity or connection.gettimeout() != 0.0
                    or connection.get_inheritable()
                    or transport.authority_transport._peer_identity(connection) != self._connection_peer
                    or self._connection_peer[:2] != (transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("release grant issuer accepted connection ownership or peer changed")
            inventory += (descriptor,)
        elif self._connection_identity is not None or self._connection_peer is not None:
            _fail("release grant issuer lost its accepted socket")
        delivery._require_inventory(inventory)

    def _current(self):
        configured, work = self._configured, self._configured.work
        capture._SharedLedger(work)
        before = work.metrics
        try:
            if (work.limits is not configured.limits
                    or configured.ceilings != (work.limits.max_hashes,
                        work.limits.max_input_bytes, work.limits.max_json_nodes)
                    or before.hash_work < self._metrics.hash_work
                    or before.input_bytes < self._metrics.input_bytes
                    or before.json_nodes < self._metrics.json_nodes):
                _fail("release grant issuer replaced or reset its work allowance")
            work.charge(input_bytes=4096)
            production._callback(work, self._identity)
            for guard in (configured.delivery_current, configured.material.live):
                epoch = guard()
                bootstrap.shape._integer(epoch, minimum=1)
                if epoch < self._last_epoch:
                    _fail("release grant issuer original authority clocks reversed")
                self._last_epoch = epoch
            epoch = clock._check_on_work(self._window, work=work)
            monotonic = production._callback(work, time.monotonic_ns)
            if (type(monotonic) is not int or monotonic < self._last_monotonic
                    or epoch < self._last_epoch or epoch >= self._window[3] or monotonic >= self._bound):
                _fail("release grant issuer narrowed processing clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, monotonic
            after = work.metrics
            if (work.limits is not configured.limits
                    or configured.ceilings != (work.limits.max_hashes,
                        work.limits.max_input_bytes, work.limits.max_json_nodes)
                    or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                    or after.json_nodes < before.json_nodes):
                _fail("release grant issuer current guard reset its work")
            self._metrics = after
            return epoch
        except BaseException:
            self._failed = True
            raise

    def _continuity(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int or epoch < 1 or monotonic < 1):
            _fail("release grant issuer producer supplied invalid restrictive clock floors")
        self._last_epoch = max(self._last_epoch, epoch)
        self._last_monotonic = max(self._last_monotonic, monotonic)
        self._current()
        return self._last_epoch, self._last_monotonic

    def _narrow(self, expiry):
        configured = self._configured
        narrowed = bootstrap.processing._narrow(self._window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=min(self._window[5], configured.control_age),
            maximum_clock_skew_ns=min(self._window[6], configured.control_skew))
        self._window = self._window_seal = narrowed
        self._bound = self._bound_seal = min(self._bound, narrowed[4])
        self._current()

    def _close_connection(self, *, guarded):
        global _cleanup_failed
        connection = self._connection
        if connection is None:
            return
        if self._connection_close_attempted:
            _cleanup_failed = True
            _fail("release grant issuer cannot retry indeterminate socket cleanup")
        if guarded:
            self._current()
        self._connection_close_attempted = True
        try:
            if self._connection_identity is None:
                _fail("release grant issuer accepted socket identity was not established")
            held, descriptor, identity = self._connection_identity
            if (connection is not held or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity):
                _fail("release grant issuer socket cleanup identity changed")
            if guarded:
                self._configured.work.charge(input_bytes=1)
                production._callback(self._configured.work, connection.close)
            else:
                connection.close()
            if connection.fileno() != -1:
                _fail("release grant issuer socket closure is indeterminate")
        except BaseException:
            _cleanup_failed = True
            # Retain uncertain objects; never let a dropped reference close a
            # replacement FD through a socket destructor.
            _quarantined.append(connection)
            raise
        self._connection = self._connection_identity = self._connection_peer = None
        if guarded:
            self._current()

    def _produce(self, originals):
        configured, work = self._configured, self._configured.work
        material = configured.material
        self._current()
        if (configured.input_bytes + sum(map(len, originals)) + transport.REQUEST_HEADER_BYTES
                + transport.RESPONSE_HEADER_BYTES + transport.MAX_RESPONSE_BYTES > bootstrap.MAX_ORIGINAL_BYTES):
            _fail("release grant issuer complete held exchange exceeds 64 MiB")
        response = producer._produce_on_work(request_originals=originals[1:],
            issuer_policy_bytes=material.issuer_policy_bytes,
            proof_bootstrap_bytes=material.proof_bootstrap_bytes,
            root_private_key=configured.key, root_public_key=configured.root,
            live_window=self._window, transport_deadline_ns=self._bound,
            work=work, _continuity=self._continuity)
        self._current()
        response = transport._originals(response, response=True)
        # The exact actual producer already authenticated both originals. This
        # bounded data-only read only tightens the same lifetime through send
        # and normal close; it cannot accept an incoming successful carrier.
        payload = producer.clients._read(response[0], work)["payload"]
        self._narrow(payload["expiresAtEpochNs"])
        self._current()
        return response

    def serve_once(self):
        """Spend once before readiness/accept; success requires normal close."""
        global _state
        with _LOCK:
            self._current()
            if self._spent or self._connection is not None:
                _fail("release grant issuer cannot repeat its exchange")
            self._spent = True
            configured, work = self._configured, self._configured.work
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
                        _fail("release grant issuer peer is not the fixed control-plane caller")

                work.charge(input_bytes=4096)
                self._current()
                remaining = transport.io._check_deadline(self._bound) / 1_000_000_000
                ready, _writers, exceptional = production._callback(work,
                    lambda: select.select((configured.listener,), (), (configured.listener,), remaining))
                self._current()
                if not ready or exceptional:
                    _fail("release grant issuer readiness was not established")
                self._current()
                production._callback(work, accept)
                self._current()
                originals = transport._recv_request(self._connection, deadline_ns=self._bound,
                    work=work, current=self._current)
                response = self._produce(originals)
                del originals
                self._current()
                transport._send_response(self._connection, response, deadline_ns=self._bound,
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
                raise ReleaseGrantIssuerStartupError(
                    "release grant issuance is not established; automatic retry is prohibited") from None

    def close(self):
        if self is not _owner:
            _fail("release grant issuer cleanup requires its actual owner")
        close()


def initialize_from_environment(*, work, live_window, transport_deadline_ns, delivery_current):
    """Continue same-PID root delivery without any new processing allowance."""
    global _state, _owner, _listener_object
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware.authority_query_read_work import _ValidationWork

    _pid()
    with _LOCK:
        if _state != "new":
            _fail("release grant issuer startup cannot restart")
        _state = "initializing"
        namespace, material = _environment(), None
        try:
            if type(work) is not _ValidationWork or not callable(delivery_current):
                _fail("release grant issuer requires actual inherited work and delivery continuity")
            capture._SharedLedger(work)
            limits = work.limits
            ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
            metrics = work.metrics
            window = clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            bound = min(transport_deadline_ns, window[4])
            last_epoch, last_monotonic = window[0], window[2]
            sealed = ()
            listener_pins = None

            def current():
                nonlocal last_epoch, last_monotonic, metrics
                capture._SharedLedger(work)
                before = work.metrics
                if (work.limits is not limits or ceilings != (limits.max_hashes,
                        limits.max_input_bytes, limits.max_json_nodes)
                        or before.hash_work < metrics.hash_work or before.input_bytes < metrics.input_bytes
                        or before.json_nodes < metrics.json_nodes):
                    _fail("release grant issuer construction reset its original work")
                work.charge(input_bytes=4096)
                production._callback(work, lambda: _process(namespace))
                for descriptor, maximum, private, identity in sealed:
                    if production._callback(work, lambda: delivery._sealed_identity(
                            descriptor, maximum, private=private)) != identity:
                        _fail("release grant issuer construction original FD changed")
                if listener_pins is not None:
                    if production._callback(work, lambda: delivery._listener(delivery.LISTENER_FD)) != listener_pins:
                        _fail("release grant issuer construction listener changed")
                production._callback(work, lambda: delivery._require_inventory(delivery.INHERITED_DESCRIPTORS))
                for guard in ((delivery_current,) if material is None else (delivery_current, material.live)):
                    epoch = guard()
                    bootstrap.shape._integer(epoch, minimum=1)
                    if epoch < last_epoch:
                        _fail("release grant issuer construction authority clocks reversed")
                    last_epoch = epoch
                epoch = clock._check_on_work(window, work=work)
                monotonic = production._callback(work, time.monotonic_ns)
                if (type(monotonic) is not int or monotonic < last_monotonic
                        or epoch < last_epoch or epoch >= window[3] or monotonic >= bound):
                    _fail("release grant issuer construction clocks expired or reversed")
                last_epoch, last_monotonic = epoch, monotonic
                after = work.metrics
                if (work.limits is not limits or ceilings != (limits.max_hashes,
                        limits.max_input_bytes, limits.max_json_nodes)
                        or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                        or after.json_nodes < before.json_nodes):
                    _fail("release grant issuer construction guard reset its work")
                metrics = after
                return epoch

            current()
            work.charge(input_bytes=4096)
            for descriptor in delivery.INHERITED_DESCRIPTORS:
                _owned[descriptor] = production._callback(work, lambda: _fd_identity(descriptor))
            descriptions = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False),
                (delivery.POLICY_FD, delivery.MAX_POLICY_BYTES, False),
                (delivery.PROOF_BOOTSTRAP_FD, delivery.MAX_PROOF_BOOTSTRAP_BYTES, False),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True))
            sealed = tuple((descriptor, maximum, private, production._callback(work,
                lambda: delivery._sealed_identity(descriptor, maximum, private=private)))
                for descriptor, maximum, private in descriptions)
            current()
            sizes = production._callback(work, lambda: tuple(os.fstat(descriptor).st_size
                for descriptor, _maximum, _private in descriptions))
            if (sum(sizes) + transport.REQUEST_HEADER_BYTES + transport.MAX_REQUEST_BYTES
                    + transport.RESPONSE_HEADER_BYTES + transport.MAX_RESPONSE_BYTES > bootstrap.MAX_ORIGINAL_BYTES):
                _fail("release grant issuer cold originals and bounded exchange exceed 64 MiB")
            raws = []
            for descriptor, maximum, _private, identity in sealed[:-1]:
                current()
                raw, observed = delivery._read_on_work(descriptor, maximum, work)
                current()
                if observed != identity:
                    _fail("release grant issuer original changed during inherited read")
                raws.append(raw)
            root_raw, bootstrap_raw, policy_raw, proof_raw = raws
            work.charge(input_bytes=len(root_raw))
            current()
            root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                _fail("release grant issuer requires the actual Ed25519 runtime root")
            current()
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, issuer_policy_bytes=policy_raw,
                proof_bootstrap_bytes=proof_raw, root_public_key=root, live_window=window,
                transport_deadline_ns=bound, work=work)
            if type(material) is not bootstrap._IssuerMaterial:
                _fail("release grant issuer requires actual original launch admission")
            current()
            selected = clock._validate(material.live_window)
            if (selected[:3] != window[:3] or material.deadline_ns > bound
                    or any(value > prior for value, prior in zip(selected[3:], window[3:]))):
                _fail("release grant issuer bootstrap widened the inherited allowance")
            window, bound = selected, min(bound, material.deadline_ns, selected[4])
            launch = material.launch
            if (tuple(launch[name] for name, _fd in bootstrap._FD_FIELDS) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS
                    or (launch["listenerPath"], launch["peerUid"], launch["peerGid"])
                        != (transport.LISTENER_PATH, transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("release grant issuer launch changed the fixed inventory or peer")
            timeout_ns = launch["requestTimeoutSeconds"] * 1_000_000_000
            window = bootstrap.processing._narrow(window, deadline_epoch_ns=window[0] + timeout_ns,
                maximum_lifetime_ns=min(window[5], timeout_ns), maximum_clock_skew_ns=window[6])
            bound = min(bound, window[4])
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            current()
            # Limited original enrollment readback preserves the producer's
            # tighter COMPLETE control policy through response send/close.
            proof = material.policy_material.proof_material
            enrolled = producer.state._admit_enrollment_on_work(
                enrollment_bytes=proof.completion_material.current_root_enrollment_bytes,
                root_public_key=root, work=work)
            current()
            age, skew = enrolled.payload["maxControlAgeNs"], enrolled.payload["maxClockSkewNs"]
            window = bootstrap.processing._narrow(window, deadline_epoch_ns=window[3],
                maximum_lifetime_ns=min(window[5], age), maximum_clock_skew_ns=min(window[6], skew))
            bound = min(bound, window[4])
            current()
            key = delivery._key_on_work(material, root, work, current=current)
            current()

            def wrap_listener():
                global _listener_object
                _listener_object = socket.socket(fileno=delivery.LISTENER_FD)

            work.charge(input_bytes=4096)
            production._callback(work, wrap_listener)
            current()
            configured = _Configuration(material, root, key, work, limits, ceilings, window, bound,
                delivery_current, namespace, sealed, _listener_object, listener_pins, sum(sizes), age, skew)
            owner = object.__new__(_IssuerOwner)
            owner._configured = owner._seal = configured
            owner._window = owner._window_seal = window
            owner._bound = owner._bound_seal = bound
            owner._last_epoch, owner._last_monotonic, owner._metrics = last_epoch, last_monotonic, work.metrics
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
            raise ReleaseGrantIssuerStartupError("release grant issuer cold construction failed") from None


def require_started():
    _pid()
    with _LOCK:
        if type(_owner) is not _IssuerOwner:
            _fail("release grant issuer has not genuinely started")
        _owner._current()
        return _owner


def close():
    """Truthful one-attempt cleanup; failure status survives repeated close."""
    global _state, _cleanup_failed
    _pid()
    with _LOCK:
        owner = _owner
        if owner is not None and not owner._closed:
            owner._closed = owner._failed = True
            try:
                owner._close_connection(guarded=False)
            except BaseException:
                _cleanup_failed = True
        _state = "closed"
        _cleanup_inherited()
