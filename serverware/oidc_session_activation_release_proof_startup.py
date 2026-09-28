"""One original-bound proof worker, not a completion or plaintext-release owner.

Only the genuine root-delivery continuation constructs this process-bound
owner. It retains one work ledger/window, one peer-checked connection, private
historical custody and two read-only readers. No completion signer, journal,
state client, SQL execution, token persistence or exchange retry is present.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_release_proof_entrypoint as delivery
from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap
from serverware import authority_oidc_session_activation_release_proof_production as producer
from serverware import authority_oidc_session_activation_release_proof_transport as transport
from serverware import authority_successor_execution_owner as packets


historical, committed = producer.custody, producer.reader
capture, clock, production = bootstrap.capture, bootstrap.clock, bootstrap.production
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner = "new", None
_owned, _cleanup_failed = {}, False


class ReleaseProofStartupError(RuntimeError):
    pass


def _fail(message):
    raise ReleaseProofStartupError(message)


def _pid():
    if os.getpid() != _PID:
        _fail("release proof worker cannot continue in a different PID")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    _pid()
    if (_environment() != namespace or namespace != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (65497,) * 3 or os.getresgid() != (65497,) * 3
            or os.getgroups() or os.environ.get("SERVERWARE_PROCESS_MODE") != transport.PROCESS_MODE):
        _fail("release proof process or closed inherited environment differs")
    delivery._require_unprivileged_process()


def _fd_identity(descriptor):
    value = os.fstat(descriptor)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_rdev


def _reader_arguments(configuration):
    dsn, timeout, role, client_dn, serial, issuer_dn, query, structure = configuration
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "database_role": role,
        "tls_client_dn": client_dn, "tls_client_serial": serial, "tls_issuer_dn": issuer_dn,
        "query_manifest_digest": query, "expected_structure_manifest_digest": structure}


def _close_inherited():
    """Attempt each still-owned original once; never close a replacement FD."""
    global _cleanup_failed
    _pid()
    for descriptor, identity in tuple(_owned.items()):
        del _owned[descriptor]
        try:
            if _fd_identity(descriptor) != identity:
                _cleanup_failed = True
                continue
            os.close(descriptor)
        except OSError:
            # Normally closed listener ownership is removed explicitly. An
            # absent still-owned descriptor is therefore indeterminate too.
            _cleanup_failed = True
        except BaseException:
            _cleanup_failed = True
    if _cleanup_failed:
        _fail("release proof inherited cleanup is not established")


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
    tls: tuple
    historical: object
    historical_configuration: object
    custody_live: object
    packet_reader: object
    packet_configuration: tuple
    commit_reader: object
    commit_configuration: tuple
    delivery_retained_bytes: int | None = None
    retained_bytes: int = 0


class _ProofOwner:
    __slots__ = ("_configured", "_seal", "_window", "_window_seal", "_bound", "_bound_seal",
        "_last_epoch", "_last_monotonic", "_custody_live", "_accepted", "_spent", "_failed",
        "_closed", "_connection", "_connection_identity")

    def __init__(self):
        _fail("release proof requires actual original cold construction")

    def _identity(self):
        _pid()
        configured = self._configured
        if (type(self) is not _ProofOwner or self is not _owner or _state != "started"
                or self._closed or self._failed or configured is not self._seal
                or type(configured) is not _Configuration
                or self._custody_live is not configured.custody_live
                or self._window is not self._window_seal or self._bound != self._bound_seal
                or self._window[:3] != configured.window[:3]
                or any(new > old for new, old in zip(self._window[3:], configured.window[3:]))
                or self._bound > min(configured.deadline_ns, self._window[4])):
            _fail("release proof owner or original processing lifetime changed")
        _process(configured.namespace)
        for descriptor, maximum, private, identity in configured.sealed:
            if delivery._sealed_identity(descriptor, maximum, private=private) != identity:
                _fail("release proof inherited original identity changed")
        if (delivery._listener(delivery.LISTENER_FD) != configured.listener_pins
                or configured.listener.fileno() != delivery.LISTENER_FD
                or historical.OidcSessionActivationDeliveryCompletionCustody._snapshot_configuration(
                    configured.historical) is not configured.historical_configuration
                or packets.SuccessorExecutionRecoveryReader._snapshot_configuration(
                    configured.packet_reader) is not configured.packet_configuration
                or committed.CurrentRootCommitReader._snapshot_configuration(
                    configured.commit_reader) is not configured.commit_configuration):
            _fail("release proof private readers or original custody changed")
        delivery._tls_unchanged(configured.tls)
        inventory = delivery.INHERITED_DESCRIPTORS
        if self._connection is not None:
            connection, descriptor, identity = self._connection_identity
            if (self._connection is not connection or connection.fileno() != descriptor
                    or _fd_identity(descriptor) != identity or connection.gettimeout() != 0.0
                    or connection.get_inheritable()):
                _fail("release proof accepted connection ownership changed")
            inventory += (descriptor,)
        elif self._connection_identity is not None:
            _fail("release proof connection identity lost its owned socket")
        delivery._require_inventory(inventory)

    def _current(self):
        configured, work = self._configured, self._configured.work
        capture._SharedLedger(work)
        before = work.metrics
        try:
            if (work.limits is not configured.limits
                    or configured.ceilings != (work.limits.max_hashes,
                        work.limits.max_input_bytes, work.limits.max_json_nodes)):
                _fail("release proof work allowance was replaced")
            if configured.delivery_retained_bytes is not None:
                from serverware import oidc_session_activation_release_proof_dynamic_entrypoint as dynamic

                if dynamic._retained_bytes_on_work(configured.delivery_current, work) != configured.delivery_retained_bytes:
                    _fail("release proof dynamic retained inventory changed")
            work.charge(input_bytes=4096)
            production._callback(work, self._identity)
            for guard in (configured.delivery_current, configured.material.live, self._custody_live):
                epoch = guard()
                bootstrap.shape._integer(epoch, minimum=1)
                if epoch < self._last_epoch:
                    _fail("release proof current original clocks reversed")
                self._last_epoch = epoch
            epoch = clock._check_on_work(self._window, work=work)
            monotonic = production._callback(work, time.monotonic_ns)
            bootstrap.shape._integer(monotonic, minimum=1)
            if (epoch < self._last_epoch or monotonic < self._last_monotonic
                    or epoch >= self._window[3] or monotonic >= self._bound):
                _fail("release proof inherited clock bracket expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, monotonic
            after = work.metrics
            if (work.limits is not configured.limits
                    or configured.ceilings != (work.limits.max_hashes,
                        work.limits.max_input_bytes, work.limits.max_json_nodes)
                    or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                    or after.json_nodes < before.json_nodes):
                _fail("release proof guard reset its cumulative work")
            return epoch
        except BaseException:
            self._failed = True
            raise

    def _continuity(self, epoch, monotonic):
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < 1 or monotonic < 1):
            _fail("release proof producer supplied invalid restrictive clock floors")
        self._last_epoch = max(self._last_epoch, epoch)
        self._last_monotonic = max(self._last_monotonic, monotonic)
        self._current()
        return self._last_epoch, self._last_monotonic

    def _narrow(self, expiry, age, skew):
        narrowed = bootstrap.processing._narrow(self._window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
        self._window = self._window_seal = narrowed
        self._bound = self._bound_seal = min(self._bound, narrowed[4])
        self._current()

    def _close_connection(self, *, guarded):
        global _cleanup_failed
        if self._connection is None:
            return
        if guarded:
            self._current()
        connection, descriptor, identity = self._connection_identity
        # Keep a changed socket object referenced rather than letting its
        # destructor close an unrelated replacement descriptor.
        if (self._connection is not connection or connection.fileno() != descriptor
                or _fd_identity(descriptor) != identity):
            _cleanup_failed = True
            _fail("release proof connection cleanup identity is indeterminate")
        try:
            if guarded:
                self._configured.work.charge(input_bytes=1)
                production._callback(self._configured.work, connection.close)
            else:
                connection.close()
        except BaseException:
            _cleanup_failed = True
            raise
        finally:
            self._connection = self._connection_identity = None
        if guarded:
            self._current()

    def _produce(self, originals):
        configured, work = self._configured, self._configured.work
        material, completion = configured.material, configured.material.completion_material
        self._current()
        intent_digest = producer.intent.contract._digest(material.intent_bytes, work)
        work.prepare_utf8(intent_digest)
        expected = intent_digest.encode("ascii")
        work.charge(input_bytes=len(expected) + len(originals[1]))
        if originals[1] != expected:
            _fail("release proof request differs from the independently pinned intent")
        old_token = producer.delivery._token(originals[2], work)
        self._current()
        sequence, head, fence = completion.current_pending
        extra = {}
        reserved = 0
        bridged = completion.custody_material.bridge_policy_interval is not None
        bounded_packet = configured.delivery_retained_bytes is not None or bridged
        packet_copies = 3
        if bounded_packet:
            reserved = (configured.retained_bytes + transport.MAX_REQUEST_BYTES + transport.REQUEST_HEADER_BYTES
                + transport.MAX_RESPONSE_BYTES + transport.RESPONSE_HEADER_BYTES + 2 * producer.MAX_GRAPH_BYTES)
            if bridged:
                producer_originals = (material.completion_request_bytes, material.state_receipt_bytes,
                    completion.authorization_bytes, completion.authorization_enrollment_bytes,
                    completion.grant_enrollment_bytes, completion.current_root_enrollment_bytes,
                    material.release_custody_bytes, material.intent_bytes,
                    material.intent_enrollment_bytes, material.proof_enrollment_bytes, old_token)
                reserved += (8 * sum(map(len, producer_originals)) + 4 * producer.MAX_GRAPH_BYTES
                    + producer.contract.MAX_BYTES
                    + 8 * len(configured.historical_configuration.historical_configuration.custody_bytes)
                    + 4 * len(completion.current_root_enrollment_bytes) + 64 * 1024)
                # Retain the reader's three copies as well as all eight new
                # producer captures before the first selected packet body.
                packet_copies += 8
            maximum_packet = min(packets.packet.MAX_BYTES,
                (bootstrap.MAX_ORIGINAL_BYTES - reserved) // packet_copies)
            if maximum_packet < 2:
                _fail("release proof dynamic originals leave no packet-read capacity")
            extra = {"maximum_packet_bytes": maximum_packet}
        if configured.delivery_retained_bytes is not None:
            # This exact original delivery guard permits only the real reader
            # to own its transient DB descriptors. Full worker inventory is
            # checked immediately before and after the genuine read.
            extra["_current"] = configured.delivery_current
        packet = packets.SuccessorExecutionRecoveryReader.read(configured.packet_reader,
            pending_decision_digest=head, packet_digest=completion.packet_digest,
            live_window=self._window, transport_deadline_ns=self._bound, work=work, **extra)
        self._current()
        if (type(packet) is not bytes or len(packet) < 2
                or len(packet) + len(material.bootstrap_bytes) + len(old_token)
                    + transport.MAX_RESPONSE_BYTES > bootstrap.MAX_ORIGINAL_BYTES):
            _fail("release proof retained originals and reserved response exceed 64 MiB")
        if bounded_packet and reserved + packet_copies * len(packet) > bootstrap.MAX_ORIGINAL_BYTES:
            _fail("release proof packet exceeds its complete reserved inventory")
        proof = producer._produce_on_work(packet_bytes=packet,
            completion_request_bytes=material.completion_request_bytes,
            state_receipt_bytes=material.state_receipt_bytes,
            expected_consume_binding=material.expected_consume_binding,
            expected_release=material.expected_release, expectations=completion.expectations,
            planner_public_key=completion.planner_public_key,
            operation_public_key=completion.operation_public_key, root_public_key=configured.root,
            authorization_bytes=completion.authorization_bytes,
            authorization_enrollment_bytes=completion.authorization_enrollment_bytes,
            grant_enrollment_bytes=completion.grant_enrollment_bytes,
            current_root_enrollment_bytes=completion.current_root_enrollment_bytes,
            configuration_digest=completion.configuration_digest,
            expected_authorization_digest=completion.authorization_digest,
            expected_database_id=completion.database_id,
            expected_generation_digest=completion.generation_digest,
            expected_pending_sequence=sequence, expected_pending_head_digest=head,
            expected_fence=fence, historical_custody=configured.historical,
            commit_reader=configured.commit_reader, live_window=self._window,
            transport_deadline_ns=self._bound, release_custody_bytes=material.release_custody_bytes,
            intent_bytes=material.intent_bytes, intent_enrollment_bytes=material.intent_enrollment_bytes,
            proof_enrollment_bytes=material.proof_enrollment_bytes, proof_private_key=configured.key,
            expected_proof_scope=material.expected_proof_scope, expected_caller_id=material.caller_id,
            old_token_bytes=old_token, work=work, _continuity=self._continuity)
        # Producer has already authenticated its exact output. This data-only
        # read can only tighten the same worker lifetime through send/close.
        self._current()
        payload = producer.contract._read(proof, work)["payload"]
        self._narrow(payload["expiresAtEpochNs"], self._window[5], self._window[6])
        response = (b"proved", material.release_custody_bytes, proof, material.proof_enrollment_bytes)
        transport._originals(response, response=True)
        self._current()
        return response

    def serve_once(self):
        """Wait once within the original deadline; accept and produce at most once."""
        global _state
        with _LOCK:
            self._current()
            if self._accepted or self._spent or self._connection is not None:
                _fail("release proof worker cannot repeat its exchange")
            self._accepted = self._spent = True
            configured, work = self._configured, self._configured.work
            try:
                def accept():
                    connection, _address = configured.listener.accept()
                    # Own the actual object immediately, before any fallible
                    # flag/identity work or callback suffix can lose it.
                    self._connection = connection
                    descriptor = connection.fileno()
                    self._connection_identity = connection, descriptor, _fd_identity(descriptor)
                    connection.setblocking(False)
                    connection.set_inheritable(False)

                work.charge(input_bytes=4096)
                self._current()
                remaining = transport.io._check_deadline(self._bound) / 1_000_000_000
                ready, _writers, exceptional = production._callback(work,
                    lambda: select.select((configured.listener,), (), (configured.listener,), remaining))
                self._current()
                if not ready or exceptional:
                    _fail("release proof listener readiness was not established")
                self._current()
                production._callback(work, accept)
                self._current()
                originals = transport._recv_request(self._connection, deadline_ns=self._bound,
                    work=work, current=self._current)
                self._current()
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
                raise ReleaseProofStartupError(
                    "release proof exchange is not established; automatic retry is prohibited") from None


def initialize_from_environment(*, work, live_window, transport_deadline_ns, delivery_current):
    """Continue the actual root delivery, without opening another allowance."""
    return _initialize(work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        delivery_current=delivery_current, retained_bytes=None)


def _initialize_from_dynamic_delivery_on_work(*, work, live_window, transport_deadline_ns, delivery_current):
    """Require this PID's real sealed dynamic delivery and measured capacity."""
    from serverware import oidc_session_activation_release_proof_dynamic_entrypoint as dynamic

    retained = dynamic._retained_bytes_on_work(delivery_current, work,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    return _initialize(work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        delivery_current=delivery_current, retained_bytes=retained)


def _initialize(*, work, live_window, transport_deadline_ns, delivery_current, retained_bytes):
    global _state, _owner
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from serverware.authority_query_read_work import _ValidationWork

    _pid()
    with _LOCK:
        if _state != "new":
            _fail("release proof startup cannot restart or accept another configuration")
        _state = "initializing"
        namespace = _environment()
        material = historical_owner = listener = custody_live = None
        try:
            if type(work) is not _ValidationWork or not callable(delivery_current):
                _fail("release proof requires its actual inherited work and delivery guard")
            capture._SharedLedger(work)
            limits = work.limits
            ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
            window = clock._validate(live_window)
            bootstrap.shape._integer(transport_deadline_ns, minimum=1)
            bound = min(transport_deadline_ns, window[4])
            last_epoch, last_monotonic = window[0], window[2]
            sealed = ()

            def current():
                nonlocal last_epoch, last_monotonic
                capture._SharedLedger(work)
                before = work.metrics
                if (work.limits is not limits or ceilings != (limits.max_hashes,
                        limits.max_input_bytes, limits.max_json_nodes)):
                    _fail("release proof construction replaced its original work")
                work.charge(input_bytes=4096)
                production._callback(work, lambda: _process(namespace))
                for descriptor, maximum, private, identity in sealed:
                    if production._callback(work, lambda: delivery._sealed_identity(
                            descriptor, maximum, private=private)) != identity:
                        _fail("release proof construction inherited descriptor changed")
                guards = (delivery_current,)
                if material is not None:
                    guards += (material.live,)
                if custody_live is not None:
                    guards += (custody_live,)
                for guard in guards:
                    epoch = guard()
                    bootstrap.shape._integer(epoch, minimum=1)
                    if epoch < last_epoch:
                        _fail("release proof original construction clock reversed")
                    last_epoch = epoch
                epoch = clock._check_on_work(window, work=work)
                monotonic = production._callback(work, time.monotonic_ns)
                if (type(monotonic) is not int or monotonic < last_monotonic
                        or epoch < last_epoch or monotonic >= bound):
                    _fail("release proof construction clock expired or reversed")
                last_epoch, last_monotonic = epoch, monotonic
                after = work.metrics
                if (work.limits is not limits or after.hash_work < before.hash_work
                        or after.input_bytes < before.input_bytes or after.json_nodes < before.json_nodes):
                    _fail("release proof construction guard reset its original work")
                return epoch

            current()
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            for descriptor in delivery.INHERITED_DESCRIPTORS:
                _owned[descriptor] = _fd_identity(descriptor)
            descriptions = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True),
                *((descriptor, delivery.MAX_RAW_KEY_BYTES, True) for descriptor in
                    (delivery.EXECUTION_BUNDLE_KEY_FD, delivery.HISTORICAL_BUNDLE_KEY_FD,
                        delivery.DELIVERY_KEY_FD)))
            work.charge(input_bytes=4096)
            sealed = tuple((descriptor, maximum, private, production._callback(work,
                lambda: delivery._sealed_identity(descriptor, maximum, private=private)))
                for descriptor, maximum, private in descriptions)
            current()
            root_raw, root_identity = delivery._read_on_work(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, work)
            current()
            bootstrap_raw, bootstrap_identity = delivery._read_on_work(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, work)
            current()
            if root_identity != sealed[0][3] or bootstrap_identity != sealed[1][3]:
                _fail("release proof initial original identities changed")
            retained_total = 0
            if retained_bytes is not None:
                reserved = (retained_bytes + len(root_raw) + len(bootstrap_raw)
                    + 16 * len(bootstrap_raw) + transport.MAX_RESPONSE_BYTES + transport.RESPONSE_HEADER_BYTES
                    + transport.MAX_REQUEST_BYTES + transport.REQUEST_HEADER_BYTES + 2 * producer.MAX_GRAPH_BYTES)
                if reserved >= bootstrap.MAX_ORIGINAL_BYTES:
                    _fail("release proof dynamic second admission exceeds the complete allocation reserve")
            work.charge(input_bytes=len(root_raw))
            root = production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                _fail("release proof requires its actual Ed25519 public root")
            extra = {} if retained_bytes is None else {"_current": delivery_current}
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root,
                live_window=window, transport_deadline_ns=bound, work=work, **extra)
            current()
            if type(material) is not bootstrap._ProofMaterial:
                _fail("release proof cold originals did not yield actual same-call material")
            if (retained_bytes is not None
                    or material.completion_material.custody_material.bridge_policy_interval is not None):
                from serverware import oidc_session_activation_release_proof_dynamic_entrypoint as dynamic

                retained_total = ((0 if retained_bytes is None else retained_bytes) + len(root_raw) + len(bootstrap_raw)
                    + 2 * dynamic._material_bytes_on_work(material, work, current))
                if retained_total + transport.MAX_RESPONSE_BYTES + 2 * producer.MAX_GRAPH_BYTES >= bootstrap.MAX_ORIGINAL_BYTES:
                    _fail("release proof dynamic reread and private custody exhaust retained capacity")
            narrowed = clock._validate(material.live_window)
            if (narrowed[:3] != window[:3]
                    or any(new > old for new, old in zip(narrowed[3:], window[3:]))
                    or material.deadline_ns > bound):
                _fail("release proof bootstrap widened the original processing allowance")
            window, bound = narrowed, min(bound, material.deadline_ns, narrowed[4])
            launch = material.launch
            if (tuple(launch[name] for name, _fd in bootstrap._FD_FIELDS) != delivery.INHERITED_DESCRIPTORS
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS
                    or (launch["listenerPath"], launch["peerUid"], launch["peerGid"])
                        != (transport.LISTENER_PATH, transport.REQUEST_PEER_UID, transport.REQUEST_PEER_GID)):
                _fail("release proof launch differs from the fixed worker inventory")
            timeout_ns = launch["requestTimeoutSeconds"] * 1_000_000_000
            window = bootstrap.processing._narrow(window,
                deadline_epoch_ns=window[0] + timeout_ns,
                maximum_lifetime_ns=min(window[5], timeout_ns),
                maximum_clock_skew_ns=window[6])
            bound = min(bound, window[4])
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            current()
            if production._callback(work, lambda: delivery._listener(delivery.LISTENER_FD)) != listener_pins:
                _fail("release proof listener differs from root-admitted pins")
            key, execution_key, historical_key, delivery_key = delivery._keys_on_work(
                material, work, current=current)
            current()
            completion = material.completion_material
            historical_owner = historical.OidcSessionActivationDeliveryCompletionCustody(
                custody_bytes=completion.custody_bytes,
                planner_bootstrap_bytes=completion.planner_bootstrap_bytes,
                planner_history_custody_bytes=completion.planner_history_custody_bytes,
                receiving_history_custody_bytes=completion.receiving_history_custody_bytes,
                root_public_key=root, expected_receiver_identity=completion.receiver_identity,
                execution_bundle_key=execution_key, historical_bundle_key=historical_key,
                delivery_custody_key=delivery_key, live_window=window, transport_deadline_ns=bound, work=work)
            del execution_key, historical_key, delivery_key
            current()
            historical.OidcSessionActivationDeliveryCompletionCustody.bind_context_on_work(
                historical_owner, root_public_key=completion.evidence_root_public_key,
                current_root_enrollment_bytes=completion.current_root_enrollment_bytes, work=work)
            window, bound = historical.OidcSessionActivationDeliveryCompletionCustody.processing_bounds_on_work(
                historical_owner, live_window=window, transport_deadline_ns=bound, work=work)
            custody_live = historical.OidcSessionActivationDeliveryCompletionCustody.check_on_work(
                historical_owner, live_window=window, transport_deadline_ns=bound, work=work)
            current()
            tls = delivery._tls_identity(completion.tls_files, work=work, current=current)
            current()
            arguments = _reader_arguments(completion.custody_configuration)
            del arguments["database_role"]
            packet_reader = packets.SuccessorExecutionRecoveryReader(**arguments)
            commit_reader = committed.CurrentRootCommitReader(**_reader_arguments(completion.commit_configuration))
            current()

            def wrap_listener():
                nonlocal listener
                listener = socket.socket(fileno=delivery.LISTENER_FD)

            work.charge(input_bytes=4096)
            production._callback(work, wrap_listener)
            current()
            configured = _Configuration(material, root, key, work, limits, ceilings, window, bound,
                delivery_current, namespace, sealed, listener, listener_pins, tls, historical_owner,
                historical.OidcSessionActivationDeliveryCompletionCustody._snapshot_configuration(historical_owner),
                custody_live,
                packet_reader, packets.SuccessorExecutionRecoveryReader._snapshot_configuration(packet_reader),
                commit_reader, committed.CurrentRootCommitReader._snapshot_configuration(commit_reader),
                retained_bytes, retained_total)
            owner = object.__new__(_ProofOwner)
            owner._configured = owner._seal = configured
            owner._window = owner._window_seal = window
            owner._bound = owner._bound_seal = bound
            owner._last_epoch, owner._last_monotonic = last_epoch, last_monotonic
            owner._custody_live = custody_live
            owner._accepted = owner._spent = owner._failed = owner._closed = False
            owner._connection = owner._connection_identity = None
            _owner, _state = owner, "started"
            owner._current()
            return owner
        except BaseException:
            _state = "failed"
            if historical_owner is not None:
                try:
                    historical.OidcSessionActivationDeliveryCompletionCustody.close(historical_owner)
                except BaseException:
                    pass
            if listener is not None:
                try:
                    if _fd_identity(listener.fileno()) == _owned.get(delivery.LISTENER_FD):
                        listener.close()
                        _owned.pop(delivery.LISTENER_FD, None)
                except BaseException:
                    pass
            try:
                _close_inherited()
            except BaseException:
                pass
            raise ReleaseProofStartupError("release proof cold construction failed") from None


def require_started():
    _pid()
    with _LOCK:
        if type(_owner) is not _ProofOwner:
            _fail("release proof worker has not been genuinely started")
        _owner._current()
        return _owner


def close():
    """Truthful best-effort cleanup, without retry or removal of retained data."""
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
            configured = owner._configured
            try:
                historical.OidcSessionActivationDeliveryCompletionCustody.close(configured.historical)
            except BaseException:
                _cleanup_failed = True
            try:
                if (_fd_identity(delivery.LISTENER_FD) != _owned.get(delivery.LISTENER_FD)
                        or configured.listener.fileno() != delivery.LISTENER_FD):
                    _cleanup_failed = True
                else:
                    configured.listener.close()
                    _owned.pop(delivery.LISTENER_FD, None)
            except BaseException:
                _cleanup_failed = True
        _state = "closed"
        _close_inherited()
