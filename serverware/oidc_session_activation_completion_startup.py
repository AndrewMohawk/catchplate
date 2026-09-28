"""Cold activation completion recovery under dedicated signing/AES custody.

The root-signed launch independently binds one packet/authorization/pending
scope, historical expectations, protected readers and a completion-journal
checkpoint. The peer cannot choose a key, database or historical context.
Genuine packet replay and committed-state readback stay in the actual owners.
The independently admitted historical owner retains distinct bundle/delivery
keys; no live receiver is relabelled and no expired planner launch is renewed.

One request work/window opens before peer/frame/body reads. One accepted
connection ends the launch, including malformed or unauthorized requests.
Previously retained completions are reused unchanged; this worker never
executes SQL mutations, replaces a completion signature or renews its expiry.
Completion and state acknowledgment are durable before a successful response.
These local checks are not off-host currentness, hostile-root protection,
session activation or a hard syscall watchdog.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_completion_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None
OPERATION = "oidc.session.activate"


class CompletionStartupError(RuntimeError):
    """Terminal cold/lifecycle failure; this process cannot renew admission."""


class CompletionRequestError(RuntimeError):
    """Terminal exchange failure; completion or acknowledgment may be durable."""


def _require_pid():
    if os.getpid() != _PID:
        raise CompletionStartupError("forked process cannot use activation completion")


def _environment():
    # Absence of ambient libpq, HOME, service and password settings is part
    # of the exact cold namespace; no environment fallback may change readers.
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "SERVERWARE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise CompletionStartupError("activation completion process or environment differs")
    delivery.delivery._require_unprivileged_process()


def _reader_arguments(configured):
    dsn, timeout, role, client_dn, client_serial, issuer_dn, query, structure = configured
    return {"dsn": dsn, "connect_timeout_seconds": timeout, "database_role": role,
        "tls_client_dn": client_dn, "tls_client_serial": client_serial,
        "tls_issuer_dn": issuer_dn, "query_manifest_digest": query,
        "expected_structure_manifest_digest": structure}


class _CompletionOwner:
    __slots__ = ("_material", "_root", "_key", "_listener", "_listener_pins", "_sealed", "_tls",
        "_journal", "_journal_fd", "_journal_pins", "_delivery", "_custody_reader", "_commit_reader",
        "_custody_configuration", "_commit_configuration", "_client", "_client_configuration",
        "_historical", "_historical_configuration",
        "_opening", "_interval", "_deadline", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_spent", "_connection")

    def __init__(self):
        raise CompletionStartupError("activation completion requires genuine cold admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise CompletionStartupError("activation completion lifetime or singleton changed")
            _process(_namespace)
            for descriptor, maximum, private, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != original:
                    raise CompletionStartupError("activation completion sealed custody changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins):
                raise CompletionStartupError("activation completion listener or journal binding changed")
            delivery._tls_unchanged(self._tls)
            from serverware import authority_current_root_journal as storage
            from serverware import authority_current_root_delivery as retained
            from serverware import authority_current_root_commit_reader as committed
            from serverware import authority_current_root_transport as state_transport
            from serverware import authority_successor_execution_owner as custody
            from serverware import authority_oidc_session_activation_history_custody as historical

            if (type(self._journal) is not storage.CurrentRootJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._delivery) is not retained.CurrentRootCompletionDelivery
                    or self._delivery._journal is not self._journal
                    or self._delivery._root_public_key is not self._root
                    or self._delivery._enrollment_bytes is not self._material.current_root_enrollment_bytes
                    or historical.OidcSessionActivationHistoryCustody._snapshot_configuration(self._historical)
                        is not self._historical_configuration
                    or custody.SuccessorExecutionRecoveryReader._snapshot_configuration(self._custody_reader)
                        != self._custody_configuration
                    or committed.CurrentRootCommitReader._snapshot_configuration(self._commit_reader)
                        != self._commit_configuration
                    or state_transport.CurrentRootDecisionClient._snapshot_configuration(self._client)
                        != self._client_configuration):
                raise CompletionStartupError("activation completion actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            retained.CurrentRootCompletionDelivery.inspect(self._delivery)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch
                        <= opened_epoch + after - opened_before):
                raise CompletionStartupError("activation completion original clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, CompletionStartupError):
                raise
            raise CompletionStartupError("activation completion lifecycle admission failed") from exc

    def _recover_on_work(self, originals, *, live_window, deadline, work):
        from serverware import authority_oidc_session_activation_completion_recovery as recovery
        from serverware import oidc_session_activation_completion_bootstrap as bootstrap

        material = self._material
        if material.launch["schema"] == bootstrap.DISPATCH_LAUNCH_SCHEMA:
            # The request carries no packet selector. Only byte equality with
            # the actual root-admitted caller original may select this owner's
            # independently pinned packet; SQL raw4 never chooses authority.
            work.charge(input_bytes=len(originals[1]) + len(material.authorization_bytes))
            if originals[1] != material.authorization_bytes:
                raise CompletionRequestError("activation completion caller differs from its cold original")
        elif material.launch["schema"] == bootstrap.LAUNCH_SCHEMA:
            work.charge(input_bytes=len(originals[1]) + len(material.packet_digest))
            if originals[1] != material.packet_digest.encode("ascii"):
                raise CompletionRequestError("activation completion packet differs from its cold pin")
        else:
            raise CompletionRequestError("activation completion launch profile changed")
        sequence, head, fence = material.current_pending
        # This is the actual pre-read window/work. Recovery may only narrow
        # the existing bound, never reopen an allowance after body reading.
        try:
            result = recovery.recover_and_deliver(custody_reader=self._custody_reader,
                commit_reader=self._commit_reader, delivery=self._delivery, client=self._client,
                historical_custody=self._historical, packet_digest=material.packet_digest,
                expectations=material.expectations, planner_public_key=material.planner_public_key,
                operation_public_key=material.operation_public_key, root_public_key=self._root,
                authorization_bytes=material.authorization_bytes,
                authorization_enrollment_bytes=material.authorization_enrollment_bytes,
                grant_enrollment_bytes=material.grant_enrollment_bytes,
                current_root_enrollment_bytes=material.current_root_enrollment_bytes,
                configuration_digest=material.configuration_digest,
                completion_private_key=self._key, expected_authorization_digest=material.authorization_digest,
                expected_database_id=material.database_id, expected_generation_digest=material.generation_digest,
                expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
                live_window=live_window, work=work,
                transport_deadline_ns=deadline)
            if type(result) is not recovery.common.SuccessorCompletionRecoveryResult:
                raise CompletionRequestError("activation completion returned no actual recovery result")
            # Return only this actual owner's durable original for the same
            # independently pinned pending scope, joined to the genuine result.
            original = recovery.delivery_store.CurrentRootCompletionDelivery._original_for_pending_on_work(
                self._delivery, expected_pending_sequence=sequence,
                expected_pending_head_digest=head, work=work)
            if type(original) is not tuple or len(original) != 2:
                raise CompletionRequestError("activation completion lacks its retained original")
            identity, request = original
            recovery.authorization.plan._same(identity, result.request_digest, work,
                "activation completion outcome differs from its retained original")
            return b"acknowledged", identity.encode("ascii"), request, result.receipt_bytes
        except Exception:
            # Completion signing/retention/state acceptance may be durable.
            # No exception text, invented receipt or rollback/retry assertion.
            # Cancellation and other BaseException subclasses propagate.
            return b"uncertain", b"", b"", b""

    def _serve_connection(self, connection):
        from serverware import authority_oidc_session_activation_completion_transport as selector_transport
        from serverware import authority_oidc_session_activation_completion_dispatch_transport as dispatch_transport
        from serverware import authority_oidc_session_activation_completion_recovery as recovery
        from serverware import oidc_session_activation_completion_bootstrap as bootstrap
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        self._live()
        profile = self._material.launch["schema"]
        if profile == bootstrap.LAUNCH_SCHEMA:
            transport = selector_transport
        elif profile == bootstrap.DISPATCH_LAUNCH_SCHEMA:
            transport = dispatch_transport
        else:
            raise CompletionRequestError("activation completion launch profile differs")
        work = _ValidationWork(QueryReadValidationLimits())
        window = recovery.clock._open_on_work(deadline_epoch_ns=self._interval[1],
            maximum_lifetime_ns=min(self._material.launch["requestTimeoutSeconds"] * 1_000_000_000,
                self._material.maximum_authorization_age_ns,
                self._material.custody_material.planner.maximum_plan_age_ns),
            maximum_clock_skew_ns=0, work=work)
        deadline = min(self._deadline, window[4])
        transport._check_deadline(deadline)
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, deadline,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise CompletionRequestError("activation completion caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=deadline)
        recovery.clock._check_on_work(window, work=work)
        self._live()
        if self._material.launch["schema"] != profile:
            raise CompletionRequestError("activation completion request profile changed")
        if self._spent:
            raise CompletionStartupError("activation completion cold request was already spent")
        self._spent = True
        response = self._recover_on_work(originals, live_window=window, deadline=deadline, work=work)
        self._live()
        recovery.clock._check_on_work(window, work=work)
        transport._check_deadline(deadline)
        transport._send_response(connection, response, deadline_ns=deadline)
        self._live()
        recovery.clock._check_on_work(window, work=work)
        transport._check_deadline(deadline)

    def serve_once(self):
        """Wait briefly, or handle one accepted connection and never reenter."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._spent or self._connection is not None:
                raise CompletionStartupError("activation completion cold exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                self._live()
                raise CompletionStartupError("activation completion original lifetime expired")
            ready, _, _ = select.select((self._listener,), (), (), min(1.0, remaining))
            self._live()
            if not ready:
                return False
            try:
                connection, _address = self._listener.accept()
            except BlockingIOError:
                self._live()
                return False
            self._connection = connection
            try:
                self._serve_connection(connection)
            except BaseException:
                self._failed = True
                raise
            finally:
                try:
                    connection.close()
                finally:
                    self._connection = None
            self._live()
            return True


def initialize_from_environment():
    global _state, _owner, _namespace
    _require_pid()
    with _LOCK:
        if _state == "started":
            return require_started()
        if _state != "new":
            raise CompletionStartupError("activation completion cannot restart in this process")
        _state, _namespace = "initializing", _environment()
        listener = journal = completion_delivery = historical_owner = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(
                delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_completion_bootstrap as bootstrap
            from serverware import authority_current_root_journal as storage
            from serverware import authority_current_root_delivery as retained
            from serverware import authority_current_root_commit_reader as committed
            from serverware import authority_current_root_transport as state_transport
            from serverware import authority_successor_execution_owner as custody
            from serverware import authority_oidc_session_activation_history_custody as historical
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise CompletionStartupError("activation completion bootstrap bounds changed")
            work = _ValidationWork(QueryReadValidationLimits())
            # One actual current startup allowance covers admission, private
            # key loading and all journal records; no per-record allowance.
            now = bootstrap.authorization.production._callback(work, time.time_ns)
            maximum = bootstrap.authority.VERIFIER_RESPONSE_MAX_AGE_NS
            window = historical.clock._open_on_work(deadline_epoch_ns=now + maximum,
                maximum_lifetime_ns=maximum, maximum_clock_skew_ns=0, work=work)
            deadline = window[4]
            work.charge(input_bytes=len(root_raw))
            root = bootstrap.authorization.production._callback(work,
                lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise CompletionStartupError("activation completion root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root,
                live_window=window, transport_deadline_ns=deadline, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"],
                    launch["peerUid"], launch["peerGid"], launch["rootPublicKeyFd"], launch["bootstrapFd"],
                    launch["listenerFd"], launch["signingKeyFd"], launch["journalDirectoryFd"],
                    launch["bundleKeyFd"], launch["deliveryKeyFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID,
                        delivery.PEER_UID, delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS, delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise CompletionStartupError("activation completion launch differs from fixed delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise CompletionStartupError("activation completion resources differ from signed identities")
            window = historical.processing_window._narrow(window,
                deadline_epoch_ns=material.attestation_interval[1],
                maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
            deadline = min(deadline, window[4], material.opening_sample[0]
                + material.attestation_interval[1] - material.opening_sample[1])
            key_identity = delivery._sealed_identity(delivery.KEY_FD, delivery.MAX_KEY_BYTES, private=True)
            bundle_identity = delivery._sealed_identity(delivery.BUNDLE_KEY_FD, 32, private=True)
            delivery_identity = delivery._sealed_identity(delivery.DELIVERY_KEY_FD, 32, private=True)
            key, bundle_key, delivery_key = delivery._keys_on_work(material, work)
            historical_owner = historical.OidcSessionActivationHistoryCustody(
                custody_bytes=material.custody_bytes, root_public_key=root,
                expected_receiver_identity=material.receiver_identity,
                bundle_key=bundle_key, delivery_custody_key=delivery_key,
                live_window=window, transport_deadline_ns=deadline, work=work)
            del bundle_key, delivery_key
            window, deadline = historical.OidcSessionActivationHistoryCustody.processing_bounds_on_work(
                historical_owner, live_window=window, transport_deadline_ns=deadline, work=work)
            current = historical.OidcSessionActivationHistoryCustody.check_on_work(historical_owner,
                live_window=window, transport_deadline_ns=deadline, work=work)
            current()
            work.charge(hashes=len(material.tls_files),
                input_bytes=sum(item["byteCount"] for item in material.tls_files.values()))
            tls_identity = bootstrap.production._callback(work,
                lambda: delivery._tls_identity(material.tls_files))
            current()
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            journal = storage.CurrentRootJournal(directory_fd=delivery.JOURNAL_FD,
                expected_device=journal_pins[0], expected_inode=journal_pins[1],
                expected_uid=delivery.SERVICE_UID, expected_gid=delivery.SERVICE_GID,
                maximum_records=launch["journalMaximumRecords"])
            completion_delivery = retained.CurrentRootCompletionDelivery(journal=journal,
                enrollment_bytes=material.current_root_enrollment_bytes, root_public_key=root,
                expected_local_sequence=material.completion_checkpoint[0],
                expected_local_head_digest=material.completion_checkpoint[1],
                live_window=window, transport_deadline_ns=deadline, work=work)
            current()
            custody_arguments = _reader_arguments(material.custody_configuration)
            del custody_arguments["database_role"]  # Actual custody constructor fixes its role.
            custody_reader = custody.SuccessorExecutionRecoveryReader(**custody_arguments)
            commit_reader = committed.CurrentRootCommitReader(**_reader_arguments(material.commit_configuration))
            path, timeout, uid, gid = material.state_endpoint
            client = state_transport.CurrentRootDecisionClient(path=path, timeout_seconds=timeout,
                expected_peer_uid=uid, expected_peer_gid=gid)
            current()
            final_sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            owner = object.__new__(_CompletionOwner)
            owner._material, owner._root, owner._key = material, root, key
            owner._listener, owner._listener_pins = listener, listener_pins
            owner._journal, owner._journal_fd, owner._journal_pins = journal, journal._directory_fd, journal_pins
            owner._delivery, owner._custody_reader, owner._commit_reader = completion_delivery, custody_reader, commit_reader
            owner._custody_configuration, owner._commit_configuration = material.custody_configuration, material.commit_configuration
            owner._client, owner._client_configuration = client, state_transport.CurrentRootDecisionClient._snapshot_configuration(client)
            owner._historical = historical_owner
            owner._historical_configuration = historical.OidcSessionActivationHistoryCustody._snapshot_configuration(historical_owner)
            owner._tls = tls_identity
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False, bootstrap_identity),
                (delivery.KEY_FD, delivery.MAX_KEY_BYTES, True, key_identity),
                (delivery.BUNDLE_KEY_FD, 32, True, bundle_identity),
                (delivery.DELIVERY_KEY_FD, 32, True, delivery_identity))
            owner._opening, owner._interval = material.opening_sample, material.attestation_interval
            history_opening = owner._historical_configuration.opening_sample
            history_interval = owner._historical_configuration.attestation_interval
            owner._deadline = min(owner._opening[0] + owner._interval[1] - owner._opening[1],
                history_opening[0] + history_interval[1] - history_opening[1])
            owner._last_epoch, owner._last_monotonic = final_sample[1], final_sample[2]
            owner._closed, owner._failed, owner._spent, owner._connection = False, False, False, None
            _owner, _state = owner, "started"
            owner._live()
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (historical_owner,
                    completion_delivery if completion_delivery is not None else journal, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            if isinstance(exc, CompletionStartupError):
                raise
            raise CompletionStartupError("activation completion cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _CompletionOwner:
            raise CompletionStartupError("activation completion has not started")
        _owner._live()
        return _owner


def close():
    """Close owned journal/listener; inherited descriptors remain borrowed."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise CompletionStartupError("cannot close an active activation completion connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            owner._key = owner._root = owner._material = owner._custody_reader = owner._commit_reader = None
            try:
                owner._historical.close()
            finally:
                owner._historical = owner._historical_configuration = None
                try:
                    owner._delivery.close()
                finally:
                    owner._listener.close()
