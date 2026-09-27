"""One cold private activation-planning request, never session activation.

Original root bootstrap admission precedes keys, TLS and private journal use.
Actual configured owners acquire/replay/sign/retain; no successful material DTO
is accepted. Peer/body/production share one original request work/window beneath
the cold launch bound. One accepted connection is terminal, including malformed
input or uncertainty. No caller permission, SQL, currentness or retry is granted.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time

from serverware import oidc_session_activation_planner_entrypoint as delivery


_PID = os.getpid()
_LOCK = threading.RLock()
_state, _owner, _namespace = "new", None, None


class ActivationPlannerStartupError(RuntimeError):
    pass


class ActivationPlannerRequestError(RuntimeError):
    pass


def _require_pid():
    if os.getpid() != _PID:
        raise ActivationPlannerStartupError("forked process cannot use the cold activation planner")


def _environment():
    return tuple(sorted(os.environ.items()))


def _process(namespace):
    expected = tuple(sorted({"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
        "SERVERWARE_PROCESS_MODE": delivery.PROCESS_MODE,
        delivery.ROOT_ENV: str(delivery.ROOT_FD), delivery.BOOTSTRAP_ENV: str(delivery.BOOTSTRAP_FD)}.items()))
    if (namespace != expected or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise ActivationPlannerStartupError("activation planner process or literal environment differs")
    delivery.delivery._require_unprivileged_process()


def _construction_window(material, clock):
    # These are the genuine bootstrap's original bracket, not a fresh opening.
    before, epoch, after = material.opening_sample
    deadline = min(material.attestation_interval[1], epoch + material.maximum_plan_age_ns)
    return clock._validate((epoch, before, after, deadline, before + deadline - epoch,
        material.maximum_plan_age_ns, material.maximum_clock_skew_ns))


def _subject(originals, work, registration):
    values = []
    for raw, maximum, label in zip(originals[3:], (1024, 128, 1366, 1024, 1024),
            ("user", "session", "credential", "credential record", "challenge")):
        # The transport byte ceilings account for UTF-8; actual semantic
        # character bounds and canonical credential bytes are enforced here.
        work.charge(input_bytes=2 * len(raw), json_nodes=1)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ActivationPlannerRequestError("activation planner subject is not valid UTF-8") from exc
        registration._text(value, "activation " + label, maximum, work)
        values.append(value)
    registration._encoded_original(values[2], 1024, work, minimum=1)
    return tuple(values)


class _PlannerOwner:
    __slots__ = ("_material", "_root", "_bootstrap_bytes", "_reader", "_journal", "_journal_fd",
        "_journal_pins", "_plan_owner", "_plan_configuration", "_listener", "_listener_pins",
        "_sealed", "_tls", "_opening", "_interval", "_deadline", "_last_epoch", "_last_monotonic",
        "_closed", "_failed", "_accepted", "_spent", "_connection")

    def __init__(self):
        raise ActivationPlannerStartupError("activation planner requires genuine cold original admission")

    def _live(self):
        global _state
        _require_pid()
        try:
            if (self is not _owner or _state != "started" or self._closed or self._failed
                    or _environment() != _namespace):
                raise ActivationPlannerStartupError("activation planner singleton or original lifetime changed")
            _process(_namespace)
            for descriptor, maximum, private, original in self._sealed:
                if delivery._sealed_identity(descriptor, maximum, private=private) != original:
                    raise ActivationPlannerStartupError("activation planner sealed original changed")
            if (delivery._listener(delivery.LISTENER_FD) != self._listener_pins
                    or delivery._listener(self._listener.fileno()) != self._listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != self._journal_pins
                    or delivery._journal(self._journal_fd) != self._journal_pins):
                raise ActivationPlannerStartupError("activation planner fixed listener or journal changed")
            delivery._tls_unchanged(self._tls)
            from serverware import authority_oidc_session_activation_journal as storage
            from serverware import authority_oidc_session_activation_plan_owner as owners
            from serverware import authority_oidc_session_activation_planning as planning

            if (type(self._journal) is not storage.ActivationOriginalJournal
                    or self._journal._directory_fd != self._journal_fd
                    or type(self._reader) is not planning.OidcSessionActivationReadPlanner
                    or type(self._plan_owner) is not owners.OidcSessionActivationPlanOwner
                    or owners.OidcSessionActivationPlanOwner._snapshot_configuration(self._plan_owner)
                        is not self._plan_configuration
                    or self._plan_configuration[1] is not self._reader
                    or self._plan_configuration[3] is not self._journal):
                raise ActivationPlannerStartupError("activation planner actual owner configuration changed")
            descriptors = (*delivery.INHERITED_DESCRIPTORS, self._listener.fileno(), self._journal_fd)
            if self._connection is not None:
                descriptors += (self._connection.fileno(),)
            delivery._require_inventory(descriptors)
            before, epoch, after = time.monotonic_ns(), time.time_ns(), time.monotonic_ns()
            opened_before, opened_epoch, opened_after = self._opening
            if (any(type(value) is not int or value <= 0 for value in (before, epoch, after))
                    or after < before or before < self._last_monotonic or epoch < self._last_epoch
                    or not self._interval[0] <= epoch < self._interval[1] or after >= self._deadline
                    or not opened_epoch + before - opened_after <= epoch <= opened_epoch + after - opened_before):
                raise ActivationPlannerStartupError("activation planner original launch clocks expired or reversed")
            self._last_epoch, self._last_monotonic = epoch, after
        except BaseException as exc:
            self._failed, _state = True, "failed"
            if isinstance(exc, ActivationPlannerStartupError):
                raise
            raise ActivationPlannerStartupError("activation planner lifecycle admission failed") from exc

    def _prepare_on_work(self, originals, *, live_window, deadline, work):
        from serverware import authority_oidc_session_activation_cold_planning as cold
        from serverware import authority_oidc_session_activation_plan_owner as owners

        try:
            subject = _subject(originals, work, owners.registration)
            prepared = cold._prepare_on_work(self._plan_owner,
                bootstrap_bytes=self._bootstrap_bytes, root_public_key=self._root,
                assertion_bytes=originals[1], old_token_bytes=originals[2], expected_user_id=subject[0],
                expected_session_id=subject[1], expected_credential_id=subject[2],
                expected_credential_record_id=subject[3], expected_challenge_id=subject[4],
                live_window=live_window, transport_deadline_ns=deadline, work=work)
            if type(prepared) is not owners.PreparedActivationPlan:
                raise ActivationPlannerRequestError("activation planner returned no actual prepared originals")
            work.charge(input_bytes=len(prepared.plan_digest) + len(prepared.journal_digest))
            return (b"prepared", prepared.request_bytes, prepared.scope_bytes, prepared.envelope_bytes,
                prepared.plan_digest.encode("ascii"), prepared.journal_digest.encode("ascii"))
        except Exception:
            # Publication can already be durable. Empty uncertainty is not
            # absence, permission to repeat, or permission to generate/sign anew.
            return b"uncertain", b"", b"", b"", b"", b""

    def _serve_connection(self, connection):
        from serverware import authority_oidc_session_activation_planner_transport as transport
        from serverware import authority_webauthn_evidence_plan_clock as clock
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        self._live()
        work = _ValidationWork(QueryReadValidationLimits())
        window = clock._open_on_work(deadline_epoch_ns=self._interval[1],
            maximum_lifetime_ns=self._material.maximum_plan_age_ns,
            maximum_clock_skew_ns=self._material.maximum_clock_skew_ns, work=work)
        deadline = min(self._deadline, window[4],
            window[1] + self._material.launch["requestTimeoutSeconds"] * 1_000_000_000)
        transport._check_deadline(deadline)
        peer_uid, peer_gid, _pid = transport.io._call_until(connection, deadline,
            lambda: transport.authority_transport._peer_identity(connection))
        if (peer_uid, peer_gid) != (delivery.PEER_UID, delivery.PEER_GID):
            raise ActivationPlannerRequestError("activation planner caller peer differs")
        originals = transport._recv_request(connection, deadline_ns=deadline)
        work.charge(input_bytes=sum(len(raw) for raw in originals))
        clock._check_on_work(window, work=work)
        self._live()
        if self._spent:
            raise ActivationPlannerStartupError("activation planner original cold request was already spent")
        self._spent = True
        response = self._prepare_on_work(originals, live_window=window, deadline=deadline, work=work)
        self._live()
        clock._check_on_work(window, work=work)
        transport._send_response(connection, response, deadline_ns=deadline)
        self._live()
        clock._check_on_work(window, work=work)
        transport._check_deadline(deadline)

    def serve_once(self):
        """Return False on an idle poll; one accepted connection ends the launch."""
        _require_pid()
        with _LOCK:
            self._live()
            if self._accepted or self._spent or self._connection is not None:
                raise ActivationPlannerStartupError("activation planner cold exchange cannot repeat")
            remaining = (self._deadline - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                self._live()
                raise ActivationPlannerStartupError("activation planner original launch expired")
            ready, _, _ = select.select((self._listener,), (), (), min(1.0, remaining))
            self._live()
            if not ready:
                return False
            try:
                connection, _address = self._listener.accept()
            except BlockingIOError:
                self._live()
                return False
            self._accepted, self._connection = True, connection
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
            raise ActivationPlannerStartupError("activation planner cannot repeat cold admission")
        _state, _namespace = "initializing", _environment()
        listener = journal = plan_owner = None
        try:
            _process(_namespace)
            delivery._require_inventory(delivery.INHERITED_DESCRIPTORS)
            root_raw, root_identity = delivery._read_original(delivery.ROOT_FD, delivery.MAX_ROOT_BYTES)
            bootstrap_raw, bootstrap_identity = delivery._read_original(delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES)
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from serverware import oidc_session_activation_planner_bootstrap as bootstrap
            from serverware import authority_oidc_session_activation_journal as storage
            from serverware import authority_oidc_session_activation_plan_owner as owners
            from serverware import authority_oidc_session_activation_planning as planning
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            if bootstrap.MAX_BYTES != delivery.MAX_BOOTSTRAP_BYTES:
                raise ActivationPlannerStartupError("activation planner bootstrap size contract changed")
            work = _ValidationWork(QueryReadValidationLimits())
            work.charge(input_bytes=len(root_raw))
            root = owners.evidence.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
            if not isinstance(root, Ed25519PublicKey):
                raise ActivationPlannerStartupError("activation planner root must be Ed25519")
            material = bootstrap._verify_on_work(bootstrap_bytes=bootstrap_raw, root_public_key=root, work=work)
            launch = material.launch
            if ((launch["processMode"], launch["serviceUid"], launch["serviceGid"], launch["peerUid"], launch["peerGid"],
                    launch["rootPublicKeyFd"], launch["bootstrapFd"], launch["listenerFd"], launch["signingKeyFd"],
                    launch["deliveryKeyFd"], launch["journalKeyFd"], launch["journalDirectoryFd"], launch["listenerPath"])
                    != (delivery.PROCESS_MODE, delivery.SERVICE_UID, delivery.SERVICE_GID, delivery.PEER_UID,
                        delivery.PEER_GID, *delivery.INHERITED_DESCRIPTORS, delivery.LISTENER_PATH)
                    or tuple(launch["inheritedFileDescriptors"]) != delivery.INHERITED_DESCRIPTORS):
                raise ActivationPlannerStartupError("activation planner launch differs from fixed descriptor delivery")
            listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
                "listenerPathDevice", "listenerPathInode"))
            journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
            if (delivery._listener(delivery.LISTENER_FD) != listener_pins
                    or delivery._journal(delivery.JOURNAL_FD) != journal_pins):
                raise ActivationPlannerStartupError("activation planner resources differ from signed identities")
            key_pins = tuple((descriptor, maximum, True, delivery._sealed_identity(descriptor, maximum, private=True))
                for descriptor, maximum in ((delivery.KEY_FD, delivery.MAX_KEY_BYTES),
                    (delivery.DELIVERY_KEY_FD, delivery.MAX_RAW_KEY_BYTES),
                    (delivery.JOURNAL_KEY_FD, delivery.MAX_RAW_KEY_BYTES)))
            bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            private, delivery_key, journal_key = delivery._keys_on_work(material, work)
            for descriptor, maximum, private_flag, identity in key_pins:
                if delivery._sealed_identity(descriptor, maximum, private=private_flag) != identity:
                    raise ActivationPlannerStartupError("activation planner key descriptor changed during admission")
            tls_identity = delivery._tls_identity(material.tls_files)
            bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            window = _construction_window(material, owners.clock)
            cold_deadline = material.opening_sample[0] + material.attestation_interval[1] - material.opening_sample[1]
            bound = min(cold_deadline, window[4])
            listener = socket.fromfd(delivery.LISTENER_FD, socket.AF_UNIX, socket.SOCK_STREAM)
            journal = storage.ActivationOriginalJournal(directory_fd=delivery.JOURNAL_FD,
                expected_device=journal_pins[0], expected_inode=journal_pins[1], expected_uid=delivery.SERVICE_UID,
                expected_gid=delivery.SERVICE_GID, maximum_records=launch["journalMaximumRecords"],
                quota_bytes=launch["journalQuotaBytes"], configuration_digest=material.configuration_digest,
                journal_key=journal_key, delivery_key=delivery_key, live_window=window, work=work, transport_deadline_ns=bound)
            config = material.reader_configuration
            reader = planning.OidcSessionActivationReadPlanner(read_dsn=config[0], connect_timeout_seconds=config[1],
                database_identity=config[2], maximum_clock_skew_ns=config[3])
            plan_owner = owners.OidcSessionActivationPlanOwner(read_planner=reader, planner_private_key=private,
                planner_public_key=material.planner_public_key, expected_planner_identity=material.planner_identity,
                expected_planner_spki_digest=material.planner_spki_digest, configuration_digest=material.configuration_digest,
                delivery_custody_key=delivery_key, journal=journal, rp_id=material.rp_id, origin=material.origin,
                authn_policy=material.authn_policy, trust_policy=material.trust_policy,
                maximum_plan_age_ns=material.maximum_plan_age_ns, maximum_clock_skew_ns=material.maximum_clock_skew_ns,
                delivery_ttl_seconds=material.delivery_ttl_seconds, live_window=window, work=work, transport_deadline_ns=bound)
            final_sample = bootstrap._fresh(material.attestation_interval, work, opening=material.opening_sample)
            owner = object.__new__(_PlannerOwner)
            owner._material, owner._root, owner._bootstrap_bytes = material, root, bootstrap_raw
            owner._reader, owner._journal, owner._plan_owner = reader, journal, plan_owner
            owner._journal_fd, owner._journal_pins = journal._directory_fd, journal_pins
            owner._plan_configuration = owners.OidcSessionActivationPlanOwner._snapshot_configuration(plan_owner)
            owner._listener, owner._listener_pins, owner._tls = listener, listener_pins, tls_identity
            owner._sealed = ((delivery.ROOT_FD, delivery.MAX_ROOT_BYTES, False, root_identity),
                (delivery.BOOTSTRAP_FD, delivery.MAX_BOOTSTRAP_BYTES, False, bootstrap_identity), *key_pins)
            owner._opening, owner._interval, owner._deadline = material.opening_sample, material.attestation_interval, cold_deadline
            owner._last_epoch, owner._last_monotonic = final_sample[1], final_sample[2]
            owner._closed, owner._failed, owner._accepted, owner._spent, owner._connection = False, False, False, False, None
            _owner, _state = owner, "started"
            owner._live()
            return owner
        except BaseException as exc:
            _owner, _state = None, "failed"
            for resource in (plan_owner if plan_owner is not None else journal, listener):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        pass
            if isinstance(exc, ActivationPlannerStartupError):
                raise
            raise ActivationPlannerStartupError("activation planner genuine cold admission failed") from exc


def require_started():
    _require_pid()
    with _LOCK:
        if type(_owner) is not _PlannerOwner:
            raise ActivationPlannerStartupError("activation planner has not started")
        _owner._live()
        return _owner


def close():
    """Close owned journal/listener and drop key references; no zeroization claim."""
    global _owner, _state
    _require_pid()
    with _LOCK:
        owner = _owner
        if owner is not None and owner._connection is not None:
            raise ActivationPlannerStartupError("cannot close an active activation planner connection")
        _owner, _state = None, "closed"
        if owner is not None:
            owner._closed, owner._failed = True, True
            owner._root = owner._material = owner._bootstrap_bytes = owner._reader = None
            try:
                owner._plan_owner.close()
            finally:
                owner._plan_owner = owner._plan_configuration = owner._journal = None
                owner._listener.close()
