"""Single-request peer-admitted serving over the actual durable decision owner.

Cold admission must supply the genuine owner and independently approved caller
UID/GID pairs. This core neither creates a listener nor admits configuration,
keys, a journal directory or a latest checkpoint. Peer credentials constrain
transport purpose; they do not replace enrolled request signatures.

An actual accepted Unix stream is owned and closed on every path. Its peer is
admitted before any prefix, and its purpose-specific peer before any body.
The complete bounded original and EOF reach the fixed owner's sole work
allowance. That owner joins the authenticated action before replay/publication
and returns only a durably published receipt (or an exact historical receipt).
Legacy bounded queries are restricted to admitted completion peers. The explicit
v4 activation-planner peer has a distinct head-only query, never those legacy
purposes. V5 adds a separate activation reserve peer, restricted to the signed
activation operation before historical receipt return or new publication.
V6 separately admits activation completion/lookup. A known lookup receipt must
belong to an actual signed activation complete control, never another purpose.
V7 admits only the separate consume-planner peer's distinct head protocol; it
cannot invoke activation heads, lookup, reserve or complete.
V8 separately admits the consume reserver for reserve/consume only. The actual
owner checks both signed fields before historical receipt return or mutation;
neither planner's head observation becomes reservation authority.
V9 separately admits consume completion and lookup of known consume complete
originals; it grants neither reservation nor either planner head protocol.
All reach genuine owner paths without a service parser or allowance.
No independent signer, SQL, success substitute or automatic retry exists here.
Failure after publication or send is not evidence of rollback/absence.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
import socket

from serverware import authority_current_root_decisions as decisions
from serverware import authority_current_root_transport as transport
from serverware import authority_revocation_writer_transport as io
from serverware import authority_transport


class CurrentRootServiceError(RuntimeError):
    pass


def _validate_configuration(config):
    if type(config) is not tuple or len(config) not in (6, 7, 8, 9, 10, 11, 12, 13, 14):
        raise CurrentRootServiceError("current-root service configuration is not a fixed profile")
    owner, reserve_uid, reserve_gid, complete_uid, complete_gid, timeout = config[:6]
    if type(owner) is not decisions.CurrentRootDecisionOwner:
        raise CurrentRootServiceError("current-root service requires the actual durable decision owner")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (reserve_uid, reserve_gid, complete_uid, complete_gid)):
        raise CurrentRootServiceError("current-root caller peer identity is invalid")
    if (type(timeout) not in (int, float) or not 0.05 <= timeout <= 30
            or not math.isfinite(timeout)):
        raise CurrentRootServiceError("current-root service timeout is invalid")
    if len(config) >= 7 and (type(config[6]) is not tuple or len(config[6]) != 2
            or any(type(value) is not int for value in config[6])
            or config[6] != (65510, 65510)
            or (reserve_uid, reserve_gid, complete_uid, complete_gid) != (65514, 65514, 65515, 65515)):
        raise CurrentRootServiceError("current-root finalization peer profile differs from fixed source")
    if len(config) >= 8 and (type(config[7]) is not tuple or len(config[7]) != 2
            or any(type(value) is not int for value in config[7]) or config[7] != (65508, 65508)):
        raise CurrentRootServiceError("current-root finalization completion peer differs from fixed source")
    if len(config) >= 9 and (type(config[8]) is not tuple or len(config[8]) != 2
            or any(type(value) is not int for value in config[8]) or config[8] != (65507, 65507)):
        raise CurrentRootServiceError("current-root activation planner peer differs from fixed source")
    if len(config) >= 10 and (type(config[9]) is not tuple or len(config[9]) != 2
            or any(type(value) is not int for value in config[9]) or config[9] != (65505, 65505)):
        raise CurrentRootServiceError("current-root activation reserve peer differs from fixed source")
    if len(config) >= 11 and (type(config[10]) is not tuple or len(config[10]) != 2
            or any(type(value) is not int for value in config[10]) or config[10] != (65503, 65503)):
        raise CurrentRootServiceError("current-root activation completion peer differs from fixed source")
    if len(config) >= 12 and (type(config[11]) is not tuple or len(config[11]) != 2
            or any(type(value) is not int for value in config[11]) or config[11] != (65501, 65501)):
        raise CurrentRootServiceError("current-root delivery planner peer differs from fixed source")
    if len(config) >= 13 and (type(config[12]) is not tuple or len(config[12]) != 2
            or any(type(value) is not int for value in config[12]) or config[12] != (65499, 65499)):
        raise CurrentRootServiceError("current-root delivery reserve peer differs from fixed source")
    if len(config) == 14 and (type(config[13]) is not tuple or len(config[13]) != 2
            or any(type(value) is not int for value in config[13]) or config[13] != (65497, 65497)):
        raise CurrentRootServiceError("current-root delivery completion peer differs from fixed source")
    return config


def _accepted_peer(connection):
    # Linux SO_PEERCRED is mandatory here; no ambient identity or alternate
    # platform peer mechanism silently changes this serving contract.
    if not hasattr(socket, "SO_PEERCRED") or not hasattr(socket, "SO_DOMAIN"):
        raise CurrentRootServiceError("current-root service requires Unix socket peer credentials")
    if (connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0):
        raise CurrentRootServiceError("current-root service requires a connected Unix stream")
    connection.getpeername()
    uid, gid, pid = authority_transport._peer_identity(connection)
    if (any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in (uid, gid))
            or type(pid) is not int or not 1 <= pid <= (1 << 31) - 1):
        raise CurrentRootServiceError("current-root socket peer credentials are invalid")
    return uid, gid, pid


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class CurrentRootDecisionService:
    """Hold approved peer pins; callers retain the owner/listener lifecycle."""

    _configuration: tuple
    _pid: int

    def __init__(self, *, owner, reserve_peer_uid, reserve_peer_gid,
            complete_peer_uid, complete_peer_gid, timeout_seconds):
        configured = _validate_configuration((owner, reserve_peer_uid, reserve_peer_gid,
            complete_peer_uid, complete_peer_gid, timeout_seconds))
        object.__setattr__(self, "_configuration", configured)
        object.__setattr__(self, "_pid", os.getpid())

    @classmethod
    def _with_finalization_reserver(cls, *, owner, timeout_seconds):
        """Cold v2 only: fixed additional reserve peer, never a peer-list API."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root finalization profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    def _snapshot_configuration(self):
        if type(self) is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root serving requires its exact configured service")
        configured = _validate_configuration(self._configuration)
        if os.getpid() != self._pid:
            raise CurrentRootServiceError("forked process cannot use current-root serving")
        return configured

    @classmethod
    def _with_finalization_completion(cls, *, owner, timeout_seconds):
        """Cold v3 only: finalization completion/query peer, no arbitrary list."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root finalization profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    @classmethod
    def _with_activation_planner(cls, *, owner, timeout_seconds):
        """Cold v4 only: fixed head-observation peer, no decision/lookup access."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root activation profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508), (65507, 65507)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    @classmethod
    def _with_activation_reserver(cls, *, owner, timeout_seconds):
        """Cold v5 only: fixed activation reserve peer, not planner authority."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root activation profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508), (65507, 65507), (65505, 65505)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    @classmethod
    def _with_activation_completion(cls, *, owner, timeout_seconds):
        """Cold v6 only: fixed activation completion/lookup peer, no live reserve."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root activation profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508), (65507, 65507),
            (65505, 65505), (65503, 65503)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    @classmethod
    def _with_delivery_planner(cls, *, owner, timeout_seconds):
        """Cold v7 only: consume-head observations, never reserve or complete."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root delivery profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508), (65507, 65507),
            (65505, 65505), (65503, 65503), (65501, 65501)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    @classmethod
    def _with_delivery_reserver(cls, *, owner, timeout_seconds):
        """Cold v8 only: signed consume reserve controls, no other purpose."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root delivery profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508), (65507, 65507),
            (65505, 65505), (65503, 65503), (65501, 65501), (65499, 65499)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    @classmethod
    def _with_delivery_completion(cls, *, owner, timeout_seconds):
        """Cold v9 only: consume complete/known-original lookup, no reserve."""
        if cls is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root delivery profile requires the exact service")
        configured = _validate_configuration((owner, 65514, 65514, 65515, 65515,
            timeout_seconds, (65510, 65510), (65508, 65508), (65507, 65507),
            (65505, 65505), (65503, 65503), (65501, 65501), (65499, 65499), (65497, 65497)))
        result = object.__new__(CurrentRootDecisionService)
        object.__setattr__(result, "_configuration", configured)
        object.__setattr__(result, "_pid", os.getpid())
        return result

    def serve_connection(self, connection, *, transport_deadline_ns=None):
        """Own one accepted socket, serve at most one request, then close it."""
        if type(connection) is not socket.socket:
            raise CurrentRootServiceError("current-root serving requires an actual accepted socket")
        try:
            configured = CurrentRootDecisionService._snapshot_configuration(self)
            owner, reserve_uid, reserve_gid, complete_uid, complete_gid, timeout = configured[:6]
            reserve_peer, complete_peer = (reserve_uid, reserve_gid), (complete_uid, complete_gid)
            finalization_peer = configured[6] if len(configured) >= 7 else None
            finalization_complete_peer = configured[7] if len(configured) >= 8 else None
            activation_planner_peer = configured[8] if len(configured) >= 9 else None
            activation_reserve_peer = configured[9] if len(configured) >= 10 else None
            activation_complete_peer = configured[10] if len(configured) >= 11 else None
            delivery_planner_peer = configured[11] if len(configured) >= 12 else None
            delivery_reserve_peer = configured[12] if len(configured) >= 13 else None
            delivery_complete_peer = configured[13] if len(configured) == 14 else None
            deadline_ns = io._deadline_ns(timeout)
            if transport_deadline_ns is not None:
                if type(transport_deadline_ns) is not int or transport_deadline_ns < 1:
                    raise CurrentRootServiceError("current-root inherited service deadline is invalid")
                deadline_ns = min(deadline_ns, transport_deadline_ns)
            transport._check_deadline(deadline_ns)
            uid, gid, _pid = io._call_until(connection, deadline_ns,
                lambda: _accepted_peer(connection))
            peer = (uid, gid)
            if peer not in (reserve_peer, complete_peer, finalization_peer,
                    finalization_complete_peer, activation_planner_peer, activation_reserve_peer,
                    activation_complete_peer, delivery_planner_peer, delivery_reserve_peer,
                    delivery_complete_peer):
                raise CurrentRootServiceError("current-root socket peer is not admitted")
            prefix = transport._recv_prefix(connection, deadline_ns=deadline_ns)
            expected_operation = None
            if prefix == transport.RESERVE_REQUEST_MAGIC:
                action, required_peer = "reserve", reserve_peer
                if delivery_reserve_peer is not None and peer == delivery_reserve_peer:
                    required_peer = delivery_reserve_peer
                    expected_operation = "oidc.session.activation-delivery.consume"
                elif activation_reserve_peer is not None and peer == activation_reserve_peer:
                    required_peer = activation_reserve_peer
                    expected_operation = "oidc.session.activate"
                elif finalization_peer is not None:
                    if peer == finalization_peer:
                        required_peer = finalization_peer
                        expected_operation = "webauthn.registration.finalize"
                    else:
                        expected_operation = "webauthn.registration.evidence.admit"
            elif prefix == transport.COMPLETE_REQUEST_MAGIC:
                action, required_peer = "complete", complete_peer
                if delivery_complete_peer is not None and peer == delivery_complete_peer:
                    required_peer = delivery_complete_peer
                    expected_operation = "oidc.session.activation-delivery.consume"
                elif activation_complete_peer is not None and peer == activation_complete_peer:
                    required_peer = activation_complete_peer
                    expected_operation = "oidc.session.activate"
                elif finalization_complete_peer is not None:
                    if peer == finalization_complete_peer:
                        required_peer = finalization_complete_peer
                        expected_operation = "webauthn.registration.finalize"
                    else:
                        expected_operation = "webauthn.registration.evidence.admit"
            elif prefix == transport.QUERY_REQUEST_MAGIC:
                action, required_peer = "query", complete_peer
                if delivery_complete_peer is not None and peer == delivery_complete_peer:
                    required_peer = delivery_complete_peer
                    expected_operation = "oidc.session.activation-delivery.consume"
                elif activation_complete_peer is not None and peer == activation_complete_peer:
                    required_peer = activation_complete_peer
                    expected_operation = "oidc.session.activate"
                elif finalization_complete_peer is not None and peer == finalization_complete_peer:
                    required_peer = finalization_complete_peer
            elif prefix == transport.HEAD_QUERY_REQUEST_MAGIC and activation_planner_peer is not None:
                action, required_peer = "head", activation_planner_peer
            elif (prefix == transport.DELIVERY_HEAD_QUERY_REQUEST_MAGIC
                    and delivery_planner_peer is not None):
                action, required_peer = "delivery-head", delivery_planner_peer
            else:
                raise CurrentRootServiceError("current-root socket purpose is not source fixed")
            if peer != required_peer:
                raise CurrentRootServiceError("current-root socket peer is not admitted for this purpose")
            # Exact class dispatch excludes instance method overrides. No
            # branch parses signed data or creates a second work allowance.
            if action == "delivery-head":
                original = transport._recv_delivery_head_query(connection,
                    prefix=prefix, deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                observation = decisions.CurrentRootDecisionOwner.observe_delivery_head(owner, original,
                    transport_deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                transport._send_delivery_head_observation(connection, observation, deadline_ns=deadline_ns)
            elif action == "head":
                original = transport._recv_head_query(connection, prefix=prefix, deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                observation = decisions.CurrentRootDecisionOwner.observe_head(owner, original,
                    transport_deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                transport._send_head_observation(connection, observation, deadline_ns=deadline_ns)
            elif action == "query":
                original = transport._recv_lookup(connection, prefix=prefix, deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                if expected_operation is not None:
                    observation = decisions.CurrentRootDecisionOwner.lookup(owner, original,
                        transport_deadline_ns=deadline_ns, expected_operation=expected_operation,
                        expected_request_action="complete")
                else:
                    observation = decisions.CurrentRootDecisionOwner.lookup(owner, original,
                        transport_deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                transport._send_observation(connection, observation, deadline_ns=deadline_ns)
            else:
                received_action, original = transport._recv_request(connection,
                    prefix=prefix, deadline_ns=deadline_ns)
                if received_action != action:
                    raise CurrentRootServiceError("current-root framing action changed")
                transport._check_deadline(deadline_ns)
                receipt = decisions.CurrentRootDecisionOwner.apply(owner, original,
                    expected_action=action, expected_operation=expected_operation,
                    transport_deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
                transport._send_response(connection, receipt, deadline_ns=deadline_ns)
        except BaseException:
            # No error frame masquerades as a receipt. Preserve even cancellation
            # and publication uncertainty if closing also fails.
            try:
                socket.socket.close(connection)
            except BaseException:
                pass
            raise
        socket.socket.close(connection)
        transport._check_deadline(deadline_ns)
