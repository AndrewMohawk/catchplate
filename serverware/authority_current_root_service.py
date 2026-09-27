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
Separate bounded queries are restricted to the completion peer and reach the
actual owner's lookup/signing path without a service parser or allowance.
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
    if type(config) is not tuple or len(config) not in (6, 7):
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
    if len(config) == 7 and (type(config[6]) is not tuple or len(config[6]) != 2
            or any(type(value) is not int for value in config[6])
            or config[6] != (65510, 65510)
            or (reserve_uid, reserve_gid, complete_uid, complete_gid) != (65514, 65514, 65515, 65515)):
        raise CurrentRootServiceError("current-root finalization peer profile differs from fixed source")
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

    def serve_connection(self, connection, *, transport_deadline_ns=None):
        """Own one accepted socket, serve at most one request, then close it."""
        if type(connection) is not socket.socket:
            raise CurrentRootServiceError("current-root serving requires an actual accepted socket")
        try:
            configured = CurrentRootDecisionService._snapshot_configuration(self)
            owner, reserve_uid, reserve_gid, complete_uid, complete_gid, timeout = configured[:6]
            reserve_peer, complete_peer = (reserve_uid, reserve_gid), (complete_uid, complete_gid)
            finalization_peer = configured[6] if len(configured) == 7 else None
            deadline_ns = io._deadline_ns(timeout)
            if transport_deadline_ns is not None:
                if type(transport_deadline_ns) is not int or transport_deadline_ns < 1:
                    raise CurrentRootServiceError("current-root inherited service deadline is invalid")
                deadline_ns = min(deadline_ns, transport_deadline_ns)
            transport._check_deadline(deadline_ns)
            uid, gid, _pid = io._call_until(connection, deadline_ns,
                lambda: _accepted_peer(connection))
            peer = (uid, gid)
            if peer not in (reserve_peer, complete_peer, finalization_peer):
                raise CurrentRootServiceError("current-root socket peer is not admitted")
            prefix = transport._recv_prefix(connection, deadline_ns=deadline_ns)
            expected_operation = None
            if prefix == transport.RESERVE_REQUEST_MAGIC:
                action, required_peer = "reserve", reserve_peer
                if finalization_peer is not None:
                    if peer == finalization_peer:
                        required_peer = finalization_peer
                        expected_operation = "webauthn.registration.finalize"
                    else:
                        expected_operation = "webauthn.registration.evidence.admit"
            elif prefix == transport.COMPLETE_REQUEST_MAGIC:
                action, required_peer = "complete", complete_peer
            elif prefix == transport.QUERY_REQUEST_MAGIC:
                action, required_peer = "query", complete_peer
            else:
                raise CurrentRootServiceError("current-root socket purpose is not source fixed")
            if peer != required_peer:
                raise CurrentRootServiceError("current-root socket peer is not admitted for this purpose")
            # Exact class dispatch excludes instance method overrides. Neither
            # branch parses signed data or creates a second work allowance.
            if action == "query":
                original = transport._recv_lookup(connection, prefix=prefix, deadline_ns=deadline_ns)
                transport._check_deadline(deadline_ns)
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
