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
No parser allowance, signer, SQL, success substitute or automatic retry exists
here. Failure after publication or send is not evidence of rollback/absence.
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
    if type(config) is not tuple or len(config) != 6:
        raise CurrentRootServiceError("current-root service configuration is not an exact six-tuple")
    owner, reserve_uid, reserve_gid, complete_uid, complete_gid, timeout = config
    if type(owner) is not decisions.CurrentRootDecisionOwner:
        raise CurrentRootServiceError("current-root service requires the actual durable decision owner")
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
            for value in (reserve_uid, reserve_gid, complete_uid, complete_gid)):
        raise CurrentRootServiceError("current-root caller peer identity is invalid")
    if (type(timeout) not in (int, float) or not 0.05 <= timeout <= 30
            or not math.isfinite(timeout)):
        raise CurrentRootServiceError("current-root service timeout is invalid")
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

    def _snapshot_configuration(self):
        if type(self) is not CurrentRootDecisionService:
            raise CurrentRootServiceError("current-root serving requires its exact configured service")
        configured = _validate_configuration(self._configuration)
        if os.getpid() != self._pid:
            raise CurrentRootServiceError("forked process cannot use current-root serving")
        return configured

    def serve_connection(self, connection):
        """Own one accepted socket, serve at most one request, then close it."""
        if type(connection) is not socket.socket:
            raise CurrentRootServiceError("current-root serving requires an actual accepted socket")
        try:
            configured = CurrentRootDecisionService._snapshot_configuration(self)
            owner, reserve_uid, reserve_gid, complete_uid, complete_gid, timeout = configured
            reserve_peer, complete_peer = (reserve_uid, reserve_gid), (complete_uid, complete_gid)
            deadline_ns = io._deadline_ns(timeout)
            uid, gid, _pid = io._call_until(connection, deadline_ns,
                lambda: _accepted_peer(connection))
            peer = (uid, gid)
            if peer not in (reserve_peer, complete_peer):
                raise CurrentRootServiceError("current-root socket peer is not admitted")
            prefix = transport._recv_prefix(connection, deadline_ns=deadline_ns)
            if prefix == transport.RESERVE_REQUEST_MAGIC:
                action, required_peer = "reserve", reserve_peer
            elif prefix == transport.COMPLETE_REQUEST_MAGIC:
                action, required_peer = "complete", complete_peer
            else:
                raise CurrentRootServiceError("current-root socket purpose is not source fixed")
            if peer != required_peer:
                raise CurrentRootServiceError("current-root socket peer is not admitted for this purpose")
            received_action, original = transport._recv_request(connection,
                prefix=prefix, deadline_ns=deadline_ns)
            if received_action != action:
                raise CurrentRootServiceError("current-root framing action changed")
            transport._check_deadline(deadline_ns)
            # Exact class dispatch excludes instance method overrides. The
            # original's bounded canonical parsing, signature/action admission,
            # history replay and durable append share the owner's one allowance.
            receipt = decisions.CurrentRootDecisionOwner.apply(owner, original,
                expected_action=action, transport_deadline_ns=deadline_ns)
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
