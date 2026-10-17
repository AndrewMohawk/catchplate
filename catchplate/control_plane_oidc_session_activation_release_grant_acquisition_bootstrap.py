"""Public-only grant acquisition endpoint in explicit root-signed parent v12.

The fixed endpoint selects a future same-permission exchange, not issuer
authority, a successful acquisition or permission to provision resources.
No root/private key, grant original, request, token or new allowance enters here.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import control_plane_oidc_session_activation_release_handoff_bootstrap as handoff
from catchplate import authority_oidc_session_activation_release_grant_transport as transport


SCHEMA = "catchplate.controlPlaneOidcSessionActivationReleaseGrantAcquisition/v1"
SOCKET_PATH = transport.LISTENER_PATH
MAX_BYTES, MAX_NODES, MAX_DEPTH = 4 * 1024, 32, 3
shape, capture = handoff.shape, handoff.capture
_FIELDS = frozenset({"schema", "endpoint"})
_ENDPOINT_FIELDS = frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"})


class OidcSessionActivationReleaseGrantAcquisitionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseGrantAcquisitionMaterial:
    """Immutable parent-authenticated endpoint data, never fresh authority."""

    endpoint: tuple


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise OidcSessionActivationReleaseGrantAcquisitionBootstrapError(
                "release grant acquisition exceeds its shape bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise OidcSessionActivationReleaseGrantAcquisitionBootstrapError(
                "release grant acquisition exceeds its node bound")
        return owned


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "release grant acquisition endpoint")
    shape._literal(value["path"], SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
    try:
        return transport._endpoint((value["path"], value["timeoutSeconds"],
            value["peerUid"], value["peerGid"]))
    except transport.AuthorityTransportError as exc:
        raise OidcSessionActivationReleaseGrantAcquisitionBootstrapError(
            "release grant acquisition endpoint differs from its fixed listener") from exc


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane release grant acquisition")
    shape._literal(value["schema"], SCHEMA)
    _endpoint(value["endpoint"])


def _admit_on_work(*, release_grant_acquisition, release_handoff, work):
    try:
        held_handoff = release_handoff
        ledger = capture._SharedLedger(work)
        _shape(release_grant_acquisition)
        if release_grant_acquisition is None:
            return None
        if type(held_handoff) is not handoff._ReleaseHandoffMaterial:
            raise OidcSessionActivationReleaseGrantAcquisitionBootstrapError(
                "release grant acquisition requires actual parent handoff configuration")
        owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(release_grant_acquisition)
        _shape(owned)
        return _ReleaseGrantAcquisitionMaterial(_endpoint(owned["endpoint"]))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseGrantAcquisitionBootstrapError):
            raise
        raise OidcSessionActivationReleaseGrantAcquisitionBootstrapError(
            "release grant acquisition cold configuration failed") from exc
