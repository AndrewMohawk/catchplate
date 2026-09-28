"""Static public handoff pins in explicit root-signed parent v11.

Client identity is an independent trusted-host-local root pin, not a measured
generic role. This lane admits no fresh grant, token or transport permission.
It is separate from the older fixed-original release_client configuration.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof
from serverware import oidc_session_activation_release_client_authorization as client


SCHEMA = "serverware.controlPlaneOidcSessionActivationReleaseHandoff/v1"
SOCKET_PATH = client.LISTENER_PATH
MAX_BYTES, MAX_NODES, MAX_DEPTH = 16 * 1024, 64, 4
shape, capture, capability = client.shape, client.capture, client.capability
_FIELDS = frozenset({"schema", "clientId", "clientIdentity", "endpoint"})


class OidcSessionActivationReleaseHandoffBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseHandoffMaterial:
    """Immutable parent-authenticated data; never fresh permission evidence."""

    client_id: str
    client_identity_bytes: bytes
    endpoint_bytes: bytes


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise OidcSessionActivationReleaseHandoffBootstrapError("handoff pins exceed their shape bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise OidcSessionActivationReleaseHandoffBootstrapError("handoff pins exceed their node bound")
        return owned


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane release handoff configuration")
    shape._literal(value["schema"], SCHEMA)
    client.authorization._token(value["clientId"])
    shape.validate_identity_shape(value["clientIdentity"])
    # The existing endpoint grammar is scalar-only; its work argument is not
    # used and this shape gate performs no hash, callback or current admission.
    client._endpoint(value["endpoint"], None)


def _decode_on_work(original_bytes, work):
    raw = client.authorization._original(original_bytes, MAX_BYTES, "retained public handoff pins")
    owned = _capture(capability.wire._decode_object(raw, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH), work)
    capability._canonical(raw, owned, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return owned


def _identity_on_work(identity_bytes, work):
    """Decode exactly the held identity3; no measurement or authority claim."""
    owned = _decode_on_work(identity_bytes, work)
    shape.validate_identity_shape(owned)
    return owned


def _endpoint_on_work(endpoint_bytes, work):
    """Decode the root-held LIVE endpoint as canonical ordinary data."""
    owned = _decode_on_work(endpoint_bytes, work)
    client._endpoint(owned, work)
    return owned


def _admit_on_work(*, release_handoff, release_intent, release_proof, work):
    try:
        # Hold actual parent results before owning the sole external graph.
        held_intent, held_proof = release_intent, release_proof
        capture._SharedLedger(work)
        _shape(release_handoff)
        if release_handoff is None:
            return None
        if (type(held_intent) is not intent._ReleaseIntentMaterial
                or type(held_proof) is not proof._ReleaseProofMaterial):
            raise OidcSessionActivationReleaseHandoffBootstrapError(
                "release handoff requires actual parent intent and proof configuration")
        owned = _capture(release_handoff, work)
        _shape(owned)
        identity_bytes = capability._wire(owned["clientIdentity"], capture._SharedLedger(work),
            MAX_BYTES, MAX_NODES)
        endpoint_bytes = capability._wire(owned["endpoint"], capture._SharedLedger(work),
            MAX_BYTES, MAX_NODES)
        _identity_on_work(identity_bytes, work)
        _endpoint_on_work(endpoint_bytes, work)
        return _ReleaseHandoffMaterial(owned["clientId"], identity_bytes, endpoint_bytes)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseHandoffBootstrapError):
            raise
        raise OidcSessionActivationReleaseHandoffBootstrapError("release handoff cold configuration failed") from exc
