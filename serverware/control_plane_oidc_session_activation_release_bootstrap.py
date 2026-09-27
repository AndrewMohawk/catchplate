"""Public-only release configuration inside the exact root-signed parent v5.

This mapper owns and joins configured originals as data. It does not admit
their signatures or freshness, open a processing window, borrow an issuer key,
or authorize transport. The actual control-plane owner must reauthenticate
these originals on its original request allowance before contacting the worker.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_revocation_configuration as configuration
from serverware import oidc_session_activation_release_client_authorization as client


SCHEMA = "serverware.controlPlaneOidcSessionActivationRelease/v1"
MAX_BYTES = configuration.authority.MAX_REQUEST_BYTES
_FIELDS = frozenset({"schema", "clientAuthorization", "serverBootstrap", "expectedScope"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ORIGINAL_LIMITS = (("clientAuthorization", client.MAX_BYTES),
    ("serverBootstrap", client.MAX_SERVER_BOOTSTRAP_BYTES))
shape, capture, plan = client.shape, client.capture, client.plan


class OidcSessionActivationReleaseBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseClientMaterial:
    """Immutable configured data, never a substitute for original admission."""

    client_authorization_bytes: bytes
    server_bootstrap_bytes: bytes
    expected_scope_bytes: bytes


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane release client configuration")
    shape._literal(value["schema"], SCHEMA)
    shape._object(value["expectedScope"], client.SCOPE_FIELDS,
        "control-plane independent release client scope")
    total = 0
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "control-plane release public original")
        shape._integer(original["byteCount"], maximum, minimum=2)
        client.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
        total += original["byteCount"]
    if total > MAX_BYTES:
        raise OidcSessionActivationReleaseBootstrapError(
            "release public originals exceed the unchanged parent bound")


def _scope_on_work(scope_bytes, work):
    """Read canonical retained scope data; this authenticates no authority."""
    original = client.authorization._original(scope_bytes, client.MAX_BYTES,
        "configured release client scope")
    decoded = client.capability.wire._decode_object(original, work=work,
        maximum_bytes=client.MAX_BYTES, maximum_nodes=client.MAX_NODES,
        maximum_depth=client.MAX_DEPTH)
    owned = client._scope(decoded, work)
    client._canonical(original, owned, work)
    return owned


def _admit_on_work(*, release_client, configuration_payload, configuration_digest,
        generation, runtime_role_identities, work):
    """Join parent-authenticated configuration, without a fresh-grant claim."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(release_client)
        if release_client is None:
            return None
        digest = configuration_digest
        shape._digest(digest)
        shape._bounded_object(generation, 24, "release client launch context")
        # Own every graph before configuration hashing or original decoding.
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit({
            "release": release_client, "configuration": configuration_payload,
            "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
            "runtime": runtime_role_identities})
        value = owned["release"]
        _shape(value)
        expected = client._scope(value["expectedScope"], work)
        configured, launch = configuration._capture_configuration_on_work(
            payload=owned["configuration"], configuration_digest=digest,
            generation=owned["generation"], work=work)
        configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=digest, launch=launch, work=work)
        plan._same((expected["configurationDigest"], expected["generationDigest"]),
            (digest, launch["digest"]), work,
            "release client scope differs from its actual parent configuration and generation")
        client_raw, server_raw = tuple(client.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        client_payload = client._read(client_raw, work)["payload"]
        plan._same({name: client_payload[name] for name in client.SCOPE_FIELDS},
            expected, work, "release client original differs from independent cold scope")
        plan._same(client._server_bootstrap_digest_on_work(server_raw, work),
            expected["serverBootstrapDigest"], work,
            "release client configuration selects different server originals")
        # Shape/canonical checks are deliberately not a root signature or
        # freshness admission. The request path must perform those genuinely.
        server = client.server
        envelope = server._decode(server_raw, work)
        shape._object(envelope, server._ENVELOPE_FIELDS, "configured release server original")
        shape._literal(envelope["schema"], server.SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        server._payload_shape(envelope["payload"], work)
        server._canonical(server_raw, envelope, work)
        payload = envelope["payload"]
        for name in ("profile", "configurationDigest", "databaseId", "generationDigest",
                "runtimeClosureDigest", "callerId", "receiverIdentity", "producerId",
                "producerIdentity", "stateReceiptDigest", "expectedRelease"):
            plan._same(payload[name], expected[name], work,
                "release server original differs from independent cold " + name)
        if expected["endpoint"]["timeoutSeconds"] > payload["launch"]["requestTimeoutSeconds"]:
            raise OidcSessionActivationReleaseBootstrapError(
                "release client timeout exceeds its configured server launch")
        # There is no control-plane role in the authority cohort. Client ID
        # and identity are explicit trusted-host-local root pins, not an
        # invented measurement borrowed from planner/verifier/issuer roles.
        scope_bytes = client._wire(expected, work)
        _scope_on_work(scope_bytes, work)
        return _ReleaseClientMaterial(client_raw, server_raw, scope_bytes)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationReleaseBootstrapError):
            raise
        raise OidcSessionActivationReleaseBootstrapError(
            "control-plane release client configuration failed") from exc
