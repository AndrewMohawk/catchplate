"""Ordinary retained-X proof of a pre-encryption generation conflict only.

The original nonce remains spent. This releases no secret, does not refresh,
and says nothing about provider issuance or token retirement. Google and native
reconciliation retain their separate admission and unchanged implementations.
"""
from __future__ import annotations

import hashlib
import hmac
import time

API_VERSION = "serverware.operatorCredentialLeaseNoEnvelope/v1"
CAPABILITY = "operator-x-oauth-v1"
REASON = "generationAdvancedBeforeEnvelope"
MAX_RESPONSE_BYTES = 16 * 1024


def _same(left, right):
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(
        left.encode("utf-8"), right.encode("utf-8"))


def _retained():
    """Metadata-only original configuration; no EX, keys, network or cache."""
    from serverware import db, operator_x_admission as admission
    from serverware import operator_x_configuration as configuration
    from serverware import operator_x_oauth_profile as profiles
    directory = admission.require_runtime()
    with db.metadata_connection() as conn:
        conn.execute("BEGIN")
        admission.check_connection(conn, directory)
        binding = configuration.retained_public_binding(conn)
        if binding is None:
            return None
        profile = profiles.parse_profile(binding["public_profile"])
        admission.check_connection(conn, directory)
        return binding, profile


def pre_encryption_generation_conflict(
    request, payload, *, prepared_credential, prepared_metadata_sha256,
    request_binding_sha256, recipient_nonce_sha256, dispatch_authority,
    claimed_release_authorization, profile, wrapped, broker, refresh_opening,
    currentness_opening,
):
    """Observe only an authenticated, nonce-spent ordinary v3 dispatch attempt.

    The caller must invoke this only at the definite generation conflict before
    creating any secret envelope, then sign the returned bytes for the original
    request. Refusals never confer reconciliation authority or unspend a nonce.
    """
    metadata = prepared_credential.get("metadata")
    if (profile != "legacy" or wrapped or broker or refresh_opening is not None
            or currentness_opening is not None or claimed_release_authorization is not None
            or payload.api_version != "serverware.credentialLeaseRequest/v3"
            or payload.purpose != "dispatchSecret"
            or payload.request_authority is not None or payload.release_authorization is not None
            or {"request_authority", "release_authorization"}.intersection(payload.model_fields_set)
            or dispatch_authority != {"controlled": False, "issuanceKind": None,
                "requestAuthority": None, "requestAuthoritySha256": None, "releaseAuthorization": None}
            or prepared_credential.get("kind") != "oauth2" or not isinstance(metadata, dict)
            or metadata.get("provider_id") != "x" or "operator_x_account" not in metadata):
        return None
    from serverware import operator_demo, operator_x_admission as admission
    if not operator_demo.active() or not admission.enabled():
        return None
    from serverware import app as application, db, oauth_application_owner
    from serverware import control_plane_credential_currentness as currentness
    from serverware import control_plane_custody_startup as custody
    if (oauth_application_owner.require_started() is not None or currentness.selected()
            or custody.credential_broker_selected()
            or not _same(application.EXPECTED_DATA_PLANE_BINARY_DIGEST, payload.data_plane_binary_digest)):
        return None
    retained = _retained()
    if retained is None:
        return None
    binding, admitted = retained
    if admitted.profile != CAPABILITY or admitted.provider_id != "x":
        return None
    from serverware import operator_catalog_x_oauth as catalog
    catalog.validate_account_metadata(metadata, admitted)
    method, path, query, response_nonce, _https, invalid_nonce = application._request_signature_inputs(request.scope)
    if (method != "POST" or path != "/api/data-plane/credential-leases" or query
            or invalid_nonce or not _same(response_nonce, payload.recipient_nonce)):
        return None
    original = application._original_data_plane_request(
        request, application._CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY, payload)
    request_body_sha256 = "sha256:" + hashlib.sha256(
        application._canonical_json(original).encode("utf-8")).hexdigest()
    if not _same(application._credential_lease_request_binding_sha256(payload), request_binding_sha256):
        return None
    nonce = application._decode_unpadded_base64url(
        payload.recipient_nonce, field_name="recipientNonce", expected_length=32)
    if not _same("sha256:" + hashlib.sha256(nonce).hexdigest(), recipient_nonce_sha256):
        return None
    with db.credential_generation_snapshot(payload.credential_id) as committed:
        if (committed is None or committed.get("kind") != "oauth2"
                or committed.get("lifecycle_status") != "active"
                or committed.get("id") != payload.credential_id
                or type(committed.get("credential_version")) is not int
                or type(payload.expected_credential_version) is not int
                or not 0 < payload.expected_credential_version < committed["credential_version"] <= (1 << 64) - 1
                or committed["credential_version"] != prepared_credential.get("credential_version")):
            return None
        committed_metadata = committed.get("metadata")
        catalog.validate_account_metadata(committed_metadata, admitted)
        snapshot = application.get_policy_snapshot()
        if snapshot is None or not _same(snapshot.hash, payload.policy_hash):
            return None
        credential_policy = application._assert_credential_lease_route_binding(payload, snapshot)
        route = application._active_route_by_id(payload.route_id, snapshot=snapshot)
        if application._assert_credential_lease_release_authorization(payload, route=route) != dispatch_authority:
            return None
        application._assert_credential_policy_binding(committed, credential_policy)
        application._assert_credential_injection_binding(committed, credential_policy)
        application._assert_route_credential_binding(route, committed, credential_policy)
        observed_metadata_sha256 = application._credential_lease_metadata_sha256(
            application._credential_lease_public_metadata(committed))
        if not _same(observed_metadata_sha256, prepared_metadata_sha256):
            return None
        # The mutation snapshot excludes publishers. A separate, readonly SQL
        # transaction joins the exact catalog/configuration without taking EX.
        from serverware import operator_x_configuration as configuration
        directory = admission.require_runtime()
        with db.metadata_connection() as conn:
            conn.execute("BEGIN")
            admission.check_connection(conn, directory)
            if configuration.retained_public_binding(conn) != binding:
                return None
            catalog.require_lease_binding(conn, principal_id=payload.principal_id,
                route_id=payload.route_id, credential_id=payload.credential_id,
                core_credential=committed, profile=admitted)
            admission.check_connection(conn, directory)
        now = time.time_ns() // 1_000_000
        if not db.credential_lease_nonce_reserved(payload.recipient_key_id,
                recipient_nonce_sha256, now_epoch_ms=now):
            return None
        if _retained() != retained:
            return None
        body = {"apiVersion": API_VERSION, "capability": CAPABILITY,
            "profileBindingSha256": admitted.binding_digest,
            "outcome": "noSecretEnvelopeIssued", "reason": REASON,
            "purpose": "dispatchSecret", "requestBodySha256": request_body_sha256,
            "requestBindingSha256": request_binding_sha256, "policyHash": payload.policy_hash,
            "scope": {"principalId": payload.principal_id, "routeId": payload.route_id,
                "credentialId": payload.credential_id},
            "dataPlaneBinaryDigest": payload.data_plane_binary_digest,
            "recipientKeyId": payload.recipient_key_id, "recipientNonceSha256": recipient_nonce_sha256,
            "expectedCredentialVersion": payload.expected_credential_version,
            "expectedMetadataSha256": payload.expected_metadata_sha256,
            "observedCredentialVersion": committed["credential_version"],
            "observedMetadataSha256": observed_metadata_sha256,
            "issuedAtEpochMs": now, "expiresAtEpochMs": now + min(payload.max_ttl_seconds, 5) * 1000}
        encoded = application._canonical_json(body).encode("utf-8")
        return encoded if len(encoded) <= MAX_RESPONSE_BYTES else None
