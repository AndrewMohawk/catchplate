"""Narrow operator-Google proof that one conflicted lease issued no envelope.

This is not evidence that no provider refresh occurred or no secret was handled
internally. Only the first definite pre-encryption generation-conflict callsite
may use it. The original recipient nonce stays spent; ordinary errors carry no
reconciliation authority. Native and controlled lease semantics are unchanged.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import hmac
import time
from typing import Any


API_VERSION = "catchplate.operatorCredentialLeaseNoEnvelope/v1"
CAPABILITY = "operator-google-v1"
REASON = "generationAdvancedBeforeEnvelope"
MAX_RESPONSE_BYTES = 16 * 1024


def _same(left: Any, right: Any) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(
        left.encode("utf-8"), right.encode("utf-8"))


def pre_encryption_generation_conflict(
    request, payload, *, prepared_credential: dict[str, Any],
    prepared_metadata_sha256: str, request_binding_sha256: str,
    recipient_nonce_sha256: str, dispatch_authority: dict[str, Any],
    claimed_release_authorization: Any, profile: str, wrapped: bool,
    broker: bool, refresh_opening: Any, currentness_opening: Any,
) -> bytes | None:
    """Return a closed proof only for a cold-admitted, unclaimed v3 attempt.

The caller has already validated/authenticated the original request, spent its
nonce and detected the prepared-generation conflict, but has not encrypted an
envelope. Recheck committed metadata under the real mutation snapshot. This
function never releases nonce state, refreshes a token, or writes a claim.
"""
    prepared_metadata = prepared_credential.get("metadata")
    if (profile != "legacy" or wrapped or broker or refresh_opening is not None
            or currentness_opening is not None or claimed_release_authorization is not None
            or payload.api_version != "catchplate.credentialLeaseRequest/v3"
            or payload.purpose != "dispatchSecret"
            or payload.request_authority is not None or payload.release_authorization is not None
            or {"request_authority", "release_authorization"}.intersection(payload.model_fields_set)
            or dispatch_authority != {"controlled": False, "issuanceKind": None,
                "requestAuthority": None, "requestAuthoritySha256": None, "releaseAuthorization": None}
            or prepared_credential.get("kind") != "oauth2"
            or not isinstance(prepared_metadata, dict)
            or prepared_metadata.get("provider_id") != "google"):
        return None

    from catchplate import operator_demo
    if not operator_demo.active():
        return None
    from catchplate import operator_catalog_oauth_profile as capability
    if not capability.selected():
        return None
    admitted = capability.require_lease_reconciliation_profile()
    from catchplate import app as application, db, oauth_application_owner
    from catchplate import control_plane_credential_currentness as currentness
    from catchplate import control_plane_custody_startup as custody
    if (admitted.profile != CAPABILITY or admitted.provider_id != "google"
            or oauth_application_owner.require_started() is not None
            or currentness.selected() or custody.credential_broker_selected()
            or not _same(application.EXPECTED_DATA_PLANE_BINARY_DIGEST, payload.data_plane_binary_digest)):
        return None
    method, path, query, response_nonce, _https, invalid_nonce = application._request_signature_inputs(request.scope)
    if (method != "POST" or path != "/api/data-plane/credential-leases" or query
            or invalid_nonce or not _same(response_nonce, payload.recipient_nonce)):
        return None
    original = application._original_data_plane_request(
        request, application._CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY, payload)
    # Unlike the ordinary request binding, this includes the actual public key,
    # attestation evidence, and all supplied fields without a model projection.
    request_body_sha256 = "sha256:" + hashlib.sha256(
        application._canonical_json(original).encode("utf-8")).hexdigest()
    if not _same(application._credential_lease_request_binding_sha256(payload), request_binding_sha256):
        return None
    nonce = application._decode_unpadded_base64url(
        payload.recipient_nonce, field_name="recipientNonce", expected_length=32)
    if not _same("sha256:" + hashlib.sha256(nonce).hexdigest(), recipient_nonce_sha256):
        return None

    from catchplate import operator_catalog_google
    with db.credential_generation_snapshot(payload.credential_id) as committed:
        if (committed is None or committed.get("kind") != "oauth2"
                or committed.get("lifecycle_status") != "active"
                or committed.get("id") != payload.credential_id
                or type(committed.get("credential_version")) is not int
                or type(payload.expected_credential_version) is not int
                or not 0 < payload.expected_credential_version < committed["credential_version"] <= (1 << 64) - 1
                or committed["credential_version"] != prepared_credential.get("credential_version")):
            return None
        metadata = committed.get("metadata")
        if (not isinstance(metadata, dict) or metadata.get("oauth") is not True
                or metadata.get("provider_id") != "google"
                or oauth_application_owner.ASSOCIATION_KEY in metadata):
            return None
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
        # The outer SQLite mutation snapshot excludes catalog/core publishers;
        # this separate connection does only reads, never publication EX or DML.
        with closing(db.connect()) as connection:
            operator_catalog_google.require_lease_binding(connection,
                principal_id=payload.principal_id, route_id=payload.route_id,
                credential_id=payload.credential_id, core_credential=committed, profile=admitted)
        now = time.time_ns() // 1_000_000
        if not db.credential_lease_nonce_reserved(payload.recipient_key_id,
                recipient_nonce_sha256, now_epoch_ms=now):
            return None
        current_profile = capability.require_lease_reconciliation_profile()
        if current_profile != admitted:
            return None
        body = {
            "apiVersion": API_VERSION, "capability": CAPABILITY,
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
            "issuedAtEpochMs": now, "expiresAtEpochMs": now + min(payload.max_ttl_seconds, 5) * 1000,
        }
        encoded = application._canonical_json(body).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            return None
        return encoded
