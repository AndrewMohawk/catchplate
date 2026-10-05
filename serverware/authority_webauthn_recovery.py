"""Original-byte last-key recovery computation for the successor writer.

No caller-produced candidate, trusted-root DTO, successful-signature result or
replay-witness reservation is accepted as recovery authority.  Hardware and
offline-root signatures are actually verified here.  Selected rows, complete
history, the root PEM, configured policy and the original database cutoff must
be independently admitted by the owning successor invocation.  In particular,
these functions do not claim the separate recovery witness or execute SQL.

The full historical credential projection below intentionally retains the
legacy 1000-row/default4MiB policy.  It is not silently reduced to the generic
single-plan proof cap.  Activation requires the real complete-history producer
and the real recovery-witness owner, not a synthetic row/count or Boolean.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_challenge_retention as retention
from serverware import authority_transition_core as core
from serverware import authority_webauthn_registration_trust as trust
from serverware import webauthn_attestation_core as attestation
from serverware.authority_query_read_work import _ValidationWork


CEREMONY_TABLE = "webauthn_recovery_ceremonies"
CREATE = "webauthn.recovery.create"
CANDIDATE = "webauthn.recovery.candidate"
FINALIZE = "webauthn.recovery.finalize"
EXPIRE = "webauthn.recovery.expire"
PRUNE = "webauthn.recovery.prune"
INVALIDATE = "webauthn.recovery.invalidate"
OPERATIONS = (CREATE, CANDIDATE, FINALIZE, EXPIRE, PRUNE, INVALIDATE)
_POLICY_FIELDS = frozenset({
    "rp_id", "origin", "allowed_authenticator_classes", "authorization_policy_digest",
    "recovery_root_key_id", "recovery_root_provider", "recovery_audience",
})
_PAYLOAD_FIELDS = frozenset({
    "v", "type", "recovery_id", "nonce", "user_id", "oidc_session_id",
    "pending_expires_at", "credential_history_digest", "trust_bundle_digest", "auth_policy_digest",
})


class RecoveryTransitionError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class CandidatePreparation:
    """Fresh internal computation only, never accepted as proof/authority."""

    row: dict[str, Any]
    history_manifest: dict[str, Any]
    history_metrics: Any


def _work(work):
    if type(work) is not _ValidationWork:
        raise RecoveryTransitionError("recovery requires the original shared work meter")


def _own(value, work):
    _work(work)
    work.prepare_normalization(value)
    return json.loads(core.canonical_bytes(value))


def _bytes(value, work):
    work.prepare_encoding(value)
    return core.canonical_bytes(value)


def _sha(value: bytes, work) -> str:
    work.charge(hashes=1, input_bytes=len(value))
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _decode(value, maximum, work):
    if (type(value) is not str or not value or len(value) > (4 * maximum + 2) // 3
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                   for character in value)):
        raise RecoveryTransitionError("recovery original-byte encoding is invalid")
    work.charge(input_bytes=4 * len(value))
    raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    if not 1 <= len(raw) <= maximum or _encode(raw, work) != value:
        raise RecoveryTransitionError("recovery original bytes are not canonical base64url")
    return raw


def _encode(value: bytes, work) -> str:
    work.charge(input_bytes=len(value) + 3 * (4 * ((len(value) + 2) // 3)))
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _time(value):
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise RecoveryTransitionError("recovery timestamp is not exact text")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RecoveryTransitionError("recovery timestamp is invalid") from exc
    if result.tzinfo is None or result.utcoffset() is None or result.utcoffset().total_seconds() != 0:
        raise RecoveryTransitionError("recovery timestamp is not explicit UTC")
    return result


def _now(value):
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise RecoveryTransitionError("recovery requires the original UTC database cutoff")
    return value


def _policy(policy, ceremony, work):
    policy = _own(policy, work)
    if type(policy) is not dict or set(policy) != _POLICY_FIELDS:
        raise RecoveryTransitionError("recovery configured policy is not source closed")
    for name in ("authorization_policy_digest", "recovery_root_key_id"):
        core.require_digest(policy[name], name)
    for name, maximum in (("rp_id", 253), ("origin", 2048),
                          ("recovery_root_provider", 128), ("recovery_audience", 512)):
        core.require_text(policy[name], name, maximum_bytes=maximum)
    classes = policy["allowed_authenticator_classes"]
    if (type(classes) is not list or not classes or len(classes) > 2
            or any(type(item) is not str or item not in ("hardware", "yubikey") for item in classes)
            or len(set(classes)) != len(classes)):
        raise RecoveryTransitionError("recovery requires trusted hardware authenticator classes")
    for source, field in (("rp_id", "rp_id"), ("origin", "origin"),
            ("authorization_policy_digest", "auth_policy_digest"),
            ("recovery_root_key_id", "recovery_root_key_id"),
            ("recovery_root_provider", "recovery_root_provider"),
            ("recovery_audience", "recovery_audience")):
        if ceremony.get(field) != policy[source]:
            raise RecoveryTransitionError("recovery ceremony differs from the admitted configuration")
    return policy


def verify_candidate(*, ceremony, challenge, response, published_row, high_water_row,
                     policy, database_now, work):
    """Recompute the actual legacy candidate from raw hardware bytes.

    Credential-ID nonreuse, complete user history and pending-publication
    absence are separate authenticated query obligations of the real caller.
    This worker never converts a missing query into a successful empty result.
    """
    now = _now(database_now)
    owned = _own({"ceremony": ceremony, "challenge": challenge, "response": response,
                  "published": published_row, "high": high_water_row}, work)
    ceremony, challenge, response = owned["ceremony"], owned["challenge"], owned["response"]
    policy = _policy(policy, ceremony, work)
    if (type(ceremony) is not dict or ceremony.get("status") not in ("pending_candidate", "prepared")
            or _time(ceremony.get("expires_at")) <= now
            or type(challenge) is not dict or set(challenge) != retention.ROW_FIELDS
            or challenge.get("id") != ceremony.get("challenge_id")
            or challenge.get("challenge_type") != "recovery-registration"
            or challenge.get("user_id") != ceremony.get("user_id")
            or challenge.get("scope_key") != ceremony.get("id")
            or challenge.get("approval_request_id") is not None
            or challenge.get("used_at") is not None or _time(challenge.get("expires_at")) <= now):
        raise RecoveryTransitionError("recovery candidate has no live exact ceremony challenge")
    payload = json.loads(challenge["payload_json"])
    if (type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS
            or type(payload["v"]) is not int or payload["v"] != 1
            or payload["type"] != "serverware.webauthn_recovery_registration"):
        raise RecoveryTransitionError("recovery challenge payload is not source closed")
    for field, ceremony_field in (("recovery_id", "id"), ("nonce", "nonce"),
            ("user_id", "user_id"), ("oidc_session_id", "oidc_session_id"),
            ("pending_expires_at", "pending_expires_at"),
            ("credential_history_digest", "credential_history_digest"),
            ("trust_bundle_digest", "trust_bundle_digest"), ("auth_policy_digest", "auth_policy_digest")):
        if payload[field] != ceremony[ceremony_field]:
            raise RecoveryTransitionError("recovery challenge semantic binding changed")
    if type(response) is not dict or type(response.get("response")) is not dict:
        raise RecoveryTransitionError("recovery requires the actual registration response")
    nested = response["response"]
    credential_id = response.get("id") or response.get("rawId")
    core.require_text(credential_id, "recovery credential ID", maximum_bytes=2048)
    client = _decode(nested.get("clientDataJSON"), attestation.MAX_CLIENT_DATA_JSON_BYTES, work)
    original = _decode(nested.get("attestationObject"), attestation.MAX_ATTESTATION_OBJECT_BYTES, work)
    transports = response.get("transports") or nested.get("transports") or []
    if (type(transports) is not list or len(transports) > 16
            or any(type(item) is not str or len(item) > 64 for item in transports)):
        raise RecoveryTransitionError("recovery transports are invalid")
    context = trust._context_on_work(published_row=owned["published"],
        high_water_row=owned["high"], rp_id=policy["rp_id"], origin=policy["origin"],
        verified_at=now, work=work)
    publication = owned["published"]
    for field, source in (("trust_bundle_digest", "bundle_digest"),
                         ("trust_bundle_sequence", "sequence"),
                         ("trust_bundle_rollback_epoch", "rollback_epoch"),
                         ("trust_signing_key_id", "signing_key_id")):
        if ceremony[field] != publication[source]:
            raise RecoveryTransitionError("recovery committed trust generation changed")
    scope = attestation.CeremonyScope(challenge_id=challenge["id"], challenge=challenge["challenge"],
        user_id=ceremony["user_id"], label=ceremony["label"],
        authorization_json=_bytes(payload, work), _work=work)
    parsed = attestation.parse_registration_data(client, original, credential_id,
        scope=scope, rp_id=policy["rp_id"], origin=policy["origin"],
        transports=tuple(transports), _work=work)
    actual = attestation.verify_registration_attestation(parsed, context, _work=work)
    receipt = actual.attestation
    if (actual.user_verified is not True or receipt.trusted is not True
            or actual.authenticator_class not in policy["allowed_authenticator_classes"]
            or actual.authenticator_class not in ("hardware", "yubikey")
            or receipt.trust_bundle_digest != publication["bundle_digest"]
            or receipt.trust_bundle_sequence != publication["sequence"]):
        raise RecoveryTransitionError("recovery requires genuinely verified current hardware attestation")
    return {
        "credentialId": actual.credential_id,
        "credentialIdDigest": _sha(actual.credential_id.encode("utf-8"), work),
        "publicKeyCose": _encode(actual.public_key_cose, work),
        "publicKeyCoseDigest": _sha(actual.public_key_cose, work),
        "signCount": actual.sign_count, "userVerified": True,
        "aaguid": actual.aaguid, "authenticatorClass": actual.authenticator_class,
        "attestationFormat": receipt.fmt, "attestationTrusted": True,
        "attestationTrustPath": list(receipt.trust_path),
        "attestationLeafSha256": receipt.leaf_sha256, "attestationRootSha256": receipt.root_sha256,
        "attestationObjectDigest": _sha(original, work), "clientDataJsonDigest": _sha(client, work),
        "responseDigest": _sha(_bytes(response, work), work),
        "trustBundleDigest": publication["bundle_digest"],
        "trustBundleSequence": publication["sequence"],
        "trustBundleRollbackEpoch": publication["rollback_epoch"],
        "trustSigningKeyId": publication["signing_key_id"], "transports": sorted(set(transports)),
    }


def verify_authorization(*, ceremony, authorization, root_public_key_original,
                         policy, database_now, work):
    """Verify the actual offline Ed25519 original; never sign or claim a witness."""
    now = _now(database_now)
    owned = _own({"ceremony": ceremony, "authorization": authorization}, work)
    ceremony, authorization = owned["ceremony"], owned["authorization"]
    policy = _policy(policy, ceremony, work)
    if (type(root_public_key_original) is not bytes
            or not 1 <= len(root_public_key_original) <= 16 * 1024):
        raise RecoveryTransitionError("recovery requires its original bounded public key")
    work.charge(input_bytes=len(root_public_key_original))
    public_key = serialization.load_pem_public_key(root_public_key_original)
    if not isinstance(public_key, Ed25519PublicKey):
        raise RecoveryTransitionError("recovery root is not Ed25519")
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if _sha(spki, work) != policy["recovery_root_key_id"]:
        raise RecoveryTransitionError("recovery public key differs from the independently configured pin")
    if type(authorization) is not dict or set(authorization) != {"statement", "signature"}:
        raise RecoveryTransitionError("recovery authorization fields are not closed")
    expected = json.loads(ceremony["statement_json"])
    statement = authorization["statement"]
    canonical = _bytes(statement, work)
    if (_bytes(expected, work) != canonical or _sha(canonical, work) != ceremony["statement_digest"]
            or _time(statement["notBefore"]) > now or _time(statement["expiresAt"]) <= now
            or _time(statement["expiresAt"]) > _time(ceremony["expires_at"])
            or _time(statement["expiresAt"]) > _time(ceremony["pending_expires_at"])):
        raise RecoveryTransitionError("recovery authorization differs from its original statement/window")
    signature_value = authorization["signature"]
    if type(signature_value) is not str or not signature_value.startswith("ed25519:"):
        raise RecoveryTransitionError("recovery signature must use Ed25519")
    signature = _decode(signature_value[8:], 64, work)
    if len(signature) != 64:
        raise RecoveryTransitionError("recovery Ed25519 signature length changed")
    # Bounded native Ed25519 verification is real work, not a caller callback or
    # boolean claim. It can never produce a signing capability.
    try:
        public_key.verify(signature, canonical)
    except InvalidSignature as exc:
        raise RecoveryTransitionError("recovery offline authorization signature failed") from exc
    normalized = _bytes(authorization, work)
    if len(normalized) > 128 * 1024:
        raise RecoveryTransitionError("recovery authorization exceeds its original byte cap")
    return authorization, _sha(normalized, work), _sha(signature, work)


def credential_history(rows, *, maximum_count, maximum_bytes, work):
    """Exact legacy history digest from full rows; completeness is not inferred."""
    if (type(maximum_count) is not int or not 1 <= maximum_count <= 10_000
            or type(maximum_bytes) is not int or not 65_536 <= maximum_bytes <= 16_777_216
            or type(rows) not in (list, tuple) or len(rows) > maximum_count):
        raise RecoveryTransitionError("recovery history exceeds its configured original bounds")
    rows = _own(list(rows), work)
    ordered = sorted(rows, key=lambda row: (row["created_at"], row["id"]))
    if len({row["id"] for row in ordered}) != len(ordered):
        raise RecoveryTransitionError("recovery history repeats a credential primary key")
    history, active = [], 0
    for row in ordered:
        active += int(row["revoked_at"] is None)
        history.append({
            "record_id": row["id"],
            "credential_id_digest": _sha(row["credential_id"].encode("utf-8"), work),
            "public_key_cose_digest": _sha(row["public_key_cose"].encode("ascii"), work),
            "sign_count": row["sign_count"], "aaguid": row["aaguid"],
            "authenticator_class": row["authenticator_class"], "attestation_fmt": row["attestation_fmt"],
            "attestation_trusted": bool(row["attestation_trusted"]),
            "attestation_trust_path": json.loads(row["attestation_trust_path"]),
            "attestation_leaf_sha256": row["attestation_leaf_sha256"],
            "attestation_root_sha256": row["attestation_root_sha256"],
            "attestation_trust_bundle_digest": row["attestation_trust_bundle_digest"],
            "attestation_trust_bundle_sequence": row["attestation_trust_bundle_sequence"],
            "attestation_verified_at": row["attestation_verified_at"],
            "transports": json.loads(row["transports"]),
            "development_material_digest": (_sha(row["dev_private_key_pem"].encode("utf-8"), work)
                                            if row["dev_private_key_pem"] is not None else None),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "last_used_at": row["last_used_at"], "revoked_at": row["revoked_at"],
            "revoked_by": row["revoked_by"], "revocation_reason": row["revocation_reason"],
            "revocation_source": row["revocation_source"],
        })
    encoded = _bytes(history, work)
    if len(encoded) > maximum_bytes:
        raise RecoveryTransitionError("recovery history exceeds its configured original byte bound")
    return {"digest": _sha(encoded, work), "count": len(history), "active_count": active}


def _session(ceremony, session, pending_token_digest, now):
    core.require_digest(pending_token_digest, "recovery pending token")
    if (type(session) is not dict or session.get("id") != ceremony.get("oidc_session_id")
            or session.get("status") != "pending_webauthn"
            or type(session.get("token_digest")) is not str
            or not hmac.compare_digest(session["token_digest"], pending_token_digest)
            or not hmac.compare_digest(ceremony["pending_token_digest"], pending_token_digest)
            or _time(session.get("pending_expires_at")) <= now
            or _time(session.get("expires_at")) <= now):
        raise RecoveryTransitionError("recovery pending OIDC session is not live and exact")
    for session_field, ceremony_field in (("user_id", "user_id"), ("oidc_token_digest", "oidc_token_digest"),
            ("roles_json", "roles_json"), ("expires_at", "session_expires_at"),
            ("pending_expires_at", "pending_expires_at")):
        if session.get(session_field) != ceremony.get(ceremony_field):
            raise RecoveryTransitionError("recovery OIDC session binding changed")


def _history_unchanged(*, operation, ceremony, manifest, count_body, read_page,
        primary_root, index_head, maximum_count, maximum_bytes, database_now, work,
        acquisition=None):
    """Replay raw history pages, never accept a digest/count verdict input.

    The dedicated owner retains its closed original per-page/total budgets.
    The callback reads bound immutable page bytes under the enclosing caller's
    unchanged deadline; it supplies neither a verifier nor a replacement root.
    Both producer and independent execution replay enter through this call.
    """
    from serverware import authority_recovery_history as history

    delta = database_now - datetime(1970, 1, 1, tzinfo=timezone.utc)
    cutoff_us = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    anchors = {"operation": operation, "user_id": ceremony["user_id"], "cutoff_us": cutoff_us,
        "maximum_count": maximum_count, "maximum_bytes": maximum_bytes,
        "primary_root": primary_root, "index_head": index_head}
    if manifest is None:
        # The producer derives descriptors while the SAME genuine history
        # engine checks every raw proof. No digest/count observation is an
        # accepted substitute. The enclosing parent binds the derived manifest
        # before a second same-MVCC pass retains the identical raw originals.
        from serverware.authority_recovery_history_acquisition import HistoryAcquisition

        if type(acquisition) is not HistoryAcquisition or count_body is not None or read_page is not None:
            raise RecoveryTransitionError("recovery history production needs its actual held acquisition owner")
        acquisition.assert_context(**anchors)
        manifest, actual = acquisition.produce()
        manifest = _own(manifest, work)
    else:
        if acquisition is not None:
            raise RecoveryTransitionError("recovery replay cannot mix a producer with retained originals")
        manifest = _own(manifest, work)
        actual = history.verify_history(manifest=manifest, count_body=count_body,
            read_page=read_page, **anchors)
    if (actual.digest != ceremony["credential_history_digest"]
            or actual.count != ceremony["credential_history_count"]
            or actual.count == 0 or actual.active_count != 0):
        raise RecoveryTransitionError("recovery credential history changed or still has a live credential")
    return manifest, actual


def prepare_candidate_row(*, ceremony, challenge, session, pending_token_digest,
        history_manifest, history_count_body, read_history_page, history_primary_root,
        history_index_head, history_maximum_count, history_maximum_bytes, metadata_root_state,
        witness_last_sequence, response, published_row, high_water_row, policy,
        database_now, work, history_acquisition=None):
    """Derive the exact prepared row after genuine raw candidate verification.

    ``witness_last_sequence`` is ordinary data from the real independently held
    recovery-witness read, not authority or a success token. The enclosing
    owner must perform that read and retain its original binding; a client
    supplied sequence must never enter this call. Finalization still performs
    the genuine external claim and handles uncertain claim outcomes.
    """
    now = _now(database_now)
    owned = _own({"ceremony": ceremony, "challenge": challenge, "session": session,
                  "root": metadata_root_state}, work)
    ceremony, challenge, session = owned["ceremony"], owned["challenge"], owned["session"]
    if ceremony.get("status") != "pending_candidate" or _time(ceremony.get("expires_at")) <= now:
        raise RecoveryTransitionError("recovery ceremony is not awaiting a candidate")
    _session(ceremony, session, pending_token_digest, now)
    manifest, history = _history_unchanged(operation=CANDIDATE, ceremony=ceremony, manifest=history_manifest,
        count_body=history_count_body, read_page=read_history_page,
        primary_root=history_primary_root, index_head=history_index_head,
        maximum_count=history_maximum_count, maximum_bytes=history_maximum_bytes,
        database_now=now, work=work, acquisition=history_acquisition)
    root = owned["root"]
    if root is not None and (type(root) is not dict
            or root.get("signing_key_id") != ceremony["recovery_root_key_id"]
            or root.get("user_id") != ceremony["user_id"]):
        raise RecoveryTransitionError("recovery metadata root identity differs")
    metadata_last = 0 if root is None else root.get("last_consumed_sequence")
    if any(type(value) is not int or not 0 <= value < 2**63 - 1
           for value in (metadata_last, witness_last_sequence)):
        raise RecoveryTransitionError("recovery root sequence is outside the original integer range")
    candidate = verify_candidate(ceremony=ceremony, challenge=challenge, response=response,
        published_row=published_row, high_water_row=high_water_row, policy=policy,
        database_now=now, work=work)
    candidate_bytes = _bytes(candidate, work)
    if len(candidate_bytes) > 64 * 1024:
        raise RecoveryTransitionError("recovery candidate exceeds the original64KiB bound")
    root_sequence = max(metadata_last, witness_last_sequence) + 1
    expiry = min(_time(ceremony["expires_at"]), _time(ceremony["pending_expires_at"])).isoformat()
    statement = {
        "apiVersion": "serverware.webauthnRecoveryAuthorization/v1",
        "type": "serverware.webauthn_last_key_recovery",
        "recoveryId": ceremony["id"], "nonce": ceremony["nonce"],
        "audience": ceremony["recovery_audience"],
        "root": {"provider": ceremony["recovery_root_provider"],
                 "keyId": ceremony["recovery_root_key_id"], "sequence": root_sequence},
        "deployment": {"rpId": ceremony["rp_id"], "origin": ceremony["origin"]},
        "subject": {"userId": ceremony["user_id"], "oidcSessionId": ceremony["oidc_session_id"],
            "pendingTokenDigest": pending_token_digest, "oidcTokenDigest": ceremony["oidc_token_digest"],
            "roles": json.loads(ceremony["roles_json"]), "identityDigest": ceremony["identity_digest"],
            "sessionExpiresAt": ceremony["session_expires_at"], "pendingExpiresAt": ceremony["pending_expires_at"]},
        "request": {"label": ceremony["label"], "reason": ceremony["reason"],
            "challengeId": ceremony["challenge_id"], "challenge": challenge["challenge"],
            "challengeDigest": ceremony["challenge_digest"]},
        "credentialHistory": {"digest": ceremony["credential_history_digest"],
            "count": ceremony["credential_history_count"], "activeCredentialCount": 0},
        "trust": {"bundleDigest": ceremony["trust_bundle_digest"],
            "bundleSequence": ceremony["trust_bundle_sequence"],
            "rollbackEpoch": ceremony["trust_bundle_rollback_epoch"], "signingKeyId": ceremony["trust_signing_key_id"]},
        "authorizationPolicyDigest": ceremony["auth_policy_digest"], "candidate": candidate,
        "signedAt": now.isoformat(), "notBefore": now.isoformat(), "expiresAt": expiry,
    }
    encoded = _bytes(statement, work)
    row = {**ceremony, "status": "prepared", "candidate_json": candidate_bytes.decode("ascii"),
            "candidate_digest": _sha(candidate_bytes, work), "statement_json": encoded.decode("ascii"),
            "statement_digest": _sha(encoded, work), "root_sequence": root_sequence,
            "prepared_at": now.isoformat()}
    return CandidatePreparation(row, manifest, history.metrics)
