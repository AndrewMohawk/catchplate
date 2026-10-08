"""Metadata-only Google consent joining the existing encrypted OAuth lifecycle.

No code, PKCE verifier, browser nonce, access token or refresh token is retained
in this catalog table. Consent saves an account, never application/rule access.
The initial opt-in profile refuses unsupported protected/enrolled combinations;
generic MFA, pending approval, activation and cleanup owners remain unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Literal

from serverware import db, operator_catalog_schema as schema
from serverware.operator_catalog_inputs import NamedInput
from serverware.operator_publication import exclusive

MAX_ACTIVE_INTENTS = 32
MAX_RETAINED_INTENTS = 1024
_STATE = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = frozenset({"id", "actor_id", "name", "provider_id", "permission_preset", "scopes",
    "oauth_profile_binding_digest", "reviewed_revision", "policy_hash", "catalog_revision",
    "created_at", "expires_at_epoch", "status", "state_digest", "credential_id", "reason"})
_PUBLIC = ("id", "name", "provider_id", "permission_preset", "scopes", "created_at",
    "expires_at_epoch", "status", "credential_id", "reason")
_STATUSES = {"prepared", "awaiting_consent", "exchanging", "connected", "failed", "expired"}


class GoogleConsentError(ValueError):
    """Fixed public failure; never carries a provider response or secret."""


class GoogleStartInput(NamedInput):
    permission_preset: Literal["gmail_readonly"] = "gmail_readonly"


def _profile():
    from serverware.operator_catalog_oauth_profile import require_profile
    return require_profile()


def canonical_granted_scopes(scope_string: str) -> list[str]:
    """Only Google's documented email alias, never additional permissions.

    Google OpenID Connect's callback example returns userinfo.email for the
    email scope. The raw provider string stays in the existing encrypted token
    JSON; catalog and policy use this exact canonical preset.
    """
    profile = _profile()
    if (not isinstance(scope_string, str) or not 1 <= len(scope_string) <= 2048
            or any(ord(char) < 32 or ord(char) > 126 for char in scope_string)):
        raise GoogleConsentError("Google granted permissions are invalid")
    scopes = scope_string.split(" ")
    if (not 1 <= len(scopes) <= 8 or any(not scope for scope in scopes)
            or len(scopes) != len(set(scopes))):
        raise GoogleConsentError("Google granted permissions are invalid")
    canonical = sorted({"email" if scope == "https://www.googleapis.com/auth/userinfo.email"
        else scope for scope in scopes})
    if canonical != list(profile.scopes):
        raise GoogleConsentError("Google granted permissions do not match the consent preset")
    return canonical


def profile_for_refresh(metadata: dict):
    """No vault reads: prove the association against real committed metadata."""
    from serverware import operator_demo
    marked = "oauth_intent_id" in metadata or "oauth_profile_binding_digest" in metadata
    if not marked and not (operator_demo.active() and metadata.get("provider_id") == "google"):
        return None
    profile = _profile()
    from serverware.operator_catalog_google import validate_record
    with db.connect() as conn:
        conn.execute("BEGIN")
        schema.validate_bindings(conn)
        matches = [row for row in schema.read_catalog(conn)["credentials"]
            if row.get("auth_type") == "google_oauth" and row.get("oauth_intent_id") == metadata.get("oauth_intent_id")]
        if len(matches) != 1:
            raise GoogleConsentError("Google refresh account binding refused")
        record = matches[0]
        core = conn.execute("SELECT id,name,kind,metadata,lifecycle_status FROM credentials WHERE id=?",
            (record["id"],)).fetchone()
        actual = validate_record(record, core, profile)
        if actual != metadata:
            raise GoogleConsentError("Google refresh metadata changed")
    return profile


def initialize(conn) -> None:
    schema._transaction(conn)
    _profile()
    conn.execute("""CREATE TABLE IF NOT EXISTS operator_catalog_oauth_intents (
        id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, state_digest TEXT UNIQUE,
        metadata_json TEXT NOT NULL)""")


def _read(row) -> dict:
    try:
        if not isinstance(row["metadata_json"], str) or len(row["metadata_json"].encode()) > 8192:
            raise ValueError()
        value = json.loads(row["metadata_json"])
        if (not isinstance(value, dict) or set(value) != _FIELDS
                or str(uuid.UUID(value["id"])) != value["id"]
                or value["id"] != row["id"] or value["actor_id"] != row["actor_id"]
                or value["state_digest"] != row["state_digest"]
                or value["status"] not in _STATUSES
                or value["provider_id"] != "google" or value["permission_preset"] != "gmail_readonly"
                or type(value["catalog_revision"]) is not int or value["catalog_revision"] < 1
                or type(value["reviewed_revision"]) is not int or value["reviewed_revision"] < 1
                or type(value["expires_at_epoch"]) is not int
                or not isinstance(value["created_at"], str) or not 1 <= len(value["created_at"]) <= 64
                or not isinstance(value["actor_id"], str) or not 1 <= len(value["actor_id"]) <= 512
                or not isinstance(value["name"], str) or not 1 <= len(value["name"]) <= 128
                or not isinstance(value["scopes"], list) or not value["scopes"]
                or any(not isinstance(item, str) or not 1 <= len(item) <= 512 for item in value["scopes"])
                or value["scopes"] != sorted(set(value["scopes"]))
                or not _HASH.fullmatch(value["policy_hash"])
                or not _HASH.fullmatch(value["oauth_profile_binding_digest"])
                or value["state_digest"] is not None and not _HASH.fullmatch(value["state_digest"])):
            raise ValueError()
        if value["credential_id"] is not None and str(uuid.UUID(value["credential_id"])) != value["credential_id"]:
            raise ValueError()
        if value["reason"] not in {None, "expired", "consent_denied", "exchange_failed", "persistence_failed", "identity_conflict"}:
            raise ValueError()
        if (value["status"] == "prepared" and value["state_digest"] is not None
                or value["status"] in {"awaiting_consent", "exchanging", "connected", "failed"}
                    and value["state_digest"] is None
                or (value["status"] == "connected") != (value["credential_id"] is not None)
                or value["status"] in {"prepared", "awaiting_consent", "exchanging", "connected"}
                    and value["reason"] is not None):
            raise ValueError()
        return value
    except (KeyError, TypeError, ValueError, AttributeError):
        raise GoogleConsentError("Google consent metadata unavailable") from None


def _save(conn, value: dict, *, create=False) -> None:
    if set(value) != _FIELDS:
        raise GoogleConsentError("Google consent metadata unavailable")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(raw.encode()) > 8192:
        raise GoogleConsentError("Google consent metadata unavailable")
    if create:
        conn.execute("INSERT INTO operator_catalog_oauth_intents VALUES(?,?,?,?)",
            (value["id"], value["actor_id"], value["state_digest"], raw))
    elif conn.execute("UPDATE operator_catalog_oauth_intents SET state_digest=?,metadata_json=? WHERE id=? AND actor_id=?",
            (value["state_digest"], raw, value["id"], value["actor_id"])).rowcount != 1:
        raise GoogleConsentError("Google consent metadata unavailable")


def _get(conn, identifier: str) -> dict:
    row = conn.execute("SELECT * FROM operator_catalog_oauth_intents WHERE id=?", (identifier,)).fetchone()
    if row is None:
        raise GoogleConsentError("Google consent intent unavailable")
    return _read(row)


def _state_hash(state: str) -> str:
    if not isinstance(state, str) or not _STATE.fullmatch(state):
        raise GoogleConsentError("Google consent state binding refused")
    return "sha256:" + hashlib.sha256(state.encode("ascii")).hexdigest()


def _cas(conn, revision: int, policy_hash: str) -> None:
    schema.require_revision(conn, revision)
    row = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()
    if row is None or row[0] != policy_hash:
        raise GoogleConsentError("Google consent review changed; start a new consent")


def _checked(conn, identifier: str, *, status: str, actor_id: str) -> dict:
    profile = _profile()
    value = _get(conn, identifier)
    if (value["status"] != status or value["expires_at_epoch"] <= int(time.time())
            or not isinstance(actor_id, str) or value["actor_id"] != actor_id
            or value["oauth_profile_binding_digest"] != profile.binding_digest
            or value["scopes"] != list(profile.scopes)):
        raise GoogleConsentError("Google consent intent is no longer usable")
    _cas(conn, value["catalog_revision"], value["policy_hash"])
    schema.validate_bindings(conn)
    return value


def _advance(conn, value: dict, event: str) -> None:
    value["catalog_revision"] = schema.advance_revision(conn, value["catalog_revision"])
    _save(conn, value)
    db.append_audit_event(conn, event_type="operator_catalog.oauth." + event,
        actor_type="admin", actor_id=value["actor_id"], event={
            "intent_id": value["id"], "provider": "google", "status": value["status"],
            "credential_id": value["credential_id"], "revision": value["catalog_revision"],
            "policy_hash": value["policy_hash"], "reason": value["reason"],
        })


def begin(payload: GoogleStartInput, actor_id: str) -> dict:
    profile = _profile()
    from serverware.config import OAUTH_STATE_TTL_SECONDS
    if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 512:
        raise GoogleConsentError("Google consent actor unavailable")
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _cas(conn, payload.expected_revision, payload.expected_policy_hash)
        schema.validate_bindings(conn)
        rows = [_read(row) for row in conn.execute("SELECT * FROM operator_catalog_oauth_intents LIMIT ?",
            (MAX_RETAINED_INTENTS + 1,))]
        if len(rows) >= MAX_RETAINED_INTENTS:
            raise GoogleConsentError("Google consent lifetime limit reached")
        now = int(time.time())
        # An uncertain exchange is not silently reset/pruned or made retryable.
        active = sum(row["status"] == "exchanging" or row["status"] in {"prepared", "awaiting_consent"}
            and row["expires_at_epoch"] > now for row in rows)
        if active >= MAX_ACTIVE_INTENTS:
            raise GoogleConsentError("Google consent active limit reached")
        from serverware.operator_catalog_mutations import _admit_create
        _admit_create(conn, schema.read_catalog(conn), "credentials")
        value = {"id": str(uuid.uuid4()), "actor_id": actor_id, "name": payload.name,
            "provider_id": "google", "permission_preset": profile.permission_preset,
            "scopes": list(profile.scopes), "oauth_profile_binding_digest": profile.binding_digest,
            "reviewed_revision": payload.expected_revision, "policy_hash": payload.expected_policy_hash,
            "catalog_revision": payload.expected_revision, "created_at": db.iso_now(),
            "expires_at_epoch": now + OAUTH_STATE_TTL_SECONDS, "status": "prepared",
            "state_digest": None, "credential_id": None, "reason": None}
        _save(conn, value, create=True)
        _advance(conn, value, "intent_created")
        conn.commit()
    return value


def bind_started(identifier: str, actor_id: str, started: dict) -> dict:
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        value = _checked(conn, identifier, status="prepared", actor_id=actor_id)
        if (started.get("provider") != "google" or sorted(started.get("scopes", [])) != value["scopes"]
                or started.get("redirectUri") != _profile().redirect_uri
                or type(started.get("expiresAtEpoch")) is not int):
            raise GoogleConsentError("Google consent start binding refused")
        value.update(state_digest=_state_hash(started.get("state")), status="awaiting_consent",
            expires_at_epoch=min(value["expires_at_epoch"], started["expiresAtEpoch"]))
        _advance(conn, value, "consent_started")
        conn.commit()
    return public(value)


def claim_consumed_state(record: dict, state: str) -> dict | None:
    """After one-use state/browser validation, before any provider contact."""
    from serverware import operator_demo
    identifier = record.get("operator_catalog_intent_id")
    if identifier is None:
        if operator_demo.active():
            raise GoogleConsentError("Operator Google consent requires a catalog intent")
        return None
    if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
        raise GoogleConsentError("Google consent intent binding refused")
    with exclusive(), db.connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        value = _checked(conn, identifier, status="awaiting_consent", actor_id=record.get("actor_id"))
        profile = _profile()
        if (not hmac.compare_digest(value["state_digest"] or "", _state_hash(state))
                or record.get("provider") != "google" or record.get("credential_name") != value["name"]
                or sorted(record.get("scopes", [])) != value["scopes"]
                or record.get("redirect_uri") != profile.redirect_uri
                or record.get("metadata") != {} or record.get("reconnect") is not None
                or record.get("setup_session_id") is not None):
            raise GoogleConsentError("Google consent state binding refused")
        value["status"] = "exchanging"
        _advance(conn, value, "exchange_claimed")
        conn.commit()
    return {"id": value["id"], "actor_id": value["actor_id"], "catalog_revision": value["catalog_revision"],
        "state_digest": value["state_digest"], "oauth_profile_binding_digest": value["oauth_profile_binding_digest"]}


def register_active(exchanged: dict, metadata: dict) -> dict:
    """One commit owns encrypted core storage, registration, revision and audit."""
    claim = exchanged.get("_operator_catalog_intent")
    if not isinstance(claim, dict):
        raise GoogleConsentError("Google consent registration binding refused")
    try:
        with exclusive(), db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            value = _checked(conn, claim.get("id"), status="exchanging", actor_id=exchanged.get("createdBy"))
            profile = _profile()
            if (claim != {"id": value["id"], "actor_id": value["actor_id"], "catalog_revision": value["catalog_revision"],
                    "state_digest": value["state_digest"], "oauth_profile_binding_digest": value["oauth_profile_binding_digest"]}
                    or exchanged.get("provider") != "google" or exchanged.get("kind") != "oauth2"
                    or exchanged.get("name") != value["name"] or exchanged.get("reconnect") is not None
                    or exchanged.get("_application_operation") is not None
                    or metadata.get("oauth") is not True or metadata.get("refreshable") is not True
                    or metadata.get("provider_id") != "google" or metadata.get("provider_identity_verified") is not True
                    or metadata.get("provider") != "google.oauth2"
                    or metadata.get("oauth_client_id") != profile.client_id
                    or metadata.get("injection_field") != "access_token"
                    or metadata.get("scopes") != list(profile.scopes)
                    or sorted(exchanged.get("scopes", [])) != list(profile.scopes)):
                raise GoogleConsentError("Google verified account or permissions do not match consent")
            provider, subject, account = db.validate_managed_oauth_account_identity(metadata)
            if provider != "google" or exchanged.get("providerSubject") != subject or exchanged.get("providerAccount") != account:
                raise GoogleConsentError("Google verified account does not match consent")
            from serverware.operator_catalog_mutations import _admit_create
            _admit_create(conn, schema.read_catalog(conn), "credentials")
            # The server alone supplies the catalog association. It is never
            # accepted as caller metadata or copied from a provider response.
            metadata = {**metadata, "oauth_intent_id": value["id"],
                "oauth_profile_binding_digest": profile.binding_digest}
            credential = db.create_credential(value["name"], "oauth2", exchanged["secret"], metadata,
                revocation_work_id=exchanged["revocationWorkId"], _connection=conn,
                _application_operation=exchanged.get("_application_operation"))
            record = {"id": credential["id"], "name": value["name"], "auth_type": "google_oauth",
                "header_name": "Authorization", "provider_subject": subject, "provider_account": account,
                "oauth_client_id": profile.client_id, "scopes": list(profile.scopes),
                "permission_preset": profile.permission_preset, "oauth_profile_binding_digest": profile.binding_digest,
                "oauth_intent_id": value["id"], "created_at": db.iso_now(), "status": "active"}
            schema.save_resource(conn, "credentials", record, create=True)
            schema.validate_bindings(conn)
            value.update(status="connected", credential_id=credential["id"])
            _advance(conn, value, "account_connected")
            _profile()  # Refuse changed cold profile before committing.
            conn.commit()
        return credential
    except db.OAuthGrantCollisionError:
        raise  # Existing grant-wide Google collision cleanup must remain authoritative.
    except Exception as error:
        raise GoogleConsentError("Google account could not be registered atomically") from error


def fail_state(provider_id: str, state: str | None, reason: str) -> None:
    """Best-effort metadata only; never revokes, retries, or handles token material."""
    if provider_id != "google" or reason not in {"consent_denied", "exchange_failed", "persistence_failed", "identity_conflict"}:
        return
    try:
        digest = _state_hash(state)
        _profile()
        with exclusive(), db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM operator_catalog_oauth_intents WHERE state_digest=?", (digest,)).fetchone()
            if row is None:
                return
            value = _read(row)
            if value["status"] not in {"awaiting_consent", "exchanging"}:
                return
            # Failure is not a replay grant or an implicit catalog/policy rebase.
            value.update(status="failed", reason=reason)
            _save(conn, value)
            db.append_audit_event(conn, event_type="operator_catalog.oauth.consent_failed",
                actor_type="admin", actor_id=value["actor_id"],
                event={"intent_id": value["id"], "provider": "google", "reason": reason})
            conn.commit()
    except Exception:
        pass  # Core retained issuance/cleanup ownership remains the source of truth.


def public(value: dict) -> dict:
    result = {key: value[key] for key in _PUBLIC if value[key] is not None}
    if value["status"] in {"prepared", "awaiting_consent"} and value["expires_at_epoch"] <= int(time.time()):
        result.update(status="expired", reason="expired")
    return result


def status(actor_id: str) -> dict:
    _profile()
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM operator_catalog_oauth_intents WHERE actor_id=? ORDER BY rowid LIMIT ?",
            (actor_id, MAX_RETAINED_INTENTS + 1)).fetchall()
        if len(rows) > MAX_RETAINED_INTENTS:
            raise GoogleConsentError("Google consent metadata unavailable")
        intents = [public(_read(row)) for row in rows]
    return {"apiVersion": "serverware.operatorGoogleConsent/v1", "intents": intents,
        "limits": {"active": MAX_ACTIVE_INTENTS, "retained": MAX_RETAINED_INTENTS},
        "productionReady": False, "protectedActivationSupported": False}
