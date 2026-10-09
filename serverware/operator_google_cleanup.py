"""Operator-only cleanup fencing; this module never contacts a provider.

The core vault/cleanup owner retains token material. These helpers join its
quarantine to catalog and policy publication, and preserve committed/deferred
outcomes across uncertain commit, materialization and publication-lock exits.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import db, operator_catalog_schema as schema
from serverware.operator_publication import exclusive

SOURCES = frozenset({"operator_google_initial_v1", "operator_google_refresh_v1", "operator_google_disconnect_v1"})
_REASONS = frozenset({"operator_google_rejected", "google_grant_collision", "registration_failed", "refresh_failed", "explicit_disconnect"})


@dataclass(frozen=True)
class CleanupOutcome:
    status: str
    work_id: str | None
    receipt: dict | None = None
    publication: str = "pending"
    reason: str = "cleanup_fence_unavailable"

    def public(self) -> dict:
        result = {"status": self.status, "work_id": self.work_id,
            "publication": self.publication, "reason": self.reason,
            "provider_revocation": "not_proven", "enforcement": "pending"}
        if self.receipt is not None:
            result["fence"] = dict(self.receipt)
        return result


class CleanupDisposition(RuntimeError):
    """A lifecycle result, never a generic persistence error or retry grant."""
    def __init__(self, outcome: CleanupOutcome):
        super().__init__("Operator Google cleanup requires its retained disposition")
        self.outcome = outcome


def _store():
    from serverware import operator_google_cleanup_store
    return operator_google_cleanup_store


def require_provider_io_unlocked() -> None:
    """Provider cleanup must never execute while this thread owns publication."""
    from serverware import operator_publication
    if getattr(operator_publication._state, "depth", 0):
        raise ValueError("Operator Google provider cleanup requires released publication ownership")


def operator_context(provider_id: str | None, *, result: dict | None = None, work_id=None) -> bool:
    """Server-owned markers and active profile cannot fall back to legacy."""
    if isinstance(result, dict) and (result.get("_operator_catalog_intent") is not None
            or result.get("_operator_google_work") is not None):
        return True
    if isinstance(work_id, str):
        try:
            if _store().get_work(work_id) is not None:
                return True
        except Exception:
            return True  # A broken operator association never lends legacy authority.
    if provider_id != "google":
        return False
    from serverware import operator_catalog_oauth_profile as profiles
    try:
        return profiles.selected() or _store().retained_ownership()
    except Exception:
        return True


def _metadata(work: dict) -> dict:
    association, identity = work["association"], work.get("identity")
    if not isinstance(identity, dict):
        raise ValueError("Google cleanup identity has not been verified")
    return {"oauth": True, "provider": "google.oauth2", "provider_id": "google",
        "provider_identity_verified": True, "oauth_client_id": association["oauth_client_id"],
        "provider_subject": identity["provider_subject"], "provider_account": identity["provider_account"]}


def fence_in_transaction(conn, work_id: str, *, reason="operator_google_rejected") -> dict:
    """Caller owns EX and one SQLite transaction; no commit or provider I/O."""
    from serverware import operator_catalog_oauth as consent, operator_catalog_policy as policy
    from serverware.operator_publication import assert_held
    assert_held()
    schema._transaction(conn)
    if reason not in _REASONS:
        raise ValueError("Google cleanup disposition is invalid")
    work = _store().get_work(work_id, conn=conn)
    if work is None or work.get("material_sha256") is None:
        raise ValueError("Google cleanup material is unavailable")
    if (reason == "explicit_disconnect") != (work["source"] == _store().DISCONNECT_SOURCE):
        raise ValueError("Google cleanup disposition does not match its owner")
    metadata = _metadata(work)
    catalog = schema.read_catalog(conn)
    schema.validate_bindings(conn, catalog)
    if work.get("fence") is not None:
        # The store validates the current reduced policy, while retaining the
        # original exact receipt after unrelated policy/revision changes.
        original = work["fence"]
        return _store().authorize_fence(conn, work_id=work_id, metadata=metadata,
            policy_hash=original["policy_hash"], catalog_revision=original["catalog_revision"])
    quarantine = db.quarantine_google_oauth_grant_family(
        oauth_client_id=metadata["oauth_client_id"], provider_subject=metadata["provider_subject"],
        actor_id=work["association"]["actor_id"], reason="operator_google_cleanup_fence",
        revocation_work_id=work_id, _connection=conn)
    changed_ids = {row["id"] for row in quarantine["credentials"]}
    by_id = {row["id"]: row for row in catalog["credentials"]}
    now = db.iso_now()
    for identifier in changed_ids:
        record = by_id.get(identifier)
        if record is None or record.get("auth_type") != "google_oauth" or record["status"] != "active":
            raise schema.CatalogIntegrityError("Google quarantine has no exact managed catalog binding")
        schema.save_resource(conn, "credentials", {**record, "status": "quarantined",
            "quarantined_at": now, "quarantine_reason": "operator_google_cleanup_fence",
            "quarantine_work_id": work_id})
    affected_rules = []
    for rule in catalog["access_rules"]:
        if rule["status"] == "active" and rule["credential_id"] in changed_ids:
            schema.save_resource(conn, "access_rules", {**rule, "status": "revoked", "revoked_at": now})
            affected_rules.append(rule["id"])
    publication = policy.publish(conn)
    revision = schema.advance_revision(conn, catalog["revision"])
    association = work["association"]
    if association["operation"] == "initial":
        intent = consent._get(conn, association["intent_id"])
        if intent["actor_id"] != association["actor_id"] or intent["status"] not in {"exchanging", "failed"}:
            raise schema.CatalogIntegrityError("Google cleanup consent disposition is inconsistent")
        # This is a protective fence, not a rebased permission to register an
        # account. Keep reviewed_revision and original consent policy intact.
        intent.update(status="failed", reason="identity_conflict" if reason == "google_grant_collision"
            else "persistence_failed", catalog_revision=revision)
        consent._save(conn, intent)
    db.append_audit_event(conn, event_type="operator_catalog.oauth.cleanup_quarantined",
        actor_type="admin", actor_id=association["actor_id"], event={"work_id": work_id,
            "credential_ids": sorted(changed_ids), "revoked_rule_ids": sorted(affected_rules),
            "revision": revision, "policy_hash": publication["policy_hash"], "reason": reason})
    return _store().authorize_fence(conn, work_id=work_id, metadata=metadata,
        policy_hash=publication["policy_hash"], catalog_revision=revision)


def materialize_committed(receipt: dict) -> CleanupOutcome:
    """Called only after definite COMMIT while publication EX remains held."""
    from serverware import operator_demo_store
    from serverware.operator_publication import assert_held
    publication = "pending"
    try:
        assert_held()
        operator_demo_store.materialize()
        publication = "materialized"
    except Exception:
        pass
    return CleanupOutcome("committed", receipt["work_id"], receipt, publication, "cleanup_fenced")


def committed(receipt: dict) -> CleanupOutcome:
    return CleanupOutcome("committed", receipt["work_id"], receipt, "pending", "cleanup_fenced")


def observe(work_id: str | None) -> CleanupOutcome:
    """Reobserve uncertain commit without replaying quarantine or provider work."""
    try:
        with exclusive(), db.connect() as conn:
            conn.execute("BEGIN")
            work = _store().get_work(work_id, conn=conn)
            if work is not None and work.get("fence") is not None:
                return committed(work["fence"])
    except Exception:
        pass
    return CleanupOutcome("deferred", work_id)


def fence(work_id: str | None, *, reason="operator_google_rejected") -> CleanupOutcome:
    """Idempotent protective transaction; provider cleanup is a separate owner."""
    receipt, did_commit, outcome = None, False, None
    try:
        with exclusive():
            with db.connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                receipt = fence_in_transaction(conn, work_id, reason=reason)
                conn.commit()
                did_commit = True
            outcome = materialize_committed(receipt)
        return outcome
    except Exception:
        if did_commit:
            return committed(receipt)  # A post-commit guard failure is not rollback.
        return observe(work_id)


def retain_uncertain(work_id: str, *, material_attached: bool) -> CleanupOutcome:
    """Never claim safe revocation or durable token retention that did not occur."""
    try:
        if material_attached:
            # Protected source remains ineligible until a fence exists; the DB
            # owner may keep this held instead of ordinary pending work.
            db.mark_oauth_revocation_work_pending(work_id, error="operator_google_cleanup_fence_required")
        else:
            db.mark_oauth_issuance_uncertain(work_id, error="operator_google_material_retention_uncertain")
    except Exception:
        pass
    return CleanupOutcome("deferred", work_id, reason="cleanup_fence_required" if material_attached
        else "material_retention_uncertain")
