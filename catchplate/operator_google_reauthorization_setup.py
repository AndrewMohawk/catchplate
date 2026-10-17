"""Explicit metadata-only setup for retained operator Google profiles.

This is administrator deployment setup, not account consent. No provider I/O,
secret reads, policy changes or automatic startup upgrades are permitted here.
"""
from __future__ import annotations

from pydantic import Field

from catchplate import db, operator_google_reauthorization_store as owner
from catchplate.operator_catalog_inputs import RevisionInput
from catchplate.operator_publication import exclusive


class SetupInput(RevisionInput):
    profile_binding_digest: str = Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$")


def status(actor_id: str) -> dict:
    owner._require(isinstance(actor_id, str) and 1 <= len(actor_id) <= 512)
    with db.connect() as conn:
        conn.execute("BEGIN")
        profile, catalog, policy_hash = owner._catalog_snapshot(conn)
        available = owner.available(conn)
        receipt = owner._audit(conn, owner.ADMISSION_ID, owner.ADMISSION_EVENT)[1] if available else None
        return {"schema": "catchplate.operatorGoogleReauthorizationStorage/v1",
            "available": available, "admission": receipt,
            "review": {"expected_revision": catalog["revision"], "expected_policy_hash": policy_hash,
                "profile_binding_digest": profile.binding_digest},
            "provider_contact": False, "account_permissions_changed": False}


def enable(payload: SetupInput, actor_id: str) -> dict:
    owner._require(type(payload) is SetupInput)
    receipt = None
    commit_attempted = False
    try:
        with exclusive(), db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            receipt = owner.upgrade(conn, actor_id=actor_id, **payload.model_dump())
            commit_attempted = True
            conn.commit()
    except Exception:
        if not commit_attempted or receipt is None:
            raise
        # A failed acknowledgement cannot authorize another schema write.
        with db.connect() as conn:
            conn.execute("BEGIN")
            owner.observe_upgrade(conn, receipt)
    return {"schema": "catchplate.operatorGoogleReauthorizationStorage/v1",
        "available": True, "admission": receipt, "provider_contact": False,
        "account_permissions_changed": False}
