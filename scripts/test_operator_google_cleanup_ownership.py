#!/usr/bin/env python3
"""Bounded real-SQLite operator cleanup ownership regressions.

Provider responses are synthetic transport only. Successful assertions use the
real schema, lifecycle, encryption and cleanup guards. Deliberate SQLite/env
corruption is confined to refusal fixtures; it is never a success bypass.
Run only in the isolated network-none backend harness selected by the root.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_google_cleanup as cleanup_tests
import test_operator_google_consent as consent_tests

ROOT = Path(__file__).resolve().parents[1]
WORK_TABLE = cleanup_tests.WORK_TABLE
Fixture = cleanup_tests.Fixture


@contextmanager
def runtime_profile_drift(f):
    """Removing an already admitted capability is drift, not cold disablement."""
    with patch.dict(os.environ):
        os.environ.pop("CATCHPLATE_OPERATOR_GOOGLE_PROFILE", None)
        consent_tests.refused(f.profiles.selected, f.profiles.OperatorGoogleProfileError)
        consent_tests.refused(f.profiles.require_profile, f.profiles.OperatorGoogleProfileError)
        yield


def core_schema(db):
    with closing(db.connect()) as conn:
        ddl = [tuple(row) for row in conn.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE tbl_name='oauth_revocation_work' ORDER BY type,name")]
        contract = [tuple(row) for row in conn.execute(
            "SELECT * FROM policy_authority_schema_contracts ORDER BY schema_version")]
    return {"ddl": ddl, "contract": contract}


def cold_start():
    f = Fixture()  # Original init_db + operator initialize, no initializer patch.
    state = core_schema(f.db)
    assert state["contract"]
    assert not [row for row in state["ddl"] if row[0] == "trigger"], \
        "operator initialization changed protected core trigger ownership"
    assert not f.history
    return state


def invalid_core_prepare():
    f = Fixture()
    with closing(f.db.connect()) as conn, conn:
        # Exact obsolete ownership strategy; only a private negative database.
        conn.execute("CREATE TRIGGER operator_google_cleanup_source_immutable "
            "BEFORE UPDATE OF id,source,provider_id,actor_id ON oauth_revocation_work "
            "BEGIN SELECT RAISE(ABORT,'obsolete operator core trigger'); END")
    return core_schema(f.db)


def invalid_core_check():
    _config, db, _store, _bundles = cleanup_tests.workspace.common.backend(initialize=False)
    before = core_schema(db)
    consent_tests.refused(db.init_db, (db.MetadataStoreError, db.PolicyCandidateAuthorityError))
    assert core_schema(db) == before, "startup silently repaired or re-sealed invalid protected DDL"
    return before


def corrupt(f, statement, values=()):
    """Seed only a refusal fixture; never use this connection for success."""
    with sqlite3.connect(str(f.config.DB_PATH)) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        conn.execute(statement, values)


def remove_association_for_refusal(f, work_id):
    # A real startup must reject guard drift. Here restore the identical guard
    # SQL after seeding one absent association, isolating the data-level refusal.
    cleanup_tests.remove_association_for_refusal(f, work_id)


def owned_corruption(change):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        row = next(row for row in f.rows("oauth_revocation_work") if row["id"] == work_id)
        secret = json.loads(f.db.decrypt_secret_envelope(row))
        if change == "orphan":
            corrupt(f, "DELETE FROM oauth_revocation_work WHERE id=?", (work_id,))
            assert any(row["work_id"] == work_id for row in f.rows(WORK_TABLE))
        elif change == "missing-association":
            remove_association_for_refusal(f, work_id)
        elif change == "retag":
            corrupt(f, "UPDATE oauth_revocation_work SET source='authorization_code_exchange',provider_id='x',"
                "actor_id='different-synthetic-actor',status='pending',next_attempt_at=? WHERE id=?",
                (cleanup_tests.OLD, work_id))
        else:
            raise AssertionError("unknown ownership refusal fixture")
        before = f.snapshot()
        assert f.profiles.selected() is True
        consent_tests.refused(lambda: f.cleanup_store.get_work(work_id), ValueError)
        # Mutable provider/source never outrank the admitted durable owner.
        assert f.cleanup.operator_context("x", work_id=work_id)
        assert f.cleanup.operator_context("x", result={"_operator_google_work": work_id})
        for action in (
            lambda: f.cleanup_store.require_permit(work_id=work_id, secret=secret),
            lambda: f.db.mark_oauth_revocation_work_pending(work_id, error="synthetic refusal"),
            lambda: f.db.complete_oauth_revocation_work(work_id),
            lambda: f.db.resolve_oauth_issuance_uncertainty(work_id, actor_id="synthetic-reviewer"),
            lambda: f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret,
                _operator_cleanup_work_id=work_id),
            lambda: f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret),
            lambda: f.db.reserve_oauth_revocation_work(provider_id="google", actor_id="synthetic-reviewer",
                source="authorization_code_exchange"),
        ):
            consent_tests.refused(action, (ValueError, f.oauth.OAuthError))
        disposition = f.app._revoke_rejected_oauth_exchange({"provider": "x", "secret": json.dumps(secret),
            "revocationWorkId": work_id, "_operator_google_work": work_id}, actor_id="synthetic-reviewer")
        assert disposition["status"] == "deferred"
        assert not f.db.claim_oauth_revocations(worker_id="ownership-refusal", limit=1)
        assert f.app._reconcile_oauth_revocations(limit=1)["revoked"] == 0
        if change == "orphan":
            with patch.object(f.db, "_OAUTH_REVOCATION_BACKLOG_MAX_COUNT", 1):
                consent_tests.refused(lambda: f.db.reserve_oauth_revocation_work(provider_id="x",
                    actor_id="synthetic-reviewer", source="authorization_code_exchange"), ValueError)
        with runtime_profile_drift(f):
            consent_tests.refused(lambda: f.db.reserve_oauth_revocation_work(provider_id="google",
                actor_id="synthetic-reviewer", source="authorization_code_exchange"),
                f.profiles.OperatorGoogleProfileError)
        assert f.snapshot() == before and f.revocations == 0
        f.assert_redacted_cleanup()
    return {"work_id": work_id, "corruption": change, "active_owner_refused": True,
        "runtime_drift_refused": True, "revocations": 0}


def direct_deletion():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        before = f.snapshot()
        for table, column in ((WORK_TABLE, "work_id"), ("oauth_revocation_work", "id")):
            with closing(f.db.connect()) as conn, conn:
                consent_tests.refused(lambda: conn.execute("DELETE FROM " + table + " WHERE " + column + "=?",
                    (work_id,)), sqlite3.DatabaseError)
            assert f.snapshot() == before
        # A separate raw SQLite connection has no retirement capability either.
        with sqlite3.connect(str(f.config.DB_PATH)) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            consent_tests.refused(lambda: conn.execute("DELETE FROM oauth_revocation_work WHERE id=?",
                (work_id,)), sqlite3.DatabaseError)
        assert f.snapshot() == before
        with closing(f.db.connect()) as conn, conn:
            consent_tests.refused(lambda: conn.execute("UPDATE " + WORK_TABLE
                + " SET source='authorization_code_exchange' WHERE work_id=?", (work_id,)), sqlite3.DatabaseError)
        assert f.snapshot() == before
        for column in ("work_id", "source", "association_json"):
            with closing(f.db.connect()) as conn, conn:
                consent_tests.refused(lambda: conn.execute("UPDATE " + WORK_TABLE + " SET "
                    + column + "=NULL WHERE work_id=?", (work_id,)), sqlite3.DatabaseError)
            assert f.snapshot() == before, "NULL bypassed immutable operator ownership"
        corrupt(f, "UPDATE oauth_revocation_work SET source='authorization_code_exchange',"
            "status='pending',next_attempt_at=? WHERE id=?", (cleanup_tests.OLD, work_id))
        retagged = f.snapshot()
        consent_tests.refused(lambda: f.cleanup_store.get_work(work_id), ValueError)
        assert not f.db.claim_oauth_revocations(worker_id="null-owner-regression", limit=1)
        assert f.snapshot() == retagged and f.revocations == 0
    return {"direct_side_delete_denied": True, "parent_cascade_denied": True,
        "separate_connection_denied": True, "owner_source_immutable": True,
        "null_owner_fields_refused": True, "core_retag_still_withheld": True}


def ordinary_work(f, *, pending=True):
    work_id = f.db.reserve_oauth_revocation_work(provider_id="x", actor_id="synthetic-ordinary-owner",
        source="authorization_code_exchange")
    f.db.mark_oauth_exchange_started(work_id)
    f.db.attach_oauth_revocation_material(work_id, secret=json.dumps({"access_token": "synthetic-ordinary-access",
        "token_type": "Bearer"}))
    if pending:
        f.db.mark_oauth_revocation_work_pending(work_id, error="synthetic ordinary cleanup")
    return work_id


def replacement_ownership():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        owner = next(row for row in f.rows(WORK_TABLE) if row["work_id"] == work_id)
        columns = ("work_id", "source", "association_json", "identity_json", "material_sha256",
            "fence_json", "created_at")
        before = f.snapshot()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("PRAGMA recursive_triggers=OFF")
            assert conn.execute("PRAGMA recursive_triggers").fetchone()[0] == 0
            for verb in ("INSERT", "INSERT OR REPLACE", "REPLACE"):
                for changed in ({}, {"association_json": "{}"}, {"identity_json": "{}"}, {"fence_json": "{}"}):
                    candidate = {**owner, **changed}
                    consent_tests.refused(lambda: conn.execute(verb + " INTO " + WORK_TABLE + " ("
                        + ",".join(columns) + ") VALUES (" + ",".join("?" for _ in columns) + ")",
                        tuple(candidate[key] for key in columns)), sqlite3.IntegrityError)
                    assert f.snapshot() == before, "duplicate insert/replacement changed durable ownership"
            for alias in ("rowid", "oid", "_rowid_"):
                consent_tests.refused(lambda: conn.execute("SELECT " + alias + " FROM " + WORK_TABLE
                    + " WHERE work_id=?", (work_id,)).fetchall(), sqlite3.OperationalError)
                consent_tests.refused(lambda: conn.execute("INSERT OR REPLACE INTO " + WORK_TABLE
                    + " (" + alias + "," + ",".join(columns) + ") VALUES (? ,"
                    + ",".join("?" for _ in columns) + ")", (1, *(owner[key] for key in columns))),
                    sqlite3.OperationalError)
                assert f.snapshot() == before, "hidden row-ID replacement erased durable ownership"
        corrupt(f, "UPDATE oauth_revocation_work SET source='authorization_code_exchange',status='pending',"
            "next_attempt_at=? WHERE id=?", (cleanup_tests.OLD, work_id))
        after_retag = f.snapshot()
        assert not f.db.claim_oauth_revocations(worker_id="replacement-owner-check", limit=1)
        assert f.snapshot() == after_retag and f.revocations == 0
    return {"duplicate_insert_replace_refusals": 12, "hidden_rowid_aliases_absent": 3,
        "recursive_triggers_disabled": True, "retagged_owner_still_withheld": True}


def expiry_and_limit():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        protected = f.held()
        corrupt(f, "UPDATE oauth_revocation_work SET source='authorization_code_exchange',"
            "status='reserved',next_attempt_at=? WHERE id=?", (cleanup_tests.OLD, protected))
        ordinary = ordinary_work(f)
        row = next(row for row in f.rows("oauth_revocation_work") if row["id"] == protected)
        assert row["status"] == "reserved", "reserved expiry erased or promoted a retained owner"
        corrupt(f, "UPDATE oauth_revocation_work SET status='held' WHERE id=?", (protected,))
        claimed = f.db.claim_oauth_revocations(worker_id="ordinary-first", limit=1)
        assert [row["id"] for row in claimed] == [ordinary]
        assert next(row for row in f.rows("oauth_revocation_work") if row["id"] == protected)["status"] == "held"
        assert f.db.finish_oauth_revocation_work(ordinary, worker_id="ordinary-first", succeeded=True)["ok"]
        # A withheld old pending row must be excluded BEFORE LIMIT, not merely
        # rejected after it consumed the only ordinary work slot.
        corrupt(f, "UPDATE oauth_revocation_work SET status='pending' WHERE id=?", (protected,))
        following = ordinary_work(f)
        claimed = f.db.claim_oauth_revocations(worker_id="ordinary-second", limit=1)
        assert [row["id"] for row in claimed] == [following]
        assert f.db.finish_oauth_revocation_work(following, worker_id="ordinary-second", succeeded=True)["ok"]
        held_ordinary = ordinary_work(f, pending=False)
        assert f.db.complete_oauth_revocation_work(held_ordinary)
        assert [row["id"] for row in f.rows("oauth_revocation_work")] == [protected]
        assert [row["work_id"] for row in f.rows(WORK_TABLE)] == [protected]
        assert f.revocations == 0
    return {"owner_excluded_from_expiry_and_promotion": True, "ordinary_claim_before_limit": True,
        "ordinary_cleanup_compatible": True, "provider_contact": False}


def deletion_fault(f, *, install):
    with closing(f.db.connect()) as conn, conn:
        if install:
            # Negative-only fault on the terminal DELETE, after its FK actions.
            # Remove before any subsequent cold startup/schema validation.
            conn.execute("CREATE TRIGGER synthetic_retirement_abort AFTER DELETE ON oauth_revocation_work "
                "BEGIN SELECT RAISE(ABORT,'synthetic retirement rollback'); END")
        else:
            conn.execute("DROP TRIGGER synthetic_retirement_abort")


def callback_denied(conn, work_id):
    assert conn.execute("SELECT operator_google_cleanup_retire_allowed(?)", (work_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT operator_google_cleanup_retire_allowed(?)",
        ("00000000-0000-0000-0000-000000000001",)).fetchone()[0] == 0


def adoption_and_refresh():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        exchanged = f.exchange()
        work_id = exchanged["revocationWorkId"]
        deletion_fault(f, install=True)
        before = f.snapshot()
        try:
            f.consent.register_active(exchanged, exchanged["metadata"])
        except f.cleanup.CleanupDisposition as error:
            assert error.outcome.status == "deferred"
        else:
            raise AssertionError("terminal adoption fault was not refused")
        assert f.snapshot() == before, "failed adoption left a half-retired pair"
        with closing(f.db.connect()) as conn:
            callback_denied(conn, work_id)
        deletion_fault(f, install=False)
        # This explicit fixture retry reuses retained verified exchange material;
        # it performs no second consent/provider exchange or automatic renewal.
        record = f.consent.register_active(exchanged, exchanged["metadata"])
        assert not f.rows(WORK_TABLE) and not f.rows("oauth_revocation_work")
        core = f.db.get_credential(record["id"], include_secret=True)
        expired, changed = f.db.update_credential_secret_if_version(core["id"],
            expected_version=core["credential_version"],
            secret=json.dumps({**json.loads(core["secret"]), "expires_at_epoch_ms": 1}),
            metadata={**core["metadata"], "expires_at_epoch_ms": 1})
        assert changed
        f.refresh_core = expired
        f.app.runtime.invalidate_secret_leases(core["id"])
        refreshed = f.app._credential_for_lease(core["id"])
        assert refreshed["credential_version"] == expired["credential_version"] + 1
        assert not f.rows(WORK_TABLE) and not f.rows("oauth_revocation_work")
        assert [item["association"]["operation"] for item in f.reservations] == ["initial", "refresh"]
        with closing(f.db.connect()) as conn:
            for reservation in f.reservations:
                callback_denied(conn, reservation["work_id"])
        assert f.revocations == 0
        f.assert_redacted_cleanup()
    return {"adoption_rollback_preserves_pair": True, "initial_and_refresh_retired": True,
        "capability_not_reusable": True}


def fenced_work(f):
    f.with_shared_family()
    work_id = f.held()
    outcome = f.cleanup.fence(work_id)
    assert outcome.status == "committed" and outcome.receipt["credential_ids"]
    f.due(work_id)
    return work_id


def worker_private_identity():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        work_id = fenced_work(f)
        claimed = f.db.claim_oauth_revocations(worker_id="identity-observer", limit=1)
        assert len(claimed) == 1 and claimed[0]["id"] == work_id
        assert claimed[0]["operator_google_cleanup_work_id"] == work_id
        secret = json.loads(claimed[0]["secret"])
        consent_tests.refused(lambda: f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret,
            _operator_cleanup_work_id="00000000-0000-0000-0000-000000000001"), f.oauth.OAuthError)
        with f.store.operator_publication.exclusive():
            consent_tests.refused(lambda: f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret,
                _operator_cleanup_work_id=work_id), f.oauth.OAuthError)
        with runtime_profile_drift(f):
            for kwargs in ({}, {"_operator_cleanup_work_id": work_id}):
                consent_tests.refused(lambda: f.oauth.revoke_oauth_token(provider_id="google",
                    token_secret=secret, **kwargs), f.oauth.OAuthError)
        assert f.revocations == 0
        f.due(work_id)  # Release only this private fixture's inspection claim.
        # Observation wrapper invokes the unmodified low-level permit/transport.
        with patch.object(f.app, "revoke_oauth_token", wraps=f.oauth.revoke_oauth_token) as observed:
            result = f.app._reconcile_oauth_revocations(limit=1)
        assert observed.call_count == 1
        assert observed.call_args.kwargs["_operator_cleanup_work_id"] == work_id
        assert result["revoked"] == 1 and f.revocations == 1
        assert not f.rows(WORK_TABLE) and not f.rows("oauth_revocation_work")
        with closing(f.db.connect()) as conn:
            callback_denied(conn, work_id)
        f.assert_redacted_cleanup()
    return {"authoritative_claim_marker": True, "exact_private_permit_id": True,
        "actual_worker_retired_pair": True}


def retirement_rollback():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        work_id = fenced_work(f)
        claimed = f.db.claim_oauth_revocations(worker_id="terminal-owner", limit=1)
        assert [row["id"] for row in claimed] == [work_id]
        secret = json.loads(claimed[0]["secret"])
        f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret,
            _operator_cleanup_work_id=work_id)
        assert f.revocations == 1
        # Generic completion has no terminal authority, even with a real fence.
        consent_tests.refused(lambda: f.db.complete_oauth_revocation_work(work_id), ValueError)
        consent_tests.refused(lambda: f.db.resolve_oauth_issuance_uncertainty(work_id,
            actor_id="synthetic-reviewer"), ValueError)
        deletion_fault(f, install=True)
        before = f.snapshot()
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            consent_tests.refused(lambda: f.cleanup_store.retire(conn, work_id,
                worker_id="wrong-worker"), ValueError)
            consent_tests.refused(lambda: f.cleanup_store.retire(conn, work_id,
                worker_id="terminal-owner"), sqlite3.DatabaseError)
            callback_denied(conn, work_id)
            assert conn.execute("SELECT 1 FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
            assert conn.execute("SELECT 1 FROM " + WORK_TABLE + " WHERE work_id=?", (work_id,)).fetchone()
            conn.rollback()
        assert f.snapshot() == before
        deletion_fault(f, install=False)
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            assert f.cleanup_store.retire(conn, work_id, worker_id="terminal-owner")
            callback_denied(conn, work_id)
            conn.commit()
        assert not f.rows(WORK_TABLE) and not f.rows("oauth_revocation_work")
        with closing(f.db.connect()) as conn:
            callback_denied(conn, work_id)
        f.assert_redacted_cleanup()
    return {"terminal_rollback_preserves_pair": True, "capability_reset_after_failure": True,
        "claimed_success_retired_pair": True, "revocations": f.revocations}


def guard_prepare(change):
    f = Fixture()
    with closing(f.db.connect()) as conn, conn:
        if change == "table-missing":
            conn.execute("DROP TABLE " + WORK_TABLE)
        else:
            conn.execute("DROP TRIGGER operator_google_cleanup_retirement_guard")
        if change == "changed":
            conn.execute("CREATE TRIGGER operator_google_cleanup_retirement_guard BEFORE DELETE ON "
                + WORK_TABLE + " BEGIN SELECT RAISE(ABORT,'different owner guard'); END")
        elif change not in {"missing", "table-missing"}:
            raise AssertionError("unknown retained schema refusal")
    return owner_schema(f.db)


def owner_schema(db):
    with closing(db.connect()) as conn:
        return [tuple(row) for row in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE tbl_name=? ORDER BY type,name", (WORK_TABLE,))]


def guard_check():
    _config, db, store, _bundles = cleanup_tests.workspace.common.backend(initialize=False)
    from catchplate import operator_google_cleanup_store
    db.init_db()  # Protected v9 schema still passes; only the side guard drifted.
    before = owner_schema(db)
    consent_tests.refused(store.initialize, operator_google_cleanup_store.CleanupStoreError)
    assert owner_schema(db) == before, "startup repaired a retained missing/malformed side guard"
    return before


def valid_owned_prepare():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        assert f.cleanup_store.get_work(work_id)["fence"] is None
        f.assert_redacted_cleanup()
    return {"work_id": work_id}


def cold_disabled_check(change):
    """A new process has never admitted Google; retained ownership still denies."""
    from catchplate import operator_catalog_oauth_profile as profiles
    assert "CATCHPLATE_OPERATOR_GOOGLE_PROFILE" not in os.environ
    assert all(key not in os.environ for key in profiles.GOOGLE_CONFIGURATION_KEYS)
    assert profiles.selected() is False
    # This is original static-profile activation, not Fixture() or an admission
    # reset. The existing core schema initializes normally; its Google catalog
    # pin must then refuse being reopened as an unconfigured Google workspace.
    config, db, store, _bundles = cleanup_tests.workspace.common.backend(initialize=False)
    from catchplate import app, oauth, operator_catalog_schema as schema
    from catchplate import operator_google_cleanup as cleanup, operator_google_cleanup_store as cleanup_store
    db.init_db()

    def retained_snapshot():
        with closing(db.connect()) as conn:
            rows = {table: sorted(tuple(row) for row in conn.execute("SELECT * FROM " + table))
                for table in cleanup_tests.TABLES}
        return rows, config.POLICY_BUNDLE_PATH.read_bytes(), owner_schema(db)

    before = retained_snapshot()  # Do not treat normal init timestamps as guard effects.
    consent_tests.refused(store.initialize, schema.CatalogIntegrityError)
    assert profiles.selected() is False and retained_snapshot() == before
    with closing(db.connect()) as conn:
        identifiers = {row[0] for row in conn.execute("SELECT work_id FROM " + WORK_TABLE)}
        identifiers.update(row[0] for row in conn.execute("SELECT id FROM oauth_revocation_work"))
    assert len(identifiers) == 1
    work_id = identifiers.pop()
    assert cleanup_store.retained_ownership() is True
    assert cleanup.operator_context("google")
    assert cleanup.operator_context("x", work_id=work_id)
    if change == "valid":
        assert cleanup_store.get_work(work_id)["work_id"] == work_id
    else:
        consent_tests.refused(lambda: cleanup_store.get_work(work_id), cleanup_store.CleanupStoreError)
    secret = {"access_token": consent_tests.ACCESS, "refresh_token": consent_tests.REFRESH, "token_type": "Bearer"}
    consent_tests.refused(lambda: cleanup_store.require_permit(work_id=work_id, secret=secret),
        cleanup_store.CleanupStoreError)
    consent_tests.refused(lambda: db.reserve_oauth_revocation_work(provider_id="google", actor_id="cold-refusal",
        source="authorization_code_exchange"), cleanup_store.CleanupStoreError)
    calls = []

    def no_transport(request, **_options):
        calls.append(request.full_url)
        raise AssertionError("unconfigured retained workspace attempted provider contact")

    with patch.object(oauth, "request_bytes", side_effect=no_transport):
        # No Google client exists in this process. These low-level refusals are
        # NOT sole proof of the permit guard: the ownership/permit/reservation
        # assertions above independently verify the retained boundary.
        for kwargs in ({}, {"_operator_cleanup_work_id": work_id}):
            consent_tests.refused(lambda: oauth.revoke_oauth_token(provider_id="google",
                token_secret=secret, **kwargs), oauth.OAuthError)
        disposition = app._revoke_rejected_oauth_exchange({"provider": "x", "secret": json.dumps(secret),
            "revocationWorkId": work_id, "_operator_google_work": work_id}, actor_id="cold-refusal")
        assert disposition["status"] == "deferred"
        assert not db.claim_oauth_revocations(worker_id="cold-refusal", limit=1)
        assert app._reconcile_oauth_revocations(limit=1)["revoked"] == 0
    assert not calls and profiles.selected() is False and retained_snapshot() == before
    return {"work_id": work_id, "cold_unconfigured": True, "startup_refused_retained_pin": True,
        "ownership_refused_without_profile": True, "provider_calls": 0}


OPERATIONS = {"cold-start": cold_start, "invalid-core-prepare": invalid_core_prepare,
    "invalid-core-check": invalid_core_check, "direct-deletion": direct_deletion,
    "replacement-ownership": replacement_ownership,
    "expiry-and-limit": expiry_and_limit, "adoption-and-refresh": adoption_and_refresh,
    "worker-private-identity": worker_private_identity, "retirement-rollback": retirement_rollback,
    "guard-missing-prepare": lambda: guard_prepare("missing"),
    "guard-changed-prepare": lambda: guard_prepare("changed"),
    "guard-table-prepare": lambda: guard_prepare("table-missing"), "guard-check": guard_check,
    "valid-owned-cold": valid_owned_prepare}
for _change in ("orphan", "missing-association", "retag"):
    OPERATIONS["owned-" + _change] = lambda change=_change: owned_corruption(change)
for _change in ("orphan", "missing-association", "retag", "valid"):
    OPERATIONS["cold-disabled-" + _change] = lambda change=_change: cold_disabled_check(change)


class OperatorGoogleCleanupOwnershipTests(unittest.TestCase):
    setUp = consent_tests.OperatorGoogleConsentTests.setUp

    def worker(self, operation, *, unconfigured=False):
        environment = self.environment.copy()
        if unconfigured:
            for name in ("CATCHPLATE_OPERATOR_GOOGLE_PROFILE", "CATCHPLATE_GOOGLE_OAUTH_CLIENT_ID",
                    "CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET_FILE", "CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI",
                    "CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET"):
                environment.pop(name, None)
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_two_cold_starts_preserve_protected_schema(self):
        self.assertEqual(self.worker("cold-start"), self.worker("cold-start"))

    def test_old_invalid_core_trigger_is_not_silently_repaired(self):
        self.assertEqual(self.worker("invalid-core-prepare"), self.worker("invalid-core-check"))

    def test_retained_missing_guard_is_not_recreated(self):
        self.assertEqual(self.worker("guard-missing-prepare"), self.worker("guard-check"))

    def test_retained_changed_guard_is_not_replaced(self):
        self.assertEqual(self.worker("guard-changed-prepare"), self.worker("guard-check"))

    def test_retained_missing_owner_table_is_not_recreated(self):
        self.assertEqual(self.worker("guard-table-prepare"), self.worker("guard-check"))


def _test(operation):
    def check(self):
        prepared = self.worker(operation)
        if operation.startswith("owned-") or operation == "valid-owned-cold":
            change = operation.removeprefix("owned-") if operation.startswith("owned-") else "valid"
            observed = self.worker("cold-disabled-" + change, unconfigured=True)
            self.assertEqual(prepared["work_id"], observed["work_id"])
    return check


for _operation in OPERATIONS:
    if not _operation.startswith(("cold-", "invalid-core-", "guard-")):
        setattr(OperatorGoogleCleanupOwnershipTests, "test_" + _operation.replace("-", "_"), _test(_operation))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
