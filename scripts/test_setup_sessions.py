#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def digest(character: str) -> str:
    return "sha256:" + character * 64


def digest_value(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def configure_sqlite(data_dir: str) -> None:
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"


def configure_postgres(base_dsn: str, data_dir: str) -> str:
    import psycopg

    schema = f"serverware_setup_test_{uuid.uuid4().hex}"
    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE SCHEMA "{schema}"')
    separator = "&" if "?" in base_dsn else "?"
    dsn = f"{base_dsn}{separator}options={quote(f'-csearch_path={schema}', safe='')}"
    os.environ["SERVERWARE_DATA_DIR"] = data_dir
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
    os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_METADATA_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_GRANT_STORE_POSTGRES_DSN"] = dsn
    os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "postgres"
    os.environ["SERVERWARE_AUDIT_STORE_POSTGRES_DSN"] = dsn
    return schema


def drop_postgres_schema(base_dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def expect_error(
    expected: type[BaseException], callback: Callable[[], Any], message: str
) -> BaseException:
    try:
        callback()
    except expected as exc:
        return exc
    raise AssertionError(message)


def create_session(db: Any, suffix: str, **overrides: Any) -> dict[str, Any]:
    values = {
        "owner_id": f"user:{suffix}",
        "current_assignee_id": f"user:{suffix}",
        "template_id": f"template:{suffix}",
        "principal_id": f"agent:{suffix}",
        "route_id": f"route:{suffix}",
        "route_policy_digest": digest("a"),
    }
    values.update(overrides)
    return db.create_setup_session(**values)


def bind_credential(db: Any, session: dict[str, Any], suffix: str) -> dict[str, Any]:
    updates = {
        "credential_id": f"credential:{suffix}",
        "credential_version": 1,
    }
    if session["route_policy_digest"] is not None:
        updates["route_policy_digest"] = session["route_policy_digest"]
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_credential",
        actor_id=session["owner_id"],
        updates=updates,
    )


def stage_candidate(
    db: Any,
    session: dict[str, Any],
    suffix: str,
    *,
    canary_id: str | None = None,
) -> dict[str, Any]:
    updates = {
        "policy_hash": digest("b"),
        "assignment_digest": digest("c"),
        "canary_id": canary_id or f"canary:{suffix}",
    }
    if session["route_policy_digest"] is None:
        updates["route_policy_digest"] = digest("a")
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_candidate",
        actor_id=session["owner_id"],
        updates=updates,
    )


def activate_policy(db: Any, session: dict[str, Any]) -> dict[str, Any]:
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="activate_policy",
        actor_id=session["owner_id"],
    )


def bind_enrollment(
    db: Any,
    session: dict[str, Any],
    suffix: str,
    *,
    enrollment_session_id: str | None = None,
) -> dict[str, Any]:
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_enrollment",
        actor_id=session["owner_id"],
        updates={
            "enrollment_session_id": enrollment_session_id or f"enrollment:{suffix}",
            "enrollment_packet_digest": digest("d"),
            "verifier_nonce_hash": digest("e"),
        },
    )


def setup_evidence(
    kind: str, suffix: str, *, verifier_key_id: str = "verifier:test"
) -> list[dict[str, Any]]:
    receipt_kinds = {
        "enrollment_verification": "serverware.setupEnrollmentVerification/v1",
        "hardware_assurance": "serverware.setupHardwareVerification/v1",
        "final_challenge_receipt": "serverware.setupFinalChallengeReceipt/v1",
    }
    document = {"receipt": suffix, "verified": True}
    if kind in receipt_kinds:
        document = {
            "kind": receipt_kinds[kind],
            "statement": {"receipt": suffix, "verified": True},
            "signature": {
                "algorithm": "test-only",
                "value": f"signed:{suffix}",
            },
        }
    return [
        {
            "kind": kind,
            "document": document,
            "verifier_key_id": verifier_key_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
    ]


def advance_to_enrollment(db: Any, suffix: str) -> dict[str, Any]:
    return bind_enrollment(
        db,
        activate_policy(
            db,
            stage_candidate(
                db,
                bind_credential(db, create_session(db, suffix), suffix),
                suffix,
            ),
        ),
        suffix,
    )


def advance_to_runtime(db: Any, suffix: str) -> dict[str, Any]:
    session = advance_to_enrollment(db, suffix)
    for transition, kind in (
        ("record_enrollment_evidence", "enrollment_verification"),
        ("record_canary_evidence", "canary_result"),
        ("record_runtime_evidence", "runtime_verification"),
    ):
        session = db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition=transition,
            actor_id=session["owner_id"],
            evidence=setup_evidence(kind, f"{suffix}:{kind}"),
        )
    return session


def bind_challenge(
    db: Any, session: dict[str, Any], challenge_digest: str
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    challenge = bytes.fromhex(challenge_digest.removeprefix("sha256:"))
    actual_digest = "sha256:" + hashlib.sha256(challenge).hexdigest()
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_attestation_challenge",
        actor_id=session["owner_id"],
        updates={
            "attestation_challenge_digest": actual_digest,
            "attestation_challenge_issued_at": (now - timedelta(seconds=1)).isoformat(),
            "attestation_challenge_expires_at": (now + timedelta(hours=1)).isoformat(),
            "attestation_challenge_value": base64.urlsafe_b64encode(challenge)
            .decode("ascii")
            .rstrip("="),
        },
    )


def exercise_challenge_recovery_and_approval_atomicity(db: Any) -> None:
    session = advance_to_runtime(db, "challenge-recovery")
    now = datetime.now(timezone.utc)
    first_challenge = b"a" * 32
    first_value = base64.urlsafe_b64encode(first_challenge).decode("ascii").rstrip("=")
    first_digest = "sha256:" + hashlib.sha256(first_challenge).hexdigest()
    session = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_attestation_challenge",
        actor_id=session["owner_id"],
        updates={
            "attestation_challenge_digest": first_digest,
            "attestation_challenge_issued_at": (now - timedelta(seconds=1)).isoformat(),
            "attestation_challenge_expires_at": (now + timedelta(seconds=1)).isoformat(),
            "attestation_challenge_value": first_value,
        },
        _now=now,
    )
    second_challenge = b"b" * 32
    second_value = (
        base64.urlsafe_b64encode(second_challenge).decode("ascii").rstrip("=")
    )
    second_digest = "sha256:" + hashlib.sha256(second_challenge).hexdigest()
    replacement_updates = {
        "attestation_challenge_digest": second_digest,
        "attestation_challenge_issued_at": (now + timedelta(seconds=1)).isoformat(),
        "attestation_challenge_expires_at": (now + timedelta(minutes=1)).isoformat(),
        "attestation_challenge_value": second_value,
    }
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="bind_attestation_challenge",
            actor_id=session["owner_id"],
            updates=replacement_updates,
            _now=now + timedelta(milliseconds=500),
        ),
        "an unexpired setup challenge was rebound",
    )
    replacement = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_attestation_challenge",
        actor_id=session["owner_id"],
        updates=replacement_updates,
        _now=now + timedelta(seconds=2),
    )
    if not (
        replacement["revision"] == session["revision"] + 1
        and replacement["attestation_challenge_digest"] == second_digest
        and replacement["attestation_challenge_value"] == second_value
    ):
        raise AssertionError("an expired setup challenge was not replaced atomically")

    approval = db.ensure_control_plane_approval(
        action="setup.attestation.finalize",
        resource_id=session["id"],
        payload_digest=digest_value("challenge-recovery-finalization"),
        requester_id=session["owner_id"],
        request={"setup_session_id": session["id"]},
        ttl_seconds=300,
    )
    approval = db.approve_control_plane_approval(
        approval["id"], actor_id="user:challenge-recovery-reviewer"
    )
    if not approval or approval["status"] != "approved":
        raise AssertionError("setup approval rollback fixture was not approved")
    try:
        with db.connect() as conn:
            consumed = db.consume_control_plane_approval(
                approval["id"],
                action="setup.attestation.finalize",
                resource_id=session["id"],
                payload_digest=digest_value("challenge-recovery-finalization"),
                actor_id=session["owner_id"],
                _connection=conn,
            )
            if not consumed["ok"]:
                raise AssertionError(f"setup approval could not be consumed: {consumed}")
            raise RuntimeError("injected transition failure")
    except RuntimeError as exc:
        if str(exc) != "injected transition failure":
            raise
    approval_after_rollback = db.get_control_plane_approval(approval["id"])
    if not approval_after_rollback or approval_after_rollback["status"] != "approved":
        raise AssertionError("setup approval consumption escaped its transaction rollback")
    consumed = db.consume_control_plane_approval(
        approval["id"],
        action="setup.attestation.finalize",
        resource_id=session["id"],
        payload_digest=digest_value("challenge-recovery-finalization"),
        actor_id=session["owner_id"],
    )
    if not consumed["ok"] or consumed["approval"]["status"] != "consumed":
        raise AssertionError("setup approval was not consumable after rollback")

    hardware = record_hardware(
        db,
        replacement,
        "challenge-recovery",
        now=now + timedelta(seconds=3),
    )
    finalized = record_final(
        db,
        hardware,
        "challenge-recovery",
        now=now + timedelta(minutes=1, seconds=1),
    )
    if finalized["phase"] != "completion_pending_audit":
        raise AssertionError(
            "a fresh final receipt could not complete hardware evidence after challenge expiry"
        )

    expired = create_session(db, "shared-transaction-expiry")
    expired_at = (now - timedelta(seconds=1)).isoformat()
    with db.connect() as conn:
        conn.execute(
            "UPDATE setup_sessions SET expires_at = ? WHERE id = ?",
            (expired_at, expired["id"]),
        )

    def mutate_expired_with_shared_transaction() -> dict[str, Any]:
        with db.connect() as conn:
            return db.transition_setup_session(
                expired["id"],
                expected_revision=expired["revision"],
                transition="claim",
                actor_id=expired["owner_id"],
                updates={"current_assignee_id": expired["owner_id"]},
                _connection=conn,
                _now=now,
            )

    expect_error(
        db.SetupSessionValidationError,
        mutate_expired_with_shared_transaction,
        "a shared approval transaction mutated an expired setup session",
    )
    expired_after = db.get_setup_session(expired["id"])
    if not expired_after or expired_after["revision"] != expired["revision"]:
        raise AssertionError("expired shared-transaction rejection changed setup state")


def record_hardware(
    db: Any,
    session: dict[str, Any],
    suffix: str,
    *,
    assurance_digest: str | None = None,
    evidence_suffix: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    hardware_evidence = setup_evidence(
        "hardware_assurance",
        evidence_suffix or f"{suffix}:hardware",
        verifier_key_id="hardware-verifier:test",
    )
    receipt_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            hardware_evidence[0]["document"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="record_hardware_receipt",
        actor_id=session["owner_id"],
        updates={
            "hardware_assurance_digest": assurance_digest
            or digest_value(f"{suffix}:hardware-assurance-artifact"),
            "hardware_verification_receipt_digest": receipt_digest,
            "release_identity_digest": digest("6"),
            "current_host_identity_digest": digest("7"),
            "proxy_server_statement_digest": digest("8"),
            "trust_profile_digest": digest("9"),
        },
        evidence=hardware_evidence,
        _now=now,
    )


def record_final(
    db: Any,
    session: dict[str, Any],
    suffix: str,
    *,
    consumption_id: str | None = None,
    evidence_suffix: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    return db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="record_final_challenge_receipt",
        actor_id=session["owner_id"],
        updates={
            "completion_identity_digest": digest("a"),
            "final_consumption_id": consumption_id or f"consumption:{suffix}",
        },
        evidence=setup_evidence(
            "final_challenge_receipt",
            evidence_suffix or f"{suffix}:final",
            verifier_key_id="final-authority:test",
        ),
        _now=now,
    )


def exercise_idempotent_schema(db: Any) -> None:
    with db.connect() as conn:
        conn.execute(
            """
            CREATE TABLE setup_sessions (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                current_assignee_id TEXT,
                status TEXT NOT NULL,
                phase TEXT NOT NULL,
                revision BIGINT NOT NULL,
                template_id TEXT,
                principal_id TEXT,
                route_id TEXT,
                route_policy_digest TEXT,
                credential_id TEXT,
                credential_version BIGINT,
                policy_hash TEXT,
                assignment_digest TEXT,
                oauth_provider TEXT,
                oauth_state_digest TEXT,
                oauth_pending_credential_id TEXT,
                canary_id TEXT,
                enrollment_session_id TEXT,
                enrollment_packet_digest TEXT,
                verifier_nonce_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                terminal_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE setup_session_evidence (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES setup_sessions(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                verifier_key_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (session_id, kind, evidence_digest)
            )
            """
        )
    db.init_db()
    db.init_db()
    with db.connect() as conn:
        for table in (
            "setup_sessions",
            "setup_session_evidence",
            "setup_session_events",
        ):
            conn.execute(f"SELECT 1 FROM {table} LIMIT 1")
        if db.metadata_uses_postgres():
            columns = {
                row["column_name"]
                for row in conn.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = ?",
                    ("setup_sessions",),
                ).fetchall()
            }
            indexes = {
                row["indexname"]
                for row in conn.execute(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE schemaname = current_schema() "
                    "AND tablename IN ('setup_sessions', 'setup_session_evidence')"
                ).fetchall()
            }
        else:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(setup_sessions)").fetchall()
            }
            indexes = {
                row["name"]
                for table in ("setup_sessions", "setup_session_evidence")
                for row in conn.execute(f"PRAGMA index_list({table})").fetchall()
            }
    expected_columns = {
        "route_policy_digest",
        "attestation_challenge_digest",
        "attestation_challenge_issued_at",
        "attestation_challenge_expires_at",
        "enrollment_verifier_receipt_digest",
        "enrollment_verifier_key_id",
        "runtime_evidence_digest",
        "hardware_assurance_digest",
        "hardware_verification_receipt_digest",
        "hardware_verifier_key_id",
        "release_identity_digest",
        "current_host_identity_digest",
        "proxy_server_statement_digest",
        "trust_profile_digest",
        "completion_identity_digest",
        "final_authority_key_id",
        "final_consumption_id",
        "final_receipt_digest",
    }
    expected_indexes = {
        "setup_sessions_one_attestation_challenge",
        "setup_sessions_one_enrollment_verifier_receipt",
        "setup_sessions_one_runtime_evidence",
        "setup_sessions_one_hardware_assurance",
        "setup_sessions_one_hardware_verification_receipt",
        "setup_sessions_one_final_consumption",
        "setup_sessions_one_final_receipt",
        "setup_session_evidence_one_kind",
        "setup_session_evidence_one_digest",
    }
    if not expected_columns <= columns:
        raise AssertionError(
            f"setup session binding migrations are missing: {expected_columns - columns}"
        )
    if not expected_indexes <= indexes:
        raise AssertionError(
            f"setup session uniqueness migrations are missing: {expected_indexes - indexes}"
        )


def exercise_capacity_race(db: Any) -> None:
    previous_active = db.SETUP_SESSION_MAX_ACTIVE
    db.SETUP_SESSION_MAX_ACTIVE = 1
    try:

        def create(index: int) -> tuple[str, str]:
            try:
                session = create_session(db, f"capacity-{index}")
                return "created", session["id"]
            except db.SetupSessionCapacityError as exc:
                return "capacity", str(exc)

        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes = list(pool.map(create, range(16)))
        if [status for status, _ in outcomes].count("created") != 1:
            raise AssertionError(
                f"bounded setup admission did not have one winner: {outcomes}"
            )
    finally:
        db.SETUP_SESSION_MAX_ACTIVE = previous_active


def exercise_create_read_list_and_route_binding(db: Any) -> None:
    session = create_session(db, "read-list")
    loaded = db.get_setup_session(session["id"], include_events=True)
    if not loaded or loaded["route_policy_digest"] != digest("a"):
        raise AssertionError(f"setup route policy binding was not persisted: {loaded}")
    if [event["transition"] for event in loaded["events"]] != ["create"]:
        raise AssertionError("setup creation event was not persisted")
    listed = db.list_setup_sessions(owner_id=session["owner_id"], status="active")
    if session["id"] not in {item["id"] for item in listed}:
        raise AssertionError(
            "setup session owner/status list omitted the created session"
        )

    bound = bind_credential(db, session, "read-list")
    if bound["phase"] != "credential_activated" or bound["revision"] != 1:
        raise AssertionError(
            f"credential transition did not advance the session: {bound}"
        )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=bound["revision"],
            transition="bind_credential",
            actor_id=session["owner_id"],
            updates={
                "credential_id": bound["credential_id"],
                "credential_version": bound["credential_version"],
                "route_policy_digest": digest("f"),
            },
        ),
        "stable route ID accepted a changed reviewed route policy digest",
    )
    unchanged = db.get_setup_session(session["id"])
    if (
        not unchanged
        or unchanged["revision"] != 1
        or unchanged["route_policy_digest"] != digest("a")
    ):
        raise AssertionError("rejected route policy rebind mutated the setup session")

    candidate_bound = create_session(
        db, "candidate-route-policy", route_policy_digest=None
    )
    candidate_bound = bind_credential(db, candidate_bound, "candidate-route-policy")
    if candidate_bound["route_policy_digest"] is not None:
        raise AssertionError("credential binding invented a route policy digest")
    candidate_bound = stage_candidate(db, candidate_bound, "candidate-route-policy")
    if candidate_bound["route_policy_digest"] != digest("a"):
        raise AssertionError(
            "candidate staging did not bind the reviewed route policy digest"
        )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            candidate_bound["id"],
            expected_revision=candidate_bound["revision"],
            transition="bind_candidate",
            actor_id=candidate_bound["owner_id"],
            updates={
                "policy_hash": candidate_bound["policy_hash"],
                "assignment_digest": candidate_bound["assignment_digest"],
                "canary_id": candidate_bound["canary_id"],
                "route_policy_digest": digest("f"),
            },
        ),
        "candidate staging rebound an existing route policy digest",
    )


def exercise_revision_and_handoff(db: Any) -> None:
    session = create_session(db, "revision")

    def transition(credential_id: str) -> tuple[str, str]:
        try:
            value = db.transition_setup_session(
                session["id"],
                expected_revision=0,
                transition="bind_credential",
                actor_id=session["owner_id"],
                updates={
                    "credential_id": credential_id,
                    "credential_version": 1,
                    "route_policy_digest": session["route_policy_digest"],
                },
            )
            return "accepted", value["credential_id"]
        except db.SetupSessionStaleRevisionError as exc:
            return "stale", str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(transition, ("credential:left", "credential:right")))
    if [status for status, _ in outcomes].count("accepted") != 1:
        raise AssertionError(f"setup revision CAS did not have one winner: {outcomes}")
    if [status for status, _ in outcomes].count("stale") != 1:
        raise AssertionError(
            f"setup revision loser was not distinguishably stale: {outcomes}"
        )

    handoff = create_session(db, "handoff")
    handed = db.claim_or_handoff_setup_session(
        handoff["id"],
        expected_revision=0,
        actor_id=handoff["owner_id"],
        assignee_id="user:next-operator",
        handoff=True,
    )
    if (
        handed["current_assignee_id"] != "user:next-operator"
        or handed["phase"] != "created"
    ):
        raise AssertionError(f"setup handoff changed the wrong fields: {handed}")


def exercise_atomic_oauth_callback_persistence(db: Any) -> None:
    def oauth_values(name: str) -> tuple[str, dict[str, Any], dict[str, Any], str]:
        secret = json.dumps(
            {
                "access_token": f"{name}-access-token",
                "refresh_token": f"{name}-refresh-token",
                "token_type": "Bearer",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        metadata = {
            "oauth": True,
            "provider": "google.oauth2",
            "provider_id": "google",
            "provider_subject": f"subject:{name}",
            "provider_account": f"{name}@example.test",
            "provider_identity_verified": True,
            "scopes": ["scope.read"],
        }
        review = {
            "credential_type": "oauth2",
            "provider": "google",
            "provider_subject": metadata["provider_subject"],
            "provider_account": metadata["provider_account"],
            "scopes": metadata["scopes"],
            "credential_name": name,
            "metadata_keys": sorted(metadata),
            "expires_at_epoch_ms": None,
        }
        payload_digest = (
            "sha256:"
            + hashlib.sha256(
                db.dumps(
                    {
                        "action": "credential.oauth.activate",
                        "review": review,
                        "encrypted_token_source_sha256": "sha256:"
                        + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                    }
                ).encode("utf-8")
            ).hexdigest()
        )
        return secret, metadata, review, payload_digest

    state_digest = digest("9")

    pending_session = create_session(db, "atomic-pending")
    pending_session = db.transition_setup_session(
        pending_session["id"],
        expected_revision=pending_session["revision"],
        transition="bind_oauth_flow",
        actor_id=pending_session["owner_id"],
        updates={"oauth_provider": "google", "oauth_state_digest": state_digest},
    )
    pending_secret, pending_metadata, pending_review, pending_digest = oauth_values(
        "atomic-pending"
    )
    pending_ids_before = {item["id"] for item in db.list_pending_oauth_credentials()}
    pending_events_before = len(
        db.get_setup_session(pending_session["id"], include_events=True)["events"]
    )
    expect_error(
        db.SetupSessionStaleRevisionError,
        lambda: db.create_pending_oauth_credential(
            name="atomic-pending",
            kind="oauth2",
            secret=pending_secret,
            metadata=pending_metadata,
            requester_id=pending_session["owner_id"],
            payload_digest=pending_digest,
            review=pending_review,
            ttl_seconds=300,
            setup_session_id=pending_session["id"],
            setup_expected_revision=pending_session["revision"] - 1,
            setup_actor_id=pending_session["owner_id"],
            setup_oauth_provider="google",
            setup_oauth_state_digest=state_digest,
        ),
        "stale setup CAS left a pending OAuth grant",
    )
    if {
        item["id"] for item in db.list_pending_oauth_credentials()
    } != pending_ids_before:
        raise AssertionError(
            "failed setup CAS persisted a standalone pending OAuth grant"
        )

    original_transition = db.transition_setup_session

    def fail_post_insert_transition(*args: Any, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("_connection") is not None:
            raise db.SetupSessionValidationError("injected post-insert failure")
        return original_transition(*args, **kwargs)

    db.transition_setup_session = fail_post_insert_transition
    try:
        expect_error(
            db.SetupSessionValidationError,
            lambda: db.create_pending_oauth_credential(
                name="atomic-pending",
                kind="oauth2",
                secret=pending_secret,
                metadata=pending_metadata,
                requester_id=pending_session["owner_id"],
                payload_digest=pending_digest,
                review=pending_review,
                ttl_seconds=300,
                setup_session_id=pending_session["id"],
                setup_expected_revision=pending_session["revision"],
                setup_actor_id=pending_session["owner_id"],
                setup_oauth_provider="google",
                setup_oauth_state_digest=state_digest,
            ),
            "post-insert setup failure left a pending OAuth grant",
        )
    finally:
        db.transition_setup_session = original_transition
    pending_after_fault = db.get_setup_session(
        pending_session["id"], include_events=True
    )
    if (
        {item["id"] for item in db.list_pending_oauth_credentials()}
        != pending_ids_before
        or pending_after_fault["revision"] != pending_session["revision"]
        or pending_after_fault["phase"] != "oauth_started"
        or len(pending_after_fault["events"]) != pending_events_before
    ):
        raise AssertionError(
            "pending OAuth insert, setup transition, and outbox did not roll back together"
        )
    pending = db.create_pending_oauth_credential(
        name="atomic-pending",
        kind="oauth2",
        secret=pending_secret,
        metadata=pending_metadata,
        requester_id=pending_session["owner_id"],
        payload_digest=pending_digest,
        review=pending_review,
        ttl_seconds=300,
        setup_session_id=pending_session["id"],
        setup_expected_revision=pending_session["revision"],
        setup_actor_id=pending_session["owner_id"],
        setup_oauth_provider="google",
        setup_oauth_state_digest=state_digest,
    )
    pending_bound = db.get_setup_session(pending_session["id"])
    if not pending_bound or not (
        pending_bound["phase"] == "oauth_verified"
        and pending_bound["oauth_pending_credential_id"] == pending["id"]
    ):
        raise AssertionError(
            "pending OAuth creation and setup binding did not commit together"
        )

    approval = db.ensure_control_plane_approval(
        action="credential.oauth.activate",
        resource_id=pending["id"],
        payload_digest=pending_digest,
        requester_id=pending_session["owner_id"],
        request=pending_review,
        ttl_seconds=300,
    )
    approval = db.approve_control_plane_approval(
        approval["id"], actor_id="user:atomic-reviewer"
    )
    if not approval or approval["status"] != "approved":
        raise AssertionError("atomic activation fixture approval was not approved")
    original_insert_setup_event = db._insert_setup_event

    def fail_activation_event(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected post-activation failure")

    db._insert_setup_event = fail_activation_event
    try:
        expect_error(
            RuntimeError,
            lambda: db.activate_pending_oauth_credential(
                pending["id"],
                approval_id=approval["id"],
                actor_id=pending_session["owner_id"],
                setup_session_id=pending_session["id"],
                setup_expected_revision=pending_bound["revision"],
            ),
            "post-activation setup failure committed partial OAuth activation",
        )
    finally:
        db._insert_setup_event = original_insert_setup_event
    approval_after_fault = db.get_control_plane_approval(approval["id"])
    setup_after_activation_fault = db.get_setup_session(pending_session["id"])
    if not (
        db.get_pending_oauth_credential(pending["id"]) is not None
        and db.get_credential(pending["id"]) is None
        and approval_after_fault
        and approval_after_fault["status"] == "approved"
        and setup_after_activation_fault
        and setup_after_activation_fault["phase"] == "oauth_verified"
        and setup_after_activation_fault["revision"] == pending_bound["revision"]
    ):
        raise AssertionError(
            "approval, credential activation, pending deletion, and setup transition did not roll back together"
        )
    with db.connect() as conn:
        conn.execute(
            "UPDATE setup_sessions SET credential_id = ?, credential_version = ? "
            "WHERE id = ?",
            ("credential:prebound", 1, pending_session["id"]),
        )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.activate_pending_oauth_credential(
            pending["id"],
            approval_id=approval["id"],
            actor_id=pending_session["owner_id"],
            setup_session_id=pending_session["id"],
            setup_expected_revision=pending_bound["revision"],
        ),
        "OAuth activation silently rebound an immutable setup credential",
    )
    rebound_after = db.get_setup_session(pending_session["id"])
    approval_after_rebind = db.get_control_plane_approval(approval["id"])
    if not (
        rebound_after
        and rebound_after["credential_id"] == "credential:prebound"
        and rebound_after["revision"] == pending_bound["revision"]
        and db.get_pending_oauth_credential(pending["id"]) is not None
        and db.get_credential(pending["id"]) is None
        and approval_after_rebind
        and approval_after_rebind["status"] == "approved"
    ):
        raise AssertionError(
            "immutable OAuth setup rebind rejection did not roll back atomically"
        )

    immediate_state_digest = digest("8")
    immediate_session = create_session(db, "atomic-immediate")
    immediate_session = db.transition_setup_session(
        immediate_session["id"],
        expected_revision=immediate_session["revision"],
        transition="bind_oauth_flow",
        actor_id=immediate_session["owner_id"],
        updates={
            "oauth_provider": "google",
            "oauth_state_digest": immediate_state_digest,
        },
    )
    immediate_secret, immediate_metadata, _, _ = oauth_values("atomic-immediate")
    credential_ids_before = {item["id"] for item in db.list_credentials()}
    expect_error(
        db.SetupSessionStaleRevisionError,
        lambda: db.create_credential(
            "atomic-immediate",
            "oauth2",
            immediate_secret,
            immediate_metadata,
            setup_session_id=immediate_session["id"],
            setup_expected_revision=immediate_session["revision"] - 1,
            setup_actor_id=immediate_session["owner_id"],
            setup_oauth_provider="google",
            setup_oauth_state_digest=immediate_state_digest,
        ),
        "stale setup CAS left an immediately active OAuth credential",
    )
    if {item["id"] for item in db.list_credentials()} != credential_ids_before:
        raise AssertionError(
            "failed setup CAS persisted a standalone active credential"
        )
    original_transition = db.transition_setup_session
    db.transition_setup_session = fail_post_insert_transition
    try:
        expect_error(
            db.SetupSessionValidationError,
            lambda: db.create_credential(
                "atomic-immediate",
                "oauth2",
                immediate_secret,
                immediate_metadata,
                setup_session_id=immediate_session["id"],
                setup_expected_revision=immediate_session["revision"],
                setup_actor_id=immediate_session["owner_id"],
                setup_oauth_provider="google",
                setup_oauth_state_digest=immediate_state_digest,
            ),
            "post-insert setup failure left an immediately active OAuth credential",
        )
    finally:
        db.transition_setup_session = original_transition
    immediate_after_fault = db.get_setup_session(immediate_session["id"])
    if (
        {item["id"] for item in db.list_credentials()} != credential_ids_before
        or immediate_after_fault["revision"] != immediate_session["revision"]
        or immediate_after_fault["phase"] != "oauth_started"
    ):
        raise AssertionError(
            "active credential insert, setup transition, and outbox did not roll back together"
        )
    credential = db.create_credential(
        "atomic-immediate",
        "oauth2",
        immediate_secret,
        immediate_metadata,
        setup_session_id=immediate_session["id"],
        setup_expected_revision=immediate_session["revision"],
        setup_actor_id=immediate_session["owner_id"],
        setup_oauth_provider="google",
        setup_oauth_state_digest=immediate_state_digest,
    )
    immediate_bound = db.get_setup_session(immediate_session["id"])
    if not immediate_bound or not (
        immediate_bound["phase"] == "credential_activated"
        and immediate_bound["credential_id"] == credential["id"]
        and immediate_bound["credential_version"] == credential["credential_version"]
    ):
        raise AssertionError(
            "immediate credential creation and setup binding did not commit together"
        )


def exercise_generation_and_expiry_fail_closed(db: Any) -> None:
    credential = db.create_credential(
        "setup-generation",
        "bearer",
        "setup-generation-secret",
        {},
    )
    session = create_session(db, "generation")
    session = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="bind_credential",
        actor_id=session["owner_id"],
        updates={
            "credential_id": credential["id"],
            "credential_version": credential["credential_version"],
            "route_policy_digest": session["route_policy_digest"],
        },
    )
    session = stage_candidate(db, session, "generation")
    rotated = db.update_credential(
        credential["id"], {"secret": "setup-generation-rotated"}
    )
    if not rotated or rotated["credential_version"] == credential["credential_version"]:
        raise AssertionError("credential generation fixture did not rotate")
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="activate_policy",
            actor_id=session["owner_id"],
            updates={
                "policy_hash": session["policy_hash"],
                "assignment_digest": session["assignment_digest"],
            },
            required_active_credential_id=credential["id"],
            required_active_credential_version=credential["credential_version"],
        ),
        "policy activation accepted a rotated credential generation",
    )
    unchanged = db.get_setup_session(session["id"])
    if not unchanged or unchanged["phase"] != "policy_staged":
        raise AssertionError("generation mismatch advanced setup policy confirmation")

    expired = create_session(db, "rejected-expiry")
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    with db.connect() as conn:
        conn.execute(
            "UPDATE setup_sessions SET expires_at = ? WHERE id = ?",
            (expired_at, expired["id"]),
        )
    expect_error(
        db.SetupSessionStaleRevisionError,
        lambda: db.transition_setup_session(
            expired["id"],
            expected_revision=expired["revision"],
            transition="bind_credential",
            actor_id=expired["owner_id"],
            updates={"credential_id": credential["id"], "credential_version": 1},
        ),
        "expired setup mutation was not rejected",
    )
    expired_after = db.get_setup_session(expired["id"], include_events=True)
    if not expired_after or not (
        expired_after["status"] == "expired"
        and expired_after["phase"] == "expired"
        and expired_after["events"][-1]["transition"] == "expire"
    ):
        raise AssertionError("rejected mutation rolled back durable setup expiration")


def exercise_transition_validation(db: Any) -> None:
    session = create_session(db, "validation")
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=0,
            transition="arbitrary_patch",
            actor_id=session["owner_id"],
        ),
        "unknown setup transition was accepted",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=0,
            transition="bind_credential",
            actor_id=session["owner_id"],
            updates={"policy_hash": digest("b")},
        ),
        "named transition accepted an unrelated update field",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=0,
            transition="bind_enrollment",
            actor_id=session["owner_id"],
            updates={
                "enrollment_session_id": "enrollment:early",
                "enrollment_packet_digest": digest("d"),
                "verifier_nonce_hash": digest("e"),
            },
        ),
        "setup transition skipped required phases",
    )
    if db.get_setup_session(session["id"])["revision"] != 0:
        raise AssertionError("rejected setup transition changed the revision")


def exercise_unique_bindings(db: Any) -> None:
    left = create_session(db, "oauth-left")
    right = create_session(db, "oauth-right")
    left = db.transition_setup_session(
        left["id"],
        expected_revision=0,
        transition="bind_oauth_flow",
        actor_id=left["owner_id"],
        updates={"oauth_provider": "google", "oauth_state_digest": digest("1")},
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            right["id"],
            expected_revision=0,
            transition="bind_oauth_flow",
            actor_id=right["owner_id"],
            updates={"oauth_provider": "google", "oauth_state_digest": digest("1")},
        ),
        "OAuth state was bound across setup sessions",
    )
    right = db.transition_setup_session(
        right["id"],
        expected_revision=0,
        transition="bind_oauth_flow",
        actor_id=right["owner_id"],
        updates={"oauth_provider": "google", "oauth_state_digest": digest("2")},
    )
    left = db.transition_setup_session(
        left["id"],
        expected_revision=left["revision"],
        transition="bind_pending_credential",
        actor_id=left["owner_id"],
        updates={"oauth_pending_credential_id": "pending:shared"},
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            right["id"],
            expected_revision=right["revision"],
            transition="bind_pending_credential",
            actor_id=right["owner_id"],
            updates={"oauth_pending_credential_id": "pending:shared"},
        ),
        "pending OAuth credential was bound across setup sessions",
    )

    canary_left = stage_candidate(
        db,
        bind_credential(db, create_session(db, "canary-left"), "canary-left"),
        "canary-left",
        canary_id="canary:shared",
    )
    canary_right = bind_credential(
        db, create_session(db, "canary-right"), "canary-right"
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: stage_candidate(
            db, canary_right, "canary-right", canary_id="canary:shared"
        ),
        "canary was bound across setup sessions",
    )

    enrollment_left = bind_enrollment(
        db,
        activate_policy(db, canary_left),
        "left",
        enrollment_session_id="enrollment:shared",
    )
    enrollment_right = activate_policy(
        db,
        stage_candidate(db, canary_right, "canary-right", canary_id="canary:right"),
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: bind_enrollment(
            db,
            enrollment_right,
            "right",
            enrollment_session_id="enrollment:shared",
        ),
        "enrollment session was bound across setup sessions",
    )
    if enrollment_left["enrollment_session_id"] != "enrollment:shared":
        raise AssertionError("first enrollment binding was not preserved")


def exercise_evidence_validation(db: Any) -> None:
    session = create_session(db, "evidence")
    session = bind_credential(db, session, "evidence")
    session = stage_candidate(db, session, "evidence")
    session = activate_policy(db, session)
    session = bind_enrollment(db, session, "evidence")
    base = {
        "kind": "enrollment_verification",
        "verifier_key_id": "verifier:test",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="record_enrollment_evidence",
            actor_id=session["owner_id"],
            evidence=[{**base, "document": {"access_token": "must-not-persist"}}],
        ),
        "secret-like evidence key was accepted",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="record_enrollment_evidence",
            actor_id=session["owner_id"],
            evidence=[
                {
                    **base,
                    "document": {
                        "result": "x" * (db.SETUP_SESSION_EVIDENCE_MAX_BYTES + 1)
                    },
                }
            ],
        ),
        "oversized setup evidence was accepted",
    )
    verified = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="record_enrollment_evidence",
        actor_id=session["owner_id"],
        evidence=[
            {**base, "document": {"verified": True, "packet_digest": digest("d")}}
        ],
    )
    if verified["phase"] != "ca_installed":
        raise AssertionError(
            "valid enrollment evidence did not advance the setup phase"
        )
    loaded = db.get_setup_session(
        session["id"], include_evidence=True, include_events=True
    )
    if (
        len(loaded["evidence"]) != 1
        or loaded["evidence"][0]["kind"] != "enrollment_verification"
    ):
        raise AssertionError("canonical setup evidence was not stored exactly once")
    evidence_digest = loaded["evidence"][0]["evidence_digest"]
    if evidence_digest not in loaded["events"][-1]["event"]["evidence_digests"]:
        raise AssertionError("transition event did not bind its evidence digest")
    with db.connect() as conn:
        raw = conn.execute(
            "SELECT evidence_json FROM setup_session_evidence WHERE session_id = ?",
            (session["id"],),
        ).fetchone()["evidence_json"]
    if "must-not-persist" in raw:
        raise AssertionError("rejected secret material reached setup evidence storage")


def exercise_authenticated_receipt_ledger(db: Any) -> None:
    session = advance_to_runtime(db, "receipt-ledger")
    loaded = db.get_setup_session(session["id"], include_evidence=True)
    runtime_evidence = next(
        item for item in loaded["evidence"] if item["kind"] == "runtime_verification"
    )
    enrollment_receipt = next(
        item for item in loaded["evidence"] if item["kind"] == "enrollment_verification"
    )
    if session["runtime_evidence_digest"] != runtime_evidence["evidence_digest"]:
        raise AssertionError("runtime evidence digest was not bound by the DB")
    if not (
        session["enrollment_verifier_receipt_digest"]
        == enrollment_receipt["evidence_digest"]
        and session["enrollment_verifier_key_id"] == "verifier:test"
        and enrollment_receipt["document"]["kind"]
        == "serverware.setupEnrollmentVerification/v1"
        and enrollment_receipt["document"]["signature"]["value"]
        == "signed:receipt-ledger:enrollment_verification"
    ):
        raise AssertionError(
            "signed enrollment receipt was not durably reconstructable"
        )

    expect_error(
        db.SetupSessionValidationError,
        lambda: record_hardware(db, session, "receipt-without-challenge"),
        "hardware receipt was accepted without an attestation challenge",
    )
    now = datetime.now(timezone.utc)
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="bind_attestation_challenge",
            actor_id=session["owner_id"],
            updates={
                "attestation_challenge_digest": digest("0"),
                "attestation_challenge_issued_at": (
                    now - timedelta(hours=2)
                ).isoformat(),
                "attestation_challenge_expires_at": (
                    now - timedelta(hours=1)
                ).isoformat(),
            },
        ),
        "expired attestation challenge was accepted",
    )
    if db.get_setup_session(session["id"])["revision"] != session["revision"]:
        raise AssertionError("rejected challenge binding changed the session")

    session = bind_challenge(db, session, digest("0"))
    if session["phase"] != "runtime_verified":
        raise AssertionError("attestation challenge binding changed the runtime phase")
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="record_hardware_receipt",
            actor_id=session["owner_id"],
            updates={
                "release_identity_digest": digest("6"),
                "current_host_identity_digest": digest("7"),
                "proxy_server_statement_digest": digest("8"),
            },
            evidence=setup_evidence(
                "hardware_assurance",
                "receipt-ledger:hardware",
                verifier_key_id="hardware-verifier:test",
            ),
        ),
        "incomplete server-derived hardware bindings were accepted",
    )
    before_hardware = db.get_setup_session(
        session["id"], include_evidence=True, include_events=True
    )
    if before_hardware["revision"] != session["revision"] or any(
        item["kind"] == "hardware_assurance" for item in before_hardware["evidence"]
    ):
        raise AssertionError("rejected hardware receipt did not roll back")

    session = record_hardware(db, session, "receipt-ledger")
    if not (
        session["phase"] == "hardware_verified"
        and session["hardware_assurance_digest"]
        == digest_value("receipt-ledger:hardware-assurance-artifact")
        and session["hardware_verification_receipt_digest"]
        and session["hardware_verifier_key_id"] == "hardware-verifier:test"
        and session["release_identity_digest"] == digest("6")
        and session["current_host_identity_digest"] == digest("7")
        and session["proxy_server_statement_digest"] == digest("8")
        and session["trust_profile_digest"] == digest("9")
    ):
        raise AssertionError("hardware receipt did not bind the verified receipt set")
    hardware_loaded = db.get_setup_session(session["id"], include_evidence=True)
    hardware_receipt = next(
        item
        for item in hardware_loaded["evidence"]
        if item["kind"] == "hardware_assurance"
    )
    if not (
        hardware_loaded["hardware_verification_receipt_digest"]
        == hardware_receipt["evidence_digest"]
        and hardware_loaded["hardware_assurance_digest"]
        != hardware_receipt["evidence_digest"]
        and hardware_receipt["document"]["kind"]
        == "serverware.setupHardwareVerification/v1"
        and hardware_receipt["document"]["signature"]["value"]
        == "signed:receipt-ledger:hardware"
    ):
        raise AssertionError(
            "hardware artifact and signed verification receipt digests were conflated"
        )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="complete",
            actor_id=session["owner_id"],
        ),
        "bare hardware_verified to complete transition remained available",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="record_final_challenge_receipt",
            actor_id=session["owner_id"],
            updates={
                "completion_identity_digest": digest("a"),
                "final_consumption_id": "consumption:receipt-ledger",
            },
        ),
        "final transition was accepted without final receipt evidence",
    )
    session = record_final(db, session, "receipt-ledger")
    if not (
        session["phase"] == "completion_pending_audit"
        and session["status"] == "active"
        and session["final_receipt_digest"]
        and session["final_authority_key_id"] == "final-authority:test"
        and session["final_consumption_id"] == "consumption:receipt-ledger"
    ):
        raise AssertionError("final receipt did not enter the audit gate")
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="system_complete",
            actor_id="system:setup-auditor",
        ),
        "setup completed before its final receipt event was audited",
    )
    if db.get_setup_session(session["id"])["revision"] != session["revision"]:
        raise AssertionError("rejected audit gate changed the session revision")
    drain_outbox(db, datetime.now(timezone.utc))
    completed = db.transition_setup_session(
        session["id"],
        expected_revision=session["revision"],
        transition="system_complete",
        actor_id="system:setup-auditor",
    )
    if completed["status"] != "complete" or completed["phase"] != "complete":
        raise AssertionError("audited final receipt did not complete the setup")
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.claim_or_handoff_setup_session(
            completed["id"],
            expected_revision=completed["revision"],
            actor_id=completed["owner_id"],
            assignee_id="user:late-handoff",
            handoff=True,
        ),
        "terminal setup session accepted a binding mutation",
    )
    terminal = db.get_setup_session(completed["id"])
    if terminal != completed:
        raise AssertionError("terminal setup bindings changed after completion")


def exercise_security_replay_constraints(db: Any) -> None:
    enrollment_left = advance_to_enrollment(db, "enrollment-replay-left")
    enrollment_right = advance_to_enrollment(db, "enrollment-replay-right")
    enrollment_left = db.transition_setup_session(
        enrollment_left["id"],
        expected_revision=enrollment_left["revision"],
        transition="record_enrollment_evidence",
        actor_id=enrollment_left["owner_id"],
        evidence=setup_evidence(
            "enrollment_verification", "enrollment:shared-signed-receipt"
        ),
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: db.transition_setup_session(
            enrollment_right["id"],
            expected_revision=enrollment_right["revision"],
            transition="record_enrollment_evidence",
            actor_id=enrollment_right["owner_id"],
            evidence=setup_evidence(
                "enrollment_verification", "enrollment:shared-signed-receipt"
            ),
        ),
        "signed enrollment verifier receipt was replayed across setup sessions",
    )
    if not enrollment_left["enrollment_verifier_receipt_digest"]:
        raise AssertionError("enrollment verifier receipt digest was not bound")

    left = advance_to_runtime(db, "replay-left")
    right = advance_to_runtime(db, "replay-right")
    left = bind_challenge(db, left, digest("b"))
    expect_error(
        db.SetupSessionValidationError,
        lambda: bind_challenge(db, right, digest("b")),
        "attestation challenge was replayed across setup sessions",
    )
    right = bind_challenge(db, right, digest("c"))
    left = record_hardware(
        db, left, "replay-left", evidence_suffix="hardware:shared-receipt"
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: record_hardware(
            db,
            right,
            "replay-right",
            assurance_digest=left["hardware_assurance_digest"],
            evidence_suffix="hardware:right-unique-receipt",
        ),
        "hardware assurance artifact digest was replayed across setup sessions",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: record_hardware(
            db, right, "replay-right", evidence_suffix="hardware:shared-receipt"
        ),
        "hardware evidence digest was replayed across setup sessions",
    )
    if db.get_setup_session(right["id"])["revision"] != right["revision"]:
        raise AssertionError("cross-session hardware replay changed the losing session")
    right = record_hardware(db, right, "replay-right")
    left = record_final(
        db,
        left,
        "replay-left",
        consumption_id="consumption:shared",
        evidence_suffix="final:shared-receipt",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: record_final(
            db,
            right,
            "replay-right",
            consumption_id="consumption:shared",
            evidence_suffix="final:right-unique",
        ),
        "final consumption ID was replayed across setup sessions",
    )
    expect_error(
        db.SetupSessionValidationError,
        lambda: record_final(
            db,
            right,
            "replay-right",
            consumption_id="consumption:right-unique",
            evidence_suffix="final:shared-receipt",
        ),
        "final receipt digest was replayed across setup sessions",
    )
    right = record_final(db, right, "replay-right")
    with db.connect() as conn:
        duplicate_kinds = conn.execute(
            "SELECT session_id, kind, COUNT(*) AS count "
            "FROM setup_session_evidence GROUP BY session_id, kind HAVING COUNT(*) > 1"
        ).fetchall()
    if duplicate_kinds:
        raise AssertionError("setup ledger stored multiple evidence rows for one kind")
    if not left["final_receipt_digest"] or not right["final_receipt_digest"]:
        raise AssertionError("valid independent final receipts were not retained")


def exercise_final_receipt_cas_and_rollback(db: Any) -> None:
    session = record_hardware(
        db,
        bind_challenge(db, advance_to_runtime(db, "final-cas"), digest("d")),
        "final-cas",
    )

    def finalize(suffix: str) -> tuple[str, str]:
        try:
            value = record_final(db, session, suffix)
            return "accepted", value["final_consumption_id"]
        except db.SetupSessionStaleRevisionError as exc:
            return "stale", str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(finalize, ("final-cas-left", "final-cas-right")))
    if [status for status, _ in outcomes].count("accepted") != 1 or [
        status for status, _ in outcomes
    ].count("stale") != 1:
        raise AssertionError(f"final receipt CAS did not have one winner: {outcomes}")
    loaded = db.get_setup_session(session["id"], include_evidence=True)
    if (
        len(
            [
                item
                for item in loaded["evidence"]
                if item["kind"] == "final_challenge_receipt"
            ]
        )
        != 1
    ):
        raise AssertionError("final receipt CAS persisted more than one receipt")

    rollback = record_hardware(
        db,
        bind_challenge(db, advance_to_runtime(db, "final-rollback"), digest("e")),
        "final-rollback",
    )
    before = db.get_setup_session(
        rollback["id"], include_evidence=True, include_events=True
    )
    original_insert_setup_event = db._insert_setup_event

    def fail_final_event(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("injected final receipt event failure")

    db._insert_setup_event = fail_final_event
    try:
        expect_error(
            RuntimeError,
            lambda: record_final(db, rollback, "final-rollback"),
            "final receipt event failure committed partial ledger state",
        )
    finally:
        db._insert_setup_event = original_insert_setup_event
    after = db.get_setup_session(
        rollback["id"], include_evidence=True, include_events=True
    )
    if after != before:
        raise AssertionError(
            "final receipt session, evidence, and event did not roll back"
        )


def exercise_strict_outbox_sequence(db: Any) -> None:
    target = bind_credential(
        db, create_session(db, "outbox-sequence"), "outbox-sequence"
    )
    target_sequences: list[int] = []
    now = datetime.now(timezone.utc)
    for attempt in range(100):
        claimed = db.claim_setup_session_audit_outbox(
            worker_id=f"worker:sequence:{attempt}", limit=500, now=now
        )
        if not claimed:
            break
        session_ids = [item["session_id"] for item in claimed]
        if len(session_ids) != len(set(session_ids)):
            raise AssertionError("one outbox claim skipped per-session sequence")
        with db.connect() as conn:
            for item in claimed:
                predecessor = conn.execute(
                    "SELECT 1 FROM setup_session_events WHERE session_id = ? "
                    "AND sequence < ? AND audit_status != 'audited' LIMIT 1",
                    (item["session_id"], item["sequence"]),
                ).fetchone()
                if predecessor:
                    raise AssertionError(
                        "outbox claimed an event before its predecessor"
                    )
        for item in claimed:
            if item["session_id"] == target["id"]:
                target_sequences.append(item["sequence"])
            if not db.finish_setup_session_audit_outbox(
                item["id"],
                claim_id=item["audit_claim_id"],
                audit_event_hash=digest("5"),
                now=now,
            ):
                raise AssertionError("strict outbox test lost an audit claim")
        if target_sequences == [1, 2]:
            break
    if target_sequences != [1, 2]:
        raise AssertionError(
            f"outbox did not claim target events in strict sequence: {target_sequences}"
        )


def exercise_outbox(db: Any) -> None:
    first_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    claimed = db.claim_setup_session_audit_outbox(
        worker_id="worker:first", limit=1, now=first_time
    )
    if len(claimed) != 1:
        raise AssertionError("setup audit outbox did not yield pending work")
    first = claimed[0]
    if not db.finish_setup_session_audit_outbox(
        first["id"],
        claim_id=first["audit_claim_id"],
        error="audit unavailable",
        now=first_time,
    ):
        raise AssertionError("setup audit outbox failure was not recorded")
    replay = db.claim_setup_session_audit_outbox(
        worker_id="worker:retry",
        limit=1,
        now=first_time + timedelta(seconds=1),
    )[0]
    if (
        replay["id"] != first["id"]
        or replay["audit_attempts"] != first["audit_attempts"] + 1
    ):
        raise AssertionError("setup audit outbox retry changed event identity")
    if not db.finish_setup_session_audit_outbox(
        replay["id"],
        claim_id=replay["audit_claim_id"],
        audit_event_hash=digest("9"),
        now=first_time + timedelta(seconds=2),
    ):
        raise AssertionError("setup audit outbox success was not recorded")

    stale = db.claim_setup_session_audit_outbox(
        worker_id="worker:stale",
        limit=1,
        now=first_time + timedelta(seconds=3),
        claim_ttl_seconds=5,
    )[0]
    takeover = db.claim_setup_session_audit_outbox(
        worker_id="worker:takeover",
        limit=1,
        now=first_time + timedelta(seconds=9),
        claim_ttl_seconds=5,
    )[0]
    if (
        takeover["id"] != stale["id"]
        or takeover["audit_claim_id"] == stale["audit_claim_id"]
    ):
        raise AssertionError("stale setup audit claim was not taken over")
    if db.finish_setup_session_audit_outbox(
        stale["id"],
        claim_id=stale["audit_claim_id"],
        audit_event_hash=digest("8"),
        now=first_time + timedelta(seconds=10),
    ):
        raise AssertionError("stale setup audit claimant completed work after takeover")
    if not db.finish_setup_session_audit_outbox(
        takeover["id"],
        claim_id=takeover["audit_claim_id"],
        audit_event_hash=digest("7"),
        now=first_time + timedelta(seconds=10),
    ):
        raise AssertionError("setup audit takeover owner could not finish work")


def drain_outbox(db: Any, now: datetime) -> None:
    while True:
        claimed = db.claim_setup_session_audit_outbox(
            worker_id="worker:drain", limit=500, now=now
        )
        if not claimed:
            return
        for item in claimed:
            if not db.finish_setup_session_audit_outbox(
                item["id"],
                claim_id=item["audit_claim_id"],
                audit_event_hash=digest("6"),
                now=now,
            ):
                raise AssertionError("setup audit drain lost its claim")


def exercise_expire_and_prune(db: Any) -> None:
    session = create_session(db, "expiry")
    now = datetime(2040, 1, 1, tzinfo=timezone.utc)
    expired_at = (now - timedelta(hours=1)).isoformat()
    with db.connect() as conn:
        conn.execute(
            "UPDATE setup_sessions SET expires_at = ? WHERE id = ?",
            (expired_at, session["id"]),
        )
    result = db.prune_setup_sessions(now=now)
    expired = db.get_setup_session(session["id"], include_events=True)
    if result["expired"] < 1 or not expired or expired["status"] != "expired":
        raise AssertionError(
            f"expired setup session did not become terminal: {result} {expired}"
        )
    if (
        expired["terminal_at"] != expired_at
        or expired["events"][-1]["transition"] != "expire"
    ):
        raise AssertionError(
            "setup expiration lost its original expiry or audit transition"
        )
    drain_outbox(db, now + timedelta(seconds=1))
    with db.connect() as conn:
        durable_security_sessions = {
            row["id"]
            for row in conn.execute(
                "SELECT id FROM setup_sessions WHERE status = 'complete' "
                "AND final_receipt_digest IS NOT NULL"
            ).fetchall()
        }
    if not durable_security_sessions:
        raise AssertionError("completed security ledger fixture was not retained")
    previous_retention = db.SETUP_SESSION_RETENTION_SECONDS
    db.SETUP_SESSION_RETENTION_SECONDS = 300
    try:
        pruned = db.prune_setup_sessions(now=now + timedelta(seconds=301))
    finally:
        db.SETUP_SESSION_RETENTION_SECONDS = previous_retention
    if pruned["pruned"] < 1 or db.get_setup_session(session["id"]) is not None:
        raise AssertionError(f"audited terminal setup session was not pruned: {pruned}")
    if any(
        db.get_setup_session(item_id) is None for item_id in durable_security_sessions
    ):
        raise AssertionError("security-bound terminal setup ledger was pruned")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--postgres-dsn")
    args = parser.parse_args()
    backend = "postgres" if args.postgres_dsn else "sqlite"
    schema = None
    with tempfile.TemporaryDirectory() as tmp:
        if args.postgres_dsn:
            schema = configure_postgres(args.postgres_dsn, tmp)
        else:
            configure_sqlite(tmp)
        try:
            from serverware import db

            exercise_idempotent_schema(db)
            exercise_capacity_race(db)
            exercise_create_read_list_and_route_binding(db)
            exercise_revision_and_handoff(db)
            exercise_atomic_oauth_callback_persistence(db)
            exercise_generation_and_expiry_fail_closed(db)
            exercise_transition_validation(db)
            exercise_unique_bindings(db)
            exercise_evidence_validation(db)
            exercise_outbox(db)
            exercise_authenticated_receipt_ledger(db)
            exercise_security_replay_constraints(db)
            exercise_challenge_recovery_and_approval_atomicity(db)
            exercise_final_receipt_cas_and_rollback(db)
            exercise_strict_outbox_sequence(db)
            exercise_expire_and_prune(db)
        finally:
            if schema and args.postgres_dsn:
                drop_postgres_schema(args.postgres_dsn, schema)
    print(
        json.dumps(
            {"backend": backend, "ok": True, "setup_sessions": "pass"}, sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
