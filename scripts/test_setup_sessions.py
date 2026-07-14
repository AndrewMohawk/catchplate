#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def exercise_idempotent_schema(db: Any) -> None:
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
            column = conn.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?",
                ("setup_sessions", "route_policy_digest"),
            ).fetchone()
        else:
            column = next(
                (
                    row
                    for row in conn.execute(
                        "PRAGMA table_info(setup_sessions)"
                    ).fetchall()
                    if row["name"] == "route_policy_digest"
                ),
                None,
            )
    if not column:
        raise AssertionError("setup session route_policy_digest migration is missing")


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
        payload_digest = "sha256:" + hashlib.sha256(
            db.dumps(
                {
                    "action": "credential.oauth.activate",
                    "review": review,
                    "encrypted_token_source_sha256": "sha256:"
                    + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                }
            ).encode("utf-8")
        ).hexdigest()
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
    pending_ids_before = {
        item["id"] for item in db.list_pending_oauth_credentials()
    }
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
        raise AssertionError("failed setup CAS persisted a standalone pending OAuth grant")

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
        raise AssertionError("pending OAuth creation and setup binding did not commit together")

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
        raise AssertionError("failed setup CAS persisted a standalone active credential")
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
        raise AssertionError("immediate credential creation and setup binding did not commit together")


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
    previous_retention = db.SETUP_SESSION_RETENTION_SECONDS
    db.SETUP_SESSION_RETENTION_SECONDS = 300
    try:
        pruned = db.prune_setup_sessions(now=now + timedelta(seconds=301))
    finally:
        db.SETUP_SESSION_RETENTION_SECONDS = previous_retention
    if pruned["pruned"] < 1 or db.get_setup_session(session["id"]) is not None:
        raise AssertionError(f"audited terminal setup session was not pruned: {pruned}")


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
