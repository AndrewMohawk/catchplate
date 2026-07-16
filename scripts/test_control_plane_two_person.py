#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def expect_http_error(
    label: str, func: Any, expected_status: int, expected_detail: str
) -> Any:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = (
            json.dumps(exc.detail, sort_keys=True)
            if isinstance(exc.detail, dict)
            else str(exc.detail)
        )
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(
                f"{label} failed with wrong error: {exc.status_code} {detail}"
            ) from exc
        return exc.detail
    raise AssertionError(f"{label} unexpectedly succeeded")


def candidate_bundle(policy_bundle: Any, sequence: int) -> dict[str, Any]:
    bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
    bundle["metadata"]["sequence"] = sequence
    return bundle


class InjectedCommitFailure(RuntimeError):
    pass


class FailPolicyCommitConnection:
    def __init__(self, connection: Any):
        self._connection = connection
        self._fail_commit = False

    def __enter__(self) -> "FailPolicyCommitConnection":
        self._connection.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        if exc_type is None and self._fail_commit:
            failure = InjectedCommitFailure("injected policy database commit failure")
            self._connection.__exit__(
                InjectedCommitFailure, failure, failure.__traceback__
            )
            raise failure
        return self._connection.__exit__(exc_type, exc, tb)

    @property
    def in_transaction(self) -> bool:
        return bool(self._connection.in_transaction)

    def execute(self, sql: str, params: Any = None) -> Any:
        normalized = " ".join(sql.lower().split())
        if "policy_high_water" in normalized and normalized.startswith(
            ("insert ", "update ")
        ):
            self._fail_commit = True
        if params is None:
            return self._connection.execute(sql)
        return self._connection.execute(sql, params)

    def commit(self) -> None:
        if self._fail_commit:
            self._connection.rollback()
            raise InjectedCommitFailure("injected policy database commit failure")
        self._connection.commit()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


def run_postgres_policy_lock_timeout(base_dsn: str) -> None:
    import psycopg

    schema = f"serverware_policy_lock_{uuid.uuid4().hex}"
    with psycopg.connect(base_dsn, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA "{schema}"')
    separator = "&" if "?" in base_dsn else "?"
    options = urllib.parse.quote(f"-csearch_path={schema}", safe="")
    isolated_dsn = f"{base_dsn}{separator}options={options}"
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_AUTHORITY_LOCK_WAIT_MS"] = "200"
        for store in ("METADATA", "AUDIT", "GRANT"):
            os.environ[f"SERVERWARE_{store}_STORE_BACKEND"] = "postgres"
            os.environ[f"SERVERWARE_{store}_STORE_POSTGRES_DSN"] = isolated_dsn
        try:
            from serverware import db

            db.init_db()
            holder = db.connect()
            contender = db.connect()
            try:
                db.lock_policy_publication(holder)
                started = time.monotonic()
                try:
                    db.lock_policy_publication(contender)
                except Exception as exc:
                    elapsed = time.monotonic() - started
                    if elapsed < 0.1 or elapsed > 2.0:
                        raise AssertionError(
                            f"PostgreSQL policy lock wait was not bounded: {elapsed:.3f}s"
                        ) from exc
                else:
                    raise AssertionError(
                        "PostgreSQL policy lock contention did not time out"
                    )
            finally:
                contender.raw_connection.rollback()
                contender.raw_connection.close()
                holder.raw_connection.rollback()
                holder.raw_connection.close()
        finally:
            with psycopg.connect(base_dsn, autocommit=True) as connection:
                connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')

    print(json.dumps({"ok": True, "postgres_policy_lock_timeout": "pass"}, sort_keys=True))


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_BUNDLE"] = str(
            Path(tmp) / "control-plane-policy-bundle.json"
        )
        os.environ["SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "0"
        os.environ["SERVERWARE_CONTROL_PLANE_TWO_PERSON_TTL_SECONDS"] = "300"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ.pop("SERVERWARE_METADATA_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_GRANT_STORE_POSTGRES_DSN", None)

        from serverware import app as app_module
        from serverware import db, policy_bundle
        from serverware.auth import AdminIdentity

        db.init_db()
        requester = AdminIdentity(
            "user:requester",
            frozenset({"credential_owner", "policy_publisher"}),
            "admin-token-header",
        )
        credential_approver = AdminIdentity(
            "user:credential-approver",
            frozenset({"credential_owner"}),
            "admin-token-header",
        )
        policy_approver = AdminIdentity(
            "user:policy-approver",
            frozenset({"policy_publisher"}),
            "admin-token-header",
        )
        route_approver = AdminIdentity(
            "user:route-approver", frozenset({"policy_author"}), "admin-token-header"
        )
        wrong_approver = AdminIdentity(
            "user:policy-author", frozenset({"policy_author"}), "admin-token-header"
        )

        credential_payload = app_module.CredentialCreate(
            name="Production Google OAuth",
            kind="bearer",
            secret="super-secret-token",
            metadata={"scope": "gmail.readonly"},
        )
        pending_detail = expect_http_error(
            "credential create without second approval",
            lambda: app_module.create_credential(
                credential_payload, identity=requester
            ),
            428,
            "control_plane_approval_required",
        )
        approval_id = pending_detail["approvalId"]
        if db.list_credentials():
            raise AssertionError(
                "credential mutation ran before second-person approval"
            )
        pending = db.get_control_plane_approval(approval_id)
        serialized_pending = json.dumps(pending, sort_keys=True)
        if "super-secret-token" in serialized_pending:
            raise AssertionError(
                "control-plane approval request stored plaintext credential material"
            )
        if pending["payload_digest"] != pending_detail["payloadDigest"]:
            raise AssertionError(f"approval payload digest mismatch: {pending}")

        expect_http_error(
            "control-plane self approval",
            lambda: app_module.control_plane_approval_approve(
                approval_id, payload=None, identity=requester
            ),
            403,
            "cannot approve their own",
        )
        expect_http_error(
            "control-plane wrong approval role",
            lambda: app_module.control_plane_approval_approve(
                approval_id, payload=None, identity=wrong_approver
            ),
            403,
            "required role",
        )
        approved = app_module.control_plane_approval_approve(
            approval_id,
            payload=app_module.ControlPlaneApprovalDecision(
                note="credential rotation reviewed"
            ),
            identity=credential_approver,
        )
        if (
            approved["status"] != "approved"
            or approved["approved_by"] != credential_approver.user_id
        ):
            raise AssertionError(f"credential approval was not approved: {approved}")

        credential_payload.mfa = {"approvalId": approval_id}
        created = app_module.create_credential(credential_payload, identity=requester)
        if created["name"] != credential_payload.name or "secret" in created:
            raise AssertionError(
                f"credential create returned unsafe payload: {created}"
            )
        consumed = db.get_control_plane_approval(approval_id)
        if (
            consumed["status"] != "consumed"
            or consumed["consumed_by"] != requester.user_id
        ):
            raise AssertionError(
                f"approval was not consumed by the mutation: {consumed}"
            )
        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"credential audit outbox did not drain: {delivery}")
        credential_audit = next(
            item
            for item in db.list_audit_events(limit=20)
            if item["event_type"] == "credential.created"
        )
        if (
            credential_audit["event"]
            .get("control_plane_approval", {})
            .get("approved_by")
            != credential_approver.user_id
        ):
            raise AssertionError(
                f"credential audit missing second-person evidence: {credential_audit}"
            )
        expect_http_error(
            "reused control-plane approval",
            lambda: app_module.create_credential(
                credential_payload, identity=requester
            ),
            409,
            "approval_consumed",
        )

        rollback_credential = app_module.CredentialCreate(
            name="Rollback credential",
            kind="bearer",
            secret="rollback-secret",
            metadata={"purpose": "transaction-regression"},
        )
        rollback_detail = expect_http_error(
            "credential rollback approval request",
            lambda: app_module.create_credential(
                rollback_credential, identity=requester
            ),
            428,
            "control_plane_approval_required",
        )
        rollback_approval_id = rollback_detail["approvalId"]
        app_module.control_plane_approval_approve(
            rollback_approval_id, payload=None, identity=credential_approver
        )
        rollback_credential.mfa = {"approvalId": rollback_approval_id}
        original_append_audit_event = db.append_audit_event

        def reject_credential_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("event_type") == "credential.created":
                raise db.AuditStoreError("injected credential audit failure")
            return original_append_audit_event(*args, **kwargs)

        db.append_audit_event = reject_credential_audit
        try:
            try:
                app_module.create_credential(rollback_credential, identity=requester)
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError(
                    "credential mutation committed after audit failure"
                )
        finally:
            db.append_audit_event = original_append_audit_event
        if db.get_control_plane_approval(rollback_approval_id)["status"] != "approved":
            raise AssertionError("credential audit failure consumed its approval")
        if any(
            item["name"] == rollback_credential.name for item in db.list_credentials()
        ):
            raise AssertionError("credential audit failure committed the credential")
        retried_credential = app_module.create_credential(
            rollback_credential, identity=requester
        )
        if retried_credential["name"] != rollback_credential.name:
            raise AssertionError("credential approval was not reusable after rollback")

        rollback_route = app_module.RouteCreate(
            name="Rollback route",
            match_host="rollback.example",
            match_path_prefix="/transaction",
        )
        route_detail = expect_http_error(
            "route rollback approval request",
            lambda: app_module.create_route(rollback_route, identity=requester),
            428,
            "control_plane_approval_required",
        )
        route_approval_id = route_detail["approvalId"]
        app_module.control_plane_approval_approve(
            route_approval_id, payload=None, identity=route_approver
        )
        rollback_route.mfa = {"approvalId": route_approval_id}

        def reject_route_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("event_type") == "route.created":
                raise db.AuditStoreError("injected route audit failure")
            return original_append_audit_event(*args, **kwargs)

        db.append_audit_event = reject_route_audit
        try:
            try:
                app_module.create_route(rollback_route, identity=requester)
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("route mutation committed after audit failure")
        finally:
            db.append_audit_event = original_append_audit_event
        if db.get_control_plane_approval(route_approval_id)["status"] != "approved":
            raise AssertionError("route audit failure consumed its approval")
        if any(item["name"] == rollback_route.name for item in db.list_routes()):
            raise AssertionError("route audit failure committed the route")
        retried_route = app_module.create_route(rollback_route, identity=requester)
        if retried_route["name"] != rollback_route.name:
            raise AssertionError("route approval was not reusable after rollback")

        policy_bundle.write_policy_bundle(candidate_bundle(policy_bundle, 1))
        publish_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2), dryRun=[]
        )
        policy_pending = expect_http_error(
            "policy publish without second approval",
            lambda: app_module.policy_publish(publish_payload, identity=requester),
            428,
            "control_plane_approval_required",
        )
        policy_approval_id = policy_pending["approvalId"]
        app_module.control_plane_approval_approve(
            policy_approval_id, payload=None, identity=policy_approver
        )
        publish_payload.mfa = {"approvalId": policy_approval_id}
        published = app_module.policy_publish(publish_payload, identity=requester)
        if (
            published.get("published") is not True
            or published["candidate"]["sequence"] != 2
        ):
            raise AssertionError(
                f"policy publish failed after second-person approval: {published}"
            )
        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"policy audit outbox did not drain: {delivery}")
        policy_audit = next(
            item
            for item in db.list_audit_events(limit=50)
            if item["event_type"] == "policy.published"
        )
        if (
            policy_audit["event"].get("control_plane_approval", {}).get("approved_by")
            != policy_approver.user_id
        ):
            raise AssertionError(
                f"policy audit missing second-person evidence: {policy_audit}"
            )

        policy_before_rollback = policy_bundle.get_policy_snapshot()
        high_water_before_rollback = db.get_policy_high_water()
        rollback_publish = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3), dryRun=[]
        )
        policy_rollback_detail = expect_http_error(
            "policy rollback approval request",
            lambda: app_module.policy_publish(rollback_publish, identity=requester),
            428,
            "control_plane_approval_required",
        )
        policy_rollback_approval_id = policy_rollback_detail["approvalId"]
        app_module.control_plane_approval_approve(
            policy_rollback_approval_id, payload=None, identity=policy_approver
        )
        rollback_publish.mfa = {"approvalId": policy_rollback_approval_id}

        def reject_policy_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("event_type") == "policy.published":
                raise db.AuditStoreError("injected policy audit failure")
            return original_append_audit_event(*args, **kwargs)

        db.append_audit_event = reject_policy_audit
        try:
            try:
                app_module.policy_publish(rollback_publish, identity=requester)
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("policy mutation committed after audit failure")
        finally:
            db.append_audit_event = original_append_audit_event
        if (
            db.get_control_plane_approval(policy_rollback_approval_id)["status"]
            != "approved"
        ):
            raise AssertionError("policy audit failure consumed its approval")
        policy_after_rollback = policy_bundle.get_policy_snapshot()
        if (
            policy_before_rollback is None
            or policy_after_rollback is None
            or policy_after_rollback.hash != policy_before_rollback.hash
            or db.get_policy_high_water() != high_water_before_rollback
        ):
            raise AssertionError("policy audit failure changed active policy state")
        retried_policy = app_module.policy_publish(rollback_publish, identity=requester)
        if retried_policy.get("published") is not True:
            raise AssertionError("policy approval was not reusable after rollback")

        def approved_policy_publish(sequence: int) -> Any:
            candidate = app_module.PolicyPublishRequest(
                bundle=candidate_bundle(policy_bundle, sequence), dryRun=[]
            )
            detail = expect_http_error(
                f"policy sequence {sequence} approval request",
                lambda: app_module.policy_publish(candidate, identity=requester),
                428,
                "control_plane_approval_required",
            )
            app_module.control_plane_approval_approve(
                detail["approvalId"], payload=None, identity=policy_approver
            )
            candidate.mfa = {"approvalId": detail["approvalId"]}
            return candidate, detail["approvalId"]

        commit_failure_publish, commit_failure_approval_id = approved_policy_publish(4)
        active_before_commit_failure = policy_bundle.get_policy_snapshot()
        high_water_before_commit_failure = db.get_policy_high_water()
        policy_bytes_before_commit_failure = app_module.POLICY_BUNDLE_PATH.read_bytes()
        original_connect = db.connect

        def fail_policy_commit_connect() -> FailPolicyCommitConnection:
            return FailPolicyCommitConnection(original_connect())

        db.connect = fail_policy_commit_connect
        try:
            try:
                app_module.policy_publish(commit_failure_publish, identity=requester)
            except InjectedCommitFailure:
                pass
            else:
                raise AssertionError(
                    "policy publication escaped an injected database commit failure"
                )
        finally:
            db.connect = original_connect
        active_after_commit_failure = policy_bundle.get_policy_snapshot()
        high_water_after_commit_failure = db.get_policy_high_water()
        commit_failure_changes = {
            "snapshot": (
                active_before_commit_failure.hash
                if active_before_commit_failure is not None
                else None,
                active_after_commit_failure.hash
                if active_after_commit_failure is not None
                else None,
            ),
            "file_changed": app_module.POLICY_BUNDLE_PATH.read_bytes()
            != policy_bytes_before_commit_failure,
            "high_water": (
                high_water_before_commit_failure,
                high_water_after_commit_failure,
            ),
        }
        if (
            commit_failure_changes["snapshot"][0]
            != commit_failure_changes["snapshot"][1]
            or commit_failure_changes["file_changed"]
            or commit_failure_changes["high_water"][0]
            != commit_failure_changes["high_water"][1]
        ):
            raise AssertionError(
                "database commit failure changed the active policy file, snapshot, "
                f"or high-water: {commit_failure_changes}"
            )
        if (
            db.get_control_plane_approval(commit_failure_approval_id)["status"]
            != "approved"
        ):
            raise AssertionError("database commit failure consumed its policy approval")

        stale_publish, stale_approval_id = approved_policy_publish(5)
        fresh_publish, fresh_approval_id = approved_policy_publish(6)
        stale_at_audit = threading.Event()
        publication_barrier = threading.Barrier(2)
        original_publication_file_lock = app_module._policy_publication_file_lock
        race_results: dict[str, Any] = {}

        @contextmanager
        def coordinated_publication_file_lock():
            if threading.current_thread().name == "policy-fresh-publisher":
                publication_barrier.wait(timeout=5)
            with original_publication_file_lock():
                yield

        def reject_stale_policy_audit(*args: Any, **kwargs: Any) -> dict[str, Any]:
            event = kwargs.get("event") or {}
            if (
                kwargs.get("event_type") == "policy.published"
                and event.get("new_sequence") == 5
            ):
                stale_at_audit.set()
                publication_barrier.wait(timeout=5)
                raise db.AuditStoreError("injected concurrent policy audit failure")
            return original_append_audit_event(*args, **kwargs)

        def publish_stale() -> None:
            try:
                app_module.policy_publish(stale_publish, identity=requester)
            except BaseException as exc:
                race_results["stale_error"] = exc
            else:
                race_results["stale_result"] = "published"

        def publish_fresh() -> None:
            try:
                race_results["fresh_result"] = app_module.policy_publish(
                    fresh_publish, identity=requester
                )
            except BaseException as exc:
                race_results["fresh_error"] = exc

        app_module._policy_publication_file_lock = coordinated_publication_file_lock
        db.append_audit_event = reject_stale_policy_audit
        stale_thread = threading.Thread(
            target=publish_stale, name="policy-stale-publisher"
        )
        fresh_thread = threading.Thread(
            target=publish_fresh, name="policy-fresh-publisher"
        )
        try:
            stale_thread.start()
            if not stale_at_audit.wait(timeout=5):
                raise AssertionError(
                    "stale policy publisher did not reach the audit barrier"
                )
            fresh_thread.start()
            stale_thread.join(timeout=10)
            fresh_thread.join(timeout=10)
        finally:
            app_module._policy_publication_file_lock = original_publication_file_lock
            db.append_audit_event = original_append_audit_event
        if stale_thread.is_alive() or fresh_thread.is_alive():
            raise AssertionError("concurrent policy publication did not terminate")
        if not isinstance(race_results.get("stale_error"), db.AuditStoreError):
            raise AssertionError(
                f"stale policy publication did not roll back: {race_results}"
            )
        if (
            race_results.get("fresh_error") is not None
            or race_results.get("fresh_result", {}).get("published") is not True
        ):
            raise AssertionError(
                f"fresh policy publication did not commit: {race_results}"
            )
        active_after_race = policy_bundle.get_policy_snapshot()
        high_water_after_race = db.get_policy_high_water()
        if (
            active_after_race is None
            or active_after_race.raw.get("metadata", {}).get("sequence") != 6
            or high_water_after_race is None
            or high_water_after_race["sequence"] != 6
            or high_water_after_race["policy_hash"] != active_after_race.hash
        ):
            raise AssertionError(
                "stale policy rollback reactivated an older policy: "
                f"snapshot={active_after_race} high_water={high_water_after_race}"
            )
        if db.get_control_plane_approval(stale_approval_id)["status"] != "approved":
            raise AssertionError("stale policy rollback consumed its approval")
        if db.get_control_plane_approval(fresh_approval_id)["status"] != "consumed":
            raise AssertionError("fresh policy publication did not consume its approval")

        postgres_policy_lock_sql: list[tuple[str, Any]] = []
        fake_postgres = db.PostgresMetadataConnection(None)

        def record_postgres_policy_lock(sql: str, params: Any = None) -> None:
            postgres_policy_lock_sql.append((sql, params))

        fake_postgres.execute = record_postgres_policy_lock
        db.lock_policy_publication(fake_postgres)
        timeout_positions = [
            index
            for index, (sql, _) in enumerate(postgres_policy_lock_sql)
            if "lock_timeout" in sql.lower()
        ]
        advisory_positions = [
            index
            for index, (sql, _) in enumerate(postgres_policy_lock_sql)
            if "pg_advisory_xact_lock" in sql.lower()
        ]
        if (
            len(timeout_positions) != 1
            or len(advisory_positions) != 1
            or timeout_positions[0] > advisory_positions[0]
        ):
            raise AssertionError(
                "PostgreSQL policy publication lock was not bounded before waiting: "
                f"{postgres_policy_lock_sql}"
            )

        search = db.search_audit_events(
            event_type="control_plane.approval.consumed", approval_id=policy_approval_id
        )
        if search["count"] != 1:
            raise AssertionError(f"consumed approval audit is not searchable: {search}")

        original_authority_lock = db._lock_webauthn_authority

        def delayed_authority_lock(conn: Any) -> None:
            original_authority_lock(conn)
            time.sleep(0.12)

        expiring = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="expiry-before-approve",
            payload_digest="sha256:" + "a" * 64,
            requester_id=requester.user_id,
            request={"summary": "expiry lock test"},
            ttl_seconds=300,
        )
        with db.connect() as conn:
            conn.execute(
                "UPDATE control_plane_approvals SET expires_at = ? WHERE id = ?",
                (
                    (db.utcnow() + timedelta(milliseconds=50)).isoformat(),
                    expiring["id"],
                ),
            )
        db._lock_webauthn_authority = delayed_authority_lock
        try:
            if (
                db.approve_control_plane_approval(
                    expiring["id"], actor_id=credential_approver.user_id
                )
                is not None
            ):
                raise AssertionError(
                    "approval crossed its expiry while waiting for the authority lock"
                )
        finally:
            db._lock_webauthn_authority = original_authority_lock

        expiring = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="expiry-before-consume",
            payload_digest="sha256:" + "b" * 64,
            requester_id=requester.user_id,
            request={"summary": "consume expiry lock test"},
            ttl_seconds=300,
        )
        if (
            db.approve_control_plane_approval(
                expiring["id"], actor_id=credential_approver.user_id
            )
            is None
        ):
            raise AssertionError("consume expiry fixture was not approved")
        with db.connect() as conn:
            conn.execute(
                "UPDATE control_plane_approvals SET expires_at = ? WHERE id = ?",
                (
                    (db.utcnow() + timedelta(milliseconds=50)).isoformat(),
                    expiring["id"],
                ),
            )
        db._lock_webauthn_authority = delayed_authority_lock
        try:
            result = db.consume_control_plane_approval(
                expiring["id"],
                action="credential.create",
                resource_id="expiry-before-consume",
                payload_digest="sha256:" + "b" * 64,
                actor_id=requester.user_id,
            )
            if result != {"ok": False, "reason": "approval_expired"}:
                raise AssertionError(f"consumption crossed approval expiry: {result}")
        finally:
            db._lock_webauthn_authority = original_authority_lock

        stale_approver_id = "oidc:stale-credential-approver@example.com"
        authority = db.get_rbac_authority_state()
        stale_approver_binding = db.mutate_rbac_role_binding(
            subject_id=stale_approver_id,
            roles=["credential_owner"],
            status="active",
            expected_generation=authority["generation"],
            actor_id=requester.user_id,
            reason="approval commit-time authority fixture",
            event_type="rbac.role_changed",
            event={"test": "approval_commit_time_authorization"},
        )
        stale_approver = AdminIdentity(
            stale_approver_id,
            frozenset({"credential_owner"}),
            "oidc-bearer",
        )
        stale_approval = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="stale-approver-before-commit",
            payload_digest="sha256:" + "c" * 64,
            requester_id=requester.user_id,
            request={"summary": "approval commit-time authority test"},
            ttl_seconds=300,
        )
        db.mutate_rbac_role_binding(
            subject_id=stale_approver_id,
            roles=[],
            status="deprovisioned",
            expected_generation=stale_approver_binding["generation"],
            actor_id=requester.user_id,
            reason="deprovision immediately before approval commit",
            event_type="rbac.deprovisioned",
            event={"test": "approval_commit_time_authorization"},
        )
        expect_http_error(
            "deprovisioned OIDC approval commit",
            lambda: app_module.control_plane_approval_approve(
                stale_approval["id"],
                payload=None,
                identity=stale_approver,
            ),
            409,
            "state changed",
        )
        if db.get_control_plane_approval(stale_approval["id"])["status"] != "pending":
            raise AssertionError("rejected stale approver changed the approval state")

        oidc_approver_id = "oidc:credential-approver@example.com"
        authority = db.get_rbac_authority_state()
        provisioned_approver = db.mutate_rbac_role_binding(
            subject_id=oidc_approver_id,
            roles=["credential_owner"],
            status="active",
            expected_generation=authority["generation"],
            actor_id=requester.user_id,
            reason="approval revocation fixture",
            event_type="rbac.role_changed",
            event={"test": "approver_commit_time_authorization"},
        )
        revocation_approval = db.ensure_control_plane_approval(
            action="credential.create",
            resource_id="revoked-approver",
            payload_digest="sha256:" + "d" * 64,
            requester_id=requester.user_id,
            request={"summary": "approver revocation test"},
            ttl_seconds=300,
        )
        if (
            db.approve_control_plane_approval(
                revocation_approval["id"], actor_id=oidc_approver_id
            )
            is None
        ):
            raise AssertionError("OIDC approver fixture was not approved")
        db.mutate_rbac_role_binding(
            subject_id=oidc_approver_id,
            roles=[],
            status="deprovisioned",
            expected_generation=provisioned_approver["generation"],
            actor_id=requester.user_id,
            reason="revoke before approval consumption",
            event_type="rbac.deprovisioned",
            event={"test": "approver_commit_time_authorization"},
        )
        revoked_consumption = db.consume_control_plane_approval(
            revocation_approval["id"],
            action="credential.create",
            resource_id="revoked-approver",
            payload_digest="sha256:" + "d" * 64,
            actor_id=requester.user_id,
            required_approver_roles={"credential_owner"},
        )
        if revoked_consumption != {
            "ok": False,
            "reason": "approval_approver_role_revoked",
        }:
            raise AssertionError(
                f"revoked OIDC approver was not rejected: {revoked_consumption}"
            )
        if (
            db.get_control_plane_approval(revocation_approval["id"])["status"]
            != "approved"
        ):
            raise AssertionError("rejected OIDC approval was consumed")

        oidc_requester_id = "oidc:credential-requester@example.com"
        authority = db.get_rbac_authority_state()
        provisioned_requester = db.mutate_rbac_role_binding(
            subject_id=oidc_requester_id,
            roles=["credential_owner"],
            status="active",
            expected_generation=authority["generation"],
            actor_id=requester.user_id,
            reason="requester commit-time authorization fixture",
            event_type="rbac.role_changed",
            event={"test": "requester_commit_time_authorization"},
        )
        stale_requester = AdminIdentity(
            oidc_requester_id,
            frozenset({"credential_owner"}),
            "oidc-bearer",
        )
        stale_payload = app_module.CredentialCreate(
            name="Requester authority must remain current",
            kind="bearer",
            secret="must-not-commit",
            metadata={"purpose": "requester-authority-race"},
        )
        stale_detail = expect_http_error(
            "OIDC requester approval request",
            lambda: app_module.create_credential(
                stale_payload,
                identity=stale_requester,
            ),
            428,
            "control_plane_approval_required",
        )
        stale_approval_id = stale_detail["approvalId"]
        app_module.control_plane_approval_approve(
            stale_approval_id,
            payload=None,
            identity=credential_approver,
        )
        db.mutate_rbac_role_binding(
            subject_id=oidc_requester_id,
            roles=[],
            status="deprovisioned",
            expected_generation=provisioned_requester["generation"],
            actor_id=requester.user_id,
            reason="deprovision immediately before protected mutation commit",
            event_type="rbac.deprovisioned",
            event={"test": "requester_commit_time_authorization"},
        )
        stale_payload.mfa = {"approvalId": stale_approval_id}
        expect_http_error(
            "deprovisioned OIDC requester commit",
            lambda: app_module.create_credential(
                stale_payload,
                identity=stale_requester,
            ),
            409,
            "approval_requester_role_revoked",
        )
        if any(item["name"] == stale_payload.name for item in db.list_credentials()):
            raise AssertionError("deprovisioned OIDC requester committed a credential")
        if db.get_control_plane_approval(stale_approval_id)["status"] != "approved":
            raise AssertionError("requester authority rejection consumed its approval")

        original_audit_backend = db.AUDIT_STORE_BACKEND
        original_postgres_append = db._append_postgres_audit_event
        db.AUDIT_STORE_BACKEND = "postgres"
        try:
            try:
                with db.connect() as conn:
                    db.append_audit_event(
                        conn,
                        event_type="test.metadata.rollback",
                        actor_type="system",
                        actor_id=None,
                        event={"must_not_commit": True},
                    )
                    raise RuntimeError("force metadata rollback")
            except RuntimeError as exc:
                if str(exc) != "force metadata rollback":
                    raise
            status = db.metadata_audit_outbox_status()
            if status["pending"] != 0:
                raise AssertionError(f"rolled-back audit intent survived: {status}")

            with db.connect() as conn:
                staged = db.append_audit_event(
                    conn,
                    event_type="test.metadata.commit",
                    actor_type="system",
                    actor_id=None,
                    event={"committed": True},
                    idempotency_key="metadata-outbox-commit-test",
                )
            if staged.get("outbox_status") != "pending":
                raise AssertionError(f"metadata audit intent was not staged: {staged}")

            def fake_postgres_append(**kwargs: Any) -> dict[str, Any]:
                return {
                    "id": kwargs["idempotency_key"],
                    "event_hash": "sha256:" + "c" * 64,
                }

            db._append_postgres_audit_event = fake_postgres_append
            delivery = db.drain_metadata_audit_outbox(limit=10)
            if delivery != {"claimed": 1, "audited": 1, "failed": 0, "pending": 0}:
                raise AssertionError(
                    f"metadata audit outbox delivery failed: {delivery}"
                )
        finally:
            db._append_postgres_audit_event = original_postgres_append
            db.AUDIT_STORE_BACKEND = original_audit_backend

    print(json.dumps({"control_plane_two_person": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--postgres-lock-dsn":
        run_postgres_policy_lock_timeout(sys.argv[2])
    else:
        main()
