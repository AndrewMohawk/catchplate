#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


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


def dry_run_case(app_module: Any) -> Any:
    return app_module.PolicyDryRunCase(
        principalId="agent:demo",
        scheme="https",
        host="demo-upstream",
        port=8443,
        method="GET",
        path="/echo",
        expect="allow",
    )


def sign_publish_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str) -> dict[str, Any]:
    digest = app_module._policy_publish_payload_digest(payload)
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=payload.bundle["metadata"]["id"],
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    serialized_options = json.dumps(options, sort_keys=True)
    if "demo-token-from-vault" in serialized_options:
        raise AssertionError("policy canary WebAuthn challenge leaked credential material")
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def sign_activate_assertion(app_module: Any, webauthn: Any, payload: Any, user_id: str, policy_id: str) -> dict[str, Any]:
    digest = app_module._policy_canary_activate_payload_digest(payload)
    options = webauthn.control_plane_mutation_options(
        user_id=user_id,
        action="policy.publish",
        resource_id=policy_id,
        payload_digest=digest,
        authn_policy={"userVerification": "required"},
    )
    return webauthn.dev_assertion(options["publicKey"]["challenge"])


def expect_http_error(label: str, func: Any, expected_status: int, expected_detail: str) -> dict[str, Any]:
    from fastapi import HTTPException

    try:
        func()
    except HTTPException as exc:
        detail = json.dumps(exc.detail, sort_keys=True) if isinstance(exc.detail, dict) else str(exc.detail)
        if exc.status_code != expected_status or expected_detail not in detail:
            raise AssertionError(f"{label} failed with wrong error: {exc.status_code} {detail}") from exc
        return exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
    raise AssertionError(f"{label} unexpectedly succeeded")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ["SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_CANARY_REQUIRED"] = "1"
        os.environ["SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS"] = "1"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_WEBAUTHN_ORIGIN"] = "http://localhost:3000"

        from serverware import app as app_module
        from serverware import db, policy_bundle, webauthn
        from serverware.auth import AdminIdentity

        db.init_db()
        user_id = "user:publisher"
        identity = AdminIdentity(user_id, frozenset({"policy_publisher", "policy_author", "auditor"}), "admin-token-header")
        webauthn.create_dev_credential(user_id)
        initial = policy_bundle.write_policy_bundle(candidate_bundle(policy_bundle, 1))
        policy_bundle.enforce_policy_high_water(initial)
        active_before = policy_bundle.get_policy_snapshot()

        full_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
        )
        expect_http_error(
            "direct full publish while canary is required",
            lambda: app_module.policy_publish(full_payload, identity=identity),
            412,
            "canary activation",
        )

        empty_status = app_module.policy_canary_status(_=identity)
        if empty_status != {"ok": True, "canary": None, "monitoring": None}:
            raise AssertionError(f"empty canary status was not idempotent: {empty_status}")

        canary_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 2),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        try:
            app_module.PolicyPublishRequest(
                bundle=candidate_bundle(policy_bundle, 2),
                dryRun=[dry_run_case(app_module)],
                activationMode="canary",
                canaryPercent=10.0,
            )
        except Exception as exc:
            if type(exc).__name__ != "ValidationError":
                raise
        else:
            raise AssertionError("removed canary traffic percentage was still accepted")
        canary_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, canary_payload, user_id)}
        canary = app_module.policy_publish(canary_payload, identity=identity)
        canary_id = canary["canary"]["id"]
        candidate_hash = canary["candidate"]["policyHash"]
        if canary.get("published") is not False or canary["policyHash"] != active_before.hash:
            raise AssertionError(f"canary publish activated the policy instead of staging it: {canary}")
        if not app_module.POLICY_CANARY_BUNDLE_PATH.exists():
            raise AssertionError("canary signed bundle was not written")
        still_active = policy_bundle.get_policy_snapshot()
        if not still_active or still_active.hash != active_before.hash:
            raise AssertionError("active policy changed during canary start")

        db.record_audit_event(
            "data_plane.response.released",
            {
                "route_id": "demo.echo",
                "decision": "allow",
                "latency_ms": 12.5,
                "policy_hash": candidate_hash,
            },
            actor_id="decision-gate-rs",
        )
        db.record_audit_event(
            "data_plane.response.released",
            {
                "route_id": "demo.echo",
                "decision": "allow",
                "latency_ms": 1,
                "policy_hash": active_before.hash,
            },
            actor_id="decision-gate-rs",
        )
        db.record_audit_event(
            "data_plane.response.released",
            {
                "decision": "allow",
                "latency_ms": 2,
                "policy_hash": candidate_hash,
            },
            actor_id="decision-gate-rs",
        )
        status = app_module.policy_canary_status(_=identity)
        if status["monitoring"]["auditEvents"] != 1 or status["monitoring"]["denials"] != 0:
            raise AssertionError(f"canary monitoring did not include audit evidence: {status}")
        if status["monitoring"]["latencyMsP95"] != 12.5:
            raise AssertionError(f"canary monitoring did not report latency evidence: {status}")

        activation = app_module.PolicyCanaryActivationRequest(canaryId=canary_id)
        activation.mfa = {"assertion": sign_activate_assertion(app_module, webauthn, activation, user_id, "serverware-demo")}
        active_before_commit_failure = policy_bundle.get_policy_snapshot()
        high_water_before_commit_failure = db.get_policy_high_water()
        policy_bytes_before_commit_failure = app_module.POLICY_BUNDLE_PATH.read_bytes()
        canary_bytes_before_commit_failure = app_module.POLICY_CANARY_STATE_PATH.read_bytes()
        original_connect = db.connect

        def fail_policy_commit_connect() -> FailPolicyCommitConnection:
            return FailPolicyCommitConnection(original_connect())

        db.connect = fail_policy_commit_connect
        try:
            try:
                app_module.policy_canary_activate(activation, identity=identity)
            except InjectedCommitFailure:
                pass
            else:
                raise AssertionError(
                    "canary activation escaped an injected database commit failure"
                )
        finally:
            db.connect = original_connect
        active_after_commit_failure = policy_bundle.get_policy_snapshot()
        canary_after_commit_failure = app_module.policy_canary_status(_=identity)
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
            "policy_file_changed": app_module.POLICY_BUNDLE_PATH.read_bytes()
            != policy_bytes_before_commit_failure,
            "canary_file_changed": app_module.POLICY_CANARY_STATE_PATH.read_bytes()
            != canary_bytes_before_commit_failure,
            "high_water": (
                high_water_before_commit_failure,
                high_water_after_commit_failure,
            ),
            "canary_status": canary_after_commit_failure["canary"]["status"],
        }
        if (
            commit_failure_changes["snapshot"][0]
            != commit_failure_changes["snapshot"][1]
            or commit_failure_changes["policy_file_changed"]
            or commit_failure_changes["canary_file_changed"]
            or commit_failure_changes["high_water"][0]
            != commit_failure_changes["high_water"][1]
            or commit_failure_changes["canary_status"] != "running"
        ):
            raise AssertionError(
                "database commit failure changed the active policy file, snapshot, "
                f"high-water, or running canary state: {commit_failure_changes}"
            )

        activation.mfa = {"assertion": sign_activate_assertion(app_module, webauthn, activation, user_id, "serverware-demo")}
        activated = app_module.policy_canary_activate(activation, identity=identity)
        if activated.get("published") is not True or activated["policyHash"] != candidate_hash:
            raise AssertionError(f"canary activation did not publish the candidate: {activated}")
        active_after = policy_bundle.get_policy_snapshot()
        if not active_after or active_after.hash != candidate_hash:
            raise AssertionError("active policy snapshot was not updated after canary activation")

        delivery = db.drain_metadata_audit_outbox_fully()
        if delivery["failed"] or delivery["pending"]:
            raise AssertionError(f"policy canary audit outbox did not drain: {delivery}")
        audits = db.list_audit_events(limit=50)
        event_types = [item["event_type"] for item in audits]
        for expected in ("policy.canary.started", "policy.canary.activated", "policy.published"):
            if expected not in event_types:
                raise AssertionError(f"missing {expected} audit event: {event_types}")
        published_event = next(item for item in audits if item["event_type"] == "policy.published")
        if published_event["event"].get("activation_mode") != "canary":
            raise AssertionError(f"published audit event did not bind canary activation: {published_event}")

        second_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 3),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        second_payload.mfa = {"assertion": sign_publish_assertion(app_module, webauthn, second_payload, user_id)}
        second_canary = app_module.policy_publish(second_payload, identity=identity)
        second_candidate_hash = second_canary["candidate"]["policyHash"]
        db.record_audit_event(
            "data_plane.response.released",
            {
                "route_id": "demo.echo",
                "decision": "allow",
                "latency_ms": 8,
                "policy_hash": second_candidate_hash,
            },
            actor_id="decision-gate-rs",
        )
        raced_activation = app_module.PolicyCanaryActivationRequest(
            canaryId=second_canary["canary"]["id"]
        )
        raced_activation.mfa = {
            "assertion": sign_activate_assertion(
                app_module, webauthn, raced_activation, user_id, "serverware-demo"
            )
        }
        cancel_payload = app_module.PolicyCanaryCancelRequest(canaryId=second_canary["canary"]["id"], note="superseded")
        activation_holds_authority = threading.Event()
        release_activation = threading.Event()
        cancellation_attempted_lock = threading.Event()
        original_publication_file_lock = app_module._policy_publication_file_lock
        original_policy_publication_lock = db.lock_policy_publication
        race_results: dict[str, Any] = {}

        @contextmanager
        def observed_publication_file_lock():
            if threading.current_thread().name == "canary-canceller":
                cancellation_attempted_lock.set()
            with original_publication_file_lock():
                yield

        def block_activation_with_authority(conn: Any) -> None:
            original_policy_publication_lock(conn)
            if threading.current_thread().name == "canary-activator":
                activation_holds_authority.set()
                if not release_activation.wait(timeout=5):
                    raise AssertionError("timed out holding canary activation authority")

        def activate_canary() -> None:
            try:
                race_results["activation"] = app_module.policy_canary_activate(
                    raced_activation, identity=identity
                )
            except BaseException as exc:
                race_results["activation_error"] = exc

        def cancel_canary() -> None:
            try:
                race_results["cancellation"] = app_module.policy_canary_cancel(
                    cancel_payload, identity=identity
                )
            except BaseException as exc:
                race_results["cancellation_error"] = exc

        app_module._policy_publication_file_lock = observed_publication_file_lock
        db.lock_policy_publication = block_activation_with_authority
        activation_thread = threading.Thread(
            target=activate_canary, name="canary-activator"
        )
        cancellation_thread = threading.Thread(
            target=cancel_canary, name="canary-canceller"
        )
        try:
            activation_thread.start()
            if not activation_holds_authority.wait(timeout=5):
                raise AssertionError("canary activation did not acquire authority")
            cancellation_thread.start()
            if not cancellation_attempted_lock.wait(timeout=5):
                raise AssertionError("canary cancellation did not attempt the shared lock")
            cancellation_thread.join(timeout=0.1)
            if not cancellation_thread.is_alive():
                raise AssertionError(
                    "canary cancellation did not serialize behind activation"
                )
            release_activation.set()
            activation_thread.join(timeout=10)
            cancellation_thread.join(timeout=10)
        finally:
            release_activation.set()
            app_module._policy_publication_file_lock = original_publication_file_lock
            db.lock_policy_publication = original_policy_publication_lock
        if activation_thread.is_alive() or cancellation_thread.is_alive():
            raise AssertionError("canary terminal-state race did not terminate")
        if (
            race_results.get("activation_error") is not None
            or race_results.get("activation", {}).get("published") is not True
        ):
            raise AssertionError(f"canary activation did not win its lock: {race_results}")
        cancellation_error = race_results.get("cancellation_error")
        if (
            getattr(cancellation_error, "status_code", None) != 409
            or "activated" not in str(getattr(cancellation_error, "detail", ""))
        ):
            raise AssertionError(
                f"serialized cancellation did not observe activated state: {race_results}"
            )
        terminal_status = app_module.policy_canary_status(_=identity)
        if (
            terminal_status["canary"]["status"] != "activated"
            or policy_bundle.get_policy_snapshot().hash != second_candidate_hash
        ):
            raise AssertionError(
                f"activation/cancellation race lost terminal state: {terminal_status}"
            )

        first_start_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 4),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        second_start_payload = app_module.PolicyPublishRequest(
            bundle=candidate_bundle(policy_bundle, 5),
            dryRun=[dry_run_case(app_module)],
            activationMode="canary",
        )
        original_mutation_webauthn_required = (
            app_module.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED
        )
        app_module.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED = False
        first_start_holds_lock = threading.Event()
        release_first_start = threading.Event()
        second_start_attempted_lock = threading.Event()
        original_write_canary_bundle = app_module._write_policy_canary_bundle
        start_results: dict[str, Any] = {}

        def block_first_canary_write(bundle: dict[str, Any]) -> None:
            if threading.current_thread().name == "first-canary-starter":
                first_start_holds_lock.set()
                if not release_first_start.wait(timeout=5):
                    raise AssertionError("timed out holding first canary start lock")
            original_write_canary_bundle(bundle)

        def start_first_canary() -> None:
            try:
                start_results["first"] = app_module.policy_publish(
                    first_start_payload, identity=identity
                )
            except BaseException as exc:
                start_results["first_error"] = exc

        def start_second_canary() -> None:
            second_start_attempted_lock.set()
            try:
                start_results["second"] = app_module.policy_publish(
                    second_start_payload, identity=identity
                )
            except BaseException as exc:
                start_results["second_error"] = exc

        app_module._write_policy_canary_bundle = block_first_canary_write
        first_start_thread = threading.Thread(
            target=start_first_canary, name="first-canary-starter"
        )
        second_start_thread = threading.Thread(
            target=start_second_canary, name="second-canary-starter"
        )
        try:
            first_start_thread.start()
            if not first_start_holds_lock.wait(timeout=5):
                raise AssertionError("first canary start did not hold the shared lock")
            second_start_thread.start()
            if not second_start_attempted_lock.wait(timeout=5):
                raise AssertionError("second canary start did not attempt the transition")
            second_start_thread.join(timeout=0.1)
            if not second_start_thread.is_alive():
                raise AssertionError("concurrent canary starts were not serialized")
            release_first_start.set()
            first_start_thread.join(timeout=10)
            second_start_thread.join(timeout=10)
        finally:
            release_first_start.set()
            app_module.CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED = (
                original_mutation_webauthn_required
            )
            app_module._write_policy_canary_bundle = original_write_canary_bundle
        if first_start_thread.is_alive() or second_start_thread.is_alive():
            raise AssertionError("concurrent canary starts did not terminate")
        if (
            start_results.get("first_error") is not None
            or start_results.get("first", {}).get("published") is not False
        ):
            raise AssertionError(f"first canary start did not commit: {start_results}")
        second_start_error = start_results.get("second_error")
        if (
            getattr(second_start_error, "status_code", None) != 409
            or "already" not in str(getattr(second_start_error, "detail", ""))
        ):
            raise AssertionError(
                f"second serialized canary start was not rejected: {start_results}"
            )
        final_running = app_module.policy_canary_status(_=identity)
        if (
            final_running["canary"]["status"] != "running"
            or final_running["canary"]["id"]
            != start_results["first"]["canary"]["id"]
        ):
            raise AssertionError(
                f"concurrent canary starts overwrote running state: {final_running}"
            )

        final_cancel = app_module.PolicyCanaryCancelRequest(
            canaryId=final_running["canary"]["id"], note="serialized cleanup"
        )
        cancelled = app_module.policy_canary_cancel(final_cancel, identity=identity)
        if cancelled["canary"]["status"] != "cancelled":
            raise AssertionError(f"canary cancel did not update state: {cancelled}")
        cancelled_activation = app_module.PolicyCanaryActivationRequest(
            canaryId=final_running["canary"]["id"]
        )
        expect_http_error(
            "activate cancelled canary",
            lambda: app_module.policy_canary_activate(cancelled_activation, identity=identity),
            409,
            "cancelled",
        )

    print(json.dumps({"ok": True, "policy_canary_workflow": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
