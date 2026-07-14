#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def config_probe(env: dict[str, str], *, expected_error: str | None = None, redacted_value: str | None = None) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json; from serverware import config; "
                "print(json.dumps({'google': bool(config.GOOGLE_OAUTH_CLIENT_SECRET), "
                "'x': bool(config.X_OAUTH_CLIENT_SECRET)}))"
            ),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if redacted_value and redacted_value in output:
        raise AssertionError("OAuth config probe disclosed client secret material")
    if expected_error is None:
        if completed.returncode != 0:
            raise AssertionError(f"valid OAuth secret-file config failed: {output}")
        parsed = json.loads(completed.stdout)
        if parsed != {"google": True, "x": True}:
            raise AssertionError(f"OAuth secret files did not configure both providers: {parsed}")
        return
    if completed.returncode == 0 or expected_error not in output:
        raise AssertionError(f"OAuth config probe did not fail with {expected_error!r}: {output}")


def write_secret(path: Path, value: str, mode: int = 0o600) -> Path:
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def run_config_secret_file_tests(tmp_path: Path) -> None:
    relevant_names = {
        "SERVERWARE_RELEASE_CHANNEL",
        "SERVERWARE_PUBLIC_URL",
        "SERVERWARE_OAUTH_STATE_TTL_SECONDS",
        "SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS",
        "SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI",
        "SERVERWARE_X_OAUTH_CLIENT_ID",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_X_OAUTH_REDIRECT_URI",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_ID",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_REDIRECT_URI",
    }
    base_env = {name: value for name, value in os.environ.items() if name not in relevant_names}
    google_secret = write_secret(tmp_path / "google-client-secret", "test-google-client-secret-0123456789")
    x_secret = write_secret(tmp_path / "x-client-secret", "test-x-client-secret-0123456789")
    base_env.update(
        {
            "SERVERWARE_RELEASE_CHANNEL": "prod",
            "SERVERWARE_PUBLIC_URL": "https://serverware.test",
            "SERVERWARE_OAUTH_STATE_TTL_SECONDS": "600",
            "SERVERWARE_OAUTH_PENDING_CREDENTIAL_TTL_SECONDS": "900",
            "SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT": "1000",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "test-google-client",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(google_secret),
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://serverware.test/api/oauth/callback/google",
            "SERVERWARE_X_OAUTH_CLIENT_ID": "test-x-client",
            "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE": str(x_secret),
            "SERVERWARE_X_OAUTH_REDIRECT_URI": "https://serverware.test/api/oauth/callback/x",
        }
    )
    config_probe(base_env)

    invalid_pending_capacity_env = dict(base_env)
    invalid_pending_capacity_env["SERVERWARE_OAUTH_PENDING_CREDENTIAL_MAX_COUNT"] = "10001"
    config_probe(invalid_pending_capacity_env, expected_error="must be between 1 and 10000")

    ambiguous_env = dict(base_env)
    ambiguous_secret = "test-ambiguous-client-secret-0123456789"
    ambiguous_env["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET"] = ambiguous_secret
    config_probe(
        ambiguous_env,
        expected_error="must not set both SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET",
        redacted_value=ambiguous_secret,
    )

    unsafe_mode = write_secret(tmp_path / "unsafe-mode-client-secret", "test-unsafe-secret-0123456789", 0o644)
    unsafe_mode_env = dict(base_env)
    unsafe_mode_env["SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE"] = str(unsafe_mode)
    config_probe(unsafe_mode_env, expected_error="mode 0400 or 0600")

    oversized = write_secret(tmp_path / "oversized-client-secret", "x" * 4097)
    oversized_env = dict(base_env)
    oversized_env["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"] = str(oversized)
    config_probe(oversized_env, expected_error="between 1 and 4096 bytes")

    symlink = tmp_path / "symlink-client-secret"
    symlink.symlink_to(google_secret)
    symlink_env = dict(base_env)
    symlink_env["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE"] = str(symlink)
    config_probe(symlink_env, expected_error="non-symlink secret file")

    relative_env = dict(base_env)
    relative_env["SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE"] = "relative-client-secret"
    config_probe(relative_env, expected_error="must be an absolute path")


def verify_compose_oauth_contract() -> None:
    development = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    production = (ROOT / "docker-compose.production.yml").read_text(encoding="utf-8")
    for setting_name in (
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID",
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI",
        "SERVERWARE_X_OAUTH_CLIENT_ID",
        "SERVERWARE_X_OAUTH_REDIRECT_URI",
    ):
        if f"{setting_name}: ${{{setting_name}:-" not in development:
            raise AssertionError(f"development Compose does not forward optional {setting_name}")
    for setting_name, container_path in (
        ("SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE", "/run/secrets/serverware-google-oauth-client-secret"),
        ("SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE", "/run/secrets/serverware-x-oauth-client-secret"),
    ):
        if f"{setting_name}: ${{{setting_name}:+{container_path}}}" not in development:
            raise AssertionError(f"development Compose does not forward optional safe path for {setting_name}")
        if f"${{{setting_name}:-/dev/null}}:{container_path}:ro" not in development:
            raise AssertionError(f"development Compose does not mount optional {setting_name}")
    for setting_name in (
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID",
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI",
        "SERVERWARE_X_OAUTH_CLIENT_ID",
        "SERVERWARE_X_OAUTH_REDIRECT_URI",
    ):
        if f"{setting_name}: ${{{setting_name}:?" not in production:
            raise AssertionError(f"production Compose does not require {setting_name}")
    if "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET:" in production or "SERVERWARE_X_OAUTH_CLIENT_SECRET:" in production:
        raise AssertionError("production Compose forwards a plaintext OAuth client secret")
    for container_path in (
        "/run/secrets/serverware-google-oauth-client-secret:ro",
        "/run/secrets/serverware-x-oauth-client-secret:ro",
    ):
        if container_path not in production:
            raise AssertionError(f"production Compose does not mount {container_path}")


def compose_manifests_available() -> bool:
    return (ROOT / "docker-compose.yml").is_file() and (ROOT / "docker-compose.production.yml").is_file()


def run_oauth_setup_session_state_tests(oauth, db, data_dir: Path) -> None:
    state_path = data_dir / "oauth-states.json"

    def state_records() -> dict[str, object]:
        if not state_path.exists():
            return {}
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        return payload.get("states", {})

    def start_flow(*, label: str, browser_nonce: str, setup_session_id=None):
        return oauth.create_authorization_url(
            provider_id="google",
            credential_name=label,
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            metadata={"test": "setup-session-continuity"},
            actor_id="user:setup-session-test",
            browser_nonce=browser_nonce,
            setup_session_id=setup_session_id,
        )

    malformed_values = (
        "",
        "not-a-uuid",
        "550E8400-E29B-41D4-A716-446655440000",
        "{550e8400-e29b-41d4-a716-446655440000}",
        "550e8400e29b41d4a716446655440000",
        "550e8400-e29b-41d4-a716-446655440000 ",
        123,
    )
    for index, malformed in enumerate(malformed_values):
        states_before = set(state_records())
        try:
            start_flow(
                label=f"Malformed setup session {index}",
                browser_nonce=f"{index + 100:043d}",
                setup_session_id=malformed,
            )
        except oauth.OAuthError as exc:
            if "canonical UUID" not in str(exc):
                raise AssertionError(f"malformed setup session failed incorrectly: {exc}") from exc
        else:
            raise AssertionError(f"malformed setup session was accepted: {malformed!r}")
        if set(state_records()) != states_before:
            raise AssertionError("malformed setup session created OAuth state")

    original_post_token_request = oauth._post_token_request
    original_fetch_provider_identity = oauth._fetch_provider_identity
    token_exchange_calls = 0

    def fake_post_token_request(provider, body, headers):
        nonlocal token_exchange_calls
        token_exchange_calls += 1
        return {
            "access_token": "setup-session-access-token",
            "refresh_token": "setup-session-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    oauth._post_token_request = fake_post_token_request
    oauth._fetch_provider_identity = lambda provider, token: {
        "provider_subject": "setup-session-subject",
        "provider_account": "setup-session@example.test",
        "provider_identity_verified": True,
        "provider_email_verified": True,
    }

    def exchange_flow(started, browser_nonce: str, code: str):
        exchanged = oauth.exchange_authorization_code(
            provider_id="google",
            code=code,
            state=str(started["state"]),
            browser_nonce=browser_nonce,
        )
        if not db.complete_oauth_revocation_work(str(exchanged["revocationWorkId"])):
            raise AssertionError("OAuth setup-session test did not release revocation work")
        return exchanged

    try:
        legacy_nonce = "l" * 43
        legacy_start = start_flow(label="Legacy OAuth state", browser_nonce=legacy_nonce)
        legacy_record = state_records().get(str(legacy_start["state"]))
        if "setupSessionId" in legacy_start or "setup_session_id" in legacy_start:
            raise AssertionError("legacy OAuth start changed its output shape")
        if not isinstance(legacy_record, dict) or "setup_session_id" in legacy_record:
            raise AssertionError("legacy OAuth state unexpectedly gained a setup binding")
        legacy_exchange = exchange_flow(legacy_start, legacy_nonce, "legacy-setup-session-code")
        if "setupSessionId" in legacy_exchange or "setup_session_id" in legacy_exchange:
            raise AssertionError("legacy OAuth exchange changed its output shape")

        setup_session_id = "550e8400-e29b-41d4-a716-446655440000"
        setup_nonce = "s" * 43
        setup_start = start_flow(
            label="Setup-bound OAuth state",
            browser_nonce=setup_nonce,
            setup_session_id=setup_session_id,
        )
        if setup_start.get("setupSessionId") != setup_session_id:
            raise AssertionError(f"OAuth start lost setup session: {setup_start}")
        if "setup_session_id" in setup_start:
            raise AssertionError("OAuth start exposed the internal setup-session field name")
        if setup_session_id in str(setup_start["authorizationUrl"]):
            raise AssertionError("OAuth authorization URL leaked its setup-session binding")
        setup_record = state_records().get(str(setup_start["state"]))
        if not isinstance(setup_record, dict) or setup_record.get("setup_session_id") != setup_session_id:
            raise AssertionError(f"OAuth state lost setup session: {setup_record}")
        setup_keys = {key for key in setup_record if "setup" in str(key).lower()}
        if setup_keys != {"setup_session_id"}:
            raise AssertionError(f"OAuth state persisted unexpected setup material: {setup_keys}")
        setup_exchange = exchange_flow(setup_start, setup_nonce, "setup-session-code")
        if setup_exchange.get("setupSessionId") != setup_session_id:
            raise AssertionError(f"OAuth exchange lost setup session: {setup_exchange}")
        if "setup_session_id" in setup_exchange:
            raise AssertionError("OAuth exchange exposed the internal setup-session field name")
        if setup_session_id in str(setup_exchange.get("secret")) or setup_session_id in json.dumps(
            setup_exchange.get("metadata", {}), sort_keys=True
        ):
            raise AssertionError("OAuth setup-session binding leaked into credential material")

        denied_setup_id = "c56a4180-65aa-42ec-a945-5fd21dec0538"
        denied_nonce = "d" * 43
        denied_start = start_flow(
            label="Denied setup-bound OAuth state",
            browser_nonce=denied_nonce,
            setup_session_id=denied_setup_id,
        )
        denied_record = oauth.consume_state(
            provider_id="google",
            state=str(denied_start["state"]),
            browser_nonce=denied_nonce,
        )
        if denied_record.get("setup_session_id") != denied_setup_id:
            raise AssertionError("OAuth denial consume path lost its setup-session binding")
        try:
            oauth.consume_state(
                provider_id="google",
                state=str(denied_start["state"]),
                browser_nonce=denied_nonce,
            )
        except oauth.OAuthError as exc:
            if "unknown or expired" not in str(exc):
                raise AssertionError(f"OAuth denial replay failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("OAuth denial consume path accepted a state replay")

        tampered_nonce = "t" * 43
        tampered_start = start_flow(
            label="Tampered setup-bound OAuth state",
            browser_nonce=tampered_nonce,
            setup_session_id=setup_session_id,
        )
        with oauth._oauth_state_lock():
            payload = oauth._read_states()
            payload["states"][str(tampered_start["state"])]["setup_session_id"] = setup_session_id.upper()
            oauth._write_states(payload)
        calls_before_tamper = token_exchange_calls
        try:
            oauth.exchange_authorization_code(
                provider_id="google",
                code="tampered-setup-session-code",
                state=str(tampered_start["state"]),
                browser_nonce=tampered_nonce,
            )
        except oauth.OAuthError as exc:
            if "setup session binding is malformed" not in str(exc):
                raise AssertionError(f"tampered OAuth state failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("tampered OAuth setup-session binding was accepted")
        if token_exchange_calls != calls_before_tamper:
            raise AssertionError("tampered OAuth state reached the provider token exchange")
        if str(tampered_start["state"]) in state_records():
            raise AssertionError("tampered OAuth setup-session state remained replayable")
        try:
            oauth.consume_state(
                provider_id="google",
                state=str(tampered_start["state"]),
                browser_nonce=tampered_nonce,
            )
        except oauth.OAuthError as exc:
            if "unknown or expired" not in str(exc):
                raise AssertionError(f"tampered OAuth state replay failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("tampered OAuth setup-session state replay was accepted")

        concurrent_setup_ids = [str(uuid.UUID(int=index + 1_000)) for index in range(12)]

        def create_concurrent_setup_flow(index: int):
            browser_nonce = f"{index + 500:043d}"
            started = start_flow(
                label=f"Concurrent setup OAuth {index}",
                browser_nonce=browser_nonce,
                setup_session_id=concurrent_setup_ids[index],
            )
            return started, browser_nonce, concurrent_setup_ids[index]

        with ThreadPoolExecutor(max_workers=6) as executor:
            concurrent_flows = list(executor.map(create_concurrent_setup_flow, range(12)))
        persisted = state_records()
        for started, _browser_nonce, expected_setup_id in concurrent_flows:
            record = persisted.get(str(started["state"]))
            if not isinstance(record, dict) or record.get("setup_session_id") != expected_setup_id:
                raise AssertionError("concurrent OAuth starts crossed setup-session bindings")
        for index, (started, browser_nonce, expected_setup_id) in reversed(
            list(enumerate(concurrent_flows))
        ):
            exchanged = exchange_flow(started, browser_nonce, f"out-of-order-code-{index}")
            if exchanged.get("setupSessionId") != expected_setup_id:
                raise AssertionError("out-of-order OAuth exchange crossed setup-session bindings")
        if any(str(started["state"]) in state_records() for started, _, _ in concurrent_flows):
            raise AssertionError("out-of-order OAuth exchanges left consumed states replayable")
    finally:
        oauth._post_token_request = original_post_token_request
        oauth._fetch_provider_identity = original_fetch_provider_identity


def run_oauth_setup_callback_persistence_failure_tests(
    app_module, oauth, db, data_dir: Path
) -> None:
    state_path = data_dir / "oauth-states.json"
    actor_id = "user:setup-callback-persistence"
    scope = "https://www.googleapis.com/auth/gmail.readonly"
    original_post_token_request = oauth._post_token_request
    original_fetch_provider_identity = oauth._fetch_provider_identity
    original_revoke_oauth_token = app_module.revoke_oauth_token
    original_reserve_revocation_work = db.reserve_oauth_revocation_work
    original_create_pending = db.create_pending_oauth_credential
    original_create_credential = db.create_credential
    original_two_person_required = app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED
    original_two_person_actions = app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS
    revocation_work_ids: list[str] = []
    revocation_attempts: list[tuple[str, dict[str, object]]] = []

    def fake_post_token_request(provider, body, headers):
        code = str(body.get("code") or "setup-callback")
        return {
            "access_token": f"{code}-access-token",
            "refresh_token": f"{code}-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    def capture_revocation_work(**kwargs):
        work_id = original_reserve_revocation_work(**kwargs)
        revocation_work_ids.append(work_id)
        return work_id

    def fail_provider_revocation(
        *, provider_id: str, token_secret: dict[str, object]
    ):
        revocation_attempts.append((provider_id, dict(token_secret)))
        raise oauth.OAuthError("injected provider revocation outage")

    def callback_request(state: str, browser_nonce: str):
        return app_module.Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/api/oauth/callback/google",
                "headers": [
                    (
                        b"cookie",
                        f"{oauth.browser_cookie_name(state)}={browser_nonce}".encode(
                            "ascii"
                        ),
                    )
                ],
            }
        )

    def start_bound_flow(case: str):
        browser_nonce = case[0] * 43
        session = db.create_setup_session(
            owner_id=actor_id,
            current_assignee_id=actor_id,
            template_id=f"template:{case}",
            principal_id=f"agent:{case}",
            route_id=f"route:{case}",
            route_policy_digest="sha256:"
            + hashlib.sha256(case.encode("ascii")).hexdigest(),
        )
        started = oauth.create_authorization_url(
            provider_id="google",
            credential_name=f"Setup callback {case}",
            scopes=[scope],
            metadata={"test": case},
            actor_id=actor_id,
            browser_nonce=browser_nonce,
            setup_session_id=session["id"],
        )
        state_digest = (
            "sha256:"
            + hashlib.sha256(str(started["state"]).encode("ascii")).hexdigest()
        )
        session = db.transition_setup_session(
            session["id"],
            expected_revision=session["revision"],
            transition="bind_oauth_flow",
            actor_id=actor_id,
            updates={
                "oauth_provider": "google",
                "oauth_state_digest": state_digest,
            },
        )
        return session, started, browser_nonce

    def assert_cookie_deleted(response, state: str, case: str) -> None:
        cookies = SimpleCookie()
        cookies.load(response.headers.get("set-cookie", ""))
        morsel = cookies.get(oauth.browser_cookie_name(state))
        if morsel is None or morsel["max-age"] != "0":
            raise AssertionError(
                f"{case} persistence failure did not delete its OAuth cookie: "
                f"{response.headers}"
            )
        if (
            not morsel["secure"]
            or not morsel["httponly"]
            or morsel["samesite"].lower() != "lax"
        ):
            raise AssertionError(
                f"{case} persistence failure weakened OAuth cookie attributes: {morsel}"
            )

    oauth._post_token_request = fake_post_token_request
    oauth._fetch_provider_identity = lambda provider, token: {
        "provider_subject": f"subject:{token}",
        "provider_account": f"{token}@example.test",
        "provider_identity_verified": True,
        "provider_email_verified": True,
    }
    app_module.revoke_oauth_token = fail_provider_revocation
    db.reserve_oauth_revocation_work = capture_revocation_work
    try:
        cases = (
            (
                "pending-persistence",
                True,
                "create_pending_oauth_credential",
                db.ManagedOAuthCredentialError,
                503,
            ),
            (
                "immediate-persistence",
                False,
                "create_credential",
                db.MetadataStoreError,
                409,
            ),
        )
        for case, two_person, persistence_name, error_type, expected_status in cases:
            session, started, browser_nonce = start_bound_flow(case)
            state = str(started["state"])
            credential_ids_before = {
                item["id"] for item in db.list_credentials()
            }
            pending_ids_before = {
                item["id"] for item in db.list_pending_oauth_credentials()
            }
            work_count_before = len(revocation_work_ids)
            revocation_count_before = len(revocation_attempts)
            original_persistence = getattr(db, persistence_name)

            def fail_persistence(*args, **kwargs):
                raise error_type(f"injected {case} failure")

            app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED = two_person
            app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = (
                ("credential.oauth.activate",) if two_person else ()
            )
            setattr(db, persistence_name, fail_persistence)
            try:
                response = app_module.oauth_callback(
                    "google",
                    callback_request(state, browser_nonce),
                    code=f"{case}-code",
                    state=state,
                )
            finally:
                setattr(db, persistence_name, original_persistence)

            if response.status_code != expected_status:
                raise AssertionError(
                    f"{case} persistence failure returned {response.status_code}: "
                    f"{response.body!r}"
                )
            if (
                response.headers.get("cache-control") != "no-store"
                or "location" in response.headers
                or b"window.location" in response.body
            ):
                raise AssertionError(
                    f"{case} persistence failure returned redirectable OAuth content"
                )
            assert_cookie_deleted(response, state, case)

            persisted_states = json.loads(state_path.read_text(encoding="utf-8"))[
                "states"
            ]
            if state in persisted_states:
                raise AssertionError(
                    f"{case} persistence failure left OAuth state replayable"
                )
            failed_session = db.get_setup_session(
                session["id"], include_events=True
            )
            if not failed_session or not (
                failed_session["status"] == "failed"
                and failed_session["phase"] == "failed"
                and failed_session["terminal_at"] is not None
            ):
                raise AssertionError(
                    f"{case} persistence failure did not terminate Setup: "
                    f"{failed_session}"
                )
            failure_event = failed_session["events"][-1]
            if not (
                failure_event["transition"] == "fail"
                and failure_event["event"].get("details", {}).get("reason")
                == "oauth_credential_persistence_failed"
            ):
                raise AssertionError(
                    f"{case} persistence failure recorded the wrong Setup event: "
                    f"{failure_event}"
                )
            if {item["id"] for item in db.list_credentials()} != credential_ids_before:
                raise AssertionError(
                    f"{case} persistence failure created an active credential"
                )
            if {
                item["id"] for item in db.list_pending_oauth_credentials()
            } != pending_ids_before:
                raise AssertionError(
                    f"{case} persistence failure created a pending credential"
                )

            if len(revocation_work_ids) != work_count_before + 1:
                raise AssertionError(
                    f"{case} persistence failure did not retain one exchanged grant"
                )
            if len(revocation_attempts) != revocation_count_before + 1:
                raise AssertionError(
                    f"{case} persistence failure did not invoke provider revocation"
                )
            provider, revoked_secret = revocation_attempts[-1]
            if provider != "google" or revoked_secret.get("access_token") != (
                f"{case}-code-access-token"
            ):
                raise AssertionError(
                    f"{case} persistence failure revoked the wrong material: "
                    f"{revocation_attempts[-1]}"
                )
            work_id = revocation_work_ids[-1]
            revocation_status = db.get_oauth_revocation_work_status(work_id)
            if not revocation_status or not (
                revocation_status["status"] == "pending"
                and revocation_status["attempts"] == 1
                and "injected provider revocation outage"
                in str(revocation_status["last_error"])
            ):
                raise AssertionError(
                    f"{case} failed revocation was not durable: {revocation_status}"
                )

            replay = app_module.oauth_callback(
                "google",
                callback_request(state, browser_nonce),
                code=f"{case}-replay-code",
                state=state,
            )
            if replay.status_code != 400 or b"unknown or expired" not in replay.body:
                raise AssertionError(
                    f"{case} persistence failure accepted an OAuth replay: "
                    f"{replay.body!r}"
                )
            if "location" in replay.headers or b"window.location" in replay.body:
                raise AssertionError(
                    f"{case} OAuth replay returned redirectable content"
                )
            assert_cookie_deleted(replay, state, case + " replay")
            if not db.complete_oauth_revocation_work(work_id):
                raise AssertionError(
                    f"{case} test could not release retained revocation work"
                )
    finally:
        oauth._post_token_request = original_post_token_request
        oauth._fetch_provider_identity = original_fetch_provider_identity
        app_module.revoke_oauth_token = original_revoke_oauth_token
        db.reserve_oauth_revocation_work = original_reserve_revocation_work
        db.create_pending_oauth_credential = original_create_pending
        db.create_credential = original_create_credential
        app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED = original_two_person_required
        app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = original_two_person_actions
        for work_id in revocation_work_ids:
            if db.get_oauth_revocation_work_status(work_id) is not None:
                db.complete_oauth_revocation_work(work_id)


def main(*, setup_session_only: bool = False) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        if not setup_session_only:
            run_config_secret_file_tests(Path(tmp))
        if not setup_session_only and compose_manifests_available():
            verify_compose_oauth_contract()
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        for name in (
            "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
            "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
            "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        ):
            os.environ.pop(name, None)
        os.environ["SERVERWARE_PUBLIC_URL"] = "https://serverware.test"
        os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_ID"] = "google-client"
        os.environ["SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET"] = "google-secret"
        os.environ["SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI"] = "https://serverware.test/api/oauth/callback/google"
        os.environ["SERVERWARE_X_OAUTH_CLIENT_ID"] = "x-client"
        os.environ["SERVERWARE_X_OAUTH_CLIENT_SECRET"] = "x-secret"
        os.environ["SERVERWARE_X_OAUTH_REDIRECT_URI"] = "https://serverware.test/api/oauth/callback/x"

        from serverware import db, oauth

        db.init_db()
        run_oauth_setup_session_state_tests(oauth, db, Path(tmp))
        from serverware import runtime
        from serverware import app as app_module
        from serverware.auth import AdminIdentity
        from serverware.policy_bundle import (
            PolicyBundleError,
            compile_policy_bundle,
            demo_policy_bundle,
        )

        if "mitmproxy" not in sys.modules:
            mitmproxy_module = types.ModuleType("mitmproxy")
            http_module = types.ModuleType("mitmproxy.http")
            mitmproxy_module.http = http_module
            sys.modules["mitmproxy"] = mitmproxy_module
            sys.modules["mitmproxy.http"] = http_module
        from serverware.policy_engine import _inject_credential

        identity = AdminIdentity("user:operator", frozenset({"admin", "credential_owner", "policy_author"}), "test")

        def oauth_request(state: str, browser_nonce: str):
            return app_module.Request(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/api/oauth/callback/test",
                    "headers": [
                        (
                            b"cookie",
                            f"{oauth.browser_cookie_name(state)}={browser_nonce}".encode("ascii"),
                        )
                    ],
                }
            )

        def start_oauth(payload: app_module.OAuthStartRequest) -> tuple[dict[str, object], str]:
            response = app_module.Response()
            started = app_module.oauth_start(payload, response=response, identity=identity)
            cookies = SimpleCookie()
            cookies.load(response.headers.get("set-cookie", ""))
            morsel = cookies.get(oauth.browser_cookie_name(str(started["state"])))
            if morsel is None:
                raise AssertionError("OAuth start did not issue the browser-binding cookie")
            if not morsel["secure"] or not morsel["httponly"] or morsel["samesite"].lower() != "lax":
                raise AssertionError(f"OAuth browser-binding cookie attributes are unsafe: {morsel}")
            return started, morsel.value

        run_oauth_setup_callback_persistence_failure_tests(
            app_module, oauth, db, Path(tmp)
        )
        if setup_session_only:
            print(json.dumps({"oauth_setup_session_state": "pass", "ok": True}, sort_keys=True))
            return

        providers = app_module.oauth_providers(identity)["providers"]
        google = next(item for item in providers if item["id"] == "google")
        if not google["configured"] or google["recommendedInjection"].get("field") != "access_token":
            raise AssertionError(f"google provider status is not usable: {google}")
        x_provider = next(item for item in providers if item["id"] == "x")
        if not x_provider["configured"]:
            raise AssertionError(f"x provider status is not usable: {x_provider}")
        if replace(oauth.provider_for("google"), client_secret="").configured:
            raise AssertionError("OAuth provider with an incomplete client secret was marked configured")

        original_revocation_request_bytes = oauth.request_bytes
        revocation_requests: list[tuple[object, dict[str, object]]] = []

        def fake_revocation_request(request, **kwargs):
            revocation_requests.append((request, dict(kwargs)))
            return SimpleNamespace(status=200, body=b"", headers={})

        oauth.request_bytes = fake_revocation_request
        try:
            google_revocation = oauth.revoke_oauth_token(
                provider_id="google",
                token_secret={"access_token": "google-access", "refresh_token": "google-refresh"},
            )
            x_revocation = oauth.revoke_oauth_token(
                provider_id="x",
                token_secret={"access_token": "x-access", "refresh_token": "x-refresh"},
            )
        finally:
            oauth.request_bytes = original_revocation_request_bytes
        if not google_revocation.get("revoked") or not x_revocation.get("revoked"):
            raise AssertionError("OAuth provider revocation did not report success")
        if len(revocation_requests) != 3:
            raise AssertionError(f"OAuth provider revocation request count is wrong: {revocation_requests}")
        google_request, x_access_request, x_refresh_request = [item[0] for item in revocation_requests]
        for _, request_options in revocation_requests:
            if request_options != {
                "timeout": 20,
                "max_bytes": 64 * 1024,
                "require_https": True,
            }:
                raise AssertionError(f"OAuth revocation request was not bounded: {request_options}")
        google_body = urllib.parse.parse_qs(bytes(google_request.data).decode("utf-8"))
        x_access_body = urllib.parse.parse_qs(bytes(x_access_request.data).decode("utf-8"))
        x_refresh_body = urllib.parse.parse_qs(bytes(x_refresh_request.data).decode("utf-8"))
        if (
            google_request.full_url != "https://oauth2.googleapis.com/revoke"
            or google_body.get("token") != ["google-refresh"]
            or google_body.get("token_type_hint") != ["refresh_token"]
        ):
            raise AssertionError("Google revocation did not use the bounded refresh-token endpoint")
        if google_request.headers.get("Authorization"):
            raise AssertionError("Google revocation unexpectedly disclosed client credentials in a header")
        if (
            x_access_request.full_url != "https://api.twitter.com/2/oauth2/revoke"
            or x_access_body.get("token") != ["x-access"]
            or x_access_body.get("token_type_hint") != ["access_token"]
            or x_refresh_request.full_url != "https://api.twitter.com/2/oauth2/revoke"
            or x_refresh_body.get("token") != ["x-refresh"]
            or x_refresh_body.get("token_type_hint") != ["refresh_token"]
        ):
            raise AssertionError("X revocation did not submit both distinct token-local grants")
        for x_request in (x_access_request, x_refresh_request):
            if not str(x_request.headers.get("Authorization") or "").startswith("Basic "):
                raise AssertionError("X confidential-client revocation did not authenticate the OAuth app")
        if x_revocation.get("token_type_hints") != ["access_token", "refresh_token"]:
            raise AssertionError(f"X revocation did not report both completed requests: {x_revocation}")

        partial_x_requests: list[object] = []

        def fail_second_x_revocation(request, **kwargs):
            partial_x_requests.append(request)
            status = 503 if len(partial_x_requests) == 2 else 200
            return SimpleNamespace(status=status, body=b"", headers={})

        oauth.request_bytes = fail_second_x_revocation
        try:
            oauth.revoke_oauth_token(
                provider_id="x",
                token_secret={"access_token": "x-partial-access", "refresh_token": "x-partial-refresh"},
            )
        except oauth.OAuthError as exc:
            if "HTTP 503" not in str(exc):
                raise AssertionError(f"partial X revocation failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("X revocation reported success before both token requests succeeded")
        finally:
            oauth.request_bytes = original_revocation_request_bytes
        partial_x_bodies = [
            urllib.parse.parse_qs(bytes(request.data).decode("utf-8"))
            for request in partial_x_requests
        ]
        if partial_x_bodies != [
            {"token": ["x-partial-access"], "token_type_hint": ["access_token"]},
            {"token": ["x-partial-refresh"], "token_type_hint": ["refresh_token"]},
        ]:
            raise AssertionError(f"partial X revocation sent the wrong requests: {partial_x_bodies}")

        if app_module._canonical_oauth_granted_scopes(["scope.z", "scope.a"]) != ("scope.a", "scope.z"):
            raise AssertionError("OAuth granted scopes were not canonicalized")
        if oauth.resolve_requested_scopes("google", None) != (
            "email",
            "https://www.googleapis.com/auth/gmail.readonly",
            "openid",
        ):
            raise AssertionError("Google OAuth defaults were not resolved before approval")
        if oauth.resolve_requested_scopes("x", []) != (
            "offline.access",
            "tweet.read",
            "users.read",
        ):
            raise AssertionError("X OAuth defaults were not resolved before approval")
        for malformed_requested_scopes in ([" scope.a"], ["scope.a scope.b"], ["scope.a", "scope.a"]):
            try:
                oauth.resolve_requested_scopes("google", malformed_requested_scopes)
            except oauth.OAuthError:
                pass
            else:
                raise AssertionError(
                    f"malformed requested OAuth scopes were accepted: {malformed_requested_scopes!r}"
                )
        for malformed_scopes in (None, [], "scope.a", [""], [" scope.a"], ["scope.a scope.b"], ["scope.a", "scope.a"]):
            try:
                app_module._canonical_oauth_granted_scopes(malformed_scopes)
            except oauth.OAuthError:
                pass
            else:
                raise AssertionError(f"malformed OAuth granted scopes were accepted: {malformed_scopes!r}")

        original_request_bytes = oauth.request_bytes

        def fake_identity_http(request, **kwargs):
            authorization = request.headers.get("Authorization")
            if authorization != "Bearer identity-access-token":
                raise AssertionError(f"identity lookup did not use the OAuth access token: {authorization}")
            if "openidconnect.googleapis.com" in request.full_url:
                body = b'{"sub":"google-subject-123","email":"andrew@example.test","email_verified":true}'
            elif "api.x.com/2/users/me" in request.full_url:
                body = b'{"data":{"id":"x-user-456","username":"andrew","verified":false}}'
            else:
                raise AssertionError(f"identity lookup used an unexpected URL: {request.full_url}")
            return SimpleNamespace(body=body)

        oauth.request_bytes = fake_identity_http
        verified_google = oauth._fetch_provider_identity(oauth.provider_for("google"), "identity-access-token")
        verified_x = oauth._fetch_provider_identity(oauth.provider_for("x"), "identity-access-token")
        oauth.request_bytes = original_request_bytes
        if verified_google.get("provider_account") != "andrew@example.test":
            raise AssertionError(f"Google identity was not normalized: {verified_google}")
        if verified_x.get("provider_account") != "@andrew":
            raise AssertionError(f"X identity was not normalized: {verified_x}")

        def create_concurrent_state(index: int) -> str:
            return oauth.create_authorization_url(
                provider_id="google",
                credential_name=f"Concurrent OAuth {index}",
                scopes=None,
                metadata={"index": index},
                actor_id="user:operator",
                browser_nonce=f"{index:043d}",
            )["state"]

        with ThreadPoolExecutor(max_workers=8) as executor:
            concurrent_states = set(executor.map(create_concurrent_state, range(24)))
        persisted_states = json.loads((Path(tmp) / "oauth-states.json").read_text())["states"]
        if len(concurrent_states) != 24 or not concurrent_states.issubset(persisted_states):
            raise AssertionError("concurrent OAuth starts lost state records")

        try:
            oauth.consume_state(provider_id="google", state="not-valid-state", browser_nonce="b" * 43)
        except oauth.OAuthError as exc:
            if "malformed" not in str(exc):
                raise AssertionError(f"malformed state failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("malformed OAuth state was accepted")

        try:
            app_module.oauth_start(
                app_module.OAuthStartRequest(
                    provider="google",
                    credentialName="Gmail OAuth - Test",
                    metadata={"blob": "x" * 5000},
                ),
                response=app_module.Response(),
                identity=identity,
            )
        except app_module.HTTPException as exc:
            if "metadata is too large" not in str(exc.detail):
                raise AssertionError(f"oversized metadata failed with wrong error: {exc.detail}") from exc
        else:
            raise AssertionError("oversized OAuth metadata was accepted")

        try:
            app_module.oauth_start(
                app_module.OAuthStartRequest(
                    provider="google",
                    credentialName="x" * 300,
                ),
                response=app_module.Response(),
                identity=identity,
            )
        except app_module.HTTPException as exc:
            if "credential name is too large" not in str(exc.detail):
                raise AssertionError(f"oversized credential name failed with wrong error: {exc.detail}") from exc
        else:
            raise AssertionError("oversized OAuth credential name was accepted")

        start, browser_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="google",
                credentialName="Gmail OAuth - Test",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                metadata={"account": "andrew@example.test", "provider_subject": "caller-controlled"},
            )
        )
        parsed = urllib.parse.urlsplit(start["authorizationUrl"])
        query = dict(urllib.parse.parse_qsl(parsed.query))
        if query.get("code_challenge_method") != "S256" or "code_verifier" in start["authorizationUrl"]:
            raise AssertionError(f"OAuth URL did not use PKCE safely: {start}")
        if query.get("state") != start["state"]:
            raise AssertionError("OAuth URL state does not match returned state")

        parallel_start, _parallel_browser_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="x",
                credentialName="Parallel X OAuth - Test",
            )
        )
        if oauth.browser_cookie_name(str(parallel_start["state"])) == oauth.browser_cookie_name(
            str(start["state"])
        ):
            raise AssertionError("parallel OAuth flows reused one browser-binding cookie")

        state_payload = json.loads((Path(tmp) / "oauth-states.json").read_text())
        state_record = state_payload["states"][start["state"]]
        if browser_nonce in json.dumps(state_record, sort_keys=True):
            raise AssertionError("raw OAuth browser binding was persisted")
        if not str(state_record.get("browser_nonce_sha256", "")).startswith("sha256:"):
            raise AssertionError("OAuth state did not persist a browser-binding hash")
        if state_record.get("code_verifier") in start["authorizationUrl"]:
            raise AssertionError("PKCE verifier leaked into the authorization URL")

        try:
            oauth.exchange_authorization_code(
                provider_id="google",
                code="x" * (oauth.MAX_OAUTH_CODE_BYTES + 1),
                state=start["state"],
                browser_nonce=browser_nonce,
            )
        except oauth.OAuthError as exc:
            if "too large" not in str(exc):
                raise AssertionError(f"oversized OAuth code failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("oversized OAuth authorization code was accepted")
        if start["state"] not in json.loads((Path(tmp) / "oauth-states.json").read_text())["states"]:
            raise AssertionError("invalid OAuth code consumed a valid one-use state")

        def fake_post_token_request(provider, body, headers):
            if body.get("code_verifier") != state_record["code_verifier"]:
                raise AssertionError(f"token request did not use stored verifier: {body}")
            if headers.get("Authorization"):
                raise AssertionError("Google token request should use client_secret_post, not basic auth")
            return {
                "access_token": "access-token-value",
                "refresh_token": "refresh-token-value",
                "token_type": "Bearer",
                "expires_in": 3600,
            }

        oauth._post_token_request = fake_post_token_request
        oauth._fetch_provider_identity = lambda provider, token: {
            "provider_subject": "google-subject-123",
            "provider_account": "andrew@example.test",
            "provider_identity_verified": True,
            "provider_email_verified": True,
        }
        wrong_browser = app_module.oauth_callback(
            "google",
            oauth_request(str(start["state"]), "z" * 43),
            code="auth-code",
            state=start["state"],
        )
        if wrong_browser.status_code != 400 or b"browser binding mismatch" not in wrong_browser.body:
            raise AssertionError(f"cross-browser OAuth callback did not fail closed: {wrong_browser.body!r}")
        if start["state"] not in json.loads((Path(tmp) / "oauth-states.json").read_text())["states"]:
            raise AssertionError("cross-browser callback consumed the legitimate OAuth state")
        response = app_module.oauth_callback(
            "google",
            oauth_request(str(start["state"]), browser_nonce),
            code="auth-code",
            state=start["state"],
        )
        if response.status_code != 200:
            raise AssertionError(f"OAuth callback failed: {response.status_code} {response.body!r}")
        if b"access-token-value" in response.body or b"refresh-token-value" in response.body:
            raise AssertionError("OAuth callback response leaked token material")

        credentials = [item for item in db.list_credentials() if item["name"] == "Gmail OAuth - Test"]
        if len(credentials) != 1:
            raise AssertionError(f"expected one OAuth credential, found {credentials}")
        listed = credentials[0]
        if "secret" in listed or listed["kind"] != "oauth2":
            raise AssertionError(f"credential listing leaked or mislabeled OAuth secret: {listed}")
        if listed["metadata"].get("provider") != "google.oauth2" or listed["metadata"].get("injection_field") != "access_token":
            raise AssertionError(f"OAuth metadata missing provider/injection field: {listed}")
        if listed["metadata"].get("scopes") != ["https://www.googleapis.com/auth/gmail.readonly"]:
            raise AssertionError(f"OAuth metadata did not preserve provider-granted scopes: {listed}")
        if (
            listed["metadata"].get("provider_account") != "andrew@example.test"
            or listed["metadata"].get("provider_subject") != "google-subject-123"
            or listed["metadata"].get("provider_identity_verified") is not True
        ):
            raise AssertionError(f"OAuth metadata is not bound to a verified provider identity: {listed}")

        stored = db.get_credential(listed["id"], include_secret=True)
        secret = json.loads(stored["secret"])
        if (
            secret["access_token"] != "access-token-value"
            or secret["refresh_token"] != "refresh-token-value"
            or secret.get("token_type") != "Bearer"
            or secret.get("scope") != "https://www.googleapis.com/auth/gmail.readonly"
        ):
            raise AssertionError("encrypted OAuth credential did not preserve token response")

        exhausted_start, exhausted_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="google",
                credentialName="Revocation capacity exhaustion",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            )
        )
        original_revocation_capacity = db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT
        token_exchange_calls = 0

        def provider_exchange_must_not_run(provider, body, headers):
            nonlocal token_exchange_calls
            token_exchange_calls += 1
            return fake_post_token_request(provider, body, headers)

        db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT = 0
        oauth._post_token_request = provider_exchange_must_not_run
        try:
            oauth.exchange_authorization_code(
                provider_id="google",
                code="must-not-exchange",
                state=exhausted_start["state"],
                browser_nonce=exhausted_nonce,
            )
        except oauth.OAuthError as exc:
            if "revocation capacity" not in str(exc):
                raise AssertionError(f"revocation capacity failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("OAuth token exchange ran without durable revocation capacity")
        finally:
            db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT = original_revocation_capacity
            oauth._post_token_request = fake_post_token_request
        if token_exchange_calls != 0:
            raise AssertionError("OAuth provider received a token exchange after revocation capacity closed")

        retention_failure_start, retention_failure_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="google",
                credentialName="Retention failure immediate revoke",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            )
        )
        retention_access_token = "retention-failure-access-token"
        retention_refresh_token = "retention-failure-refresh-token"
        oauth._post_token_request = lambda provider, body, headers: {
            "access_token": retention_access_token,
            "refresh_token": retention_refresh_token,
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
            "expires_in": 3600,
        }
        original_attach_revocation_material = db.attach_oauth_revocation_material
        original_immediate_revoke = oauth.revoke_oauth_token
        immediately_revoked: list[dict[str, object]] = []

        def fail_revocation_attachment(work_id: str, *, secret: str) -> None:
            raise db.MetadataStoreError("simulated revocation material persistence failure")

        def immediate_provider_revoke(*, provider_id: str, token_secret: dict[str, object]):
            immediately_revoked.append(dict(token_secret))
            return {"provider": provider_id, "revoked": True}

        db.attach_oauth_revocation_material = fail_revocation_attachment
        oauth.revoke_oauth_token = immediate_provider_revoke
        try:
            oauth.exchange_authorization_code(
                provider_id="google",
                code="retention-failure-code",
                state=retention_failure_start["state"],
                browser_nonce=retention_failure_nonce,
            )
        except oauth.OAuthError as exc:
            if "revoked because durable retention failed" not in str(exc):
                raise AssertionError(f"retention failure did not fail closed: {exc}") from exc
        else:
            raise AssertionError("OAuth retention failure returned issued provider material")
        finally:
            db.attach_oauth_revocation_material = original_attach_revocation_material
            oauth.revoke_oauth_token = original_immediate_revoke
            oauth._post_token_request = fake_post_token_request
        if immediately_revoked != [
            {
                "access_token": retention_access_token,
                "refresh_token": retention_refresh_token,
                "token_type": "Bearer",
            }
        ]:
            raise AssertionError(f"retention failure revoked the wrong material: {immediately_revoked}")

        failed_exchange_start, failed_exchange_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="google",
                credentialName="Post-exchange failure must revoke",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            )
        )
        failed_access_token = "issued-access-token-must-be-revoked"
        failed_refresh_token = "issued-refresh-token-must-be-revoked"
        successful_identity_lookup = oauth._fetch_provider_identity
        oauth._post_token_request = lambda provider, body, headers: {
            "access_token": failed_access_token,
            "refresh_token": failed_refresh_token,
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
            "expires_in": 3600,
        }

        def failed_identity_lookup(provider, token):
            raise oauth.OAuthError("provider identity response was adversarially malformed")

        oauth._fetch_provider_identity = failed_identity_lookup
        try:
            oauth.exchange_authorization_code(
                provider_id="google",
                code="issued-but-invalid-code",
                state=failed_exchange_start["state"],
                browser_nonce=failed_exchange_nonce,
            )
        except oauth.OAuthError as exc:
            if "identity response" not in str(exc):
                raise AssertionError(f"post-exchange validation failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("post-exchange identity failure returned untracked provider tokens")
        finally:
            oauth._fetch_provider_identity = successful_identity_lookup
            oauth._post_token_request = fake_post_token_request

        with db.connect() as conn:
            retained_rows = conn.execute(
                "SELECT * FROM oauth_revocation_work WHERE source = ?",
                ("authorization_code_exchange",),
            ).fetchall()
        if len(retained_rows) != 1 or retained_rows[0]["status"] != "pending":
            raise AssertionError(f"post-exchange failure did not retain retryable revocation work: {retained_rows}")
        retained_serialized = json.dumps(dict(retained_rows[0]), sort_keys=True)
        if failed_access_token in retained_serialized or failed_refresh_token in retained_serialized:
            raise AssertionError("OAuth revocation work persisted provider material without encryption")
        retained_work_id = str(retained_rows[0]["id"])
        original_reconcile_revoke = app_module.revoke_oauth_token
        reconcile_attempts: list[dict[str, object]] = []

        def retryable_revoke_failure(*, provider_id: str, token_secret: dict[str, object]):
            reconcile_attempts.append(dict(token_secret))
            raise oauth.OAuthError("provider revocation temporarily unavailable")

        app_module.revoke_oauth_token = retryable_revoke_failure
        try:
            first_reconcile = app_module._reconcile_oauth_revocations(limit=1)
        finally:
            app_module.revoke_oauth_token = original_reconcile_revoke
        if first_reconcile != {"claimed": 1, "revoked": 0, "failed": 1}:
            raise AssertionError(f"failed OAuth revocation was not bounded and retryable: {first_reconcile}")
        if (
            len(reconcile_attempts) != 1
            or reconcile_attempts[0].get("access_token") != failed_access_token
            or reconcile_attempts[0].get("refresh_token") != failed_refresh_token
        ):
            raise AssertionError("OAuth revocation retry lost the exact issued provider material")
        with db.connect() as conn:
            retained_after_failure = conn.execute(
                "SELECT * FROM oauth_revocation_work WHERE id = ?",
                (retained_work_id,),
            ).fetchone()
            conn.execute(
                "UPDATE oauth_revocation_work SET next_attempt_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00+00:00", retained_work_id),
            )
        if retained_after_failure is None or int(retained_after_failure["attempts"] or 0) != 1:
            raise AssertionError("failed OAuth revocation work was not durably retained with retry state")
        app_module.revoke_oauth_token = lambda **kwargs: {
            "provider": kwargs["provider_id"],
            "revoked": True,
        }
        try:
            second_reconcile = app_module._reconcile_oauth_revocations(limit=1)
        finally:
            app_module.revoke_oauth_token = original_reconcile_revoke
        if second_reconcile != {"claimed": 1, "revoked": 1, "failed": 0}:
            raise AssertionError(f"OAuth revocation retry did not complete: {second_reconcile}")
        with db.connect() as conn:
            if conn.execute(
                "SELECT 1 FROM oauth_revocation_work WHERE id = ?",
                (retained_work_id,),
            ).fetchone() is not None:
                raise AssertionError("successfully reconciled OAuth revocation work remained queued")

        missing_claim = object()

        def assert_initial_token_response_rejected(
            *,
            case: str,
            claim: str,
            value: object = missing_claim,
            required_scope: bool = False,
        ) -> None:
            rejected_start, rejected_nonce = start_oauth(
                app_module.OAuthStartRequest(
                    provider="google",
                    credentialName=f"Rejected initial token response: {case}",
                    scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                )
            )
            access_token = f"rejected-initial-access-{case}"
            refresh_token = f"rejected-initial-refresh-{case}"
            token_response: dict[str, object] = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
                "expires_in": 3600,
            }
            if value is missing_claim:
                token_response.pop(claim)
            else:
                token_response[claim] = value

            original_providers = oauth._providers
            original_post_token_request = oauth._post_token_request
            if required_scope:
                provider = replace(
                    oauth.provider_for("google"),
                    token_response_scope_optional=False,
                )
                oauth._providers = lambda: {"google": provider}
            oauth._post_token_request = lambda provider, body, headers: token_response
            try:
                oauth.exchange_authorization_code(
                    provider_id="google",
                    code=f"rejected-code-{case}",
                    state=rejected_start["state"],
                    browser_nonce=rejected_nonce,
                )
            except oauth.OAuthError as exc:
                if claim.replace("_", " ") not in str(exc):
                    raise AssertionError(
                        f"{case} failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(f"{case} was accepted in an initial OAuth token response")
            finally:
                oauth._providers = original_providers
                oauth._post_token_request = original_post_token_request

            with db.connect() as conn:
                rejected_work = conn.execute(
                    "SELECT * FROM oauth_revocation_work WHERE source = ?",
                    ("authorization_code_exchange",),
                ).fetchall()
            if len(rejected_work) != 1 or rejected_work[0]["status"] != "pending":
                raise AssertionError(f"{case} did not retain issued token material: {rejected_work}")

            revoked: list[dict[str, object]] = []
            original_reconcile_revoke = app_module.revoke_oauth_token

            def revoke_rejected_initial(*, provider_id: str, token_secret: dict[str, object]):
                revoked.append(dict(token_secret))
                return {"provider": provider_id, "revoked": True}

            app_module.revoke_oauth_token = revoke_rejected_initial
            try:
                reconciled = app_module._reconcile_oauth_revocations(limit=1)
            finally:
                app_module.revoke_oauth_token = original_reconcile_revoke
            if reconciled != {"claimed": 1, "revoked": 1, "failed": 0}:
                raise AssertionError(f"{case} revocation work did not reconcile: {reconciled}")
            if (
                len(revoked) != 1
                or revoked[0].get("access_token") != access_token
                or revoked[0].get("refresh_token") != refresh_token
            ):
                raise AssertionError(f"{case} changed rejected-token revocation behavior: {revoked}")

        for rejected_case, rejected_claim, rejected_value in (
            ("missing-token-type", "token_type", missing_claim),
            ("empty-token-type", "token_type", ""),
            ("non-string-token-type", "token_type", []),
            ("empty-scope", "scope", ""),
            ("non-string-scope", "scope", []),
        ):
            assert_initial_token_response_rejected(
                case=rejected_case,
                claim=rejected_claim,
                value=rejected_value,
            )
        assert_initial_token_response_rejected(
            case="contract-required-missing-scope",
            claim="scope",
            required_scope=True,
        )

        renamed = db.update_credential(stored["id"], {"name": "Gmail OAuth - Renamed"})
        if renamed is None or renamed["name"] != "Gmail OAuth - Renamed":
            raise AssertionError("managed OAuth credential rename failed")
        for forbidden_update in (
            {"kind": "bearer"},
            {"secret": stored["secret"]},
            {"metadata": {**stored["metadata"], "provider_subject": "different-account"}},
        ):
            try:
                db.update_credential(stored["id"], forbidden_update)
            except db.ManagedOAuthCredentialError:
                pass
            else:
                raise AssertionError(f"managed OAuth identity was mutable through the generic update path: {forbidden_update}")
        stored_after_forbidden_updates = db.get_credential(stored["id"], include_secret=True)
        if (
            stored_after_forbidden_updates is None
            or stored_after_forbidden_updates["credential_version"] != stored["credential_version"]
            or stored_after_forbidden_updates["metadata"].get("provider_subject") != "google-subject-123"
        ):
            raise AssertionError("rejected managed OAuth update changed the stored credential")
        try:
            db.update_credential_secret_if_version(
                stored["id"],
                expected_version=int(stored["credential_version"]),
                secret=stored["secret"],
                metadata={**stored["metadata"], "provider_subject": "different-account"},
            )
        except db.ManagedOAuthCredentialError:
            pass
        else:
            raise AssertionError("OAuth refresh path changed the verified provider account identity")
        gmail_scope = "https://www.googleapis.com/auth/gmail.readonly"
        valid_credential_policy = SimpleNamespace(
            provider="google",
            provider_subject="google-subject-123",
            scopes=(gmail_scope,),
        )
        app_module._assert_credential_policy_binding(stored, valid_credential_policy)
        malformed_scope_credentials = (
            {**stored, "metadata": {**stored["metadata"], "scopes": gmail_scope}},
            {**stored, "metadata": {**stored["metadata"], "scopes": [gmail_scope, gmail_scope]}},
        )
        for malformed_credential in malformed_scope_credentials:
            try:
                app_module._assert_credential_policy_binding(malformed_credential, valid_credential_policy)
            except app_module.HTTPException as exc:
                if exc.status_code != 503:
                    raise AssertionError(f"malformed stored OAuth scopes failed with wrong status: {exc.status_code}") from exc
            else:
                raise AssertionError("malformed stored OAuth scopes passed lease policy binding")
        try:
            app_module._assert_credential_policy_binding(
                stored,
                SimpleNamespace(
                    provider="google",
                    provider_subject="google-subject-123",
                    scopes=(gmail_scope, gmail_scope),
                ),
            )
        except app_module.HTTPException as exc:
            if exc.status_code != 503:
                raise AssertionError(f"malformed policy OAuth scopes failed with wrong status: {exc.status_code}") from exc
        else:
            raise AssertionError("malformed signed-policy OAuth scopes passed lease policy binding")
        for mismatched_policy in (
            SimpleNamespace(provider="google", provider_subject="different-account", scopes=(gmail_scope,)),
            SimpleNamespace(provider="google", provider_subject=None, scopes=(gmail_scope,)),
            SimpleNamespace(provider="generic", provider_subject="google-subject-123", scopes=(gmail_scope,)),
            SimpleNamespace(
                provider="google",
                provider_subject="google-subject-123",
                scopes=(gmail_scope, "openid"),
            ),
        ):
            try:
                app_module._assert_credential_policy_binding(stored, mismatched_policy)
            except app_module.HTTPException as exc:
                if exc.status_code != 409:
                    raise AssertionError(f"mismatched OAuth policy failed with wrong status: {exc.status_code}") from exc
            else:
                raise AssertionError("mismatched OAuth account or scope policy passed lease binding")
        for invalid_credential in (
            {**stored, "metadata": {**stored["metadata"], "provider_identity_verified": False}},
            {**stored, "metadata": {**stored["metadata"], "oauth": False}},
            {**stored, "kind": "bearer"},
        ):
            try:
                app_module._assert_credential_policy_binding(invalid_credential, valid_credential_policy)
            except app_module.HTTPException as exc:
                if exc.status_code != 409:
                    raise AssertionError(f"unverified OAuth binding failed with wrong status: {exc.status_code}") from exc
            else:
                raise AssertionError("unverified or non-OAuth credential satisfied a signed provider account binding")

        canonical_oauth_injection = {
            "type": "bearer",
            "header": "Authorization",
            "field": "access_token",
            "prefix": "Bearer ",
        }
        canonical_lease_policy = SimpleNamespace(injection=canonical_oauth_injection)
        for provider_id in ("google", "x"):
            access_token = f"{provider_id}-lease-access-token-distinctive"
            refresh_token = f"{provider_id}-lease-refresh-token-distinctive"
            full_secret = json.dumps(
                {
                    "refresh_token": refresh_token,
                    "token_type": "Bearer",
                    "access_token": access_token,
                },
                separators=(",", ":"),
                sort_keys=False,
            )
            credential = {
                "id": f"{provider_id}-lease-custody",
                "kind": "oauth2",
                "secret": full_secret,
                "metadata": {"provider_id": provider_id},
            }
            expected_projection = json.dumps(
                {"access_token": access_token},
                separators=(",", ":"),
                sort_keys=True,
            )
            lease_secret = app_module._credential_secret_for_lease(
                credential,
                canonical_lease_policy,
            )
            projected = runtime._project_credential_for_data_plane(credential)
            if lease_secret != expected_projection:
                raise AssertionError(
                    f"{provider_id} lease secret was not canonical access-token-only JSON: "
                    f"{lease_secret}"
                )
            if projected is None or projected.get("secret") != expected_projection:
                raise AssertionError(
                    f"{provider_id} runtime projection was not access-token-only: {projected}"
                )
            if refresh_token in lease_secret or refresh_token in str(projected.get("secret")):
                raise AssertionError(f"{provider_id} refresh token crossed the data-plane boundary")
            if credential["secret"] != full_secret:
                raise AssertionError(f"{provider_id} runtime projection mutated credential custody material")

        malformed_custody_secrets = (
            ("malformed", '{"access_token":'),
            (
                "duplicate",
                '{"access_token":"duplicate-first","access_token":"duplicate-second",'
                '"refresh_token":"duplicate-refresh"}',
            ),
            ("missing", '{"refresh_token":"missing-access-refresh"}'),
        )
        for malformed_kind, malformed_secret in malformed_custody_secrets:
            malformed_credential = {
                "id": f"oauth-custody-{malformed_kind}",
                "kind": "oauth2",
                "secret": malformed_secret,
                "metadata": {"provider_id": "x"},
            }
            try:
                app_module._credential_secret_for_lease(
                    malformed_credential,
                    canonical_lease_policy,
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 503 or malformed_secret in str(exc.detail):
                    raise AssertionError(
                        f"{malformed_kind} OAuth lease material failed unsafely: {exc.detail}"
                    ) from exc
            else:
                raise AssertionError(f"{malformed_kind} OAuth lease material crossed custody")
            if runtime._project_credential_for_data_plane(malformed_credential) is not None:
                raise AssertionError(
                    f"runtime accepted {malformed_kind} OAuth lease material"
                )

        for provider in ("google.oauth2", "x.oauth2"):
            canonical_policy = demo_policy_bundle("cred-oauth-custody")
            canonical_policy["credentials"][0].update(
                {
                    "provider": provider,
                    "providerSubject": f"{provider}-subject",
                    "injection": dict(canonical_oauth_injection),
                }
            )
            compile_policy_bundle(canonical_policy)
            invalid_injections = (
                ("fieldless", {"type": "bearer", "header": "Authorization"}),
                (
                    "refresh-token",
                    {
                        "type": "bearer",
                        "header": "Authorization",
                        "field": "refresh_token",
                    },
                ),
                (
                    "alternate-header",
                    {
                        "type": "bearer",
                        "header": "X-OAuth-Token",
                        "field": "access_token",
                    },
                ),
                (
                    "alternate-type",
                    {
                        "type": "header",
                        "name": "Authorization",
                        "field": "access_token",
                    },
                ),
                (
                    "alternate-prefix",
                    {
                        "type": "bearer",
                        "header": "Authorization",
                        "field": "access_token",
                        "prefix": "Token ",
                    },
                ),
            )
            for case, invalid_injection in invalid_injections:
                invalid_policy = json.loads(json.dumps(canonical_policy))
                invalid_policy["credentials"][0]["injection"] = invalid_injection
                try:
                    compile_policy_bundle(invalid_policy)
                except PolicyBundleError:
                    pass
                else:
                    raise AssertionError(
                        f"{provider} policy accepted {case} OAuth injection"
                    )

        try:
            oauth.exchange_authorization_code(
                provider_id="google",
                code="auth-code-2",
                state=start["state"],
                browser_nonce=browser_nonce,
            )
        except oauth.OAuthError as exc:
            if "unknown or expired" not in str(exc):
                raise AssertionError(f"state replay failed with wrong error: {exc}") from exc
        else:
            raise AssertionError("OAuth state replay was accepted")

        denied_start, denied_browser_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="google",
                credentialName="Denied Gmail OAuth",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            )
        )
        denied_response = app_module.oauth_callback(
            "google",
            oauth_request(str(denied_start["state"]), denied_browser_nonce),
            state=denied_start["state"],
            error="access_denied",
            error_description="The operator denied access",
        )
        if denied_response.status_code != 400 or b"OAuth denied" not in denied_response.body:
            raise AssertionError(f"provider denial callback failed incorrectly: {denied_response.body!r}")
        if denied_start["state"] in json.loads((Path(tmp) / "oauth-states.json").read_text())["states"]:
            raise AssertionError("provider denial callback did not consume OAuth state")
        denied_replay = app_module.oauth_callback(
            "google",
            oauth_request(str(denied_start["state"]), denied_browser_nonce),
            state=denied_start["state"],
            error="access_denied",
        )
        if denied_replay.status_code != 400 or b"unknown or expired" not in denied_replay.body:
            raise AssertionError(f"provider denial state replay was accepted: {denied_replay.body!r}")

        x_start, x_browser_nonce = start_oauth(
            app_module.OAuthStartRequest(
                provider="twitter",
                credentialName="X OAuth - Test",
                scopes=["tweet.read", "users.read", "offline.access"],
            )
        )
        x_state_payload = json.loads((Path(tmp) / "oauth-states.json").read_text())
        x_state_record = x_state_payload["states"][x_start["state"]]

        def fake_x_post_token_request(provider, body, headers):
            if provider.id != "x":
                raise AssertionError(f"unexpected provider for X token request: {provider}")
            if body.get("code_verifier") != x_state_record["code_verifier"]:
                raise AssertionError(f"X token request did not use stored verifier: {body}")
            if not str(headers.get("Authorization", "")).startswith("Basic "):
                raise AssertionError(f"X token request did not use confidential-client Basic auth: {headers}")
            if "client_secret" in body:
                raise AssertionError("X token request leaked client_secret in form body")
            return {
                "access_token": "x-access-token-value",
                "refresh_token": "x-refresh-token-value",
                "token_type": "Bearer",
                "scope": "tweet.read users.read offline.access",
                "expires_in": 7200,
            }

        oauth._post_token_request = fake_x_post_token_request
        oauth._fetch_provider_identity = lambda provider, token: {
            "provider_subject": "x-user-456",
            "provider_account": "@andrew",
            "provider_identity_verified": True,
            "provider_profile_verified": False,
        }
        x_response = app_module.oauth_callback(
            "x",
            oauth_request(str(x_start["state"]), x_browser_nonce),
            code="x-auth-code",
            state=x_start["state"],
        )
        if x_response.status_code != 200:
            raise AssertionError(f"X OAuth callback failed: {x_response.status_code} {x_response.body!r}")
        x_credentials = [item for item in db.list_credentials() if item["name"] == "X OAuth - Test"]
        if len(x_credentials) != 1 or x_credentials[0]["metadata"].get("provider") != "x.oauth2":
            raise AssertionError(f"X OAuth credential was not created with provider metadata: {x_credentials}")
        if x_credentials[0]["metadata"].get("provider_account") != "@andrew":
            raise AssertionError(f"X OAuth credential is not bound to the verified account: {x_credentials}")
        if x_credentials[0]["metadata"].get("x_app_id") != "x-client":
            raise AssertionError(f"X OAuth credential is not bound to its OAuth app ID: {x_credentials}")
        if x_credentials[0]["metadata"].get("scopes") != ["offline.access", "tweet.read", "users.read"]:
            raise AssertionError(f"X OAuth metadata did not preserve provider-granted scopes: {x_credentials}")

        original_exchange_for_pending = app_module.exchange_authorization_code
        original_two_person_required = app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED
        original_two_person_actions = app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS
        pending_access_token = "pending-access-token-must-never-leak"
        pending_refresh_token = "pending-refresh-token-must-never-leak"
        app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED = True
        app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = ("credential.oauth.activate",)
        app_module.exchange_authorization_code = lambda **kwargs: {
            "name": "Exact account OAuth - Test",
            "kind": "oauth2",
            "secret": json.dumps(
                {
                    "access_token": pending_access_token,
                    "refresh_token": pending_refresh_token,
                    "token_type": "Bearer",
                    "scope": "https://www.googleapis.com/auth/gmail.readonly",
                    "expires_at_epoch_ms": 4_102_444_800_000,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            "metadata": {
                "oauth": True,
                "refreshable": True,
                "provider": "google.oauth2",
                "provider_id": "google",
                "provider_subject": "google-exact-subject-789",
                "provider_account": "exact-account@example.test",
                "provider_identity_verified": True,
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "token_type": "Bearer",
                "expires_at_epoch_ms": 4_102_444_800_000,
                "created_by": "user:operator",
                "injection_field": "access_token",
            },
            "provider": "google",
            "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
            "expiresAtEpochMs": 4_102_444_800_000,
            "createdBy": "user:operator",
            "providerAccount": "exact-account@example.test",
            "providerSubject": "google-exact-subject-789",
        }
        try:
            pending_response = app_module.oauth_callback(
                "google",
                oauth_request("x" * 43, "y" * 43),
                code="pending-auth-code",
                state="x" * 43,
            )
            if pending_response.status_code != 200 or b"OAuth account verified" not in pending_response.body:
                raise AssertionError(f"exact-account OAuth callback did not stage approval: {pending_response.body!r}")
            if pending_access_token.encode() in pending_response.body or pending_refresh_token.encode() in pending_response.body:
                raise AssertionError("pending OAuth callback response disclosed token material")
            if b"exact-account@example.test" not in pending_response.body:
                raise AssertionError("pending OAuth callback did not identify the exact account")

            pending_items = db.list_pending_oauth_credentials()
            pending = next((item for item in pending_items if item["name"] == "Exact account OAuth - Test"), None)
            if pending is None:
                raise AssertionError(f"OAuth callback did not create an encrypted pending credential: {pending_items}")
            serialized_pending = json.dumps(pending, sort_keys=True)
            if pending_access_token in serialized_pending or pending_refresh_token in serialized_pending:
                raise AssertionError("pending OAuth listing disclosed token material")
            if pending["review"].get("provider_account") != "exact-account@example.test":
                raise AssertionError(f"pending OAuth review lost the verified account: {pending}")
            if pending["review"].get("provider_subject") != "google-exact-subject-789":
                raise AssertionError(f"pending OAuth review lost the verified subject: {pending}")
            if db.get_credential(pending["id"], include_secret=True) is not None:
                raise AssertionError("pending OAuth token was reachable through the active credential store")

            bootstrap = app_module.bootstrap(identity)
            if bootstrap.get("currentUserId") != "user:operator" or not any(
                item["id"] == pending["id"] for item in bootstrap.get("pendingOAuthCredentials", [])
            ):
                raise AssertionError(f"portal bootstrap did not expose the exact-account activation task: {bootstrap}")

            owner_only_identity = AdminIdentity(
                "user:operator",
                frozenset({"credential_owner"}),
                "test",
            )
            inventory_outsider = AdminIdentity(
                "user:inventory-outsider",
                frozenset({"credential_owner"}),
                "test",
            )
            owner_inventory = app_module.oauth_pending_credentials(owner_only_identity)[
                "pendingCredentials"
            ]
            outsider_inventory = app_module.oauth_pending_credentials(
                inventory_outsider
            )["pendingCredentials"]
            admin_inventory = app_module.oauth_pending_credentials(identity)[
                "pendingCredentials"
            ]
            if pending["id"] not in {item["id"] for item in owner_inventory}:
                raise AssertionError("pending OAuth inventory omitted its non-admin owner")
            if outsider_inventory:
                raise AssertionError(
                    "pending OAuth inventory disclosed another owner's grants"
                )
            if pending["id"] not in {item["id"] for item in admin_inventory}:
                raise AssertionError("admin pending OAuth review lost cross-owner inventory")
            if app_module.bootstrap(inventory_outsider).get("pendingOAuthCredentials"):
                raise AssertionError(
                    "portal bootstrap disclosed another owner's pending OAuth grants"
                )

            other_requester = AdminIdentity(
                "user:other",
                frozenset({"admin", "credential_owner"}),
                "test",
            )
            try:
                app_module.oauth_pending_credential_activate(
                    pending["id"],
                    app_module.OAuthPendingActivateRequest(),
                    other_requester,
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 403:
                    raise AssertionError(f"wrong OAuth requester failed with {exc.status_code}") from exc
            else:
                raise AssertionError("a different operator activated the pending OAuth credential")

            try:
                app_module.oauth_pending_credential_activate(
                    pending["id"],
                    app_module.OAuthPendingActivateRequest(),
                    identity,
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 428 or not isinstance(exc.detail, dict):
                    raise AssertionError(f"pending OAuth activation did not require exact approval: {exc.detail}") from exc
                approval_id = exc.detail.get("approvalId")
            else:
                raise AssertionError("pending OAuth activation succeeded without exact-account approval")

            approval = db.get_control_plane_approval(str(approval_id))
            if approval is None:
                raise AssertionError("exact-account OAuth approval was not persisted")
            approval_json = json.dumps(approval, sort_keys=True)
            if pending_access_token in approval_json or pending_refresh_token in approval_json:
                raise AssertionError("exact-account OAuth approval disclosed token material")
            for field, expected in (
                ("provider", "google"),
                ("provider_subject", "google-exact-subject-789"),
                ("provider_account", "exact-account@example.test"),
            ):
                if approval["request"].get(field) != expected:
                    raise AssertionError(f"exact-account approval did not bind {field}: {approval}")

            unrelated = db.ensure_control_plane_approval(
                action="credential.oauth.activate",
                resource_id="different-pending-credential",
                payload_digest=pending["payload_digest"],
                requester_id="user:operator",
                request=pending["review"],
                ttl_seconds=300,
            )
            unrelated = db.approve_control_plane_approval(
                unrelated["id"],
                actor_id="user:reviewer",
                note="wrong resource",
            )
            try:
                app_module.oauth_pending_credential_activate(
                    pending["id"],
                    app_module.OAuthPendingActivateRequest(mfa={"approvalId": unrelated["id"]}),
                    identity,
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 409 or exc.detail.get("reason") != "resource_mismatch":
                    raise AssertionError(f"wrong-resource OAuth approval failed incorrectly: {exc.detail}") from exc
            else:
                raise AssertionError("wrong-resource approval activated a pending OAuth credential")
            if db.get_pending_oauth_credential(pending["id"]) is None:
                raise AssertionError("failed OAuth activation removed the pending credential")

            approved = db.approve_control_plane_approval(
                str(approval_id),
                actor_id="user:reviewer",
                note="verified exact account and scopes",
            )
            if approved is None or approved["status"] != "approved":
                raise AssertionError(f"exact-account OAuth approval could not be approved: {approved}")
            activated = app_module.oauth_pending_credential_activate(
                pending["id"],
                app_module.OAuthPendingActivateRequest(mfa={"approvalId": approval_id}),
                identity,
            )
            if not activated.get("ok") or activated["approval"].get("status") != "consumed":
                raise AssertionError(f"exact-account OAuth activation did not atomically consume approval: {activated}")
            if db.get_pending_oauth_credential(pending["id"]) is not None:
                raise AssertionError("activated OAuth credential remained in the pending store")
            active_exact = db.get_credential(pending["id"], include_secret=True)
            if active_exact is None:
                raise AssertionError("approved exact-account OAuth credential was not promoted")
            active_secret = json.loads(active_exact["secret"])
            if active_secret.get("access_token") != pending_access_token or active_secret.get("refresh_token") != pending_refresh_token:
                raise AssertionError("OAuth activation changed the encrypted token material")
            try:
                app_module.oauth_pending_credential_activate(
                    pending["id"],
                    app_module.OAuthPendingActivateRequest(mfa={"approvalId": approval_id}),
                    identity,
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 404:
                    raise AssertionError(f"OAuth activation replay failed with {exc.status_code}") from exc
            else:
                raise AssertionError("OAuth activation approval was replayed")

            try:
                start_oauth(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialId=active_exact["id"],
                    )
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 409 or "Disconnect" not in str(exc.detail):
                    raise AssertionError(f"Google reconnect failed incorrectly: {exc.detail}") from exc
            else:
                raise AssertionError("Google OAuth reconnect was accepted in place")

            reconnect_source = db.get_credential(x_credentials[0]["id"], include_secret=True)
            if reconnect_source is None:
                raise AssertionError("X reconnect fixture credential disappeared")
            reconnect_created = db.create_credential(
                "X OAuth reconnect fixture",
                "oauth2",
                reconnect_source["secret"],
                reconnect_source["metadata"],
            )
            reconnect_target = db.get_credential(reconnect_created["id"], include_secret=True)
            if reconnect_target is None:
                raise AssertionError("X reconnect fixture could not be reloaded")
            reconnect_route = db.create_route(
                {
                    "name": "OAuth reconnect identity route",
                    "enabled": True,
                    "match_host": "reconnect.example.test",
                    "match_path_prefix": "/",
                    "credential_id": reconnect_target["id"],
                    "injection": {"type": "bearer", "field": "access_token"},
                    "policies": [],
                }
            )
            try:
                start_oauth(
                    app_module.OAuthStartRequest(
                        provider="google",
                        credentialId=reconnect_target["id"],
                    )
                )
            except app_module.HTTPException as exc:
                if exc.status_code != 409 or "provider" not in str(exc.detail):
                    raise AssertionError(f"cross-provider reconnect failed incorrectly: {exc.detail}") from exc
            else:
                raise AssertionError("OAuth reconnect accepted a different provider")

            original_reconnect_revoke = app_module.revoke_oauth_token
            rejected_reconnect_tokens: list[tuple[str, dict[str, object]]] = []

            def revoke_rejected_reconnect(*, provider_id: str, token_secret: dict[str, object]):
                rejected_reconnect_tokens.append((provider_id, dict(token_secret)))
                return {"provider": provider_id, "revoked": True}

            def reconnect_exchange(
                binding: dict[str, object],
                suffix: str,
                *,
                provider_subject: str = "x-user-456",
                provider_account: str = "@andrew",
            ) -> dict[str, object]:
                current = db.get_credential(reconnect_target["id"], include_secret=True)
                if current is None:
                    raise AssertionError("reconnect fixture credential disappeared")
                next_secret = {
                    **json.loads(current["secret"]),
                    "access_token": f"reconnect-access-{suffix}",
                    "refresh_token": f"reconnect-refresh-{suffix}",
                    "expires_at_epoch_ms": 4_102_444_800_000,
                }
                next_metadata = {
                    **current["metadata"],
                    "provider_subject": provider_subject,
                    "provider_account": provider_account,
                    "expires_at_epoch_ms": 4_102_444_800_000,
                }
                return {
                    "name": current["name"],
                    "kind": "oauth2",
                    "secret": json.dumps(next_secret, separators=(",", ":"), sort_keys=True),
                    "metadata": next_metadata,
                    "provider": "x",
                    "scopes": list(next_metadata["scopes"]),
                    "expiresAtEpochMs": 4_102_444_800_000,
                    "createdBy": "user:operator",
                    "providerAccount": provider_account,
                    "providerSubject": provider_subject,
                    "reconnect": dict(binding),
                }

            app_module.revoke_oauth_token = revoke_rejected_reconnect
            try:
                baseline_version = int(reconnect_target["credential_version"])
                baseline_secret = reconnect_target["secret"]
                pending_before_mismatch = {
                    item["id"] for item in db.list_pending_oauth_credentials()
                }
                for suffix, changed_identity in (
                    (
                        "wrong-subject",
                        {
                            "provider_subject": "different-provider-subject",
                            "provider_account": "@andrew",
                        },
                    ),
                    (
                        "wrong-account",
                        {
                            "provider_subject": "x-user-456",
                            "provider_account": "@different-account",
                        },
                    ),
                ):
                    reconnect_start, reconnect_nonce = start_oauth(
                        app_module.OAuthStartRequest(
                            provider="x",
                            credentialId=reconnect_target["id"],
                            credentialName=reconnect_target["name"],
                            scopes=["tweet.read", "users.read", "offline.access"],
                        )
                    )
                    reconnect_record = json.loads((Path(tmp) / "oauth-states.json").read_text())[
                        "states"
                    ][reconnect_start["state"]]
                    binding = reconnect_record.get("reconnect")
                    if (
                        not isinstance(binding, dict)
                        or binding.get("credential_id") != reconnect_target["id"]
                        or binding.get("credential_version") != baseline_version
                        or binding.get("provider_subject") != "x-user-456"
                        or binding.get("provider_account") != "@andrew"
                    ):
                        raise AssertionError(f"OAuth reconnect state lost its exact credential binding: {binding}")
                    app_module.exchange_authorization_code = lambda **kwargs: reconnect_exchange(
                        binding,
                        suffix,
                        **changed_identity,
                    )
                    rejected = app_module.oauth_callback(
                        "x",
                        oauth_request(str(reconnect_start["state"]), reconnect_nonce),
                        code=f"{suffix}-code",
                        state=reconnect_start["state"],
                    )
                    if rejected.status_code != 409 or b"exact existing provider subject and account" not in rejected.body:
                        raise AssertionError(f"OAuth reconnect identity drift was accepted: {rejected.body!r}")
                    unchanged = db.get_credential(reconnect_target["id"], include_secret=True)
                    if (
                        unchanged is None
                        or int(unchanged["credential_version"]) != baseline_version
                        or unchanged["secret"] != baseline_secret
                    ):
                        raise AssertionError("rejected OAuth reconnect changed the active credential")
                if len(rejected_reconnect_tokens) != 2:
                    raise AssertionError(
                        f"rejected OAuth reconnect tokens were not revoked: {rejected_reconnect_tokens}"
                    )
                pending_after_mismatch = {
                    item["id"] for item in db.list_pending_oauth_credentials()
                }
                if pending_after_mismatch != pending_before_mismatch:
                    raise AssertionError("identity-mismatched OAuth reconnect staged a pending credential")

                stale_start, stale_nonce = start_oauth(
                    app_module.OAuthStartRequest(
                        provider="x",
                        credentialId=reconnect_target["id"],
                    )
                )
                stale_binding = json.loads((Path(tmp) / "oauth-states.json").read_text())["states"][
                    stale_start["state"]
                ]["reconnect"]

                def assert_x_refresh_retirement_work(
                    expected_material: dict[str, str],
                    *plaintext_tokens: str,
                ) -> None:
                    with db.connect() as conn:
                        work_rows = conn.execute(
                            "SELECT * FROM oauth_revocation_work WHERE source = ?",
                            ("refresh_superseded",),
                        ).fetchall()
                    if len(work_rows) != 1 or work_rows[0]["status"] != "pending":
                        raise AssertionError(
                            f"X refresh did not queue one pending retirement item: {work_rows}"
                        )
                    serialized_work = json.dumps(dict(work_rows[0]), sort_keys=True)
                    if any(token in serialized_work for token in plaintext_tokens):
                        raise AssertionError("X refresh retirement work stored plaintext token material")
                    material = json.loads(db.decrypt_secret_envelope(work_rows[0]))
                    if material != expected_material:
                        raise AssertionError(
                            f"X refresh queued the wrong retirement material: {material}"
                        )

                def assert_oauth_secrets_absent_from_api_and_audit(*secrets: str) -> None:
                    api_text = json.dumps(app_module.bootstrap(identity), sort_keys=True)
                    audit_text = json.dumps(db.list_audit_events(limit=1000), sort_keys=True)
                    for secret_value in secrets:
                        if secret_value in api_text:
                            raise AssertionError("control-plane API disclosed OAuth token material")
                        if secret_value in audit_text:
                            raise AssertionError("OAuth audit events disclosed token material")

                def issue_x_refresh(
                    credential: dict[str, object],
                    response: dict[str, object],
                ) -> dict[str, object]:
                    current_token_secret = json.loads(str(credential["secret"]))
                    expected_refresh_token = current_token_secret["refresh_token"]

                    def x_refresh_request(provider, body, headers):
                        if provider.id != "x":
                            raise AssertionError(f"unexpected X refresh provider: {provider.id}")
                        if body.get("refresh_token") != expected_refresh_token:
                            raise AssertionError(f"X refresh used the wrong current token: {body}")
                        if not str(headers.get("Authorization", "")).startswith("Basic "):
                            raise AssertionError("X refresh did not authenticate the confidential client")
                        return response

                    oauth._post_token_request = x_refresh_request
                    return oauth.refresh_access_token(
                        provider_id="x",
                        token_secret=current_token_secret,
                        metadata=credential["metadata"],
                        now_epoch=int(time.time()),
                    )

                nonrotating_refresh = issue_x_refresh(
                    reconnect_target,
                    {
                        "access_token": "concurrent-refresh-before-reconnect",
                        "token_type": "Bearer",
                        "expires_in": 7200,
                    },
                )
                nonrotating_secret = json.loads(str(nonrotating_refresh["secret"]))
                if (
                    nonrotating_refresh.get("refreshTokenRotated") is not False
                    or nonrotating_secret.get("refresh_token") != "x-refresh-token-value"
                ):
                    raise AssertionError(
                        "X refresh did not preserve an omitted replacement refresh token"
                    )
                concurrently_refreshed, rotated = db.update_credential_secret_if_version(
                    reconnect_target["id"],
                    expected_version=baseline_version,
                    secret=str(nonrotating_refresh["secret"]),
                    metadata=nonrotating_refresh["metadata"],
                    revocation_work_id=str(nonrotating_refresh["revocationWorkId"]),
                )
                if concurrently_refreshed is None or not rotated:
                    raise AssertionError("stale reconnect fixture did not rotate the active credential")
                app_module.runtime.invalidate_secret_leases(reconnect_target["id"])
                assert_x_refresh_retirement_work(
                    {"access_token": "x-access-token-value"},
                    "x-access-token-value",
                    "x-refresh-token-value",
                    "concurrent-refresh-before-reconnect",
                )
                assert_oauth_secrets_absent_from_api_and_audit(
                    "x-access-token-value",
                    "x-refresh-token-value",
                    "concurrent-refresh-before-reconnect",
                )
                refresh_superseded_reconcile = app_module._reconcile_oauth_revocations(limit=1)
                if refresh_superseded_reconcile != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(
                        f"X refresh superseded-token reconciliation failed: {refresh_superseded_reconcile}"
                    )
                if (
                    len(rejected_reconnect_tokens) != 3
                    or rejected_reconnect_tokens[-1]
                    != ("x", {"access_token": "x-access-token-value"})
                ):
                    raise AssertionError(
                        "X refresh without refresh-token rotation retired the current refresh token"
                    )

                malformed_access_token = "malformed-x-access-token-must-not-leak"
                malformed_refresh_token = "malformed-x-refresh-token-must-not-leak"
                before_malformed = db.get_credential(reconnect_target["id"], include_secret=True)
                if before_malformed is None:
                    raise AssertionError("X malformed-refresh fixture credential disappeared")
                malformed_secret = {
                    **json.loads(before_malformed["secret"]),
                    "access_token": malformed_access_token,
                    "refresh_token": [malformed_refresh_token],
                }
                try:
                    db.update_credential_secret_if_version(
                        reconnect_target["id"],
                        expected_version=int(before_malformed["credential_version"]),
                        secret=json.dumps(malformed_secret, separators=(",", ":"), sort_keys=True),
                        metadata=before_malformed["metadata"],
                    )
                except db.ManagedOAuthCredentialError as exc:
                    if (
                        malformed_access_token in str(exc)
                        or malformed_refresh_token in str(exc)
                        or str(exc) != "OAuth token retirement material is malformed"
                    ):
                        raise AssertionError(
                            f"malformed X retirement material failed unsafely: {exc}"
                        ) from exc
                else:
                    raise AssertionError("malformed X retirement material was persisted")
                after_malformed = db.get_credential(reconnect_target["id"], include_secret=True)
                if (
                    after_malformed is None
                    or after_malformed["credential_version"] != before_malformed["credential_version"]
                    or after_malformed["secret"] != before_malformed["secret"]
                ):
                    raise AssertionError("malformed X retirement material changed the credential")
                with db.connect() as conn:
                    malformed_work_count = conn.execute(
                        "SELECT COUNT(*) AS count FROM oauth_revocation_work "
                        "WHERE source = ?",
                        ("refresh_superseded",),
                    ).fetchone()
                if int(malformed_work_count["count"] if malformed_work_count else -1) != 0:
                    raise AssertionError("malformed X retirement material left revocation work behind")
                assert_oauth_secrets_absent_from_api_and_audit(
                    malformed_access_token,
                    malformed_refresh_token,
                )

                app_module.exchange_authorization_code = lambda **kwargs: reconnect_exchange(
                    stale_binding,
                    "stale-version",
                )
                stale_response = app_module.oauth_callback(
                    "x",
                    oauth_request(str(stale_start["state"]), stale_nonce),
                    code="stale-reconnect-code",
                    state=stale_start["state"],
                )
                if stale_response.status_code != 409 or b"changed during authorization" not in stale_response.body:
                    raise AssertionError(f"stale OAuth reconnect binding was accepted: {stale_response.body!r}")
                after_stale = db.get_credential(reconnect_target["id"], include_secret=True)
                if (
                    after_stale is None
                    or json.loads(after_stale["secret"]).get("access_token")
                    != "concurrent-refresh-before-reconnect"
                ):
                    raise AssertionError("stale OAuth reconnect overwrote a concurrent credential rotation")
                if len(rejected_reconnect_tokens) != 4:
                    raise AssertionError("stale OAuth reconnect token was not revoked")

                rotating_refresh = issue_x_refresh(
                    after_stale,
                    {
                        "access_token": "concurrent-refresh-after-rotation",
                        "refresh_token": "x-refresh-token-rotated",
                        "token_type": "Bearer",
                        "expires_in": 7200,
                    },
                )
                rotating_secret = json.loads(str(rotating_refresh["secret"]))
                if (
                    rotating_refresh.get("refreshTokenRotated") is not True
                    or rotating_secret.get("refresh_token") != "x-refresh-token-rotated"
                ):
                    raise AssertionError("X refresh did not preserve a rotated refresh token")
                rotated_credential, refresh_token_rotated = db.update_credential_secret_if_version(
                    reconnect_target["id"],
                    expected_version=int(after_stale["credential_version"]),
                    secret=str(rotating_refresh["secret"]),
                    metadata=rotating_refresh["metadata"],
                    revocation_work_id=str(rotating_refresh["revocationWorkId"]),
                )
                if rotated_credential is None or not refresh_token_rotated:
                    raise AssertionError("X rotated-refresh fixture did not rotate the credential")
                assert_x_refresh_retirement_work(
                    {
                        "access_token": "concurrent-refresh-before-reconnect",
                        "refresh_token": "x-refresh-token-value",
                    },
                    "concurrent-refresh-before-reconnect",
                    "x-refresh-token-value",
                    "concurrent-refresh-after-rotation",
                    "x-refresh-token-rotated",
                )
                assert_oauth_secrets_absent_from_api_and_audit(
                    "concurrent-refresh-before-reconnect",
                    "x-refresh-token-value",
                    "concurrent-refresh-after-rotation",
                    "x-refresh-token-rotated",
                )
                rotated_refresh_reconcile = app_module._reconcile_oauth_revocations(limit=1)
                if rotated_refresh_reconcile != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(
                        f"rotated X refresh retirement did not reconcile: {rotated_refresh_reconcile}"
                    )
                if (
                    len(rejected_reconnect_tokens) != 5
                    or rejected_reconnect_tokens[-1]
                    != (
                        "x",
                        {
                            "access_token": "concurrent-refresh-before-reconnect",
                            "refresh_token": "x-refresh-token-value",
                        },
                    )
                ):
                    raise AssertionError("rotated X refresh did not retire both superseded tokens")

                successful_start, successful_nonce = start_oauth(
                    app_module.OAuthStartRequest(
                        provider="x",
                        credentialId=reconnect_target["id"],
                    )
                )
                successful_binding = json.loads((Path(tmp) / "oauth-states.json").read_text())[
                    "states"
                ][successful_start["state"]]["reconnect"]
                app_module.exchange_authorization_code = lambda **kwargs: reconnect_exchange(
                    successful_binding,
                    "accepted",
                )
                successful_callback = app_module.oauth_callback(
                    "x",
                    oauth_request(str(successful_start["state"]), successful_nonce),
                    code="accepted-reconnect-code",
                    state=successful_start["state"],
                )
                if successful_callback.status_code != 200 or b"OAuth account verified" not in successful_callback.body:
                    raise AssertionError(f"valid OAuth reconnect did not stage approval: {successful_callback.body!r}")
                reconnect_pending = next(
                    (
                        item
                        for item in db.list_pending_oauth_credentials()
                        if item.get("target_credential_id") == reconnect_target["id"]
                    ),
                    None,
                )
                if (
                    reconnect_pending is None
                    or reconnect_pending.get("target_credential_version")
                    != successful_binding["credential_version"]
                    or reconnect_pending["review"].get("reconnect_credential_id")
                    != reconnect_target["id"]
                ):
                    raise AssertionError(f"valid OAuth reconnect lost its target binding: {reconnect_pending}")
                still_active = db.get_credential(reconnect_target["id"], include_secret=True)
                if (
                    still_active is None
                    or json.loads(still_active["secret"]).get("access_token")
                    != "concurrent-refresh-after-rotation"
                    or json.loads(still_active["secret"]).get("refresh_token")
                    != "x-refresh-token-rotated"
                ):
                    raise AssertionError("pending OAuth reconnect replaced the active credential before approval")
                if db.get_route(reconnect_route["id"])["credential_id"] != reconnect_target["id"]:
                    raise AssertionError("pending OAuth reconnect changed the route credential identity")

                try:
                    app_module.oauth_pending_credential_activate(
                        reconnect_pending["id"],
                        app_module.OAuthPendingActivateRequest(),
                        identity,
                    )
                except app_module.HTTPException as exc:
                    if exc.status_code != 428:
                        raise AssertionError(f"reconnect activation approval failed incorrectly: {exc.detail}") from exc
                    reconnect_approval_id = exc.detail["approvalId"]
                else:
                    raise AssertionError("OAuth reconnect activated without exact-account approval")
                reconnect_approval = db.approve_control_plane_approval(
                    reconnect_approval_id,
                    actor_id="user:reviewer",
                    note="verified reconnect account and credential identity",
                )
                if reconnect_approval is None or reconnect_approval["status"] != "approved":
                    raise AssertionError("OAuth reconnect approval could not be approved")
                original_revocation_capacity = db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT
                db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT = 0
                try:
                    app_module.oauth_pending_credential_activate(
                        reconnect_pending["id"],
                        app_module.OAuthPendingActivateRequest(
                            mfa={"approvalId": reconnect_approval_id}
                        ),
                        identity,
                    )
                except app_module.HTTPException as exc:
                    if (
                        exc.status_code != 503
                        or not isinstance(exc.detail, dict)
                        or exc.detail.get("reason") != "revocation_capacity_exhausted"
                    ):
                        raise AssertionError(
                            f"full reconnect retirement queue failed incorrectly: {exc.detail}"
                        ) from exc
                else:
                    raise AssertionError("OAuth reconnect bypassed a full token-retirement queue")
                finally:
                    db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT = original_revocation_capacity
                unchanged_after_capacity = db.get_credential(
                    reconnect_target["id"], include_secret=True
                )
                retained_approval = db.get_control_plane_approval(reconnect_approval_id)
                if (
                    unchanged_after_capacity is None
                    or json.loads(unchanged_after_capacity["secret"]).get("access_token")
                    != "concurrent-refresh-after-rotation"
                    or db.get_pending_oauth_credential(reconnect_pending["id"]) is None
                    or retained_approval is None
                    or retained_approval.get("status") != "approved"
                ):
                    raise AssertionError(
                        "full token-retirement queue did not roll back reconnect activation atomically"
                    )
                reconnected = app_module.oauth_pending_credential_activate(
                    reconnect_pending["id"],
                    app_module.OAuthPendingActivateRequest(
                        mfa={"approvalId": reconnect_approval_id}
                    ),
                    identity,
                )
                if reconnected["credential"]["id"] != reconnect_target["id"]:
                    raise AssertionError("OAuth reconnect allocated a new credential identity")
                reconnect_target = db.get_credential(reconnect_target["id"], include_secret=True)
                if (
                    reconnect_target is None
                    or json.loads(reconnect_target["secret"]).get("access_token") != "reconnect-access-accepted"
                    or int(reconnect_target["credential_version"])
                    <= int(successful_binding["credential_version"])
                ):
                    raise AssertionError("OAuth reconnect did not rotate the existing encrypted credential")
                if db.get_route(reconnect_route["id"])["credential_id"] != reconnect_target["id"]:
                    raise AssertionError("OAuth reconnect did not preserve the route policy reference")
                with db.connect() as conn:
                    superseded_work = conn.execute(
                        "SELECT * FROM oauth_revocation_work WHERE source = ?",
                        ("reconnect_superseded",),
                    ).fetchall()
                if len(superseded_work) != 1 or superseded_work[0]["status"] != "pending":
                    raise AssertionError(
                        f"X reconnect did not atomically queue superseded token revocation: {superseded_work}"
                    )
                superseded_material = json.loads(db.decrypt_secret_envelope(superseded_work[0]))
                if superseded_material != {
                    "access_token": "concurrent-refresh-after-rotation",
                    "refresh_token": "x-refresh-token-rotated",
                }:
                    raise AssertionError(
                        f"X reconnect did not retain both superseded tokens: {superseded_material}"
                    )
                superseded_reconcile = app_module._reconcile_oauth_revocations(limit=1)
                if superseded_reconcile != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(
                        f"superseded X token revocation did not reconcile: {superseded_reconcile}"
                    )
                if (
                    len(rejected_reconnect_tokens) != 6
                    or rejected_reconnect_tokens[-1][0] != "x"
                    or rejected_reconnect_tokens[-1][1].get("access_token")
                    != "concurrent-refresh-after-rotation"
                    or rejected_reconnect_tokens[-1][1].get("refresh_token")
                    != "x-refresh-token-rotated"
                ):
                    raise AssertionError(
                        f"X reconnect did not retain the exact superseded tokens: {rejected_reconnect_tokens}"
                    )
            finally:
                app_module.revoke_oauth_token = original_reconnect_revoke
                app_module.exchange_authorization_code = original_exchange_for_pending

            original_pending_capacity = db.OAUTH_PENDING_CREDENTIAL_MAX_COUNT
            db.OAUTH_PENDING_CREDENTIAL_MAX_COUNT = 1
            capacity_ids: list[str] = []
            capacity_metadata = dict(active_exact["metadata"])
            capacity_secret = json.dumps(active_secret, separators=(",", ":"), sort_keys=True)
            try:
                first_review = {**pending["review"], "credential_name": "OAuth capacity one"}
                first_digest = app_module._oauth_activation_payload_digest(
                    review=first_review,
                    secret=capacity_secret,
                )
                first_capacity_item = db.create_pending_oauth_credential(
                    name="OAuth capacity one",
                    kind="oauth2",
                    secret=capacity_secret,
                    metadata=capacity_metadata,
                    requester_id="user:operator",
                    payload_digest=first_digest,
                    review=first_review,
                    ttl_seconds=900,
                )
                capacity_ids.append(first_capacity_item["id"])

                second_review = {**pending["review"], "credential_name": "OAuth capacity two"}
                second_digest = app_module._oauth_activation_payload_digest(
                    review=second_review,
                    secret=capacity_secret,
                )
                try:
                    db.create_pending_oauth_credential(
                        name="OAuth capacity two",
                        kind="oauth2",
                        secret=capacity_secret,
                        metadata=capacity_metadata,
                        requester_id="user:operator",
                        payload_digest=second_digest,
                        review=second_review,
                        ttl_seconds=900,
                    )
                except db.ManagedOAuthCredentialError as exc:
                    if "capacity" not in str(exc):
                        raise AssertionError(f"pending OAuth capacity failed incorrectly: {exc}") from exc
                else:
                    raise AssertionError("pending OAuth staging exceeded its configured capacity")

                with db.connect() as conn:
                    conn.execute(
                        "UPDATE pending_oauth_credentials SET expires_at = ? WHERE id = ?",
                        ("2000-01-01T00:00:00+00:00", first_capacity_item["id"]),
                    )
                expired_capacity_item = db.get_pending_oauth_credential(first_capacity_item["id"])
                if expired_capacity_item is None or expired_capacity_item.get("status") != "expired":
                    raise AssertionError("expired pending OAuth credential was not terminalized")
                second_capacity_item = db.create_pending_oauth_credential(
                    name="OAuth capacity two",
                    kind="oauth2",
                    secret=capacity_secret,
                    metadata=capacity_metadata,
                    requester_id="user:operator",
                    payload_digest=second_digest,
                    review=second_review,
                    ttl_seconds=900,
                )
                capacity_ids.append(second_capacity_item["id"])
                original_capacity_revoke = app_module.revoke_oauth_token
                app_module.revoke_oauth_token = lambda **kwargs: (_ for _ in ()).throw(
                    oauth.OAuthError("provider revocation outage")
                )
                try:
                    failed_expiry_reconcile = app_module._reconcile_oauth_revocations(limit=1)
                finally:
                    app_module.revoke_oauth_token = original_capacity_revoke
                if failed_expiry_reconcile != {"claimed": 1, "revoked": 0, "failed": 1}:
                    raise AssertionError(
                        f"expired OAuth grant was not automatically reconciled with bounded work: "
                        f"{failed_expiry_reconcile}"
                    )
                retained_expired = db.get_pending_oauth_credential(first_capacity_item["id"])
                if (
                    retained_expired is None
                    or retained_expired.get("status") != "expired"
                    or retained_expired.get("revocation_status") != "failed"
                    or retained_expired.get("revocation_attempts") != 1
                ):
                    raise AssertionError(
                        f"expired OAuth revocation failure was not retained for retry: {retained_expired}"
                    )
                original_backlog_capacity = db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT
                db.OAUTH_PENDING_CREDENTIAL_MAX_COUNT = 2
                db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT = 1
                backlog_review = {**pending["review"], "credential_name": "OAuth backlog bound"}
                try:
                    db.create_pending_oauth_credential(
                        name="OAuth backlog bound",
                        kind="oauth2",
                        secret=capacity_secret,
                        metadata=capacity_metadata,
                        requester_id="user:operator",
                        payload_digest=app_module._oauth_activation_payload_digest(
                            review=backlog_review,
                            secret=capacity_secret,
                        ),
                        review=backlog_review,
                        ttl_seconds=900,
                    )
                except db.ManagedOAuthCredentialError as exc:
                    if "revocation backlog capacity" not in str(exc):
                        raise AssertionError(f"OAuth revocation backlog failed incorrectly: {exc}") from exc
                else:
                    raise AssertionError("terminal OAuth revocation work grew past its hard bound")
                finally:
                    db.OAUTH_PENDING_CREDENTIAL_MAX_COUNT = 1
                    db._OAUTH_REVOCATION_BACKLOG_MAX_COUNT = original_backlog_capacity
                with db.connect() as conn:
                    conn.execute(
                        "UPDATE pending_oauth_credentials SET revocation_next_attempt_at = ? WHERE id = ?",
                        ("2000-01-01T00:00:00+00:00", first_capacity_item["id"]),
                    )
                app_module.revoke_oauth_token = lambda **kwargs: {
                    "provider": kwargs["provider_id"],
                    "revoked": True,
                }
                try:
                    successful_expiry_reconcile = app_module._reconcile_oauth_revocations(limit=1)
                finally:
                    app_module.revoke_oauth_token = original_capacity_revoke
                if successful_expiry_reconcile != {"claimed": 1, "revoked": 1, "failed": 0}:
                    raise AssertionError(
                        f"expired OAuth revocation retry did not drain terminal work: "
                        f"{successful_expiry_reconcile}"
                    )
                if db.get_pending_oauth_credential(first_capacity_item["id"]) is not None:
                    raise AssertionError("revoked expired pending OAuth credential remained reachable")

                mismatched_review = {**second_review, "provider_account": "different@example.test"}
                try:
                    db.create_pending_oauth_credential(
                        name="OAuth capacity two",
                        kind="oauth2",
                        secret=capacity_secret,
                        metadata=capacity_metadata,
                        requester_id="user:operator",
                        payload_digest=app_module._oauth_activation_payload_digest(
                            review=mismatched_review,
                            secret=capacity_secret,
                        ),
                        review=mismatched_review,
                        ttl_seconds=900,
                    )
                except db.ManagedOAuthCredentialError as exc:
                    if "verified account" not in str(exc):
                        raise AssertionError(f"mismatched OAuth review failed incorrectly: {exc}") from exc
                else:
                    raise AssertionError("pending OAuth staging accepted a mismatched exact-account review")
            finally:
                db.OAUTH_PENDING_CREDENTIAL_MAX_COUNT = original_pending_capacity
                with db.connect() as conn:
                    for capacity_id in capacity_ids:
                        conn.execute("DELETE FROM pending_oauth_credentials WHERE id = ?", (capacity_id,))

            approvals_before_start = {
                item["id"] for item in db.list_control_plane_approvals(limit=1000)
            }
            app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = (
                "credential.create",
                "credential.oauth.activate",
            )
            blind_start, _ = start_oauth(
                app_module.OAuthStartRequest(
                    provider="google",
                    credentialName="No blind pre-identity approval",
                    scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                )
            )
            app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = ("credential.oauth.activate",)
            approvals_after_start = [
                item
                for item in db.list_control_plane_approvals(limit=1000)
                if item["id"] not in approvals_before_start
            ]
            if not blind_start.get("authorizationUrl") or any(
                item["action"] == "credential.create" for item in approvals_after_start
            ):
                raise AssertionError(
                    "OAuth start created a blind two-person approval before provider identity was known"
                )

            terminal_ids: list[str] = []

            def stage_terminal(name: str) -> dict[str, object]:
                review = {**pending["review"], "credential_name": name}
                digest = app_module._oauth_activation_payload_digest(
                    review=review,
                    secret=capacity_secret,
                )
                item = db.create_pending_oauth_credential(
                    name=name,
                    kind="oauth2",
                    secret=capacity_secret,
                    metadata=capacity_metadata,
                    requester_id="user:operator",
                    payload_digest=digest,
                    review=review,
                    ttl_seconds=900,
                )
                terminal_ids.append(str(item["id"]))
                return item

            reviewer = AdminIdentity(
                "user:reviewer",
                frozenset({"admin", "credential_owner"}),
                "test",
            )
            original_revoke_oauth_token = app_module.revoke_oauth_token
            revoked_tokens: list[tuple[str, dict[str, object]]] = []

            def successful_revoke(*, provider_id: str, token_secret: dict[str, object]):
                revoked_tokens.append((provider_id, dict(token_secret)))
                return {"provider": provider_id, "revoked": True}

            app_module.revoke_oauth_token = successful_revoke
            try:
                denied_pending = stage_terminal("OAuth denial terminal")
                denied_approval = db.ensure_control_plane_approval(
                    action="credential.oauth.activate",
                    resource_id=str(denied_pending["id"]),
                    payload_digest=str(denied_pending["payload_digest"]),
                    requester_id="user:operator",
                    request=dict(denied_pending["review"]),
                    ttl_seconds=300,
                )
                denied = app_module.control_plane_approval_deny(
                    denied_approval["id"],
                    app_module.ControlPlaneApprovalDecision(note="wrong account for this workflow"),
                    reviewer,
                )
                if denied.get("status") != "denied" or denied.get("oauthRevocation", {}).get("ok") is not True:
                    raise AssertionError(f"OAuth denial was not terminal and revoked: {denied}")
                if db.get_pending_oauth_credential(str(denied_pending["id"])) is not None:
                    raise AssertionError("successfully revoked denied OAuth token remained staged")
                try:
                    app_module.oauth_pending_credential_activate(
                        str(denied_pending["id"]),
                        app_module.OAuthPendingActivateRequest(),
                        identity,
                    )
                except app_module.HTTPException as exc:
                    if exc.status_code != 404:
                        raise AssertionError(f"denied OAuth activation failed with {exc.status_code}") from exc
                else:
                    raise AssertionError("denied OAuth connection created a second activation approval")

                cancelled_pending = stage_terminal("OAuth cancellation terminal")

                def failed_revoke(**kwargs):
                    raise oauth.OAuthError("provider revocation temporarily unavailable")

                app_module.revoke_oauth_token = failed_revoke
                cancelled = app_module.oauth_pending_credential_cancel(
                    str(cancelled_pending["id"]),
                    identity,
                )
                if cancelled.get("revocation", {}).get("reason") != "provider_revocation_failed":
                    raise AssertionError(f"failed OAuth revocation was not retained for retry: {cancelled}")
                retained_cancelled = db.get_pending_oauth_credential(str(cancelled_pending["id"]))
                if (
                    retained_cancelled is None
                    or retained_cancelled.get("status") != "cancelled"
                    or retained_cancelled.get("revocation_status") != "failed"
                ):
                    raise AssertionError(f"cancelled OAuth token was not terminal and retryable: {retained_cancelled}")
                try:
                    app_module.oauth_pending_credential_activate(
                        str(cancelled_pending["id"]),
                        app_module.OAuthPendingActivateRequest(),
                        identity,
                    )
                except app_module.HTTPException as exc:
                    if exc.status_code != 409 or exc.detail.get("reason") != "pending_credential_cancelled":
                        raise AssertionError(f"cancelled OAuth activation failed incorrectly: {exc.detail}") from exc
                else:
                    raise AssertionError("cancelled OAuth credential became activatable")

                app_module.revoke_oauth_token = successful_revoke
                retried = app_module.oauth_pending_credential_revoke(
                    str(cancelled_pending["id"]),
                    identity,
                )
                if not retried.get("ok") or db.get_pending_oauth_credential(str(cancelled_pending["id"])) is not None:
                    raise AssertionError(f"OAuth revocation retry did not delete token material: {retried}")
                if [provider for provider, _ in revoked_tokens] != ["google", "google"]:
                    raise AssertionError(f"OAuth revocation used the wrong provider identity: {revoked_tokens}")
            finally:
                app_module.revoke_oauth_token = original_revoke_oauth_token
                with db.connect() as conn:
                    for terminal_id in terminal_ids:
                        conn.execute("DELETE FROM pending_oauth_credentials WHERE id = ?", (terminal_id,))
        finally:
            app_module.exchange_authorization_code = original_exchange_for_pending
            app_module.CONTROL_PLANE_TWO_PERSON_REQUIRED = original_two_person_required
            app_module.CONTROL_PLANE_TWO_PERSON_ACTIONS = original_two_person_actions

        disconnect_id = x_credentials[0]["id"]
        disconnect_route = db.create_route(
            {
                "name": "OAuth disconnect fail-closed route",
                "enabled": True,
                "match_host": "disconnect.example.test",
                "match_path_prefix": "/",
                "credential_id": disconnect_id,
                "injection": {"type": "bearer", "field": "access_token"},
                "policies": [],
            }
        )
        original_disconnect_revoke = app_module.revoke_oauth_token
        disconnect_attempts: list[tuple[str, dict[str, object], str]] = []

        def failed_disconnect_revoke(*, provider_id: str, token_secret: dict[str, object]):
            retained = db.get_credential(
                disconnect_id,
                include_secret=True,
                include_inactive=True,
            )
            if retained is None or retained.get("lifecycle_status") != "revocation_pending":
                raise AssertionError("OAuth credential was deleted or remained active before provider revocation")
            if db.get_credential(disconnect_id, include_secret=True) is not None:
                raise AssertionError("OAuth credential remained leaseable during provider revocation")
            disconnect_attempts.append((provider_id, dict(token_secret), "failed"))
            raise oauth.OAuthError("provider revocation temporarily unavailable")

        app_module.revoke_oauth_token = failed_disconnect_revoke
        try:
            app_module.delete_credential(disconnect_id, None, identity)
        except app_module.HTTPException as exc:
            if (
                exc.status_code != 503
                or not isinstance(exc.detail, dict)
                or exc.detail.get("retryable") is not True
                or exc.detail.get("lifecycleStatus") != "revocation_failed"
            ):
                raise AssertionError(f"OAuth disconnect did not fail closed and retryable: {exc.detail}") from exc
        else:
            raise AssertionError("OAuth disconnect deleted local material after provider revocation failed")
        retained_disconnect = next(
            (item for item in db.list_credentials() if item["id"] == disconnect_id),
            None,
        )
        if (
            retained_disconnect is None
            or retained_disconnect.get("lifecycle_status") != "revocation_failed"
            or "temporarily unavailable" not in str(retained_disconnect.get("revocation_error"))
        ):
            raise AssertionError(f"failed OAuth disconnect was not retained for retry: {retained_disconnect}")
        if db.get_credential(disconnect_id, include_secret=True) is not None:
            raise AssertionError("revocation-failed OAuth credential was available through the normal read path")
        with db.credential_lease_snapshot(disconnect_id) as failed_snapshot:
            if failed_snapshot is not None:
                raise AssertionError("revocation-failed OAuth credential was available to a final lease snapshot")
        if db.get_route(disconnect_route["id"])["credential_id"] != disconnect_id:
            raise AssertionError("failed OAuth disconnect removed the policy reference needed for retry")
        try:
            db.delete_credential(disconnect_id)
        except db.ManagedOAuthCredentialError:
            pass
        else:
            raise AssertionError("direct database deletion bypassed managed OAuth provider revocation")

        def successful_disconnect_revoke(*, provider_id: str, token_secret: dict[str, object]):
            retained = db.get_credential(
                disconnect_id,
                include_secret=True,
                include_inactive=True,
            )
            if retained is None or retained.get("lifecycle_status") != "revocation_pending":
                raise AssertionError("OAuth revocation retry lost its retained provider material")
            disconnect_attempts.append((provider_id, dict(token_secret), "revoked"))
            return {"provider": provider_id, "revoked": True}

        app_module.revoke_oauth_token = successful_disconnect_revoke
        try:
            disconnected = app_module.delete_credential(disconnect_id, None, identity)
        finally:
            app_module.revoke_oauth_token = original_disconnect_revoke
        if disconnected != {"deleted": True, "providerRevoked": True}:
            raise AssertionError(f"OAuth disconnect retry did not report provider revocation: {disconnected}")
        if db.get_credential(disconnect_id, include_secret=True, include_inactive=True) is not None:
            raise AssertionError("successfully revoked OAuth credential remained in local storage")
        if db.get_route(disconnect_route["id"])["credential_id"] is not None:
            raise AssertionError("successful OAuth disconnect did not clear the route credential reference")
        if [attempt[0] for attempt in disconnect_attempts] != ["x", "x"]:
            raise AssertionError(f"OAuth disconnect used the wrong provider: {disconnect_attempts}")
        for _, token_secret, _ in disconnect_attempts:
            if (
                token_secret.get("access_token") != "x-access-token-value"
                or token_secret.get("refresh_token") != "x-refresh-token-value"
            ):
                raise AssertionError("OAuth disconnect did not retain the exact provider token for retry")

        original_exchange_authorization_code = app_module.exchange_authorization_code
        app_module.exchange_authorization_code = lambda **kwargs: {
            "name": "Malformed OAuth scopes",
            "kind": "oauth2",
            "secret": json.dumps(
                {
                    "access_token": "malformed-scope-access-token",
                    "refresh_token": "malformed-scope-refresh-token",
                    "token_type": "Bearer",
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            "metadata": {"scopes": ["scope.metadata"]},
            "provider": "google",
            "scopes": ["scope.provider"],
        }
        original_malformed_revoke = app_module.revoke_oauth_token
        app_module.revoke_oauth_token = lambda **kwargs: (_ for _ in ()).throw(
            oauth.OAuthError("provider revocation unavailable during callback rejection")
        )
        try:
            malformed_response = app_module.oauth_callback(
                "google",
                oauth_request(str(x_start["state"]), "m" * 43),
                code="malformed-code",
                state="malformed-state",
            )
        finally:
            app_module.exchange_authorization_code = original_exchange_authorization_code
            app_module.revoke_oauth_token = original_malformed_revoke
        if malformed_response.status_code != 400 or b"does not match" not in malformed_response.body:
            raise AssertionError(f"mismatched provider/metadata scopes did not fail closed: {malformed_response.body!r}")
        if any(item["name"] == "Malformed OAuth scopes" for item in db.list_credentials()):
            raise AssertionError("OAuth callback persisted a credential with mismatched granted scopes")
        with db.connect() as conn:
            malformed_work = conn.execute(
                "SELECT * FROM oauth_revocation_work WHERE source = ?",
                ("callback_validation",),
            ).fetchall()
        if len(malformed_work) != 1 or malformed_work[0]["status"] != "pending":
            raise AssertionError(
                f"callback validation failure did not retain encrypted revocation work: {malformed_work}"
            )
        malformed_work_id = str(malformed_work[0]["id"])
        malformed_work_text = json.dumps(dict(malformed_work[0]), sort_keys=True)
        if "malformed-scope-access-token" in malformed_work_text:
            raise AssertionError("callback revocation work disclosed provider token material")
        with db.connect() as conn:
            conn.execute(
                "UPDATE oauth_revocation_work SET next_attempt_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00+00:00", malformed_work_id),
            )
        app_module.revoke_oauth_token = lambda **kwargs: {
            "provider": kwargs["provider_id"],
            "revoked": True,
        }
        try:
            malformed_reconcile = app_module._reconcile_oauth_revocations(limit=1)
        finally:
            app_module.revoke_oauth_token = original_malformed_revoke
        if malformed_reconcile != {"claimed": 1, "revoked": 1, "failed": 0}:
            raise AssertionError(f"callback revocation retry did not drain work: {malformed_reconcile}")
        with db.connect() as conn:
            if conn.execute(
                "SELECT 1 FROM oauth_revocation_work WHERE id = ?",
                (malformed_work_id,),
            ).fetchone() is not None:
                raise AssertionError("reconciled callback revocation work remained queued")

        flow = SimpleNamespace(request=SimpleNamespace(headers={}, query={}))
        policy = SimpleNamespace(injection={"type": "bearer", "field": "access_token", "header": "Authorization"})
        reason = _inject_credential(flow, policy, stored)
        if flow.request.headers.get("Authorization") != "Bearer access-token-value":
            raise AssertionError(f"OAuth access token field was not injected: {flow.request.headers}, reason={reason}")

        try:
            _inject_credential(
                SimpleNamespace(request=SimpleNamespace(headers={}, query={})),
                SimpleNamespace(injection={"type": "bearer", "field": "missing"}),
                stored,
            )
        except ValueError as exc:
            if "canonical access-token-only bearer" not in str(exc):
                raise AssertionError(f"missing field failed with wrong error: {exc}") from exc
        else:
            raise AssertionError("missing OAuth token field did not fail closed")

        try:
            _inject_credential(
                SimpleNamespace(request=SimpleNamespace(headers={}, query={})),
                SimpleNamespace(injection={"type": "bearer", "field": "*.access_token"}),
                stored,
            )
        except ValueError as exc:
            if "canonical access-token-only bearer" not in str(exc):
                raise AssertionError(f"wildcard field failed with wrong error: {exc}") from exc
        else:
            raise AssertionError("wildcard OAuth token field did not fail closed")

        expired_secret = json.loads(stored["secret"])
        expired_secret["expires_at_epoch_ms"] = 1
        expired_metadata = {**listed["metadata"], "expires_at_epoch_ms": 1}
        expired, expired_rotated = db.update_credential_secret_if_version(
            listed["id"],
            expected_version=int(stored["credential_version"]),
            secret=json.dumps(expired_secret, separators=(",", ":"), sort_keys=True),
            metadata=expired_metadata,
        )
        if expired is None or not expired_rotated:
            raise AssertionError("OAuth expiry fixture did not rotate through the dedicated refresh path")
        app_module.runtime.invalidate_secret_leases(listed["id"])
        original_refresh_access_token = app_module.refresh_access_token
        app_module.refresh_access_token = lambda **kwargs: {
            "secret": json.dumps({**expired_secret, "access_token": "must-not-persist"}),
            "revocationSecret": json.dumps(
                {"access_token": "must-not-persist", "token_type": "Bearer"},
                separators=(",", ":"),
                sort_keys=True,
            ),
            "metadata": {**expired_metadata, "scopes": "not-an-array"},
            "expiresAtEpochMs": int(time.time() * 1000) + 3_600_000,
            "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
            "refreshTokenRotated": False,
        }
        original_refresh_rejection_revoke = app_module.revoke_oauth_token
        rejected_refresh_material: list[dict[str, object]] = []

        def revoke_rejected_refresh(*, provider_id: str, token_secret: dict[str, object]):
            rejected_refresh_material.append(dict(token_secret))
            return {"provider": provider_id, "revoked": True}

        app_module.revoke_oauth_token = revoke_rejected_refresh
        try:
            app_module._credential_for_lease(listed["id"])
        except app_module.HTTPException as exc:
            if exc.status_code != 503:
                raise AssertionError(f"malformed refreshed scopes failed with wrong status: {exc.status_code}") from exc
        else:
            raise AssertionError("malformed refreshed OAuth scopes were persisted")
        finally:
            app_module.refresh_access_token = original_refresh_access_token
            app_module.revoke_oauth_token = original_refresh_rejection_revoke
        if rejected_refresh_material != [
            {"access_token": "must-not-persist", "token_type": "Bearer"}
        ]:
            raise AssertionError(
                f"post-refresh validation failure did not revoke only issued material: "
                f"{rejected_refresh_material}"
            )
        rejected_refresh = db.get_credential(listed["id"], include_secret=True)
        if (
            int(rejected_refresh["credential_version"]) != int(expired["credential_version"])
            or json.loads(rejected_refresh["secret"])["access_token"] == "must-not-persist"
        ):
            raise AssertionError("malformed refreshed OAuth scope claims changed the stored credential")
        refresh_calls = 0
        refresh_calls_lock = threading.Lock()

        def fake_refresh_token_request(provider, body, headers):
            nonlocal refresh_calls
            if provider.id != "google":
                raise AssertionError(f"unexpected refresh provider: {provider.id}")
            if body != {
                "grant_type": "refresh_token",
                "refresh_token": "refresh-token-value",
                "client_id": "google-client",
                "client_secret": "google-secret",
            }:
                raise AssertionError(f"Google refresh request was malformed: {body}")
            if "Authorization" in headers:
                raise AssertionError("Google client_secret_post refresh unexpectedly used Basic auth")
            with refresh_calls_lock:
                refresh_calls += 1
            time.sleep(0.03)
            return {
                "access_token": "refreshed-access-token",
                "expires_in": 3600,
            }

        oauth._post_token_request = fake_refresh_token_request
        with ThreadPoolExecutor(max_workers=8) as executor:
            refreshed_credentials = list(executor.map(lambda _: app_module._credential_for_lease(listed["id"]), range(8)))
        if refresh_calls != 1:
            raise AssertionError(f"concurrent OAuth lease refresh was not single-flight: calls={refresh_calls}")
        refreshed_versions = {item["credential_version"] for item in refreshed_credentials if item}
        if len(refreshed_versions) != 1 or next(iter(refreshed_versions)) <= int(expired["credential_version"]):
            raise AssertionError(f"OAuth refresh did not rotate the credential version: {refreshed_versions}")
        refreshed_stored = db.get_credential(listed["id"], include_secret=True)
        refreshed_secret = json.loads(refreshed_stored["secret"])
        if (
            refreshed_secret.get("access_token") != "refreshed-access-token"
            or refreshed_secret.get("refresh_token") != "refresh-token-value"
            or refreshed_secret.get("token_type") != "Bearer"
            or refreshed_secret.get("scope") != "https://www.googleapis.com/auth/gmail.readonly"
        ):
            raise AssertionError("OAuth refresh did not preserve omitted token bindings while rotating material")

        stale_result, stale_updated = db.update_credential_secret_if_version(
            listed["id"],
            expected_version=int(expired["credential_version"]),
            secret=json.dumps({**refreshed_secret, "access_token": "stale-writer-token"}, sort_keys=True),
            metadata=refreshed_stored["metadata"],
        )
        if stale_updated or json.loads(stale_result["secret"])["access_token"] != "refreshed-access-token":
            raise AssertionError("stale OAuth refresh writer replaced a newer credential version")

        oauth._post_token_request = lambda provider, body, headers: {
            "access_token": "expanded-scope-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive",
            "expires_in": 3600,
        }
        try:
            oauth.refresh_access_token(
                provider_id="google",
                token_secret=refreshed_secret,
                metadata=refreshed_stored["metadata"],
                now_epoch=int(time.time()),
            )
        except oauth.OAuthError as exc:
            if "scope" not in str(exc):
                raise AssertionError(f"expanded OAuth scope failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("OAuth refresh expanded the credential scope binding")

        def reconcile_failed_refresh(
            *,
            expected_access_token: str,
            expected_refresh_token: str | None,
        ) -> None:
            with db.connect() as conn:
                work_rows = conn.execute(
                    "SELECT * FROM oauth_revocation_work WHERE source = ?",
                    ("refresh_token_exchange",),
                ).fetchall()
            if len(work_rows) != 1 or work_rows[0]["status"] != "pending":
                raise AssertionError(f"failed OAuth refresh was not durably retryable: {work_rows}")
            serialized_work = json.dumps(dict(work_rows[0]), sort_keys=True)
            if expected_access_token in serialized_work or (
                expected_refresh_token and expected_refresh_token in serialized_work
            ):
                raise AssertionError("failed OAuth refresh persisted issued material without encryption")
            revoked_refresh_material: list[dict[str, object]] = []
            original_failed_refresh_revoke = app_module.revoke_oauth_token

            def revoke_failed_refresh(*, provider_id: str, token_secret: dict[str, object]):
                revoked_refresh_material.append(dict(token_secret))
                return {"provider": provider_id, "revoked": True}

            app_module.revoke_oauth_token = revoke_failed_refresh
            try:
                reconciled = app_module._reconcile_oauth_revocations(limit=1)
            finally:
                app_module.revoke_oauth_token = original_failed_refresh_revoke
            if reconciled != {"claimed": 1, "revoked": 1, "failed": 0}:
                raise AssertionError(f"failed OAuth refresh did not reconcile: {reconciled}")
            if len(revoked_refresh_material) != 1:
                raise AssertionError("failed OAuth refresh did not revoke one issued grant")
            material = revoked_refresh_material[0]
            if material.get("access_token") != expected_access_token:
                raise AssertionError(f"failed OAuth refresh lost its issued access token: {material}")
            if material.get("refresh_token") != expected_refresh_token:
                raise AssertionError(
                    f"failed OAuth refresh revoked the wrong refresh-token material: {material}"
                )

        reconcile_failed_refresh(
            expected_access_token="expanded-scope-token",
            expected_refresh_token="rotated-refresh-token",
        )

        for malformed_claim, malformed_value in (
            ("token_type", ""),
            ("token_type", []),
            ("scope", ""),
            ("scope", []),
        ):
            malformed_kind = "empty" if malformed_value == "" else "non-string"
            malformed_access_token = f"malformed-refresh-{malformed_claim}-{malformed_kind}"
            malformed_response: dict[str, object] = {
                "access_token": malformed_access_token,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
                "expires_in": 3600,
            }
            malformed_response[malformed_claim] = malformed_value
            oauth._post_token_request = lambda provider, body, headers, response=malformed_response: response
            try:
                oauth.refresh_access_token(
                    provider_id="google",
                    token_secret=refreshed_secret,
                    metadata=refreshed_stored["metadata"],
                    now_epoch=int(time.time()),
                )
            except oauth.OAuthError as exc:
                if malformed_claim.replace("_", " ") not in str(exc):
                    raise AssertionError(
                        f"{malformed_kind} OAuth refresh {malformed_claim} failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"{malformed_kind} OAuth refresh {malformed_claim} was silently replaced"
                )
            reconcile_failed_refresh(
                expected_access_token=malformed_access_token,
                expected_refresh_token=None,
            )

        oauth._post_token_request = lambda provider, body, headers: {
            "access_token": "reduced-scope-token",
            "token_type": "Bearer",
            "scope": "https://www.googleapis.com/auth/gmail.readonly",
            "expires_in": 3600,
        }
        try:
            oauth.refresh_access_token(
                provider_id="google",
                token_secret={
                    **refreshed_secret,
                    "scope": "https://www.googleapis.com/auth/gmail.readonly openid",
                },
                metadata={
                    **refreshed_stored["metadata"],
                    "scopes": ["https://www.googleapis.com/auth/gmail.readonly", "openid"],
                },
                now_epoch=int(time.time()),
            )
        except oauth.OAuthError as exc:
            if "scope" not in str(exc):
                raise AssertionError(f"reduced OAuth scope failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("OAuth refresh reduced the credential scope binding")
        reconcile_failed_refresh(
            expected_access_token="reduced-scope-token",
            expected_refresh_token=None,
        )

        audits = db.list_audit_events(limit=1000)
        audit_text = json.dumps(audits, sort_keys=True)
        if (
            "access-token-value" in audit_text
            or "refresh-token-value" in audit_text
            or "x-access-token-value" in audit_text
            or "x-refresh-token-value" in audit_text
            or "auth-code" in audit_text
            or "x-auth-code" in audit_text
        ):
            raise AssertionError("OAuth audit events leaked token or auth-code material")
        event_types = {item["event_type"] for item in audits}
        if {
            "credential.oauth_authorization_started",
            "credential.oauth_connected",
            "credential.oauth_reconnected",
            "credential.oauth_revocation_failed",
            "credential.oauth_disconnected",
            "credential.oauth_refreshed",
        } - event_types:
            raise AssertionError(f"OAuth audit events missing: {event_types}")

    print(json.dumps({"oauth_credentials": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1:] == ["--compose-contract-only"]:
        verify_compose_oauth_contract()
        print(json.dumps({"oauth_compose_contract": "pass", "ok": True}, sort_keys=True))
    elif sys.argv[1:] == ["--setup-session-only"]:
        main(setup_session_only=True)
    else:
        main()
