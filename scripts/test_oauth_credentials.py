#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.parse
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
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "test-google-client",
            "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(google_secret),
            "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": "https://serverware.test/api/oauth/callback/google",
            "SERVERWARE_X_OAUTH_CLIENT_ID": "test-x-client",
            "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE": str(x_secret),
            "SERVERWARE_X_OAUTH_REDIRECT_URI": "https://serverware.test/api/oauth/callback/x",
        }
    )
    config_probe(base_env)

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


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        run_config_secret_file_tests(Path(tmp))
        if compose_manifests_available():
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
        from serverware import app as app_module
        from serverware.auth import AdminIdentity

        if "mitmproxy" not in sys.modules:
            mitmproxy_module = types.ModuleType("mitmproxy")
            http_module = types.ModuleType("mitmproxy.http")
            mitmproxy_module.http = http_module
            sys.modules["mitmproxy"] = mitmproxy_module
            sys.modules["mitmproxy.http"] = http_module
        from serverware.policy_engine import _inject_credential

        db.init_db()
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

        providers = app_module.oauth_providers(identity)["providers"]
        google = next(item for item in providers if item["id"] == "google")
        if not google["configured"] or google["recommendedInjection"].get("field") != "access_token":
            raise AssertionError(f"google provider status is not usable: {google}")
        x_provider = next(item for item in providers if item["id"] == "x")
        if not x_provider["configured"]:
            raise AssertionError(f"x provider status is not usable: {x_provider}")
        if replace(oauth.provider_for("google"), client_secret="").configured:
            raise AssertionError("OAuth provider with an incomplete client secret was marked configured")

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
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
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
        if secret["access_token"] != "access-token-value" or secret["refresh_token"] != "refresh-token-value":
            raise AssertionError("encrypted OAuth credential did not preserve token response")
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

        original_exchange_authorization_code = app_module.exchange_authorization_code
        app_module.exchange_authorization_code = lambda **kwargs: {
            "name": "Malformed OAuth scopes",
            "kind": "oauth2",
            "secret": "must-not-persist",
            "metadata": {"scopes": ["scope.metadata"]},
            "provider": "google",
            "scopes": ["scope.provider"],
        }
        malformed_response = app_module.oauth_callback(
            "google",
            oauth_request(str(x_start["state"]), "m" * 43),
            code="malformed-code",
            state="malformed-state",
        )
        app_module.exchange_authorization_code = original_exchange_authorization_code
        if malformed_response.status_code != 400 or b"does not match" not in malformed_response.body:
            raise AssertionError(f"mismatched provider/metadata scopes did not fail closed: {malformed_response.body!r}")
        if any(item["name"] == "Malformed OAuth scopes" for item in db.list_credentials()):
            raise AssertionError("OAuth callback persisted a credential with mismatched granted scopes")

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
            if "missing field" not in str(exc):
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
            if "dotted object path" not in str(exc):
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
            "metadata": {**expired_metadata, "scopes": "not-an-array"},
            "expiresAtEpochMs": int(time.time() * 1000) + 3_600_000,
            "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
            "refreshTokenRotated": False,
        }
        try:
            app_module._credential_for_lease(listed["id"])
        except app_module.HTTPException as exc:
            if exc.status_code != 503:
                raise AssertionError(f"malformed refreshed scopes failed with wrong status: {exc.status_code}") from exc
        else:
            raise AssertionError("malformed refreshed OAuth scopes were persisted")
        finally:
            app_module.refresh_access_token = original_refresh_access_token
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
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/gmail.readonly",
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
        ):
            raise AssertionError("OAuth refresh did not atomically preserve and rotate token material")

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

        audits = db.list_audit_events(limit=20)
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
            "credential.oauth_refreshed",
        } - event_types:
            raise AssertionError(f"OAuth audit events missing: {event_types}")

    print(json.dumps({"oauth_credentials": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    if sys.argv[1:] == ["--compose-contract-only"]:
        verify_compose_oauth_contract()
        print(json.dumps({"oauth_compose_contract": "pass", "ok": True}, sort_keys=True))
    else:
        main()
