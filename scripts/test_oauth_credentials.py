#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
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

        providers = app_module.oauth_providers(identity)["providers"]
        google = next(item for item in providers if item["id"] == "google")
        if not google["configured"] or google["recommendedInjection"].get("field") != "access_token":
            raise AssertionError(f"google provider status is not usable: {google}")
        x_provider = next(item for item in providers if item["id"] == "x")
        if not x_provider["configured"]:
            raise AssertionError(f"x provider status is not usable: {x_provider}")

        try:
            app_module.oauth_start(
                app_module.OAuthStartRequest(
                    provider="google",
                    credentialName="Gmail OAuth - Test",
                    metadata={"blob": "x" * 5000},
                ),
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
                identity=identity,
            )
        except app_module.HTTPException as exc:
            if "credential name is too large" not in str(exc.detail):
                raise AssertionError(f"oversized credential name failed with wrong error: {exc.detail}") from exc
        else:
            raise AssertionError("oversized OAuth credential name was accepted")

        start = app_module.oauth_start(
            app_module.OAuthStartRequest(
                provider="google",
                credentialName="Gmail OAuth - Test",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                metadata={"account": "andrew@example.test"},
            ),
            identity=identity,
        )
        parsed = urllib.parse.urlsplit(start["authorizationUrl"])
        query = dict(urllib.parse.parse_qsl(parsed.query))
        if query.get("code_challenge_method") != "S256" or "code_verifier" in start["authorizationUrl"]:
            raise AssertionError(f"OAuth URL did not use PKCE safely: {start}")
        if query.get("state") != start["state"]:
            raise AssertionError("OAuth URL state does not match returned state")

        state_payload = json.loads((Path(tmp) / "oauth-states.json").read_text())
        state_record = state_payload["states"][start["state"]]
        if state_record.get("code_verifier") in start["authorizationUrl"]:
            raise AssertionError("PKCE verifier leaked into the authorization URL")

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
        response = app_module.oauth_callback("google", code="auth-code", state=start["state"])
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

        stored = db.get_credential(listed["id"], include_secret=True)
        secret = json.loads(stored["secret"])
        if secret["access_token"] != "access-token-value" or secret["refresh_token"] != "refresh-token-value":
            raise AssertionError("encrypted OAuth credential did not preserve token response")

        try:
            oauth.exchange_authorization_code(provider_id="google", code="auth-code-2", state=start["state"])
        except oauth.OAuthError as exc:
            if "unknown or expired" not in str(exc):
                raise AssertionError(f"state replay failed with wrong error: {exc}") from exc
        else:
            raise AssertionError("OAuth state replay was accepted")

        x_start = app_module.oauth_start(
            app_module.OAuthStartRequest(
                provider="twitter",
                credentialName="X OAuth - Test",
                scopes=["tweet.read", "users.read", "offline.access"],
            ),
            identity=identity,
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
        x_response = app_module.oauth_callback("x", code="x-auth-code", state=x_start["state"])
        if x_response.status_code != 200:
            raise AssertionError(f"X OAuth callback failed: {x_response.status_code} {x_response.body!r}")
        x_credentials = [item for item in db.list_credentials() if item["name"] == "X OAuth - Test"]
        if len(x_credentials) != 1 or x_credentials[0]["metadata"].get("provider") != "x.oauth2":
            raise AssertionError(f"X OAuth credential was not created with provider metadata: {x_credentials}")

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
        if {"credential.oauth_authorization_started", "credential.oauth_connected"} - event_types:
            raise AssertionError(f"OAuth audit events missing: {event_types}")

    print(json.dumps({"oauth_credentials": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
