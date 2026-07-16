#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.oauth_provider_simulator import OAuthProviderSimulator  # noqa: E402


ADMIN_TOKEN = "browser-oauth-admin-token"
DATA_PLANE_TOKEN = "browser-oauth-credential-lease-token"
DATA_PLANE_DIGEST = "sha256:" + "d" * 64
GOOGLE_NAME = "Browser Gmail OAuth"
X_NAME = "Browser X OAuth"
GOOGLE_SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/gmail.readonly",
]
X_SCOPES = ["tweet.read", "users.read", "offline.access"]
OAUTH_COOKIE_PREFIX = "__Host-serverware-oauth-"
DEFAULT_TIMEOUT_MS = 20_000
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _reserve_https_socket() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.set_inheritable(False)
    return listener


def _configure_environment(
    data_dir: Path, public_url: str, simulator: OAuthProviderSimulator
) -> None:
    values = {
        "SERVERWARE_DATA_DIR": str(data_dir),
        "SERVERWARE_RELEASE_CHANNEL": "dev",
        "SERVERWARE_PUBLIC_URL": public_url,
        "SERVERWARE_WEB_TLS_CERT_FILE": str(simulator.server_cert_path),
        "SERVERWARE_WEB_TLS_KEY_FILE": str(simulator.server_key_path),
        "SERVERWARE_ADMIN_TOKEN": ADMIN_TOKEN,
        "SERVERWARE_ADMIN_USER": "user:browser-operator",
        "SERVERWARE_ADMIN_ROLES": (
            "admin,approver,auditor,policy_author,policy_publisher,credential_owner,"
            "attestation_operator,attestation_reviewer"
        ),
        "SERVERWARE_DEV_AUTHENTICATOR": "1",
        "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
        "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
        "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
        "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
        "SERVERWARE_OIDC_ENABLED": "0",
        "SERVERWARE_OIDC_BROWSER_LOGIN_ENABLED": "0",
        "SERVERWARE_CONTROL_PLANE_TWO_PERSON_REQUIRED": "0",
        "SERVERWARE_CONTROL_PLANE_MUTATION_WEBAUTHN_REQUIRED": "0",
        "SERVERWARE_CONTROL_PLANE_MUTATION_REQUIRE_HARDWARE_ATTESTATION": "0",
        "SERVERWARE_POLICY_PUBLISH_DRY_RUN_REQUIRED": "1",
        "SERVERWARE_POLICY_CANARY_REQUIRED": "0",
        "SERVERWARE_POLICY_CANARY_MIN_OBSERVATION_SECONDS": "0",
        "SERVERWARE_POLICY_CANARY_MIN_AUDIT_EVENTS": "0",
        "SERVERWARE_POLICY_CANARY_MAX_DENIALS": "0",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": simulator.GOOGLE_CLIENT_ID,
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET": simulator.GOOGLE_CLIENT_SECRET,
        "SERVERWARE_GOOGLE_OAUTH_REDIRECT_URI": f"{public_url}/api/oauth/callback/google",
        "SERVERWARE_X_OAUTH_CLIENT_ID": simulator.X_CLIENT_ID,
        "SERVERWARE_X_OAUTH_CLIENT_SECRET": simulator.X_CLIENT_SECRET,
        "SERVERWARE_X_OAUTH_REDIRECT_URI": f"{public_url}/api/oauth/callback/x",
        "SERVERWARE_WEBAUTHN_RP_ID": "serverware.test",
        "SERVERWARE_WEBAUTHN_ORIGIN": public_url,
        "SERVERWARE_DATA_PLANE_INSTANCE_ID": (
            "spiffe://test.serverware/decision-gate/browser-oauth"
        ),
        "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": DATA_PLANE_TOKEN,
        "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": DATA_PLANE_DIGEST,
        "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
        "SERVERWARE_AUDIT_ANCHOR_URL": "",
        "SERVERWARE_DECISION_GATE_BASE": "",
        "SSL_CERT_FILE": str(simulator.ca_cert_path),
        "NO_PROXY": "serverware.test,127.0.0.1,localhost",
        "no_proxy": "serverware.test,127.0.0.1,localhost",
    }
    for name in (
        "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
        "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
        "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_ID",
        "SERVERWARE_TWITTER_OAUTH_CLIENT_SECRET",
        "SERVERWARE_TWITTER_OAUTH_REDIRECT_URI",
    ):
        os.environ.pop(name, None)
    os.environ.update(values)


def _certificate_spki_sha256(cert_path: Path) -> str:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    spki = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def _assert_simulator_contract(simulator: OAuthProviderSimulator) -> None:
    _require(
        simulator.redirect_base_url.startswith("https://serverware.test:"),
        "simulator did not retain the configured HTTPS callback origin",
    )
    certificate = x509.load_pem_x509_certificate(
        simulator.server_cert_path.read_bytes()
    )
    san = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value
    dns_names = set(san.get_values_for_type(x509.DNSName))
    ip_addresses = {str(value) for value in san.get_values_for_type(x509.IPAddress)}
    _require(
        "serverware.test" in dns_names,
        "simulator certificate lacks serverware.test SAN",
    )
    _require("localhost" in dns_names, "simulator certificate lost its localhost SAN")
    _require(
        "127.0.0.1" in ip_addresses, "simulator certificate lost its loopback IP SAN"
    )


def _assert_redirect_validation(work_dir: Path) -> None:
    default = OAuthProviderSimulator(work_dir / "default-contract")
    _require(
        default.redirect_base_url == "https://serverware.test",
        "simulator default redirect origin changed",
    )
    invalid_origins = (
        "http://serverware.test",
        "https://serverware.test/path",
        "https://serverware.test?query=1",
        "https://user@serverware.test",
        "https://serverware.test#fragment",
        "https://serverware.test:70000",
        " https://serverware.test",
        "https://serverware.test.",
    )
    for index, origin in enumerate(invalid_origins):
        try:
            OAuthProviderSimulator(
                work_dir / f"invalid-{index}", redirect_base_url=origin
            )
        except ValueError:
            continue
        raise AssertionError(
            f"simulator accepted an unsafe redirect origin: {origin!r}"
        )


class _UvicornThread:
    def __init__(
        self, app: Any, listener: socket.socket, simulator: OAuthProviderSimulator
    ) -> None:
        try:
            import uvicorn
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "uvicorn is unavailable; run this script with the repository requirements.lock"
            ) from exc
        self._listener = listener
        self._error: BaseException | None = None
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=int(listener.getsockname()[1]),
                ssl_certfile=str(simulator.server_cert_path),
                ssl_keyfile=str(simulator.server_key_path),
                log_level="warning",
                access_log=False,
                proxy_headers=False,
                server_header=False,
                lifespan="on",
            )
        )
        self._thread = threading.Thread(
            target=self._run,
            name="serverware-browser-oauth-portal",
            daemon=True,
        )

    def _run(self) -> None:
        try:
            self._server.run(sockets=[self._listener])
        except BaseException as exc:  # pragma: no cover - surfaced to the caller
            self._error = exc

    def start(self) -> None:
        self._thread.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self._server.started:
                return
            if self._error is not None:
                raise RuntimeError(
                    "HTTPS portal failed during startup"
                ) from self._error
            if not self._thread.is_alive():
                raise RuntimeError("HTTPS portal stopped before startup completed")
            time.sleep(0.05)
        raise TimeoutError("HTTPS portal did not become ready")

    def close(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=20)
        if self._thread.is_alive():
            self._server.force_exit = True
            self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("HTTPS portal did not stop")
        if self._error is not None:
            raise RuntimeError("HTTPS portal failed") from self._error


def _api_json(page: Any, path: str) -> Any:
    result = page.evaluate(
        """
        async (path) => {
          const token = document.querySelector('#admin-token')?.value || '';
          const response = await fetch(path, {
            headers: {
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            credentials: 'same-origin',
            cache: 'no-store'
          });
          const text = await response.text();
          return {status: response.status, text};
        }
        """,
        path,
    )
    if result["status"] != 200:
        raise AssertionError(
            f"GET {path} returned HTTP {result['status']}: {result['text'][:500]}"
        )
    return json.loads(result["text"])


def _wait_for_api(
    page: Any,
    path: str,
    predicate: Callable[[Any], bool],
    *,
    timeout_seconds: float = 20,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last: Any = None
    while time.monotonic() < deadline:
        last = _api_json(page, path)
        if predicate(last):
            return last
        time.sleep(0.1)
    raise AssertionError(f"GET {path} did not reach the expected state: {last!r}")


def _credential_by_name(bootstrap: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item for item in bootstrap.get("credentials", []) if item.get("name") == name
    ]
    _require(len(matches) == 1, f"expected exactly one credential named {name!r}")
    return matches[0]


def _assert_public_credential(
    credential: dict[str, Any],
    *,
    provider: str,
    subject: str,
    account: str,
    scopes: list[str],
) -> None:
    metadata = credential.get("metadata") or {}
    _require(
        credential.get("kind") == "oauth2", f"{provider} credential kind is not oauth2"
    )
    _require(
        metadata.get("oauth") is True, f"{provider} credential is not managed OAuth"
    )
    _require(
        metadata.get("provider_id") == provider,
        f"{provider} credential provider mismatch",
    )
    _require(
        metadata.get("provider_subject") == subject,
        f"{provider} credential subject was not callback-verified",
    )
    _require(
        metadata.get("provider_account") == account,
        f"{provider} credential account was not callback-verified",
    )
    _require(
        metadata.get("provider_identity_verified") is True,
        f"{provider} credential identity is not marked verified",
    )
    _require(
        set(metadata.get("scopes") or []) == set(scopes),
        f"{provider} credential granted scopes mismatch",
    )
    forbidden_keys = {
        "secret",
        "encrypted_secret",
        "ciphertext",
        "access_token",
        "refresh_token",
        "client_secret",
        "code_verifier",
    }

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            overlap = forbidden_keys.intersection(value)
            _require(
                not overlap,
                f"public credential exposed secret-bearing keys: {sorted(overlap)}",
            )
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(credential)


def _wait_for_portal(
    page: Any, public_url: str, *, expected_url: str | None = None
) -> None:
    expected = expected_url or (public_url + "/")
    page.wait_for_url(
        re.compile(rf"^{re.escape(expected)}(?:\?.*)?$"), timeout=DEFAULT_TIMEOUT_MS
    )
    page.locator("#oauth-form").wait_for(state="visible", timeout=DEFAULT_TIMEOUT_MS)
    page.wait_for_function(
        """
        () => document.querySelector('#operator-auth-status')?.textContent === 'Token session'
          && document.querySelectorAll('#oauth-provider option').length === 2
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )


def _assert_no_oauth_cookies(context: Any) -> None:
    cookies = context.cookies()
    residue = [
        item["name"] for item in cookies if item["name"].startswith(OAUTH_COOKIE_PREFIX)
    ]
    _require(
        not residue, f"OAuth state cookies survived callback consumption: {residue}"
    )


def _assert_no_horizontal_overflow(page: Any, *, label: str) -> None:
    dimensions = page.evaluate(
        """
        () => ({
          viewportWidth: window.innerWidth,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body.scrollWidth
        })
        """
    )
    maximum = max(dimensions["documentWidth"], dimensions["bodyWidth"])
    _require(
        maximum <= dimensions["viewportWidth"] + 1,
        f"{label} portal overflows horizontally: {dimensions}",
    )


def _assert_stripe_uses_manual_credential_flow(
    page: Any, browser_observations: list[dict[str, Any]]
) -> None:
    oauth_requests_before = sum(
        1
        for item in browser_observations
        if item.get("type") == "request" and "/api/oauth/" in item.get("url", "")
    )
    oauth_state_before = page.evaluate(
        """
        () => ({
          provider: document.querySelector('#oauth-provider')?.value || '',
          draft: sessionStorage.getItem('serverware.oauthDraft'),
          setupSessionId: state.oauthSetupSessionId
        })
        """
    )
    credential_form_before = {
        "name": page.locator("#credential-name").input_value(),
        "kind": page.locator("#credential-kind").input_value(),
        "metadata": page.locator("#credential-metadata").input_value(),
    }

    page.locator("#setup-template").select_option("stripe_payment_intent_jit")
    page.locator("#setup-principal").select_option("agent:demo")
    # The setup action records a durable run against an active route before it opens
    # the credential form. Reuse a seeded route only for this UI-path assertion.
    page.locator("#setup-route-id").fill("demo.echo")
    page.wait_for_function(
        """
        () => document.querySelector('#setup-template')?.value === 'stripe_payment_intent_jit'
          && document.querySelector('#setup-connect-button')?.textContent === 'Add credential'
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )

    setup_credential = page.locator("#setup-credential")
    unrelated_bearer = setup_credential.locator(
        "option[value='cred-demo-bearer']"
    )
    _require(
        unrelated_bearer.count() == 1 and unrelated_bearer.is_disabled(),
        "Stripe setup did not reject the unrelated seeded bearer credential",
    )
    _require(
        setup_credential.input_value() == "",
        "Stripe setup silently selected an unrelated bearer credential",
    )
    _require(
        page.locator("#oauth-provider option[value='stripe']").count() == 0,
        "Stripe was incorrectly exposed as an OAuth provider",
    )
    add_credential = page.get_by_role("button", name="Add credential", exact=True)
    _require(add_credential.is_enabled(), "Stripe manual credential action is disabled")
    add_credential.click()
    page.wait_for_function(
        """
        () => {
          try {
            const metadata = JSON.parse(document.querySelector('#credential-metadata')?.value || '{}');
            return document.querySelector('#credential-kind')?.value === 'bearer'
              && metadata.provider === 'stripe'
              && new URL(window.location.href).searchParams.has('setup');
          } catch (_) {
            return false;
          }
        }
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    _require(
        page.locator("#credential-name").input_value()
        == "Tokenized PaymentIntent create + hardware JIT credential",
        "Stripe manual credential name was not prefilled",
    )
    _require(
        json.loads(page.locator("#credential-metadata").input_value())
        == {"provider": "stripe"},
        "Stripe provider metadata was not prefilled",
    )
    _require(
        page.evaluate("document.activeElement?.id") == "credential-name",
        "Stripe setup did not focus the manual static credential form",
    )

    stripe_state = page.evaluate(
        """
        () => ({
          sessionId: state.setupSession?.id || null,
          revision: state.setupSession?.revision ?? null,
          oauthSetupSessionId: state.oauthSetupSessionId,
          oauthProvider: document.querySelector('#oauth-provider')?.value || '',
          oauthDraft: sessionStorage.getItem('serverware.oauthDraft')
        })
        """
    )
    _require(stripe_state["sessionId"], "Stripe setup did not create its temporary run")
    _require(
        stripe_state["oauthSetupSessionId"] == oauth_state_before["setupSessionId"],
        "Stripe manual setup was incorrectly attached to OAuth state",
    )
    _require(
        stripe_state["oauthProvider"] == oauth_state_before["provider"]
        and stripe_state["oauthDraft"] == oauth_state_before["draft"],
        "Stripe manual setup changed the selected OAuth provider or draft",
    )
    oauth_requests_after = sum(
        1
        for item in browser_observations
        if item.get("type") == "request" and "/api/oauth/" in item.get("url", "")
    )
    _require(
        oauth_requests_after == oauth_requests_before,
        "Stripe manual setup started an OAuth request",
    )

    cancelled = page.evaluate(
        """
        async ({sessionId, revision}) => {
          const token = document.querySelector('#admin-token')?.value || '';
          const response = await fetch(`/api/setup/sessions/${encodeURIComponent(sessionId)}/cancel`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Serverware-Admin-Token': token,
              'Authorization': `Bearer ${token}`
            },
            credentials: 'same-origin',
            body: JSON.stringify({
              expectedRevision: revision,
              reason: 'Browser Stripe manual credential flow assertion complete'
            })
          });
          return {status: response.status, text: await response.text()};
        }
        """,
        {"sessionId": stripe_state["sessionId"], "revision": stripe_state["revision"]},
    )
    _require(
        200 <= cancelled["status"] < 300,
        f"temporary Stripe setup run could not be cancelled: {cancelled}",
    )
    page.locator("#setup-session").select_option("")
    page.wait_for_function(
        """
        () => !new URL(window.location.href).searchParams.has('setup')
          && state.setupSession === null
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    page.locator("#setup-template").select_option("gmail_recent")
    page.locator("#credential-name").fill(credential_form_before["name"])
    page.locator("#credential-kind").select_option(credential_form_before["kind"])
    page.locator("#credential-metadata").fill(credential_form_before["metadata"])
    page.wait_for_function(
        """
        () => document.querySelector('#setup-template')?.value === 'gmail_recent'
          && document.querySelector('#setup-connect-button')?.textContent === 'Connect credential'
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )


def _connect_oauth(
    page: Any,
    context: Any,
    public_url: str,
    *,
    provider: str,
    name: str,
    scopes: list[str],
    account: str,
) -> dict[str, Any]:
    page.locator("#oauth-provider").select_option(provider)
    page.locator("#oauth-credential-name").fill(name)
    page.locator("#oauth-scopes").fill("\n".join(scopes))
    page.locator("#oauth-metadata").fill(
        json.dumps({"evidence": "deterministic-browser-oauth"}, separators=(",", ":"))
    )
    _require(
        page.locator("#oauth-submit").is_enabled(),
        f"{provider} OAuth submit is disabled",
    )
    page.locator("#oauth-submit").click(no_wait_after=True)
    try:
        page.get_by_role(
            "heading", name="OAuth credential connected", exact=True
        ).wait_for(state="visible", timeout=DEFAULT_TIMEOUT_MS)
    except Exception as exc:
        diagnostic = page.evaluate(
            """
            () => ({
              url: window.location.href,
              heading: document.querySelector('h1,h2')?.textContent || '',
              body: (document.body?.innerText || '').slice(0, 1000)
            })
            """
        )
        raise AssertionError(
            f"{provider} OAuth callback did not succeed: {diagnostic}"
        ) from exc
    page.wait_for_url(
        re.compile(rf"^{re.escape(public_url)}/(?:\?.*)?$"), timeout=DEFAULT_TIMEOUT_MS
    )
    _require(
        page.locator("#admin-token").input_value() == "",
        "manual admin token unexpectedly survived the OAuth navigation",
    )
    page.locator("#admin-token").fill(ADMIN_TOKEN)
    page.locator("#admin-token").dispatch_event("change")
    _wait_for_portal(page, public_url)
    page.wait_for_function(
        """
        ({name, account}) => [...document.querySelectorAll('#credentials tr')].some(
          (row) => row.textContent.includes(name)
            && row.textContent.includes(account)
            && row.textContent.includes('verified identity')
        )
        """,
        arg={"name": name, "account": account},
        timeout=DEFAULT_TIMEOUT_MS,
    )
    _assert_no_oauth_cookies(context)
    bootstrap = _api_json(page, "/api/bootstrap")
    return _credential_by_name(bootstrap, name)


def _preview_stage_activate_policy(
    page: Any,
    *,
    template: str,
    route_id: str,
    credential_id: str,
) -> dict[str, Any]:
    active_before = _api_json(page, "/api/policy")
    _require(
        active_before.get("ready") is True, "demo seed did not install an active policy"
    )
    old_hash = active_before.get("policy_hash")

    page.locator("#policy-template").select_option(template)
    page.locator("#policy-route-id").fill(route_id)
    page.locator("#policy-principal").select_option("agent:demo")
    page.locator("#policy-credential").select_option(credential_id)
    page.locator("#policy-route-form button[type='submit']").click()
    try:
        page.wait_for_function(
            """
            (routeId) => state.policyCandidate?.routeId === routeId
              && state.policyCandidate?.report?.dryRun?.passed === true
              && document.querySelector('#policy-candidate-summary')?.textContent.includes(
                '2/2 dry-run checks passed'
              )
            """,
            arg=route_id,
            timeout=DEFAULT_TIMEOUT_MS,
        )
    except Exception as exc:
        diagnostics = page.evaluate(
            """
            () => ({
              status: document.querySelector('#operator-status')?.textContent || '',
              authStatus: document.querySelector('#operator-auth-status')?.textContent || '',
              candidateSummary: document.querySelector('#policy-candidate-summary')?.textContent || '',
              candidateOutput: document.querySelector('#policy-candidate-output')?.value || '',
              tokenLength: document.querySelector('#admin-token')?.value?.length || 0
            })
            """
        )
        raise AssertionError(
            f"{route_id} candidate preview did not complete: {diagnostics}"
        ) from exc
    preview = json.loads(page.locator("#policy-candidate-output").input_value())
    report = preview.get("candidate") or {}
    checks = (report.get("dryRun") or {}).get("results") or []
    _require(report.get("ok") is True, f"{route_id} candidate preview failed")
    _require(
        (report.get("dryRun") or {}).get("passed") is True
        and len(checks) == 2
        and all(item.get("passed") is True for item in checks),
        f"{route_id} candidate did not pass both allow/deny dry runs",
    )

    page.locator("#policy-stage-button").wait_for(
        state="visible", timeout=DEFAULT_TIMEOUT_MS
    )
    _require(
        page.locator("#policy-stage-button").is_enabled(),
        "validated candidate cannot be staged",
    )
    page.locator("#policy-stage-button").click()
    page.wait_for_function(
        """
        () => {
          try {
            return JSON.parse(document.querySelector('#policy-canary-status')?.value || '{}')
              .canary?.status === 'running';
          } catch (_) {
            return false;
          }
        }
        """,
        timeout=DEFAULT_TIMEOUT_MS,
    )
    _require(
        page.locator("#policy-activate-button").is_enabled(),
        "running canary cannot be activated",
    )
    page.locator("#policy-activate-button").click()
    active_after = _wait_for_api(
        page,
        "/api/policy",
        lambda payload: payload.get("ready") is True
        and payload.get("policy_hash") != old_hash,
    )
    route = next(
        (
            item
            for item in active_after["bundle"].get("routes", [])
            if item.get("id") == route_id
        ),
        None,
    )
    _require(route is not None, f"activated policy omits route {route_id}")
    _require(
        route.get("credentialRef") == credential_id,
        f"{route_id} credential assignment mismatch",
    )
    _require(
        route.get("principals") == ["agent:demo"],
        f"{route_id} principal assignment mismatch",
    )
    return active_after


def _assert_policy_evidence(
    policy: dict[str, Any], google_id: str, x_id: str, simulator: OAuthProviderSimulator
) -> None:
    bundle = policy["bundle"]
    defaults = bundle.get("defaults") or {}
    _require(
        defaults
        == {
            "action": "deny",
            "failMode": "closed",
            "unknownHosts": "block",
            "unknownPaths": "block",
            "validationFailure": "block",
        },
        "activated policy is not fail closed",
    )
    credentials = {item["id"]: item for item in bundle.get("credentials", [])}
    google = credentials.get(google_id) or {}
    x_credential = credentials.get(x_id) or {}
    _require(google.get("provider") == "google", "policy lost Google provider binding")
    _require(
        google.get("providerSubject") == "google-subject-001",
        "policy lost callback-verified Google subject",
    )
    _require(
        set(google.get("scopes") or []) == set(GOOGLE_SCOPES),
        "policy lost Google scopes",
    )
    _require(x_credential.get("provider") == "x", "policy lost X provider binding")
    _require(
        x_credential.get("providerSubject") == "x-subject-001",
        "policy lost callback-verified X subject",
    )
    _require(
        set(x_credential.get("scopes") or []) == set(X_SCOPES), "policy lost X scopes"
    )

    routes = {item["id"]: item for item in bundle.get("routes", [])}
    gmail = routes["browser.gmail.last-30-days"]
    x_search = routes["browser.x.search.seven-days"]
    _require(gmail["match"]["methods"] == ["GET"], "Gmail route is not read-only")
    _require(gmail["adapter"]["type"] == "gmail.v1", "Gmail route adapter mismatch")
    _require(
        gmail["adapter"]["config"].get("maxAgeDays") == 30
        and gmail["adapter"]["config"]["response"].get("validateInternalDate") is True,
        "Gmail route does not enforce and validate the 30-day boundary",
    )
    _require(x_search["match"]["methods"] == ["GET"], "X search route is not read-only")
    _require(
        x_search["adapter"]["config"].get("blockWrites") is True,
        "X search route does not block writes",
    )
    _require(
        x_search["adapter"]["config"].get("appIds") == [simulator.X_CLIENT_ID],
        "X route is not bound to the verified OAuth app",
    )
    _require(
        any(
            item.get("type") == "responseDateWindow" and item.get("maxAgeDays") == 7
            for item in x_search.get("constraints", [])
        ),
        "X route does not validate the seven-day response boundary",
    )


def _capture_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 1440, "height": 1100})
    page.locator(selector).scroll_into_view_if_needed()
    page.evaluate("window.scrollBy(0, -16)")
    page.wait_for_timeout(150)
    page.screenshot(
        path=str(destination),
        type="png",
        full_page=False,
        mask=[page.locator("#admin-token")],
        mask_color="#e8efed",
    )


def _capture_mobile_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator(selector).scroll_into_view_if_needed()
    page.evaluate("window.scrollBy(0, -8)")
    page.wait_for_timeout(150)
    page.screenshot(
        path=str(destination),
        type="png",
        full_page=False,
        mask=[page.locator("#admin-token")],
        mask_color="#e8efed",
    )


def _capture_element_screenshot(page: Any, selector: str, destination: Path) -> None:
    page.set_viewport_size({"width": 1440, "height": 1100})
    target = page.locator(selector)
    target.scroll_into_view_if_needed()
    page.wait_for_timeout(150)
    target.screenshot(path=str(destination), type="png")


def _create_browser_jit_approval() -> dict[str, Any]:
    from serverware import db
    from serverware.policy_bundle import get_policy_snapshot

    snapshot = get_policy_snapshot()
    _require(snapshot is not None, "demo policy is unavailable for approval review")
    credential = db.get_credential("cred-demo-bearer")
    _require(credential is not None, "demo credential is unavailable for approval review")
    return db.ensure_jit_approval_request(
        route_id="demo.npm.publish.jit",
        method="PUT",
        url="https://demo-upstream:8443/npm/@scope%2Fbrowser-package",
        principal_id="agent:demo",
        credential_id=credential["id"],
        credential_version=int(credential["credential_version"]),
        policy_hash=snapshot.hash,
        request_digest="sha256:" + "a" * 64,
        operation_digest="sha256:" + "b" * 64,
        canonical_request={
            "principal": "agent:demo",
            "request": {
                "method": "PUT",
                "body_sha256": "sha256:" + "c" * 64,
            },
            "operation": {
                "type": "npm.publish",
                "packageName": "@scope/browser-package",
                "packageVersion": "1.2.3",
                "tarballIntegrity": "sha512-browser-fixture",
            },
        },
        redacted_display={
            "package": "@scope/browser-package",
            "version": "1.2.3",
        },
        pending_ttl_seconds=300,
        grant_ttl_seconds=30,
        grant_max_uses=1,
    )


def _assert_storage_and_disk_do_not_leak_tokens(
    page: Any,
    context: Any,
    data_dir: Path,
    simulator: OAuthProviderSimulator,
    api_documents: list[Any],
    browser_observations: list[dict[str, Any]],
) -> None:
    storage = page.evaluate(
        """
        () => ({
          session: Object.fromEntries(Object.entries(sessionStorage)),
          local: Object.fromEntries(Object.entries(localStorage)),
          html: document.documentElement.outerHTML
        })
        """
    )
    observable = {
        "storage": storage,
        "cookies": context.cookies(),
        "api": api_documents,
        "browser": browser_observations,
    }
    simulator.assert_no_token_values(
        json.dumps(observable, sort_keys=True, default=str)
    )
    for path in data_dir.rglob("*"):
        if not path.is_file():
            continue
        size = path.stat().st_size
        _require(
            size <= MAX_EVIDENCE_FILE_BYTES,
            f"unexpected oversized evidence file: {path}",
        )
        simulator.assert_no_token_values(path.read_bytes())


def _assert_provider_observations(simulator: OAuthProviderSimulator) -> dict[str, Any]:
    observations = simulator.observations()
    for provider in ("google", "x"):
        counts = observations["counts"][provider]
        for key in (
            "authorization_requests",
            "authorization_codes_issued",
            "token_requests",
            "authorization_code_exchanges",
            "token_responses",
            "identity_requests",
        ):
            _require(
                counts.get(key) == 1, f"{provider} {key} count was {counts.get(key)!r}"
            )
        for key in (
            "authorization_denials",
            "token_rejections",
            "identity_rejections",
            "revocation_rejections",
        ):
            _require(not counts.get(key), f"{provider} recorded unexpected {key}")
    _require(
        observations["active"]["authorizationCodes"] == 0,
        "simulator retained an unconsumed authorization code",
    )
    rejected = [
        event for event in observations["events"] if "rejected" in event.get("type", "")
    ]
    _require(
        not rejected, f"simulator recorded rejected or replayed operations: {rejected}"
    )
    return observations


def _run_browser_journey(
    public_url: str,
    data_dir: Path,
    simulator: OAuthProviderSimulator,
    screenshots_dir: Path | None,
) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Playwright is unavailable; install playwright==1.61.0 and its Chromium browser"
        ) from exc

    browser_observations: list[dict[str, Any]] = []
    console_errors: list[str] = []
    page_errors: list[str] = []
    api_documents: list[Any] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--host-resolver-rules=MAP serverware.test 127.0.0.1",
                f"--ignore-certificate-errors-spki-list={_certificate_spki_sha256(simulator.server_cert_path)}",
                "--no-proxy-server",
                "--disable-background-networking",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1440, "height": 1100},
            locale="en-US",
            timezone_id="UTC",
            reduced_motion="reduce",
        )
        page = context.new_page()
        page.set_default_timeout(DEFAULT_TIMEOUT_MS)

        def record_request(request: Any) -> None:
            browser_observations.append(
                {"type": "request", "method": request.method, "url": request.url}
            )

        def record_response(response: Any) -> None:
            browser_observations.append(
                {"type": "response", "status": response.status, "url": response.url}
            )

        page.on("request", record_request)
        page.on("response", record_response)
        page.on(
            "console",
            lambda message: console_errors.append(message.text)
            if message.type == "error"
            else None,
        )
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        try:
            response = page.goto(public_url + "/", wait_until="domcontentloaded")
            _require(
                response is not None and response.status == 200,
                "portal did not return HTTP 200",
            )
            response_headers = response.headers
            expected_headers = {
                "cache-control": "no-store",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
            }
            for name, expected in expected_headers.items():
                _require(
                    response_headers.get(name) == expected,
                    f"portal security header {name} was not {expected!r}",
                )
            _require(
                "frame-ancestors 'none'" in response_headers.get(
                    "content-security-policy", ""
                ),
                "portal CSP does not deny framing",
            )
            _require(
                response_headers.get("strict-transport-security", "").startswith(
                    "max-age=31536000"
                ),
                "HTTPS portal response omitted HSTS",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)
            token_storage = page.evaluate(
                "() => JSON.stringify({session: {...sessionStorage}, local: {...localStorage}})"
            )
            _require(
                ADMIN_TOKEN not in token_storage,
                "manually entered operator token was written to Web Storage",
            )
            page.reload(wait_until="domcontentloaded")
            _require(
                page.locator("#admin-token").input_value() == "",
                "manually entered operator token survived a portal reload",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)
            _assert_no_horizontal_overflow(page, label="desktop initial")

            page.once("dialog", lambda dialog: dialog.accept())
            page.get_by_role("button", name="Seed demo", exact=True).click()
            _wait_for_api(
                page,
                "/api/policy",
                lambda payload: payload.get("ready") is True,
            )
            _wait_for_api(
                page,
                "/api/bootstrap",
                lambda payload: any(
                    item.get("id") == "agent:demo"
                    for item in payload.get("policyPrincipals", [])
                ),
            )
            page.wait_for_function(
                """
                () => [...document.querySelectorAll('#policy-principal option')].some(
                  (item) => item.value === 'agent:demo'
                )
                """,
                timeout=DEFAULT_TIMEOUT_MS,
            )
            seed_status = page.locator("#operator-status").inner_text()
            if "failed:" in seed_status.lower():
                refresh_stack = page.evaluate(
                    """
                    async () => {
                      try {
                        await refresh();
                        return null;
                      } catch (error) {
                        return String(error?.stack || error);
                      }
                    }
                    """
                )
                raise AssertionError(
                    f"demo seed failed: {seed_status}; refresh stack: {refresh_stack}"
                )
            _assert_stripe_uses_manual_credential_flow(page, browser_observations)
            if screenshots_dir is not None:
                _capture_screenshot(
                    page,
                    ".passkey-section",
                    screenshots_dir / "operator-portal-desktop.png",
                )
                _capture_mobile_screenshot(
                    page,
                    ".passkey-section",
                    screenshots_dir / "operator-portal-mobile.png",
                )
                page.set_viewport_size({"width": 1440, "height": 1100})

            approval = _create_browser_jit_approval()
            approval_url = f"{public_url}/approvals/{quote(approval['id'], safe='')}"
            approval_response = page.goto(approval_url, wait_until="domcontentloaded")
            _require(
                approval_response is not None and approval_response.status == 200,
                "approval deep link did not return the operator portal",
            )
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url, expected_url=approval_url)
            page.wait_for_function(
                "(id) => state.approvalReview?.id === id",
                arg=approval["id"],
                timeout=DEFAULT_TIMEOUT_MS,
            )
            page.wait_for_function(
                """
                (id) => {
                  const text = document.querySelector('#approval-review')?.textContent || '';
                  return text.includes(id) && text.includes('Request digest');
                }
                """,
                arg=approval["id"],
                timeout=DEFAULT_TIMEOUT_MS,
            )
            review_panel = page.locator("#approval-review")
            _require(review_panel.is_visible(), "approval review panel is not visible")
            review_text = review_panel.text_content() or ""
            for marker in (
                approval["id"],
                "demo.npm.publish.jit",
                "Request digest",
                "Operation digest",
                "@scope/browser-package",
            ):
                _require(marker in review_text, f"approval review omitted {marker!r}")
            _require(
                page.evaluate("document.activeElement?.id") == "approval-review",
                "approval deep link did not focus the canonical review document",
            )
            _assert_no_horizontal_overflow(page, label="desktop approval review")
            if screenshots_dir is not None:
                _capture_screenshot(
                    page,
                    "#approval-review",
                    screenshots_dir / "operator-portal-approval.png",
                )
                page.set_viewport_size({"width": 390, "height": 844})
                review_panel.scroll_into_view_if_needed()
                page.wait_for_timeout(150)
                page.locator("#approval-review").screenshot(
                    path=str(screenshots_dir / "operator-portal-approval-mobile.png"),
                    type="png",
                )
                page.set_viewport_size({"width": 1440, "height": 1100})

            page.goto(public_url + "/", wait_until="domcontentloaded")
            page.locator("#admin-token").fill(ADMIN_TOKEN)
            page.locator("#admin-token").dispatch_event("change")
            _wait_for_portal(page, public_url)

            page.locator("#setup-template").select_option("gmail_recent")
            page.locator("#setup-principal").select_option("agent:demo")
            page.locator("#setup-route-id").fill("browser.gmail.last-30-days")
            page.locator("#setup-connect-button").click()
            page.wait_for_function(
                """
                () => state.oauthSetupSessionId
                  && state.setupSession?.id === state.oauthSetupSessionId
                  && state.setupSession?.routeId === 'browser.gmail.last-30-days'
                  && state.setupSession?.routePolicyDigest === null
                  && document.activeElement?.id === 'oauth-provider'
                """,
                timeout=DEFAULT_TIMEOUT_MS,
            )
            google_credential = _connect_oauth(
                page,
                context,
                public_url,
                provider="google",
                name=GOOGLE_NAME,
                scopes=GOOGLE_SCOPES,
                account="operator@example.test",
            )
            _assert_public_credential(
                google_credential,
                provider="google",
                subject="google-subject-001",
                account="operator@example.test",
                scopes=GOOGLE_SCOPES,
            )
            setup_after_google = page.evaluate("() => state.setupSession")
            _require(
                setup_after_google.get("routeId") == "browser.gmail.last-30-days"
                and setup_after_google.get("credentialId") == google_credential["id"]
                and setup_after_google.get("phase") == "credential_activated",
                f"fresh Setup OAuth flow did not bind its credential: {setup_after_google}",
            )
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    ".oauth-connect-section",
                    screenshots_dir / "operator-portal-oauth.png",
                )

            gmail_policy = _preview_stage_activate_policy(
                page,
                template="gmail_recent",
                route_id="browser.gmail.last-30-days",
                credential_id=google_credential["id"],
            )
            api_documents.append(gmail_policy)

            x_credential = _connect_oauth(
                page,
                context,
                public_url,
                provider="x",
                name=X_NAME,
                scopes=X_SCOPES,
                account="@operator_x",
            )
            _assert_public_credential(
                x_credential,
                provider="x",
                subject="x-subject-001",
                account="@operator_x",
                scopes=X_SCOPES,
            )
            _require(
                (x_credential.get("metadata") or {}).get("x_app_id")
                == simulator.X_CLIENT_ID,
                "X credential is not bound to the OAuth client app",
            )

            final_policy = _preview_stage_activate_policy(
                page,
                template="x_read_recent",
                route_id="browser.x.search.seven-days",
                credential_id=x_credential["id"],
            )
            _assert_policy_evidence(
                final_policy,
                google_credential["id"],
                x_credential["id"],
                simulator,
            )
            if screenshots_dir is not None:
                _capture_element_screenshot(
                    page,
                    ".policy-authoring-section",
                    screenshots_dir / "operator-portal-policy.png",
                )

            final_bootstrap = _api_json(page, "/api/bootstrap")
            final_policy_api = _api_json(page, "/api/policy")
            api_documents.extend([final_bootstrap, final_policy_api])
            _require(
                not final_bootstrap.get("pendingOAuthCredentials"),
                "browser journey left a pending OAuth credential",
            )
            _require(
                not final_bootstrap.get("oauthIssuanceUncertainties"),
                "browser journey left uncertain provider issuance",
            )
            _assert_no_oauth_cookies(context)
            state_path = data_dir / "oauth-states.json"
            if state_path.exists():
                state_document = json.loads(state_path.read_text(encoding="utf-8"))
                _require(
                    state_document.get("states") == {},
                    "consumed OAuth state remains on disk",
                )

            page.set_viewport_size({"width": 390, "height": 844})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(100)
            _assert_no_horizontal_overflow(page, label="mobile final")
            page.set_viewport_size({"width": 1440, "height": 1100})
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(100)
            _assert_no_horizontal_overflow(page, label="desktop final")

            _require(not page_errors, f"browser page errors occurred: {page_errors}")
            _require(
                not console_errors, f"browser console errors occurred: {console_errors}"
            )
            _assert_storage_and_disk_do_not_leak_tokens(
                page,
                context,
                data_dir,
                simulator,
                api_documents,
                browser_observations,
            )
            observations = _assert_provider_observations(simulator)
            return {
                "ok": True,
                "portalUrl": public_url,
                "credentials": {
                    "google": google_credential["id"],
                    "x": x_credential["id"],
                },
                "policyHash": final_policy_api["policy_hash"],
                "routes": [
                    "browser.gmail.last-30-days",
                    "browser.x.search.seven-days",
                ],
                "providerCounts": observations["counts"],
                "screenshots": str(screenshots_dir)
                if screenshots_dir is not None
                else None,
            }
        finally:
            context.close()
            browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drive the real HTTPS Serverware portal through deterministic Google and X OAuth"
    )
    parser.add_argument(
        "--screenshots-dir",
        type=Path,
        help="refresh the canonical portal, approval, OAuth, and policy screenshots",
    )
    args = parser.parse_args()
    screenshots_dir = args.screenshots_dir.resolve() if args.screenshots_dir else None
    if screenshots_dir is not None:
        screenshots_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="serverware-oauth-contract-"
    ) as raw_contract_tmp:
        _assert_redirect_validation(Path(raw_contract_tmp))
    with tempfile.TemporaryDirectory(prefix="serverware-browser-oauth-") as raw_tmp:
        tmp = Path(raw_tmp)
        listener = _reserve_https_socket()
        portal_port = int(listener.getsockname()[1])
        public_url = f"https://serverware.test:{portal_port}"
        simulator = OAuthProviderSimulator(
            tmp / "provider",
            redirect_base_url=public_url,
        )
        portal: _UvicornThread | None = None
        original_providers: Any = None
        original_request_bytes: Any = None
        original_reconciler: Any = None
        oauth_module: Any = None
        app_module: Any = None
        try:
            simulator.start()
            _assert_simulator_contract(simulator)
            _configure_environment(tmp / "serverware", public_url, simulator)

            from serverware import app as app_module
            from serverware import oauth as oauth_module

            original_providers = oauth_module._providers
            configured = original_providers()
            google_provider = replace(
                configured["google"],
                **simulator.provider_urls("google"),
            )
            x_provider = replace(configured["x"], **simulator.provider_urls("x"))
            oauth_module._providers = lambda: {
                "google": google_provider,
                "x": x_provider,
                "twitter": x_provider,
            }

            original_request_bytes = oauth_module.request_bytes

            def trusted_provider_request(request: Any, **kwargs: Any) -> Any:
                kwargs["context"] = simulator.client_ssl_context
                return original_request_bytes(request, **kwargs)

            oauth_module.request_bytes = trusted_provider_request
            original_reconciler = app_module._start_oauth_revocation_reconciler
            app_module._start_oauth_revocation_reconciler = lambda: None

            portal = _UvicornThread(app_module.app, listener, simulator)
            portal.start()
            result = _run_browser_journey(
                public_url,
                tmp / "serverware",
                simulator,
                screenshots_dir,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
        finally:
            if portal is not None:
                portal.close()
            else:
                listener.close()
            if oauth_module is not None:
                if original_providers is not None:
                    oauth_module._providers = original_providers
                if original_request_bytes is not None:
                    oauth_module.request_bytes = original_request_bytes
            if app_module is not None and original_reconciler is not None:
                app_module._start_oauth_revocation_reconciler = original_reconciler
            simulator.close()


if __name__ == "__main__":
    main()
