#!/usr/bin/env python3
"""GitHub App catalog stories with real SQLite, encryption and signed policy.

Only the fixed GitHub HTTP transport is synthetic. JWT signing/verification,
provider response validation, catalog CAS, custody, policy publication and API
admission stay real. Run cold workers in the root-approved network-none app
image; these tests do not establish actual GitHub, SDK, proxy or deployment
acceptance.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import test_operator_catalog_github as legacy
import test_operator_workspace_store as workspace

ACTOR = "operator-github-app-catalog-test"
ADMIN = "synthetic-github-app-catalog-administrator"
ORIGIN = "https://console.example.com"
PATH = "/api/operator-demo/credentials/github-app"
REPOSITORY = {"owner": "catchplate-fixture", "name": "operator-demo"}
APP_ID, INSTALLATION_ID, ACCOUNT_ID, REPOSITORY_ID = 12345, 23456, 34567, 45678
NETWORK_ATTEMPTS = []


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("GitHub App fixture attempted network contact")


def require(value, message):
    if not value:
        raise AssertionError(message)


def refused(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("GitHub App negative control unexpectedly succeeded")


class Provider:
    """Fixed URL/body oracle; no HTTP or successful cryptographic stubs."""
    def __init__(self, key):
        self.key, self.calls, self.tokens, self.jwts = key, [], [], []
        self.issues = "write"
        self.expiries = []
        self.installation_changes = {}
        self.before_listing = None
        self.forced_status = None

    def jwt(self, token):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        parts = token.split(".")
        require(len(parts) == 3, "actual App JWT shape")
        decoded = [base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)) for part in parts]
        require(json.loads(decoded[0]) == {"alg": "RS256", "typ": "JWT"}, "actual App JWT algorithm")
        claims = json.loads(decoded[1])
        require(set(claims) == {"iss", "iat", "exp"} and claims["iss"] == str(APP_ID)
            and type(claims["iat"]) is int and type(claims["exp"]) is int
            and claims["exp"] - claims["iat"] == 600
            and claims["iat"] <= int(time.time()) < claims["exp"], "actual App JWT bounds")
        self.key.public_key().verify(decoded[2], ".".join(parts[:2]).encode(),
            padding.PKCS1v15(), hashes.SHA256())
        self.jwts.append(token)

    def __call__(self, request, *, timeout, max_bytes, require_https, deadline, expected_statuses):
        from catchplate.http_client import HttpDeadline, HttpResponse
        require(timeout == 10.0 and require_https is True and type(deadline) is HttpDeadline
            and deadline.expires_at > time.monotonic()
            and expected_statuses == tuple(range(200, 600)), "bounded actual provider transport contract")
        headers = {name.lower(): value for name, value in request.header_items()}
        require(headers.get("accept") == "application/vnd.github+json"
            and headers.get("x-github-api-version") == "2022-11-28"
            and headers.get("accept-encoding") == "identity"
            and headers.get("user-agent") == "catchplate-github-app/1"
            and headers.get("authorization", "").startswith("Bearer "), "actual provider headers")
        authorization = headers["authorization"].removeprefix("Bearer ")
        method, url = request.get_method(), request.full_url
        if url == "https://api.github.com/repos/catchplate-fixture/operator-demo/installation":
            require(method == "GET" and request.data is None and max_bytes == 1048576,
                "fixed installation request")
            self.jwt(authorization)
            self.calls.append("installation")
            status, value = 200, {"id": INSTALLATION_ID, "app_id": APP_ID,
                "account": {"id": ACCOUNT_ID, "login": REPOSITORY["owner"], "type": "Organization"},
                "target_id": ACCOUNT_ID, "target_type": "Organization", "suspended_at": None,
                "permissions": {"issues": "write", "metadata": "read"}, **self.installation_changes}
        elif url == "https://api.github.com/app/installations/23456/access_tokens":
            require(method == "POST" and max_bytes == 65536
                and headers.get("content-type") == "application/json", "fixed token request")
            self.jwt(authorization)
            body = json.loads(request.data)
            expected = {"permissions": {"issues": self.issues, "metadata": "read"}}
            require(body in (expected | {"repositories": [REPOSITORY["name"]]},
                expected | {"repository_ids": [REPOSITORY_ID]}), "exact one-repository permission ceiling")
            self.calls.append("mint-id" if "repository_ids" in body else "mint-name")
            token = "ghs_synthetic_GitHubApp_installation_" + str(len(self.tokens) + 1)
            self.tokens.append(token)
            ttl = self.expiries.pop(0) if self.expiries else 3600
            status, value = 201, {"token": token,
                "expires_at": datetime.fromtimestamp(int(time.time()) + ttl, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "permissions": expected["permissions"], "repository_selection": "selected"}
        else:
            require(url == "https://api.github.com/installation/repositories?per_page=100&page=1"
                and method == "GET" and request.data is None and max_bytes == 1048576
                and self.tokens and authorization == self.tokens[-1], "independent token repository verification")
            self.calls.append("repositories")
            if self.before_listing is not None:
                callback, self.before_listing = self.before_listing, None
                callback()
            status, value = 200, {"total_count": 1, "repositories": [{"id": REPOSITORY_ID,
                "name": REPOSITORY["name"], "full_name": REPOSITORY["owner"] + "/" + REPOSITORY["name"],
                "owner": {"id": ACCOUNT_ID, "login": REPOSITORY["owner"]}}]}
        if self.forced_status is not None:
            status, value = self.forced_status, {"message": "Synthetic provider refusal"}
        raw = json.dumps(value, separators=(",", ":")).encode()
        return HttpResponse(status, {"content-type": "application/json"},
            (("Content-Type", "application/json"), ("Content-Length", str(len(raw)))), raw)


class Fixture:
    def __init__(self, *, full_startup=False):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        if full_startup:
            # Match the real cold runner: bootstrap readers must run BEFORE
            # db/store initialization admits the retained publication owner.
            Path(os.environ["CATCHPLATE_DATA_DIR"]).mkdir(mode=0o700)
            from catchplate import operator_demo
            operator_demo.activate()
            from catchplate.control_plane_startup import validate_control_plane_startup
            validate_control_plane_startup()
            from catchplate import config, db, operator_demo_store, policy_bundle
            from catchplate import operator_catalog_schema, operator_catalog_inputs, operator_catalog_mutations
            self.config, self.db, self.store, self.bundles = config, db, operator_demo_store, policy_bundle
            self.schema, self.inputs, self.mutations = operator_catalog_schema, operator_catalog_inputs, operator_catalog_mutations
        else:
            (self.config, self.db, self.store, self.bundles, self.schema,
                self.inputs, self.mutations) = workspace.workspace()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode("ascii")
        self.provider, self.application_tokens = Provider(self.key), []

    def transport(self):
        from catchplate import github_app
        return patch.object(github_app.http_client, "request_bytes", self.provider)

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def fields(self, **changes):
        return {**self.review(), "name": "Synthetic GitHub App", "app_id": str(APP_ID),
            "installation_id": str(INSTALLATION_ID), "repository": dict(REPOSITORY),
            "issues_permission": "write", "private_key_pem": self.pem, **changes}

    def create(self, **changes):
        fields = self.fields(**changes)
        self.provider.issues = fields["issues_permission"]
        return self.mutations.create_github_app_credential(self.inputs.GithubAppInput(**fields), ACTOR)

    def application(self):
        value = self.mutations.create_application(self.inputs.ApplicationInput(**self.review(),
            name="GitHub App SDK application", token_lifetime_seconds=3600,
            proxy_authentication="basic_and_bearer_v1"), ACTOR)
        self.application_tokens.append(value["client_token"])
        return value["application"]

    def rule(self, application, credential, *, bundle=legacy.READ, repository=None):
        return self.mutations.create_github_rule(self.inputs.GithubRuleInput(**self.review(),
            name="Exact GitHub App repository", application_id=application["id"],
            credential_id=credential["id"], operation_bundle=bundle,
            repository=dict(REPOSITORY) if repository is None else repository), ACTOR)

    def snapshot(self):
        return (workspace.snapshot(self.db, catalog=True), self.config.POLICY_BUNDLE_PATH.read_bytes(),
            self.store.get_policy_high_water())

    def catalog(self):
        return workspace.catalog(self.db, self.schema)

    def target(self, identifier):
        return self.inputs.TargetInput(**self.review(), id=identifier)

    def signed(self):
        return workspace.verify_signed(self.config, self.db, self.store, self.bundles)

    def clean(self, value):
        raw = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
        sensitive = [self.pem, *self.pem.splitlines()[1:-1], legacy.TOKEN, ADMIN,
            *self.provider.tokens, *self.provider.jwts, *self.application_tokens]
        require(all(secret.encode() not in raw for secret in sensitive), "private GitHub App material disclosed")

    def storage_clean(self):
        with closing(self.db.connect()) as conn:
            self.clean("\n".join(conn.iterdump()).encode())
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.config.DB_PATH) + suffix)
            if path.exists():
                require(path.stat().st_size <= 32 * 1024**2, "bounded synthetic database")
                self.clean(path.read_bytes())
        require(not NETWORK_ATTEMPTS, "unexpected network contact")


def save_and_policy():
    f = Fixture()
    with f.transport():
        pat = f.mutations.create_github_credential(f.inputs.GithubTokenInput(**f.review(),
            name="Retained PAT", secret=legacy.TOKEN), ACTOR)["credential"]
        pat_before = f.db.get_credential(pat["id"], include_secret=True)
        policy_before = f.snapshot()[1:]
        created = f.create(installation_id=None)
        credential = created["credential"]
        require(created["revision"] == 3 and credential["connection_type"] == "github_app_v1"
            and credential["auth_type"] == "bearer" and credential["provider_id"] == "github"
            and credential["credential_generation"] == 1, "explicit GitHub App credential")
        require(credential["github_app"] == {"app_id": str(APP_ID), "installation_id": str(INSTALLATION_ID),
            "account_id": str(ACCOUNT_ID), "repository_id": str(REPOSITORY_ID),
            "repository": REPOSITORY, "issues_permission": "write", "token_refresh": "automatic"},
            "verified public App binding")
        require(f.snapshot()[1:] == policy_before and f.db.get_credential(pat["id"], include_secret=True) == pat_before,
            "App save changed PAT or policy authority")
        require(f.provider.calls == ["installation", "mint-name", "repositories"], "one verified provider sequence")
        f.clean(created)
        core = f.db.get_credential(credential["id"], include_secret=True)
        private = json.loads(core["secret"])
        require(f.pem in private.values(), "actual decrypted stored PEM")
        for bundle in (legacy.READ, legacy.WRITE):
            app = f.application()
            rule = f.rule(app, credential, bundle=bundle)["access_rule"]
            signed = f.signed()
            route = next(item for item in signed["routes"] if item["id"] == rule["route_id"])
            require(route["match"] == {"scheme": "https", "host": "api.github.com", "port": 443,
                "methods": ["GET"] if bundle == legacy.READ else ["GET", "POST"],
                "paths": ["/repos/catchplate-fixture/operator-demo/issues",
                    "/repos/catchplate-fixture/operator-demo/issues/{issue_number}",
                    "/repos/catchplate-fixture/operator-demo/issues/{issue_number}/comments",
                    "/repos/catchplate-fixture/operator-demo/issues/comments/{comment_id}"]},
                "signed exact repository method ceiling")
            require(route["credentialRef"] == credential["id"] and route["principals"] == [app["principal_id"]]
                and route["adapter"]["config"]["githubRepository"] == REPOSITORY
                and route["adapter"]["config"]["operationBundle"] == bundle
                and route["credentialHeader"] == {"mode": "replaceExact",
                    "expectedValue": "token catchplate-github-placeholder-v1"}, "signed App route binding")
            from catchplate import operator_github_app as owner
            compiled = f.bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
            runtime_route = next(item for item in compiled.routes if item.id == rule["route_id"])
            runtime_policy = compiled.credentials[credential["id"]]
            public = f.db.get_credential(credential["id"], include_secret=False)
            owner.prepare_dispatch_token(public, runtime_route, runtime_policy)
            with f.db.credential_generation_snapshot(credential["id"]) as current:
                require(owner.cached_dispatch_token(current, runtime_route, runtime_policy) == f.provider.tokens[0],
                    "postcommit seed did not serve the actual original token")
            require(len(f.provider.calls) == 3, "fresh postcommit seed unexpectedly refreshed")
        count = len(f.provider.calls)
        f.clean(f.mutations.catalog_status())
        require(len(f.provider.calls) == count, "catalog GET contacted GitHub")
        committed = f.snapshot()
        f.store.initialize()
        require(f.snapshot() == committed and f.db.get_credential(pat["id"], include_secret=True) == pat_before,
            "retained App or PAT changed on reinitialize")
        f.storage_clean()
    return {"signed_presets": 2, "provider_calls": 3, "encrypted_pem": True, "pat_unchanged": True}


def ceilings_and_lifecycle():
    f = Fixture()
    with f.transport():
        credential = f.create(issues_permission="read")["credential"]
        app = f.application()
        before = f.snapshot()
        for repository, bundle in ((REPOSITORY, legacy.WRITE),
                ({"owner": REPOSITORY["owner"], "name": "another-repository"}, legacy.READ),
                ({"owner": "another-owner", "name": REPOSITORY["name"]}, legacy.READ)):
            refused(lambda: f.rule(app, credential, bundle=bundle, repository=repository), ValueError)
            require(f.snapshot() == before, "refused scope changed authority")
        rule = f.rule(app, credential)["access_rule"]
        before = f.snapshot()
        refused(lambda: f.mutations.replace_credential_key(f.inputs.ReplaceCredentialKeyInput(
            **f.review(), id=credential["id"], expected_credential_generation=1, secret=legacy.REPLACEMENT), ACTOR),
            f.schema.CatalogConflict)
        refused(lambda: f.mutations.create_rule(f.inputs.RuleInput(**f.review(), name="No generic App bypass",
            application_id=app["id"], credential_id=credential["id"],
            upstream_url="https://api.example.com/v1/items", methods=["GET"], response_fields=["id"]), ACTOR),
            (ValueError, f.schema.CatalogIntegrityError))
        refused(lambda: f.mutations.revoke_credential(f.target(credential["id"]), ACTOR), f.schema.CatalogConflict)
        require(f.snapshot() == before, "generic replacement or active revoke changed App authority")
        f.mutations.revoke_application(f.target(app["id"]), ACTOR)
        require(next(item for item in f.catalog()["access_rules"] if item["id"] == rule["id"])["status"] == "revoked",
            "actual application revocation did not revoke rule")
        f.mutations.revoke_credential(f.target(credential["id"]), ACTOR)
        require(f.db.get_credential(credential["id"], include_secret=False) is None, "App credential remains active")
        before = f.snapshot()
        refused(lambda: f.rule(app, credential), f.schema.CatalogConflict)
        require(f.snapshot() == before and f.provider.calls == ["installation", "mint-name", "repositories"],
            "local permissions or revocation contacted provider or replayed mutation")
        f.clean(f.mutations.catalog_status())
        f.signed()
        f.storage_clean()
    return {"exact_scope_and_read_ceiling": True, "generic_replacement_refused": True, "revoked": True}


def input_and_cas():
    f = Fixture()
    with f.transport():
        before = f.snapshot()
        for changes in ({"app_id": value} for value in (0, True, "0", "01", "-1", "9007199254740992")):
            refused(lambda: f.inputs.GithubAppInput(**f.fields(**changes)), ValueError)
        for value in (0, True, "", "0", "01", "-1", "9007199254740992"):
            refused(lambda: f.inputs.GithubAppInput(**f.fields(installation_id=value)), ValueError)
        omitted = f.fields()
        omitted.pop("installation_id")
        require(f.inputs.GithubAppInput(**omitted).installation_id is None
            and f.inputs.GithubAppInput(**f.fields(installation_id=None)).installation_id is None,
            "optional installation ID setup input")
        for changes in ({"installation_id": "01"}, {"issues_permission": "admin"},
                {"repository": {**REPOSITORY, "id": REPOSITORY_ID}}, {"private_key_pem": ""},
                {"private_key_pem": "x" * 8193}, {"secret": legacy.TOKEN}, {"expected_revision": True}):
            refused(lambda: f.inputs.GithubAppInput(**f.fields(**changes)), ValueError)
        require(f.snapshot() == before and not f.provider.calls, "invalid DTO had effects")
        stale = f.inputs.GithubAppInput(**f.fields())
        f.application()
        before = f.snapshot()
        refused(lambda: f.mutations.create_github_app_credential(stale, ACTOR), f.schema.CatalogConflict)
        require(f.snapshot() == before and not f.provider.calls, "stale first CAS contacted provider")
        # A normal catalog mutation at the provider boundary proves the save
        # does not keep publication/SQLite ownership over the external exchange.
        retained = {}
        def intervening_application():
            f.application()
            retained["snapshot"] = f.snapshot()
        f.provider.before_listing = intervening_application
        refused(lambda: f.create(), f.schema.CatalogConflict)
        require(f.snapshot() == retained["snapshot"] and not f.catalog()["credentials"]
            and f.provider.calls == ["installation", "mint-name", "repositories"],
            "final CAS lost or minted token caused an unreviewed credential")
        f.storage_clean()
    return {"strict_inputs": True, "stale_before_provider": True, "final_cas_preserved": True}


def provider_refusal():
    f = Fixture()
    with f.transport():
        f.provider.installation_changes = {"app_id": APP_ID + 1}
        before = f.snapshot()
        from catchplate.operator_github_app import GitHubAppUnavailable
        refused(lambda: f.create(installation_id=None), GitHubAppUnavailable)
        require(f.snapshot() == before and f.provider.calls == ["installation"] and not f.provider.tokens,
            "wrong App installation was persisted or minted")
        f.clean(f.mutations.catalog_status())
        require(f.provider.calls == ["installation"], "catalog GET retried provider refusal")
        f.storage_clean()
    return {"wrong_provider_binding_refused": True, "provider_calls": 1}


def token_refresh_and_backoff():
    from catchplate import operator_github_app as owner
    f = Fixture()
    with f.transport():
        # A real short-lived provider response is valid provisioning evidence
        # but already inside the owner's refresh margin. No clock is patched.
        f.provider.expiries = [30, 3600]
        credential = f.create()["credential"]
        app = f.application()
        rule = f.rule(app, credential)["access_rule"]
        compiled = f.bundles.compile_policy_bundle(f.signed(), verify_signature=True, validate_schema=True)
        route = next(item for item in compiled.routes if item.id == rule["route_id"])
        policy = compiled.credentials[credential["id"]]
        public = f.db.get_credential(credential["id"], include_secret=False)
        require(owner.selected(public), "runtime did not recognize App credential")
        before = f.snapshot()
        owner.prepare_dispatch_token(public, route, policy)
        require(f.provider.calls == ["installation", "mint-name", "repositories",
            "installation", "mint-id", "repositories"], "refresh did not retain original numeric repository pins")
        with f.db.credential_generation_snapshot(credential["id"]) as current:
            token = owner.cached_dispatch_token(current, route, policy)
        require(token == f.provider.tokens[1] and token != f.provider.tokens[0], "near-expiry token was reused")
        owner.prepare_dispatch_token(public, route, policy)
        f.clean(f.mutations.catalog_status())
        require(len(f.provider.calls) == 6 and f.snapshot() == before, "cache hit or GET contacted provider or persisted token")
        identity = owner._identity(public)
        with owner._lock:
            entry = owner._cache[identity]
        require(type(entry.token) is owner.protocol.InstallationToken and entry.usable(),
            "real refreshed installation token has no usable clock anchors")
        # Retain the actual minted token and real clocks. These are invalid
        # insertion anchors, not a mocked clock or substituted mint result.
        for changes in ({"wall": entry.token.issued_at - 1}, {"wall": float("nan")},
                {"wall": float("inf")}, {"wall": True}, {"monotonic": -1},
                {"monotonic": float("nan")}, {"monotonic": float("inf")}, {"monotonic": False}):
            candidate = replace(entry, **changes)
            require(candidate.usable() is False, "invalid token cache clock anchor accepted")
            refused(lambda: owner._put(identity, candidate.token, candidate.wall, candidate.monotonic),
                owner.GitHubAppUnavailable)
            with owner._lock:
                require(owner._cache.get(identity) is entry, "refused clock anchor changed retained cache entry")
        for altered_route, altered_policy in ((replace(route, host="other.example.com"), policy),
                (replace(route, adapter_config={**route.adapter_config,
                    "githubRepository": {**REPOSITORY, "name": "other"}}), policy),
                (replace(route, adapter_config={**route.adapter_config,
                    "response": {**route.adapter_config["response"],
                        "maxBodyBytes": route.adapter_config["response"]["maxBodyBytes"] + 1}}), policy),
                (route, replace(policy, provider="github"))):
            refused(lambda: owner.prepare_dispatch_token(public, altered_route, altered_policy), owner.GitHubAppUnavailable)
            with f.db.credential_generation_snapshot(credential["id"]) as current:
                refused(lambda: owner.cached_dispatch_token(current, altered_route, altered_policy),
                    owner.GitHubAppUnavailable)
        require(len(f.provider.calls) == 6 and f.snapshot() == before, "wrong runtime binding contacted provider")
        owner.forget(credential["id"])  # Actual explicit local cache invalidation; no retained row changes.
        f.provider.forced_status = 401
        refused(lambda: owner.prepare_dispatch_token(public, route, policy), owner.GitHubAppUnavailable)
        require(len(f.provider.calls) == 7 and f.provider.calls[-1] == "installation", "401 did not fail closed before mint")
        refused(lambda: owner.prepare_dispatch_token(public, route, policy), owner.GitHubAppUnavailable)
        with f.db.credential_generation_snapshot(credential["id"]) as current:
            refused(lambda: owner.cached_dispatch_token(current, route, policy), owner.GitHubAppUnavailable)
        require(len(f.provider.calls) == 7 and f.snapshot() == before, "backoff retried or stale token escaped")
        f.storage_clean()
    return {"automatic_refresh_margin": True, "numeric_repository_pinned": True,
        "cache_hit_no_contact": True, "provider_401_backoff": True,
        "clock_anchor_refusals": 8, "full_route_cache_refusal": True}


async def api_story():
    from test_operator_notifications_connected_backend import FullASGI
    f = Fixture(full_startup=True)
    from catchplate import app as application
    app = FullASGI(application.app, ADMIN)

    async def call(method, path, *, body=None, status=200, authenticate=True,
            origin=ORIGIN, media="application/json"):
        raw = b"" if body is None else body if type(body) is bytes else json.dumps(body).encode()
        headers = [] if body is None else [("origin", origin), ("content-type", media),
            ("content-length", str(len(raw)))]
        response = await app.request(method, path, headers, raw, authenticate=authenticate)
        require(response["status"] == status, "actual GitHub App API status")
        normalized = {key.lower(): value for key, value in response["headers"]}
        require(normalized.get("cache-control") == "no-store", "actual API cache boundary")
        public = base64.b64decode(response["body_b64"], validate=True)
        f.clean(public)
        return json.loads(public)

    started = False
    with f.transport():
        try:
            await app.start()
            started = True
            before = f.snapshot()
            await call("GET", "/api/operator-demo/catalog", status=401, authenticate=False)
            await call("POST", PATH, body={}, origin="https://foreign.example.com", status=403)
            await call("POST", PATH, body=f.fields(), media="text/plain", status=415)
            await call("POST", PATH, body=f.fields(private_key_pem="not-a-private-key"), status=422)
            await call("POST", PATH, body=f.fields(installation_id=""), status=422)
            await call("POST", PATH, body=b"x" * 32769, status=413)
            initial = await call("GET", "/api/operator-demo/catalog")
            require(initial["capabilities"]["github_app"]["connection_type"] == "github_app_v1"
                and initial["capabilities"]["github_app"]["create_credential_path"] == PATH,
                "real GitHub App capability route")
            require(f.snapshot() == before and not f.provider.calls, "API admission or catalog GET had effects")
            payload = f.fields()
            payload.pop("installation_id")
            saved = await call("POST", PATH, body=payload, status=201)
            credential = saved["credential"]
            require(credential["connection_type"] == "github_app_v1"
                and credential["github_app"]["repository"] == REPOSITORY
                and credential["github_app"]["installation_id"] == str(INSTALLATION_ID)
                and saved["revision"] == initial["revision"] + 1
                and saved["policy"]["policy_hash"] == initial["policy"]["policy_hash"], "actual API save receipt")
            committed = f.snapshot()
            await call("POST", PATH, body=payload, status=409)
            observed = await call("GET", "/api/operator-demo/catalog")
            require(f.snapshot() == committed and observed["credentials"] == [credential]
                and f.provider.calls == ["installation", "mint-name", "repositories"],
                "API stale save or discovery repeated provider operation")
            created = await call("POST", "/api/operator-demo/applications", status=201, body={**f.review(),
                "name": "API GitHub App client", "token_lifetime_seconds": 3600,
                "proxy_authentication": "basic_and_bearer_v1"})
            f.application_tokens.append(created["client_token"])
            granted = await call("POST", "/api/operator-demo/access-rules/github", status=201, body={**f.review(),
                "name": "API exact repository", "application_id": created["application"]["id"],
                "credential_id": credential["id"], "repository": REPOSITORY,
                "operation_bundle": legacy.READ})
            require(granted["access_rule"]["credential_id"] == credential["id"], "actual API grant binding")
            signed = f.signed()
            require(len(signed["routes"]) == 1 and signed["routes"][0]["credentialRef"] == credential["id"],
                "API permission did not reach real signed policy")
            events = workspace.rows(f.db, "audit_events")
            require(sum(row["event_type"] == "operator_catalog.credential.github_app_created" for row in events) == 1
                and all(row["actor_id"] == ACTOR for row in events if row["event_type"].startswith("operator_catalog.")),
                "actual authenticated API actor/audit")
            require(len(f.provider.calls) == 3, "API app or grant unexpectedly contacted GitHub")
            f.storage_clean()
            return {"full_asgi": True, "credential_and_rule": True, "provider_calls": 3,
                "admission_controls": [401, 403, 415, 422, 413, 409]}
        finally:
            if started:
                await app.stop()


OPERATIONS = {"saved": save_and_policy, "ceilings": ceilings_and_lifecycle,
    "cas": input_and_cas, "provider": provider_refusal, "refresh": token_refresh_and_backoff,
    "api": lambda: asyncio.run(api_story())}


class OperatorCatalogGithubAppTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.update(CATCHPLATE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com","https://api.github.com"]',
            CATCHPLATE_PUBLIC_URL=ORIGIN, CATCHPLATE_ADMIN_TOKEN=ADMIN, CATCHPLATE_ADMIN_USER=ACTOR,
            CATCHPLATE_ADMIN_ROLES="admin", CATCHPLATE_DECISION_GATE_BASE="")
        for key in tuple(self.environment):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                self.environment.pop(key)

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            self.fail("isolated GitHub App worker failed (exit " + str(result.returncode)
                + "): " + legacy.worker_failure_summary(result))
        self.assertTrue(result.stdout.strip(), "worker returned no acceptance receipt")
        value = json.loads(result.stdout)
        self.assertIs(type(value), dict)
        self.assertTrue(value, "empty worker receipt")
        return value

    def test_encrypted_app_save_preserves_pat_and_signs_two_repository_presets(self):
        self.assertEqual(self.worker("saved"), {"signed_presets": 2, "provider_calls": 3,
            "encrypted_pem": True, "pat_unchanged": True})

    def test_exact_repository_read_ceiling_generic_replace_and_revocation(self):
        self.assertEqual(self.worker("ceilings"), {"exact_scope_and_read_ceiling": True,
            "generic_replacement_refused": True, "revoked": True})

    def test_strict_inputs_and_both_sides_of_real_catalog_cas(self):
        self.assertEqual(self.worker("cas"), {"strict_inputs": True,
            "stale_before_provider": True, "final_cas_preserved": True})

    def test_wrong_provider_binding_no_mint_or_catalog_retry(self):
        self.assertEqual(self.worker("provider"), {"wrong_provider_binding_refused": True, "provider_calls": 1})

    def test_automatic_near_expiry_refresh_cache_hit_and_provider_401_backoff(self):
        self.assertEqual(self.worker("refresh"), {"automatic_refresh_margin": True,
            "numeric_repository_pinned": True, "cache_hit_no_contact": True, "provider_401_backoff": True,
            "clock_anchor_refusals": 8, "full_route_cache_refusal": True})

    def test_real_full_asgi_save_and_signed_rule_with_auth_framing_and_cas(self):
        self.assertEqual(self.worker("api"), {"full_asgi": True, "credential_and_rule": True,
            "provider_calls": 3, "admission_controls": [401, 403, 415, 422, 413, 409]})


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker" and sys.argv[2] in OPERATIONS:
        os.umask(0o077)
        signal.alarm(110)
        sys.addaudithook(no_network)
        try:
            outcome = OPERATIONS[sys.argv[2]]()
        except BaseException as error:
            print(json.dumps(legacy.safe_worker_failure(error), sort_keys=True), flush=True)
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True), flush=True)
    else:
        unittest.main(verbosity=2)
