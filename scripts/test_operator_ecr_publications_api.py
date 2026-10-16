#!/usr/bin/env python3
"""Real ASGI/catalog/encrypted SQLite/staging ECR controls, no provider traffic.

Uses the existing isolated workspace initializer and the application middleware
and router, without starting a socket listener. Only the absent gate readiness
observation is supplied while creating the exact signed catalog rule. This does
not claim Rust proxy, external HTTP, AWS signing or provider publication proof.
"""
import asyncio
import base64
from contextlib import closing
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import unquote
import uuid

import test_operator_catalog_github as diagnostics
import test_operator_workspace_store as workspace
from test_operator_notifications_connected_backend import FullASGI

ROOT = Path(__file__).resolve().parents[1]
ADMIN_TOKEN = "synthetic-ecr-admin-" + "A" * 32
MACHINE_TOKEN = "synthetic-ecr-gate-" + "G" * 32
NETWORK_ATTEMPTS = []


def no_network(event, _args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("ECR API fixture forbids sockets and DNS")


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class Client:
    """Small response adapter over the existing socket-free ASGI harness."""
    def __init__(self, application):
        async def routed(scope, receive, send):
            path, _, query = scope["path"].partition("?")
            scope = {**scope, "path": unquote(path), "raw_path": path.encode(), "query_string": query.encode()}
            await application(scope, receive, send)
        self.transport = FullASGI(routed, ADMIN_TOKEN)

    async def request(self, method, path, *, content=None, headers=()):
        values = list(headers.items()) if isinstance(headers, dict) else list(headers)
        if content is not None and not any(key.lower() == "content-length" for key, _ in values):
            values.append(("content-length", str(len(content))))
        result = await self.transport.request(method, path, values, content or b"", authenticate=False)
        raw = base64.b64decode(result["body_b64"])
        return SimpleNamespace(status_code=result["status"], content=raw, text=raw.decode(),
            headers={key.lower(): value for key, value in result["headers"]}, json=lambda: json.loads(raw))

    async def post(self, path, **kwargs):
        return await self.request("POST", path, **kwargs)


class Fixture:
    def __init__(self):
        self.config, self.db, self.store, _, self.schema, self.inputs, self.mutations = workspace.workspace()
        from serverware import app, operator_catalog_ecr as ecr, operator_ecr_publications_api as api
        from serverware import ecr_image_artifact as artifact
        self.app, self.api = app, api
        self.stack = []
        for name in ("loaded_policy_hash", "loaded_gate_status"):
            item = patch.object(self.store, name, return_value=None)
            item.start()
            self.stack.append(item)
        credential = self.mutations.create_aws_credential(self.inputs.AwsSigV4CredentialInput(
            **self.review(), name="ECR API encrypted fixture", credential_kind="long_term",
            access_key_id="AKIA" + "F" * 16, secret_access_key="G" * 40,
            session_token=None, expires_at=None), "fixture")["credential"]
        self.primary = self.application("ECR publisher")
        self.other = self.application("Other client")
        self.scope = {"registry_id": "123456789012", "region": "us-east-1",
            "repository_name": "fixture/repository", "image_tag": "reviewed"}
        with patch.object(ecr, "require_available", return_value=None):
            rule = self.mutations.create_ecr_rule(self.inputs.AwsEcrRuleInput(**self.review(),
                name="Exact ECR image", application_id=self.primary["id"], credential_id=credential["id"],
                operation_bundle="aws_ecr_publish_v1", approval_mode="host_review_v1", **self.scope), "fixture")
        self.rule = rule["access_rule"]
        self.policy = self.store.get_policy_high_water()["policy_hash"]
        self.primary, self.other = [next(row for row in workspace.catalog(self.db, self.schema)["applications"]
            if row["id"] == item["id"]) for item in (self.primary, self.other)]
        vector = json.loads((ROOT / "scripts/fixtures/ecr_image_artifact_v1.json").read_bytes())
        self.manifest = vector["manifest"].encode()
        self.blobs = {item["digest"]: item["utf8"].encode() for item in vector["blobs"]}
        self.image = artifact.verify_image(self.manifest, {key: io.BytesIO(raw) for key, raw in self.blobs.items()})
        spec = importlib.util.spec_from_file_location("ecr_client_contract", ROOT / "examples/ecr-publish-python/publish.py")
        self.example = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.example)
        self.client_config = {"application_id": self.primary["id"], "access_rule_id": self.rule["id"],
            "expected_policy_hash": self.policy, **self.scope}
        self.create_body = {key: self.client_config[key] for key in
            ("application_id", "access_rule_id", "expected_policy_hash")}
        self.create_body.update(manifest_digest=self.image.manifest.digest, artifact_sha256=self.image.commitment_sha256)

    def close(self):
        for identifier in list(self.api.owner._HANDLES):
            self.api.owner._drop(identifier)
        for item in reversed(self.stack):
            item.stop()

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def application(self, name):
        return self.mutations.create_application(self.inputs.ApplicationInput(**self.review(),
            name=name, token_lifetime_seconds=3600), "fixture")["application"]

    def headers(self, *, admin=False, application=None):
        if admin:
            return {"x-serverware-admin-token": ADMIN_TOKEN, "origin": self.config.PUBLIC_URL.rstrip("/")}
        application = application or self.primary
        return {"x-serverware-data-plane-token": MACHINE_TOKEN,
            "x-serverware-principal-id": application["principal_id"],
            "x-serverware-client-token-sha256": application["token_sha256"],
            "x-serverware-policy-hash": self.policy}

    async def call(self, client, method, path, body=None, *, expected=200, headers=None, binary=False):
        selected = self.headers() if headers is None else dict(headers)
        raw = body if isinstance(body, bytes) else encoded(body) if body is not None else None
        if raw is not None:
            selected.setdefault("content-type", "application/octet-stream" if binary else "application/json")
        result = await client.request(method, path, content=raw, headers=selected)
        assert result.status_code == expected, (path, result.status_code, expected, result.text[:300])
        assert result.headers["cache-control"] == "no-store"
        assert result.headers["pragma"] == "no-cache"
        assert all(value.encode() not in result.content for value in (MACHINE_TOKEN, ADMIN_TOKEN, "G" * 40, self.primary["token_sha256"]))
        return result.json()

    def dto(self, value):
        return self.example.publication(value, self.client_config, image=self.image)


async def lifecycle(f, client):
    api = f.api
    item = f.dto(await f.call(client, "POST", api.CLIENT, f.create_body, expected=201))
    identifier = item["id"]
    path = api.CLIENT + "/" + identifier
    assert item["status"] == "staging"
    f.dto(await f.call(client, "GET", path))
    await f.call(client, "GET", path, {}, expected=400)
    await f.call(client, "GET", path + "?unexpected=1", expected=400)
    await f.call(client, "GET", path, headers=f.headers(application=f.other), expected=409)
    await f.call(client, "POST", path + "/activate", {}, expected=409)
    f.dto(await f.call(client, "POST", path + "/manifest", f.manifest, binary=True))
    for digest, raw in f.blobs.items():
        f.dto(await f.call(client, "POST", path + "/blobs/" + digest[7:] + "/parts/0", raw, binary=True))
    item = f.dto(await f.call(client, "POST", path + "/submit", {}))
    assert item["status"] == "awaiting_review" and item["artifact"] == f.image.commitment()
    await f.call(client, "POST", path + "/activate", {}, expected=409)
    admin = api.ADMIN + "/" + identifier
    review = await f.call(client, "POST", admin + "/review", {}, headers=f.headers(admin=True))
    decision = {key: review[key] for key in ("review_receipt_id", "review_digest")}
    decision.update(decision="approve", note=None)
    item = f.dto(await f.call(client, "POST", admin + "/decision", decision, headers=f.headers(admin=True)))
    assert item["status"] == "approved"
    await f.call(client, "POST", admin + "/decision", decision, headers=f.headers(admin=True), expected=409)
    active = f.dto(await f.call(client, "POST", path + "/activate", {}))
    assert active["status"] == "active" and active["expires_at_epoch_ms"] == item["expires_at_epoch_ms"]
    assert active["progress"]["calls"] == 0 and active["child"] is None
    f.dto(await f.call(client, "GET", admin, headers=f.headers(admin=True)))
    listing = await f.call(client, "GET", api.ADMIN, headers=f.headers(admin=True))
    assert [entry["id"] for entry in listing["publications"]] == [identifier]
    await f.call(client, "POST", path + "/manifest", f.manifest, binary=True, expected=409)
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM operator_ecr_child_ids").fetchone()[0] == 0
    assert f.db.verify_audit_chain()["ok"]


async def admission_controls(f, client):
    from fastapi import HTTPException
    from starlette.requests import Request
    from serverware import operator_demo, auth
    api = f.api
    identifier = str(uuid.uuid4())
    paths = [api.CLIENT, api.CLIENT + "/" + identifier + "/manifest",
        api.CLIENT + "/" + identifier + "/submit", api.CLIENT + "/" + identifier + "/activate",
        api.CLIENT + "/" + identifier + "/blobs/" + "a" * 64 + "/parts/0",
        api.ADMIN + "/" + identifier + "/review", api.ADMIN + "/" + identifier + "/decision"]
    for path in paths:
        assert api.owns_post(path) and operator_demo.request_allowed("POST", path)
        assert not operator_demo.request_allowed("PUT", path)
        assert not api.owns_post(path + "/extra")
    assert operator_demo.request_allowed("GET", api.ADMIN)
    assert operator_demo.request_allowed("GET", api.CLIENT + "/" + identifier)
    # Authentication precedes body consumption even through the real classifier.
    for extra, expected in (({}, 401), ({"x-serverware-data-plane-token": "wrong"}, 401)):
        reads = []
        async def receive():
            reads.append(True)
            raise AssertionError("unauthenticated body was read")
        request = Request({"type": "http", "method": "POST", "path": api.CLIENT,
            "raw_path": api.CLIENT.encode(), "query_string": b"", "headers":
                [(key.encode(), value.encode()) for key, value in extra.items()]}, receive)
        async def invoke(current):
            return await api.create(current)
        try:
            await f.app.bounded_control_plane_request_middleware(request, invoke)
        except HTTPException as error:
            assert error.status_code == expected
        else:
            raise AssertionError("unauthenticated ECR create admitted")
        assert not reads
    for key, value, expected in (("authorization", "Bearer x", 401), ("origin", f.config.PUBLIC_URL, 401),
            ("cookie", "admin=x", 401), ("x-serverware-principal-id", "unknown", 409),
            ("x-serverware-client-token-sha256", "sha256:" + "0" * 64, 409),
            ("x-serverware-policy-hash", "sha256:" + "0" * 64, 409)):
        await f.call(client, "POST", api.CLIENT, f.create_body,
            headers={**f.headers(), key: value}, expected=expected)
    for body in ({**f.create_body, "extra": True}, {key: value for key, value in f.create_body.items()
            if key != "manifest_digest"}, {**f.create_body, "application_id": True},
            {**f.create_body, "manifest_digest": "not-a-digest"}):
        await f.call(client, "POST", api.CLIENT, body, expected=422)
    for key, value, expected in (("content-type", "application/json; charset=utf-8", 415),
            ("content-encoding", "gzip", 415), ("transfer-encoding", "chunked", 415),
            ("content-length", "01", 400), ("content-length", "0", 413),
            ("content-length", "16385", 413), ("content-length", "1", 400)):
        await f.call(client, "POST", api.CLIENT, f.create_body,
            headers={**f.headers(), key: value}, expected=expected)
    duplicate = list(f.headers().items()) + [("content-type", "application/json"), ("x-serverware-policy-hash", f.policy)]
    result = await client.post(api.CLIENT, content=encoded(f.create_body), headers=duplicate)
    assert result.status_code == 400
    for raw in (b'{"application_id":1,"application_id":2}', b'{"x":NaN}'):
        await f.call(client, "POST", api.CLIENT, raw, expected=422)
    await f.call(client, "POST", api.CLIENT + "?unexpected=1", f.create_body, expected=400)
    await f.call(client, "POST", api.CLIENT.replace("ecr-publications", "ecr%2dpublications"),
        f.create_body, expected=400)
    await f.call(client, "POST", api.CLIENT, {**f.create_body, "application_id": f.other["id"]}, expected=409)
    await f.call(client, "POST", api.ADMIN + "/" + identifier + "/review", {}, headers={}, expected=401)
    await f.call(client, "POST", api.ADMIN + "/" + identifier + "/review", {},
        headers={"x-serverware-admin-token": ADMIN_TOKEN, "origin": "https://other.test"}, expected=403)
    request = Request({"type": "http", "method": "POST", "path": api.ADMIN,
        "query_string": b"", "headers": [(b"origin", f.config.PUBLIC_URL.encode())]})
    for identity in (auth.AdminIdentity("wrong-admin", frozenset({"admin"}), "admin-token-header"),
            auth.AdminIdentity(f.config.ADMIN_USER_ID, frozenset({"viewer"}), "admin-token-header"),
            auth.AdminIdentity(f.config.ADMIN_USER_ID, frozenset({"admin"}), "bearer-token")):
        try:
            api._administrator(request, identity, mutation=True)
        except HTTPException as error:
            assert error.status_code == 403
        else:
            raise AssertionError("wrong administrator identity admitted")
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM operator_ecr_publications").fetchone()[0] == 0
    identity = (f.primary["principal_id"], f.primary["token_sha256"], f.policy)
    with patch.object(api.time, "time_ns", return_value=f.primary["token_expires_at_epoch_ms"] * 1_000_000):
        try:
            api._current_client(identity)
        except api.owner.PublicationConflict:
            pass
        else:
            raise AssertionError("expired client admitted")
    f.mutations.rotate_application_token(f.inputs.RotateApplicationInput(**f.review(),
        id=f.primary["id"], token_lifetime_seconds=3600), "fixture")
    await f.call(client, "POST", api.CLIENT, f.create_body, expected=409)
    current_hash = f.store.get_policy_high_water()["policy_hash"]
    assert current_hash != f.policy
    await f.call(client, "POST", api.CLIENT, {**f.create_body, "expected_policy_hash": current_hash},
        headers={**f.headers(), "x-serverware-policy-hash": current_hash}, expected=409)


async def worker(name):
    f = Fixture()
    try:
        await {"lifecycle": lifecycle, "admission": admission_controls}[name](f, Client(f.app.app))
        assert not NETWORK_ATTEMPTS
        return {"ok": True}
    finally:
        f.close()


class EcrPublicationApiTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        root = Path(self.scratch.name) / "artifacts"
        root.mkdir(mode=0o700)
        self.environment.update(SERVERWARE_ECR_ARTIFACT_ROOT=str(root),
            SERVERWARE_PUBLIC_URL="https://console.example.com", SERVERWARE_ADMIN_TOKEN=ADMIN_TOKEN,
            SERVERWARE_DATA_PLANE_INSTANCE_ID="synthetic-ecr-api-gate",
            SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN=MACHINE_TOKEN,
            SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com","https://api.ecr.us-east-1.amazonaws.com"]')

    def check(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        if result.returncode:
            self.fail(diagnostics.worker_failure_summary(result))
        self.assertEqual(json.loads(result.stdout), {"ok": True})

    def test_actual_stage_review_activate_status_and_example_dto(self):
        self.check("lifecycle")

    def test_closed_admission_current_client_framing_and_administrator(self):
        self.check("admission")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        try:
            print(json.dumps(asyncio.run(worker(sys.argv[2]))))
        except Exception as error:
            print(json.dumps(diagnostics.safe_worker_failure(error)))
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)
