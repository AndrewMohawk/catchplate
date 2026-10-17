#!/usr/bin/env python3
"""Real full-ASGI first-X-configuration stories in fresh network-none workers.

The actual cold startup, administrator/origin admission, publication lock,
SQLite transaction, AES-GCM custody and audit chain are not substituted. The
only injected fault discards a completed response at the ASGI transport-return
boundary. This is backend integration, not browser, TCP, X consent, deployed
readiness, or native-authority acceptance. No provider request is permitted.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import traceback
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import test_operator_google_managed_config as fixtures
from test_operator_notifications_connected_backend import FAILURE_CONTEXT, FullASGI, require

ORIGIN = "https://console.example.com"
PREFIX = "/api/operator-demo/oauth/x/configuration/v1"
ADMIN = "synthetic-connected-X-configuration-administrator"
CLIENT = "synthetic-connected-X-application"
SECRET = "synthetic-connected-X-client-secret-NEVER-PERSIST-PLAINTEXT"
RESULT = "CONNECTED_X_RESULT "
NETWORK_ATTEMPTS = []


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("connected X configuration attempted network contact")


def public_clean(value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    require(all(secret.encode() not in raw for secret in
        (SECRET, ADMIN, fixtures.workspace.common._PROVIDER_SECRET)), "private fixture material exposed")


def key_evidence(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 512,
        "dedicated key file identity")
    raw = path.read_bytes()
    public_clean(raw)
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode),
        info.st_size, hashlib.sha256(raw).hexdigest())


class ResponseLost(RuntimeError):
    """Fixed synthetic transport failure after the real handler completed."""


class LoseFirstSaveResponse:
    def __init__(self, application, enabled):
        self.application, self.enabled = application, enabled
        self.dropped = False
        self.status = None

    async def __call__(self, scope, receive, send):
        drop = (self.enabled and not self.dropped and scope["type"] == "http"
            and scope["method"] == "POST" and scope["path"] == PREFIX)

        async def observed_send(message):
            if drop and message["type"] == "http.response.start":
                self.status = message["status"]
            if message["type"] == "http.response.body":
                public_clean(message.get("body", b""))
            await send(message)

        await self.application(scope, receive, observed_send)
        if drop:
            require(self.status == 201, "lost-response fault requires actual successful save")
            self.dropped = True
            # FullASGI has collected bytes, but its caller receives no response
            # or receipt. No handler, transaction, or success value is mocked.
            raise ResponseLost("synthetic completed response was not delivered")


async def request(app, method, path=PREFIX, *, body=None, status=200, authenticate=True,
        origin=ORIGIN):
    raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = [] if body is None else [("origin", origin), ("content-type", "application/json"),
        ("content-length", str(len(raw)))]
    response = await app.request(method, path, headers, raw, authenticate=authenticate)
    public_clean(response)
    require(response["status"] == status, "unexpected real application status")
    # The outer signed-response owner emits Title-Case security headers;
    # HTTP names remain case-insensitive even for pre-handler refusals.
    headers_by_name = {name.lower(): value for name, value in response["headers"]}
    require(headers_by_name.get("cache-control") == "no-store", "API cache boundary")
    payload = base64.b64decode(response["body_b64"], validate=True)
    public_clean(payload)
    return json.loads(payload)


def globals_unconfigured(fixture):
    config = fixture.config
    require(config.X_OAUTH_CLIENT_ID == "" and config.X_OAUTH_CLIENT_SECRET == ""
        and config.X_OAUTH_CLIENT_SECRET_FILE is None
        and config.X_OAUTH_REDIRECT_URI == ORIGIN + "/api/oauth/callback/x"
        and not any(key.startswith(("CATCHPLATE_X_OAUTH_", "CATCHPLATE_TWITTER_OAUTH_"))
            for key in os.environ), "legacy X configuration was hot-adopted")


def inspect_commit(fixture, before_catalog, before_audit, authority, settings, operation):
    from catchplate import operator_x_configuration as service, operator_x_admission as admission
    from catchplate import operator_x_provider_custody as custody, operator_provider_key as keys

    require(fixture.authority() == authority and fixture.rows("operator_demo_settings") == settings,
        "X configuration changed existing authority or settings")
    catalog = fixtures.workspace.catalog(fixture.db, fixture.schema)
    require(catalog == {**before_catalog, "revision": before_catalog["revision"] + 1},
        "configuration must change exactly one catalog revision and no resources")
    audit = fixture.rows("audit_events")
    require(audit[:-1] == before_audit and len(audit) == len(before_audit) + 1,
        "configuration must append exactly one event")
    event = audit[-1]
    require(event["event_type"] == service.EVENT and event["actor_type"] == "admin"
        and event["actor_id"] == fixtures.ACTOR
        and event["id"] == "operator-x-configuration:" + operation["operation_id"], "exact save audit")
    require(fixture.db.verify_audit_chain().get("ok") is True, "actual audit chain")
    fixtures.workspace.verify_signed(fixture.config, fixture.db, fixture.store, fixture.bundles)
    directory = admission.require_runtime()
    require(stat.S_IMODE(directory.path.stat().st_mode) == 0o700, "private X directory")
    require({path.name for path in directory.path.iterdir()} == {keys.FILENAME}, "exact X key inventory")
    key_path = directory.path / keys.FILENAME
    evidence = key_evidence(key_path)
    require(evidence[2:4] == (os.geteuid(), 0o600), "private owned X key")
    with closing(fixture.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        rows = conn.execute("SELECT * FROM operator_x_configuration").fetchall()
        require(len(rows) == 1, "one retained configuration")
        binding = json.loads(rows[0]["binding_json"])
        require(binding["operation_id"] == operation["operation_id"]
            and binding["actor_id"] == fixtures.ACTOR
            and binding["reviewed_revision"] == before_catalog["revision"]
            and binding["committed_revision"] == operation["committed_revision"]
            and binding["public_profile"] == operation["public_profile"]
            and binding["profile_binding_digest"] == operation["profile_binding_digest"],
            "actual retained operation binding")
        owner = admission.admit_owner(binding["owner_id"])
        bound = custody.bind_x(owner, config_version=1, public_profile=binding["public_profile"])
        pin = keys.read_existing_pinned(directory, owner.owner_id)
        try:
            require(custody.read_secret(conn, owner, bound, key=pin.material).secret == SECRET,
                "actual authenticated ciphertext readback")
            keys.check_pin(pin)
        finally:
            keys.close_pin(pin)
        require(conn.execute("SELECT count(*) FROM " + custody.TABLE).fetchone()[0] == 1,
            "one ciphertext version")
        public_clean("\n".join(conn.iterdump()).encode())
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(fixture.config.DB_PATH) + suffix)
        if path.exists():
            require(path.stat().st_size <= 32 * 1024**2, "bounded fixture database")
            public_clean(path.read_bytes())
    globals_unconfigured(fixture)
    return key_path, evidence


async def story(mode):
    require(ROOT == Path("/app"), "isolated read-only app source required")
    interfaces = {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()
        if ":" in line}
    require(interfaces == {"lo"}, "network-none required")
    os.umask(0o077)  # Match the real runner before runtime imports or database creation.
    sys.addaudithook(no_network)
    fixture = fixtures.Fixture()  # Actual bootstrap/admission after the X environment was selected.
    fixture.seed()  # Preserve nonempty real credentials, applications, rules, nonce, policy and CA.
    require(stat.S_IMODE(fixture.config.DB_PATH.lstat().st_mode) == 0o600, "private retained database mode")
    from catchplate import operator_x_configuration as service

    transport = LoseFirstSaveResponse(fixture.app.app, mode == "lost")
    app = FullASGI(transport, ADMIN)
    started = False
    process = os.getpid()
    try:
        await app.start()
        started = True
        authority, settings = fixture.authority(), fixture.rows("operator_demo_settings")
        before_catalog = fixtures.workspace.catalog(fixture.db, fixture.schema)
        before_audit = fixture.rows("audit_events")
        unchanged = fixture.snapshot()
        lock_path = fixture.config.DATA_DIR / fixture.store.operator_publication.LOCK_NAME
        lock_before = lock_path.stat()
        x_directory = Path(os.environ["CATCHPLATE_OPERATOR_X_CUSTODY_DIR"])
        google_directory = Path(os.environ["CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR"])
        require(not list(x_directory.iterdir()) and not list(google_directory.iterdir()), "initial empty custody")
        globals_unconfigured(fixture)
        denied = await request(app, "GET", authenticate=False, status=401)
        require(denied == {"detail": "administrator authentication required"}
            and fixture.snapshot() == unchanged and not list(x_directory.iterdir())
            and not list(google_directory.iterdir()), "exact unauthenticated denial without service effects")
        # The fault applies only after these authentic admission negatives.
        transport.enabled = False
        await request(app, "POST", body={}, origin="https://foreign.example.com", status=403)
        transport.enabled = mode == "lost"
        discovery = await request(app, "GET")
        require(discovery["schema"] == service.SCHEMA and discovery["state"] == "unconfigured"
            and discovery["configuration"] is None and discovery["operation"] is None
            and discovery["consent_ready"] is False and discovery["blocked_reason"] is None
            and discovery["review"] == fixture.review(), "actual unconfigured discovery and CAS")
        require(await request(app, "GET") == discovery and fixture.snapshot() == unchanged
            and not list(x_directory.iterdir()) and not list(google_directory.iterdir()),
            "discovery or denial initialized storage")
        payload = {**discovery["review"], "operation_id": str(uuid.uuid4()),
            "client_id": CLIENT, "client_secret": SECRET}
        received = None
        try:
            received = await request(app, "POST", body=payload, status=201)
        except ResponseLost:
            require(mode == "lost" and transport.dropped, "only the explicit transport fault is accepted")
        require((received is None) == (mode == "lost") and transport.dropped == (mode == "lost"),
            "response delivery boundary")
        # The next action is status, never a save retry. It must find the exact
        # committed operation even when no response body reached the caller.
        operation = await request(app, "GET", PREFIX + "/" + payload["operation_id"])
        require(received is None or received == operation, "save/status receipt equality")
        require(operation["schema"] == service.OPERATION_SCHEMA and operation["status"] == "committed"
            and operation["operation_id"] == payload["operation_id"]
            and operation["committed_revision"] == discovery["revision"] + 1
            and operation["policy_hash"] == discovery["policy_hash"]
            and operation["client_secret_configured"] is True and operation["consent_ready"] is False,
            "exact committed operation")
        profile = operation["public_profile"]
        require(profile["client_id"] == CLIENT and profile["provider_id"] == "x"
            and profile["redirect_uri"] == ORIGIN + "/api/oauth/callback/x"
            and profile["client_auth_method"] == "client_secret_basic"
            and profile["permission_preset"] == "x_text_post_v1"
            and profile["scopes"] == ["offline.access", "tweet.read", "tweet.write", "users.read"]
            and profile["api_origins"] == ["https://api.x.com"], "actual exact X public profile")
        configured = await request(app, "GET")
        require(configured["state"] == "configured" and configured["operation"] == operation
            and configured["revision"] == operation["committed_revision"]
            and configured["policy_hash"] == discovery["policy_hash"]
            and configured["review"] is None and configured["blocked_reason"] == "already_configured"
            and configured["consent_ready"] is False, "configured without consent or restart claim")
        require(service.status(payload["operation_id"], fixtures.ACTOR) == operation, "actual actor recovery")
        try:
            service.status(payload["operation_id"], "different-synthetic-actor")
        except service.ConfigurationNotFound:
            pass
        else:
            raise AssertionError("foreign actor acquired configuration operation")
        key_path, key_before = inspect_commit(fixture, before_catalog, before_audit, authority, settings, operation)
        committed = fixture.snapshot()
        await request(app, "GET", PREFIX + "/" + str(uuid.uuid4()), status=404)
        # Deliberate negative controls, not automatic outcome retries.
        await request(app, "POST", body=payload, status=409)
        next_payload = {**payload, "operation_id": str(uuid.uuid4()),
            "expected_revision": operation["committed_revision"]}
        await request(app, "POST", body=next_payload, status=409)
        require(fixture.snapshot() == committed and key_evidence(key_path) == key_before,
            "repeat/refused save changed retained state")
        # Move only this fresh fixture's key outside its dedicated directory.
        # An existing configuration must never regenerate a missing key.
        retained_key = x_directory.parent / "retained-X-key"
        require(not retained_key.exists(), "fresh missing-key control target")
        key_path.rename(retained_key)
        await request(app, "GET", status=503)
        await request(app, "GET", PREFIX + "/" + payload["operation_id"], status=503)
        await request(app, "POST", body=next_payload, status=503)
        require(not key_path.exists() and not list(x_directory.iterdir())
            and key_evidence(retained_key) == key_before and fixture.snapshot() == committed,
            "missing key regenerated or changed committed state")
        require(fixture.authority() == authority and fixture.rows("operator_demo_settings") == settings
            and not list(google_directory.iterdir()), "retained authority or separate Google custody changed")
        lock_after = lock_path.stat()
        require((lock_after.st_dev, lock_after.st_ino, lock_after.st_mode) ==
            (lock_before.st_dev, lock_before.st_ino, lock_before.st_mode), "publication lock custody changed")
        globals_unconfigured(fixture)
        require(os.getpid() == process and not NETWORK_ATTEMPTS and not fixture.provider_calls,
            "unexpected restart or provider/network contact")
        return {"story": mode, "full_asgi": True, "revision_delta": 1, "save_audits": 1,
            "encrypted_readback": True, "retained_authority": True, "actor_recovery": True,
            "missing_key_regenerated": False, "lost_response": transport.dropped,
            "network_attempts": 0, "provider_calls": 0, "consent_ready": False}
    finally:
        if started:
            await app.stop()


class OperatorXConfigurationConnectedTests(unittest.TestCase):
    def setUp(self):
        fixtures.ManagedGoogleConfigurationTests.setUp(self)
        self.x_directory = Path(self.scratch.name) / "x-provider-custody"
        self.x_directory.mkdir(mode=0o700)
        self.environment.update(CATCHPLATE_OPERATOR_MANAGED_X_ENABLED="1",
            CATCHPLATE_OPERATOR_X_CUSTODY_DIR=str(self.x_directory), CATCHPLATE_PUBLIC_URL=ORIGIN,
            CATCHPLATE_ADMIN_TOKEN=ADMIN, CATCHPLATE_ADMIN_USER=fixtures.ACTOR,
            CATCHPLATE_ADMIN_ROLES="admin")
        for key in tuple(self.environment):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                self.environment.pop(key)

    def run_story(self, mode):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", mode],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=120)
        public_clean((result.stdout + result.stderr).encode())
        # Never echo arbitrary application logs or exception messages. Only our
        # fixed report and source location triples may become test diagnostics.
        lines = [line.removeprefix(RESULT) for line in result.stdout.splitlines() if line.startswith(RESULT)]
        self.assertEqual(len(lines), 1, "worker did not return its closed receipt")
        receipt = json.loads(lines[0])
        self.assertEqual(result.returncode, 0, json.dumps(receipt, sort_keys=True))
        self.assertEqual(receipt, {"story": mode, "full_asgi": True, "revision_delta": 1,
            "save_audits": 1, "encrypted_readback": True, "retained_authority": True,
            "actor_recovery": True, "missing_key_regenerated": False, "lost_response": mode == "lost",
            "network_attempts": 0, "provider_calls": 0, "consent_ready": False})

    def test_first_save_real_full_application(self):
        self.run_story("normal")

    def test_lost_response_status_recovery_without_effect_replay(self):
        self.run_story("lost")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker" and sys.argv[2] in {"normal", "lost"}:
        signal.alarm(110)
        try:
            result = asyncio.run(story(sys.argv[2]))
        except BaseException as error:
            frames = [[Path(frame.filename).name, frame.name, frame.lineno]
                for frame in traceback.extract_tb(error.__traceback__)[-10:]]
            result = {"failed": True, "frames": frames,
                "lifespan_frames": FAILURE_CONTEXT.get("lifespan_frames", [])}
            print(RESULT + json.dumps(result, sort_keys=True), flush=True)
            raise SystemExit(1) from None
        print(RESULT + json.dumps(result, sort_keys=True), flush=True)
    else:
        unittest.main()
