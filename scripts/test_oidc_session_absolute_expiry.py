#!/usr/bin/env python3
"""Focused source/real-SQLite/cookie controls, not a live OIDC/custody proof.

Source-extracted DB functions execute their real SQL against source DDL and the
actual SQLite clock. The authority lock and external provider authentication are
explicit fixture boundaries; no registry import, native PG, network or services.
"""
from __future__ import annotations

import ast
import base64
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from types import SimpleNamespace
from typing import Any
import unittest
import urllib.request
import uuid

from starlette.responses import Response


ROOT = Path(__file__).resolve().parents[1]
SOURCES = {name: (ROOT / "serverware" / name).read_text() for name in (
    "config.py", "db.py", "db_common.py", "rbac.py", "operator_oidc.py", "app.py",
    "authority_store/metadata_schema_source.py", "authority_transition_oidc_session_activation.py",
    "authority_transition_oidc_session_activation_delivery.py",
    "control_plane_oidc_session_activation_delivery.py",
    "control_plane_oidc_session_activation_recovery_delivery.py",
    "control_plane_oidc_session_activation_completion_recovery_delivery_response.py",
)}


def definitions(name, selected, namespace):
    nodes = [node for node in ast.parse(SOURCES[name]).body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in selected]
    if {node.name for node in nodes} != set(selected):
        raise AssertionError("source definitions changed")
    module = ast.Module(body=[*ast.parse("from __future__ import annotations").body, *nodes], type_ignores=[])
    exec(compile(module, name, "exec"), namespace)


class Rows:
    def __init__(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        for table in ("webauthn_credentials", "oidc_browser_sessions", "oidc_session_activation_deliveries"):
            match = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \(.*?\n            \);",
                              SOURCES["authority_store/metadata_schema_source.py"], re.S)
            if match is None:
                raise AssertionError("source DDL missing")
            self.connection.executescript(match.group(0))
        self.opens = self.locks = self.serial = 0
        self.ns = dict(datetime=datetime, timezone=timezone, timedelta=timedelta, json=json,
                       re=re, uuid=uuid, Any=Any, Iterable=Iterable,
                       PostgresMetadataConnection=type("UnusedPostgresBoundary", (), {}))
        for node in ast.parse(SOURCES["db.py"]).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.startswith("_OIDC_BROWSER_SESSION_"):
                        # Keep the source's fixed arithmetic (for example
                        # 4 * 1024); literal_eval deliberately excludes it.
                        exec(compile(ast.Module(body=[node], type_ignores=[]), "db.py", "exec"), self.ns)
        role_tree = ast.parse(SOURCES["rbac.py"])
        roles = next(node for node in role_tree.body if isinstance(node, ast.Assign))
        exec(compile(ast.Module(body=[roles], type_ignores=[]), "rbac.py", "exec"), self.ns)
        definitions("rbac.py", ("RBACRoleValidationError", "normalize_rbac_roles"), self.ns)
        definitions("db_common.py", ("dumps", "loads"), self.ns)
        definitions("db.py", ("MetadataStoreError", "_metadata_utcnow", "_oidc_browser_session_digest",
            "_oidc_browser_session_text", "_oidc_browser_session_roles", "_prune_oidc_activation_deliveries",
            "_prune_oidc_browser_sessions", "row_to_oidc_browser_session", "create_oidc_browser_session",
            "activate_oidc_browser_session", "get_oidc_browser_session_recovery_target"), self.ns)
        self.ns.update(connect=self.connect, _lock_webauthn_authority=self.lock)

    def connect(self):
        self.opens += 1
        return self.connection

    def lock(self, conn):
        assert conn is self.connection
        self.locks += 1  # Fixture boundary, not PostgreSQL lock evidence.

    def now(self):
        return self.ns["_metadata_utcnow"](self.connection)

    def create(self, **overrides):
        self.serial += 1
        values = dict(token_digest="sha256:" + hashlib.sha256(str(self.serial).encode()).hexdigest(),
            oidc_token_digest="sha256:" + "a" * 64, user_id="user:fixture", roles=["admin"],
            ttl_seconds=600, provider_expires_at_epoch=int(self.now().timestamp()) + 1200,
            require_webauthn=False, pending_ttl_seconds=120)
        values.update(overrides)
        return self.ns["create_oidc_browser_session"](**values)


def operator(cap, now):
    namespace = dict(datetime=datetime, timezone=timezone, time=SimpleNamespace(time=lambda: now),
                     OIDC_SESSION_NOT_AFTER_EPOCH=cap, Any=Any)
    definitions("operator_oidc.py", ("OperatorOIDCError", "_oidc_session_cookie_lifetime",
                "oidc_session_cookie_attributes", "oidc_session_cookie_options"), namespace)
    return namespace


class AbsoluteExpiryControls(unittest.TestCase):
    def setUp(self):
        self.rows = Rows()
        self.addCleanup(self.rows.connection.close)

    def test_01_canonical_configuration_and_db_argument_refusals(self):
        namespace = {}
        definitions("config.py", ("_oidc_session_not_after_epoch",), namespace)
        parse = namespace["_oidc_session_not_after_epoch"]
        self.assertIsNone(parse(None))
        for value in ("1", "1900000000", "253402300799"):
            self.assertEqual(parse(value), int(value))
        for value in ("", "0", "01", "+1", " 1", "1 ", "1.0", "1e3", "\u0661", "253402300800", "9" * 100):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                parse(value)
        for value in (True, False, 0, -1, 1.5, "1900000000", 253402300800):
            opened = self.rows.opens
            with self.subTest(value=value), self.assertRaises(self.rows.ns["MetadataStoreError"]):
                self.rows.create(absolute_not_after_epoch=value)
            self.assertEqual(self.rows.opens, opened)
        expired = int(self.rows.now().timestamp())
        with self.assertRaisesRegex(self.rows.ns["MetadataStoreError"], "not-after has elapsed"):
            self.rows.create(absolute_not_after_epoch=expired)
        self.assertEqual(self.rows.connection.execute("SELECT COUNT(*) FROM oidc_browser_sessions").fetchone()[0], 0)

    def test_02_db_clock_provider_ttl_cap_and_pending_minima(self):
        for pending in (False, True):
            for bound in (None, int(self.rows.now().timestamp()) + 60):
                row = self.rows.create(require_webauthn=pending, absolute_not_after_epoch=bound)
                created = datetime.fromisoformat(row["created_at"])
                provider = datetime.fromisoformat(row["provider_expires_at"])
                expected = min(created + timedelta(seconds=600), provider)
                if bound is not None:
                    expected = min(expected, datetime.fromtimestamp(bound, timezone.utc))
                    self.assertGreater(provider, expected)
                self.assertEqual(row["expires_at"], expected.isoformat())
                self.assertEqual(row["pending_expires_at"],
                    min(created + timedelta(seconds=120), expected).isoformat() if pending else None)
        now = int(self.rows.now().timestamp())
        provider_first = self.rows.create(provider_expires_at_epoch=now + 30, absolute_not_after_epoch=now + 100)
        self.assertEqual(provider_first["expires_at"], provider_first["provider_expires_at"])
        ttl_first = self.rows.create(ttl_seconds=10, absolute_not_after_epoch=now + 100)
        self.assertEqual(datetime.fromisoformat(ttl_first["expires_at"]) - datetime.fromisoformat(ttl_first["created_at"]), timedelta(seconds=10))
        self.assertEqual(self.rows.opens, self.rows.locks)

    def test_03_stored_activation_preserves_cap_and_recovery_lookup_expires(self):
        cap = int(self.rows.now().timestamp()) + 60
        row = self.rows.create(require_webauthn=True, absolute_not_after_epoch=cap)
        self.rows.connection.execute("""INSERT INTO webauthn_credentials
            (id, credential_id, user_id, label, public_key_cose, created_at, updated_at)
            VALUES ('credential', 'synthetic', 'user:fixture', 'fixture', 'synthetic', ?, ?)""",
            (row["created_at"], row["created_at"]))
        activated = self.rows.ns["activate_oidc_browser_session"](
            token_digest=row["token_digest"], credential_record_id="credential")
        self.assertTrue(activated["ok"])
        self.assertEqual(activated["session"]["expires_at"], row["expires_at"])
        self.assertEqual(activated["session"]["provider_expires_at"], row["provider_expires_at"])
        self.assertIsNone(activated["session"]["pending_expires_at"])
        target = self.rows.ns["get_oidc_browser_session_recovery_target"]
        self.assertIsNotNone(target(user_id=row["user_id"], session_id=row["id"]))
        # Explicit advanced DB-clock double for the boundary, not elapsed live time.
        self.rows.ns["_metadata_utcnow"] = lambda conn: datetime.fromtimestamp(cap, timezone.utc)
        self.assertIsNone(target(user_id=row["user_id"], session_id=row["id"]))
        transition = ast.parse(SOURCES["authority_transition_oidc_session_activation.py"])
        updated = next(node.value for node in ast.walk(transition) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "updated_session" for target in node.targets))
        self.assertIsInstance(updated, ast.Dict)
        self.assertEqual(ast.unparse(updated.values[0]), "session")
        self.assertNotIn("expires_at", [key.value for key in updated.keys if isinstance(key, ast.Constant)])
        self.assertIn("delivery_expires <= session_expires <= provider_expires",
                      SOURCES["authority_transition_oidc_session_activation_delivery.py"])

    def test_04_actual_login_forwards_only_server_cap_into_stored_row(self):
        cap = int(self.rows.now().timestamp()) + 60
        provider = cap + 600
        token = "fixture." + base64.urlsafe_b64encode(json.dumps({"exp": provider}).encode()).decode().rstrip("=") + ".fixture"
        ns = operator(cap, cap - 50)
        ns.update(base64=base64, hashlib=hashlib, json=json,
            secrets=SimpleNamespace(token_urlsafe=lambda size: "T" * 64),
            request_bytes=lambda *args, **kwargs: SimpleNamespace(body=json.dumps({"id_token": token}).encode()),
            browser_login_configured=lambda: True, _token_request=lambda *args: None,
            oidc_identity_from_token=lambda *args, **kwargs: SimpleNamespace(user_id="user:fixture", roles={"admin"}),
            OIDCAuthError=type("OIDCAuthError", (Exception,), {}), OIDCAccessDenied=type("OIDCAccessDenied", (Exception,), {}),
            OIDCAuthoritativeStateError=type("OIDCAuthoritativeStateError", (Exception,), {}),
            HttpClientError=type("HttpClientError", (Exception,), {}), urllib=urllib,
            MAX_TOKEN_RESPONSE_BYTES=256*1024, MAX_SESSION_ID_TOKEN_BYTES=3500,
            OIDC_SESSION_TTL_SECONDS=600, OIDC_SESSION_WEBAUTHN_PENDING_TTL_SECONDS=120,
            OIDC_SESSION_WEBAUTHN_REQUIRED=True,
            db=SimpleNamespace(MetadataStoreError=self.rows.ns["MetadataStoreError"],
                consume_oidc_login_state=lambda **kwargs: {"code_verifier":"fixture", "oidc_nonce":"fixture"},
                create_oidc_browser_session=self.rows.ns["create_oidc_browser_session"]))
        definitions("operator_oidc.py", ("complete_operator_login",), ns)
        completed = ns["complete_operator_login"](state="fixture", code="fixture", browser_nonce="fixture")
        self.assertEqual(completed["session"]["expires_at"], datetime.fromtimestamp(cap, timezone.utc).isoformat())
        self.assertEqual(completed["session"]["pending_expires_at"], completed["session"]["expires_at"])
        self.assertEqual(completed["expires_at"], provider)
        self.assertEqual(completed["cookie_max_age"], 50)

    def test_05_actual_cookie_serialization_and_elapsed_subsecond_refusal(self):
        cap = 1900000000
        expiry = datetime.fromtimestamp(cap, timezone.utc)
        session = dict(status="pending_webauthn", expires_at=(expiry + timedelta(seconds=20)).isoformat(),
                       pending_expires_at=expiry.isoformat())
        for configured in (None, cap):
            ns = operator(configured, cap - 10.5)
            response = Response()
            response.set_cookie("session", "synthetic", **ns["oidc_session_cookie_options"](session),
                                httponly=True, secure=True, samesite="strict")
            cookie = response.headers["set-cookie"].lower()
            self.assertIn("httponly", cookie)
            if configured is None:
                self.assertIn("max-age=10", cookie)
                self.assertNotIn("expires=", cookie)
            else:
                self.assertIn("expires=", cookie)
                self.assertNotIn("max-age", cookie)
        for now in (cap - 0.5, cap, cap + 1):
            ns = operator(cap, now)
            with self.assertRaises(ns["OperatorOIDCError"]):
                ns["oidc_session_cookie_options"](session)

    def test_06_three_protected_cookie_sites_use_retained_expiry_and_exact_headers(self):
        cap = 1900000000
        ns = operator(cap, cap - 20)
        for name in ("control_plane_oidc_session_activation_delivery.py",
                     "control_plane_oidc_session_activation_recovery_delivery.py",
                     "control_plane_oidc_session_activation_completion_recovery_delivery_response.py"):
            source = SOURCES[name]
            tree = ast.parse(source)
            emitters = [node for node in ast.walk(tree) if isinstance(node, ast.Lambda)
                and isinstance(node.body, ast.Call) and isinstance(node.body.func, ast.Attribute)
                and node.body.func.attr == "set_cookie"]
            self.assertEqual(len(emitters), 1)
            response = Response()
            request = SimpleNamespace(url=SimpleNamespace(scheme="https"))
            scope = dict(ns, response=response, request=request, max_age=20,
                         staged=SimpleNamespace(_session_expiry=cap*10**9, _request=request),
                         application=SimpleNamespace(OIDC_SESSION_COOKIE_NAME="session"), active_token="synthetic")
            eval(compile(ast.Expression(body=emitters[0]), name, "eval"), scope)()
            self.assertIn("expires=", response.headers["set-cookie"].lower())
            self.assertNotIn("max-age", response.headers["set-cookie"].lower())
            self.assertIn("now >= self._session_expiry", source)
            before_send = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_before_send")
            self.assertIn("self._current()", ast.unparse(before_send))
            self.assertIn("self._cookie", ast.unparse(before_send))
            self.assertIn('b"set-cookie"', source)
        self.assertIn("cookie_options = oidc_session_cookie_options(completed[\"session\"])", SOURCES["app.py"])
        self.assertIn("cookie_options = oidc_session_cookie_options(active_session)", SOURCES["app.py"])
        self.assertIn('"automaticRetryAllowed": False', SOURCES["app.py"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
