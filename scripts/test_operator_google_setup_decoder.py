#!/usr/bin/env python3
"""Pure legacy setup-decoder/import-boundary checks, not managed setup acceptance.

Uses only synthetic in-memory SQLite and bounded fresh subprocesses. No provider,
application bootstrap, configured database, publication write or live state runs.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.abc
import itertools
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FORBIDDEN = {"serverware.config", "serverware.db", "serverware.crypto"}


class ImportGuard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in FORBIDDEN:
            raise AssertionError("configured runtime import forbidden in early setup decoder")


if "--early-worker" in sys.argv:
    sys.meta_path.insert(0, ImportGuard())

from serverware import db_common
from serverware import operator_google_setup as setup

OPERATION = "11111111-2222-4333-8444-555555555555"
ACTOR = "synthetic-administrator"
CLIENT = "123-synthetic.apps.googleusercontent.com"
ORIGIN = "https://console.example.com"
POLICY = "sha256:" + "a" * 64
CREATED = "2026-10-10T10:00:00+00:00"
COMPLETED = "2026-10-10T10:01:00+00:00"
SECRET_SENTINEL = "synthetic-secret-must-not-appear-in-errors"


def legacy_hash(**value):
    """Independent copy of the pre-refactor wire algorithm, not helper reuse."""
    encoded = json.dumps({"id": value["event_id"], "event_type": value["event_type"],
        "actor_type": value["actor_type"], "actor_id": value["actor_id"],
        "event_json": value["event_json"], "prev_event_hash": value["prev_event_hash"],
        "created_at": value["created_at"]}, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def database_hash_wrapper():
    """Load only db._audit_hash's function AST, never execute/import db.py.

    Its declaration is within the first 1000 lines. Bounding this read avoids
    parsing the rest of the large configured database module for one wrapper.
    """
    selected = []
    with (ROOT / "serverware/db.py").open(encoding="utf-8") as stream:
        for line in itertools.islice(stream, 1000):
            if line.startswith("def _audit_hash("):
                selected.append(line)
            elif selected:
                if line.startswith("def "):
                    break
                selected.append(line)
    if not selected:
        raise AssertionError("bounded audit wrapper source not found")
    tree = ast.parse("".join(selected), filename="isolated-db-audit-hash")
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != "_audit_hash":
        raise AssertionError("audit wrapper extraction shape changed")
    namespace = {"_common_audit_hash": db_common.audit_hash}
    exec(compile(tree, "isolated-db-audit-hash", "exec"), namespace)
    return namespace["_audit_hash"]


def public_binding():
    old = {"allowed_upstreams": ["https://api.example.com"], "fixture_cidrs": []}
    redirect = ORIGIN + setup.profiles.CALLBACK_PATH
    profile = setup.profiles._record(CLIENT, redirect)
    return {"operation_id": OPERATION, "actor_id": ACTOR, "client_id": CLIENT,
        "old_settings": old, "target_settings": setup._target(old),
        "expected_settings_digest": setup._digest(old), "public_url": ORIGIN,
        "redirect_uri": redirect, "profile_binding": profile,
        "profile_binding_digest": setup._digest(profile), "reviewed_revision": 7,
        "staged_revision": 8, "policy_hash": POLICY, "created_at": CREATED}


def append_audit(conn, action, value, *, previous=None):
    record = {"event_id": "operator-google-setup:" + OPERATION + ":" + action,
        "event_type": setup._PREFIX + action, "actor_type": "admin", "actor_id": ACTOR,
        "event_json": db_common.dumps(value), "prev_event_hash": previous,
        "created_at": CREATED if action == "prepared" else COMPLETED}
    digest = legacy_hash(**record)
    conn.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?,?,?)", (
        record["event_id"], record["event_type"], record["actor_type"], record["actor_id"],
        record["event_json"], record["prev_event_hash"], record["created_at"], digest))
    return digest


def fixture(status="pending", *, schema=True, record=True):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE audit_events (id TEXT PRIMARY KEY,event_type TEXT,actor_type TEXT,"
        "actor_id TEXT,event_json TEXT,prev_event_hash TEXT,created_at TEXT,event_hash TEXT)")
    if schema:
        for _, _, sql in setup._DEFINITIONS:
            conn.execute(sql)
    if record:
        value = public_binding()
        terminal = status != "pending"
        conn.execute("INSERT INTO operator_google_setups VALUES(?,?,?,?,?,?,?)", (
            OPERATION, ACTOR, status, setup._canonical(value),
            9 if terminal else None, POLICY if terminal else None, COMPLETED if terminal else None))
        previous = append_audit(conn, "prepared", value)
        if terminal:
            append_audit(conn, status, {"operation_id": OPERATION, "actor_id": ACTOR,
                "status": status, "revision": 9, "policy_hash": POLICY,
                "profile_binding_digest": value["profile_binding_digest"], "completed_at": COMPLETED}, previous=previous)
    conn.commit()
    conn.execute("BEGIN")
    return conn


def early_worker():
    assert not FORBIDDEN.intersection(sys.modules)
    for status in ("pending", "cancelled", "activated"):
        conn = fixture(status)
        try:
            conn.execute("PRAGMA query_only=ON")
            before = tuple(conn.iterdump()), conn.total_changes
            item, = setup._rows(conn)
            assert item["status"] == status
            assert setup._public(setup._get(conn, OPERATION, ACTOR))["status"] == status
            assert (tuple(conn.iterdump()), conn.total_changes) == before
        finally:
            conn.close()
    assert not FORBIDDEN.intersection(sys.modules)
    print("early-setup-decode-ok")


class SetupDecoderTests(unittest.TestCase):
    def connection(self, *args, **kwargs):
        conn = fixture(*args, **kwargs)
        self.addCleanup(conn.close)
        return conn

    def refused(self, conn):
        with self.assertRaises(setup.SetupUnavailable) as caught:
            setup._rows(conn)
        self.assertEqual(str(caught.exception), "operator Google setup unavailable")
        self.assertNotIn(SECRET_SENTINEL, repr(caught.exception))

    def corrupt_binding(self, conn, raw):
        conn.execute("DROP TRIGGER operator_google_setups_immutable")
        conn.execute("UPDATE operator_google_setups SET binding_json=?", (raw,))
        conn.execute(setup._IMMUTABLE)

    def test_import_independent_decode_in_fresh_process(self):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--early-worker"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(result.stdout, b"early-setup-decode-ok\n")
        self.assertFalse(FORBIDDEN.intersection(sys.modules))

    def test_hash_matches_legacy_algorithm_and_existing_db_wrapper(self):
        wrapper = database_hash_wrapper()
        base = {"event_id": "synthetic:record:1", "event_type": "synthetic.event",
            "actor_type": "admin", "actor_id": ACTOR, "event_json": '{"x":1}',
            "prev_event_hash": None, "created_at": CREATED}
        cases = [base, {**base, "actor_id": None}, {**base, "event_json": '{"unicode":"é☃"}'},
            {**base, "event_json": '{ "x": 1 }'}, {**base, "actor_id": "synthetic-\"admin\\"},
            {**base, "prev_event_hash": "sha256:" + "b" * 64},
            {**base, "created_at": "2026-10-10T10:00:00.123456+00:00"}]
        for value in cases:
            with self.subTest(value=value):
                expected = legacy_hash(**value)
                self.assertEqual(db_common.audit_hash(**value), expected)
                self.assertEqual(wrapper(**value), expected)
        self.assertNotEqual(db_common.audit_hash(**cases[0]), db_common.audit_hash(**cases[3]))

    def test_legacy_pending_public_shape_and_actor_owned_lookup(self):
        conn = self.connection()
        item, = setup._rows(conn)
        self.assertEqual(item["binding"], public_binding())
        public = setup._public(setup._get(conn, OPERATION, ACTOR))
        expected = {key: value for key, value in public_binding().items() if key != "actor_id"}
        expected.update(schema="serverware.operatorGoogleSetup/v1", status="pending", revision=8,
            completed_at=None, activation_receipt=None)
        self.assertEqual(public, expected)
        with self.assertRaises(setup.SetupNotFound):
            setup._get(conn, OPERATION, "different-actor")

    def test_legacy_terminal_states_and_activation_receipt(self):
        for status in ("cancelled", "activated"):
            conn = self.connection(status)
            public = setup._public(setup._get(conn, OPERATION, ACTOR))
            self.assertEqual(public["status"], status)
            self.assertEqual(public["revision"], 9)
            if status == "cancelled":
                self.assertIsNone(public["activation_receipt"])
            else:
                self.assertEqual(public["activation_receipt"], {
                    "schema": "serverware.operatorGoogleSetupActivation/v1", "operation_id": OPERATION,
                    "activated_revision": 9, "policy_hash": POLICY,
                    "profile_binding_digest": public_binding()["profile_binding_digest"],
                    "settings_digest": setup._digest(public_binding()["target_settings"]), "activated_at": COMPLETED})

    def test_absence_and_orphan_audit_differ(self):
        conn = self.connection(schema=False, record=False)
        self.assertEqual(setup._rows(conn), [])
        append_audit(conn, "prepared", public_binding())
        self.refused(conn)

    def test_malformed_json_and_noncanonical_binding_are_fixed_refusals(self):
        for raw in ('{"private":"' + SECRET_SENTINEL, "null", "[]", "[" * 1000,
                " " * 32769, b"not-text", json.dumps(public_binding(), indent=2)):
            with self.subTest(kind=type(raw).__name__):
                conn = self.connection()
                self.corrupt_binding(conn, raw)
                self.refused(conn)

    def test_wrong_nested_types_and_unknown_binding_keys_are_fixed_refusals(self):
        changes = ({"old_settings": []}, {"client_id": 4}, {"operation_id": "not-a-uuid"},
            {"client_secret": SECRET_SENTINEL}, {"profile_binding_digest": "wrong"},
            {"old_settings": {"allowed_upstreams": None}})
        for change in changes:
            conn = self.connection()
            self.corrupt_binding(conn, setup._canonical({**public_binding(), **change}))
            self.refused(conn)

    def test_bad_audit_record_and_json_are_fixed_refusals(self):
        for column, value in (("event_json", '{"private":"' + SECRET_SENTINEL),
                ("event_json", "[]"), ("event_hash", "sha256:" + "0" * 64),
                ("actor_id", "different-actor")):
            conn = self.connection()
            conn.execute("UPDATE audit_events SET " + column + "=?", (value,))
            self.refused(conn)

    def test_missing_audit_or_schema_refused(self):
        conn = self.connection()
        conn.execute("DELETE FROM audit_events")
        self.refused(conn)
        conn = self.connection()
        conn.execute("DROP TRIGGER operator_google_setups_retained")
        self.refused(conn)
        conn = self.connection()
        conn.execute("CREATE TRIGGER synthetic_extra BEFORE UPDATE ON operator_google_setups BEGIN SELECT 1; END")
        self.refused(conn)

    def test_closed_connection_and_missing_core_schema_are_fixed_refusals(self):
        conn = self.connection()
        conn.close()
        self.refused(conn)
        empty = sqlite3.connect(":memory:")
        self.addCleanup(empty.close)
        self.refused(empty)

    def test_query_only_decoding_preserves_snapshot(self):
        conn = self.connection("activated")
        conn.execute("PRAGMA query_only=ON")
        before = tuple(conn.iterdump()), conn.total_changes
        setup._rows(conn)
        setup._get(conn, OPERATION, ACTOR)
        self.assertEqual((tuple(conn.iterdump()), conn.total_changes), before)

    def test_legacy_prepare_input_still_refuses_secrets_and_new_grammar(self):
        base = {"expected_revision": 7, "expected_policy_hash": POLICY, "operation_id": OPERATION,
            "client_id": CLIENT, "expected_settings_digest": public_binding()["expected_settings_digest"]}
        self.assertEqual(setup.SetupInput.model_validate(base).model_dump(), base)
        for extra in ({"client_secret": SECRET_SENTINEL}, {"setup_contract": "managed-v1"},
                {"custody_ref": {"owner_id": OPERATION, "config_version": 1}}):
            with self.assertRaises(ValueError):
                setup.SetupInput.model_validate({**base, **extra})


if __name__ == "__main__":
    if "--early-worker" in sys.argv:
        early_worker()
    else:
        unittest.main(verbosity=2)
