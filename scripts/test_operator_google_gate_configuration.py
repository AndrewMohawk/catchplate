#!/usr/bin/env python3
"""Committed public Google projection/export in disposable network-none workers.

Uses real managed bootstrap, SQLite, publication EX, encrypted preparation and
cold activation. Provider contact is forbidden. No Rust or live acceptance is
claimed; root runs this script only in the bounded isolated test harness.
"""
from __future__ import annotations

from contextlib import closing, ExitStack
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_google_managed_config as managed

ROOT = Path(__file__).resolve().parents[1]
FILENAME = "operator-google-configuration.json"


def refused(function):
    from serverware import operator_google_gate_configuration as gate
    try:
        function()
    except gate.GateConfigurationUnavailable as error:
        assert str(error) == "operator Google gate configuration unavailable"
    else:
        raise AssertionError("invalid public configuration snapshot was accepted")


def secret_guards(f):
    stack = ExitStack()
    forbidden = AssertionError("public configuration accessed provider secret/key authority")
    for module, names in ((f.keys, ("read_existing_pinned", "initialize_first")),
            (f.custody, ("read_secret", "open_secret", "read_existing_master_key", "AESGCM")),
            (f.profiles, ("selected", "require_profile"))):
        for name in names:
            stack.enter_context(patch.object(module, name, side_effect=forbidden))
    return stack


def project(f):
    from serverware import operator_google_gate_configuration as gate
    before = f.snapshot(), managed.key_evidence()
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        assert not managed.coordination.shared_probe(f.config.DATA_DIR / f.store.operator_publication.LOCK_NAME)
        with secret_guards(f):
            value = gate.record(conn)
            identity = gate.expected_identity(conn)
        assert conn.total_changes == 0 and conn.in_transaction
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
    assert (f.snapshot(), managed.key_evidence()) == before
    assert set(value) == {"schema", "operation", "profile_binding", "profile_binding_digest",
        "effective_settings", "effective_settings_digest"}
    assert value["schema"] == gate.SCHEMA
    assert identity == {key: value[key] for key in (
        "operation", "profile_binding_digest", "effective_settings_digest")}
    raw = f.setup._canonical(value)
    assert len(raw.encode("ascii")) <= gate.MAX_BYTES
    assert managed.SECRET not in raw and str(f.config.DATA_DIR) not in raw
    assert os.environ[managed.KEY_DIRECTORY] not in raw
    assert not f.provider_calls
    return value


def exact_export(f, value):
    target = f.config.DATA_DIR / "gate-runtime" / FILENAME
    info = target.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid() and info.st_nlink == 1
    assert target.read_bytes() == f.setup._canonical(value).encode("ascii")
    assert set(path.name for path in target.parent.iterdir()) == {
        FILENAME, "policy-bundle.json", "mitmproxy", ".operator-publication.lock", ".serverware-operator-demo.json"}
    assert (target.parent / "policy-bundle.json").read_bytes() == f.config.POLICY_BUNDLE_PATH.read_bytes()
    return target


def disabled(value):
    assert value["operation"] is value["profile_binding"] is value["profile_binding_digest"] is None
    assert value["effective_settings"] == {
        "allowed_upstreams": managed.legacy.OLD_ORIGINS, "fixture_cidrs": managed.legacy.CIDRS}


def lifecycle(_request):
    f = managed.Fixture()
    initial = project(f)
    disabled(initial)
    exact_export(f, initial)
    assert managed.key_evidence() == {}
    operation = f.prepare()
    pending = project(f)
    disabled(pending)
    assert pending == initial
    f.store.materialize()
    exact_export(f, pending)
    cancelled = f.setup.cancel({**f.review(), "operation_id": operation["operation_id"]}, managed.ACTOR)
    assert cancelled["status"] == "cancelled"
    assert project(f) == initial
    f.store.materialize()
    exact_export(f, initial)
    return {"fresh_pending_cancelled_joint_null": True, "projection_writes": 0, "secret_reads": 0}


def prepare(_request):
    f = managed.Fixture()
    operation = f.prepare()
    disabled(project(f))
    return {"operation": operation}


def active(request):
    f = managed.Fixture()  # Actual cold bootstrap commits the prepared activation.
    selected = f.selected()
    assert selected["operation_id"] == request["operation"]["operation_id"] and selected["status"] == "activated"
    value = project(f)
    assert value["operation"] == {"operation_id": selected["operation_id"],
        "owner_id": selected["custody_ref"]["owner_id"], "config_version": selected["custody_ref"]["config_version"]}
    assert value["profile_binding"] == selected["profile_binding"]
    assert value["profile_binding_digest"] == selected["profile_binding_digest"]
    assert value["effective_settings"] == selected["target_settings"]
    target = exact_export(f, value)
    if request.get("repair"):
        before = f.snapshot(), managed.key_evidence()
        target.unlink()
        f.store.materialize()
        exact_export(f, value)
        target.write_bytes(b"synthetic stale public configuration")
        f.store.materialize()
        exact_export(f, value)
        assert (f.snapshot(), managed.key_evidence()) == before
    if request.get("current_settings"):
        settings = {**value["effective_settings"], "allowed_upstreams": [
            *value["effective_settings"]["allowed_upstreams"], "https://registry.npmjs.org"]}
        # Synthetic retained-settings drift tests projection, not activation of
        # an upstream operation. No authority API is replaced with a success.
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn, conn:
            conn.execute("UPDATE operator_demo_settings SET settings_json=?", (json.dumps(settings, sort_keys=True),))
        current = project(f)
        assert current["effective_settings"] == settings
        assert current["effective_settings_digest"] == f.setup._digest(settings)
        assert current["effective_settings_digest"] != selected["activation_receipt"]["settings_digest"]
        assert current["operation"] == value["operation"]
        f.store.materialize()
        exact_export(f, current)
        value = current
    return {"operation": selected, "record": value, "secret_reads": 0, "projection_writes": 0}


def admission(_request):
    f = managed.Fixture()
    from serverware import operator_google_gate_configuration as gate
    before = f.snapshot(), managed.key_evidence()
    with closing(f.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        refused(lambda: gate.record(conn))  # No publication ownership.
    with f.store.operator_publication.exclusive():
        refused(lambda: gate.record(object()))
        with closing(f.db.connect()) as conn:
            conn.execute("PRAGMA query_only=ON")
            refused(lambda: gate.record(conn))  # No SQLite transaction.
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN")
            refused(lambda: gate.record(conn))  # Not a query-only connection.
        with closing(f.db.connect()) as conn:
            conn.execute("UPDATE operator_demo_settings SET settings_json=settings_json")
            conn.execute("PRAGMA query_only=ON")
            refused(lambda: gate.record(conn))  # Own uncommitted write cannot be exported.
            conn.rollback()
            conn.execute("BEGIN")
            refused(lambda: gate.record(conn))  # Used writers are not fresh read snapshots.
        with closing(f.db.connect()) as conn:
            conn.execute("ATTACH DATABASE ':memory:' AS unrelated")
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            refused(lambda: gate.record(conn))
        with closing(f.db.connect()) as conn:
            conn.execute("PRAGMA read_uncommitted=ON")
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            refused(lambda: gate.record(conn))
        with closing(sqlite3.connect(":memory:")) as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            refused(lambda: gate.record(conn))
        with closing(f.db.connect()) as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            for value in ("0", "", "true", "01"):
                with patch.dict(os.environ, {managed.FLAG: value}):
                    refused(lambda: gate.record(conn))
            for name, value in (("RELEASE_CHANNEL", "prod"), ("PRODUCTION_IMAGE", True),
                    ("METADATA_STORE_BACKEND", "postgres"), ("KEY_RELEASE_REQUIRED", True)):
                with patch.object(f.config, name, value):
                    refused(lambda: gate.record(conn))
    assert (f.snapshot(), managed.key_evidence()) == before
    project(f)
    return {"unowned_writer_wrong_database_and_deployment_refused": True}


def corrupt(request):
    f = managed.Fixture()
    if request["kind"].startswith("selection-") or request["kind"] == "custody":
        f.prepare()
    kind = request["kind"]
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn, conn:
        if kind == "settings-missing":
            conn.execute("DROP TABLE operator_demo_settings")
        elif kind == "settings-unknown-key":
            raw = json.loads(conn.execute("SELECT settings_json FROM operator_demo_settings").fetchone()[0])
            conn.execute("UPDATE operator_demo_settings SET settings_json=?", (json.dumps({**raw, "secret": "no"}, sort_keys=True),))
        elif kind == "settings-cidr":
            raw = json.loads(conn.execute("SELECT settings_json FROM operator_demo_settings").fetchone()[0])
            conn.execute("UPDATE operator_demo_settings SET settings_json=?", (json.dumps({**raw, "fixture_cidrs": ["127.0.0.0/24"]}, sort_keys=True),))
        elif kind == "selection-schema":
            conn.execute("DROP TRIGGER operator_google_managed_selection_immutable")
        elif kind == "selection-pointer":
            conn.execute("UPDATE operator_google_managed_selection SET operation_id=NULL")
        elif kind == "custody":
            conn.execute("DROP TABLE operator_provider_custody")
        elif kind == "unselected-profile":
            conn.execute("CREATE TABLE operator_catalog_oauth_unselected (value TEXT)")
        elif kind == "unselected-cleanup":
            conn.execute("CREATE TABLE operator_google_cleanup_orphan (value TEXT)")
        elif kind == "unselected-reauthorization":
            conn.execute("CREATE TABLE operator_google_reauthorization_orphan (value TEXT)")
        elif kind == "unselected-credential":
            conn.execute("INSERT INTO operator_catalog_credentials VALUES(?,1,?)", (
                "c86d3c12-5c07-4b14-9b59-510bb3cbb9dc", json.dumps({"auth_type": "google_oauth"})))
        elif kind == "active-profile":
            conn.execute("UPDATE operator_catalog_oauth_profile SET binding_digest=?", ("sha256:" + "0" * 64,))
        elif kind == "active-audit":
            conn.execute("UPDATE audit_events SET event_hash=? WHERE event_type='operator_catalog.google_setup.activated'", ("sha256:" + "0" * 64,))
        else:
            raise AssertionError("unknown corruption fixture")
    from serverware import operator_google_gate_configuration as gate
    before = f.snapshot(), managed.key_evidence()
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        with secret_guards(f):
            refused(lambda: gate.record(conn))
            refused(lambda: gate.expected_identity(conn))
    assert (f.snapshot(), managed.key_evidence()) == before
    return {"malformed_state_refused_without_writes": kind}


def failed_activation_export(request):
    from serverware import operator_gate_publication as exporter
    original = exporter._replace_publication
    observed = []

    def fail_manifest(path, raw, **options):
        if path.name == FILENAME:
            exporter.operator_publication.assert_held()
            public = json.loads(raw)
            assert public["operation"]["operation_id"] == request["operation"]["operation_id"]
            observed.append(public)
            raise OSError("synthetic manifest publication failure after SQL activation")
        return original(path, raw, **options)

    with patch.object(exporter, "_replace_publication", side_effect=fail_manifest):
        try:
            managed.Fixture()
        except (OSError, RuntimeError):
            pass
        else:
            raise AssertionError("startup ignored manifest publication failure")
    assert len(observed) == 1
    from serverware import config, control_plane_startup
    with closing(sqlite3.connect(config.DB_PATH.as_uri() + "?mode=ro", uri=True)) as conn:
        row = conn.execute("SELECT status FROM operator_google_setups WHERE operation_id=?",
            (request["operation"]["operation_id"],)).fetchone()
        assert row == ("activated",), "failure fixture did not reach the postcommit boundary"
    target = config.DATA_DIR / "gate-runtime" / FILENAME
    disabled(json.loads(target.read_bytes()))
    # A committed application profile is not the complete serving/readiness
    # grant. The actual startup sequence must still fail before that boundary.
    assert control_plane_startup.control_plane_startup_required()
    return {"operation": request["operation"], "postcommit_manifest_failure": True,
        "stale_public_sha256": hashlib.sha256(target.read_bytes()).hexdigest()}


class GoogleGateConfigurationTests(unittest.TestCase):
    def setUp(self):
        managed.ManagedGoogleConfigurationTests.setUp(self)

    def worker(self, name, request=None, *, changes=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env={**self.environment, **(changes or {})},
            capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        self.assertNotIn(managed.SECRET, result.stdout)
        return json.loads(result.stdout)

    def isolated_case(self, index):
        data, provider = Path(self.scratch.name) / ("case-data-" + str(index)), Path(self.scratch.name) / ("case-provider-" + str(index))
        data.mkdir(mode=0o700)
        provider.mkdir(mode=0o700)
        return {"SERVERWARE_DATA_DIR": str(data), managed.KEY_DIRECTORY: str(provider)}

    def test_fresh_pending_and_cancelled_are_explicit_profile_off_without_secrets(self):
        self.worker("lifecycle")

    def test_actual_cold_activation_exact_public_export_and_second_restart(self):
        prepared = self.worker("prepare")
        activated = self.worker("active", prepared)
        self.assertEqual(self.worker("active", activated), activated)

    def test_settings_digest_uses_current_retained_settings_not_activation_receipt(self):
        self.worker("active", {**self.worker("prepare"), "current_settings": True})

    def test_missing_and_stale_manifest_repair_without_authority_changes(self):
        self.worker("active", {**self.worker("prepare"), "repair": True})

    def test_postcommit_manifest_failure_refuses_readiness_and_cold_restart_repairs(self):
        failed = self.worker("failed_activation_export", self.worker("prepare"))
        self.assertTrue(failed["postcommit_manifest_failure"])
        self.worker("active", failed)

    def test_actual_lock_read_transaction_database_and_deployment_admission(self):
        self.worker("admission")

    def test_missing_malformed_or_unselected_settings_and_profile_refuse(self):
        for index, kind in enumerate(("settings-missing", "settings-unknown-key", "settings-cidr",
                "unselected-profile", "unselected-cleanup", "unselected-reauthorization", "unselected-credential")):
            with self.subTest(kind=kind):
                self.worker("corrupt", {"kind": kind}, changes=self.isolated_case(index))

    def test_broken_selection_and_custody_never_become_profile_off(self):
        for index, kind in enumerate(("selection-schema", "selection-pointer", "custody")):
            with self.subTest(kind=kind):
                self.worker("corrupt", {"kind": kind}, changes=self.isolated_case(index))

    def test_active_profile_and_activation_audit_must_still_join(self):
        for index, kind in enumerate(("active-profile", "active-audit")):
            with self.subTest(kind=kind):
                changes = self.isolated_case(index)
                self.worker("prepare", changes=changes)
                self.worker("corrupt", {"kind": kind}, changes=changes)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(managed.no_network)
        actions = {function.__name__: function for function in (
            lifecycle, prepare, active, admission, corrupt, failed_activation_export)}
        result = actions[sys.argv[2]](json.loads(sys.stdin.read(65536)))
        assert managed.NETWORK_ATTEMPTS == [], "a refused send is not no-contact proof"
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
