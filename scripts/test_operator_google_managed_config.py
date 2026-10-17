#!/usr/bin/env python3
"""Connected managed Google configuration in bounded network-none workers.

The real runner sequence, retained SQLite, EX ownership, setup/audit transaction,
dedicated key, ciphertext and profile guards run unchanged. Provider contact is
forbidden. Internal preparation is not HTTP, Google consent or serving proof.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import importlib.abc
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
import uuid

import test_operator_google_setup as legacy
import test_operator_publication as coordination
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
FLAG = "CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED"
KEY_DIRECTORY = "CATCHPLATE_OPERATOR_PROVIDER_CUSTODY_DIR"
CLIENT = "123-managed-configuration.apps.googleusercontent.com"
SECRET = "synthetic-managed-configuration-secret-not-public"
ACTOR = workspace.common._ACTOR
FORBIDDEN = {"catchplate.config", "catchplate.db", "catchplate.crypto"}
NETWORK_ATTEMPTS = []


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("managed Google configuration attempted network contact")


class ImportGuard(importlib.abc.MetaPathFinder):
    def __init__(self):
        self.attempts = []

    def find_spec(self, fullname, path=None, target=None):
        if fullname in FORBIDDEN:
            self.attempts.append(fullname)
            raise AssertionError("early managed reader imported configured runtime")


def key_evidence():
    directory = Path(os.environ[KEY_DIRECTORY])
    result = {}
    for path in directory.iterdir():
        info = path.lstat()
        result[path.name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode & 0o777,
            "owner": info.st_uid, "links": info.st_nlink}
    return result


def raw_snapshot():
    return legacy.readonly_snapshot(), key_evidence()


class Fixture(legacy.Fixture):
    def __init__(self):
        from catchplate import operator_google_managed_config as managed
        # Mirror the real runner: bootstrap before activate/config, then the
        # existing fixture invokes the actual control-plane startup sequence.
        managed.bootstrap()
        super().__init__()
        from catchplate import operator_google_managed_selection, operator_provider_custody, operator_provider_key
        self.managed, self.selection = managed, operator_google_managed_selection
        self.custody, self.keys = operator_provider_custody, operator_provider_key

    def payload(self, **changes):
        value = self.setup.review_configuration(ACTOR)
        assert value["schema"] == "catchplate.operatorGoogleManagedSetupReview/v2" and value["eligible"]
        return {key: value[key] for key in (
            "expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
                "operation_id": str(uuid.uuid4()), "client_id": CLIENT, "client_secret": SECRET} | changes

    def selected(self):
        with closing(self.db.connect()) as conn:
            conn.execute("BEGIN")
            return self.selection.read_selection(conn)

    def retained(self):
        with closing(self.db.connect()) as conn:
            custody = {table: [{key: value.hex() if isinstance(value, bytes) else value
                for key, value in dict(row).items()} for row in conn.execute("SELECT * FROM " + table)]
                for table in (self.custody.META, self.custody.TABLE)}
        return {"authority": self.authority(), "custody": custody, "provider_key": key_evidence()}

    def prepare(self, **changes):
        before = self.authority()
        payload = self.payload(**changes)
        observed = []
        original = self.custody.insert_secret

        def insert(conn, owner, binding, **options):
            self.store.operator_publication.assert_held()
            assert conn.in_transaction
            assert not coordination.shared_probe(self.config.DATA_DIR / self.store.operator_publication.LOCK_NAME)
            original(conn, owner, binding, **options)
            observed.append((owner.owner_id, binding.config_version))

        with patch.object(self.custody, "insert_secret", side_effect=insert):
            result = self.setup.prepare_configuration(payload, ACTOR)
        assert observed == [(result["custody_ref"]["owner_id"], result["custody_ref"]["config_version"])]
        assert self.authority() == before
        assert result["schema"] == "catchplate.operatorGoogleManagedSetup/v2"
        assert result["setup_contract"] == "catchplate.operatorGoogleManagedSetupBinding/v2"
        assert result["custody_ref"]["key_source"] == "operator-provider-key-v1"
        assert result["status"] == "pending" and result["activation_receipt"] is None
        assert result["staged_revision"] == result["revision"] == payload["expected_revision"] + 1
        assert result["operation_id"] == payload["operation_id"] and result["secret_present"] is True
        assert self.selected() == result
        assert self.setup.status(result["operation_id"], ACTOR) == result
        assert not self.profiles.selected(), "Prepare hot-adopted managed Google configuration"
        assert self.demo.settings()["allowed_upstreams"] == result["old_settings"]["allowed_upstreams"]
        assert not self.provider_calls and SECRET not in json.dumps(result)
        with closing(self.db.connect()) as conn:
            assert SECRET not in "\n".join(conn.iterdump())
        return result


def prepare(request):
    f = Fixture()
    assert key_evidence() == {} and not (f.config.DATA_DIR / "master.key").exists()
    operation = f.prepare()
    assert operation["custody_ref"]["config_version"] == 1
    assert set(key_evidence()) == {f.keys.FILENAME}
    assert not (f.config.DATA_DIR / "master.key").exists(), "managed Prepare initialized the old master key"
    if request.get("stale"):
        workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations,
            "Intervening reviewed-revision fixture")
    if request.get("activation_failure"):
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER managed_activation_abort BEFORE INSERT ON audit_events "
                "WHEN NEW.event_type='operator_catalog.google_setup.activated' "
                "BEGIN SELECT RAISE(ABORT,'synthetic managed activation audit refusal'); END")
    return {"operation": operation, "retained": f.retained(), "audit": f.rows("audit_events")}


def cold_selection(request):
    assert not FORBIDDEN.intersection(sys.modules)
    guard = ImportGuard()
    sys.meta_path.insert(0, guard)
    from catchplate import operator_google_managed_selection as selection
    from catchplate import operator_provider_custody as custody, operator_provider_key as keys, operator_publication
    admission = operator_publication.admit_bootstrap_reader(Path(os.environ["CATCHPLATE_DATA_DIR"]),
        operator_development=True, release_channel="dev", production_image=False, native_or_enrolled=False)
    forbidden = AssertionError("structural selection accessed provider key or secret")
    with patch.object(keys, "read_existing_pinned", side_effect=forbidden), \
            patch.object(keys, "initialize_first", side_effect=forbidden), \
            patch.object(custody, "read_secret", side_effect=forbidden), \
            patch.object(custody, "open_secret", side_effect=forbidden), \
            operator_publication.bootstrap_read(admission) as conn:
        before = tuple(conn.iterdump())
        result = selection.read_selection(conn)
        assert result == request["operation"]
        assert tuple(conn.iterdump()) == before
    assert guard.attempts == [] and not FORBIDDEN.intersection(sys.modules)
    return {"exact_structural_selection": result, "configured_imports": [], "secret_reads": 0}


def activate(request):
    expected = request["operation"]
    phases = []
    original = sqlite3.connect

    class ObservedCommit(sqlite3.Connection):
        def commit(self):
            try:
                activation = self.in_transaction and self.execute("SELECT id FROM audit_events WHERE id=?", (
                    "operator-google-setup:" + expected["operation_id"] + ":activated",)).fetchone()
            except sqlite3.OperationalError:
                activation = False
            if activation and not phases and request.get("observe_commit", True):
                from catchplate import operator_catalog_oauth_profile as profiles, operator_publication
                operator_publication.assert_held()
                # The exact startup transaction may validate the provisional
                # profile; another thread must not acquire that capability.
                assert profiles.require_profile().binding_digest == expected["profile_binding_digest"]
                refused = []

                def other_thread():
                    try:
                        profiles.require_profile()
                    except profiles.OperatorGoogleProfileError:
                        refused.append(True)

                thread = threading.Thread(target=other_thread, daemon=True)
                thread.start()
                thread.join(2)
                assert not thread.is_alive() and refused == [True]
                result = super().commit()
                try:
                    profiles.require_profile()
                except profiles.OperatorGoogleProfileError:
                    phases.append("real_commit_before_readiness")
                else:
                    raise AssertionError("commit alone enabled managed profile before committed-state validation")
                return result
            return super().commit()

    def connect(*args, **kwargs):
        assert "factory" not in kwargs
        return original(*args, factory=ObservedCommit, **kwargs)

    with patch.object(sqlite3, "connect", side_effect=connect):
        f = Fixture()
    if request.get("observe_commit", True):
        assert phases == ["real_commit_before_readiness"]
    actual = f.setup.status(expected["operation_id"], ACTOR)
    assert actual["status"] == "activated" and f.selected() == actual
    assert actual["revision"] == expected["staged_revision"] + 1
    assert actual["activation_receipt"] == {"schema": "catchplate.operatorGoogleSetupActivation/v1",
        "operation_id": expected["operation_id"], "activated_revision": actual["revision"],
        "policy_hash": expected["policy_hash"], "profile_binding_digest": expected["profile_binding_digest"],
        "settings_digest": f.setup._digest(expected["target_settings"]), "activated_at": actual["completed_at"]}
    profile = f.profiles.require_profile()
    assert profile.client_id == expected["client_id"] and profile.binding_digest == expected["profile_binding_digest"]
    assert f.config.GOOGLE_OAUTH_CLIENT_ID == expected["client_id"]
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET == SECRET + request.get("secret_suffix", "")
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET_FILE is None
    assert f.demo.settings()["allowed_upstreams"] == expected["target_settings"]["allowed_upstreams"]
    assert json.loads(os.environ["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"]) == expected["old_settings"]["allowed_upstreams"]
    assert not f.provider_calls
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    return {"operation": actual, "retained": f.retained(), "audit": f.rows("audit_events")}


def cancel_reprepare(_request):
    f = Fixture()
    first = f.prepare()
    key = key_evidence()
    forbidden = AssertionError("public status/cancel decrypted provider custody")
    with patch.object(f.keys, "read_existing_pinned", side_effect=forbidden), \
            patch.object(f.custody, "read_secret", side_effect=forbidden):
        assert f.setup.status(first["operation_id"], ACTOR) == first
        cancelled = f.setup.cancel({**f.review(), "operation_id": first["operation_id"]}, ACTOR)
        assert cancelled["status"] == "cancelled" and f.selected() is None
    second = f.prepare(client_id="456-next-managed.apps.googleusercontent.com", client_secret=SECRET + "-second")
    assert key_evidence() == key
    assert second["custody_ref"] == {**first["custody_ref"], "config_version": 2}
    assert f.setup.status(first["operation_id"], ACTOR) == cancelled
    return {"operation": second, "retained": f.retained(), "audit": f.rows("audit_events")}


def prepare_rollback(_request):
    f = Fixture()
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER managed_prepare_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.google_setup.prepared' "
            "BEGIN SELECT RAISE(ABORT,'synthetic managed preparation audit refusal'); END")
    before = f.snapshot()
    payload = f.payload()
    try:
        f.setup.prepare_configuration(payload, ACTOR)
    except f.setup.SetupUnavailable as error:
        assert str(error) == "operator Google setup unavailable"
    else:
        raise AssertionError("managed Prepare ignored audit failure")
    assert f.snapshot() == before and f.selected() is None
    orphan = key_evidence()
    assert set(orphan) == {f.keys.FILENAME}
    assert not (f.config.DATA_DIR / "master.key").exists()
    with closing(f.db.connect()) as conn, conn:
        conn.execute("DROP TRIGGER managed_prepare_abort")
    operation = f.prepare()
    assert key_evidence() == orphan
    return {"operation": operation, "retained": f.retained(), "orphan_key_reused": True}


def lost_ack(_request):
    f = Fixture()
    payload = f.payload()
    original, committed = sqlite3.connect, []
    event_id = "operator-google-setup:" + payload["operation_id"] + ":prepared"

    class LostAcknowledgement(sqlite3.Connection):
        def commit(self):
            found = self.in_transaction and self.execute("SELECT id FROM audit_events WHERE id=?", (event_id,)).fetchone()
            if found and not committed:
                super().commit()
                committed.append(True)
                raise OSError("synthetic managed Prepare acknowledgement lost after commit")
            return super().commit()

    def connect(*args, **kwargs):
        assert "factory" not in kwargs
        return original(*args, factory=LostAcknowledgement, **kwargs)

    with patch.object(sqlite3, "connect", side_effect=connect):
        try:
            f.setup.prepare_configuration(payload, ACTOR)
        except f.setup.SetupUnavailable as error:
            assert str(error) == "operator Google setup unavailable"
        else:
            raise AssertionError("lost managed acknowledgement returned success")
    assert committed == [True]
    operation = f.setup.status(payload["operation_id"], ACTOR)
    assert operation["status"] == "pending" and f.selected() == operation
    try:
        f.setup.status(payload["operation_id"], ACTOR + "-other")
    except f.setup.SetupNotFound:
        pass
    else:
        raise AssertionError("managed lost-response recovery ignored actor ownership")
    return {"operation": operation, "retained": f.retained(), "audit": f.rows("audit_events")}


def refused_bootstrap(_request):
    before = raw_snapshot()
    assert not FORBIDDEN.intersection(sys.modules)
    guard = ImportGuard()
    sys.meta_path.insert(0, guard)
    from catchplate import operator_google_managed_config as managed
    try:
        managed.bootstrap()
    except managed.profiles.OperatorGoogleProfileError as error:
        assert str(error) == "operator Google profile refused"
    else:
        raise AssertionError("unsafe retained managed configuration admitted")
    assert guard.attempts == [] and not FORBIDDEN.intersection(sys.modules) and raw_snapshot() == before
    return {"pre_config_refusal": True, "retained_state_unchanged": True}


def activation_rollback(_request):
    from catchplate import operator_google_managed_config as managed
    managed.bootstrap()
    from catchplate import operator_demo
    original, boundary, contacts = operator_demo.bootstrap, [], []

    def observed():
        boundary.append(raw_snapshot())
        return original()

    with patch.object(operator_demo, "bootstrap", side_effect=observed):
        try:
            legacy.cold_startup(contacts)
        except RuntimeError:
            pass
        else:
            raise AssertionError("managed startup ignored activation audit failure")
    assert len(boundary) == 1 and not contacts and raw_snapshot() == boundary[0]
    from catchplate import operator_catalog_oauth_profile as profiles
    try:
        profiles.require_profile()
    except profiles.OperatorGoogleProfileError:
        pass
    else:
        raise AssertionError("rolled-back activation retained managed profile readiness")
    return {"activation_rollback": True, "profile_unavailable_after_rollback": True}


def legacy_off(request):
    f = Fixture()
    if request.get("operation"):
        result = f.setup.status(request["operation"]["operation_id"], ACTOR)
        assert result == request["operation"]
    else:
        workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations)
        review = f.setup.review(ACTOR)
        payload = {key: review[key] for key in (
            "expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
                "operation_id": str(uuid.uuid4()), "client_id": CLIENT, "client_secret": SECRET}
        result = f.setup.prepare_managed(payload, ACTOR)
    assert result["schema"] == "catchplate.operatorGoogleManagedSetup/v1" and result["status"] == "pending"
    assert not f.profiles.selected() and key_evidence() == {}
    return {"operation": result, "authority": f.authority()}


class ManagedGoogleConfigurationTests(unittest.TestCase):
    def setUp(self):
        legacy.OperatorGoogleSetupTests.setUp(self)
        self.directory.mkdir(mode=0o700)
        self.provider = Path(self.scratch.name) / "provider-custody"
        self.provider.mkdir(mode=0o700)
        self.environment.update({FLAG: "1", KEY_DIRECTORY: str(self.provider),
            "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "1", "CATCHPLATE_DECISION_GATE_BASE": ""})

    def worker(self, name, request=None, *, changes=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env={**self.environment, **(changes or {})},
            capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        self.assertNotIn(SECRET, result.stdout)
        return json.loads(result.stdout)

    def test_first_prepare_exact_selected_cold_activation_commit_gate_and_second_restart(self):
        prepared = self.worker("prepare")
        self.worker("cold_selection", prepared)
        activated = self.worker("activate", prepared)
        self.assertEqual(activated["retained"], prepared["retained"])
        self.assertEqual(activated["audit"][:len(prepared["audit"])], prepared["audit"])
        events = [row for row in activated["audit"] if row["event_type"] == "operator_catalog.google_setup.activated"]
        self.assertEqual(len(events), 1)
        self.assertEqual(self.worker("activate", {**activated, "observe_commit": False}), activated)

    def test_cancel_clears_exact_selection_and_reprepare_retains_original_key(self):
        prepared = self.worker("cancel_reprepare")
        self.worker("cold_selection", prepared)
        activated = self.worker("activate", {**prepared, "secret_suffix": "-second"})
        self.assertEqual(activated["retained"], prepared["retained"])

    def test_prepare_audit_rollback_reuses_durable_orphan_only_on_explicit_retry(self):
        prepared = self.worker("prepare_rollback")
        self.assertTrue(prepared["orphan_key_reused"])
        self.worker("cold_selection", prepared)

    def test_postcommit_lost_acknowledgement_recovers_exact_actor_owned_receipt(self):
        prepared = self.worker("lost_ack")
        self.worker("cold_selection", prepared)
        activated = self.worker("activate", prepared)
        self.assertEqual(activated["retained"], prepared["retained"])

    def test_activation_audit_failure_rolls_back_without_profile_readiness(self):
        self.worker("prepare", {"activation_failure": True})
        self.worker("activation_rollback")

    def test_missing_key_selection_schema_pointer_and_custody_refuse_without_writes(self):
        for index, kind in enumerate(("key", "selection-schema", "selection-pointer", "custody")):
            data, provider = Path(self.scratch.name) / ("refusal-data-" + str(index)), Path(self.scratch.name) / ("refusal-provider-" + str(index))
            data.mkdir(mode=0o700)
            provider.mkdir(mode=0o700)
            changes = {"CATCHPLATE_DATA_DIR": str(data), KEY_DIRECTORY: str(provider)}
            self.worker("prepare", changes=changes)
            if kind == "key":
                (provider / "provider-key.json").rename(Path(self.scratch.name) / "retained-missing-provider-key")
            else:
                with closing(sqlite3.connect(data / "catchplate.sqlite3")) as conn, conn:
                    if kind == "selection-schema":
                        conn.execute("DROP TRIGGER operator_google_managed_selection_immutable")
                    elif kind == "selection-pointer":
                        conn.execute("UPDATE operator_google_managed_selection SET operation_id=NULL")
                    else:
                        conn.execute("DROP TABLE operator_provider_custody")
            self.worker("refused_bootstrap", changes=changes)
            if kind == "key":
                self.assertFalse((provider / "provider-key.json").exists())

    def test_environment_drift_and_stale_review_refuse_before_config_import(self):
        self.worker("prepare")
        for changes in ({"CATCHPLATE_PUBLIC_URL": "https://different.example.com"},
                {"CATCHPLATE_OPERATOR_DEMO_UPSTREAMS": '["https://different.example.com"]'},
                {"CATCHPLATE_GOOGLE_OAUTH_CLIENT_ID": "456-unapproved.apps.googleusercontent.com"}):
            self.worker("refused_bootstrap", changes=changes)
        data, provider = Path(self.scratch.name) / "stale-data", Path(self.scratch.name) / "stale-provider"
        data.mkdir(mode=0o700)
        provider.mkdir(mode=0o700)
        changes = {"CATCHPLATE_DATA_DIR": str(data), KEY_DIRECTORY: str(provider)}
        self.worker("prepare", {"stale": True}, changes=changes)
        self.worker("refused_bootstrap", changes=changes)

    def test_flag_off_keeps_legacy_v1_preparation_unselected_on_restart(self):
        before = self.worker("legacy_off", changes={FLAG: "0"})
        self.assertEqual(self.worker("legacy_off", before, changes={FLAG: "0"}), before)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        actions = {function.__name__: function for function in (prepare, cold_selection, activate,
            cancel_reprepare, prepare_rollback, lost_ack, refused_bootstrap, activation_rollback, legacy_off)}
        result = actions[sys.argv[2]](json.loads(sys.stdin.read(65536)))
        assert NETWORK_ATTEMPTS == [], "a refused provider attempt is not successful no-contact proof"
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
