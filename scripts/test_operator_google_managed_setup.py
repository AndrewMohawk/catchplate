#!/usr/bin/env python3
"""Internal managed preparation with real SQLite/publication/custody/audit.

Run only in the bounded network-none harness, not on the host. Each case uses a
fresh disposable operator fixture; no HTTP endpoint, provider, managed runtime
activation, deployment or public gate is started. Cold bootstrap integration is
separately exercised by test_operator_provider_cold_read.py.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
CLIENT = "123-managed-fixture.apps.googleusercontent.com"
SECRET = "synthetic-managed-application-secret-never-public"
PUBLIC_URL = "https://console.example.com"
ACTOR = workspace.common._ACTOR


class Fixture:
    def __init__(self, *, seed_credential=True):
        (self.config, self.db, self.store, self.bundles, self.catalog,
            self.inputs, self.mutations) = workspace.workspace()
        from serverware import operator_google_setup, operator_provider_custody, operator_publication
        self.setup, self.custody, self.publication = operator_google_setup, operator_provider_custody, operator_publication
        if seed_credential:
            # This slice consumes an existing key. Use the real credential-save
            # path to establish it, not fixture-written key bytes or a relaxed
            # custody reader. Fresh-empty initialization is a separate feature.
            workspace.create_credential(self.db, self.store, self.catalog, self.inputs, self.mutations)
            assert (self.config.DATA_DIR / "master.key").is_file()

    def payload(self, **changes):
        review = self.setup.review(ACTOR)
        return {key: review[key] for key in ("expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
            "operation_id": str(uuid.uuid4()), "client_id": CLIENT, "client_secret": SECRET} | changes

    def files(self):
        result = {}
        for name in ("master.key", "policy-bundle.json", "policy-signing-ed25519.pem", "policy-signing-ed25519.pub.pem"):
            path = self.config.DATA_DIR / name
            if path.exists():
                info = path.stat()
                result[name] = (info.st_dev, info.st_ino, info.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())
        return result

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            return tuple(conn.iterdump()), self.files()

    def prepare(self, **changes):
        return self.setup.prepare_managed(self.payload(**changes), ACTOR)

    def cancel(self, value):
        review = workspace.review(self.db, self.store, self.catalog)
        return self.setup.cancel({**review, "operation_id": value["operation_id"]}, ACTOR)

    def exact(self, value):
        ref = value["custody_ref"]
        owner = self.setup._admit_managed_owner(ref["owner_id"])
        return owner, self.custody.bind_google(owner, config_version=ref["config_version"],
            public_profile=value["profile_binding"])

    def refused(self, action):
        before = self.snapshot()
        try:
            action()
        except self.setup.SetupUnavailable as error:
            assert str(error) == "operator Google setup unavailable"
            assert SECRET not in repr(error)
        else:
            raise AssertionError("managed preparation unexpectedly admitted")
        assert self.snapshot() == before

    def conflict(self, action):
        before = self.snapshot()
        try:
            action()
        except self.catalog.CatalogConflict:
            pass
        else:
            raise AssertionError("managed setup conflict unexpectedly admitted")
        assert self.snapshot() == before


def preparation():
    f = Fixture()
    before_catalog = workspace.catalog(f.db, f.catalog)
    before_files = f.files()
    payload = f.payload()
    model = f.setup.ManagedSetupInput(**payload)
    assert SECRET not in repr(model) and "client_secret" not in model.model_dump()
    result = f.setup.prepare_managed(model, ACTOR)
    assert result["schema"] == f.setup.MANAGED_PUBLIC and result["setup_contract"] == f.setup.MANAGED_BINDING
    assert result["secret_present"] is True and result["status"] == "pending" and result["activation_receipt"] is None
    assert result["custody_ref"]["config_version"] == 1
    assert str(uuid.UUID(result["custody_ref"]["owner_id"])) == result["custody_ref"]["owner_id"]
    assert SECRET not in json.dumps(result) and "client_secret" not in result and "actor_id" not in result
    assert f.files() == before_files
    after_catalog = workspace.catalog(f.db, f.catalog)
    assert after_catalog == {**before_catalog, "revision": before_catalog["revision"] + 1}
    assert f.setup.status(result["operation_id"], ACTOR) == result
    try:
        f.setup.status(result["operation_id"], "not-the-preparing-actor")
    except f.setup.SetupNotFound:
        pass
    else:
        raise AssertionError("lost-response lookup ignored actor ownership")
    owner, exact = f.exact(result)
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN")
        assert f.setup.read_managed_pending(conn, result["operation_id"]) == result
        key = f.custody.read_existing_master_key(f.config.DATA_DIR, owner)
        assert f.custody.read_secret(conn, owner, exact, key=key).secret == SECRET
        event = conn.execute("SELECT event_json FROM audit_events WHERE id=?", (
            "operator-google-setup:" + result["operation_id"] + ":prepared",)).fetchone()[0]
        assert json.loads(event)["custody_ref"] == result["custody_ref"]
        assert SECRET not in "\n".join(conn.iterdump())
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone() is None
    assert f.db.verify_audit_chain()["ok"]
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(f.config.DB_PATH) + suffix)
        if path.exists():
            assert SECRET.encode() not in path.read_bytes()
    # Existing disabled startup remains usable; no automatic adoption occurs.
    f.store.initialize()
    assert f.setup.status(result["operation_id"], ACTOR) == result
    return {"atomic_public_pending": True, "disabled_restart_usable": True}


def missing_existing_key(*, formerly_present):
    f = Fixture(seed_credential=formerly_present)
    key_path = f.config.DATA_DIR / "master.key"
    retained_key = None
    if formerly_present:
        # Preserve the synthetic key for the oracle; do not delete real state.
        retained_key = key_path.with_name("master.key-test-held")
        key_path.rename(retained_key)
        info = retained_key.stat()
        evidence = (info.st_dev, info.st_ino, info.st_mode, retained_key.read_bytes())
    assert not key_path.exists()
    payload = f.payload()
    f.refused(lambda: f.setup.prepare_managed(payload, ACTOR))
    assert not key_path.exists(), "managed preparation created a missing master key"
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_provider_custody*' "
            "OR lower(name) GLOB 'operator_google_setups*' LIMIT 1").fetchone() is None
        assert conn.execute("SELECT 1 FROM audit_events WHERE event_type LIKE 'operator_catalog.google_setup.%' LIMIT 1").fetchone() is None
    if retained_key is not None:
        info = retained_key.stat()
        assert evidence == (info.st_dev, info.st_ino, info.st_mode, retained_key.read_bytes())
    return {"missing_key_refused_without_creation": True, "formerly_present": formerly_present}


def cancellation_and_owner():
    f = Fixture()
    first = f.prepare()
    before_files = f.files()
    forbidden = AssertionError("metadata-only setup opened provider custody")
    with patch.object(f.custody, "read_existing_master_key", side_effect=forbidden), \
            patch.object(f.custody, "read_secret", side_effect=forbidden), \
            patch.object(f.custody, "open_secret", side_effect=forbidden), \
            patch.object(f.custody, "AESGCM", side_effect=forbidden):
        assert f.setup.status(first["operation_id"], ACTOR) == first
        cancelled = f.cancel(first)
        assert cancelled["status"] == "cancelled" and cancelled["secret_present"] is True
        assert f.setup.status(first["operation_id"], ACTOR) == cancelled
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN")
            try:
                f.setup.read_managed_pending(conn, first["operation_id"])
            except f.setup.SetupUnavailable:
                pass
            else:
                raise AssertionError("cancelled managed operation selected for cold read")
    second = f.prepare(client_id="456-next.apps.googleusercontent.com", client_secret=SECRET + "-second")
    assert second["custody_ref"] == {"owner_id": first["custody_ref"]["owner_id"], "config_version": 2}
    assert f.files() == before_files
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN")
        assert len(f.setup._rows(conn)) == 2
        for result, expected in ((first, SECRET), (second, SECRET + "-second")):
            owner, exact = f.exact(result)
            key = f.custody.read_existing_master_key(f.config.DATA_DIR, owner)
            assert f.custody.read_secret(conn, owner, exact, key=key).secret == expected
    return {"stable_owner": True, "cancelled_versions_retained": 1, "no_status_decrypt": True}


def conflicts_and_public_exclusion():
    f = Fixture()
    payload = f.payload()
    legacy = f.setup.prepare({key: value for key, value in payload.items() if key != "client_secret"}, ACTOR)
    f.conflict(lambda: f.setup.prepare_managed(f.payload(), ACTOR))
    f.cancel(legacy)
    stale = f.payload()
    pending = f.prepare()
    f.conflict(lambda: f.setup.prepare_managed(stale, ACTOR))
    f.conflict(lambda: f.setup.prepare_managed(f.payload(), ACTOR))
    f.cancel(pending)
    f.conflict(lambda: f.setup.prepare_managed(f.payload(operation_id=pending["operation_id"]), ACTOR))
    legacy_payload = {key: value for key, value in f.payload().items() if key != "client_secret"}
    f.refused(lambda: f.setup.prepare(legacy_payload, ACTOR))
    f.store.initialize()
    # This branch is the legacy external-profile consumer. Public inspection is
    # not selection authority, even after managed preparation was cancelled.
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN")
        with patch.object(f.setup.profiles, "selected", return_value=True):
            try:
                f.setup.validate_startup(conn, None, None)
            except f.setup.SetupUnavailable:
                pass
            else:
                raise AssertionError("external owner adopted cancelled managed custody")
    return {"cas_and_pending_conflicts": True, "exclusive_managed_owner": True}


def input_and_runtime_admission():
    f = Fixture()
    payload = f.payload()
    for changes in ({"client_secret": ""}, {"client_secret": "x\n"}, {"client_secret": " x"},
            {"client_secret": "é" * 2049}, {"client_secret": 123}, {"unknown": SECRET},
            {"operation_id": "not-a-uuid"}, {"client_id": "not-a-google-client"}):
        f.refused(lambda changes=changes: f.setup.prepare_managed(payload | changes, ACTOR))
    # Mutating imported flags cannot turn structural inspection into authority.
    pending = f.prepare()
    f.cancel(pending)
    for attribute, value in (("PRODUCTION_IMAGE", True), ("RELEASE_CHANNEL", "production"),
            ("TEE_PLATFORM", "aws-nitro"), ("KEY_RELEASE_REQUIRED", True),
            ("GOOGLE_OAUTH_CLIENT_ID", CLIENT), ("GOOGLE_OAUTH_CLIENT_SECRET", SECRET)):
        candidate = f.payload()
        with patch.object(f.config, attribute, value):
            with closing(f.db.connect()) as conn:
                conn.execute("BEGIN")
                assert f.setup._rows(conn)[0]["status"] == "cancelled"
            f.refused(lambda: f.setup.prepare_managed(candidate, ACTOR))
    candidate = f.payload()
    with patch.dict(os.environ, {"SERVERWARE_OAUTH_APPLICATION_CONFIG_FD": "77"}):
        f.refused(lambda: f.setup.prepare_managed(candidate, ACTOR))
    return {"strict_inputs": True, "inspection_is_not_runtime_admission": True}


def version_bound():
    f = Fixture()
    owner_id = None
    for version in range(1, f.custody.MAX_VERSIONS + 1):
        value = f.prepare()
        owner_id = owner_id or value["custody_ref"]["owner_id"]
        assert value["custody_ref"] == {"owner_id": owner_id, "config_version": version}
        f.cancel(value)
    f.conflict(lambda: f.prepare())
    assert f.db.verify_audit_chain()["ok"]
    return {"bounded_retained_versions": f.custody.MAX_VERSIONS}


def orphan_refusal(empty):
    f = Fixture()
    if empty:
        candidate = f.payload()
        owner = f.setup._admit_managed_owner(str(uuid.uuid4()))
        with f.publication.exclusive(), closing(f.db.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            f.custody.install_empty_store(conn, owner)
        f.refused(lambda: f.setup.prepare_managed(candidate, ACTOR))
    else:
        pending = f.prepare()
        owner, _ = f.exact(pending)
        extra = f.custody.bind_google(owner, config_version=2, public_profile=pending["profile_binding"])
        key = f.custody.read_existing_master_key(f.config.DATA_DIR, owner)
        with f.publication.exclusive(), closing(f.db.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            f.custody.insert_secret(conn, owner, extra, key=key, secret=SECRET + "-orphan")
        f.refused(lambda: f.setup.status(pending["operation_id"], ACTOR))
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN")
            try:
                f.setup.read_managed_pending(conn, pending["operation_id"])
            except f.setup.SetupUnavailable:
                pass
            else:
                raise AssertionError("orphan custody became a cold candidate")
    return {"orphan_refused": True, "empty": empty}


def worker(name):
    actions = {"prepare": preparation, "cancel": cancellation_and_owner,
        "conflicts": conflicts_and_public_exclusion, "admission": input_and_runtime_admission,
        "capacity": version_bound, "orphan-empty": lambda: orphan_refusal(True),
        "orphan-row": lambda: orphan_refusal(False),
        "empty-key": lambda: missing_existing_key(formerly_present=False),
        "missing-key": lambda: missing_existing_key(formerly_present=True)}
    print(json.dumps(actions[name](), sort_keys=True))


class ManagedSetupTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment["SERVERWARE_PUBLIC_URL"] = PUBLIC_URL

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-50:]))
        self.assertNotIn(SECRET, result.stdout)
        return json.loads(result.stdout)

    def test_atomic_public_pending_and_disabled_restart(self):
        self.assertTrue(self.run_worker("prepare")["atomic_public_pending"])

    def test_empty_and_missing_existing_key_refuse_without_key_or_schema_creation(self):
        for operation in ("empty-key", "missing-key"):
            with self.subTest(operation=operation):
                self.assertTrue(self.run_worker(operation)["missing_key_refused_without_creation"])

    def test_cancel_inspects_only_and_next_prepare_retains_owner(self):
        self.assertTrue(self.run_worker("cancel")["stable_owner"])

    def test_cas_pending_and_public_owner_exclusion(self):
        self.assertTrue(self.run_worker("conflicts")["exclusive_managed_owner"])

    def test_strict_input_and_actual_runtime_admission(self):
        self.assertTrue(self.run_worker("admission")["inspection_is_not_runtime_admission"])

    def test_retained_version_capacity_is_not_rotation(self):
        self.assertEqual(self.run_worker("capacity")["bounded_retained_versions"], 16)

    def test_empty_orphan_custody_schema_is_not_first_configuration(self):
        self.assertTrue(self.run_worker("orphan-empty")["orphan_refused"])

    def test_orphan_custody_version_is_not_implicitly_selected(self):
        self.assertTrue(self.run_worker("orphan-row")["orphan_refused"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)  # Match the real operator runner before creating its private store.
        worker(sys.argv[2])
    else:
        unittest.main()
