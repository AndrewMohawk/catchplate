#!/usr/bin/env python3
"""Connected managed-preparation/cold-read controls, not activation acceptance.

Run only in the bounded network-none regression harness. A configured writer
uses the real operator store, publication EX, SQLite transaction, audit and
custody encryption. A fresh child then uses the config-independent bootstrap SH
reader and the exact operation/owner/version/profile returned to its caller.
No provider, application server, managed activation or serving path is started.
"""
from __future__ import annotations

from contextlib import closing
import fcntl
import hashlib
import importlib.abc
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FORBIDDEN = {"catchplate.config", "catchplate.db", "catchplate.crypto"}
CLIENT = "123-connected-fixture.apps.googleusercontent.com"
SECRET = "synthetic-connected-provider-secret-never-real"
ORIGIN = "https://console.example.com"
ADMISSION = dict(operator_development=True, release_channel="dev",
    production_image=False, native_or_enrolled=False)
RETAINED = ("credentials", "credential_generations", "operator_demo_connections",
    "operator_demo_revocations", "operator_demo_nonces", "operator_catalog_credentials",
    "operator_catalog_applications", "operator_catalog_rules", "operator_demo_policy",
    "operator_demo_settings")


class ColdImportGuard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in FORBIDDEN:
            raise AssertionError("configured runtime import forbidden in cold reader")


def forbid_network():
    """Independent fail-on-contact sentinel in each already isolated child."""
    contacts = []

    def observe(event, _arguments):
        if event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "socket.bind"}:
            contacts.append(event)
            raise AssertionError("metadata-only provider preparation contacted network")

    sys.addaudithook(observe)
    return contacts


def file_state(directory):
    result = {}
    for name in ("master.key", "policy-bundle.json", "policy-signing-ed25519.pem",
            "policy-signing-ed25519.pub.pem", ".operator-publication.lock"):
        path = directory / name
        if path.exists():
            info = path.stat()
            result[name] = (info.st_dev, info.st_ino, info.st_mode & 0o777,
                hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def rows(conn):
    return {table: [tuple(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY 1")]
        for table in RETAINED}


def digest(conn):
    return hashlib.sha256("\n".join(conn.iterdump()).encode()).hexdigest()


def writer(mode):
    contacts = forbid_network()
    import test_operator_workspace_store as workspace
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    from catchplate import operator_google_setup as setup
    from catchplate import operator_provider_custody as custody
    from catchplate import operator_catalog_oauth_profile as profiles
    from catchplate import operator_publication as publication

    # Preserve real pre-existing credential/application/rule and signed policy.
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    workspace.create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
    workspace.verify_signed(config, db, store, bundles)
    review = setup.review(workspace.common._ACTOR)
    operation_id = str(uuid.uuid4())
    payload = {key: review[key] for key in
        ("expected_revision", "expected_policy_hash", "expected_settings_digest")}
    payload.update(operation_id=operation_id, client_id=CLIENT, client_secret=SECRET)
    previous_files = file_state(config.DATA_DIR)

    if mode == "unheld":
        admitted = custody.admit_development_owner(str(uuid.uuid4()), **ADMISSION)
        with closing(db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            before = digest(conn)
            try:
                custody.install_empty_store(conn, admitted)
            except custody.CustodyError as error:
                assert str(error) == "operator provider custody refused"
            else:
                raise AssertionError("real custody writer accepted absent publication EX")
            assert digest(conn) == before
            conn.rollback()
        assert file_state(config.DATA_DIR) == previous_files and not contacts
        return {"unheld_writer_refused": True, "provider_contacts": 0}

    if mode == "rollback":
        with closing(db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER connected_setup_audit_abort BEFORE INSERT ON audit_events "
                "WHEN NEW.event_type='operator_catalog.google_setup.prepared' "
                "BEGIN SELECT RAISE(ABORT,'synthetic connected setup audit refusal'); END")
    with closing(db.connect()) as conn:
        before, retained = digest(conn), rows(conn)

    inserted = []
    original_insert = custody.insert_secret

    def observed_insert(conn, owner, binding, **options):
        # Observe the real writer, never replace/mock its ownership assertion.
        publication.assert_held()
        assert conn.in_transaction
        descriptor = os.open(config.DATA_DIR / publication.LOCK_NAME, os.O_RDONLY | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise AssertionError("custody insertion lacked actual publication EX")
        finally:
            os.close(descriptor)
        original_insert(conn, owner, binding, **options)
        inserted.append((owner.owner_id, binding.config_version))

    with patch.object(custody, "insert_secret", side_effect=observed_insert):
        if mode == "rollback":
            try:
                setup.prepare_managed(payload, workspace.common._ACTOR)
            except setup.SetupUnavailable as error:
                assert str(error) == "operator Google setup unavailable"
                assert SECRET not in repr(error)
            else:
                raise AssertionError("managed preparation ignored real audit failure")
        else:
            assert mode == "prepare"
            operation = setup.prepare_managed(payload, workspace.common._ACTOR)
    assert len(inserted) == 1
    assert file_state(config.DATA_DIR) == previous_files
    with closing(db.connect()) as conn:
        assert rows(conn) == retained
        if mode == "rollback":
            assert digest(conn) == before
            assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (custody.TABLE,)).fetchone()
            assert not setup._rows(conn)
        else:
            assert SECRET not in "\n".join(conn.iterdump())
            assert operation["schema"] == "catchplate.operatorGoogleManagedSetup/v1"
            assert operation["operation_id"] == operation_id and operation["client_id"] == CLIENT
            assert operation["profile_binding"] == profiles._record(CLIENT, ORIGIN + profiles.CALLBACK_PATH)
            assert operation["policy_hash"] == review["expected_policy_hash"]
            assert operation["staged_revision"] == operation["revision"] == review["expected_revision"] + 1
            assert schema.read_catalog(conn)["revision"] == operation["staged_revision"]
            assert operation["status"] == "pending" and operation["activation_receipt"] is None
            assert operation["secret_present"] is True
            assert operation["custody_ref"] == dict(owner_id=inserted[0][0], config_version=inserted[0][1])
            assert operation["custody_ref"]["config_version"] == 1
            assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone()
    assert not profiles.selected(), "preparation activated configured Google capability"
    workspace.verify_signed(config, db, store, bundles)
    if mode == "prepare":
        # Ordinary status is structural/public: it must not open any secret.
        with patch.object(custody, "read_existing_master_key", side_effect=AssertionError("status read key")), \
                patch.object(custody, "read_secret", side_effect=AssertionError("status read secret")), \
                patch.object(custody, "open_secret", side_effect=AssertionError("status decrypted")), \
                patch.object(custody, "AESGCM", side_effect=AssertionError("status used cipher")):
            assert setup.status(operation_id, workspace.common._ACTOR) == operation
        assert SECRET not in json.dumps(operation)
    assert not contacts
    return {"operation": operation if mode == "prepare" else None,
        "rollback": mode == "rollback", "actual_ex_transaction_observed": True,
        "inactive": True, "provider_contacts": 0}


def cold(mode, request):
    sys.meta_path.insert(0, ColdImportGuard())
    contacts = forbid_network()
    assert not FORBIDDEN.intersection(sys.modules)
    from catchplate import operator_google_setup as setup
    from catchplate import operator_provider_custody as custody
    from catchplate import operator_publication as publication
    directory = Path(request["directory"])
    admission = publication.admit_bootstrap_reader(directory, **ADMISSION)
    before_files = file_state(directory)
    with publication.bootstrap_read(admission) as conn:
        assert conn.in_transaction and conn.execute("PRAGMA query_only").fetchone()[0] == 1
        before = digest(conn)
        if mode == "absent":
            assert not setup._rows(conn)
            assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (custody.TABLE,)).fetchone()
            public = None
        else:
            expected = request["operation"]
            public = setup.read_managed_pending(conn, expected["operation_id"])
            assert public == expected, "cold reader did not preserve exact caller-held preparation"
            assert public["status"] == "pending" and public["activation_receipt"] is None
            assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone()
            reference = expected["custody_ref"]
            owner = custody.admit_development_owner(reference["owner_id"], **ADMISSION)
            binding = custody.bind_google(owner, config_version=reference["config_version"],
                public_profile=expected["profile_binding"])
            inspected = custody.inspect_public_binding(conn, owner, binding)
            assert inspected == {"schema": custody.SCHEMA, **reference,
                "public_profile": expected["profile_binding"], "secret_present": True}
            if mode == "missing-key":
                assert not (directory / "master.key").exists()
                try:
                    custody.read_existing_master_key(directory, owner)
                except custody.CustodyError as error:
                    assert str(error) == "operator provider custody refused"
                else:
                    raise AssertionError("cold reader supplied a missing master key")
                assert not (directory / "master.key").exists(), "reader recreated missing key"
            else:
                key = custody.read_existing_master_key(directory, owner)
                material = custody.read_secret(conn, owner, binding, key=key)
                assert material.secret == SECRET, "cold reader decrypted different synthetic material"
                assert material.public_view() == inspected
                if mode == "mismatch":
                    try:
                        setup.read_managed_pending(conn, str(uuid.uuid4()))
                    except (setup.SetupNotFound, setup.SetupUnavailable):
                        pass
                    else:
                        raise AssertionError("cold reader selected a different operation as fallback")
                    wrong_owner = custody.admit_development_owner(str(uuid.uuid4()), **ADMISSION)
                    wrong_profile = {**expected["profile_binding"], "client_id": "999-other.apps.googleusercontent.com"}
                    cases = ((wrong_owner, custody.bind_google(wrong_owner,
                        config_version=reference["config_version"], public_profile=expected["profile_binding"])),
                        (owner, custody.bind_google(owner, config_version=reference["config_version"] + 1,
                            public_profile=expected["profile_binding"])),
                        (owner, custody.bind_google(owner, config_version=reference["config_version"],
                            public_profile=wrong_profile)))
                    for selected_owner, selected_binding in cases:
                        try:
                            custody.read_secret(conn, selected_owner, selected_binding, key=key)
                        except custody.CustodyError as error:
                            assert str(error) == "operator provider custody refused"
                        else:
                            raise AssertionError("cold reader adopted a different custody binding")
        try:
            conn.execute("DELETE FROM audit_events WHERE 0")
        except sqlite3.OperationalError:
            pass
        else:
            raise AssertionError("cold bootstrap connection allowed SQL writes")
        assert digest(conn) == before and conn.total_changes == 0
    assert file_state(directory) == before_files
    assert not FORBIDDEN.intersection(sys.modules) and not contacts
    assert SECRET not in json.dumps(public)
    return {"operation": public, "config_independent": True, "authority_unchanged": True,
        "missing_key_not_created": mode == "missing-key", "inactive": True, "provider_contacts": 0}


class ProviderColdReadTests(unittest.TestCase):
    def setUp(self):
        import test_operator_demo_persistence as common
        self.scratch = tempfile.TemporaryDirectory(prefix="catchplate-provider-cold-read-",
            dir=os.getenv("TMPDIR", "/srv/catchplate-fast/tmp"))
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name) / "data"
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("CATCHPLATE_")}
        self.environment.update(common._ENVIRONMENT, CATCHPLATE_DATA_DIR=str(self.directory),
            CATCHPLATE_PUBLIC_URL=ORIGIN)

    def child(self, mode, *, operation=None, reading=False):
        environment = dict(self.environment)
        if reading:
            environment = {key: value for key, value in environment.items() if not key.startswith("CATCHPLATE_")}
        request = {"directory": str(self.directory), "operation": operation}
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
            "--cold" if reading else "--writer", mode], cwd=ROOT, env=environment,
            input=json.dumps(request), text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-40:]))
        self.assertNotIn(SECRET, result.stdout)
        return json.loads(result.stdout)

    def test_real_preparation_survives_config_independent_cold_read(self):
        prepared = self.child("prepare")
        self.assertTrue(prepared["actual_ex_transaction_observed"])
        cold_read = self.child("read", operation=prepared["operation"], reading=True)
        self.assertEqual(cold_read["operation"], prepared["operation"])
        self.assertEqual(self.child("read", operation=prepared["operation"], reading=True), cold_read)

    def test_real_audit_failure_rolls_back_setup_revision_and_custody(self):
        self.assertTrue(self.child("rollback")["rollback"])
        self.assertIsNone(self.child("absent", reading=True)["operation"])

    def test_missing_key_is_not_recreated_by_public_or_private_cold_read(self):
        prepared = self.child("prepare")
        key = self.directory / "master.key"
        retained = self.directory / "retained-synthetic-master.key"
        before = file_state(self.directory)
        key.rename(retained)
        try:
            result = self.child("missing-key", operation=prepared["operation"], reading=True)
            self.assertTrue(result["missing_key_not_created"])
            self.assertFalse(key.exists())
        finally:
            retained.rename(key)
        self.assertEqual(file_state(self.directory), before)

    def test_exact_owner_version_and_public_profile_cannot_be_substituted(self):
        prepared = self.child("prepare")
        self.assertTrue(self.child("mismatch", operation=prepared["operation"], reading=True)["authority_unchanged"])

    def test_real_store_custody_writer_requires_publication_ex(self):
        self.assertTrue(self.child("unheld")["unheld_writer_refused"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] in {"--writer", "--cold"}:
        os.umask(0o077)
        raw = sys.stdin.buffer.read(65_537)
        assert len(raw) <= 65_536
        request = json.loads(raw)
        result = writer(sys.argv[2]) if sys.argv[1] == "--writer" else cold(sys.argv[2], request)
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
