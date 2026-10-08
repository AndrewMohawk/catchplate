#!/usr/bin/env python3
"""Focused operator publication coordination tests; no server or network.

Real SQLite/signing/encryption and Linux flock, with bounded synthetic workers.
Existing persistence/catalog fixture scripts are imported, never edited. This
is Python coordination evidence, not Rust ACK or deployed end-to-end evidence.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

import test_operator_demo_persistence as common
import test_operator_workspace_store as workspace


def fail(function, *, text=None):
    try:
        function()
    except (RuntimeError, OSError) as error:
        if text is not None:
            assert text in str(error), type(error).__name__
    else:
        raise AssertionError("closed publication guard accepted operation")


def saved(config, db):
    with closing(db.connect()) as connection:
        rows = "\n".join(connection.iterdump())
    policy = config.POLICY_BUNDLE_PATH.read_bytes() if config.POLICY_BUNDLE_PATH.exists() else None
    return rows, policy


def shared_probe(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    finally:
        os.close(descriptor)


@contextmanager
def other_process_shared(path):
    # A separate OFD/process models the Rust SH guard without running a gate.
    command = [sys.executable, "-B", "-c",
        "import fcntl,os,sys; f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); "
        "fcntl.flock(f,fcntl.LOCK_SH); print('ready',flush=True); sys.stdin.readline(); os.close(f)", str(path)]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        # This process only opens a known local regular file; alarm bounds even
        # a broken handshake without leaving a background holder behind.
        import select
        assert select.select([child.stdout], [], [], 5)[0], "shared holder did not start"
        assert child.stdout.readline().strip() == "ready"
        yield
    finally:
        if child.poll() is None:
            child.communicate("release\n", timeout=5)
        assert child.returncode == 0


def fresh():
    config, db, store, _ = common.backend()
    publication = store.operator_publication
    path = config.DATA_DIR / publication.LOCK_NAME
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid()
    assert info.st_nlink == 1 and info.st_size == 0
    before = saved(config, db)
    store.initialize()
    assert saved(config, db) == before
    assert path.stat().st_ino == info.st_ino
    assert publication.ACQUISITION_SECONDS == 5.0 and shared_probe(path)
    return {"fresh_and_restart": True}


def bootstrap_fixture():
    config, db, store, _, schema, _ = workspace.legacy_fixture()
    workspace.migrate(db, schema)
    return {"initialized": True}


def operator_reopen():
    # Reopen the provisioned operator store, not generic db.init_db(), whose
    # existing schema migration bookkeeping deliberately refreshes applied_at.
    config, db, store, _ = common.backend(initialize=False)
    publication = store.operator_publication
    path = config.DATA_DIR / publication.LOCK_NAME
    identity = publication._file_identity(path.stat())
    before = saved(config, db)
    store.initialize()
    assert saved(config, db) == before
    assert publication._file_identity(path.stat()) == identity
    return {"operator_reopened_without_authority_changes": True}


def startup_refusal():
    config, db, store, _ = common.backend(initialize=False)
    before = saved(config, db)
    fail(store.initialize, text="offline publication-lock provisioning")
    assert saved(config, db) == before
    assert not (config.DATA_DIR / store.operator_publication.LOCK_NAME).exists()
    return {"unchanged": True}


def partial(kind):
    config, db, store, _ = common.backend(initialize=False)
    db.init_db()
    if kind == "table":
        with closing(db.connect()) as conn, conn:
            conn.execute("CREATE TABLE operator_catalog_partial (id INTEGER)")
    else:
        config.POLICY_BUNDLE_PATH.write_bytes(b"retained-synthetic-policy-path")
    before = saved(config, db)
    fail(store.initialize, text="offline publication-lock provisioning")
    assert saved(config, db) == before
    assert not (config.DATA_DIR / store.operator_publication.LOCK_NAME).exists()
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='operator_demo_policy'").fetchone() is None
    return {"partial_refused": kind}


def malformed():
    config, db, store, _ = common.backend(initialize=False)
    db.init_db()
    path = config.DATA_DIR / store.operator_publication.LOCK_NAME
    target = config.DATA_DIR / "synthetic-lock-target"
    target.touch(mode=0o600)
    before = saved(config, db)
    cases = ("mode", "content", "symlink", "hardlink", "fifo", "directory")
    for case in cases:
        if case == "symlink":
            path.symlink_to(target)
        elif case == "hardlink":
            os.link(target, path)
        elif case == "fifo":
            os.mkfifo(path, 0o600)
        elif case == "directory":
            path.mkdir(mode=0o700)
        else:
            path.write_bytes(b"x" if case == "content" else b"")
            path.chmod(0o644 if case == "mode" else 0o600)
        fail(store.initialize)
        assert saved(config, db) == before
        path.rmdir() if case == "directory" else path.unlink()
    return {"malformed_refused": len(cases)}


def pinned_changes():
    config, db, store, _ = common.backend()
    path = config.DATA_DIR / store.operator_publication.LOCK_NAME
    original = config.DATA_DIR / "retained-original-lock"
    before = saved(config, db)
    path.rename(original)
    fail(store.materialize)
    fail(store.initialize)
    assert not path.exists(), "missing pinned guard was recreated"
    path.touch(mode=0o600)
    fail(store.materialize)
    path.unlink()
    original.rename(path)
    path.chmod(0o640)
    fail(store.materialize)
    path.chmod(0o600)
    store.materialize()
    assert saved(config, db) == before
    return {"pinned_changes_refused": True}


def nested_and_local_bound():
    config, db, store, _ = common.backend()
    publication = store.operator_publication
    path = config.DATA_DIR / publication.LOCK_NAME
    calls = []
    flock = fcntl.flock
    def observe(descriptor, operation):
        calls.append(operation)
        return flock(descriptor, operation)
    with patch.object(publication.fcntl, "flock", observe):
        with publication.exclusive():
            deadline = publication._state.deadline
            with publication.exclusive():
                assert publication._state.deadline == deadline
                assert publication._state.depth == 2
                store.materialize()
            assert publication._state.depth == 1
    assert calls == [fcntl.LOCK_EX | fcntl.LOCK_NB, fcntl.LOCK_UN], calls
    entered, release = threading.Event(), threading.Event()
    def holder():
        with store._LOCK:
            entered.set()
            assert release.wait(3)
    thread = threading.Thread(target=holder)
    thread.start()
    assert entered.wait(3)
    try:
        with patch.object(publication, "ACQUISITION_SECONDS", 0.05):
            start = time.monotonic()
            fail(store.materialize, text="timed out")
            assert time.monotonic() - start < 0.5
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and shared_probe(path)
    return {"nested_reuses_guard": True, "local_wait_bounded": True}


def blocked_publishers():
    config, db, store, _, schema, _ = workspace.legacy_fixture(with_revocation=False)
    publication = store.operator_publication
    path = config.DATA_DIR / publication.LOCK_NAME
    from serverware import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    identifier = workspace.rows(db, "operator_demo_connections")[0]["id"]
    digest = store.get_policy_high_water()["policy_hash"]
    revoke = store.RevocationInput(connection_id=identifier, expected_policy_hash=digest)
    create = inputs.CredentialInput(expected_revision=1, expected_policy_hash=digest,
        name="Blocked synthetic", auth_type="bearer", secret=common._PROVIDER_SECRET)
    operations = [store.initialize, store.materialize, lambda: common.create_connection(store),
        lambda: store.revoke_connection(revoke, common._ACTOR),
        lambda: mutations.create_credential(create, common._ACTOR)]
    original_connect = db.connect
    for operation in operations:
        before = saved(config, db)
        attempted = threading.Event()
        worker_id = []
        errors = []
        connections = []
        flock = fcntl.flock
        def observe_flock(descriptor, flags):
            if flags == fcntl.LOCK_EX | fcntl.LOCK_NB:
                attempted.set()
            return flock(descriptor, flags)
        def observe_connect():
            if worker_id and threading.get_ident() == worker_id[0]:
                connections.append(True)
            return original_connect()
        def run():
            worker_id.append(threading.get_ident())
            try:
                operation()
            except publication.PublicationError as error:
                errors.append(str(error))
            except BaseException as error:
                errors.append(type(error).__name__)
        with other_process_shared(path), patch.object(publication, "ACQUISITION_SECONDS", 0.2), \
                patch.object(publication.fcntl, "flock", observe_flock), patch.object(db, "connect", observe_connect):
            thread = threading.Thread(target=run)
            thread.start()
            assert attempted.wait(3)
            # The SH holder and waiting publisher must not obstruct receiver /
            # nonce writers. This real writer is a deterministic lock oracle.
            with closing(sqlite3.connect(config.DB_PATH, timeout=0.05)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            assert store.get_policy_high_water() is not None
            thread.join(3)
            assert not thread.is_alive()
        assert errors == ["operator publication ownership timed out"], errors
        assert not connections, "publisher opened SQLite while waiting for publication ownership"
        assert saved(config, db) == before
    with other_process_shared(path):
        assert db.reserve_credential_lease_nonce(common._NONCE_KEY, "sha256:" + "3" * 64,
            now_epoch_ms=common._NOW) is None
    return {"publishers_blocked_before_sqlite": len(operations), "nonce_writer_unblocked": True}


def held_through_materialization():
    config, db, store, _, schema, inputs, mutations = workspace.workspace()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    path = config.DATA_DIR / store.operator_publication.LOCK_NAME
    old_policy = config.POLICY_BUNDLE_PATH.read_bytes()
    original = store.materialize
    phases = []
    def materialize():
        store.operator_publication.assert_held()
        assert not shared_probe(path)
        with closing(db.connect()) as conn:
            committed = conn.execute("SELECT signed_bundle_json FROM operator_demo_policy").fetchone()[0].encode()
        assert committed != old_policy and config.POLICY_BUNDLE_PATH.read_bytes() == old_policy
        phases.append("committed_exclusive")
        original()
        assert config.POLICY_BUNDLE_PATH.read_bytes() == committed
        assert not shared_probe(path)
        phases.append("materialized_exclusive")
    def loaded():
        assert shared_probe(path), "HTTP observation entered under EX"
        return None
    with patch.object(store, "materialize", materialize), patch.object(store, "loaded_policy_hash", loaded):
        workspace.create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
    assert phases == ["committed_exclusive", "materialized_exclusive"]
    assert shared_probe(path)
    return {"commit_materialize_one_guard": True}


def transaction_assertion():
    config, db, store, _ = common.backend()
    from serverware import operator_catalog_policy
    before = saved(config, db)
    with closing(db.connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        fail(lambda: operator_catalog_policy.publish(connection), text="ownership required")
        connection.rollback()
    assert saved(config, db) == before
    return {"transaction_cannot_acquire_late": True}


def inactive():
    from serverware import operator_publication
    def enter():
        with operator_publication.exclusive(startup=True):
            raise AssertionError("inactive profile admitted")
    fail(enter, text="profile unavailable")
    assert not Path(os.environ["SERVERWARE_DATA_DIR"]).exists()
    return {"inactive_unchanged": True}


def crash_holding():
    config, db, store, _ = common.backend(initialize=False)
    with store.operator_publication.exclusive(startup=True):
        os._exit(73)


def worker(operation):
    functions = {"fresh": fresh, "fixture": bootstrap_fixture, "operator-reopen": operator_reopen,
        "startup-refusal": startup_refusal,
        "partial-table": lambda: partial("table"), "partial-policy": lambda: partial("policy"),
        "malformed": malformed, "pinned": pinned_changes, "nested": nested_and_local_bound,
        "blocked": blocked_publishers, "lifetime": held_through_materialization,
        "assertion": transaction_assertion, "inactive": inactive, "crash-held": crash_holding,
        "publication-recovery": workspace.publication_recovery}
    print(json.dumps(functions[operation](), sort_keys=True))


class OperatorPublicationTests(unittest.TestCase):
    setUp = common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation, *, expected=0):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=common.ROOT, env=self.environment, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, expected, "\n".join(result.stderr.splitlines()[-40:]))
        return json.loads(result.stdout) if expected == 0 else None

    def retained(self):
        with closing(sqlite3.connect((self.directory / "serverware.sqlite3").as_uri() + "?mode=ro", uri=True)) as conn:
            dump = "\n".join(conn.iterdump())
        return dump, (self.directory / "policy-bundle.json").read_bytes()

    def test_fresh_and_repeat_startup(self):
        self.run_worker("fresh")

    def test_missing_initialized_guard_refuses_without_writes(self):
        self.run_worker("fixture")
        (self.directory / ".operator-publication.lock").unlink()
        self.run_worker("startup-refusal")

    def test_partial_table_refuses_before_operator_ddl(self):
        self.run_worker("partial-table")

    def test_policy_path_without_operator_tables_refuses(self):
        self.run_worker("partial-policy")

    def test_malformed_preexisting_guards_never_repaired(self):
        self.run_worker("malformed")

    def test_pinned_guard_missing_replaced_or_mode_changed_refuses(self):
        self.run_worker("pinned")

    def test_nested_guard_reuses_deadline_and_local_wait_is_bounded(self):
        self.run_worker("nested")

    def test_all_publishers_wait_before_sqlite_and_nonce_does_not_wait(self):
        self.run_worker("blocked")

    def test_exclusive_covers_commit_materialization_not_http_observation(self):
        self.run_worker("lifetime")

    def test_transaction_level_publish_requires_existing_ownership(self):
        self.run_worker("assertion")

    def test_inactive_profile_is_unchanged(self):
        self.run_worker("inactive")

    def test_explicit_stopped_migration_preserves_authority_and_is_idempotent(self):
        self.run_worker("fixture")
        (self.directory / ".operator-publication.lock").unlink()
        before = self.retained()
        command = [sys.executable, "-B", "-m", "serverware.operator_publication", "--provision-existing-stopped"]
        for _ in range(2):
            result = subprocess.run(command, cwd=common.ROOT, env=self.environment,
                capture_output=True, text=True, timeout=35)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.retained(), before)
        self.assertIn("acknowledged, not verified", result.stdout)
        self.run_worker("operator-reopen")
        self.assertEqual(self.retained(), before)

    def test_abrupt_exit_releases_exclusive_without_mutation(self):
        self.run_worker("fixture")
        before = self.retained()
        self.run_worker("crash-held", expected=73)
        self.assertTrue(shared_probe(self.directory / ".operator-publication.lock"))
        self.assertEqual(self.retained(), before)

    def test_postcommit_materialization_failure_retains_pending_recovery(self):
        self.run_worker("publication-recovery")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        worker(sys.argv[2])
    else:
        unittest.main(verbosity=2)
