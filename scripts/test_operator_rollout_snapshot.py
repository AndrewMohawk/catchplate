#!/usr/bin/env python3
"""Synthetic SQLite/tempfile observer tests; never reads runtime data."""
from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

import operator_rollout_snapshot as observer


def initialize_ecr(connection):
    """Run only the actual owner DDL on disposable SQLite; no app initialization."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from catchplate import operator_ecr_publications as owner, operator_publication
    previous_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN IMMEDIATE")
        with patch.object(owner, "_profile", return_value=(None, None)), \
                patch.object(operator_publication, "assert_held"):
            owner.initialize(connection)
        connection.commit()
    finally:
        connection.row_factory = previous_factory


def populate(connection, *, without_rowid=True):
    connection.executescript("CREATE TABLE credentials(id TEXT PRIMARY KEY,value BLOB);"
        "INSERT INTO credentials VALUES('one',X'010203');"
        "CREATE TABLE audit_events(id TEXT PRIMARY KEY,value TEXT);"
        "INSERT INTO audit_events VALUES('before','synthetic audit');"
        "CREATE TABLE metadata_audit_outbox(id TEXT PRIMARY KEY);"
        "CREATE TABLE catchplate_store_migrations(migration TEXT PRIMARY KEY,version BIGINT,applied_at TEXT);"
        "INSERT INTO catchplate_store_migrations VALUES('schema',1,'2026-01-01T00:00:00+00:00');")
    for table in sorted(observer.NOTIFICATIONS | {"operator_upstream_setups"}):
        connection.execute('CREATE TABLE "' + table + '" (id TEXT PRIMARY KEY,value TEXT)'
            + (' WITHOUT ROWID' if without_rowid else ''))
        connection.executemany('INSERT INTO "' + table + '" VALUES (?,?)', [('two', 'b'), ('one', 'a')])
    connection.commit()


class DatabaseTests(unittest.TestCase):
    def pair(self):
        connections = [sqlite3.connect(":memory:") for _ in range(2)]
        for connection in connections:
            self.addCleanup(connection.close)
            populate(connection)
        return connections

    def test_all_five_notifications_and_without_rowid_are_compared(self):
        before, after = self.pair()
        after.execute("INSERT INTO audit_events VALUES('after','new audit')")
        after.commit()
        result = observer.compare_databases(before, after)
        self.assertEqual(result['notification_tables'], sorted(observer.NOTIFICATIONS))
        self.assertIn('operator_upstream_setups', result['all_non_audit_tables'])
        self.assertEqual((result['prior_audit_count'], result['current_audit_count']), (1, 2))

    def test_each_notification_table_change_is_refused(self):
        for table in sorted(observer.NOTIFICATIONS):
            with self.subTest(table=table):
                before, after = self.pair()
                after.execute('UPDATE "' + table + '" SET value=? WHERE id=?', ('changed', 'one'))
                after.commit()
                with self.assertRaises(observer.SnapshotError) as raised:
                    observer.compare_databases(before, after)
                self.assertEqual((raised.exception.code, raised.exception.table), ('authority_table_changed', table))

    def test_complete_schema_is_dynamic_not_old_583_objects(self):
        before, after = self.pair()
        for connection in (before, after):
            for number in range(600):
                connection.execute('CREATE VIEW view_' + str(number) + ' AS SELECT 1')
            connection.commit()
        self.assertGreater(observer.compare_databases(before, after)['schema_object_count'], 600)

    def test_schema_object_added_at_end_is_refused(self):
        before, after = self.pair()
        after.execute('CREATE VIEW z_last AS SELECT 1')
        after.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after)
        self.assertEqual(raised.exception.code, 'database_schema_changed')

    def test_schema_over_bound_is_not_truncated(self):
        before, after = self.pair()
        original = observer.MAX_OBJECTS
        try:
            observer.MAX_OBJECTS = 1
            with self.assertRaises(observer.SnapshotError) as raised:
                observer.compare_databases(before, after)
            self.assertEqual(raised.exception.code, 'schema_bound')
        finally:
            observer.MAX_OBJECTS = original

    def test_audit_prefix_mutation_is_refused(self):
        before, after = self.pair()
        after.execute("UPDATE audit_events SET value='changed'")
        after.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after)
        self.assertEqual(raised.exception.code, 'audit_prefix_changed')

    def test_timestamp_only_migration_change_is_explicitly_reported(self):
        before, after = self.pair()
        after.execute("UPDATE catchplate_store_migrations SET applied_at='2026-01-02T00:00:00+00:00'")
        after.commit()
        self.assertTrue(observer.compare_databases(before, after)['migration_timestamps']['timestamp_only_change'])

    def test_migration_version_change_is_not_a_timestamp_exception(self):
        before, after = self.pair()
        after.execute('UPDATE catchplate_store_migrations SET version=2')
        after.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after)
        self.assertEqual(raised.exception.code, 'migration_authority_changed')

    def test_nonempty_outbox_and_partial_notifications_refused(self):
        before, after = self.pair()
        for connection in (before, after):
            connection.execute("INSERT INTO metadata_audit_outbox VALUES('pending')")
            connection.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after)
        self.assertEqual(raised.exception.code, 'audit_outbox_not_empty')
        before, after = self.pair()
        for connection in (before, after):
            connection.execute('DROP TABLE operator_notification_attempts')
            connection.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after)
        self.assertEqual(raised.exception.code, 'partial_notification_schema')

    def test_typed_rows_distinguish_integer_and_real(self):
        before, after = self.pair()
        for connection, value in ((before, 1), (after, 1.0)):
            connection.execute('CREATE TABLE typed(value)')
            connection.execute('INSERT INTO typed VALUES (?)', (value,))
            connection.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after)
        self.assertEqual((raised.exception.code, raised.exception.table), ('authority_table_changed', 'typed'))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='operator-observer-pure-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.persistent, self.custody = self.root / 'persistent', self.root / 'custody'
        self.persistent.mkdir(mode=0o700)
        self.custody.mkdir(mode=0o700)
        (self.persistent / 'app-data').mkdir(mode=0o700)
        self.database = self.persistent / observer.DB_MAIN
        with sqlite3.connect(self.database) as connection:
            populate(connection)
        self.database.chmod(0o600)
        self.put(self.persistent / 'app-data/master.key', b'synthetic retained key')
        self.put(self.persistent / 'app-data/decision-gate-ca-cert.pem', b'synthetic derived certificate')
        self.put(self.custody / 'notification-key.json', b'synthetic notification key')

    def put(self, filename, data):
        filename.write_bytes(data)
        filename.chmod(0o600)

    def receipt(self):
        return observer.inventory(self.persistent, self.custody)

    def test_end_to_end_private_copies_are_bound_to_actual_inventory(self):
        before = self.receipt()
        before_root, before_custody = self.root / 'before', self.root / 'before-custody'
        after_root, after_custody = self.root / 'after', self.root / 'after-custody'
        shutil.copytree(self.persistent, before_root)
        shutil.copytree(self.custody, before_custody)
        with sqlite3.connect(self.database) as connection:
            connection.execute("INSERT INTO audit_events VALUES('after','later synthetic audit')")
        after = self.receipt()
        shutil.copytree(self.persistent, after_root)
        shutil.copytree(self.custody, after_custody)
        result = observer.compare(before_root, after_root, before_custody, after_custody, before, after)
        self.assertTrue(result['ok'])
        self.assertFalse(result['live_sqlite_opened'])
        self.assertEqual((result['prior_audit_count'], result['current_audit_count']), (1, 2))
        self.assertEqual(self.receipt(), after)

    def test_custody_bytes_mode_and_inode_changes_are_refused(self):
        before = self.receipt()
        for field, value in (('sha256', '0' * 64), ('mode', 0o644), ('ino', before['custody']['notification-key.json']['ino'] + 1)):
            changed = deepcopy(before)
            changed['custody']['notification-key.json'][field] = value
            with self.subTest(field=field), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, changed, identities=True)

    def test_only_exact_derived_ca_inode_exception_is_allowed(self):
        before = self.receipt()
        changed = deepcopy(before)
        name = 'app-data/decision-gate-ca-cert.pem'
        changed['persistent'][name]['ino'] += 1
        self.assertEqual(observer.compare_files(before, changed, identities=True), [name])
        for field in ('mode', 'dev', 'uid'):
            refused = deepcopy(changed)
            refused['persistent'][name][field] += 1
            with self.subTest(field=field), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, refused, identities=True)
        changed = deepcopy(before)
        changed['persistent']['app-data/master.key']['ino'] += 1
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, changed, identities=True)

    def test_symlink_hardlink_and_new_empty_directory_refused(self):
        before = self.receipt()
        link = self.persistent / 'extra'
        link.symlink_to(self.custody, target_is_directory=True)
        with self.assertRaises(observer.SnapshotError):
            self.receipt()
        link.unlink()
        os.link(self.persistent / 'app-data/master.key', link)
        with self.assertRaises(observer.SnapshotError):
            self.receipt()
        link.unlink()
        link.mkdir()
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, self.receipt(), identities=True)


class EcrInitializationTests(unittest.TestCase):
    """Exact first-init delta only; old comparisons remain strict by default."""

    pair = DatabaseTests.pair
    setUp = FileTests.setUp
    put = FileTests.put
    receipt = FileTests.receipt

    def test_actual_final_owner_schema_and_initial_state_are_exactly_pinned(self):
        before, after = self.pair()
        initialize_ecr(after)
        result = observer.compare_databases(before, after, ecr_initialization=True)
        self.assertFalse(result['database_schema_equal'])
        self.assertTrue(result['preexisting_schema_preserved'])
        self.assertEqual(result['ecr_initialization']['schema_sha256'], observer.ECR_SCHEMA_SHA256)
        self.assertEqual(result['ecr_initialization']['audit_append_count'], 0)
        self.assertEqual(result['all_non_audit_tables']['operator_ecr_owner']['count'], 1)
        for table in ('operator_ecr_publications', 'operator_ecr_child_ids'):
            self.assertEqual(result['all_non_audit_tables'][table]['count'], 0)
        columns = [row[1] for row in after.execute('PRAGMA table_info(operator_ecr_publications)')]
        self.assertIn('artifact_retirement_status', columns)
        self.assertIn('artifacts_retired_at_epoch_ms', columns)

    def test_schema_exception_is_opt_in_first_only_and_closed_to_all_other_objects(self):
        for case in ('no-opt-in', 'already-present', 'alter', 'index', 'other-table', 'ecr-view', 'quota-first'):
            before, after = self.pair()
            initialize_ecr(after)
            if case == 'already-present':
                initialize_ecr(before)
            elif case == 'alter':
                after.execute('ALTER TABLE operator_ecr_publications ADD COLUMN surprise TEXT')
            elif case == 'index':
                after.execute('DROP INDEX operator_ecr_publications_page')
            elif case == 'other-table':
                after.execute('CREATE TABLE unrelated_addition(id TEXT)')
            elif case == 'ecr-view':
                after.execute('CREATE VIEW operator_ecr_surprise AS SELECT 1')
            after.commit()
            options = {'ecr_initialization': case != 'no-opt-in'}
            if case == 'quota-first':
                options['x_quota_transition'] = 'first'
            with self.subTest(case=case), self.assertRaises(observer.SnapshotError):
                observer.compare_databases(before, after, **options)

    def test_owner_shape_empty_jobs_and_exact_audit_delta_are_required(self):
        changes = ["DELETE FROM operator_ecr_owner",
            "UPDATE operator_ecr_owner SET owner_process='not-a-uuid'",
            "UPDATE operator_ecr_owner SET boot_id='00000000-0000-1000-8000-000000000001'",
            "INSERT INTO operator_ecr_child_ids VALUES('child','parent','binding')",
            "INSERT INTO operator_ecr_publications(id,status,binding_json,manifest_digest,artifact_sha256,"
                "boot_id,created_at_epoch_ms,expires_at_epoch_ms,deadline_monotonic_ns) "
                "VALUES('parent','staging','{}','manifest','artifact','boot',1,2,3)",
            "INSERT INTO audit_events VALUES('new','unexpected append')",
            "UPDATE credentials SET value=X'09'", "UPDATE audit_events SET value='changed'"]
        for statement in changes:
            before, after = self.pair()
            initialize_ecr(after)
            after.execute(statement)
            after.commit()
            with self.subTest(statement=statement), self.assertRaises(observer.SnapshotError):
                observer.compare_databases(before, after, ecr_initialization=True)
        before, after = self.pair()
        initialize_ecr(after)
        after.execute("UPDATE catchplate_store_migrations SET applied_at='2026-01-02T00:00:00+00:00'")
        after.commit()
        self.assertTrue(observer.compare_databases(before, after,
            ecr_initialization=True)['migration_timestamps']['timestamp_only_change'])

    def test_retained_quota_and_new_ecr_keep_both_closed_contracts(self):
        import test_operator_rollout_x_quota as quota_fixture
        before, after = quota_fixture.DatabaseTests.pair(self, retained=True)
        initialize_ecr(after)
        result = observer.compare_databases(before, after,
            x_quota_transition='retained', ecr_initialization=True)
        self.assertEqual(result['x_quota_initialization']['added_schema_objects'], [])
        self.assertEqual(result['x_quota_initialization']['audit_append_count'], 0)
        self.assertEqual(result['ecr_initialization']['audit_append_count'], 0)
        before, after = quota_fixture.DatabaseTests.pair(self, retained=True)
        initialize_ecr(after)
        after.execute('UPDATE operator_x_quota_state SET wall_highwater_ms=wall_highwater_ms+1')
        after.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(before, after, x_quota_transition='retained', ecr_initialization=True)
        self.assertEqual(raised.exception.code, 'authority_table_changed')

    def test_new_empty_directory_requires_exact_path_owner_mode_device_and_non_alias(self):
        before = self.receipt()
        (self.persistent / observer.ECR_DIRECTORY).mkdir(mode=0o700)
        after = self.receipt()
        self.assertEqual(observer.compare_files(before, after, identities=True, ecr_initialization=True), [])
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, after, identities=True)
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(after, after, identities=True, ecr_initialization=True)
        for field, value in (('mode', 0o750), ('uid', after['persistent'][observer.ECR_DIRECTORY]['uid'] + 1),
                ('gid', after['persistent'][observer.ECR_DIRECTORY]['gid'] + 1),
                ('dev', after['persistent'][observer.ECR_DIRECTORY]['dev'] + 1), ('kind', 'file')):
            changed = deepcopy(after)
            changed['persistent'][observer.ECR_DIRECTORY][field] = value
            with self.subTest(field=field), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, changed, identities=True, ecr_initialization=True)
        alias = deepcopy(after)
        alias['persistent'][observer.ECR_DIRECTORY]['ino'] = before['persistent']['app-data']['ino']
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, alias, identities=True, ecr_initialization=True)
        for filename in (observer.ECR_DIRECTORY + '/unexpected', 'app-data/ecr-artifacts-other'):
            changed = deepcopy(after)
            changed['persistent'][filename] = deepcopy(after['persistent']['app-data/master.key'])
            with self.subTest(filename=filename), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, changed, identities=True, ecr_initialization=True)
        changed = deepcopy(after)
        changed['persistent']['app-data/master.key']['sha256'] = '0' * 64
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, changed, identities=True, ecr_initialization=True)

    def test_private_copy_comparison_joins_directory_and_actual_sqlite_initialization(self):
        before = self.receipt()
        before_root, before_custody = self.root / 'before', self.root / 'before-custody'
        after_root, after_custody = self.root / 'after', self.root / 'after-custody'
        shutil.copytree(self.persistent, before_root)
        shutil.copytree(self.custody, before_custody)
        with sqlite3.connect(self.database) as connection:
            initialize_ecr(connection)
        (self.persistent / observer.ECR_DIRECTORY).mkdir(mode=0o700)
        after = self.receipt()
        shutil.copytree(self.persistent, after_root)
        shutil.copytree(self.custody, after_custody)
        result = observer.compare(before_root, after_root, before_custody, after_custody,
            before, after, ecr_initialization=True)
        self.assertEqual(result['schema'], 'catchplate.operatorRolloutComparison/v5')
        self.assertEqual(result['ecr_artifact_directory_added'], observer.ECR_DIRECTORY)
        self.assertTrue(result['non_sqlite_files_and_custody_preserved'])
        self.assertEqual(result['prior_audit_count'], result['current_audit_count'])
        self.assertFalse(result['live_sqlite_opened'])
        self.assertEqual(self.receipt(), after)

    def test_cli_flag_is_explicit_and_cannot_apply_to_inventory(self):
        arguments = ['operator_rollout_snapshot.py', 'compare', '--private-copies-acknowledged', '--ecr-initialization']
        for name in ('before-root', 'after-root', 'before-custody', 'after-custody', 'before-inventory', 'after-inventory'):
            arguments.extend(['--' + name, str(self.root / name)])
        with patch.object(observer.sys, 'argv', arguments), patch.object(observer.signal, 'alarm'), \
                patch.object(observer.os, 'umask'), patch.object(observer, 'load_receipt', return_value={}), \
                patch.object(observer, 'compare', return_value={'ok': True}) as comparison, redirect_stdout(io.StringIO()):
            observer.main()
        self.assertIs(comparison.call_args.kwargs['ecr_initialization'], True)
        with patch.object(observer.sys, 'argv', ['operator_rollout_snapshot.py', 'inventory', '--ecr-initialization']), \
                redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            observer.main()


class ManagedTransitionTests(unittest.TestCase):
    """Synthetic stopped-copy observations, not managed startup acceptance."""

    put = FileTests.put

    def setUp(self):
        FileTests.setUp(self)
        self.provider = self.root / 'provider-custody'
        self.provider.mkdir(mode=0o700)
        self.settings = {'allowed_upstreams': ['https://demo-upstream:8443', 'https://api.github.com'],
            'fixture_cidrs': ['127.0.0.1/32']}
        self.policy = b'{"synthetic":"retained signed bytes"}'
        with sqlite3.connect(self.database) as connection:
            connection.execute('CREATE TABLE operator_demo_settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1), settings_json TEXT NOT NULL)')
            connection.execute('INSERT INTO operator_demo_settings VALUES(1,?)', (json.dumps(self.settings, sort_keys=True),))
            connection.execute('CREATE TABLE operator_demo_policy (singleton INTEGER PRIMARY KEY CHECK(singleton=1), signed_bundle_json TEXT NOT NULL)')
            connection.execute('INSERT INTO operator_demo_policy VALUES(1,?)', (self.policy.decode(),))
            connection.execute('CREATE TABLE operator_catalog_credentials (id TEXT PRIMARY KEY, data_json TEXT NOT NULL)')
            connection.execute('INSERT INTO operator_catalog_credentials VALUES(?,?)', ('synthetic', '{"auth_type":"bearer"}'))
            connection.execute('CREATE TABLE proxy_token_verifiers (id TEXT PRIMARY KEY, verifier BLOB, expires_at BIGINT)')
            connection.execute("INSERT INTO proxy_token_verifiers VALUES('retained',X'070809',123456789)")
        self.put(self.persistent / observer.POLICY, self.policy)
        for name, raw in (('.operator-publication.lock', b''), ('.catchplate-operator-demo.json', b'synthetic marker'),
                ('policy-high-water.json', b'synthetic high water'), ('mitmproxy-ca-original.pem', b'synthetic original CA')):
            self.put(self.persistent / 'app-data' / name, raw)
        self.serial = 0

    def receipt(self):
        return observer.inventory(self.persistent, self.custody,
            managed_unconfigured=True, provider_custody_root=self.provider)

    def public(self):
        return {'schema': 'catchplate.operatorGoogleGateConfiguration/v1', 'operation': None,
            'profile_binding': None, 'profile_binding_digest': None, 'effective_settings': self.settings,
            'effective_settings_digest': 'sha256:' + observer.digest(self.settings)}

    def publish(self):
        for name in sorted(observer.GATE_DIRECTORIES):
            (self.persistent / name).mkdir(mode=0o700)
        self.put(self.persistent / observer.GATE_POLICY, self.policy)
        self.put(self.persistent / observer.GATE_GOOGLE, observer.canonical(self.public()).encode())
        for name in observer.GATE_PLACEHOLDERS:
            self.put(self.persistent / name, b'')
            (self.persistent / name).chmod(0)

    def copies(self):
        self.serial += 1
        destinations = tuple(self.root / (str(self.serial) + '-' + name) for name in ('data', 'notifications', 'provider'))

        def copy_file(source, target):
            relative = str(Path(source).relative_to(self.persistent))
            if relative in observer.GATE_PLACEHOLDERS:
                self.assertEqual(Path(source).stat().st_size, 0)
                Path(target).write_bytes(b'')
                Path(target).chmod(0)
                return target
            return shutil.copy2(source, target)

        shutil.copytree(self.persistent, destinations[0], copy_function=copy_file)
        shutil.copytree(self.custody, destinations[1])
        shutil.copytree(self.provider, destinations[2])
        return destinations

    def compare(self, before, old_copies, *, phase='first'):
        after, new_copies = self.receipt(), self.copies()
        result = observer.compare(old_copies[0], new_copies[0], old_copies[1], new_copies[1], before, after,
            managed_transition=phase, before_provider_custody=old_copies[2], after_provider_custody=new_copies[2])
        self.assertEqual(self.receipt(), after)
        return result

    def first(self):
        before, copies = self.receipt(), self.copies()
        self.publish()
        return before, copies

    def test_managed_origin_capacity_preserves_sixteen_and_accepts_thirty_two(self):
        for capacity in (16, 32, 33):
            self.settings['allowed_upstreams'] = ['https://demo-upstream:8443'] + [
                f'https://service-{number}.example.com' for number in range(capacity - 1)]
            with sqlite3.connect(self.database) as connection:
                connection.execute('UPDATE operator_demo_settings SET settings_json=?',
                    (json.dumps(self.settings, sort_keys=True),))
            snapshot = self.receipt()
            with self.subTest(capacity=capacity), sqlite3.connect(self.database) as connection:
                if capacity <= 32:
                    result = observer.managed_database_identity(connection, snapshot)
                    self.assertEqual(result['effective_settings_digest'], 'sha256:' + observer.digest(self.settings))
                else:
                    with self.assertRaises(observer.SnapshotError) as raised:
                        observer.managed_database_identity(connection, snapshot)
                    self.assertEqual(raised.exception.code, 'managed_settings')

    def test_initial_addition_and_same_source_second_restart(self):
        before, copies = self.first()
        with sqlite3.connect(self.database) as connection:
            connection.execute("INSERT INTO audit_events VALUES('after','new startup audit')")
            connection.execute("UPDATE catchplate_store_migrations SET applied_at='2026-01-02T00:00:00+00:00'")
        first = self.compare(before, copies)
        self.assertEqual(first['schema'], 'catchplate.operatorRolloutComparison/v2')
        self.assertEqual(first['derived_gate_files_added'], sorted(observer.GATE_MEMBERS))
        self.assertEqual(first['managed_unconfigured']['effective_settings_digest'], 'sha256:' + observer.digest(self.settings))
        self.assertTrue(first['provider_custody_empty'])
        self.assertTrue(first['provider_custody_live_identity_preserved'])
        self.assertTrue(first['migration_timestamps']['timestamp_only_change'])
        self.assertEqual((first['prior_audit_count'], first['current_audit_count']), (1, 2))
        self.assertIn('proxy_token_verifiers', first['all_non_audit_tables'])
        self.assertEqual(first['notification_tables'], sorted(observer.NOTIFICATIONS))
        self.assertFalse(first['live_sqlite_opened'])
        self.assertFalse(first['services_stopped_verified'])
        retained = self.compare(self.receipt(), self.copies(), phase='retained')
        self.assertEqual(retained['derived_gate_files_added'], [])
        self.assertEqual(retained['managed_unconfigured'], first['managed_unconfigured'])

    def test_opt_in_and_phase_are_required_no_v1_weakening(self):
        old_v1 = observer.inventory(self.persistent, self.custody)
        before, copies = self.first()
        after = self.receipt()
        v1_after = {key: value for key, value in after.items() if key not in {'provider_custody', 'managed_unconfigured'}}
        v1_after['schema'] = observer.SCHEMA
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(old_v1, v1_after, identities=True)
        for left, right, phase in ((before, after, None), (before, after, 'retained'), (after, after, 'first')):
            with self.subTest(phase=phase), self.assertRaises(observer.SnapshotError):
                observer.compare_files(left, right, identities=True, managed_transition=phase)
        with self.assertRaises(observer.SnapshotError):
            observer.inventory(self.persistent, self.custody, provider_custody_root=self.provider)

    def test_closed_gate_inventory_and_permissions(self):
        self.publish()
        after = self.receipt()
        for name in observer.GATE_MEMBERS:
            changed = deepcopy(after)
            changed['persistent'].pop(name)
            with self.subTest(missing=name), self.assertRaises(observer.SnapshotError):
                observer.managed_gate_inventory(changed)
            for field in ('mode', 'uid', 'gid'):
                changed = deepcopy(after)
                changed['persistent'][name][field] += 1
                with self.subTest(name=name, field=field), self.assertRaises(observer.SnapshotError):
                    observer.managed_gate_inventory(changed)
        for name in ('unexpected', '.operator-policy-' + 'a' * 32, 'mitmproxy/extra'):
            changed = deepcopy(after)
            changed['persistent'][observer.GATE_ROOT + '/' + name] = deepcopy(after['persistent'][observer.GATE_POLICY])
            with self.subTest(extra=name), self.assertRaises(observer.SnapshotError):
                observer.managed_gate_inventory(changed)
        placeholder = self.persistent / sorted(observer.GATE_PLACEHOLDERS)[0]
        placeholder.chmod(0o600)
        placeholder.write_bytes(b'not inert')
        placeholder.chmod(0)
        with self.assertRaises(observer.SnapshotError):
            self.receipt()

    def test_zero_mode_mountpoints_are_never_opened_or_chmodded(self):
        self.publish()
        original = os.open

        def guarded(filename, *args, **kwargs):
            self.assertNotIn(str(Path(filename).relative_to(self.persistent)) if Path(filename).is_relative_to(self.persistent) else '',
                observer.GATE_PLACEHOLDERS)
            return original(filename, *args, **kwargs)

        with patch.object(observer.os, 'open', side_effect=guarded), patch.object(observer.os, 'chmod', side_effect=AssertionError('no chmod')):
            self.receipt()
        for name in observer.GATE_PLACEHOLDERS:
            self.assertEqual((self.persistent / name).stat().st_mode & 0o777, 0)

    def test_gate_placeholders_cannot_be_symlinks_or_hardlinks(self):
        self.publish()
        filename = self.persistent / sorted(observer.GATE_PLACEHOLDERS)[0]
        filename.unlink()
        filename.symlink_to(self.persistent / 'app-data/.operator-publication.lock')
        with self.assertRaises(observer.SnapshotError) as raised:
            self.receipt()
        self.assertEqual(raised.exception.code, 'special_file_refused')
        filename.unlink()
        os.link(self.persistent / 'app-data/.operator-publication.lock', filename)
        with self.assertRaises(observer.SnapshotError) as raised:
            self.receipt()
        self.assertEqual(raised.exception.code, 'hardlink_refused')

    def test_public_artifact_must_be_exact_unconfigured_sql_projection(self):
        before, copies = self.first()
        filename = self.persistent / observer.GATE_GOOGLE
        cases = []
        for key, value in (('operation', {'operation_id': 'synthetic'}), ('profile_binding', {}),
                ('profile_binding_digest', 'sha256:' + '1' * 64), ('extra', 'synthetic-secret'),
                ('effective_settings_digest', 'sha256:' + '2' * 64)):
            item = self.public()
            item[key] = value
            cases.append(observer.canonical(item).encode())
        changed = deepcopy(self.public())
        changed['effective_settings']['fixture_cidrs'] = ['127.0.0.2/32']
        changed['effective_settings_digest'] = 'sha256:' + observer.digest(changed['effective_settings'])
        cases += [observer.canonical(changed).encode(), observer.canonical(self.public()).encode() + b'\n',
            observer.canonical(self.public()).encode()[:-1] + b',"operation":null}']
        for index, raw in enumerate(cases):
            self.put(filename, raw)
            with self.subTest(case=index), self.assertRaises(observer.SnapshotError) as raised:
                self.compare(before, copies)
            self.assertEqual(raised.exception.code, 'managed_public_not_authoritative')

    def test_policy_export_and_original_must_join_retained_sql_bytes(self):
        before, copies = self.first()
        self.put(self.persistent / observer.GATE_POLICY, b'changed')
        with self.assertRaises(observer.SnapshotError) as raised:
            self.receipt()
        self.assertEqual(raised.exception.code, 'gate_policy_changed')
        self.put(self.persistent / observer.GATE_POLICY, self.policy)
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE operator_demo_policy SET signed_bundle_json='different retained bytes'")
        current = self.receipt()
        with sqlite3.connect(self.database) as connection, self.assertRaises(observer.SnapshotError) as raised:
            observer.managed_database_identity(connection, current)
        self.assertEqual(raised.exception.code, 'policy_not_authoritative')

    def test_provider_directory_stays_empty_private_disjoint_and_app_owned(self):
        self.put(self.provider / 'provider-key.json', b'synthetic forbidden key')
        with self.assertRaises(observer.SnapshotError):
            self.receipt()
        (self.provider / 'provider-key.json').unlink()
        self.provider.chmod(0o750)
        with self.assertRaises(observer.SnapshotError):
            self.receipt()
        self.provider.chmod(0o700)
        for root in (self.persistent, self.persistent / 'app-data', self.custody):
            with self.subTest(root=root.name), self.assertRaises(observer.SnapshotError):
                observer.inventory(self.persistent, self.custody, managed_unconfigured=True, provider_custody_root=root)
        original = observer.tree
        for field in ('uid', 'gid'):
            def changed_owner(root, **kwargs):
                value = original(root, **kwargs)
                if Path(root) == self.provider:
                    value['.'][field] += 1
                return value
            with self.subTest(field=field), patch.object(observer, 'tree', side_effect=changed_owner), self.assertRaises(observer.SnapshotError):
                self.receipt()
        # Bind-mount alias simulation: path names differ, inode identity does not.
        notification_root = original(self.custody)['.']
        def aliased(root, **kwargs):
            value = original(root, **kwargs)
            if Path(root) == self.provider:
                for key in ('dev', 'ino'):
                    value['.'][key] = notification_root[key]
            return value
        with patch.object(observer, 'tree', side_effect=aliased), self.assertRaises(observer.SnapshotError) as raised:
            self.receipt()
        self.assertEqual(raised.exception.code, 'provider_custody_alias')

    def test_all_original_authority_and_provider_identities_remain_pinned(self):
        before, copies = self.first()
        after = self.receipt()
        names = ('app-data/master.key', 'app-data/.operator-publication.lock', 'app-data/.catchplate-operator-demo.json',
            'app-data/mitmproxy-ca-original.pem', 'app-data/policy-high-water.json', observer.POLICY, observer.DB_MAIN)
        for name in names:
            changed = deepcopy(after)
            changed['persistent'][name]['ino'] += 1
            with self.subTest(name=name), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, changed, identities=True, managed_transition='first')
        changed = deepcopy(after)
        changed['provider_custody']['.']['ino'] += 1
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, changed, identities=True, managed_transition='first')
        # Only the preexisting, separately reported two CA publication copies
        # retain their v1 inode exception; real CA/lock above never do.
        name = 'app-data/decision-gate-ca-cert.pem'
        changed = deepcopy(after)
        changed['persistent'][name]['ino'] += 1
        self.assertEqual(observer.compare_files(before, changed, identities=True, managed_transition='first'), [name])
        for name in observer.GATE_MEMBERS:
            changed = deepcopy(after)
            changed['persistent'][name]['ino'] += 1
            with self.subTest(retained=name), self.assertRaises(observer.SnapshotError):
                observer.compare_files(after, changed, identities=True, managed_transition='retained')

    def test_no_arbitrary_added_private_file_or_directory_is_ignored(self):
        before, copies = self.first()
        for name in ('app-data/new-private', 'app-data/gate-runtime-other'):
            (self.persistent / name).mkdir()
            with self.subTest(name=name), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, self.receipt(), identities=True, managed_transition='first')
            (self.persistent / name).rmdir()

    def test_retained_schema_rows_expiry_verifier_and_audit_are_strict(self):
        before, copies = self.first()
        with sqlite3.connect(self.database) as connection:
            original = connection.execute('SELECT verifier,expires_at FROM proxy_token_verifiers').fetchone()
        for column, value in (('verifier', b'changed'), ('expires_at', 123456790)):
            with sqlite3.connect(self.database) as connection:
                connection.execute('UPDATE proxy_token_verifiers SET ' + column + '=?', (value,))
            with self.subTest(column=column), self.assertRaises(observer.SnapshotError) as raised:
                self.compare(before, copies)
            self.assertEqual((raised.exception.code, raised.exception.table), ('authority_table_changed', 'proxy_token_verifiers'))
            with sqlite3.connect(self.database) as connection:
                connection.execute('UPDATE proxy_token_verifiers SET verifier=?,expires_at=?', original)
        with sqlite3.connect(self.database) as connection:
            connection.execute('CREATE TABLE new_notification_schema(id TEXT)')
        with self.assertRaises(observer.SnapshotError) as raised:
            self.compare(before, copies)
        self.assertEqual(raised.exception.code, 'database_schema_changed')
        with sqlite3.connect(self.database) as connection:
            connection.execute('DROP TABLE new_notification_schema')
            connection.execute("UPDATE audit_events SET value='changed prefix'")
        with self.assertRaises(observer.SnapshotError) as raised:
            self.compare(before, copies)
        self.assertEqual(raised.exception.code, 'audit_prefix_changed')

    def test_existing_managed_history_or_google_credential_refuses_unconfigured_claim(self):
        self.publish()
        for name in ('operator_google_setups', 'operator_google_managed_selection', 'operator_provider_custody', 'operator_catalog_oauth_profile'):
            with sqlite3.connect(self.database) as connection:
                connection.execute('CREATE TABLE ' + name + '(id TEXT)')
                with self.subTest(name=name), self.assertRaises(observer.SnapshotError) as raised:
                    observer.managed_database_identity(connection, self.receipt())
                self.assertEqual(raised.exception.code, 'managed_state_present')
                connection.execute('DROP TABLE ' + name)
        with sqlite3.connect(self.database) as connection:
            connection.execute('UPDATE operator_catalog_credentials SET data_json=?', ('{"auth_type":"google_oauth"}',))
            with self.assertRaises(observer.SnapshotError) as raised:
                observer.managed_database_identity(connection, self.receipt())
            self.assertEqual(raised.exception.code, 'managed_state_present')

    def test_private_copies_and_receipt_schema_cannot_be_mixed(self):
        before, copies = self.first()
        filename = self.root / 'receipt.json'
        self.put(filename, json.dumps(before).encode())
        self.assertEqual(observer.load_receipt(filename, managed_unconfigured=True), before)
        with self.assertRaises(observer.SnapshotError):
            observer.load_receipt(filename)
        self.persistent.chmod(0o750)
        with self.assertRaises(observer.SnapshotError) as raised:
            self.receipt()
        self.assertEqual(raised.exception.code, 'private_copies_required')

    def test_cli_requires_source_acknowledgement_before_managed_inventory(self):
        argv = ['operator_rollout_snapshot.py', 'inventory', '--managed-unconfigured',
            '--persistent-root', str(self.persistent), '--custody-root', str(self.custody),
            '--provider-custody-root', str(self.provider)]
        with patch.object(observer.sys, 'argv', argv), patch.object(observer.signal, 'alarm'), \
                patch.object(observer.os, 'umask'), patch.object(observer, 'inventory', side_effect=AssertionError('no capture')):
            with self.assertRaises(observer.SnapshotError) as raised:
                observer.main()
        self.assertEqual(raised.exception.code, 'private_copies_required')

    def test_cli_inventory_acknowledgements_are_mutually_exclusive(self):
        argv = ['operator_rollout_snapshot.py', 'inventory', '--managed-unconfigured',
            '--persistent-root', str(self.persistent), '--custody-root', str(self.custody),
            '--provider-custody-root', str(self.provider), '--private-copies-acknowledged',
            '--stopped-files-acknowledged']
        with patch.object(observer.sys, 'argv', argv), redirect_stderr(io.StringIO()), \
                patch.object(observer, 'inventory', side_effect=AssertionError('no capture')), \
                patch.object(observer.sqlite3, 'connect', side_effect=AssertionError('no SQLite open')):
            with self.assertRaises(SystemExit) as raised:
                observer.main()
        self.assertEqual(raised.exception.code, 2)

    def test_cli_acknowledged_inventory_preserves_original_identities_without_sqlite_open(self):
        expected = self.receipt()
        argv = ['operator_rollout_snapshot.py', 'inventory', '--managed-unconfigured',
            '--persistent-root', str(self.persistent), '--custody-root', str(self.custody),
            '--provider-custody-root', str(self.provider)]
        for acknowledgement in ('--private-copies-acknowledged', '--stopped-files-acknowledged'):
            output = io.StringIO()
            with self.subTest(acknowledgement=acknowledgement), \
                    patch.object(observer.sys, 'argv', argv + [acknowledgement]), \
                    patch.object(observer.signal, 'alarm'), patch.object(observer.os, 'umask'), \
                    patch.object(observer.sqlite3, 'connect', side_effect=AssertionError('no SQLite open')), \
                    redirect_stdout(output):
                observer.main()
            actual = json.loads(output.getvalue())
            self.assertEqual(actual, expected)
            self.assertEqual(actual['persistent'][observer.DB_MAIN]['ino'], self.database.stat().st_ino)
            self.assertEqual(actual['provider_custody']['.']['ino'], self.provider.stat().st_ino)
            self.assertFalse(actual['live_sqlite_opened'])
            self.assertNotIn('services_stopped_verified', actual)

    def test_cli_stopped_files_acknowledgement_never_authorizes_comparison(self):
        argv = ['operator_rollout_snapshot.py', 'compare']
        for name in ('before-root', 'after-root', 'before-custody', 'after-custody',
                'before-inventory', 'after-inventory'):
            argv += ['--' + name, str(self.root / name)]
        for acknowledgements in (['--stopped-files-acknowledged'],
                ['--private-copies-acknowledged', '--stopped-files-acknowledged']):
            with self.subTest(acknowledgements=acknowledgements), \
                    patch.object(observer.sys, 'argv', argv + acknowledgements), redirect_stderr(io.StringIO()), \
                    patch.object(observer, 'compare', side_effect=AssertionError('no comparison')), \
                    patch.object(observer.sqlite3, 'connect', side_effect=AssertionError('no SQLite open')):
                with self.assertRaises(SystemExit) as raised:
                    observer.main()
            self.assertEqual(raised.exception.code, 2)


class ManagedXTransitionTests(unittest.TestCase):
    """Explicit first-X/retained-X copied-state profile, not startup proof."""

    put = FileTests.put
    public = ManagedTransitionTests.public

    def setUp(self):
        ManagedTransitionTests.setUp(self)
        ManagedTransitionTests.publish(self)
        self.x_custody = self.root / 'x-custody'
        self.x_custody.mkdir(mode=0o700)
        with sqlite3.connect(self.database) as connection:
            connection.execute("ALTER TABLE audit_events ADD COLUMN event_type TEXT NOT NULL DEFAULT 'synthetic.retained'")
            connection.execute("ALTER TABLE credentials ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")

    def receipt(self):
        return observer.inventory(self.persistent, self.custody, managed_unconfigured=True,
            provider_custody_root=self.provider, managed_x_unconfigured=True, x_custody_root=self.x_custody)

    def x_public(self):
        return {**self.public(), 'schema': 'catchplate.operatorXGateConfiguration/v1'}

    def publish_x(self, raw=None):
        self.put(self.persistent / observer.GATE_X,
            observer.canonical(self.x_public()).encode() if raw is None else raw)

    def copies(self):
        prior = ManagedTransitionTests.copies(self)
        target = self.root / (str(self.serial) + '-x-custody')
        shutil.copytree(self.x_custody, target)
        return (*prior, target)

    def compare(self, before, old_copies, *, phase='first'):
        after, new_copies = self.receipt(), self.copies()
        result = observer.compare(old_copies[0], new_copies[0], old_copies[1], new_copies[1], before, after,
            managed_transition=phase, before_provider_custody=old_copies[2], after_provider_custody=new_copies[2],
            managed_x_unconfigured=True, before_x_custody=old_copies[3], after_x_custody=new_copies[3])
        self.assertEqual(self.receipt(), after)
        return result

    def test_first_x_adds_only_one_manifest_and_retained_restart_adds_nothing(self):
        before, copies = self.receipt(), self.copies()
        self.assertEqual(before['schema'], 'catchplate.operatorRolloutInventory/v3')
        self.assertEqual(observer.gate_members(before), observer.GATE_MEMBERS)
        self.publish_x()
        result = self.compare(before, copies)
        self.assertEqual(result['schema'], 'catchplate.operatorRolloutComparison/v3')
        self.assertEqual(result['derived_gate_files_added'], [observer.GATE_X])
        self.assertTrue(result['managed_x_unconfigured'] and result['x_custody_empty']
            and result['x_custody_live_identity_preserved'])
        self.assertEqual(result['managed_unconfigured']['x_public_sha256'],
            observer.hashlib.sha256(observer.canonical(self.x_public()).encode()).hexdigest())
        self.assertEqual(result['prior_audit_count'], result['current_audit_count'])
        self.assertFalse(result['live_sqlite_opened'] or result['services_stopped_verified'])
        self.assertEqual(result['notification_tables'], sorted(observer.NOTIFICATIONS))
        retained = self.compare(self.receipt(), self.copies(), phase='retained')
        self.assertEqual(retained['derived_gate_files_added'], [])
        self.assertEqual(retained['managed_unconfigured'], result['managed_unconfigured'])
        for left, right, phase in ((before, before, 'first'), (before, self.receipt(), 'retained'),
                (self.receipt(), self.receipt(), 'first')):
            with self.subTest(phase=phase), self.assertRaises(observer.SnapshotError):
                observer.compare_files(left, right, identities=True, managed_transition=phase, managed_x_unconfigured=True)

    def test_x_profile_is_explicit_and_does_not_widen_legacy_schema_or_gate_roster(self):
        before = self.receipt()
        filename = self.root / 'x-receipt.json'
        self.put(filename, observer.canonical(before).encode())
        self.assertEqual(observer.load_receipt(filename, managed_unconfigured=True, managed_x_unconfigured=True), before)
        for options in ({}, {'managed_unconfigured': True}, {'managed_x_unconfigured': True}):
            with self.subTest(options=options), self.assertRaises(observer.SnapshotError):
                observer.load_receipt(filename, **options)
        for options in ({'managed_x_unconfigured': True, 'x_custody_root': self.x_custody},
                {'managed_unconfigured': True, 'provider_custody_root': self.provider, 'x_custody_root': self.x_custody},
                {'managed_unconfigured': True, 'provider_custody_root': self.provider, 'managed_x_unconfigured': True}):
            with self.subTest(options=list(options)), self.assertRaises(observer.SnapshotError):
                observer.inventory(self.persistent, self.custody, **options)
        legacy = observer.inventory(self.persistent, self.custody, managed_unconfigured=True, provider_custody_root=self.provider)
        self.assertEqual(legacy['schema'], observer.MANAGED_SCHEMA)
        self.assertNotIn('x_custody', legacy)
        self.publish_x()
        with self.assertRaises(observer.SnapshotError):
            observer.inventory(self.persistent, self.custody, managed_unconfigured=True, provider_custody_root=self.provider)
        with self.assertRaises(observer.SnapshotError):
            observer.compare_files(before, self.receipt(), identities=True, managed_transition='first')

    def test_x_manifest_matches_exact_sql_settings_not_caller_supplied_identity(self):
        before, copies = self.receipt(), self.copies()
        cases = []
        for key, value in (('schema', 'catchplate.operatorGoogleGateConfiguration/v1'), ('operation', {}),
                ('profile_binding', {}), ('profile_binding_digest', 'sha256:' + '1' * 64),
                ('effective_settings_digest', 'sha256:' + '2' * 64), ('extra', 'synthetic-forbidden')):
            changed = self.x_public(); changed[key] = value
            cases.append(observer.canonical(changed).encode())
        changed = deepcopy(self.x_public())
        changed['effective_settings']['allowed_upstreams'].append('https://api.x.com')
        changed['effective_settings_digest'] = 'sha256:' + observer.digest(changed['effective_settings'])
        valid = observer.canonical(self.x_public()).encode()
        cases.extend((observer.canonical(changed).encode(), valid + b'\n', valid[:-1] + b',"operation":null}'))
        for index, raw in enumerate(cases):
            self.publish_x(raw)
            with self.subTest(case=index), self.assertRaises(observer.SnapshotError) as raised:
                self.compare(before, copies)
            self.assertEqual(raised.exception.code, 'managed_x_public_not_authoritative')

    def test_x_custody_is_empty_owned_disjoint_and_identity_pinned(self):
        before, copies = self.receipt(), self.copies()
        self.publish_x()
        self.put(self.x_custody / 'provider-key.json', b'synthetic forbidden key')
        with self.assertRaises(observer.SnapshotError): self.receipt()
        (self.x_custody / 'provider-key.json').unlink()
        self.x_custody.chmod(0o750)
        with self.assertRaises(observer.SnapshotError): self.receipt()
        self.x_custody.chmod(0o700)
        for other in (self.persistent, self.persistent / 'app-data', self.custody, self.provider):
            with self.subTest(overlap=other.name), self.assertRaises(observer.SnapshotError):
                observer.inventory(self.persistent, self.custody, managed_unconfigured=True,
                    provider_custody_root=self.provider, managed_x_unconfigured=True, x_custody_root=other)
        original = observer.tree
        for field in ('uid', 'gid'):
            def changed_owner(root, **kwargs):
                value = original(root, **kwargs)
                if Path(root) == self.x_custody: value['.'][field] += 1
                return value
            with self.subTest(owner=field), patch.object(observer, 'tree', side_effect=changed_owner), \
                    self.assertRaises(observer.SnapshotError): self.receipt()
        google = original(self.provider)['.']
        def alias(root, **kwargs):
            value = original(root, **kwargs)
            if Path(root) == self.x_custody:
                value['.'].update(dev=google['dev'], ino=google['ino'])
            return value
        with patch.object(observer, 'tree', side_effect=alias), self.assertRaises(observer.SnapshotError): self.receipt()
        after = self.receipt()
        for namespace in ('custody', 'provider_custody', 'x_custody'):
            changed = deepcopy(after); changed[namespace]['.']['ino'] += 1
            with self.subTest(namespace=namespace), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, changed, identities=True, managed_transition='first', managed_x_unconfigured=True)

    def test_x_history_objects_audit_and_reserved_markers_are_not_first_configuration(self):
        self.publish_x()
        def check(connection):
            return observer.managed_database_identity(connection, self.receipt(), managed_x_unconfigured=True)
        with sqlite3.connect(self.database) as connection:
            for name in ('operator_x_configuration', 'operator_x_provider_custody', 'operator_x_account_intents',
                    'operator_x_account_work', 'operator_x_account_captures', 'OPERATOR_X_CONFIGURATION_shadow'):
                connection.execute('CREATE TABLE ' + name + '(id TEXT)')
                with self.subTest(table=name), self.assertRaises(observer.SnapshotError): check(connection)
                connection.execute('DROP TABLE ' + name)
            for identifier, kind in (('extra', 'operator_catalog.x_oauth.configuration_saved'),
                    ('extra', 'operator_catalog.x_oauth.consent_started'), ('operator-x-configuration:orphan', 'other')):
                connection.execute('INSERT INTO audit_events(id,event_type) VALUES(?,?)', (identifier, kind))
                with self.subTest(audit=kind), self.assertRaises(observer.SnapshotError): check(connection)
                connection.execute('DELETE FROM audit_events WHERE id=?', (identifier,))
            for table, column, original in (('credentials', 'metadata', '{}'),
                    ('operator_catalog_credentials', 'data_json', '{"auth_type":"bearer"}')):
                for value in ({'auth_type': 'x_oauth'}, {'connection_type': 'x_user_oauth_v1'}, {'operator_x_account': None}):
                    connection.execute('UPDATE ' + table + ' SET ' + column + '=?', (json.dumps(value),))
                    with self.subTest(table=table, marker=list(value)), self.assertRaises(observer.SnapshotError): check(connection)
                connection.execute('UPDATE ' + table + ' SET ' + column + '=?', (original,))
            # Static X bearer credentials are not managed-X account history.
            connection.execute('UPDATE credentials SET metadata=?', ('{"provider_id":"x","connection_type":"x_api_token_v1"}',))
            self.assertIn('x_public_sha256', check(connection))

    def test_x_profile_retains_exact_existing_files_rows_and_closed_gate_objects(self):
        before, copies = self.receipt(), self.copies()
        self.publish_x(); after = self.receipt()
        for name in observer.GATE_MEMBERS:
            changed = deepcopy(after); changed['persistent'][name]['ino'] += 1
            with self.subTest(retained=name), self.assertRaises(observer.SnapshotError):
                observer.compare_files(before, changed, identities=True, managed_transition='first', managed_x_unconfigured=True)
        for field in ('mode', 'uid', 'gid'):
            changed = deepcopy(after); changed['persistent'][observer.GATE_X][field] += 1
            with self.subTest(x_field=field), self.assertRaises(observer.SnapshotError):
                observer.managed_gate_inventory(changed, managed_x_unconfigured=True)
        for name in (observer.GATE_X, observer.GATE_GOOGLE, observer.GATE_ROOT):
            changed = deepcopy(after); changed['persistent'].pop(name)
            if name == observer.GATE_X:
                with self.assertRaises(observer.SnapshotError):
                    observer.compare_files(before, changed, identities=True, managed_transition='first', managed_x_unconfigured=True)
            else:
                with self.assertRaises(observer.SnapshotError):
                    observer.managed_gate_inventory(changed, managed_x_unconfigured=True)
        extra = self.persistent / 'app-data/extra-private'; self.put(extra, b'forbidden')
        with self.assertRaises(observer.SnapshotError): self.compare(before, copies)
        extra.unlink()
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE proxy_token_verifiers SET expires_at=123456790")
        with self.assertRaises(observer.SnapshotError) as raised: self.compare(before, copies)
        self.assertEqual((raised.exception.code, raised.exception.table), ('authority_table_changed', 'proxy_token_verifiers'))

    def test_x_cli_requires_explicit_base_profile_and_never_opens_inventory_sqlite(self):
        argv = ['operator_rollout_snapshot.py', 'inventory', '--managed-unconfigured', '--managed-x-unconfigured',
            '--persistent-root', str(self.persistent), '--custody-root', str(self.custody),
            '--provider-custody-root', str(self.provider), '--x-custody-root', str(self.x_custody),
            '--private-copies-acknowledged']
        expected = self.receipt(); output = io.StringIO()
        with patch.object(observer.sys, 'argv', argv), patch.object(observer.signal, 'alarm'), \
                patch.object(observer.os, 'umask'), redirect_stdout(output), \
                patch.object(observer.sqlite3, 'connect', side_effect=AssertionError('inventory opened SQLite')):
            observer.main()
        self.assertEqual(json.loads(output.getvalue()), expected)
        with patch.object(observer.sys, 'argv', [part for part in argv if part != '--managed-unconfigured']), \
                patch.object(observer.signal, 'alarm'), patch.object(observer.os, 'umask'), \
                self.assertRaises(observer.SnapshotError): observer.main()


if __name__ == '__main__':
    unittest.main(verbosity=2)
