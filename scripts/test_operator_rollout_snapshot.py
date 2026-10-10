#!/usr/bin/env python3
"""Synthetic SQLite/tempfile observer tests; never reads runtime data."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import operator_rollout_snapshot as observer


def populate(connection, *, without_rowid=True):
    connection.executescript("CREATE TABLE credentials(id TEXT PRIMARY KEY,value BLOB);"
        "INSERT INTO credentials VALUES('one',X'010203');"
        "CREATE TABLE audit_events(id TEXT PRIMARY KEY,value TEXT);"
        "INSERT INTO audit_events VALUES('before','synthetic audit');"
        "CREATE TABLE metadata_audit_outbox(id TEXT PRIMARY KEY);"
        "CREATE TABLE serverware_store_migrations(migration TEXT PRIMARY KEY,version BIGINT,applied_at TEXT);"
        "INSERT INTO serverware_store_migrations VALUES('schema',1,'2026-01-01T00:00:00+00:00');")
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
        after.execute("UPDATE serverware_store_migrations SET applied_at='2026-01-02T00:00:00+00:00'")
        after.commit()
        self.assertTrue(observer.compare_databases(before, after)['migration_timestamps']['timestamp_only_change'])

    def test_migration_version_change_is_not_a_timestamp_exception(self):
        before, after = self.pair()
        after.execute('UPDATE serverware_store_migrations SET version=2')
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
        for name, raw in (('.operator-publication.lock', b''), ('.serverware-operator-demo.json', b'synthetic marker'),
                ('policy-high-water.json', b'synthetic high water'), ('mitmproxy-ca-original.pem', b'synthetic original CA')):
            self.put(self.persistent / 'app-data' / name, raw)
        self.serial = 0

    def receipt(self):
        return observer.inventory(self.persistent, self.custody,
            managed_unconfigured=True, provider_custody_root=self.provider)

    def public(self):
        return {'schema': 'serverware.operatorGoogleGateConfiguration/v1', 'operation': None,
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

    def test_initial_addition_and_same_source_second_restart(self):
        before, copies = self.first()
        with sqlite3.connect(self.database) as connection:
            connection.execute("INSERT INTO audit_events VALUES('after','new startup audit')")
            connection.execute("UPDATE serverware_store_migrations SET applied_at='2026-01-02T00:00:00+00:00'")
        first = self.compare(before, copies)
        self.assertEqual(first['schema'], 'serverware.operatorRolloutComparison/v2')
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
        names = ('app-data/master.key', 'app-data/.operator-publication.lock', 'app-data/.serverware-operator-demo.json',
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

    def test_cli_requires_private_copy_acknowledgement_before_inventory(self):
        argv = ['operator_rollout_snapshot.py', 'inventory', '--managed-unconfigured',
            '--persistent-root', str(self.persistent), '--custody-root', str(self.custody),
            '--provider-custody-root', str(self.provider)]
        with patch.object(observer.sys, 'argv', argv), patch.object(observer.signal, 'alarm'), \
                patch.object(observer.os, 'umask'), patch.object(observer, 'inventory', side_effect=AssertionError('no capture')):
            with self.assertRaises(observer.SnapshotError) as raised:
                observer.main()
        self.assertEqual(raised.exception.code, 'private_copies_required')


if __name__ == '__main__':
    unittest.main(verbosity=2)
