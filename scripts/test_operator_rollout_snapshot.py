#!/usr/bin/env python3
"""Synthetic SQLite/tempfile observer tests; never reads runtime data."""
from copy import deepcopy
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
