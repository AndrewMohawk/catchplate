#!/usr/bin/env python3
"""Synthetic, stdlib-only quota rollout observations; no app initialization.

The real storage CREATE statements are extracted, never its runtime imports or
initializer. Audit fixtures independently encode the reviewed SQLite producer.
These tests prove the observer's bounds, not a stopped or deployed service.
"""
import ast
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import operator_rollout_snapshot as observer
import operator_rollout_x_quota as quota
import test_operator_rollout_snapshot as previous

SOURCE = Path(__file__).resolve().parents[1] / 'serverware/operator_x_quota.py'
NOW = 1_800_000_000_000
MARKER = '22222222-2222-4222-8222-222222222222'
PRIOR = '11111111-1111-4111-8111-111111111111'
SCHEMA = 'serverware.operatorXPostingQuotaStore/v1'


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def actual_ddl():
    """Only the fixed CREATE construction block, with independent constants."""
    tree = ast.parse(SOURCE.read_text())
    start = next(i for i, node in enumerate(tree.body) if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == '_DDL')
    end = next(i for i, node in enumerate(tree.body) if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id == '_AUTO_INDEXES')
    block = tree.body[start:end]
    assert all(isinstance(node, (ast.Assign, ast.For)) for node in block)
    namespace = dict(PREFIX='operator_x_quota_', STATE='operator_x_quota_state',
        ACCOUNTS='operator_x_quota_accounts', BUCKETS='operator_x_quota_buckets',
        ATTEMPTS='operator_x_quota_attempts', MAX_INTEGER=9007199254740991,
        MAX_OUTSTANDING=1024, MAX_TTL_MS=5000)
    exec(compile(ast.Module(body=block, type_ignores=[]), str(SOURCE), 'exec'), namespace)
    return namespace['_DDL']


def audit(conn, *, identifier=MARKER, event_type='operator_x.quota.initialized',
        actor_type='system', actor_id='startup', body=None, **overrides):
    previous_hash = conn.execute('SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1').fetchone()
    row = dict(id=identifier, event_type=event_type, actor_type=actor_type, actor_id=actor_id,
        event_json=compact(body if body is not None else dict(schema=SCHEMA, initialized_at_epoch_ms=NOW)),
        prev_event_hash=previous_hash[0] if previous_hash else None,
        created_at='2027-01-15T08:00:00+00:00')
    row.update({key: value for key, value in overrides.items() if key in row})
    hashed = 'sha256:' + hashlib.sha256(compact(row).encode('utf-8')).hexdigest()
    row.update(encrypted_canonical_event_json=None, storage_format_version=2, event_hash=hashed)
    row.update(overrides)
    conn.execute('INSERT INTO audit_events (' + ','.join(row) + ') VALUES ('
        + ','.join('?' for _ in row) + ')', tuple(row.values()))
    return row


def audit_schema(conn):
    conn.execute('DROP TABLE audit_events')
    conn.execute('''CREATE TABLE audit_events (
        id TEXT PRIMARY KEY, event_type TEXT NOT NULL, actor_type TEXT NOT NULL,
        actor_id TEXT, event_json TEXT NOT NULL, encrypted_canonical_event_json TEXT,
        storage_format_version INTEGER NOT NULL DEFAULT 1, prev_event_hash TEXT,
        event_hash TEXT NOT NULL, created_at TEXT NOT NULL)''')
    audit(conn, identifier=PRIOR, event_type='synthetic.retained', body={'retained': True})
    conn.execute('CREATE TABLE audit_witness (id TEXT PRIMARY KEY,value BLOB)')
    conn.execute("INSERT INTO audit_witness VALUES('head',X'090807')")


def install_fixture(conn, *, marker=True, state=True, marker_options=None, state_options=None):
    for statement in actual_ddl().values():
        conn.execute(statement)
    row = audit(conn, **(marker_options or {})) if marker else dict(id=MARKER, event_hash='sha256:' + '0' * 64)
    if state:
        values = dict(singleton=1, schema_version=1, initialization_id=row['id'],
            initialization_hash=row['event_hash'], initialized_at_epoch_ms=NOW, wall_highwater_ms=NOW)
        values.update(state_options or {})
        conn.execute('INSERT INTO operator_x_quota_state VALUES(?,?,?,?,?,?)', tuple(values.values()))
    conn.commit()


class DatabaseTests(unittest.TestCase):
    def pair(self, *, retained=False, **install):
        result = [sqlite3.connect(':memory:') for _ in range(2)]
        for conn in result:
            self.addCleanup(conn.close)
            previous.populate(conn)
            audit_schema(conn)
            conn.commit()
        if retained:
            install_fixture(result[0])
        install_fixture(result[1], **install)
        return result

    def refused(self, pair, *, phase='first', code=None):
        for conn in pair:
            conn.commit()
        with self.assertRaises(observer.SnapshotError) as raised:
            observer.compare_databases(*pair, x_quota_transition=phase)
        if code:
            self.assertEqual(raised.exception.code, code)

    def test_actual_complete_schema_and_first_additive_report(self):
        before, after = self.pair()
        rows = after.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
        selected = [row for row in rows if row[1] in quota.OBJECTS]
        self.assertEqual(len(actual_ddl()), 14)
        self.assertEqual(len(selected), 19)
        self.assertEqual(hashlib.sha256(compact(selected).encode()).hexdigest(), quota.SCHEMA_SHA256)
        result = observer.compare_databases(before, after, x_quota_transition='first')
        self.assertFalse(result['database_schema_equal'])
        self.assertTrue(result['preexisting_schema_preserved'])
        self.assertEqual(result['schema_object_count'] - result['prior_schema_object_count'], 19)
        self.assertEqual((result['prior_audit_count'], result['current_audit_count']), (1, 2))
        report = result['x_quota_initialization']
        self.assertEqual(report['added_schema_objects'], sorted(quota.OBJECTS))
        self.assertEqual(report['empty_usage_tables'], sorted(quota.USAGE_TABLES))
        self.assertEqual(report['initialization_event_id'], MARKER)
        self.assertTrue(report['audit_chain_extension_verified'])
        self.assertEqual(result['all_non_audit_tables']['operator_x_quota_state']['count'], 1)
        self.assertEqual(before.execute('PRAGMA query_only').fetchone(), (1,))

    def test_default_stays_strict_and_retained_is_exact(self):
        self.refused(self.pair(), phase=None, code='database_schema_changed')
        pair = self.pair(retained=True)
        result = observer.compare_databases(*pair, x_quota_transition='retained')
        self.assertTrue(result['database_schema_equal'])
        self.assertEqual(result['x_quota_initialization']['added_schema_objects'], [])
        self.assertEqual(result['x_quota_initialization']['audit_append_count'], 0)
        self.refused(self.pair(retained=True), code='x_quota_not_fresh')

    def test_every_index_trigger_and_unrelated_object_are_closed(self):
        for statement in ('DROP INDEX operator_x_quota_expiry',
                'DROP TRIGGER operator_x_quota_attempts_update',
                'CREATE VIEW operator_x_quota_surprise AS SELECT 1',
                'CREATE VIEW unrelated_addition AS SELECT 1'):
            with self.subTest(statement=statement):
                pair = self.pair()
                pair[1].execute(statement)
                self.refused(pair)
        pair = self.pair(retained=True)
        for conn in pair:
            conn.execute('CREATE VIEW operator_x_quota_surprise AS SELECT 1')
        self.refused(pair, phase='retained', code='x_quota_schema')

    def test_missing_state_marker_and_state_binding_refused(self):
        for options in ({'state': False}, {'marker': False},
                {'state_options': {'initialization_hash': 'sha256:' + 'f' * 64}},
                {'state_options': {'wall_highwater_ms': NOW + 1}}):
            with self.subTest(options=options):
                self.refused(self.pair(**options))

    def test_exact_producer_actor_body_encoding_and_hash_refused(self):
        for options in ({'actor_type': 'data_plane'}, {'actor_id': 'other'},
                {'event_hash': 'sha256:' + 'e' * 64},
                {'body': {'schema': SCHEMA, 'initialized_at_epoch_ms': NOW, 'extra': True}},
                {'event_json': json.dumps(dict(schema=SCHEMA, initialized_at_epoch_ms=NOW))},
                {'storage_format_version': 1}, {'encrypted_canonical_event_json': 'unexpected'},
                {'created_at': '2027-01-15T08:00:00Z'}):
            with self.subTest(options=options):
                self.refused(self.pair(marker_options=options))

    def test_exact_chain_prefix_and_only_one_new_marker(self):
        self.refused(self.pair(marker_options={'prev_event_hash': 'sha256:' + 'c' * 64}),
            code='x_quota_audit_chain')
        for kind in ('additional', 'duplicate', 'prefix', 'rowid'):
            with self.subTest(kind=kind):
                pair = self.pair()
                if kind in ('additional', 'duplicate'):
                    audit(pair[1], identifier='33333333-3333-4333-8333-333333333333',
                        event_type='synthetic.extra' if kind == 'additional' else quota.EVENT)
                elif kind == 'prefix':
                    pair[1].execute("UPDATE audit_events SET actor_id='changed' WHERE id=?", (PRIOR,))
                else:
                    pair[1].execute('UPDATE audit_events SET rowid=99 WHERE id=?', (PRIOR,))
                self.refused(pair)

    def test_each_usage_table_must_be_empty(self):
        statements = (
            "INSERT INTO operator_x_quota_accounts VALUES('123',1,1)",
            "INSERT INTO operator_x_quota_buckets VALUES('bucket','123',1,0,0)",
            "INSERT INTO operator_x_quota_attempts VALUES('reservation','nonce','bucket','123',1,'{}',"
            "'digest','reserved',1,2,NULL)")
        for statement in statements:
            with self.subTest(statement=statement):
                pair = self.pair()
                pair[1].execute(statement)
                self.refused(pair, code='x_quota_usage_not_empty')

    def test_all_old_authority_and_notifications_still_compared(self):
        for table in sorted(observer.NOTIFICATIONS | {'credentials', 'audit_witness'}):
            with self.subTest(table=table):
                pair = self.pair()
                pair[1].execute('UPDATE "' + table + '" SET value=?', (b'changed',))
                self.refused(pair, code='authority_table_changed')

    def test_retained_state_and_audit_cannot_advance(self):
        pair = self.pair(retained=True)
        pair[1].execute('UPDATE operator_x_quota_state SET wall_highwater_ms=wall_highwater_ms+1')
        self.refused(pair, phase='retained', code='authority_table_changed')
        pair = self.pair(retained=True)
        audit(pair[1], identifier='33333333-3333-4333-8333-333333333333', event_type='synthetic.extra')
        self.refused(pair, phase='retained', code='x_quota_audit_delta')

    def test_existing_migration_stamp_exception_is_not_expanded(self):
        pair = self.pair()
        pair[1].execute("UPDATE serverware_store_migrations SET applied_at='2026-01-02T00:00:00+00:00'")
        pair[1].commit()
        result = observer.compare_databases(*pair, x_quota_transition='first')
        self.assertTrue(result['migration_timestamps']['timestamp_only_change'])
        pair = self.pair()
        pair[1].execute('UPDATE serverware_store_migrations SET version=2')
        self.refused(pair, code='migration_authority_changed')


class CopyTests(unittest.TestCase):
    put = previous.ManagedXTransitionTests.put
    public = previous.ManagedXTransitionTests.public
    x_public = previous.ManagedXTransitionTests.x_public
    publish_x = previous.ManagedXTransitionTests.publish_x
    receipt = previous.ManagedXTransitionTests.receipt
    copies = previous.ManagedXTransitionTests.copies

    def setUp(self):
        previous.ManagedXTransitionTests.setUp(self)
        self.publish_x()
        with sqlite3.connect(self.database) as conn:
            audit_schema(conn)

    def compare(self, before, old_copies, **options):
        after, new_copies = self.receipt(), self.copies()
        result = observer.compare(old_copies[0], new_copies[0], old_copies[1], new_copies[1], before, after,
            managed_transition='retained', before_provider_custody=old_copies[2],
            after_provider_custody=new_copies[2], managed_x_unconfigured=True,
            before_x_custody=old_copies[3], after_x_custody=new_copies[3], **options)
        self.assertEqual(self.receipt(), after)
        return result

    def test_actual_private_copies_first_and_second_observation(self):
        before, copies = self.receipt(), self.copies()
        with sqlite3.connect(self.database) as conn:
            install_fixture(conn)
        result = self.compare(before, copies, x_quota_transition='first')
        self.assertEqual(result['schema'], 'serverware.operatorRolloutComparison/v4')
        self.assertEqual(result['derived_gate_files_added'], [])
        self.assertTrue(result['non_sqlite_files_and_custody_preserved'])
        self.assertFalse(result['live_sqlite_opened'] or result['services_stopped_verified'])
        retained = self.compare(self.receipt(), self.copies(), x_quota_transition='retained')
        self.assertEqual(retained['x_quota_initialization']['audit_append_count'], 0)
        self.assertTrue(retained['database_schema_equal'])

    def test_opt_in_requires_retained_unconfigured_x_before_any_read(self):
        for options in ({}, {'managed_transition': 'first', 'managed_x_unconfigured': True},
                {'managed_transition': 'retained'}, {'managed_x_unconfigured': True}):
            with self.subTest(options=options), patch.object(observer, 'path', side_effect=AssertionError('read')):
                with self.assertRaises(observer.SnapshotError) as raised:
                    observer.compare(None, None, None, None, None, None, x_quota_transition='first', **options)
                self.assertEqual(raised.exception.code, 'x_quota_options')

    def test_quota_mode_never_excuses_changed_key_or_new_gate_file(self):
        for mode in ('key', 'gate'):
            with self.subTest(mode=mode):
                before, copies = self.receipt(), self.copies()
                target = self.custody / 'notification-key.json' if mode == 'key' else (
                    self.persistent / observer.GATE_ROOT / 'unexpected.json')
                self.put(target, b'synthetic changed bytes')
                with self.assertRaises(observer.SnapshotError):
                    self.compare(before, copies, x_quota_transition='first')


if __name__ == '__main__':
    unittest.main(verbosity=2)
