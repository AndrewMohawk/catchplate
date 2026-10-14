#!/usr/bin/env python3
"""Inert controls only: no app imports, databases, containers or captured bytes."""
import ast
import copy
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import operator_source_revision_retained as h
import run_operator_source_revision_retained as worker


def inputs():
    value = {key: 'a' * 64 for key in worker.INPUT_KEYS}
    value.update(schema=worker.INPUT_SCHEMA, candidateCommit=worker.COMMIT,
        normalBinarySha256=h.BINARY_SHA, capturePins={name: 'b' * 64 for name in h.CAPTURE_NAMES})
    return value


def startup_fixture():
    before = {'objects': [['table', 'audit_events']], 'orderedAudit': 'fixed-audit-digest',
        'persistentJournalFormat': 'wal', 'rows': {'audit_events': {'count': 497, 'sha256': 'fixed'},
            'retained': {'count': 1, 'sha256': 'fixed'}, 'serverware_store_migrations': {'sha256': 'old'}}}
    after = copy.deepcopy(before)
    after['rows']['serverware_store_migrations'] = {'sha256': 'new'}
    timestamps = {'policy_candidate_authority': {'rowid': 1, 'applied_at': '2026-10-14T00:00:00+00:00'},
        'other': {'rowid': 2, 'applied_at': '2026-10-13T00:00:00+00:00'}}
    current = copy.deepcopy(timestamps)
    current['policy_candidate_authority']['applied_at'] = '2026-10-14T00:00:02+00:00'
    return [before, after, timestamps, current,
        datetime(2026, 10, 14, 0, 0, 1, tzinfo=timezone.utc),
        datetime(2026, 10, 14, 0, 0, 3, tzinfo=timezone.utc)]


class RetainedSourceControls(unittest.TestCase):
    def test_fixed_inputs_and_roles(self):
        worker.validate_inputs(inputs())
        self.assertEqual(worker.COMMIT, 'cb326c64de920aa3eeca692b6b9b8e411a8a0cd1')
        self.assertEqual(worker.ROLES, ('prepare', 'recover', 'plan', 'apply', 'freeze',
            'startup1', 'observe1', 'startup2', 'observe2', 'result'))
        self.assertEqual(h.PIN_SHA, '72ce5ebdb7f422e881987749310493451f6d19fa397bb39157313bb85b7472e4')

    def test_inputs_reject_unknown_or_missing_keys(self):
        for key in worker.INPUT_KEYS:
            value = inputs()
            del value[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.validate_inputs(value)
        value = inputs()
        value['liveDirectory'] = '/not-admitted'
        with self.assertRaises(ValueError):
            worker.validate_inputs(value)

    def test_inputs_reject_changed_identity_and_capture_roster(self):
        for key in ('schema', 'candidateCommit', 'normalBinarySha256', 'workerSha256'):
            value = inputs()
            value[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                worker.validate_inputs(value)
        value = inputs()
        value['capturePins']['../elsewhere'] = 'a' * 64
        with self.assertRaises(ValueError):
            worker.validate_inputs(value)

    def test_json_rejects_duplicate_and_nonfinite(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":{"x":0,"x":1}}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                h.strict_json(raw)

    def test_output_is_exclusive_and_hash_bound(self):
        with tempfile.TemporaryDirectory(prefix='retained-inert-') as directory:
            path = Path(directory) / 'claim.json'
            h.save(path, {'ok': True})
            raw = h.raw_file(path)
            self.assertEqual(h.pinned(path, h.sha(raw)), raw)
            with self.assertRaises(FileExistsError):
                h.save(path, {'ok': False})
            self.assertEqual(h.read(path), {'ok': True})
            with self.assertRaises(ValueError):
                h.pinned(path, '0' * 64)

    def test_bounded_regular_file_only(self):
        with tempfile.TemporaryDirectory(prefix='retained-inert-') as directory:
            path = Path(directory) / 'item'
            h.save(path, b'123')
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                h.raw_file(alias)
            with self.assertRaises(ValueError):
                h.raw_file(path, 2)

    def test_only_derived_ca_inode_may_change(self):
        before = {'app-data/decision-gate-ca-cert.pem': {'dev': 1, 'ino': 2, 'sha256': 'fixed'},
            'app-data/retained': {'dev': 1, 'ino': 3, 'sha256': 'fixed'}}
        after = copy.deepcopy(before)
        after['app-data/decision-gate-ca-cert.pem']['ino'] = 9
        h.require_non_database_tree(before, after)
        for name, key in (('app-data/decision-gate-ca-cert.pem', 'dev'),
                ('app-data/decision-gate-ca-cert.pem', 'sha256'), ('app-data/retained', 'ino')):
            changed = copy.deepcopy(after)
            changed[name][key] = 'changed'
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                h.require_non_database_tree(before, changed)

    def test_startup_accepts_one_bounded_stamp_without_mutating_input(self):
        fixture = startup_fixture()
        saved = copy.deepcopy(fixture)
        h.require_startup_preservation(*fixture)
        self.assertEqual(fixture, saved)

    def test_startup_rejects_other_stamp_or_rowid(self):
        for key in ('applied_at', 'rowid'):
            fixture = startup_fixture()
            fixture[3]['other'][key] = 'changed'
            with self.subTest(key=key), self.assertRaises(ValueError):
                h.require_startup_preservation(*fixture)
        fixture = startup_fixture()
        fixture[3]['policy_candidate_authority']['rowid'] = 9
        with self.assertRaises(ValueError):
            h.require_startup_preservation(*fixture)

    def test_startup_rejects_stamp_outside_interval_or_naive(self):
        for stamp in ('2026-10-14T00:00:00+00:00', '2026-10-14T00:00:04+00:00', '2026-10-14T00:00:02'):
            fixture = startup_fixture()
            fixture[3]['policy_candidate_authority']['applied_at'] = stamp
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                h.require_startup_preservation(*fixture)

    def test_startup_rejects_audit_append_reorder_or_other_row_change(self):
        for mutation in ('audit_append', 'audit_reorder', 'retained_row', 'schema', 'journal', 'table'):
            fixture = startup_fixture()
            after = fixture[1]
            if mutation == 'audit_append': after['rows']['audit_events']['count'] += 1
            elif mutation == 'audit_reorder': after['orderedAudit'] = 'changed'
            elif mutation == 'retained_row': after['rows']['retained']['sha256'] = 'changed'
            elif mutation == 'schema': after['objects'] = []
            elif mutation == 'journal': after['persistentJournalFormat'] = 'rollback'
            else: del after['rows']['retained']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                h.require_startup_preservation(*fixture)

    def test_both_migration_roles_admit_sibling_import_before_runpy(self):
        for role in ('plan', 'apply'):
            events = []
            shared = SimpleNamespace(sha=h.sha, canonical=h.canon)
            with self.subTest(role=role), patch.object(worker, 'observer',
                    side_effect=lambda: (events.append('observer'), shared)[1]), \
                    patch.object(worker.h, 'read', return_value={}), \
                    patch.object(worker.os, 'open', return_value=123), \
                    patch.object(worker.os, 'fdopen', return_value=io.StringIO()), \
                    patch.object(worker.runpy, 'run_path', side_effect=lambda *a, **k: events.append('runpy')), \
                    patch.object(sys, 'argv', ['inert-test']):
                worker.migration_cli(role)
                self.assertEqual(events, ['observer', 'runpy'])
                self.assertEqual(sys.argv[:3], ['/app/scripts/migrate_operator_authority_source_revision.py',
                    '--data-directory', '/data'])

    def test_host_receipt_requires_actual_terminal_and_cleanup(self):
        value = dict(schema='serverware.sourceRevisionRetainedHost/v1', ok=True, role='plan',
            inputsSha256='a' * 64, workerSha256='b' * 64, exitCode=0, oomKilled=False,
            restartCount=0, containerRemoved=True, containerId='c' * 64)
        with patch.object(worker, 'cfg', {'workerSha256': 'b' * 64}), patch.object(h, 'read', return_value=value):
            self.assertEqual(worker.host_receipt('plan', 'a' * 64), value)
            for key, bad in (('ok', False), ('exitCode', 1), ('oomKilled', True), ('restartCount', 1),
                    ('containerRemoved', False), ('containerId', 'short'), ('inputsSha256', 'd' * 64)):
                changed = {**value, key: bad}
                with self.subTest(key=key), patch.object(h, 'read', return_value=changed), self.assertRaises(ValueError):
                    worker.host_receipt('plan', 'a' * 64)

    def test_source_has_actual_start_and_stopped_observer_boundaries(self):
        text = Path(h.__file__).read_text()
        self.assertIn('operator_google_managed_config.bootstrap(); operator_demo.activate()', text)
        self.assertIn('validate_control_plane_startup()', text)
        self.assertIn("read('/out/migrated-database.json')", text)
        self.assertIn("read('/out/capture-baseline.json')['snapshot']", text)
        self.assertIn("need(snapshot == expected)", text)
        self.assertNotIn('compare_databases(', text)

    def test_source_has_exclusive_private_environment_copy(self):
        text = Path(h.__file__).read_text()
        self.assertIn("save(WORK / 'startup.env', environment, 10001)", text)
        self.assertIn("(WORK / 'startup.env').chmod(0o400)", text)
        self.assertIn('os.O_EXCL | os.O_NOFOLLOW', text)
        self.assertNotIn('CAPTURE.chmod', text)

    def test_worker_has_no_shell_or_live_lifecycle_and_closed_stage_names(self):
        text = Path(worker.__file__).read_text()
        tree = ast.parse(text)
        self.assertNotIn('subprocess', text)
        assignments = [node for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))]
        for node in assignments:
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                self.assertFalse(any(isinstance(item, ast.Attribute) and item.attr == 'ROOT'
                    and isinstance(item.value, ast.Name) and item.value.id == 'shared'
                    for item in ast.walk(target)))
        stages = set()
        def collect_stage(target, value):
            if isinstance(target, ast.Name) and target.id == 'stage':
                self.assertIsInstance(value, ast.Constant)
                self.assertIs(type(value.value), str)
                stages.add(value.value)
            elif isinstance(target, (ast.Tuple, ast.List)):
                self.assertIsInstance(value, (ast.Tuple, ast.List))
                self.assertEqual(len(target.elts), len(value.elts))
                for item, assigned in zip(target.elts, value.elts):
                    collect_stage(item, assigned)
        for node in assignments:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    # Only unpack assignments containing the stage variable.
                    if any(isinstance(item, ast.Name) and item.id == 'stage' for item in ast.walk(target)):
                        collect_stage(target, node.value)
        self.assertEqual(stages, {'arguments', 'inputs', 'preflight', 'source_before', 'previous_receipt',
            'claim', 'selected_role', 'source_after', 'phase_receipt'})
        self.assertIn('"hostCleanupVerification": "required"', text)
        self.assertIn('"normalBinaryExecuted": False', text)


if __name__ == '__main__':
    unittest.main()
