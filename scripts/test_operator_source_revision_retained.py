#!/usr/bin/env python3
"""Inert and synthetic file controls: no app imports, live state or containers."""
import ast
import copy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import operator_source_revision_retained as h
import run_operator_source_revision_retained as worker
import migrate_operator_authority_contract as shared


def inputs():
    value = {key: 'a' * 64 for key in worker.INPUT_KEYS}
    value.update(schema=worker.INPUT_SCHEMA, candidateCommit=worker.COMMIT,
        normalBinarySha256=h.BINARY_SHA, capturePins={name: 'b' * 64 for name in h.CAPTURE_NAMES})
    return value


def startup_fixture():
    before = {'objects': [['table', 'audit_events']], 'orderedAudit': 'fixed-audit-digest',
        'persistentJournalFormat': 'wal', 'rows': {'audit_events': {'count': 497, 'sha256': 'fixed'},
            'retained': {'count': 1, 'sha256': 'fixed'}, 'catchplate_store_migrations': {'sha256': 'old'}}}
    after = copy.deepcopy(before)
    after['rows']['catchplate_store_migrations'] = {'sha256': 'new'}
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
        value = dict(schema='catchplate.sourceRevisionRetainedHost/v1', ok=True, role='plan',
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


class MigratedDatabaseByteControls(unittest.TestCase):
    """Real file/descriptor checks, not a simulated successful migration."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='retained-byte-controls-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data, self.output = self.root / 'data', self.root / 'out'
        self.data.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self.database = self.data / shared.DATABASE
        self.raw = b'synthetic bytes, not an admitted SQLite database'
        h.save(self.database, self.raw)

    def test_real_bytes_and_complete_identity_are_held(self):
        expected = list(shared.identity(self.database.stat(follow_symlinks=False)))
        with worker.held_database_bytes(shared, self.data, self.output) as (value, verify):
            self.assertEqual(value, {'name': shared.DATABASE, 'sha256': h.sha(self.raw),
                'bytes': len(self.raw), 'identity': expected})
            verify()
        self.assertEqual(self.database.read_bytes(), self.raw)

    def test_byte_receipt_is_fsynced_read_only_and_exclusive(self):
        with worker.held_database_bytes(shared, self.data, self.output) as (value, verify):
            verify()
            worker.save_database_bytes(self.output, {'database': value})
        path = self.output / 'migrated-database-bytes.json'
        self.assertEqual(h.read(path), {'database': value})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.assertEqual(path.stat().st_nlink, 1)
        original = path.read_bytes()
        with self.assertRaises(FileExistsError):
            worker.save_database_bytes(self.output, {'database': 'changed'})
        self.assertEqual(path.read_bytes(), original)

    def test_all_main_and_witness_sidecars_refuse_before_read(self):
        for name in (shared.DATABASE, shared.WITNESS):
            for suffix in ('-wal', '-shm', '-journal'):
                sidecar = self.data / (name + suffix)
                h.save(sidecar, b'')
                with self.subTest(name=name, suffix=suffix), self.assertRaises(shared.Refused):
                    with worker.held_database_bytes(shared, self.data, self.output):
                        self.fail('sidecar reached the byte receipt body')
                sidecar.unlink()

    def test_dangling_sidecar_symlink_is_not_absent(self):
        (self.data / (shared.DATABASE + '-wal')).symlink_to(self.data / 'missing')
        with self.assertRaises(shared.Refused):
            with worker.held_database_bytes(shared, self.data, self.output):
                self.fail('dangling sidecar reached the byte receipt body')

    def test_changed_bytes_refuse_before_publication(self):
        with self.assertRaises(ValueError):
            with worker.held_database_bytes(shared, self.data, self.output) as (_value, verify):
                with self.database.open('r+b') as stream:
                    stream.write(b'changed')
                    stream.flush()
                    os.fsync(stream.fileno())
                verify()
        self.assertFalse((self.output / 'migrated-database-bytes.json').exists())

    def test_identical_bytes_on_replacement_inode_refuse(self):
        replacement = self.data / 'replacement'
        h.save(replacement, self.raw)
        with self.assertRaises(ValueError):
            with worker.held_database_bytes(shared, self.data, self.output):
                replacement.replace(self.database)

    def test_metadata_change_refuses(self):
        with self.assertRaises(ValueError):
            with worker.held_database_bytes(shared, self.data, self.output):
                self.database.chmod(0o400)

    def test_startup_claims_refuse(self):
        for role in ('startup1', 'startup2'):
            path = self.output / (role + '.claim.json')
            h.save(path, {'role': role})
            with self.subTest(role=role), self.assertRaises(ValueError):
                with worker.held_database_bytes(shared, self.data, self.output):
                    self.fail('existing startup claim reached the byte receipt body')
            path.unlink()

    def test_state_changes_after_receipt_fsync_refuse(self):
        for mutation in ('bytes', 'sidecar', 'startup'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                    prefix='retained-byte-final-') as directory:
                root = Path(directory)
                database = root / shared.DATABASE
                h.save(database, self.raw)
                with self.assertRaises(ValueError):
                    with worker.held_database_bytes(shared, root, root) as (value, _verify):
                        worker.save_database_bytes(root, {'database': value})
                        if mutation == 'bytes':
                            with database.open('r+b') as stream:
                                stream.write(b'changed')
                                stream.flush()
                                os.fsync(stream.fileno())
                        elif mutation == 'sidecar':
                            h.save(root / (shared.WITNESS + '-journal'), b'')
                        else:
                            h.save(root / 'startup1.claim.json', {'role': 'startup1'})
                # The partial output is preserved, but no phase success is minted.
                self.assertTrue((root / 'migrated-database-bytes.json').is_file())
                self.assertFalse((root / 'phase-freeze.json').exists())

    def test_freeze_keeps_logical_output_and_joins_exact_evidence(self):
        tree = ast.parse(Path(worker.__file__).read_text())
        freeze = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == 'freeze_migrated')
        held = next(node for node in freeze.body if isinstance(node, ast.With)
            and isinstance(node.items[0].context_expr, ast.Call)
            and isinstance(node.items[0].context_expr.func, ast.Name)
            and node.items[0].context_expr.func.id == 'held_database_bytes')
        calls = [node for node in ast.walk(held) if isinstance(node, ast.Call)]
        self.assertTrue(any(isinstance(node.func, ast.Attribute) and node.func.attr == 'inspect'
            for node in calls))
        self.assertTrue(any(isinstance(node.func, ast.Attribute) and node.func.attr == 'save'
            and node.args and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == '/out/migrated-database.json' for node in calls))
        byte_call = next(node for node in calls if isinstance(node.func, ast.Name)
            and node.func.id == 'save_database_bytes')
        receipt = byte_call.args[1]
        self.assertIsInstance(receipt, ast.Dict)
        fields = {key.value: ast.unparse(value) for key, value in zip(receipt.keys, receipt.values)}
        for name, expression in {'candidateCommit': 'COMMIT', 'inputsSha256': 'inputs_sha',
                'sourceProof': 'proof', 'transitionId': 'migration.TRANSITION',
                'pinsSha256': 'migration.PIN_SHA256', 'planSha256': "receipt['planSha256']",
                'planFileSha256': 'h.sha(plan_raw)', 'migrationReceiptSha256': 'h.sha(receipt_raw)',
                'migratedBaselineSha256': 'h.sha(h.canon(after))', 'database': 'commitment',
                'observation': "'freeze-before-first-startup'",
                'requiredPhaseReceipt': "'phase-freeze.json'"}.items():
            with self.subTest(field=name):
                self.assertEqual(fields[name], expression)


class PromotionHashHandoffControls(unittest.TestCase):
    def test_prepare_reads_only_three_root_files_and_emits_only_hashes(self):
        payload = b'synthetic private bytes that must never appear in stdout'
        with patch.object(h, 'raw_file', return_value=payload) as read:
            value = worker.phase_stdout('prepare')
        expected = {'copy/source-proof.json', 'copy/prepared.json', 'copy/auxiliary-preserved.json'}
        self.assertEqual(set(value), {'schema', 'ok', 'role', 'liveAccess', 'hostCleanupVerification', 'promotionFileSha256'})
        self.assertEqual(value['promotionFileSha256'], {name: h.sha(payload) for name in expected})
        self.assertEqual({str(call.args[0]) for call in read.call_args_list},
            {'/job/source-proof.json', '/job/prepared.json', '/job/auxiliary-preserved.json'})
        self.assertNotIn(payload.decode(), json.dumps(value))

    def test_freeze_reads_exact_fourteen_out_files_including_saved_phase(self):
        expected = {'plan.json', 'apply.json', 'migrated-database.json', 'migrated-database-bytes.json',
            'freeze.json', 'expected-contract.json', 'catchplate.sqlite3.baseline.json', 'baseline-contract.json',
            'recovered-files.json', 'phase-prepare.json', 'phase-recover.json', 'phase-plan.json',
            'phase-apply.json', 'phase-freeze.json'}
        with patch.object(h, 'raw_file', side_effect=lambda path: str(path).encode()) as read:
            value = worker.phase_stdout('freeze')
        self.assertEqual(value['promotionFileSha256'],
            {'copy/out/' + name: h.sha(('/out/' + name).encode()) for name in expected})
        self.assertEqual({str(call.args[0]) for call in read.call_args_list}, {'/out/' + name for name in expected})
        self.assertEqual(read.call_count, 14)
        self.assertLess(len(json.dumps(value)), 4096)

    def test_other_phases_do_not_read_or_emit_promotion_files(self):
        with patch.object(h, 'raw_file') as read:
            for role in set(worker.ROLES) - {'prepare', 'freeze'}:
                with self.subTest(role=role):
                    self.assertNotIn('promotionFileSha256', worker.phase_stdout(role))
            with self.assertRaises(ValueError):
                worker.phase_stdout('unrecognized')
        read.assert_not_called()

    def test_missing_or_unreadable_file_prevents_success_handoff(self):
        for role, error in (('prepare', FileNotFoundError), ('freeze', PermissionError)):
            with self.subTest(role=role), patch.object(h, 'raw_file', side_effect=error), self.assertRaises(error):
                worker.phase_stdout(role)

    def test_handoff_call_is_after_source_recheck_and_phase_receipt_save(self):
        tree = ast.parse(Path(worker.__file__).read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        source_after = next(node.lineno for node in main.body if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant) and node.value.value == 'source_after')
        save_phase = next(node.lineno for node in main.body if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == 'save' and ast.unparse(node.value.args[0]).startswith("output /"))
        handoff = next(node.lineno for node in ast.walk(main) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == 'phase_stdout')
        self.assertLess(source_after, save_phase)
        self.assertLess(save_phase, handoff)
        self.assertEqual(main.body[-1].lineno, handoff)


if __name__ == '__main__':
    unittest.main()
