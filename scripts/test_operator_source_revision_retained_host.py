#!/usr/bin/env python3
"""Inert host-owner controls: synthetic Docker models, no Docker or runtime."""
import copy
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('retained_host',
    Path(__file__).with_name('run_operator_source_revision_retained_host.py'))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

CID, INPUTS, HELPER = 'a' * 64, 'b' * 64, 'c' * 64
CFG = {'workerSha256': 'd' * 64, 'helpersSha256': 'e' * 64,
    'normalBinarySha256': host.BINARY_SHA, 'capturePins': {'app.env': 'f' * 64}}
PROOF = {'commit': host.COMMIT}
CONTEXT = {'inputsSha256': INPUTS, 'helperSha256': HELPER,
    'workerSha256': CFG['workerSha256'], 'helpersSha256': CFG['helpersSha256'], 'previousReceipt': None}


def model(selected, *, state='created'):
    privileged = selected['role'] in ('prepare', 'result')
    return {'Id': CID, 'Name': '/' + selected['name'], 'Image': host.IMAGE, 'RestartCount': 0,
        'State': {'Status': state, 'Running': state == 'running', 'Paused': False, 'Restarting': False,
            'Dead': False, 'ExitCode': 0, 'OOMKilled': False, 'Pid': 123 if state == 'running' else 0,
            'StartedAt': '2026-10-14T12:00:00Z', 'FinishedAt': '2026-10-14T12:00:01Z'},
        'Mounts': [{'Type': 'bind', 'Propagation': 'rprivate', 'Source': source,
            'Destination': target, 'RW': not readonly} for source, target, readonly in selected['mounts']],
        'NetworkSettings': {'Ports': {}, 'Networks': {}},
        'Config': {'Labels': {host.LABEL_KEY: host.LABEL}, 'User': '0:0' if privileged else '10001:10001',
            'Healthcheck': {'Test': ['NONE']}, 'WorkingDir': '/app', 'Entrypoint': ['python'],
            'Cmd': ['-B', '/runner/run_operator_source_revision_retained.py', selected['role'], INPUTS],
            'OpenStdin': False, 'Tty': False, 'Env': ['PATH=/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE=1']},
        'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
            'Memory': 768 * 1024**2, 'MemorySwap': 768 * 1024**2, 'NanoCpus': 1_000_000_000,
            'PidsLimit': 96, 'Ulimits': [{'Name': 'fsize', 'Hard': host.MAX_FILE_BYTES, 'Soft': host.MAX_FILE_BYTES}],
            'CapDrop': ['ALL'], 'CapAdd': ['CAP_DAC_OVERRIDE', 'CAP_CHOWN', 'CAP_FOWNER'] if privileged else [],
            'SecurityOpt': ['no-new-privileges'], 'LogConfig': {'Type': 'none', 'Config': {}},
            'Tmpfs': {'/tmp': host.TMPFS}, 'PortBindings': {},
            'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
            'PidMode': '', 'IpcMode': 'private', 'UTSMode': '', 'CgroupnsMode': 'private', 'UsernsMode': ''}}


class FakeCommands:
    def __init__(self, role='apply', *, create_status='passed', run_status='passed',
            inspect_change=None, terminal_change=None, leftovers=False):
        self.selected = host.plan(role, INPUTS)
        self.expected_env = host.environment(model(self.selected)['Config']['Env'])
        self.create_status, self.run_status = create_status, run_status
        self.inspect_change, self.terminal_change = inspect_change, terminal_change
        self.leftovers = leftovers
        self.events, self.started, self.created, self.removed = [], False, False, False

    def matching(self, selected):
        self.events.append(('matching', selected['name']))
        return [[CID], [CID]] if self.created and (not self.removed or self.leftovers) else [[], []]

    def run(self, argv, *, seconds, logs=None):
        if 'create' in argv:
            self.events.append(('create', seconds))
            self.created = True
            return {'status': self.create_status, 'exitCode': 0}, CID.encode()
        if 'start' in argv:
            self.events.append(('start', argv[-1], seconds))
            self.started = True
            return {'status': self.run_status, 'exitCode': 0, 'bytes': [0, 0]}, b''
        raise AssertionError('unexpected synthetic command')

    def inspect(self, identifier):
        self.events.append(('inspect', identifier))
        actual = model(self.selected, state='exited' if self.started else 'created')
        if self.inspect_change:
            self.inspect_change(actual)
        if self.started and self.terminal_change:
            self.terminal_change(actual)
        return actual

    def docker(self, *argv):
        self.events.append(argv)
        if argv[0] == 'rm':
            self.removed = True
            return CID
        raise AssertionError('unexpected synthetic Docker command')


class HostControls(unittest.TestCase):
    def execute(self, commands, *, preservation=lambda: PROOF, save_error=None):
        saved = []
        def save(path, value, **_kwargs):
            if save_error:
                raise save_error
            saved.append((path.name, copy.deepcopy(value)))
        with patch.object(host, 'save', side_effect=save):
            try:
                result = host.run_role(commands, commands.selected, commands.expected_env,
                    preservation, PROOF, CONTEXT)
            except BaseException as error:
                return None, saved, error
        return result, saved, None

    def test_plan_all_roles_are_explicit_and_no_live_path_or_socket_is_mounted(self):
        for role in host.ROLES:
            with self.subTest(role=role):
                selected = host.plan(role, INPUTS)
                argv = selected['createArgv']
                self.assertEqual(argv[:4], [*host.DOCKER, 'create'])
                self.assertIn('--pull', argv)
                self.assertEqual(argv[argv.index('--pull') + 1], 'never')
                self.assertEqual(argv[-5:], [host.IMAGE, '-B', '/runner/run_operator_source_revision_retained.py', role, INPUTS])
                self.assertNotIn('/var/run/docker.sock', [row[1] for row in selected['mounts']])
                for source, target, readonly in selected['mounts']:
                    self.assertTrue(Path(source).is_relative_to(host.ROOT) or Path(source).is_relative_to(host.CAPTURE))
                    if Path(source).is_relative_to(host.CAPTURE):
                        self.assertTrue(readonly)
                    if target == '/host-receipts':
                        self.assertEqual(source, str(host.RECEIPTS))
                        self.assertTrue(readonly)
                writable = [row[1] for row in selected['mounts'] if not row[2]]
                if role in ('prepare', 'result'):
                    self.assertEqual(writable, ['/job'])
                else:
                    self.assertNotIn('/job', writable)
                    data = next(row for row in selected['mounts'] if row[1] == '/data')
                    self.assertEqual(data[2], role in ('plan', 'freeze', 'observe1', 'observe2'))

    def test_startup_plan_uses_only_private_derived_file_and_matches_inspected_environment(self):
        captured = (b'SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=sha256:old\n'
            b'PYTHONDONTWRITEBYTECODE=0\nSERVERWARE_DATA_DIR=/data\nOPAQUE_VALUE=fixture=value #literal\n')
        derived = host.startup_environment_bytes(captured)
        for role in ('startup1', 'startup2'):
            with patch.object(host, 'startup_environment', return_value={'sha256': host.sha(derived)}), \
                    patch.object(host, 'pinned', return_value=derived):
                expected = host.expected_environment(['PATH=/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE=1'], role, CFG)
            selected = host.plan(role, INPUTS)
            argv = selected['createArgv']
            overrides = host.environment(derived.decode().splitlines())
            key = 'SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST'
            self.assertEqual(overrides[key], expected[key])
            self.assertEqual(overrides[key], 'sha256:' + host.BINARY_SHA)
            self.assertNotIn('--env', argv)
            self.assertEqual(argv.count('--env-file'), 1)
            self.assertEqual(argv[argv.index('--env-file') + 1], str(host.STARTUP_ENVIRONMENT))
            self.assertFalse(any('fixture=value' in value for value in argv))
            self.assertIn([str(host.WORK / 'startup.env'), '/startup.env', True], selected['mounts'])
            actual = model(selected)
            actual['Config']['Env'] = [key + '=' + value for key, value in expected.items()]
            host.isolation(actual, selected, expected)
        for role in set(host.ROLES) - {'startup1', 'startup2'}:
            self.assertNotIn('--env-file', host.plan(role, INPUTS)['createArgv'])

    def test_startup_environment_replaces_only_two_existing_keys_in_original_order(self):
        before = (b'FIRST=fixture=unchanged #literal\nPYTHONDONTWRITEBYTECODE=0\n'
            b'MIDDLE=\nSERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=sha256:old\nLAST=unchanged\n')
        after = host.startup_environment_bytes(before)
        self.assertEqual(after.splitlines(), [b'FIRST=fixture=unchanged #literal', b'PYTHONDONTWRITEBYTECODE=1',
            b'MIDDLE=', ('SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=sha256:' + host.BINARY_SHA).encode(),
            b'LAST=unchanged'])
        self.assertEqual(list(host.environment(before.decode().splitlines())),
            list(host.environment(after.decode().splitlines())))
        self.assertTrue(after.endswith(b'\n'))

    def test_startup_environment_refuses_duplicate_missing_or_noncanonical_lines(self):
        valid = b'PYTHONDONTWRITEBYTECODE=0\nSERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=sha256:old\n'
        for captured in (valid + b'PYTHONDONTWRITEBYTECODE=1\n', valid.removesuffix(b'\n'),
                valid.replace(b'\n', b'\r\n'), valid + b'\n', valid + b'#comment\n',
                valid + b'INVALID\n', valid + b'OPAQUE_VALUE=\x00\n', b'OTHER=value\n', b'x' * 65537):
            with self.subTest(size=len(captured)), self.assertRaises(ValueError):
                host.startup_environment_bytes(captured)

    def startup_environment_metadata(self):
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o400, st_uid=1000, st_gid=1000,
            st_nlink=1, st_dev=7, st_ino=9, st_size=200, st_mtime_ns=3, st_ctime_ns=4)

    def test_startup_environment_creation_is_exclusive_private_and_rechecked(self):
        captured = b'PYTHONDONTWRITEBYTECODE=0\nSERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=sha256:old\n'
        derived = host.startup_environment_bytes(captured)
        metadata = self.startup_environment_metadata()
        def pinned(path, digest, limit):
            if path == host.CAPTURE / 'app.env':
                self.assertEqual(digest, CFG['capturePins']['app.env'])
                return captured
            self.assertEqual(path, host.STARTUP_ENVIRONMENT)
            self.assertEqual(digest, host.sha(derived))
            self.assertEqual(limit, 65536)
            return derived
        with patch.object(host, 'pinned', side_effect=pinned), \
                patch.object(host.Path, 'lstat', return_value=metadata), \
                patch.object(host, 'save_bytes') as save:
            receipt = host.startup_environment(CFG, create=True)
            save.assert_called_once_with(host.STARTUP_ENVIRONMENT, derived, mode=0o400)
            self.assertEqual(receipt['sha256'], host.sha(derived))
            self.assertNotIn('values', receipt)
            save.reset_mock()
            self.assertEqual(host.startup_environment(CFG), receipt)
            save.assert_not_called()
            save.side_effect = FileExistsError
            with self.assertRaises(FileExistsError):
                host.startup_environment(CFG, create=True)

    def test_startup_environment_rejects_permissions_owner_link_or_identity_changes(self):
        captured = b'PYTHONDONTWRITEBYTECODE=0\nSERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST=sha256:old\n'
        derived = host.startup_environment_bytes(captured)
        for change in ({'st_mode': stat.S_IFREG | 0o444}, {'st_uid': 10001}, {'st_gid': 10001},
                {'st_nlink': 2}, {'st_mode': stat.S_IFLNK | 0o400}):
            metadata = self.startup_environment_metadata()
            metadata.__dict__.update(change)
            with patch.object(host, 'pinned', return_value=captured), \
                    patch.object(host.Path, 'lstat', return_value=metadata), self.assertRaises(ValueError):
                host.startup_environment(CFG)
        first, second = self.startup_environment_metadata(), self.startup_environment_metadata()
        second.st_ino += 1
        with patch.object(host, 'pinned', side_effect=[captured, derived]), \
                patch.object(host.Path, 'lstat', side_effect=[first, second]), self.assertRaises(ValueError):
            host.startup_environment(CFG)

    def test_private_byte_writer_uses_exclusive_nofollow_creation(self):
        with patch.object(host.os, 'open', side_effect=FileExistsError) as opened:
            with self.assertRaises(FileExistsError):
                host.save_bytes(host.STARTUP_ENVIRONMENT, b'private fixture', mode=0o400)
            opened.assert_called_once_with(host.STARTUP_ENVIRONMENT,
                host.os.O_WRONLY | host.os.O_CREAT | host.os.O_EXCL | host.os.O_NOFOLLOW, 0o600)

    def test_environment_refuses_duplicate_keys_and_unknown_binary(self):
        for values in (['KEY=1', 'KEY=2'], ['MISSING'], ['1KEY=x'], ['KEY=x\x00']):
            with self.subTest(values=values), self.assertRaises(ValueError):
                host.environment(values)
        with self.assertRaises(ValueError):
            host.expected_environment([], 'prepare', {**CFG, 'normalBinarySha256': '0' * 64})

    def test_every_exact_model_is_admitted_and_receipt_does_not_include_environment(self):
        for role in host.ROLES:
            selected = host.plan(role, INPUTS)
            actual = model(selected)
            host.identity(CID, actual, selected)
            receipt = host.isolation(actual, selected, host.environment(actual['Config']['Env']))
            self.assertTrue(receipt['mountsExact'])
            self.assertTrue(receipt['environmentExact'])
            self.assertNotIn('Env', receipt)

    def test_image_expose_metadata_is_not_a_published_port(self):
        selected = host.plan('prepare', INPUTS)
        actual = model(selected)
        actual['NetworkSettings']['Ports'] = {'3000/tcp': None, '8080/tcp': None, '8443/tcp': None}
        expected = host.environment(actual['Config']['Env'])
        host.isolation(actual, selected, expected)
        actual['NetworkSettings']['Ports']['3000/tcp'] = [{'HostIp': '127.0.0.1', 'HostPort': '3000'}]
        with self.assertRaises(ValueError):
            host.isolation(actual, selected, expected)

    def test_model_rejects_extra_mounts_write_capture_ports_and_resources(self):
        changes = [lambda value: value['Mounts'].append({'Type': 'bind', 'Propagation': 'rprivate',
                    'Source': '/var/run/docker.sock', 'Destination': '/socket', 'RW': True}),
            lambda value: value['Mounts'][0].update(RW=True),
            lambda value: value['Mounts'][0].update(Propagation='rshared'),
            lambda value: value['HostConfig'].update(NetworkMode='host'),
            lambda value: value['HostConfig'].update(ReadonlyRootfs=False),
            lambda value: value['HostConfig'].update(Privileged=True),
            lambda value: value['HostConfig'].update(MemorySwap=-1),
            lambda value: value['HostConfig'].update(PidsLimit=0),
            lambda value: value['HostConfig'].update(NanoCpus=0),
            lambda value: value['HostConfig'].update(PortBindings={'80/tcp': [{'HostPort': '8080'}]}),
            lambda value: value['HostConfig'].update(PidMode='host'),
            lambda value: value['HostConfig'].update(CapAdd=['CAP_SYS_ADMIN']),
            lambda value: value['HostConfig'].update(SecurityOpt=['no-new-privileges', 'seccomp=unconfined']),
            lambda value: value['HostConfig'].update(Devices=[{'PathOnHost': '/dev/secret'}]),
            lambda value: value['HostConfig'].update(RestartPolicy={'Name': 'always', 'MaximumRetryCount': 0}),
            lambda value: value['Config'].update(Env=['PATH=/other', 'PYTHONDONTWRITEBYTECODE=1']),
            lambda value: value['Config'].update(User='0:0')]
        selected = host.plan('apply', INPUTS)
        expected = host.environment(model(selected)['Config']['Env'])
        for change in changes:
            actual = model(selected)
            change(actual)
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                host.isolation(actual, selected, expected)

    def test_identity_requires_full_id_exact_image_name_and_label(self):
        selected = host.plan('apply', INPUTS)
        for identifier, change in ((CID[:12], lambda _: None), (CID, lambda value: value.update(Id='f' * 64)),
                (CID, lambda value: value.update(Name='/other')), (CID, lambda value: value.update(Image='sha256:other')),
                (CID, lambda value: value['Config']['Labels'].update({host.LABEL_KEY: 'other'}))):
            actual = model(selected)
            change(actual)
            with self.assertRaises(ValueError):
                host.identity(identifier, actual, selected)

    def test_terminal_requires_zero_exit_no_oom_no_restart(self):
        selected = host.plan('apply', INPUTS)
        host.terminal_state(model(selected, state='exited'))
        for key, value in (('Status', 'running'), ('Running', True), ('Paused', True), ('Restarting', True),
                ('Dead', True), ('ExitCode', 1), ('OOMKilled', True)):
            actual = model(selected, state='exited')
            actual['State'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.terminal_state(actual)
        actual = model(selected, state='exited')
        actual['RestartCount'] = 1
        with self.assertRaises(ValueError):
            host.terminal_state(actual)

    def test_success_orders_inspection_before_start_and_full_id_removal(self):
        commands = FakeCommands()
        receipt, saved, error = self.execute(commands)
        self.assertIsNone(error)
        self.assertTrue(receipt['ok'])
        self.assertEqual([name for name, _ in saved], ['host-apply.claim.json', 'apply.json'])
        self.assertLess(commands.events.index(('inspect', CID)), commands.events.index(('start', CID, 85)))
        self.assertIn(('rm', CID), commands.events)
        self.assertFalse(receipt['oomKilled'])
        self.assertEqual(receipt['restartCount'], 0)
        host.validate_receipt(receipt, 'apply', INPUTS, HELPER, CFG, PROOF)

    def test_changed_model_never_starts_or_removes_unproven_container(self):
        commands = FakeCommands(inspect_change=lambda value: value['Mounts'][0].update(RW=True))
        _, saved, error = self.execute(commands)
        self.assertIsInstance(error, ValueError)
        self.assertFalse(commands.started)
        self.assertFalse(commands.removed)
        self.assertFalse(saved[-1][1]['ok'])
        self.assertEqual(saved[-1][1]['cleanupErrorType'], 'ValueError')

    def test_ambiguous_create_never_recovers_ownership_by_name(self):
        commands = FakeCommands(create_status='timeout')
        _, saved, error = self.execute(commands)
        self.assertIsInstance(error, ValueError)
        self.assertFalse(commands.started)
        self.assertFalse(commands.removed)
        self.assertIsNone(saved[-1][1]['containerId'])

    def test_timeout_retains_running_owned_cid_without_stop_force_or_retry(self):
        commands = FakeCommands(run_status='timeout', terminal_change=lambda value: value['State'].update(
            Status='running', Running=True, Pid=123))
        _, saved, error = self.execute(commands)
        self.assertIsInstance(error, ValueError)
        self.assertFalse(any(event[0] in ('rm', 'stop', 'kill') for event in commands.events))
        self.assertEqual(sum(event[0] == 'start' for event in commands.events), 1)
        self.assertEqual(sum(event[0] == 'create' for event in commands.events), 1)
        self.assertFalse(saved[-1][1]['ok'])
        self.assertFalse(saved[-1][1]['containerRemoved'])
        self.assertEqual(saved[-1][1]['containerId'], CID)
        self.assertEqual(saved[-1][1]['cleanupState']['Pid'], 123)
        self.assertEqual(saved[-1][1]['cleanupErrorType'], 'ValueError')

    def test_timeout_removes_only_confirmed_stopped_owned_cid_non_forcibly(self):
        for status in ('created', 'exited'):
            commands = FakeCommands(run_status='timeout', terminal_change=lambda value: value['State'].update(
                Status=status, Running=False, Pid=0))
            _, saved, error = self.execute(commands)
            self.assertIsInstance(error, ValueError)
            self.assertIn(('rm', CID), commands.events)
            self.assertFalse(any(event[0] in ('stop', 'kill') or '-f' in event for event in commands.events))
            self.assertFalse(saved[-1][1]['ok'])
            self.assertTrue(saved[-1][1]['containerRemoved'])

    def test_cleanup_retains_uncertain_state_or_pid(self):
        for changes in ({'Status': 'removing'}, {'Status': 'unknown'}, {'Pid': 1}, {'Pid': None},
                {'Pid': False}, {'Paused': True}, {'Restarting': True}, {'Dead': True}, {'Running': None}):
            commands = FakeCommands(run_status='timeout', terminal_change=lambda value: value['State'].update(changes))
            _, saved, error = self.execute(commands)
            with self.subTest(changes=changes):
                self.assertIsInstance(error, ValueError)
                self.assertFalse(any(event[0] in ('rm', 'stop', 'kill') for event in commands.events))
                self.assertFalse(commands.removed)
                self.assertEqual(saved[-1][1]['containerId'], CID)
                self.assertFalse(saved[-1][1]['containerRemoved'])
                self.assertIsNotNone(saved[-1][1]['cleanupState'])

    def test_cleanup_inspection_failure_retains_cid_and_prior_terminal_evidence(self):
        commands = FakeCommands()
        original = commands.inspect
        calls = 0
        def inspect(identifier):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise ValueError('synthetic unavailable inspection')
            return original(identifier)
        commands.inspect = inspect
        _, saved, error = self.execute(commands)
        self.assertIsInstance(error, ValueError)
        self.assertFalse(any(event[0] in ('rm', 'stop', 'kill') for event in commands.events))
        self.assertEqual(saved[-1][1]['containerId'], CID)
        self.assertEqual(saved[-1][1]['terminalState']['Status'], 'exited')
        self.assertIsNone(saved[-1][1]['cleanupState'])
        self.assertFalse(saved[-1][1]['containerRemoved'])

    def test_oom_is_recorded_and_never_admitted(self):
        commands = FakeCommands(terminal_change=lambda value: value['State'].update(OOMKilled=True, ExitCode=137))
        _, saved, error = self.execute(commands)
        self.assertIsInstance(error, ValueError)
        self.assertTrue(saved[-1][1]['oomKilled'])
        self.assertEqual(saved[-1][1]['terminalState']['ExitCode'], 137)
        self.assertFalse(saved[-1][1]['ok'])

    def test_leftovers_or_changed_preservation_fail_success(self):
        for commands, preservation in ((FakeCommands(leftovers=True), lambda: PROOF),
                (FakeCommands(), lambda: {'commit': 'changed'})):
            _, saved, error = self.execute(commands, preservation=preservation)
            self.assertIsInstance(error, ValueError)
            self.assertFalse(saved[-1][1]['ok'])

    def test_existing_claim_stops_before_create_and_preserves_prior_receipts(self):
        commands = FakeCommands()
        _, saved, error = self.execute(commands, save_error=FileExistsError())
        self.assertIsInstance(error, FileExistsError)
        self.assertFalse(commands.created)
        self.assertEqual(saved, [])

    def test_predecessor_is_exact_role_input_source_and_success_not_intent(self):
        commands = FakeCommands(role='freeze')
        receipt, _, error = self.execute(commands)
        self.assertIsNone(error)
        for key, value in (('role', 'apply'), ('inputsSha256', '0' * 64), ('helperSha256', '0' * 64),
                ('workerSha256', '0' * 64), ('helpersSha256', '0' * 64), ('sourceProof', {}),
                ('ok', False), ('containerRemoved', False), ('sourceAndCaptureUnchanged', False),
                ('oomKilled', True), ('restartCount', 1), ('containerId', CID[:12])):
            changed = {**receipt, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.validate_receipt(changed, 'freeze', INPUTS, HELPER, CFG, PROOF)

    def test_startup1_requires_freeze_receipt_not_apply(self):
        commands = FakeCommands(role='freeze')
        receipt, _, _ = self.execute(commands)
        import json
        raw = json.dumps(receipt).encode()
        expected_path = host.RECEIPTS / 'freeze.json'
        with patch.object(host.Path, 'read_bytes', return_value=raw), \
                patch.object(host.Path, 'resolve', return_value=expected_path), \
                patch.object(host.Path, 'is_symlink', return_value=False):
            actual = host.previous_receipt('startup1', INPUTS, HELPER, CFG, PROOF)
            self.assertEqual(actual, {'role': 'freeze', 'sha256': host.sha(raw)})

    def test_predecessor_binds_same_private_startup_environment_identity(self):
        commands = FakeCommands(role='freeze')
        receipt, _, _ = self.execute(commands)
        environment_proof = {'sha256': '1' * 64, 'inode': 9}
        receipt['startupEnvironment'] = environment_proof
        import json
        raw = json.dumps(receipt).encode()
        with patch.object(host.Path, 'read_bytes', return_value=raw), \
                patch.object(host.Path, 'resolve', return_value=host.RECEIPTS / 'freeze.json'), \
                patch.object(host.Path, 'is_symlink', return_value=False):
            host.previous_receipt('startup1', INPUTS, HELPER, CFG, PROOF, environment_proof)
            with self.assertRaises(ValueError):
                host.previous_receipt('startup1', INPUTS, HELPER, CFG, PROOF, {**environment_proof, 'inode': 10})


if __name__ == '__main__':
    unittest.main()
