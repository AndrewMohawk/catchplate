#!/usr/bin/env python3
"""Pure receipt-parser controls only; no Rust, Docker, or native authority."""
import importlib.util
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('native_review_rust_runner', Path(__file__).with_name('run_native_jit_review_rust.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReceiptParsers(unittest.TestCase):
    def test_exact_test_names_and_zero_skips(self):
        runner.check_tests('x::a: test\nx::b: test\n',
            'test x::a ... ok\ntest x::b ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored; 5 filtered out;\n',
            ['x::a', 'x::b'])

    def test_missing_duplicate_ignored_and_wrong_names_refuse(self):
        listed = 'x::a: test\nx::b: test\n'
        output = 'test x::a ... ok\ntest x::b ... ok\ntest result: ok. 2 passed; 0 failed; 0 ignored;\n'
        for bad_list, bad_output in ((listed.replace('x::b', 'x::a'), output), (listed, output.replace('x::b', 'x::c')),
                                    (listed, output.replace('0 ignored', '1 ignored')), ('', output), (listed, output + output)):
            with self.subTest(listed=bad_list, output=bad_output), self.assertRaises(ValueError):
                runner.check_tests(bad_list, bad_output, ['x::a', 'x::b'])

    def api_error(self, code='E0616', line=2, filename=None):
        return json.dumps({'level': 'error', 'code': {'code': code}, 'spans': [
            {'is_primary': True, 'line_start': line,
             'file_name': filename or '/repository/' + runner.CRATE + 'src/native_jit_review_open_api_tests/private_attempts.rs'}]}).encode()

    def test_exact_api_code_file_line(self):
        runner.check_api(b'', self.api_error(), 'E0616', 'native_jit_review_open_api_tests/private_attempts.rs', 2)
        runner.check_api(b'', b'', None, 'native_jit_review_open_api_tests/pass.rs', None)

    def test_wrong_api_diagnostic_and_unrelated_failure_refuse(self):
        for diagnostic in (b'', self.api_error('E0425'), self.api_error(line=1), self.api_error(filename='/wrong.rs'),
                           self.api_error() + b'\n' + self.api_error()):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                runner.check_api(b'', diagnostic, 'E0616', 'native_jit_review_open_api_tests/private_attempts.rs', 2)
        with self.assertRaises(ValueError):
            runner.check_api(b'unexpected', b'', None, 'pass.rs', None)

    def cargo(self, fresh=False):
        return {'reason': 'compiler-artifact', 'target': {'name': 'catchplate_decision_gate', 'kind': ['lib'],
            'src_path': '/repository/' + runner.CRATE + 'src/custody_protocol.rs'}, 'profile': {'test': False}, 'fresh': fresh}

    def test_fresh_cargo_artifact_and_completed_build(self):
        row = self.cargo()
        data = json.dumps(row) + '\n' + json.dumps({'reason': 'build-finished', 'success': True})
        self.assertEqual(runner.cargo_row(data, 'library'), row)

    def test_cached_wrong_target_and_failed_cargo_refuse(self):
        for row, finished in ((self.cargo(True), True), (self.cargo(), False)):
            with self.subTest(row=row, finished=finished), self.assertRaises(ValueError):
                runner.cargo_row(json.dumps(row) + '\n' + json.dumps({'reason': 'build-finished', 'success': finished}), 'library')
        with self.assertRaises(ValueError):
            runner.cargo_row(json.dumps(self.cargo()) + '\n' + json.dumps({'reason': 'build-finished', 'success': True}), 'bintest')

    def test_compiler_input_normalization_and_escape_refusal(self):
        actual = runner.compiler_inputs(b'/target/release/deps/a.d: src/a.rs src/a.rs src/../../../scripts/fixture.json\n')
        self.assertEqual(actual, {runner.CRATE + 'src/a.rs', 'scripts/fixture.json'})
        for raw in (b'/target/release/a.d: ../../../../escape\n', b'/target/release/a.d: /etc/passwd\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                runner.compiler_inputs(raw)

    def test_retained_control_roster_counts_and_no_duplicate_names(self):
        roster = json.loads(Path(__file__).with_name('native_jit_review_rust_tests.json').read_bytes())
        totals = {'library': 0, 'binary': 0}; names = []
        for item in roster.values():
            totals[item['kind']] += len(item['names'])
            names += [item['prefix'] + name for name in item['names']]
        self.assertEqual(totals, {'library': 29, 'binary': 24})
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(runner.APIS), 5)


class NormalArtifactParsers(unittest.TestCase):
    """Synthetic parser/file fixtures, never evidence of an actual Rust build."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve()
        self.files = {}
        for name, body in {
            runner.CRATE + 'Cargo.toml': b'[package]\nname="catchplate-decision-gate"\nversion="0.1.0"\n',
            runner.CRATE + 'Cargo.lock': b'version = 4\n',
            runner.CRATE + 'src/main.rs': b'fn main() {}\n',
            runner.CRATE + 'src/custody_protocol.rs': b'pub fn fixture() {}\n',
            'schemas/fixture.json': b'{}\n',
            **{name: b'{}\n' for name in runner.NORMAL_FILES},
            'docs/fixture.md': b'not a compiler input\n',
            'catchplate/operator_demo_web/fixture.js': b'// not a compiler input\n',
        }.items():
            self.put(name, body)

    def put(self, name, body):
        path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        self.files[name] = ('100644', hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest())

    def identity(self):
        return runner.normal_input_identity(self.repo, self.files)

    def elf(self):
        body = bytearray(64); body[:7] = b'\x7fELF\x02\x01\x01'; body[16:20] = b'\x03\x00\x3e\x00'
        return bytes(body)

    def receipt(self):
        identity = self.identity(); compiler = {}
        for kind, source in (('binary', 'main.rs'), ('library', 'custody_protocol.rs')):
            stem = '/target/release/deps/catchplate_decision_gate-' + ('1' if kind == 'binary' else '2') * 16
            name = runner.CRATE + 'src/' + source
            compiler[kind] = {'artifactPath': '/target/release/catchplate-decision-gate' if kind == 'binary' else
                stem.replace('/catchplate_', '/libcatchplate_') + '.rlib', 'depInfoPath': stem + '.d',
                'artifactSha256': hashlib.sha256(self.elf()).hexdigest() if kind == 'binary' else 'c' * 64,
                'depInfoSha256': 'a' * 64, 'files': {name: identity['files'][name]},
                'environment': {'CARGO_PKG_VERSION': '0.1.0'} if kind == 'binary' else {}}
        return {'schema': 'catchplate.hostedNormalRust/v1', 'ok': True, 'sourceRevision': 'a' * 40,
            'buildInputIdentity': runner.identity_digest(identity), 'buildInputs': identity,
            'cargoLockSha256': identity['files'][runner.CRATE + 'Cargo.lock']['sha256'],
            'github': {'repository': 'example/catchplate', 'runId': 123, 'runAttempt': 1,
                'workflowPath': '.github/workflows/native-review-rust.yml', 'job': 'normal-proxy'},
            'runnerSourceSha256': 'b' * 64,
            'toolchain': {'rustcVersionVerbose': 'rustc 1.88.0 (fixture)\nhost: x86_64-unknown-linux-gnu\n',
                          'cargoVersion': 'cargo 1.88.0 (fixture)\n'},
            'binary': {'name': 'catchplate-decision-gate', 'sha256': hashlib.sha256(self.elf()).hexdigest(),
                       'bytes': 64, 'mode': '0555'}, 'compilerInputs': compiler,
            'cleanup': {'allOwnedContainersRemoved': True, 'phases': ['provision', 'normal']},
            'normalBinary': True, 'tested': False, 'deployed': False, 'nativeAdmission': False,
            'cacheRestored': False, 'automaticRetry': False}

    def test_identity_ignores_app_js_and_docs_but_keeps_original_build_commit(self):
        before = self.identity(); receipt = self.receipt()
        self.put('docs/fixture.md', b'changed documentation\n')
        self.put('catchplate/operator_demo_web/fixture.js', b'// changed app\n')
        self.assertEqual(self.identity(), before)
        runner.verify_normal_receipt(receipt, self.elf(), self.identity())
        self.assertEqual(receipt['sourceRevision'], 'a' * 40)
        self.assertNotIn('sourceRevision', before)

    def test_identity_changes_for_existing_new_library_schema_and_lock_inputs(self):
        original = self.identity()
        for name in (runner.CRATE + 'src/custody_protocol.rs', runner.CRATE + 'src/new.rs',
                     'schemas/new.json', runner.CRATE + 'Cargo.lock'):
            self.put(name, b'changed bytes\n')
            self.assertNotEqual(runner.identity_digest(self.identity()), runner.identity_digest(original))

    def test_input_identity_refuses_unjoined_bytes_and_selected_submodule(self):
        path = self.repo / runner.CRATE / 'src/main.rs'; path.write_bytes(b'changed outside Git\n')
        with self.assertRaises(ValueError): self.identity()
        self.put(runner.CRATE + 'src/main.rs', b'fn main() {}\n')
        self.files[runner.CRATE + 'submodule'] = ('160000', 'c' * 40)
        with self.assertRaises(ValueError): self.identity()
        raw = b'160000 commit ' + b'c' * 40 + b'\t' + (runner.CRATE + 'submodule').encode() + b'\0'
        self.assertEqual(runner.normal_git_files(raw)[runner.CRATE + 'submodule'][0], '160000')

    def test_workspace_config_toolchain_and_build_scripts_refuse(self):
        for name in ('Cargo.toml', 'data-plane/Cargo.toml', '.cargo/config.toml',
                     'data-plane/.cargo/config.toml', runner.CRATE + '.cargo/config.toml',
                     'rust-toolchain', 'data-plane/rust-toolchain.toml', runner.CRATE + 'rust-toolchain.toml',
                     runner.CRATE + 'build.rs'):
            path = self.repo / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('unsupported')
            with self.subTest(name=name), self.assertRaises(ValueError): self.identity()
            path.unlink()
            if path.parent.name == '.cargo': path.parent.rmdir()
        manifest = self.repo / runner.CRATE / 'Cargo.toml'
        original = manifest.read_bytes()
        for suffix in (b'build="other.rs"\n', b'\n[build-dependencies]\n', b'\n[workspace]\n'):
            self.put(runner.CRATE + 'Cargo.toml', original + suffix)
            with self.assertRaises(ValueError): self.identity()
        self.put(runner.CRATE + 'Cargo.toml', original)

    def cargo(self):
        rows = []
        for kind, name, source in (('binary', 'catchplate-decision-gate', 'main.rs'),
                                   ('library', 'catchplate_decision_gate', 'custody_protocol.rs')):
            rows.append({'reason': 'compiler-artifact', 'target': {'name': name, 'kind': ['bin'] if kind == 'binary' else ['lib'],
                'src_path': '/repository/' + runner.CRATE + 'src/' + source}, 'profile': {'test': False, 'opt_level': '3'},
                'features': [], 'fresh': False, 'executable': '/target/release/catchplate-decision-gate' if kind == 'binary' else None,
                'filenames': ['/target/release/catchplate-decision-gate'] if kind == 'binary' else []})
        return rows + [{'reason': 'build-finished', 'success': True}]

    def test_normal_cargo_requires_actual_normal_and_linked_library(self):
        def parse(rows): return runner.normal_cargo_rows('\n'.join(json.dumps(row) for row in rows))
        self.assertEqual(set(parse(self.cargo())), {'binary', 'library'})
        for change in (lambda rows: rows[0]['profile'].update(test=True), lambda rows: rows[1].update(fresh=True),
                       lambda rows: rows[0].update(executable='/target/release/deps/catchplate_decision_gate-' + 'a' * 16),
                       lambda rows: rows[0].update(features=['other']), lambda rows: rows.pop(1),
                       lambda rows: rows.append(deepcopy(rows[0])), lambda rows: rows[-1].update(success=False)):
            rows = self.cargo(); change(rows)
            with self.assertRaises(ValueError): parse(rows)

    def test_complete_unit_dep_info_and_package_environment_are_bound(self):
        stem = '/target/release/deps/catchplate_decision_gate-' + '1' * 16
        raw = (stem + '.d: src/main.rs src/../../../schemas/fixture.json\n\n' + stem + ': src/main.rs src/../../../schemas/fixture.json\n'
               '\nsrc/main.rs:\nsrc/../../../schemas/fixture.json:\n\n# env-dep:CARGO_PKG_VERSION=0.1.0\n').encode()
        files, environment = runner.normal_dep_info(raw, {stem, stem + '.d'}, '0.1.0')
        self.assertEqual(files, {runner.CRATE + 'src/main.rs', 'schemas/fixture.json'})
        self.assertEqual(environment, {'CARGO_PKG_VERSION': '0.1.0'})
        for bad in (raw.replace(b'=0.1.0', b'=0.2.0'), raw.replace(b'CARGO_PKG_VERSION', b'HOST_SECRET'),
                    raw.replace(b'src/main.rs', b'/etc/passwd'), raw + b'# unknown\n',
                    raw + b'# env-dep:CARGO_PKG_VERSION=0.1.0\n', raw.replace(b'src/main.rs', b'src/main\\.rs'),
                    raw.replace(stem.encode(), b'/target/release/wrong')):
            with self.assertRaises(ValueError): runner.normal_dep_info(bad, {stem, stem + '.d'}, '0.1.0')

    def test_receipt_refuses_tampered_elf_scope_current_inputs_and_cleanup(self):
        receipt = self.receipt(); runner.verify_normal_receipt(receipt, self.elf(), self.identity())
        changes = (lambda v: v.update(tested=True), lambda v: v.update(normalBinary=False),
            lambda v: v.update(buildInputIdentity='0' * 64), lambda v: v.update(extra='not public'),
            lambda v: v['cleanup'].update(allOwnedContainersRemoved=1), lambda v: v['cleanup'].update(phases=['normal']),
            lambda v: v['github'].update(job='focused-rust'), lambda v: v['github'].update(runId=True),
            lambda v: v['binary'].update(mode='0755'), lambda v: v['binary'].update(sha256='0' * 64),
            lambda v: v['compilerInputs'].pop('library'),
            lambda v: v['compilerInputs']['binary'].update(artifactSha256='0' * 64),
            lambda v: v['compilerInputs']['library'].update(artifactPath='/target/release/deps/libcatchplate_decision_gate-' + '9' * 16 + '.rlib'),
            lambda v: v['compilerInputs']['binary']['environment'].update(CARGO_PKG_VERSION='wrong'),
            lambda v: v['compilerInputs']['library']['files'].clear(),
            lambda v: v['toolchain'].update(cargoVersion='cargo 1.89.0 (wrong)'))
        for change in changes:
            changed = deepcopy(receipt); change(changed)
            with self.assertRaises((ValueError, KeyError)): runner.verify_normal_receipt(changed, self.elf(), self.identity())
        for data in (b'not ELF', self.elf()[:-1], self.elf().replace(b'\x3e\x00', b'\x28\x00')):
            with self.assertRaises(ValueError): runner.verify_normal_receipt(receipt, data, self.identity())
        self.put(runner.CRATE + 'src/main.rs', b'fn main() {panic!()}\n')
        with self.assertRaises(ValueError): runner.verify_normal_receipt(receipt, self.elf(), self.identity())

    def test_workflow_default58_and_exact_two_file_normal_upload(self):
        source = Path(__file__).resolve().parents[1]
        workflow = (source / '.github/workflows/native-review-rust.yml').read_text()
        self.assertIn('default: engineering', workflow)
        self.assertIn('timeout-minutes: 65', workflow)
        normal = workflow.split('  normal-proxy:\n', 1)[1]
        self.assertIn('timeout-minutes: 50', normal)
        self.assertIn('--mode normal', normal)
        self.assertNotIn('if: always()', normal)
        upload = normal.split('name: Upload only the normal executable and public provenance', 1)[1]
        paths = [line.strip() for line in upload.splitlines() if '/artifact/' in line]
        self.assertEqual(paths, ['${{ runner.temp }}/normal-proxy-rust/artifact/catchplate-decision-gate',
                                 '${{ runner.temp }}/normal-proxy-rust/artifact/normal.json'])
        self.assertNotIn('/results/', upload)
        failure = normal.split('name: Retain only closed normal failure metadata', 1)[1]
        self.assertIn('if: failure()', failure)
        self.assertEqual([line.strip() for line in failure.splitlines() if line.strip().startswith('path:')],
                         ['path: ${{ runner.temp }}/normal-proxy-rust/normal-failure.json'])

    def orchestrate(self, *, terminal=True, library_root=False):
        # This tests the real producer wiring, not a genuine compilation. Only
        # synthetic fixture files exist and all Git/Docker calls are replaced.
        self.put(runner.NORMAL_RUNNER, b'# synthetic producer source\n')
        self.put(runner.CRATE + 'Cargo.lock', b'[[package]]\nname="catchplate-decision-gate"\nversion="0.1.0"\n')
        output = self.repo / ('job-root' if library_root else 'job'); output.mkdir()
        run = runner.HostedRun(self.repo, output, 'a' * 40)
        tree = b''.join(mode.encode() + b' blob ' + oid.encode() + b'\t' + name.encode() + b'\0'
                        for name, (mode, oid) in self.files.items())
        calls = []
        def command(label, argv, seconds, **kwargs):
            calls.append((label, argv))
            if label == 'revision': return 0, b'a' * 40 + b'\n'
            if label == 'git-inputs': return 0, tree
            if label == 'image': return 0, runner.IMAGE_ID.encode() + b'\n'
            self.assertIn(label, ('source-before', 'pull', 'source-after', 'provision-remaining', 'normal-remaining'))
            return 0, b''
        def container(phase, argv, seconds, **kwargs):
            self.assertIn(phase, ('provision', 'normal'))
            run.receipt['containers'].append({'phase': phase, 'removed': terminal,
                'cleanupUncertain': not terminal, 'exitCode': 0, 'oomKilled': False,
                'runningBeforeCleanup': False, 'token': phase})
            if phase == 'provision': return
            self.assertEqual(seconds, 1800)
            self.assertTrue(argv[-1].endswith('exec ' + runner.shlex.join(runner.NORMAL_COMMAND)))
            deps = output / 'target/release/deps'; deps.mkdir(parents=True)
            executable = output / 'target/release/catchplate-decision-gate'
            executable.write_bytes(self.elf()); executable.chmod(0o555)
            unit = deps / ('catchplate_decision_gate-' + '1' * 16); os.link(executable, unit)
            library = deps / ('libcatchplate_decision_gate-' + '2' * 16 + '.rlib')
            library.write_bytes(b'!<arch>\nsynthetic-only')
            if library_root:
                library = output / 'target/release/libcatchplate_decision_gate.rlib'
                library.write_bytes(b'!<arch>\nsynthetic-only')
            for kind, stem, source in (('binary', unit, 'main.rs'),
                ('library', deps / ('catchplate_decision_gate-' + '2' * 16), 'custody_protocol.rs')):
                target = '/' + stem.relative_to(output).as_posix()
                (Path(str(stem) + '.d')).write_text(target + '.d: src/' + source + '\n\nsrc/' + source + ':\n'
                    + ('\n# env-dep:CARGO_PKG_VERSION=0.1.0\n' if kind == 'binary' else ''))
            messages = self.cargo(); messages[1]['filenames'] = ['/' + library.relative_to(output).as_posix()]
            (run.results / 'normal.stdout.log').write_text('\n'.join(json.dumps(row) for row in messages))
            for name, value in (('normal-rustc.txt', 'rustc 1.88.0 (fixture)\nhost: x86_64-unknown-linux-gnu\n'),
                                ('normal-cargo.txt', 'cargo 1.88.0 (fixture)\n')):
                (run.results / name).write_text(value)
        run.command, run.container = command, container
        environment = {'GITHUB_SHA': 'a' * 40, 'GITHUB_JOB': 'normal-proxy', 'GITHUB_REPOSITORY': 'example/catchplate',
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_WORKFLOW_REF': 'example/catchplate/' + runner.NORMAL_WORKFLOW + '@refs/heads/main'}
        with patch.dict(os.environ, environment), patch.object(runner.os, 'statvfs', return_value=SimpleNamespace(
                f_bavail=10 * 1024**3, f_frsize=1)):
            if terminal:
                run.run_normal()
            else:
                with self.assertRaises(ValueError): run.run_normal()
        return run, calls

    def test_actual_producer_wiring_exports_only_two_public_files_after_cleanup(self):
        for library_root in (False, True):
            with self.subTest(library_root=library_root):
                run, calls = self.orchestrate(library_root=library_root)
                export = run.root / 'artifact'
                self.assertEqual({path.name for path in export.iterdir()}, {'catchplate-decision-gate', 'normal.json'})
                receipt = json.loads((export / 'normal.json').read_bytes())
                runner.verify_normal_receipt(receipt, (export / 'catchplate-decision-gate').read_bytes(), self.identity())
                self.assertEqual(receipt['compilerInputs']['library']['artifactPath'],
                                 '/target/release/deps/libcatchplate_decision_gate-' + '2' * 16 + '.rlib')
                self.assertEqual((export / 'catchplate-decision-gate').stat().st_mode & 0o777, 0o555)
                self.assertEqual([label for label, _ in calls][-3:], ['provision-remaining', 'normal-remaining', 'source-after'])
                self.assertEqual(receipt['sourceRevision'], 'a' * 40)
                self.assertFalse(receipt['tested'])
                self.assertTrue(run.receipt['normalProxyBinaryBuilt'])
                runner.save_normal_failure(run)
                self.assertFalse((run.root / 'normal-failure.json').exists())

    def test_actual_producer_wiring_refuses_export_on_uncertain_cleanup(self):
        run, _ = self.orchestrate(terminal=False)
        self.assertFalse((run.root / 'artifact').exists())
        self.assertFalse(run.receipt['normalProxyBinaryBuilt'])

    def test_failure_receipt_retains_observed_worker_state_and_no_private_metadata(self):
        for index, (code, oom, cleanup) in enumerate(((101, False, 'removed'), (137, True, 'removed'),
                (124, False, 'removed'), (101, False, 'remove-failed'), (101, False, 'inspect-failed'))):
            with self.subTest(code=code, oom=oom, cleanup=cleanup):
                output = self.repo / ('failure-' + str(index)); output.mkdir()
                run = runner.HostedRun(self.repo, output, 'a' * 40); run.normal_phase = 'normal'
                def command(label, argv, seconds, **kwargs):
                    exit_code = code if label == 'normal' else 1 if label == 'normal-' + cleanup.split('-')[0] and cleanup != 'removed' else 0
                    run.command_results.append({'command': label, 'exitCode': exit_code, 'reason': 'completed'})
                    if label == 'normal-create': return 0, b'c' * 64
                    if label == 'normal': return code, b'private compile output'
                    if label == 'normal-inspect':
                        if cleanup == 'inspect-failed': return 1, b''
                        return 0, json.dumps({'Id': 'c' * 64, 'Image': runner.IMAGE_ID,
                            'Labels': {runner.LABEL: 'private-token'},
                            'State': {'ExitCode': code, 'OOMKilled': oom, 'Running': False}}).encode()
                    self.assertEqual(label, 'normal-remove')
                    if cleanup == 'remove-failed': raise ValueError('private removal diagnostic')
                    return 0, b'c' * 64
                run.command = command
                with patch.object(runner.secrets, 'token_hex', return_value='private-token'), self.assertRaises(ValueError):
                    run.container('normal', ['private argv'], 1800)
                run.receipt.update(ok=False, error='private exception', pendingChildren=[{'pid': 999, 'command': 'private'}])
                runner.save_normal_failure(run)
                value = json.loads((output / 'normal-failure.json').read_bytes())
                self.assertEqual(set(value), {'schema', 'ok', 'sourceRevision', 'phase', 'normalBuildLimitSeconds',
                    'failedCommands', 'workers', 'pendingChildren', 'normalBinaryPublished', 'automaticRetry', 'cacheRestored'})
                self.assertEqual(value['phase'], 'normal'); self.assertEqual(value['pendingChildren'], 1)
                self.assertEqual(value['failedCommands'][0], {'command': 'normal', 'exitCode': code, 'reason': 'completed'})
                self.assertEqual(value['workers'], [{'phase': 'normal', 'limitSeconds': 1800,
                    'exitCode': None if cleanup == 'inspect-failed' else code,
                    'oomKilled': None if cleanup == 'inspect-failed' else oom,
                    'runningBeforeCleanup': None if cleanup == 'inspect-failed' else False,
                    'removed': cleanup == 'removed', 'cleanupUncertain': cleanup != 'removed'}])
                self.assertNotIn('private', json.dumps(value)); self.assertNotIn('c' * 64, json.dumps(value))
                self.assertFalse(value['normalBinaryPublished']); self.assertFalse((output / 'artifact').exists())

    def test_failure_command_timeout_disk_floor_and_pending_are_direct_observations(self):
        for reason in ('timeout', 'disk_floor', 'pending_child'):
            with self.subTest(reason=reason):
                output = self.repo / reason; output.mkdir()
                run = runner.HostedRun(self.repo, output, 'a' * 40); run.normal_phase = 'normal'
                class Child:
                    pid = 999999999
                    code = None
                    def poll(self): return self.code
                    def kill(self): self.code = -9
                    def wait(self, timeout):
                        if reason == 'pending_child': raise runner.subprocess.TimeoutExpired('private argv', timeout)
                        return self.code
                with patch.object(runner.subprocess, 'Popen', return_value=Child()), \
                        patch.object(runner.time, 'monotonic', side_effect=[0, 0 if reason == 'disk_floor' else 2, 2]), \
                        patch.object(runner.os, 'statvfs', return_value=SimpleNamespace(
                            f_bavail=0 if reason == 'disk_floor' else 10 * 1024**3, f_frsize=1)), self.assertRaises(ValueError):
                    run.command('normal', ['private argv'], 1)
                run.receipt['ok'] = False
                value = runner.normal_failure_receipt(run)
                self.assertEqual(value['failedCommands'], [{'command': 'normal',
                    'exitCode': None if reason == 'pending_child' else -9, 'reason': reason}])
                self.assertEqual(value['pendingChildren'], int(reason == 'pending_child'))
                self.assertNotIn('private', json.dumps(value)); self.assertNotIn('999999999', json.dumps(value))

    def test_failure_projection_refuses_unknown_public_scope_and_success(self):
        output = self.repo / 'closed-failure'; output.mkdir()
        run = runner.HostedRun(self.repo, output, 'a' * 40); run.receipt['ok'] = False
        run.command_results = [{'command': '/private/path', 'exitCode': 1, 'reason': 'completed'}]
        with self.assertRaises(ValueError): runner.normal_failure_receipt(run)
        run.command_results = []; run.normal_phase = 'private diagnostic'
        with self.assertRaises(ValueError): runner.normal_failure_receipt(run)
        run.normal_phase = 'prepare'; run.receipt['ok'] = True
        with self.assertRaises(ValueError): runner.normal_failure_receipt(run)


if __name__ == '__main__':
    unittest.main()
