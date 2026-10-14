#!/usr/bin/env python3
"""Pure receipt-parser controls only; no Rust, Docker, or native authority."""
import importlib.util
import json
from pathlib import Path
import unittest

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
        return {'reason': 'compiler-artifact', 'target': {'name': 'serverware_decision_gate', 'kind': ['lib'],
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


if __name__ == '__main__':
    unittest.main()
