"""Inert managed-X recipe and complete dependency-tree controls.

No SDK, app, socket, subprocess, container or provider is executed. Synthetic
temporary files exercise the actual inventory and exact recipe validator.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_operator_x_post_fixture as recipe


SOURCE, BINARY, INITIALIZER = (Path('/synthetic/' + name) for name in ('source', 'gate', 'initialize.py'))
NODE = Path('/home/catchplate/.nvm/versions/node/v25.5.0/bin/node')
JOB = Path('/srv/catchplate-fast/tmp/serverware-x-post-private.abcdef12')
MODULES, PYTHON, PACKAGES, GO = (Path('/synthetic/' + name) for name in ('node_modules', 'python', 'packages', 'x-post'))
ARGS = (SOURCE, BINARY, INITIALIZER, JOB, NODE, MODULES, PYTHON, PACKAGES, GO)
PINS = dict(expected_binary_sha256='a' * 64, expected_go_sha256='b' * 64,
    expected_dependencies_sha256='c' * 64)


class InertTests(unittest.TestCase):
    def setUp(self):
        for name in ('socket.socket', 'socket.create_connection', 'socket.getaddrinfo',
                'subprocess.Popen', 'subprocess.run'):
            self.enterContext(patch(name, side_effect=AssertionError('runtime I/O forbidden in pure controls')))


class RecipeTests(InertTests):
    def setUp(self):
        super().setUp()
        self.config = recipe.build(*ARGS, **PINS)

    def test_closed_service_roster_network_and_original_resource_bounds(self):
        self.assertEqual(set(self.config), {'name', 'services'})
        self.assertEqual(recipe.RUNTIME_SERVICES, {'network', 'provider', 'serverware', 'decision-gate-rs', 'edge', 'check'})
        self.assertEqual(set(self.config['services']), recipe.RUNTIME_SERVICES | {'initialize', 'x-post-pki', 'basic-pki'})
        for name, service in self.config['services'].items():
            self.assertEqual(service['network_mode'], 'none' if name in
                {'initialize', 'x-post-pki', 'basic-pki', 'network'} else 'service:network')
            for forbidden in ('ports', 'expose', 'networks', 'extra_hosts', 'dns', 'privileged',
                    'devices', 'pid', 'ipc', 'env_file', 'volumes_from'):
                self.assertNotIn(forbidden, service)
            self.assertTrue(service['read_only'])
            self.assertEqual(service['pull_policy'], 'never')
            self.assertEqual(service['restart'], 'no')
            self.assertEqual(service['cap_drop'], ['ALL'])
            self.assertIn('no-new-privileges:true', service['security_opt'])
            self.assertNotIn('HOME', service.get('environment', {}))
            self.assertLessEqual(service['cpus'], 2)
            self.assertLessEqual(service['pids_limit'], 128)
            self.assertEqual(service['mem_limit'], service['memswap_limit'])
            self.assertIn(service['mem_limit'], {'64m', '128m', '256m', '512m', '1g'})
            targets = [row['target'] for row in service['volumes']]
            self.assertEqual(len(targets), len(set(targets)))
            self.assertTrue(all(not row['bind']['create_host_path'] for row in service['volumes']))

    def test_managed_app_only_custody_and_original_curated_gate_leaf_binds(self):
        app, gate = (self.config['services'][name] for name in ('serverware', 'decision-gate-rs'))
        env = app['environment']
        self.assertEqual(env['SERVERWARE_PUBLIC_URL'], 'https://serverware-x.example.com')
        self.assertEqual(env['SERVERWARE_OPERATOR_MANAGED_X_ENABLED'], '1')
        self.assertEqual(env['SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED'], '1')
        self.assertEqual(env['SSL_CERT_FILE'], '/x-public/ca.pem')
        self.assertEqual(env['SERVERWARE_OPERATOR_X_CUSTODY_DIR'], '/x-custody')
        for key in ('SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED', 'SERVERWARE_KEY_RELEASE_REQUIRED',
                'SERVERWARE_DEV_AUTHENTICATOR', 'SERVERWARE_DEV_DEMO_SEED'):
            self.assertEqual(env[key], '0')
        self.assertEqual(app['depends_on'], {'provider': {'condition': 'service_healthy'}})
        custody = [(name, row) for name, service in self.config['services'].items()
            for row in service['volumes'] if row['target'] == '/x-custody']
        self.assertEqual(len(custody), 1)
        self.assertEqual(custody[0][0], 'serverware')
        self.assertEqual(custody[0][1]['source'], str(JOB / 'runtime/x-custody'))
        self.assertFalse(custody[0][1]['read_only'])
        gate_data = {row['target']: row for row in gate['volumes'] if row['target'].startswith('/data')}
        self.assertEqual(set(gate_data), {'/data'} | {'/data/' + leaf for leaf in recipe.LEAVES})
        self.assertEqual(gate_data['/data']['source'], str(JOB / 'runtime/app-data/gate-runtime'))
        for leaf in recipe.LEAVES:
            self.assertEqual(gate_data['/data/' + leaf]['source'], str(JOB / 'runtime/app-data' / leaf))
        self.assertTrue(all(row['read_only'] for row in gate_data.values()))
        self.assertEqual(gate['environment']['SERVERWARE_OPERATOR_MANAGED_X_ENABLED'], '1')

    def test_provider_private_observations_and_fixed_public_tls_paths(self):
        provider = self.config['services']['provider']
        mounts = {row['target']: row for row in provider['volumes']}
        self.assertEqual(mounts['/x']['source'], str(JOB / 'runtime/upstream-data/x'))
        self.assertFalse(mounts['/x']['read_only'])
        self.assertFalse(any(target.startswith('/x/') for target in mounts))
        self.assertEqual(provider['command'], ['python', '-B', '-m', 'scripts.operator_x_post_fixture', '--lifetime-seconds', '300'])
        self.assertIn('https://api.x.com/__test__/observations', provider['healthcheck']['test'][-1])
        self.assertEqual(self.config['services']['initialize']['command'],
            ['python', '-B', '-m', 'scripts.operator_x_post_fixture_network', 'initialize'])
        self.assertEqual(self.config['services']['x-post-pki']['command'],
            ['python', '-B', '-m', 'scripts.operator_x_post_fixture', '--setup'])
        self.assertEqual((recipe.INITIAL_TOKEN_SECONDS, recipe.CHECKER_SECONDS, recipe.KEEPER_SECONDS,
            recipe.EDGE_SECONDS, recipe.CHECKER_OUTER_SECONDS, recipe.PRECHECK_SECONDS), (120, 180, 300, 240, 210, 75))
        self.assertEqual(recipe.PRECHECK_SECONDS + recipe.CHECKER_OUTER_SECONDS + 15, recipe.KEEPER_SECONDS)

    def test_stock_posting_entrypoints_dependencies_and_distinct_tls_roots(self):
        check = self.config['services']['check']
        self.assertEqual(check['image'], recipe.PYTHON_IMAGE)
        self.assertEqual(check['user'], '10001:10001')
        self.assertEqual(check['entrypoint'], ['/example-python/bin/python', '-B'])
        self.assertEqual(check['command'][0], '/app/scripts/check_operator_x_post.py')
        flags = dict(zip(check['command'][1::2], check['command'][2::2]))
        self.assertEqual(flags['--control-base'], 'https://serverware-x.example.com')
        self.assertEqual(flags['--operator-origin'], flags['--control-base'])
        self.assertEqual(flags['--proxy-url'], 'https://proxy.operator-basic.example.test:8443')
        self.assertEqual(flags['--timeout-seconds'], '180')
        self.assertEqual(flags['--expected-binary-sha256'], 'sha256:' + 'a' * 64)
        self.assertEqual(flags['--expected-go-sha256'], 'b' * 64)
        self.assertEqual(flags['--expected-dependencies-sha256'], 'c' * 64)
        self.assertEqual(flags['--ca-file'], '/client-trust/inner-ca.pem')
        self.assertEqual(flags['--proxy-ca-file'], '/client-trust/outer-ca.pem')
        self.assertEqual(flags['--control-ca-file'], '/x-public/ca.pem')
        mounts = {row['target']: row for row in check['volumes']}
        for source, target in ((MODULES, '/app/examples/x-post-node/node_modules'), (PYTHON, '/example-python'),
                (PACKAGES, '/example-python/lib/python3.12/site-packages'), (GO, '/example-go/x-post'),
                (NODE, '/node'), (JOB / 'dependencies.json', '/client-dependencies.json')):
            self.assertEqual(mounts[target]['source'], str(source))
            self.assertTrue(mounts[target]['read_only'])
        self.assertNotIn('x-username', json.dumps(check))
        self.assertNotIn('/x-custody', mounts)
        self.assertNotIn('/data', mounts)

    def test_actual_production_origin_admission_and_closed_fixture_consistency(self):
        # The production validator is pure; do not patch it, activate the app,
        # initialize state or resolve the public-form fixture hostname.
        from serverware import operator_demo
        from scripts import operator_x_post_fixture_network as network
        from scripts import operator_x_post_fixture as provider
        from scripts import check_operator_x_post as checker
        self.assertEqual(operator_demo.origin(recipe.CONTROL_ORIGIN),
            ('https://serverware-x.example.com', '/'))
        with self.assertRaises(ValueError):
            operator_demo.origin('https://serverware-x.example.test')
        self.assertEqual(recipe.CONTROL_ORIGIN, network.CONTROL_ORIGIN)
        self.assertEqual(recipe.CONTROL_ORIGIN, checker.CONTROL)
        self.assertEqual(network.CONTROL_HOST, 'serverware-x.example.com')
        self.assertEqual(provider.CALLBACK_URL, recipe.CONTROL_ORIGIN + checker.CALLBACK)
        mapping = {host: row[0] for row in (line.split() for line in network.HOSTS.decode().splitlines())
            for host in row[1:]}
        self.assertEqual(mapping[network.CONTROL_HOST], '127.0.0.1')
        self.assertNotIn('serverware-x.example.test', mapping)
        self.assertEqual(mapping['api.x.com'], '93.184.216.34')
        self.assertEqual(mapping['x.com'], '93.184.216.34')
        self.assertEqual(network.PROXY_HOST, 'proxy.operator-basic.example.test')
        self.assertEqual(mapping[network.PROXY_HOST], '127.0.0.1')
        state = 's' * 43
        location = provider.CALLBACK_URL + '?code=synthetic-code&state=' + state
        self.assertEqual(checker.callback_target([('Location', location)], state)[1], 'synthetic-code')
        with self.assertRaises(checker.CheckFailure):
            checker.callback_target([('Location', location.replace('.example.com', '.example.test'))], state)

    def test_exact_recomputation_rejects_any_recipe_drift(self):
        recipe.validate(self.config, *ARGS, **PINS)
        changes = [lambda c: c['services']['check'].update(network_mode='host'),
            lambda c: c['services']['check'].update(ports=['8443:8443']),
            lambda c: c['services']['check']['command'].__setitem__(-1, '181'),
            lambda c: c['services']['check']['environment'].update(HOME='/tmp'),
            lambda c: c['services']['decision-gate-rs']['volumes'][-1].update(read_only=False),
            lambda c: c['services']['decision-gate-rs']['volumes'].append(
                deepcopy(c['services']['serverware']['volumes'][-2])),
            lambda c: c['services']['provider']['command'].__setitem__(-1, '301'),
            lambda c: c['services']['serverware']['environment'].update(SERVERWARE_OPERATOR_MANAGED_X_ENABLED='0')]
        for index, change in enumerate(changes):
            changed = deepcopy(self.config); change(changed)
            with self.subTest(index=index), self.assertRaises(ValueError): recipe.validate(changed, *ARGS, **PINS)

    def test_exact_new_root_absolute_paths_and_bare_pins_required(self):
        for key in PINS:
            for invalid in (None, True, 'a' * 63, 'A' * 64, 'sha256:' + 'a' * 64):
                changed = dict(PINS); changed[key] = invalid
                with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError): recipe.build(*ARGS, **changed)
        for invalid in (Path('/tmp') / JOB.name, JOB.with_name('serverware-x-private.abcdef12')):
            with self.assertRaises(ValueError): recipe.build(*ARGS[:3], invalid, *ARGS[4:], **PINS)
        for index in (0, 1, 2, 4, 5, 6, 7, 8):
            changed = list(ARGS); changed[index] = Path('/synthetic/../different')
            with self.subTest(index=index), self.assertRaises(ValueError): recipe.build(*changed, **PINS)


class InventoryTests(InertTests):
    def setUp(self):
        super().setUp()
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary).resolve(); self.root.chmod(0o755)

    def write(self, relative, content=b'synthetic bytes\n'):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == self.root or parent.is_relative_to(self.root): parent.chmod(0o755)
        path.write_bytes(content); path.chmod(0o644)
        return path

    def test_complete_modes_directory_roster_bytes_and_canonical_hash(self):
        entry = self.write('package/index.js')
        observed = recipe.tree_inventory(self.root, kind='node')
        expected = {'files': {'package/index.js': {'size': 16, 'sha256': hashlib.sha256(entry.read_bytes()).hexdigest(),
            'mode': 0o644}}, 'directories': {'.': 0o755, 'package': 0o755}, 'symlinks': {}}
        self.assertEqual(observed, expected)
        self.assertEqual(recipe.dependencies_sha256(observed), hashlib.sha256(json.dumps(expected,
            sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest())
        entry.chmod(0o444)
        self.assertNotEqual(recipe.dependencies_sha256(recipe.tree_inventory(self.root, kind='node')),
            recipe.dependencies_sha256(observed))
        entry.chmod(0o644); (self.root / 'empty').mkdir(mode=0o755)
        self.assertNotEqual(recipe.tree_inventory(self.root, kind='node'), observed)
        (self.root / 'empty').rmdir(); entry.write_bytes(b'different bytes\n')
        self.assertNotEqual(recipe.tree_inventory(self.root, kind='node'), observed)

    def test_node_links_are_only_relative_internal_bin_files_and_python_has_none(self):
        self.write('package/index.js'); link = self.root / '.bin/tool'
        link.parent.mkdir(mode=0o755); link.symlink_to('../package/index.js')
        self.assertEqual(recipe.tree_inventory(self.root, kind='node')['symlinks'],
            {'.bin/tool': {'target': '../package/index.js', 'mode': 0o777}})
        with self.assertRaises(ValueError): recipe.tree_inventory(self.root, kind='python')
        for target in ('/etc/passwd', '../../outside', '../package/missing', '../package'):
            link.unlink(); link.symlink_to(target)
            with self.subTest(target=target), self.assertRaises((ValueError, OSError)):
                recipe.tree_inventory(self.root, kind='node')

    def test_hardlinks_unreadable_root_alias_and_git_entries_are_refused(self):
        entry = self.write('entry'); hard = self.root / 'hard'; os.link(entry, hard)
        with self.assertRaises(ValueError): recipe.tree_inventory(self.root, kind='node')
        hard.unlink(); entry.chmod(0o600)
        with self.assertRaises(ValueError): recipe.tree_inventory(self.root, kind='node')
        entry.chmod(0o644); self.root.chmod(0o700)
        with self.assertRaises(ValueError): recipe.tree_inventory(self.root, kind='node')
        self.root.chmod(0o755); (self.root / '.git').mkdir()
        with self.assertRaises(ValueError): recipe.tree_inventory(self.root, kind='node')
        (self.root / '.git').rmdir(); alias = self.root / 'alias'; alias.symlink_to(self.root)
        with self.assertRaises(ValueError): recipe.tree_inventory(alias, kind='node')

    def test_complete_runtime_requires_only_exact_four_declared_links(self):
        self.write('runtime/pyvenv.cfg', b'version = 3.12.14\n')
        self.write('runtime/lib/.fixture'); runtime = self.root / 'runtime'
        (runtime / 'bin').mkdir(mode=0o755)
        for name, target in recipe.RUNTIME_LINKS.items(): (runtime / name).symlink_to(target)
        actual = recipe.tree_inventory(runtime, kind='runtime')
        self.assertEqual({name: row['target'] for name, row in actual['symlinks'].items()}, {
            'bin/python': '/usr/local/bin/python', 'bin/python3': 'python', 'bin/python3.12': 'python', 'lib64': 'lib'})
        (runtime / 'bin/python3').unlink()
        with self.assertRaises(ValueError): recipe.tree_inventory(runtime, kind='runtime')
        (runtime / 'bin/python3').symlink_to('/usr/bin/python3')
        with self.assertRaises(ValueError): recipe.tree_inventory(runtime, kind='runtime')

    def test_actual_dependency_identity_and_full_runtime_file_bytes_are_bound(self):
        for name, version in recipe.profiles.NODE_DEPENDENCIES.items():
            self.write('node/' + name + '/package.json', json.dumps({'name': name, 'version': version}).encode())
        for name, version in recipe.PYTHON_VERSIONS.items():
            self.write('packages/' + name + '.dist-info/METADATA', ('Name: ' + name + '\nVersion: ' + version + '\n').encode())
        self.write('runtime/pyvenv.cfg', b'version = 3.12.14\n'); self.write('runtime/bin/activate')
        (self.root / 'runtime/lib').mkdir(mode=0o755)
        for name, target in recipe.RUNTIME_LINKS.items(): (self.root / 'runtime' / name).symlink_to(target)
        args = (self.root / 'node', self.root / 'runtime', self.root / 'packages')
        observed = recipe.dependencies(*args)
        self.assertEqual(set(observed), {'schema', 'node', 'python', 'pythonRuntime'})
        self.assertEqual(observed['schema'], 'serverware.privateXPostDependencies/v1')
        self.write('runtime/bin/activate', b'changed, still never executed\n')
        self.assertNotEqual(recipe.dependencies_sha256(recipe.dependencies(*args)), recipe.dependencies_sha256(observed))
        self.write('node/undici/package.json', b'{"name":"undici","version":"0.0.0"}')
        with self.assertRaises(ValueError): recipe.dependencies(*args)


if __name__ == '__main__':
    unittest.main()
