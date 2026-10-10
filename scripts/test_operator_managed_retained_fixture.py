#!/usr/bin/env python3
"""Pure recipe/temporary-copy tests; no containers, app startup or network.

The source archive, executable, database and tokens here are synthetic. Passing
these tests does not establish real namespace isolation or retained startup.
"""
from copy import deepcopy
import ast
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_operator_managed_retained_fixture as fixture
from scripts import check_operator_managed_retained_fixture as checker


SOURCE = Path('/synthetic/source')
BINARY = Path('/synthetic/serverware-decision-gate')
BINARY_SHA = '1' * 64
ROOT = fixture.base.SCRATCH / 'serverware-managed-retained-private.Unit001'


class RecipeTests(unittest.TestCase):
    def setUp(self):
        self.config = fixture.build(SOURCE, BINARY, ROOT, expected_binary_sha256=BINARY_SHA)
        self.services = self.config['services']

    def test_three_services_only_without_initializer_provider_upstream_or_external_network(self):
        self.assertEqual(set(self.config), {'name', 'services'})
        self.assertEqual(set(self.services), {'serverware', 'decision-gate-rs', 'network'})
        self.assertEqual({name: service['image'] for name, service in self.services.items()},
            {'serverware': fixture.base.APP_IMAGE, 'decision-gate-rs': fixture.base.GATE_IMAGE, 'network': fixture.base.GATE_IMAGE})
        self.assertEqual(self.config, fixture.build(SOURCE, BINARY, ROOT, expected_binary_sha256=BINARY_SHA))
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertEqual(service['network_mode'], 'none' if name == 'network' else 'service:network')
                for field in ('ports', 'networks', 'dns', 'privileged', 'devices', 'pid', 'ipc', 'env_file', 'extends', 'profiles'):
                    self.assertNotIn(field, service)
                self.assertEqual(service['pull_policy'], 'never')
                self.assertEqual(service['restart'], 'no')
                self.assertTrue(service['read_only'])
                self.assertEqual(service['cap_drop'], ['ALL'])
                self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
                self.assertEqual(service['mem_limit'], service['memswap_limit'])
                self.assertLessEqual(service['cpus'], 2)
                self.assertLessEqual(service['pids_limit'], 128)
                self.assertEqual(service['labels']['traefik.enable'], 'false')
        self.assertEqual(self.services['serverware']['command'], ['python', '-B', '-m', 'serverware.operator_demo_runner'])
        self.assertEqual(self.services['decision-gate-rs']['entrypoint'], ['/usr/local/bin/serverware-decision-gate'])

    def test_retained_addresses_metadata_urls_and_unconfigured_manifest(self):
        self.assertEqual(fixture.ADDRESSES, ('172.16.249.18', '172.16.249.19', '172.16.249.20'))
        self.assertEqual(fixture.HOSTS.decode().splitlines(), ['127.0.0.1 localhost',
            '172.16.249.18 demo-upstream', '172.16.249.19 serverware', '172.16.249.20 decision-gate-rs'])
        self.assertEqual(fixture.RESOLV, b'nameserver 127.0.0.1\noptions attempts:1 timeout:1\n')
        manifest = fixture.manifest()
        self.assertEqual(set(manifest), {'schema', 'operation', 'profile_binding', 'profile_binding_digest',
            'effective_settings', 'effective_settings_digest'})
        self.assertEqual(manifest['schema'], 'serverware.operatorGoogleGateConfiguration/v1')
        self.assertIsNone(manifest['operation'])
        self.assertIsNone(manifest['profile_binding'])
        self.assertIsNone(manifest['profile_binding_digest'])
        self.assertEqual(manifest['effective_settings_digest'], 'sha256:' + fixture.snapshots.digest(manifest['effective_settings']))
        for name in ('serverware', 'decision-gate-rs'):
            env = self.services[name]['environment']
            self.assertEqual(json.loads(env['SERVERWARE_OPERATOR_DEMO_UPSTREAMS']), manifest['effective_settings']['allowed_upstreams'])
            self.assertEqual(json.loads(env['SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS']), manifest['effective_settings']['fixture_cidrs'])
            self.assertEqual(env['SERVERWARE_OPERATOR_DEMO_PROXY_URL'], 'https://serverware-proxy.example.com:443')
            self.assertEqual(env['SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED'], '1')
        app = self.services['serverware']['environment']
        self.assertEqual(app['SERVERWARE_PUBLIC_URL'], 'https://serverware-demo.example.com')
        self.assertEqual(app['SERVERWARE_DECISION_GATE_BASE'], 'http://decision-gate-rs:9091')
        self.assertEqual(app['SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST'], 'sha256:' + BINARY_SHA)
        gate = self.services['decision-gate-rs']['environment']
        for field, suffix in (('SERVERWARE_POLICY_TRUST_ROOT_ATTESTATION_URL', '/attestation'),
                ('SERVERWARE_CONTROL_PLANE_CREDENTIAL_LEASE_URL', '/api/data-plane/credential-leases'),
                ('SERVERWARE_CONTROL_PLANE_AUDIT_URL', '/api/data-plane/audit')):
            self.assertEqual(gate[field], 'http://serverware:3000' + suffix)
        self.assertEqual(gate['SERVERWARE_DECISION_GATE_MANAGEMENT_HOST'], fixture.ADDRESSES[2])
        self.assertEqual(gate['SERVERWARE_DATA_PLANE_AUDIT_BATCH_MAX'], '1')
        self.assertNotIn('SERVERWARE_DATA_PLANE_AUDIT_QUEUE_MAX', gate)

    def test_notifications_on_and_managed_admission_have_no_provider_or_native_binding(self):
        env = self.services['serverware']['environment']
        for name in ('SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED', 'SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED'):
            self.assertEqual(env[name], '1')
        for name in ('SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED', 'SERVERWARE_KEY_RELEASE_REQUIRED',
                'SERVERWARE_DEV_AUTHENTICATOR', 'SERVERWARE_DEV_DEMO_SEED'):
            self.assertEqual(env[name], '0')
        for name in ('SERVERWARE_METADATA_STORE_BACKEND', 'SERVERWARE_AUDIT_STORE_BACKEND', 'SERVERWARE_GRANT_STORE_BACKEND'):
            self.assertEqual(env[name], 'sqlite')
        self.assertEqual(env['SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR'], '/provider-custody')
        self.assertEqual(env['SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR'], '/notification-custody')
        self.assertEqual(env['SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON'], '{"bindings":[]}')
        for service in self.services.values():
            keys = service.get('environment', {})
            self.assertFalse(any('CLIENT_SECRET' in name or 'GOOGLE_CLIENT' in name or 'PILOT_SOURCE' in name
                or 'WEBHOOK' in name or 'SLACK' in name or name.startswith('PRIVATE_OPERATOR_') for name in keys))

    def test_curated_gate_mounts_exclude_all_application_and_custody_authority(self):
        gate = {row['target']: row for row in self.services['decision-gate-rs']['volumes']}
        self.assertEqual(gate['/data']['source'], str(ROOT / 'runtime/app-data/gate-runtime'))
        self.assertTrue(gate['/data']['read_only'])
        for leaf in fixture.LEAVES:
            row = gate['/data/' + leaf]
            self.assertEqual(row['source'], str(ROOT / 'runtime/app-data' / leaf))
            self.assertTrue(row['read_only'])
        app = {row['target']: row for row in self.services['serverware']['volumes']}
        for target, relative in (('/data', 'runtime/app-data'), ('/provider-custody', 'provider-custody'),
                ('/notification-custody', 'notification-custody')):
            self.assertEqual(app[target]['source'], str(ROOT / relative))
            self.assertFalse(app[target]['read_only'])
        self.assertNotIn('/private-audit-fixture.json', app)
        for target in ('/provider-custody', '/notification-custody', '/run/secrets/serverware/admin.token'):
            self.assertNotIn(target, gate)
        for service in self.services.values():
            for row in service['volumes']:
                self.assertEqual(row['type'], 'bind')
                self.assertEqual(row['bind'], {'create_host_path': False})
                source = Path(row['source'])
                self.assertTrue(source in (SOURCE, BINARY) or source.is_relative_to(ROOT))
                if source in (SOURCE, BINARY):
                    self.assertTrue(row['read_only'])
        for row in gate.values():
            self.assertNotIn(Path(row['source']), (ROOT / 'runtime/app-data', ROOT / 'provider-custody', ROOT / 'notification-custody'))
        self.assertEqual({row['target'] for row in gate.values() if not row['read_only']}, {'/gate-data'})

    def test_network_keeper_is_bounded_and_cannot_mount_private_state(self):
        keeper = self.services['network']
        self.assertEqual(keeper['network_mode'], 'none')
        self.assertEqual(keeper['user'], '0:0')
        self.assertFalse(keeper['init'])
        self.assertEqual(keeper['cap_add'], ['NET_ADMIN', 'SETUID', 'SETGID'])
        self.assertEqual(keeper['pids_limit'], 16)
        self.assertEqual(keeper['cpus'], 0.25)
        self.assertEqual(keeper['sysctls'], {'net.ipv4.ip_nonlocal_bind': '0'})
        self.assertEqual(keeper['command'], ['python', '-B', '-m', 'scripts.check_operator_managed_retained_fixture', 'network'])
        self.assertEqual({row['target'] for row in keeper['volumes']}, {'/app', '/etc/hosts', '/etc/resolv.conf'})
        self.assertTrue(all(row['read_only'] for row in keeper['volumes']))
        self.assertEqual(fixture.KEEPER_SECONDS, 600)
        self.assertEqual(self.services['serverware']['depends_on'], {'network': {'condition': 'service_healthy'}})
        self.assertEqual(self.services['decision-gate-rs']['depends_on'], {'serverware': {'condition': 'service_healthy'}})
        for name in ('serverware', 'decision-gate-rs'):
            self.assertEqual(self.services[name]['user'], '10001:10001')
            self.assertNotIn('cap_add', self.services[name])

    def test_job_paths_and_binary_pin_are_closed(self):
        for root in (Path('/tmp/serverware-managed-retained-private.Unit001'), ROOT / 'child',
                ROOT.with_name('serverware-managed-retained-private.short'), ROOT.with_name('serverware-catalog-private.Unit001')):
            with self.subTest(root=str(root)), self.assertRaises(ValueError):
                fixture.build(SOURCE, BINARY, root, expected_binary_sha256=BINARY_SHA)
        for digest in ('', 'sha256:' + BINARY_SHA, 'A' * 64, '1' * 63):
            with self.subTest(length=len(digest)), self.assertRaises(ValueError):
                fixture.build(SOURCE, BINARY, ROOT, expected_binary_sha256=digest)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='managed-retained-pure-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(patch.stopall)
        patch.object(fixture.base, 'SCRATCH', self.root).start()
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o755)
        self.source.chmod(0o755)
        names = {fixture.CHECKER, fixture.PREPARER, 'scripts/operator_rollout_snapshot.py',
            fixture.basic.CHECKER, fixture.basic.SETUP, fixture.basic.RELAY,
            'scripts/demo_upstream.py', 'scripts/operator_ordinary_client_fixture.py'}
        hashes = {}
        for name in names:
            filename = self.source / name
            filename.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            filename.parent.chmod(0o755)
            raw = b'# inert synthetic source asset\n'
            filename.write_bytes(raw)
            filename.chmod(0o444)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        self.binary = self.root / 'synthetic-binary'
        self.binary.write_bytes(b'not an executable; pure inventory fixture')
        self.binary.chmod(0o444)
        self.manifest = self.root / 'source-manifest.json'
        self.manifest.write_text(json.dumps({'schema': 'serverware.privateProxyBasicSource/v1',
            'sourceCommit': '2' * 40, 'files': hashes}, sort_keys=True))
        self.historical = self.root / 'historical.json'
        self.historical.write_text('{}')
        self.job = self.root / 'serverware-managed-retained-private.Unit001'
        self.job.mkdir(mode=0o700)
        self.args = SimpleNamespace(job_root=self.job, source=self.source, binary=self.binary,
            source_manifest=self.manifest, expected_source_manifest_sha256=fixture.base.digest(self.manifest),
            expected_source_commit='2' * 40, expected_binary_sha256=fixture.base.digest(self.binary),
            retained_inventory=self.historical, expected_retained_inventory_sha256=fixture.base.digest(self.historical),
            write=False, verify_prepared=False, preflight=False, private_copies_acknowledged=False)

    def write(self):
        self.args.write = True
        result = fixture.prepare(self.args)
        self.args.write = False
        return result

    def synthetic_state(self):
        runtime = self.job / 'runtime'
        data = runtime / 'app-data'
        data.mkdir(mode=0o700, parents=True)
        runtime.chmod(0o700)
        for name in ('notification-custody', 'provider-custody'):
            (self.job / name).mkdir(mode=0o700)
        database = data / 'serverware.sqlite3'
        with sqlite3.connect(database) as connection:
            connection.execute('CREATE TABLE audit_events(event_type TEXT)')
            connection.execute('CREATE TABLE operator_demo_settings(singleton INTEGER PRIMARY KEY,settings_json TEXT)')
            connection.execute('INSERT INTO operator_demo_settings VALUES(1,?)', (json.dumps(fixture.SETTINGS, sort_keys=True),))
            connection.execute('CREATE TABLE operator_catalog_credentials(data_json TEXT)')
            connection.execute('INSERT INTO operator_catalog_credentials VALUES(?)', ('{"auth_type":"bearer"}',))
            connection.execute('CREATE TABLE operator_demo_policy(singleton INTEGER PRIMARY KEY,signed_bundle_json TEXT)')
            connection.execute('INSERT INTO operator_demo_policy VALUES(1,?)', ('synthetic retained policy',))
        database.chmod(0o600)
        policy = data / 'policy-bundle.json'
        policy.write_bytes(b'synthetic retained policy')
        policy.chmod(0o600)
        historical = fixture.snapshots.inventory(runtime, self.job / 'notification-custody')
        self.historical.write_text(json.dumps(historical, sort_keys=True))
        self.args.expected_retained_inventory_sha256 = fixture.base.digest(self.historical)
        return database, historical

    def test_default_no_write_then_exact_four_public_outputs_and_verify(self):
        result = fixture.prepare(self.args)
        self.assertEqual(list(self.job.iterdir()), [])
        self.assertFalse(result['automatic_execution'])
        self.assertFalse(result['initializer'])
        self.assertFalse(result['provider_service'])
        self.assertTrue(result['notifications_enabled'])
        self.write()
        self.assertEqual({path.name for path in self.job.iterdir()}, {'compose.json', 'preparation.json', 'hosts', 'resolv.conf'})
        for path in self.job.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o444 if path.name in {'hosts', 'resolv.conf'} else 0o600)
        self.args.verify_prepared = True
        self.assertEqual(fixture.prepare(self.args), result)
        self.assertEqual(json.loads((self.job / 'compose.json').read_text()),
            fixture.build(self.source, self.binary, self.job, expected_binary_sha256=self.args.expected_binary_sha256))

    def test_write_refuses_nonempty_job_including_symlink_and_never_overwrites(self):
        sentinel = self.job / 'retained-private-sentinel'
        sentinel.write_bytes(b'preserve')
        self.args.write = True
        with self.assertRaises(ValueError):
            fixture.prepare(self.args)
        self.assertEqual(sentinel.read_bytes(), b'preserve')
        self.assertEqual({path.name for path in self.job.iterdir()}, {sentinel.name})
        sentinel.unlink()
        sentinel.symlink_to(self.binary)
        with self.assertRaises(ValueError):
            fixture.prepare(self.args)
        self.assertTrue(sentinel.is_symlink())

    def test_write_requires_current_owner_without_restricting_readonly_root_observation(self):
        self.args.write = True
        original = Path.stat

        def foreign_owner(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == self.job:
                fields = list(info)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return info

        with patch.object(Path, 'stat', foreign_owner), self.assertRaises(ValueError):
            fixture.prepare(self.args)
        self.assertEqual(list(self.job.iterdir()), [])

    def test_prepared_recipe_rejects_added_service_ports_egress_and_private_gate_mounts(self):
        self.write()
        self.args.verify_prepared = True
        filename = self.job / 'compose.json'
        original = filename.read_bytes()
        controls = (
            lambda value: value['services'].update(provider=deepcopy(value['services']['network'])),
            lambda value: value['services']['serverware'].update(ports=['3000:3000']),
            lambda value: value['services']['network'].update(network_mode='host'),
            lambda value: value['services']['decision-gate-rs'].update(cap_add=['NET_ADMIN']),
            lambda value: value['services']['decision-gate-rs']['volumes'].append(
                fixture.base.bind(self.job / 'runtime/app-data', '/private-data')),
            lambda value: value['services']['serverware']['environment'].update(SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED='0'),
        )
        for index, control in enumerate(controls):
            value = json.loads(original)
            control(value)
            filename.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
            with self.subTest(control=index), self.assertRaises(ValueError):
                fixture.prepare(self.args)
        filename.write_bytes(original)
        self.assertTrue(fixture.prepare(self.args)['ok'])

    def test_source_binary_and_historical_pins_cannot_drift(self):
        for field in ('expected_binary_sha256', 'expected_source_manifest_sha256', 'expected_retained_inventory_sha256'):
            original = getattr(self.args, field)
            setattr(self.args, field, '0' * 64)
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.prepare(self.args)
            setattr(self.args, field, original)
        self.job.chmod(0o750)
        with self.assertRaises(ValueError):
            fixture.prepare(self.args)

    def test_preflight_requires_explicit_private_copy_acknowledgement(self):
        self.write()
        self.args.preflight = True
        with patch.object(fixture, 'preflight', side_effect=AssertionError('no private read')):
            with self.assertRaises(ValueError) as raised:
                fixture.prepare(self.args)
        self.assertIn('acknowledgement', str(raised.exception))

    def test_real_disposable_sqlite_preflight_matches_retained_settings_without_mutation(self):
        database, historical = self.synthetic_state()
        before = fixture.snapshots.inventory(self.job / 'runtime', self.job / 'notification-custody',
            managed_unconfigured=True, provider_custody_root=self.job / 'provider-custody')
        result = fixture.preflight(self.job, historical)
        self.assertTrue(result['ok'])
        self.assertEqual(result['effective_settings_digest'], fixture.manifest()['effective_settings_digest'])
        self.assertTrue(result['notification_schema_absent'])
        self.assertTrue(result['provider_custody_empty'])
        self.assertFalse(result['original_database_opened'])
        self.assertEqual(fixture.snapshots.inventory(self.job / 'runtime', self.job / 'notification-custody',
            managed_unconfigured=True, provider_custody_root=self.job / 'provider-custody'), before)
        with sqlite3.connect(database) as connection:
            changed = deepcopy(fixture.SETTINGS)
            changed['fixture_cidrs'] = ['172.16.249.21/32']
            connection.execute('UPDATE operator_demo_settings SET settings_json=?', (json.dumps(changed, sort_keys=True),))
        current = fixture.snapshots.inventory(self.job / 'runtime', self.job / 'notification-custody')
        with self.assertRaises(ValueError):
            fixture.preflight(self.job, current)

    def test_notification_history_even_without_schema_refuses_enabled_rehearsal(self):
        database, _ = self.synthetic_state()
        with sqlite3.connect(database) as connection:
            connection.execute('INSERT INTO audit_events VALUES(?)', ('notification.saved',))
        historical = fixture.snapshots.inventory(self.job / 'runtime', self.job / 'notification-custody')
        with self.assertRaises(ValueError):
            fixture.preflight(self.job, historical)


class ProbeTests(unittest.TestCase):
    def test_generated_probe_is_closed_pinned_readonly_source_not_executed(self):
        for mode in ('app', 'gate'):
            source = checker.emit_probe(mode, BINARY_SHA)
            tree = ast.parse(source)
            assignments = {node.targets[0].id: ast.literal_eval(node.value)
                for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {'mode', 'expected_binary', 'expected_manifest'}}
            self.assertEqual(assignments, {'mode': mode, 'expected_binary': BINARY_SHA, 'expected_manifest': fixture.manifest()})
            self.assertIn('retained_network', {node.name for node in tree.body if isinstance(node, ast.FunctionDef)})
            self.assertIn('preservation_claimed', source)
        requests = [node for node in ast.walk(ast.parse(checker.READINESS_PROBE)) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == 'Request']
        self.assertEqual(len(requests), 1)
        self.assertEqual({keyword.arg: ast.literal_eval(keyword.value) for keyword in requests[0].keywords
            if keyword.arg == 'method'}, {'method': 'GET'})
        urls = {node.value for node in ast.walk(ast.parse(checker.READINESS_PROBE)) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and node.value.startswith('http://')}
        self.assertEqual(urls, {'http://172.16.249.20:9091/healthz', 'http://172.16.249.19:3000/api/operator-demo/catalog',
            'http://172.16.249.19:3000/api/operator-demo/notifications', 'http://172.16.249.19:3000/api/audit/verify?limit=1000'})
        for mode, digest in (('other', BINARY_SHA), ('gate', 'sha256:' + BINARY_SHA), ('app', 'A' * 64)):
            with self.subTest(mode=mode, digest_length=len(digest)), self.assertRaises(ValueError):
                checker.emit_probe(mode, digest)
        with patch.object(checker.managed, 'probe_source', return_value='changed anchors'), self.assertRaises(ValueError):
            checker.emit_probe('gate', BINARY_SHA)

    def network(self, *, changed=None, interfaces=None, resolution=None):
        files = {'/etc/hosts': fixture.HOSTS, '/etc/resolv.conf': fixture.RESOLV,
            '/proc/net/route': 'Iface Destination Gateway Flags RefCnt Use Metric Mask\n',
            '/proc/net/ipv6_route': '', '/proc/sys/net/ipv4/ip_nonlocal_bind': '0\n',
            '/proc/net/fib_trie': ''.join(' |-- ' + address + '\n    /32 host LOCAL\n'
                for address in ('127.0.0.1', *fixture.ADDRESSES)),
            '/proc/self/status': 'NoNewPrivs:\t1\nCapEff:\t0\nCapPrm:\t0\nCapInh:\t0\nCapAmb:\t0\n'}
        files.update(changed or {})
        bound = []

        class InertPath:
            def __init__(self, value):
                self.value = value
            def read_bytes(self):
                return files[self.value]
            def read_text(self):
                return files[self.value]

        class InertSocket:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def bind(self, value):
                bound.append(value)

        scope = {'Path': InertPath, 'HOSTS': fixture.HOSTS, 'RESOLV': fixture.RESOLV, 'ADDRESSES': fixture.ADDRESSES,
            'os': SimpleNamespace(geteuid=lambda: 10001, getegid=lambda: 10001, readlink=lambda _: 'net:[synthetic]'),
            'need': lambda value: fixture.base.require(value, 'synthetic namespace refusal')}
        # Execute definitions only; the actual function runs with inert proc and
        # socket methods. keeper(), NETLINK, setuid and real /proc never run.
        exec(compile(checker.NETWORK_PROBE, '<inert-network-oracle>', 'exec'), scope)
        names = dict(zip(('demo-upstream', 'serverware', 'decision-gate-rs'), fixture.ADDRESSES))
        def resolve(host, *_):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ((resolution or names)[host], 443))]
        with patch.object(socket, 'if_nameindex', return_value=interfaces or [(1, 'lo')]), \
                patch.object(socket, 'socket', return_value=InertSocket()), patch.object(socket, 'getaddrinfo', side_effect=resolve):
            result = scope['retained_network']()
        self.assertEqual(bound, [(address, 0) for address in fixture.ADDRESSES])
        return result

    def test_network_oracle_checks_containment_and_dropped_capabilities(self):
        result = self.network()
        self.assertEqual(result['interfaces'], ['lo'])
        self.assertEqual(result['ipv4_local_addresses'], sorted(['127.0.0.1', *fixture.ADDRESSES]))
        self.assertEqual(result['effective_capabilities'], 0)
        self.assertFalse(result['default_route'])
        controls = [('/etc/hosts', b'changed'), ('/etc/resolv.conf', b'nameserver 8.8.8.8\n'),
            ('/proc/net/route', 'header\nlo 00000000 00000000 0 0 0 0 00000000\n'),
            ('/proc/net/ipv6_route', 'synthetic default eth0\n'),
            ('/proc/sys/net/ipv4/ip_nonlocal_bind', '1\n'), ('/proc/net/fib_trie', '')]
        for path, value in controls:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.network(changed={path: value})
        for field in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'NoNewPrivs'):
            status = {name: '1' if name == 'NoNewPrivs' else '0'
                for name in ('NoNewPrivs', 'CapEff', 'CapPrm', 'CapInh', 'CapAmb')}
            status[field] = '0' if field == 'NoNewPrivs' else '1'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.network(changed={'/proc/self/status': ''.join(name + ':\t' + value + '\n' for name, value in status.items())})
        with self.assertRaises(ValueError):
            self.network(interfaces=[(1, 'lo'), (2, 'eth0')])
        with self.assertRaises(ValueError):
            self.network(resolution={'demo-upstream': '203.0.113.1', 'serverware': fixture.ADDRESSES[1],
                'decision-gate-rs': fixture.ADDRESSES[2]})


if __name__ == '__main__':
    unittest.main(verbosity=2)
