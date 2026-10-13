#!/usr/bin/env python3
"""Current Compose/nginx source contracts; no daemon, app, DB or provider calls.

Compose CLI rendering uses synthetic values and an unreachable Docker socket.
These tests do not replace isolated nginx or live authenticated route acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = 'serverware.example.com'
OLD = 'serverware-demo.example.com'


def statements(block):
    return '\n'.join(line.strip() for line in block.splitlines()
                     if line.strip() and not line.lstrip().startswith('#'))


class CanonicalOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ROOT / 'docker/serverware-operator-demo'
        cls.nginx = (stack / 'config/nginx.conf.template').read_text()
        # TCP ingress has its own stream/server block; these assertions cover
        # only the existing console HTTP virtual hosts and their auth boundary.
        http = cls.nginx.split('\nhttp {\n', 1)[1]
        cls.blocks = re.findall(r'(?ms)^    server \{\n.*?^    \}', http)
        env = {k: v for k, v in os.environ.items() if k in {'PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR'}}
        env.update(GOMAXPROCS='2', DOCKER_HOST='unix:///serverware-canonical-test-no-daemon.sock',
            TRAEFIK_IPV4='127.0.0.1', OPERATOR_DEMO_UPSTREAMS='["https://demo-upstream:8443"]',
            OPERATOR_DEMO_SDK_SOURCE='/fixture/source', OPERATOR_DEMO_RUST_BINARY='/fixture/gate',
            OPERATOR_DEMO_RUST_BINARY_SHA256='1' * 64, OPERATOR_DEMO_DATA_ROOT='/fixture/data')
        result = subprocess.run(['docker', 'compose', '--env-file', '/dev/null', '-f',
            str(stack / 'docker-compose.yml'), 'config', '--format', 'json'], env=env,
            capture_output=True, text=True, timeout=30, check=True)
        cls.model = json.loads(result.stdout)

    def server(self, name):
        matches = [block for block in self.blocks if 'server_name ' + name + ';' in block]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_current_origin_without_changing_authority_or_proxy_identity(self):
        services = self.model['services']
        self.assertEqual(set(services), {'serverware', 'decision-gate-rs', 'edge', 'demo-upstream'})
        app = services['serverware']['environment']
        self.assertEqual(app['SERVERWARE_PUBLIC_URL'], 'https://' + PUBLIC)
        self.assertEqual(app['SERVERWARE_OPERATOR_DEMO'], '1')
        self.assertEqual(app['SERVERWARE_RELEASE_CHANNEL'], 'dev')
        for name in ('serverware', 'decision-gate-rs'):
            self.assertEqual(services[name]['environment']['SERVERWARE_OPERATOR_DEMO_PROXY_URL'],
                'https://serverware-proxy.example.com:443')
        for service in services.values():
            self.assertNotIn('ports', service)
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(self.model['networks']['sandbox']['internal'], True)

    def test_exact_router_hosts_auth_and_backend(self):
        labels = self.model['services']['edge']['labels']
        expected = {'serverware-public': (PUBLIC, 'authelia-public@file'),
            'serverware-lab': ('serverware.lab.example.com', 'localnetwork@file'),
            'serverware-demo-public': (OLD, 'authelia-public@file'),
            'serverware-demo-lab': ('serverware-demo.lab.example.com', 'localnetwork@file')}
        routers = {k: v for k, v in labels.items() if k.startswith('traefik.http.routers.')}
        wanted = {}
        for name, (host, middleware) in expected.items():
            prefix = 'traefik.http.routers.' + name + '.'
            wanted.update({prefix + 'rule': 'Host(`' + host + '`)', prefix + 'entrypoints': 'websecure',
                prefix + 'tls': 'true', prefix + 'middlewares': middleware,
                prefix + 'service': 'serverware-demo-edge'})
        self.assertEqual(routers, wanted)
        self.assertEqual(labels['traefik.http.services.serverware-demo-edge.loadbalancer.server.port'], '8080')

    def test_canonical_peer_user_origin_and_header_boundary(self):
        canonical = self.server(PUBLIC)
        for opening, expected in (
            ('geo $traefik_peer', 'default 0;\n${TRAEFIK_IPV4}/32 1;'),
            ('map $http_remote_user $sandbox_operator', 'default 0;\n~^operator$ 1;'),
            ('map $http_origin $foreign_origin', 'default 1;\n"" 0;\n"https://' + PUBLIC + '" 0;'),
            ('map "$request_method:$http_origin" $unsafe_origin',
                'default 1;\n~^(GET|HEAD|OPTIONS): 0;\n'
                + r'~^[A-Z]+:https://serverware\.example\.com$ 0;')):
            match = re.search(r'(?ms)^    ' + re.escape(opening) + r' \{\n(.*?)^    \}', self.nginx)
            self.assertIsNotNone(match)
            self.assertEqual(statements(match.group(1)), expected)
        for guard in ('if ($traefik_peer = 0) { return 403; }',
            'if ($sandbox_operator = 0) { return 403; }', 'if ($foreign_origin = 1) { return 403; }',
            'if ($unsafe_origin = 1) { return 403; }'):
            self.assertIn(guard, canonical)
        for line in ('${TRAEFIK_IPV4}/32 1;', '~^operator$ 1;',
            '"https://' + PUBLIC + '" 0;', r'~^[A-Z]+:https://serverware\.example\.com$ 0;'):
            self.assertIn(line, self.nginx)
        self.assertNotIn('https://' + OLD, self.nginx)
        for name in ('Authorization', 'X-Serverware-Bootstrap-Token', 'Forwarded'):
            self.assertIn('proxy_set_header ' + name + ' "";', canonical)
        self.assertIn('proxy_set_header Host ' + PUBLIC + ';', canonical)
        self.assertIn('proxy_set_header X-Forwarded-Host ' + PUBLIC + ';', canonical)
        self.assertIn('include /run/secrets/serverware-edge/admin-header.conf;', canonical)
        self.assertIn('proxy_next_upstream off;', self.nginx)

    def test_old_host_is_closed_navigation_only_no_callback_query_or_method_replay(self):
        self.assertEqual(statements(self.server(OLD)), statements('''
server {
listen 8080;
server_name serverware-demo.example.com;
if ($traefik_peer = 0) { return 403; }
if ($sandbox_operator = 0) { return 403; }
if ($foreign_origin = 1) { return 403; }
if ($request_method !~ ^(GET|HEAD)$) { return 405; }
if ($args != "") { return 400; }
add_header Cache-Control no-store always;
add_header Referrer-Policy no-referrer always;
location ^~ /api/ { return 410; }
location / { return 302 https://serverware.example.com/; }
}'''))

    def test_lab_health_has_no_admin_injection_and_no_query_redirect(self):
        lab = self.server('serverware.lab.example.com serverware-demo.lab.example.com')
        self.assertIn('if ($traefik_peer = 0) { return 403; }', lab)
        self.assertIn('limit_except GET { deny all; }', lab)
        self.assertNotIn('include ', lab)
        self.assertIn('if ($request_method !~ ^(GET|HEAD)$) { return 405; }', lab)
        self.assertIn('if ($args != "") { return 400; }', lab)
        self.assertNotIn('$request_uri', lab)
        self.assertEqual(len(self.blocks), 5)
        self.assertIn('return 403;', self.server('_'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args, remaining = parser.parse_known_args()
    ROOT = args.source_root.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
