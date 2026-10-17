#!/usr/bin/env python3
"""Closed proxy-ingress source contracts; Compose renders without a daemon.

No containers, application calls, provider requests or live configuration reads.
Actual opaque relay/fence behavior is a separate isolated runtime check.
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
TCP_LABELS = {
    'traefik.tcp.routers.catchplate-operator-proxy.rule':
        'HostSNI(`catchplate-proxy.example.com`)',
    'traefik.tcp.routers.catchplate-operator-proxy.entrypoints': 'websecure',
    'traefik.tcp.routers.catchplate-operator-proxy.tls': 'true',
    'traefik.tcp.routers.catchplate-operator-proxy.tls.options': 'mcp-http1@file',
    'traefik.tcp.routers.catchplate-operator-proxy.service': 'catchplate-operator-proxy',
    'traefik.tcp.services.catchplate-operator-proxy.loadbalancer.server.port': '9090',
}


def stream_block(template):
    matches = re.findall(r'(?ms)^stream \{\n.*?^\}', template)
    if len(matches) != 1:
        raise ValueError('exactly one top-level stream block required')
    return matches[0]


def directives(text):
    return '\n'.join(line.strip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith('#'))


class ProxyIngressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ROOT / 'docker/catchplate-operator-demo'
        cls.template = (stack / 'config/nginx.conf.template').read_text()
        env = {key: value for key, value in os.environ.items()
               if key in {'PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR'}}
        env.update(GOMAXPROCS='2', DOCKER_HOST='unix:///catchplate-ingress-test-no-daemon.sock',
            TRAEFIK_IPV4='192.0.2.17', OPERATOR_DEMO_UPSTREAMS='["https://demo-upstream:8443"]',
            OPERATOR_DEMO_SDK_SOURCE='/fixture/source', OPERATOR_DEMO_RUST_BINARY='/fixture/gate',
            OPERATOR_DEMO_RUST_BINARY_SHA256='1' * 64, OPERATOR_DEMO_DATA_ROOT='/fixture/data')
        result = subprocess.run(['docker', 'compose', '--env-file', '/dev/null', '-f',
            str(stack / 'docker-compose.yml'), 'config', '--format', 'json'],
            env=env, capture_output=True, text=True, timeout=30, check=True)
        cls.model = json.loads(result.stdout)
        cls.services = cls.model['services']

    def test_edge_exclusively_owns_unchanged_proxy_endpoint_and_tls_labels(self):
        observed = {name: {key: value for key, value in service.get('labels', {}).items()
                          if key.startswith('traefik.tcp.')}
                    for name, service in self.services.items()}
        self.assertEqual(observed, {'edge': TCP_LABELS, 'catchplate': {},
                                   'demo-upstream': {}, 'decision-gate-rs': {}})
        edge = self.services['edge']
        self.assertEqual(edge['labels']['traefik.enable'], 'true')
        self.assertEqual(edge['labels']['traefik.docker.network'], 'traefik-v3-public')
        self.assertEqual(edge['environment']['TRAEFIK_IPV4'], '192.0.2.17')
        # Compose's JSON model retains the dollar escape; the existing runtime
        # comparison normalizes it when checking the container environment.
        self.assertEqual(edge['environment']['NGINX_ENVSUBST_FILTER'], '^TRAEFIK_IPV4$$')
        self.assertEqual(edge['command'], ['nginx', '-c', '/tmp/nginx.conf', '-g', 'daemon off;'])

    def test_gate_is_not_discoverable_or_attached_to_public_overlay(self):
        gate = self.services['decision-gate-rs']
        self.assertEqual(gate['labels'], {'traefik.enable': 'false',
            'com.centurylinklabs.watchtower.enable': 'false'})
        self.assertEqual(gate['networks'], {'sandbox': {'ipv4_address': '172.16.249.20'},
            'outbound': {'ipv4_address': '172.16.249.34'}})
        self.assertEqual([name for name, service in self.services.items()
            if 'traefik-v3-public' in service.get('networks', {})], ['edge'])
        self.assertEqual(self.services['edge']['networks']['sandbox']['ipv4_address'], '172.16.249.21')
        self.assertIs(self.model['networks']['sandbox']['internal'], True)
        for service in self.services.values():
            self.assertNotIn('ports', service)
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'], ['ALL'])

    def test_exact_opaque_relay_socket_peer_fixed_destination_and_bounds(self):
        self.assertEqual(directives(stream_block(self.template)), directives('''
stream {
access_log off;
error_log /dev/null;
server {
listen 9090;
allow ${TRAEFIK_IPV4}/32;
deny all;
proxy_pass 172.16.249.20:9090;
proxy_connect_timeout 3s;
proxy_timeout 10m;
proxy_half_close on;
proxy_next_upstream off;
proxy_protocol off;
proxy_ssl off;
}
}'''))
        stream = stream_block(self.template)
        for forbidden in ('proxy_set_header', 'proxy_ssl_certificate', 'ssl_preread',
                          'set_real_ip_from', 'real_ip_header', 'proxy_bind', 'include ',
                          'resolver ', 'udp', 'transparent'):
            self.assertNotIn(forbidden, stream)
        self.assertEqual(stream.count('${'), 1)
        # No TLS/PROXY listen flags, secondary target, retry pool or payload log.
        self.assertEqual(re.findall(r'(?m)^\s*listen (.*);$', stream), ['9090'])
        self.assertEqual(re.findall(r'(?m)^\s*proxy_pass (.*);$', stream), ['172.16.249.20:9090'])

    def test_console_and_management_ports_remain_separate(self):
        labels = self.services['edge']['labels']
        self.assertEqual(labels['traefik.http.services.catchplate-demo-edge.loadbalancer.server.port'], '8080')
        self.assertEqual(labels['traefik.http.routers.catchplate-public.middlewares'], 'authelia-public@file')
        self.assertEqual(labels['traefik.http.routers.catchplate-lab.middlewares'], 'localnetwork@file')
        gate = self.services['decision-gate-rs']['environment']
        self.assertEqual(gate['CATCHPLATE_DECISION_GATE_MANAGEMENT_HOST'], '172.16.249.20')
        self.assertEqual(gate['CATCHPLATE_DECISION_GATE_MANAGEMENT_PORT'], '9091')
        self.assertIn('include /run/secrets/catchplate-edge/admin-header.conf;',
                      self.template.split('\nhttp {\n', 1)[1])
        self.assertNotIn('9091', stream_block(self.template))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args, remaining = parser.parse_known_args()
    ROOT = args.source_root.resolve()
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
