"""Bounded source/self-tests only; no containers, live traffic or real ACK claim."""
from email.message import Message
import io
import json
from pathlib import Path
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import config
import relay
import check as private_check


SOURCE = Path('/fixture-source')
BINARY = Path('/fixture-binary')
RUNTIME = Path('/new-fixture/runtime')


def configuration():
    return config.build(SOURCE, BINARY, RUNTIME, 'a' * 64,
        'catchplate-audit-private-123456abcdef', '172.16.249.48/28')


def event(number):
    return {'eventId': 'sha256:' + format(number, '064x'),
        'eventType': 'data_plane.fixture.unit', 'event': {'syntheticOnly': True}}


def identity(nonce='unit-nonce-1', numbers=(1, 2)):
    body = json.dumps({'events': [event(n) for n in numbers]}).encode()
    return relay.batch_identity(body, nonce)


def required_identity(number, nonce='required-singleton-nonce'):
    value = event(number)
    value['eventType'] = 'data_plane.credential.release_started'
    return relay.batch_identity(json.dumps({'events': [value]}).encode(), nonce)


def handler(path, method='GET', headers=None, body=b''):
    value = relay.RelayHandler.__new__(relay.RelayHandler)
    value.path, value.command, value.request_version = path, method, 'HTTP/1.1'
    value.requestline = method + ' ' + path + ' HTTP/1.1'
    value.server = SimpleNamespace(token='unit-token', fault=relay.FaultState())
    value.headers = Message()
    for key, item in (headers or {}).items():
        value.headers[key] = item
    value.rfile, value.wfile = io.BytesIO(body), io.BytesIO()
    value.connection = Mock()
    value.close_connection = False
    value.forward = Mock(return_value=(200, [('Content-Type', 'application/json')], b'{}'))
    return value


class ConfigTests(unittest.TestCase):
    def test_fixture_keeps_canonical_guard_and_pins_new_addresses(self):
        value = configuration()
        gate = value['services']['decision-gate-rs']
        app = value['services']['control-plane']
        self.assertEqual(gate['environment']['CATCHPLATE_CONTROL_PLANE_AUDIT_URL'], 'http://catchplate:3000/api/data-plane/audit')
        self.assertEqual(gate['environment']['CATCHPLATE_CONTROL_PLANE_CREDENTIAL_LEASE_URL'], 'http://catchplate:3000/api/data-plane/credential-leases')
        self.assertEqual(app['environment']['CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS'], '["172.16.249.50/32"]')
        self.assertEqual(gate['environment']['CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS'], '["172.16.249.50/32"]')
        self.assertEqual(gate['environment']['CATCHPLATE_DECISION_GATE_MANAGEMENT_HOST'], '172.16.249.52')
        self.assertTrue(value['networks']['fixture']['internal'])
        self.assertNotIn('edge', value['services'])

    def test_generated_config_contains_no_live_mount_or_ingress(self):
        raw = json.dumps(configuration())
        for forbidden in ('homelab_data', 'catchplate-operator-demo/', 'traefik-v3-public', 'docker.sock'):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(configuration()['services']['initialize']['network_mode'], 'none')

    def test_config_guard_rejects_exposure_mutations(self):
        changes = ({'ports': ['9999:3000']}, {'privileged': True}, {'network_mode': 'host'},
            {'user': '0:0'}, {'cap_add': ['SYS_ADMIN']}, {'read_only': False},
            {'pids_limit': 1000}, {'cpus': 8}, {'mem_limit': '20g'},
            {'extra_hosts': ['other:1.1.1.1']}, {'security_opt': []}, {'pull_policy': 'always'})
        for change in changes:
            with self.subTest(change=change):
                value = configuration()
                value['services']['catchplate'].update(change)
                with self.assertRaises(ValueError):
                    config.validate(value, SOURCE, BINARY, RUNTIME)

    def test_mount_guard_rejects_live_or_writable_source(self):
        for volume in (config.bind('/live/data', '/data', False), config.bind(SOURCE, '/app', False)):
            value = configuration()
            value['services']['catchplate']['volumes'].append(volume)
            with self.assertRaises(ValueError):
                config.validate(value, SOURCE, BINARY, RUNTIME)

    def test_subnet_and_project_guard(self):
        for subnet in ('0.0.0.0/0', '172.16.249.48/29', '8.8.8.0/28', '::1/128'):
            with self.assertRaises(ValueError):
                config.build(SOURCE, BINARY, RUNTIME, 'a' * 64, 'catchplate-audit-private-123456abcdef', subnet)
        with self.assertRaises(ValueError):
            config.build(SOURCE, BINARY, RUNTIME, 'a' * 64, 'catchplate-operator-demo', '172.16.249.48/28')


class StateTests(unittest.TestCase):
    def test_required_singletons_are_separate_before_during_and_after_lost_ack(self):
        state = relay.FaultState()
        state.control('arm')
        mode, first_required = state.before(required_identity(10))
        self.assertEqual(mode, 'required')
        state.committed(first_required, False)
        self.assertIsNone(state.snapshot()['original'])
        self.assertFalse(state.snapshot()['dropped'])
        mode, original = state.before(identity())
        self.assertEqual(mode, 'first')
        state.committed(original, True)
        mode, during = state.before(required_identity(11))
        self.assertEqual(mode, 'required')
        state.committed(during, False)
        self.assertEqual(state.before(identity('retry-nonce'))[0], 'hold')
        state.control('release')
        mode, after = state.before(required_identity(12))
        self.assertEqual(mode, 'required')
        state.committed(after, False)
        mode, retried = state.before(identity('acknowledged-retry-nonce'))
        self.assertEqual(mode, 'forward')
        state.committed(retried, False)
        mode, fresh = state.before(identity('fresh-queued-nonce', (3, 4)))
        self.assertEqual(mode, 'forward')
        state.committed(fresh, False)
        result = state.snapshot()
        self.assertIsNone(result['failure'])
        self.assertEqual(len(result['requiredAttempts']), 3)
        self.assertEqual(len(result['attempts']), 4)
        self.assertTrue(all(record['acknowledged'] and not record['responseDropped']
            for record in result['requiredAttempts']))
        self.assertEqual(result['attempts'][-1]['eventIds'], identity(numbers=(3, 4))['eventIds'])

    def test_required_singleton_cannot_relabel_original_subset_or_reuse_identity(self):
        for select in ('original', 'required', 'fresh-queued'):
            with self.subTest(select=select):
                state = relay.FaultState()
                state.control('arm')
                number = 1
                if select == 'original':
                    state.before(identity())
                elif select == 'fresh-queued':
                    _, original = state.before(identity())
                    state.committed(original, True)
                    state.control('release')
                    state.before(identity(numbers=(3, 4)))
                    number = 3
                else:
                    state.before(required_identity(1))
                with self.assertRaises(ValueError):
                    state.before(required_identity(number, 'another-nonce'))
                self.assertIsNotNone(state.snapshot()['failure'])

    def test_queued_batch_cannot_reuse_required_singleton_identity(self):
        state = relay.FaultState()
        state.control('arm')
        state.before(required_identity(1))
        with self.assertRaises(ValueError):
            state.before(identity(numbers=(1, 2)))

    def test_nonrequired_singleton_or_changed_original_bytes_remain_refused(self):
        for changed in (identity('new-singleton', (3,)),
                relay.batch_identity(json.dumps({'events': [event(1), event(2)]}, indent=2).encode(), 'changed-bytes')):
            with self.subTest(changed=changed['bodyDigest']):
                state = relay.FaultState()
                state.control('arm')
                state.before(identity())
                with self.assertRaises(ValueError):
                    state.before(changed)
                self.assertIsNotNone(state.snapshot()['failure'])

    def test_one_shot_lost_ack_hold_then_fresh_batch(self):
        state = relay.FaultState()
        self.assertEqual(state.before(identity()), ('pass', None))
        state.control('arm')
        mode, original = state.before(identity())
        self.assertEqual(mode, 'first')
        state.committed(original, True)
        mode, held = state.before(identity('unit-nonce-2'))
        self.assertEqual(mode, 'hold')
        self.assertFalse(held['forwarded'])
        state.control('release')
        mode, retried = state.before(identity('unit-nonce-3'))
        self.assertEqual(mode, 'forward')
        state.committed(retried, False)
        mode, fresh = state.before(identity('unit-nonce-4', (3, 4)))
        self.assertEqual(mode, 'forward')
        state.committed(fresh, False)
        result = state.snapshot()
        self.assertTrue(result['dropped'])
        self.assertIsNone(result['failure'])
        self.assertEqual(len(result['attempts']), 4)
        with self.assertRaises(ValueError):
            state.control('arm')

    def test_changed_pending_batch_is_rejected(self):
        state = relay.FaultState()
        state.control('arm')
        state.before(identity())
        with self.assertRaises(ValueError):
            state.before(identity('new-nonce', (1, 3)))
        self.assertIsNotNone(state.snapshot()['failure'])

    def test_only_multi_event_original_and_only_committed_release(self):
        state = relay.FaultState()
        state.control('arm')
        self.assertEqual(state.before(identity(numbers=(1,))), ('pass', None))
        with self.assertRaises(ValueError):
            state.control('release')

    def test_duplicate_or_malformed_event_id_is_rejected(self):
        for body in ({'events': []}, {'events': [event(1), event(1)]}, {'events': [{'eventId': 'invalid'}]}):
            with self.assertRaises(ValueError):
                relay.batch_identity(json.dumps(body).encode(), 'nonce')

    def test_ack_shape_requires_exact_batch_and_detached_proof_headers(self):
        current = identity()
        body = json.dumps({'apiVersion': 'catchplate.dataPlaneAuditAck/v1', 'ok': True,
            'accepted': 2, 'batchDigest': current['bodyDigest'], 'instanceId': relay.INSTANCE}).encode()
        headers = [(name, 'unit-shape-only-not-a-valid-signature') for name in relay.PROOF_HEADERS]
        relay.real_ack(200, headers, body, current)
        for status, selected_headers, selected_identity in ((413, headers, current), (200, [], current), (200, headers, identity(numbers=(3, 4)))):
            with self.assertRaises(ValueError):
                relay.real_ack(status, selected_headers, body, selected_identity)


class HandlerTests(unittest.TestCase):
    def test_health_and_control_auth_never_forward(self):
        for path, status in (('/__fixture/health', b'200'), ('/__fixture/status', b'403')):
            selected = handler(path)
            selected.handle_operation()
            self.assertIn(status, selected.wfile.getvalue().split(b'\r\n', 1)[0])
            selected.forward.assert_not_called()

    def test_unknown_absolute_admin_and_query_operations_never_forward(self):
        for path, method in (('http://third-party.invalid/a', 'GET'), ('/api/admin', 'GET'),
                ('/api/data-plane/audit?extra=1', 'POST'), ('/api/data-plane/credential-leases', 'GET')):
            selected = handler(path, method)
            selected.handle_operation()
            selected.forward.assert_not_called()

    def test_body_and_transfer_encoding_bounds(self):
        for headers in ({'Content-Length': str(relay.MAX_BODY + 1)}, {'Transfer-Encoding': 'chunked'}, {'Content-Length': '-1'}):
            selected = handler(relay.LEASE, 'POST', headers)
            selected.handle_operation()
            selected.forward.assert_not_called()

    def test_attestation_passes_exact_path_and_response_bytes(self):
        selected = handler('/attestation?nonce=unit-nonce')
        selected.forward.return_value = (200, [('Content-Type', 'application/json'), ('X-Catchplate-Response-Signature', 'unit-only')], b' {"unit":true}\n')
        selected.handle_operation()
        selected.forward.assert_called_once_with(b'')
        self.assertTrue(selected.wfile.getvalue().endswith(b' {"unit":true}\n'))
        self.assertIn(b'X-Catchplate-Response-Signature: unit-only\r\n', selected.wfile.getvalue())


class ClaimTests(unittest.TestCase):
    def test_claim_is_retained_and_repeat_refused(self):
        with tempfile.TemporaryDirectory(prefix='private-audit-claim-') as directory:
            path = Path(directory) / 'run.claim'
            private_check.claim_run('sha256:' + 'a' * 64, path=path)
            first = path.read_bytes()
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(json.loads(first)['replayAllowed'])
            with self.assertRaises(private_check.CheckFailure):
                private_check.claim_run('sha256:' + 'b' * 64, path=path)
            self.assertEqual(path.read_bytes(), first)

    def test_incomplete_claim_is_not_removed_or_replayed(self):
        with tempfile.TemporaryDirectory(prefix='private-audit-claim-') as directory:
            path = Path(directory) / 'run.claim'
            with patch.object(private_check.os, 'fsync', side_effect=OSError('unit-only fsync failure')):
                with self.assertRaises(OSError):
                    private_check.claim_run('sha256:' + 'a' * 64, path=path)
            self.assertTrue(path.exists())
            with self.assertRaises(private_check.CheckFailure):
                private_check.claim_run('sha256:' + 'a' * 64, path=path)

    def test_claim_refusal_happens_before_acceptance_construction_or_mutation(self):
        marker = json.dumps({'schema': 'catchplate.privateOperatorAuditFixture/v1', 'syntheticOnly': True})
        with patch.dict(os.environ, {'PRIVATE_OPERATOR_AUDIT_FIXTURE': '1'}), \
                patch.object(Path, 'read_text', return_value=marker), \
                patch.object(private_check, 'claim_run', side_effect=private_check.CheckFailure('already claimed')), \
                patch.object(private_check, 'OperatorDemoCheck') as acceptance:
            with self.assertRaises(private_check.CheckFailure):
                private_check.run('sha256:' + 'a' * 64)
            acceptance.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
