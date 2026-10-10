#!/usr/bin/env python3
"""Sanitized model and repository recipe controls; no Docker or live env reads."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import unittest
from unittest.mock import patch

from scripts import operator_demo_deployment_review as legacy
from scripts import operator_managed_deployment_review as review
from scripts import test_operator_demo_deployment_review as historical


CANARY = 'synthetic-private-drift-value-never-public'


def mount(target, source, readonly=True):
    return {'type': 'bind', 'source': str(source), 'target': target, 'read_only': readonly,
        'bind': {'create_host_path': False}}


def engine_mount(value):
    return {'Type': 'bind', 'Source': value['source'], 'Destination': value['target'],
        'RW': not value['read_only'], 'Propagation': 'rprivate'}


def documents():
    """Extend the existing comparator's coherent synthetic engine fixtures.

    These are public fixed paths and synthetic values, never inspected runtime
    data. Engine objects independently retain old mounts/env; only the proposed
    model receives the explicitly reviewed managed delta.
    """
    model = {'name': legacy.PROJECT, 'services': {}, 'networks': deepcopy(legacy.MODEL_NETWORKS),
        'x-isolated': deepcopy(legacy.BASE_EXTENSION)}
    observed, images = {}, {}
    for index, name in enumerate(sorted(legacy.SERVICES), 1):
        proposed, live, image = historical.service(name)
        image['Id'] = 'sha256:' + str(index) * 64
        proposed['image'] = live['Image'] = image['Id']
        live.update(Id=str(index) * 64, RestartCount=0,
            State={'Running': True, 'Health': {'Status': 'healthy'}, 'Pid': index, 'StartedAt': 'synthetic-start'})
        live['Config']['Labels'].update({'com.docker.compose.project': legacy.PROJECT,
            'com.docker.compose.service': name, 'com.docker.compose.oneoff': 'False'})
        address = {'demo-upstream': '172.16.249.18', 'serverware': '172.16.249.19',
            'decision-gate-rs': '172.16.249.20', 'edge': '172.16.249.21'}[name]
        proposed['networks'] = {'sandbox': {'ipv4_address': address}}
        live['NetworkSettings']['Networks'] = {legacy.MODEL_NETWORKS['sandbox']['name']:
            {'IPAddress': address, 'IPAMConfig': {'IPv4Address': address}, 'Aliases': [name]}}
        if name in {'decision-gate-rs', 'edge'}:
            proposed['networks']['traefik-v3-public'] = {}
            live['NetworkSettings']['Networks']['traefik-v3-public'] = {
                'IPAddress': '10.0.1.' + str(160 + index), 'IPAMConfig': {'IPv4Address': '10.0.1.' + str(160 + index)}}
        if name == 'decision-gate-rs':
            proposed['networks']['outbound'] = {'ipv4_address': '172.16.249.34'}
            live['NetworkSettings']['Networks'][legacy.MODEL_NETWORKS['outbound']['name']] = {
                'IPAddress': '172.16.249.34', 'IPAMConfig': {'IPv4Address': '172.16.249.34'}}
        labels = {'synthetic.retained': 'yes'}
        if name == 'edge':
            labels['traefik.http.routers.operator.middlewares'] = 'synthetic-auth@docker'
        proposed['labels'] = labels
        live['Config']['Labels'].update(labels)
        environment = legacy.envmap(live['Config']['Env'])
        if name == 'serverware':
            environment[legacy.EXPECTED_DIGEST] = 'sha256:' + review.OLD_SHA
            proposed['environment'][legacy.EXPECTED_DIGEST] = 'sha256:' + review.NEW_SHA
            proposed['environment'].update(review.APP_MANAGED_ENV)
            proposed['volumes'][0]['source'] = review.NEW_SOURCE
            live['Mounts'][0]['Source'] = review.OLD_SOURCE
            retained = [mount('/data', review.APP_DATA, False),
                mount('/run/secrets/serverware', review.DATA_ROOT / 'service-secrets')]
            proposed['volumes'].extend(retained)
            live['Mounts'].extend(engine_mount(value) for value in retained)
            proposed['volumes'].append(mount('/provider-custody', review.PROVIDER_CUSTODY, False))
        elif name == 'decision-gate-rs':
            proposed['environment']['SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED'] = '1'
            proposed['volumes'][0]['source'] = review.NEW_BINARY
            live['Mounts'][0]['Source'] = review.OLD_BINARY
            live['Mounts'].append(engine_mount(mount('/data', review.APP_DATA)))
            proposed['volumes'].append(mount('/data', review.APP_DATA / 'gate-runtime'))
            proposed['volumes'].extend(mount('/data/' + leaf, review.APP_DATA / leaf) for leaf in review.LEAVES)
            retained = mount('/gate-data', review.DATA_ROOT / 'gate-data', False)
            proposed['volumes'].append(retained)
            live['Mounts'].append(engine_mount(retained))
        live['Config']['Env'] = [key + '=' + value for key, value in environment.items()]
        model['services'][name], observed[name], images[proposed['image']] = proposed, live, image
    return model, observed, images


def deployed(documents_value):
    model, observed, images = deepcopy(documents_value)
    for name in ('serverware', 'decision-gate-rs'):
        proposed, live = model['services'][name], observed[name]
        live['Mounts'] = [engine_mount(value) for value in proposed['volumes']]
        live['Config']['Env'] = [key + '=' + value for key, value in proposed['environment'].items()]
    return model, observed, images


class ManagedDeploymentReviewTests(unittest.TestCase):
    def test_checked_in_layer_bytes_match_the_reviewed_pins(self):
        self.assertEqual(set(review.PINS), set(review.LAYERS))
        for path, expected in review.PINS.items():
            with self.subTest(layer=path.name):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ('subprocess.run', 'socket.socket', 'socket.create_connection', 'socket.getaddrinfo', 'builtins.open'):
            stack.enter_context(patch(name, side_effect=AssertionError('pure comparator attempted external I/O')))

    def compare(self, value, *, phase='proposed', digest=lambda _: 'same-public-template-digest', provider=None):
        return review.compare_model(*value, provider_custody=review.PROVIDER_CUSTODY if provider is None else provider,
            digest_file=digest, phase=phase)

    def refused(self, value, **kwargs):
        with self.assertRaises(legacy.Refused) as caught:
            self.compare(value, **kwargs)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertNotIn(historical.SECRET, str(caught.exception))
        receipt = review.error_receipt(caught.exception)
        self.assertEqual(receipt, {'ok': False, 'error': 'managed candidate comparison refused'})

    def test_exact_reviewed_transition_and_deployed_match_without_input_mutation(self):
        self.assertEqual(review.APP_MANAGED_ENV, {
            'SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED': '1',
            'SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR': '/provider-custody',
            'SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED': '1',
            'SERVERWARE_PROCESS_MODE': 'serverware-control-plane', 'SERVERWARE_RELEASE_CHANNEL': 'dev',
            'SERVERWARE_METADATA_STORE_BACKEND': 'sqlite', 'SERVERWARE_AUDIT_STORE_BACKEND': 'sqlite',
            'SERVERWARE_GRANT_STORE_BACKEND': 'sqlite', 'SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED': '0',
            'SERVERWARE_KEY_RELEASE_REQUIRED': '0', 'SERVERWARE_DEV_AUTHENTICATOR': '0', 'SERVERWARE_DEV_DEMO_SEED': '0'})
        value = documents()
        before = deepcopy(value)
        result = self.compare(value)
        self.assertTrue(result['ok'])
        self.assertEqual(result['approvedDifferences'], sorted(review.APPROVED_DELTAS))
        self.assertFalse(result['runtimeMutationsPerformed'])
        self.assertFalse(result['rolloutVerified'])
        self.assertEqual(value, before)
        actual = deployed(value)
        actual_before = deepcopy(actual)
        result = self.compare(actual, phase='deployed')
        self.assertTrue(result['ok'])
        self.assertEqual(result['approvedDifferences'], [])
        self.assertFalse(result['rolloutVerified'])
        self.assertEqual(actual, actual_before)
        self.refused(value, phase='deployed')
        self.refused(actual)

    def test_historical_reviewer_globals_and_original_transition_remain_unchanged(self):
        names = ('OLD_SOURCE', 'NEW_SOURCE', 'OLD_BINARY', 'NEW_BINARY', 'OLD_SHA', 'NEW_SHA', 'APPROVED_DELTAS')
        original = {name: deepcopy(getattr(legacy, name)) for name in names}
        self.compare(documents())
        self.compare(deployed(documents()), phase='deployed')
        self.assertEqual({name: getattr(legacy, name) for name in names}, original)
        changes = set()
        for name in legacy.SERVICES:
            changes.update(legacy.compare_service(name, *historical.service(name), historical.NETWORKS,
                digest_file=lambda _: 'same-public-template-digest'))
        self.assertEqual(changes, legacy.APPROVED_DELTAS)
        self.assertEqual(review.OLD_SHA, '2bfe5e384d7e9c655de70704c25350c16336c55a2584fc59f363f12164f297d6')
        self.assertEqual(review.NEW_SHA, '333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0')
        self.assertTrue(review.OLD_SOURCE.endswith('source-577badff84b32eea052c53d6df8f6fd5de61d66a'))
        self.assertTrue(review.NEW_SOURCE.endswith('source-9222b4c090d77aa983d3c01be34e0a2ba79f8e6c'))

    def test_each_managed_admission_value_is_exact_not_a_general_environment_exception(self):
        for field in review.APP_MANAGED_ENV:
            for mode in ('missing', 'changed'):
                value = documents()
                env = value[0]['services']['serverware']['environment']
                if mode == 'missing':
                    env.pop(field)
                else:
                    env[field] = CANARY
                with self.subTest(field=field, mode=mode):
                    self.refused(value)
        for name in legacy.SERVICES:
            value = documents()
            value[0]['services'][name]['environment']['UNREVIEWED_VALUE'] = CANARY
            with self.subTest(service=name):
                self.refused(value)
        value = documents()
        value[0]['services']['decision-gate-rs']['environment'].pop('SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED')
        self.refused(value)
        value = documents()
        value[0]['services']['serverware']['environment']['SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED'] = '0'
        self.refused(value)

    def test_retained_development_defaults_must_already_match_exactly(self):
        for field in ('SERVERWARE_RELEASE_CHANNEL', 'SERVERWARE_METADATA_STORE_BACKEND', 'SERVERWARE_DEV_DEMO_SEED'):
            value = documents()
            env = value[1]['serverware']['Config']['Env']
            env.append(field + '=' + review.APP_MANAGED_ENV[field])
            with self.subTest(field=field):
                self.assertTrue(self.compare(value)['ok'])
                env[-1] = field + '=' + CANARY
                self.refused(value)

    def test_original_and_candidate_source_binary_pins_are_not_optional(self):
        for name, target in (('serverware', '/app'), ('decision-gate-rs', legacy.BINARY_TARGET)):
            for side in ('candidate', 'retained'):
                value = documents()
                rows = value[0]['services'][name]['volumes'] if side == 'candidate' else value[1][name]['Mounts']
                key = 'target' if side == 'candidate' else 'Destination'
                next(row for row in rows if row[key] == target)['source' if side == 'candidate' else 'Source'] = '/unreviewed/' + CANARY
                with self.subTest(service=name, side=side):
                    self.refused(value)
        value = documents()
        value[0]['services']['serverware']['environment'][legacy.EXPECTED_DIGEST] = 'sha256:' + review.OLD_SHA
        self.refused(value)
        value = documents()
        value[1]['serverware']['Config']['Env'].append(legacy.EXPECTED_DIGEST + '=duplicate')
        self.refused(value)

    def test_provider_mount_is_exact_app_only_not_auto_created_or_propagated(self):
        for change in ('missing', 'source', 'readonly', 'create', 'propagation', 'duplicate', 'gate-exposure'):
            value = documents()
            mounts = value[0]['services']['serverware']['volumes']
            provider = next(row for row in mounts if row['target'] == '/provider-custody')
            if change == 'missing': mounts.remove(provider)
            elif change == 'source': provider['source'] = str(review.APP_DATA)
            elif change == 'readonly': provider['read_only'] = True
            elif change == 'create': provider['bind']['create_host_path'] = True
            elif change == 'propagation': provider['bind']['propagation'] = 'rshared'
            elif change == 'duplicate': mounts.append(deepcopy(provider))
            else: value[0]['services']['decision-gate-rs']['volumes'].append(deepcopy(provider))
            with self.subTest(change=change):
                self.refused(value)

    def test_compose_omitted_false_provider_readonly_is_the_same_reviewed_bind(self):
        for phase in ('proposed', 'deployed'):
            value = documents()
            if phase == 'deployed':
                value = deployed(value)
            expected = self.compare(value, phase=phase)
            provider = next(row for row in value[0]['services']['serverware']['volumes']
                if row['target'] == '/provider-custody')
            provider.pop('read_only')
            self.assertEqual(provider, {'type': 'bind', 'source': str(review.PROVIDER_CUSTODY),
                'target': '/provider-custody', 'bind': {'create_host_path': False}})
            before = deepcopy(value)
            with self.subTest(phase=phase):
                self.assertEqual(self.compare(value, phase=phase), expected)
                self.assertEqual(value, before)

    def test_provider_bind_default_omission_does_not_coerce_or_ignore_other_fields(self):
        changes = [
            ('readonly-' + str(index), lambda row, value=value: row.update(read_only=value))
            for index, value in enumerate((True, 0, 1, 0.0, None, 'false', [], {}))]
        changes.extend([
            ('unknown-field', lambda row: row.update(consistency='cached')),
            ('unknown-bind-field', lambda row: row['bind'].update(propagation='rprivate')),
            ('missing-bind', lambda row: row.pop('bind')),
            ('missing-create-guard', lambda row: row['bind'].pop('create_host_path')),
            ('null-bind', lambda row: row.update(bind=None)),
        ])
        changes.extend([
            ('create-guard-' + str(index), lambda row, value=value: row['bind'].update(create_host_path=value))
            for index, value in enumerate((True, 0, 1, 0.0, None, 'false'))])
        for phase in ('proposed', 'deployed'):
            for label, change in changes:
                value = documents()
                if phase == 'deployed':
                    value = deployed(value)
                provider = next(row for row in value[0]['services']['serverware']['volumes']
                    if row['target'] == '/provider-custody')
                provider.pop('read_only')
                change(provider)
                with self.subTest(phase=phase, change=label):
                    self.refused(value, phase=phase)

    def test_curated_gate_requires_only_exact_original_readonly_leaves(self):
        for target in ['/data', *('/data/' + leaf for leaf in review.LEAVES)]:
            for change in ('missing', 'source', 'rw', 'omitted-readonly', 'numeric-readonly', 'create'):
                value = documents()
                mounts = value[0]['services']['decision-gate-rs']['volumes']
                row = next(item for item in mounts if item['target'] == target)
                if change == 'missing': mounts.remove(row)
                elif change == 'source': row['source'] = str(review.APP_DATA / 'unreviewed')
                elif change == 'rw': row['read_only'] = False
                elif change == 'omitted-readonly': row.pop('read_only')
                elif change == 'numeric-readonly': row['read_only'] = 1
                else: row['bind']['create_host_path'] = True
                with self.subTest(target=target, change=change):
                    self.refused(value)
        value = documents()
        value[0]['services']['decision-gate-rs']['volumes'].append(mount('/app-private-data', review.APP_DATA))
        self.refused(value)
        value = documents()
        next(row for row in value[0]['services']['decision-gate-rs']['volumes'] if row['target'] == '/gate-data')['source'] += '-changed'
        self.refused(value)

    def test_unrelated_health_auth_process_resources_and_security_drift_refused(self):
        changes = (
            lambda service: service.update(cpus=2), lambda service: service.update(mem_limit=2048),
            lambda service: service.update(memswap_limit=4096), lambda service: service.update(pids_limit=64),
            lambda service: service.update(user='0:0'), lambda service: service.update(read_only=False),
            lambda service: service.update(command=['unreviewed']), lambda service: service.update(cap_add=['NET_ADMIN']),
            lambda service: service.update(security_opt=[]), lambda service: service.update(dns=['8.8.8.8']),
            lambda service: service.update(ports=['9090:9090']), lambda service: service.update(network_mode='host'),
            lambda service: service['healthcheck'].update(retries=4),
            lambda service: service['labels'].update({'traefik.http.routers.operator.middlewares': CANARY}),
        )
        for name in legacy.SERVICES:
            for index, change in enumerate(changes):
                value = documents()
                change(value[0]['services'][name])
                with self.subTest(service=name, mutation=index):
                    self.refused(value)

    def test_networks_and_top_level_extensions_are_not_normalized_away(self):
        changes = (
            lambda model: model['networks']['sandbox'].update(internal=False),
            lambda model: model['networks']['outbound']['ipam']['config'][0].update(subnet='172.16.249.48/28'),
            lambda model: model['networks']['traefik-v3-public'].update(external=False),
            lambda model: model.update({'x-unreviewed': {}}),
            lambda model: model['x-isolated'].update(read_only=False),
            lambda model: model['services'].update(provider={}),
            lambda model: model['services']['serverware']['networks']['sandbox'].update(ipv4_address='172.16.249.22'),
            lambda model: model['services']['decision-gate-rs']['networks']['outbound'].update(ipv4_address='172.16.249.35'),
        )
        for index, change in enumerate(changes):
            value = documents()
            change(value[0])
            with self.subTest(mutation=index):
                self.refused(value)

    def test_edge_template_path_exception_remains_bytes_only_and_fixture_has_none(self):
        self.assertTrue(self.compare(documents())['ok'])
        self.refused(documents(), digest=lambda path: str(path))
        value = documents()
        value[0]['services']['demo-upstream']['volumes'][0]['source'] = review.NEW_SOURCE
        self.refused(value)
        value = documents()
        value[0]['services']['edge']['environment']['NGINX_ENVSUBST_FILTER'] = '.*'
        self.refused(value)

    def test_postdeployment_verification_accepts_no_partial_upgrade_or_additional_delta(self):
        for name in ('serverware', 'decision-gate-rs', 'edge', 'demo-upstream'):
            for side in ('model', 'engine'):
                value = deployed(documents())
                if side == 'model': value[0]['services'][name]['environment']['UNREVIEWED_VALUE'] = CANARY
                else: value[1][name]['Config']['Env'].append('UNREVIEWED_VALUE=' + CANARY)
                with self.subTest(service=name, side=side):
                    self.refused(value, phase='deployed')
        value = deployed(documents())
        next(row for row in value[1]['decision-gate-rs']['Mounts'] if row['Destination'] == '/data')['Source'] = str(review.APP_DATA)
        self.refused(value, phase='deployed')
        self.refused(documents(), phase='unknown')

    def test_error_receipt_is_closed_even_for_unexpected_secret_bearing_errors(self):
        for error in (legacy.Refused(CANARY), RuntimeError(historical.SECRET), ValueError({'private': CANARY}), KeyError(CANARY)):
            receipt = review.error_receipt(error)
            self.assertEqual(receipt, {'ok': False, 'error': 'managed candidate comparison refused'})
            self.assertNotIn(CANARY, json.dumps(receipt))
            self.assertNotIn(historical.SECRET, json.dumps(receipt))


if __name__ == '__main__':
    unittest.main(verbosity=2)
