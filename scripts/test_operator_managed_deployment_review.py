#!/usr/bin/env python3
"""Sanitized model and repository recipe controls; no Docker or live env reads."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import operator_demo_deployment_review as legacy
from scripts import operator_managed_deployment_review as review
from scripts import test_operator_demo_deployment_review as historical


CANARY = 'synthetic-private-drift-value-never-public'
SYNTHETIC_CANDIDATE = {'binary_sha256': '7' * 64, 'layer_sha256': '8' * 64,
    'join_path': Path('/synthetic/public/compiler-join.json'), 'join_sha256': '9' * 64,
    'compiler_input_files': 499}


def rich_compiler_join():
    """Independent public receipt fixture; the executable digest is synthetic.

    No production expected-receipt helper is used as this test's oracle. These
    facts describe compiler-input equality, not a new build or full-tree match.
    """
    return {
        'allowedSourceChanges': [
            'docs/operator-npm-publish.md', 'scripts/check_operator_npm_publish.py',
            'scripts/test_operator_catalog_header_replacement.py',
            'scripts/test_operator_catalog_mutation_receipts.py',
            'scripts/test_operator_catalog_timing.py',
            'scripts/test_operator_npm_publish_breadcrumbs.py', 'serverware/app.py',
            'serverware/operator_catalog_api.py', 'serverware/operator_catalog_mutations.py',
            'serverware/operator_catalog_timing.py'],
        'archiveSha256': 'dd87e896b23be7c1698b1f242986692c22a1e32e889235870656e9a4d1e1ceb5',
        'binaryBuildCommit': 'b55f3024a0a2e696a462df723dae9a8a1fdded6a',
        'binaryBuildTree': '47359a0e049d1d9a731568e9de05264f93bf9b6f',
        'binarySha256': SYNTHETIC_CANDIDATE['binary_sha256'],
        'buildReceiptSha256': 'b4679c6b62b9e0add258fdc419b560d16be94e945025fc90298e881567e74382',
        'cargoManifestAndLockMatched': True,
        'compilerDepfileSha256': '63634621f9bf9c5cd273065f21175b89830de4d74a27daa603c1249f7f1ad880',
        'compilerInputGitModesMatched': True,
        'completeCrateFilesMatched': 745,
        'completeGitTreeEqualityClaimed': False,
        'exactCompilerInputFilesMatched': 499,
        'externalCompilerInputs': [
            'schemas/adapters/generic.rest.schema.json', 'schemas/adapters/gmail.read.v1.schema.json',
            'schemas/adapters/gmail.v1.schema.json', 'schemas/adapters/npm.metadata.v1.schema.json',
            'schemas/adapters/npm.publish.v1.schema.json', 'schemas/adapters/npm.registry.schema.json',
            'schemas/adapters/x.v2.schema.json', 'schemas/policy-bundle.v1.schema.json',
            'schemas/policy-bundle.v2.schema.json'],
        'freshRustTestsRun': 0,
        'newRustBuildClaimed': False,
        'retainedRustTestCommit': 'b55f3024a0a2e696a462df723dae9a8a1fdded6a',
        'retainedRustTestCount': 116,
        'retainedRustTestReceiptSha256': 'fc98d3de725e82c22faa26fb6bd71d3853b2394717cdc977f4f8e73d401fdd88',
        'schema': 'serverware.pythonSnapshotCompilerEquality/v1',
        'sourceCommit': '3724110941888e753bc194459e14170bc2a28916',
        'sourceManifestSha256': 'c11de979a8b8091940fdf22538e9844acff6bc5accc2b2980f4305afb5fe9228',
        'sourceTree': '23e2f96a8c0e9b9fbfbc25b272b1e42ccffe2f1e',
    }


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


def retained_documents():
    """Start from the original managed candidate, not an invented new baseline."""
    model, observed, images = deployed(documents())
    for name, target, source in (('serverware', '/app', review.RETAINED_SOURCE),
            ('decision-gate-rs', legacy.BINARY_TARGET, legacy.ARTIFACTS + 'sha256-'
                + SYNTHETIC_CANDIDATE['binary_sha256'] + '/serverware-decision-gate')):
        next(row for row in model['services'][name]['volumes'] if row['target'] == target)['source'] = source
    model['services']['serverware']['environment'][legacy.EXPECTED_DIGEST] = 'sha256:' + SYNTHETIC_CANDIDATE['binary_sha256']
    return model, observed, images


class ManagedDeploymentReviewTests(unittest.TestCase):
    def test_checked_in_layer_bytes_match_the_reviewed_pins(self):
        self.assertEqual(set(review.PINS), set(review.LAYERS))
        for path, expected in review.PINS.items():
            with self.subTest(layer=path.name):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_retained_recipe_changes_only_binary_pins_and_keeps_required_source_selection(self):
        selected = review.selection('retained')
        candidate = review.RETAINED_LAYER.read_bytes()
        self.assertEqual(hashlib.sha256(candidate).hexdigest(),
            'd2ef222b896243a7e582ea9f84a44a6b160ebf8cca058bd7a45196393451d383')
        self.assertEqual(selected['pins'][review.RETAINED_LAYER], hashlib.sha256(candidate).hexdigest())
        # Compare the complete executable YAML body to the already-pinned
        # historical layer, without inventing a permissive YAML normalizer.
        retained_body = review.MANAGED.read_bytes().split(b'services:\n', 1)[1]
        candidate_body = candidate.split(b'services:\n', 1)[1]
        old = b'333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0'
        new = b'82a99cf00a7763dd1187f86607ffe2415487e98734f4b7d585f44909150e7b85'
        self.assertEqual(retained_body.count(old), 2)
        self.assertEqual(candidate_body.count(new), 2)
        self.assertEqual(candidate_body, retained_body.replace(old, new))
        for required in (
                b'${OPERATOR_MANAGED_SOURCE:?Set the reviewed immutable managed source directory}',
                b'${OPERATOR_MANAGED_PROVIDER_CUSTODY_DIR:?Set the reviewed empty app-only provider custody directory}'):
            self.assertEqual(candidate_body.count(required), 1)
        self.assertEqual(selected['layers'], (legacy.BASE, review.RETAINED_LAYER, review.CURATED, legacy.NOTIFICATIONS))
        self.assertNotIn(review.RETAINED_LAYER, review.selection('migration')['layers'])

    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ('subprocess.run', 'socket.socket', 'socket.create_connection', 'socket.getaddrinfo', 'builtins.open'):
            stack.enter_context(patch(name, side_effect=AssertionError('pure comparator attempted external I/O')))

    def compare(self, value, *, phase='proposed', digest=lambda _: 'same-public-template-digest', provider=None,
                transition_mode='migration'):
        return review.compare_model(*value, provider_custody=review.PROVIDER_CUSTODY if provider is None else provider,
            digest_file=digest, phase=phase, transition_mode=transition_mode)

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


class RetainedDeploymentReviewTests(unittest.TestCase):
    """Pure comparator inputs; synthetic pins are not a compiled-build receipt."""
    compare = ManagedDeploymentReviewTests.compare
    refused = ManagedDeploymentReviewTests.refused

    def setUp(self):
        ManagedDeploymentReviewTests.setUp(self)
        candidate = patch.object(review, 'RETAINED_CANDIDATE', deepcopy(SYNTHETIC_CANDIDATE))
        candidate.start()
        self.addCleanup(candidate.stop)

    def test_explicit_retained_mode_admits_only_source_binary_and_expected_digest(self):
        value = retained_documents()
        before = deepcopy(value)
        result = self.compare(value, transition_mode='retained')
        self.assertTrue(result['ok'])
        self.assertEqual(result['approvedDifferences'], sorted(legacy.APPROVED_DELTAS))
        self.assertEqual(len(result['approvedDifferences']), 3)
        self.assertEqual(result['transitionMode'], 'retained')
        self.assertEqual(result['sourceCommit'], '3724110941888e753bc194459e14170bc2a28916')
        self.assertEqual(result['candidateBinarySha256'], SYNTHETIC_CANDIDATE['binary_sha256'])
        for field in ('rolloutVerified', 'runtimeMutationsPerformed', 'providerCustodyMetadataVerified', 'curatedFilesystemVerified'):
            self.assertFalse(result[field])
        self.assertEqual(value, before)
        self.refused(value)
        self.refused(deployed(documents()))
        self.refused(documents(), transition_mode='retained')
        self.refused(value, transition_mode='retained', phase='deployed')
        self.assertEqual(self.compare(deployed(value), transition_mode='retained', phase='deployed')['approvedDifferences'], [])
        self.refused(deployed(value), phase='deployed')
        # Selecting the new fixed profile must not alter either older mode.
        old = self.compare(documents())
        self.assertNotIn('transitionMode', old)
        self.assertEqual(old['approvedDifferences'], sorted(review.APPROVED_DELTAS))
        self.assertEqual(self.compare(deployed(documents()), phase='deployed')['approvedDifferences'], [])

    def test_retained_selection_is_closed_and_refuses_absent_or_incomplete_build_pins(self):
        selected = review.selection('retained')
        self.assertEqual(selected['transition'], (review.NEW_SOURCE, review.RETAINED_SOURCE,
            review.NEW_SHA, SYNTHETIC_CANDIDATE['binary_sha256'], review.NEW_BINARY,
            legacy.ARTIFACTS + 'sha256-' + SYNTHETIC_CANDIDATE['binary_sha256'] + '/serverware-decision-gate'))
        self.assertEqual(selected['source_manifest_sha256'], 'c11de979a8b8091940fdf22538e9844acff6bc5accc2b2980f4305afb5fe9228')
        self.assertEqual(selected['source_files'], 4952)
        self.assertEqual(selected['compiler_source_commit'], 'b55f3024a0a2e696a462df723dae9a8a1fdded6a')
        self.assertNotEqual(selected['compiler_source_commit'], selected['commit'])
        self.assertEqual(selected['compiler_input_files'], 499)
        self.assertIs(selected['new_build'], False)
        self.assertEqual(selected['layers'], (legacy.BASE, review.RETAINED_LAYER, review.CURATED, legacy.NOTIFICATIONS))
        self.assertEqual(set(selected['pins']), set(selected['layers']))
        self.assertEqual(selected['pins'][review.RETAINED_LAYER], SYNTHETIC_CANDIDATE['layer_sha256'])
        controls = [None, {}, {**SYNTHETIC_CANDIDATE, 'unreviewed': CANARY}]
        controls.extend({key: value for key, value in SYNTHETIC_CANDIDATE.items() if key != missing}
            for missing in SYNTHETIC_CANDIDATE)
        for field in ('binary_sha256', 'layer_sha256', 'join_sha256'):
            controls.extend({**SYNTHETIC_CANDIDATE, field: value}
                for value in ('', '0' * 64, 'A' * 64, '1' * 63, 'sha256:' + '1' * 64, None))
        controls.extend({**SYNTHETIC_CANDIDATE, 'binary_sha256': value}
            for value in (legacy.OLD_SHA, review.OLD_SHA, review.NEW_SHA))
        controls.extend({**SYNTHETIC_CANDIDATE, 'compiler_input_files': value} for value in (0, -1, 4097, True, 500.0, '500'))
        controls.extend({**SYNTHETIC_CANDIDATE, 'join_path': value}
            for value in (Path('relative.json'), Path('/synthetic/../join.json'), '/synthetic/join.json'))
        for index, value in enumerate(controls):
            with self.subTest(control=index), patch.object(review, 'RETAINED_CANDIDATE', value):
                self.refused(retained_documents(), transition_mode='retained')
                self.assertTrue(self.compare(documents())['ok'])
        for mode in ('', 'managed', 'migration,retained', None, True):
            with self.subTest(mode=mode):
                self.refused(retained_documents(), transition_mode=mode)

    def test_retained_mode_requires_both_previous_and_next_exact_source_binary_pairs(self):
        for name, target in (('serverware', '/app'), ('decision-gate-rs', legacy.BINARY_TARGET)):
            for side in ('candidate', 'baseline'):
                value = retained_documents()
                rows = value[0]['services'][name]['volumes'] if side == 'candidate' else value[1][name]['Mounts']
                key = 'target' if side == 'candidate' else 'Destination'
                next(row for row in rows if row[key] == target)['source' if side == 'candidate' else 'Source'] = '/unreviewed/' + CANARY
                with self.subTest(service=name, side=side):
                    self.refused(value, transition_mode='retained')
        for side in ('candidate', 'baseline'):
            value = retained_documents()
            if side == 'candidate':
                value[0]['services']['serverware']['environment'][legacy.EXPECTED_DIGEST] = 'sha256:' + review.NEW_SHA
            else:
                env = value[1]['serverware']['Config']['Env']
                env[:] = [field if not field.startswith(legacy.EXPECTED_DIGEST + '=')
                    else legacy.EXPECTED_DIGEST + '=sha256:' + review.OLD_SHA for field in env]
            with self.subTest(digest_side=side):
                self.refused(value, transition_mode='retained')

    def test_retained_managed_flags_are_existing_authority_not_new_ignored_environment(self):
        for phase in ('proposed', 'deployed'):
            for field in review.APP_MANAGED_ENV:
                for side in ('candidate', 'baseline'):
                    value = retained_documents()
                    if phase == 'deployed':
                        value = deployed(value)
                    if side == 'candidate':
                        value[0]['services']['serverware']['environment'].pop(field)
                    else:
                        env = value[1]['serverware']['Config']['Env']
                        env[:] = [row for row in env if not row.startswith(field + '=')]
                    with self.subTest(phase=phase, field=field, side=side):
                        self.refused(value, phase=phase, transition_mode='retained')
            for name in legacy.SERVICES:
                value = retained_documents() if phase == 'proposed' else deployed(retained_documents())
                value[0]['services'][name]['environment']['UNREVIEWED_VALUE'] = CANARY
                with self.subTest(phase=phase, service=name):
                    self.refused(value, phase=phase, transition_mode='retained')
            for key in ('SERVERWARE_GOOGLE_CLIENT_ID', 'SERVERWARE_OPERATOR_GOOGLE_PROFILE'):
                value = retained_documents() if phase == 'proposed' else deployed(retained_documents())
                value[0]['services']['serverware']['environment'][key] = CANARY
                value[1]['serverware']['Config']['Env'].append(key + '=' + CANARY)
                with self.subTest(phase=phase, external_profile=key):
                    self.refused(value, phase=phase, transition_mode='retained')

    def test_retained_provider_ca_lock_and_highwater_mounts_have_no_new_exception(self):
        targets = [('serverware', '/data'), ('serverware', '/provider-custody'),
            ('serverware', '/notification-custody'), ('decision-gate-rs', '/data'), ('decision-gate-rs', '/gate-data')]
        targets.extend(('decision-gate-rs', '/data/' + leaf) for leaf in review.LEAVES)
        for name, target in targets:
            for side in ('candidate', 'baseline'):
                for change in ('source', 'missing', 'access'):
                    value = retained_documents()
                    rows = value[0]['services'][name]['volumes'] if side == 'candidate' else value[1][name]['Mounts']
                    key = 'target' if side == 'candidate' else 'Destination'
                    row = next(row for row in rows if row[key] == target)
                    if change == 'source': row['source' if side == 'candidate' else 'Source'] += '-unreviewed'
                    elif change == 'missing': rows.remove(row)
                    else:
                        flag = 'read_only' if side == 'candidate' else 'RW'
                        row[flag] = not row[flag]
                    with self.subTest(service=name, target=target, side=side, change=change):
                        self.refused(value, transition_mode='retained')
        self.refused(retained_documents(), transition_mode='retained', provider=review.APP_DATA)
        value = retained_documents()
        next(row for row in value[0]['services']['serverware']['volumes']
            if row['target'] == '/provider-custody').pop('read_only')
        self.assertTrue(self.compare(value, transition_mode='retained')['ok'])

    def test_retained_mode_preserves_edge_auth_network_health_and_resource_guards(self):
        for name in legacy.SERVICES:
            for mutate in (lambda row: row.update(cpus=2), lambda row: row.update(user='0:0'),
                    lambda row: row['healthcheck'].update(retries=4), lambda row: row.update(ports=['9090:9090']),
                    lambda row: row.update(network_mode='host'), lambda row: row.update(cap_add=['NET_ADMIN']),
                    lambda row: row['labels'].update({'traefik.http.routers.operator.middlewares': CANARY})):
                value = retained_documents()
                mutate(value[0]['services'][name])
                with self.subTest(service=name):
                    self.refused(value, transition_mode='retained')
        for mutate in (lambda model: model['networks']['sandbox'].update(internal=False),
                lambda model: model['services'].update(provider={}),
                lambda model: model['services']['edge']['environment'].update(NGINX_ENVSUBST_FILTER='.*'),
                lambda model: model['services']['serverware']['environment'].update(SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED='0')):
            value = retained_documents()
            mutate(value[0])
            self.refused(value, transition_mode='retained')
        self.refused(retained_documents(), transition_mode='retained', digest=lambda path: str(path))

    def test_retained_public_artifact_receipt_requires_exact_source_manifest_and_compiler_join(self):
        selected = review.selection('retained')
        source, manifest = Path(review.RETAINED_SOURCE), Path('/synthetic/public/source-manifest.json')
        joined = rich_compiler_join()
        binaries = {review.NEW_BINARY: review.NEW_SHA, selected['binary']: SYNTHETIC_CANDIDATE['binary_sha256']}
        # Only public artifact-reading seams are inert. The actual selection,
        # pin propagation and exact receipt admission run unchanged; this is
        # not evidence that those source or binary artifacts exist on disk.
        with patch.object(review.archives, 'source_inventory', return_value=dict.fromkeys(range(4952), 'synthetic')) as inventory, \
                patch.object(review.os, 'walk', return_value=[(str(source), [], ['asset'])]), \
                patch.object(Path, 'stat', side_effect=lambda *args, **kwargs: SimpleNamespace(st_mode=0o555)), \
                patch.object(legacy, 'file_digest', side_effect=lambda path: binaries[path]) as hashed, \
                patch.object(review.archives, 'pinned_json', return_value=joined) as receipt:
            review.source_identity(source, manifest, transition_mode='retained')
            inventory.assert_called_once_with(source, manifest, review.RETAINED_MANIFEST_SHA, review.RETAINED_COMMIT)
            receipt.assert_called_once_with(SYNTHETIC_CANDIDATE['join_path'], SYNTHETIC_CANDIDATE['join_sha256'])
            self.assertEqual([call.args[0] for call in hashed.call_args_list], [review.NEW_BINARY, selected['binary']])
            self.assertEqual(receipt.return_value, rich_compiler_join())
            controls = [{**joined, field: CANARY} for field in joined]
            controls.extend({key: value for key, value in joined.items() if key != missing} for missing in joined)
            controls.extend((None, [], list(joined.items()), {**joined, 'unreviewed': CANARY}))
            # A lossy eight-field derivative is not the original rich receipt,
            # even when all of its overlapping facts happen to agree.
            old_join = {key: joined[key] for key in ('binarySha256', 'cargoManifestAndLockMatched',
                'completeGitTreeEqualityClaimed', 'exactCompilerInputFilesMatched', 'newRustBuildClaimed',
                'sourceCommit', 'sourceManifestSha256')}
            old_join['binarySourceCommit'] = joined['binaryBuildCommit']
            controls.append(old_join)
            for field, value in joined.items():
                if type(value) is bool:
                    controls.extend({**joined, field: changed} for changed in (int(value), not value, str(value)))
                elif type(value) is int:
                    controls.extend({**joined, field: changed} for changed in
                        (float(value), bool(value), str(value), value + 1, value - 1))
                elif type(value) is str:
                    # Same-shaped provenance substitutions must also refuse.
                    if field.endswith('Sha256'):
                        controls.append({**joined, field: '6' * 64})
                    elif field.endswith(('Commit', 'Tree')):
                        controls.append({**joined, field: '6' * 40})
                elif type(value) is list:
                    controls.extend({**joined, field: changed} for changed in (
                        tuple(value), value[:-1], value + [value[-1]], list(reversed(value)),
                        [*value[:-1], CANARY], [*value[:-1], 1]))
            controls.extend((
                {**joined, 'binaryBuildCommit': joined['sourceCommit']},
                {**joined, 'retainedRustTestCommit': joined['sourceCommit']},
                {**joined, 'sourceCommit': joined['binaryBuildCommit']},
                {**joined, 'binaryBuildTree': joined['sourceTree']},
                {**joined, 'externalCompilerInputs': [*joined['externalCompilerInputs'], 'serverware/app.py']},
                {**joined, 'allowedSourceChanges': [*joined['allowedSourceChanges'], 'data-plane/decision-gate-rs/src/main.rs']},
                {**joined, 'schema': 'serverware.pythonSnapshotCompilerEquality/v2'},
            ))
            for index, changed in enumerate(controls):
                receipt.return_value = changed
                with self.subTest(join_control=index):
                    with self.assertRaises(legacy.Refused) as caught:
                        review.source_identity(source, manifest, transition_mode='retained')
                    self.assertNotIn(CANARY, str(caught.exception))
                    self.assertEqual(review.error_receipt(caught.exception),
                        {'ok': False, 'error': 'managed candidate comparison refused'})
            receipt.return_value = joined
            for count in (0, 4930, 4951, 4953):
                inventory.return_value = dict.fromkeys(range(count), 'synthetic')
                with self.subTest(source_files=count), self.assertRaises(legacy.Refused):
                    review.source_identity(source, manifest, transition_mode='retained')
            inventory.return_value = dict.fromkeys(range(4952), 'synthetic')
            for binary in binaries:
                original = binaries[binary]
                binaries[binary] = '0' * 64
                with self.subTest(binary=binary), self.assertRaises(legacy.Refused):
                    review.source_identity(source, manifest, transition_mode='retained')
                binaries[binary] = original
            with self.assertRaises(legacy.Refused):
                review.source_identity(Path(review.NEW_SOURCE), manifest, transition_mode='retained')

    def test_migration_source_identity_retains_its_original_eight_field_receipt(self):
        selected = review.selection('migration')
        source, manifest = Path(review.NEW_SOURCE), Path('/synthetic/public/legacy-manifest.json')
        joined = {
            'binarySha256': '333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0',
            'binarySourceCommit': 'ff6d86b1a0267dcb5915e07684bdc5b216dbde7d',
            'cargoManifestAndLockMatched': True, 'completeGitTreeEqualityClaimed': False,
            'exactCompilerInputFilesMatched': 494, 'newRustBuildClaimed': False,
            'sourceCommit': '9222b4c090d77aa983d3c01be34e0a2ba79f8e6c',
            'sourceManifestSha256': 'b724e252161476dbd5106aadbb71c4229afb36e47c1528e4678e166333f7a3da'}
        binaries = {review.OLD_BINARY: review.OLD_SHA, review.NEW_BINARY: review.NEW_SHA}
        with patch.object(review.archives, 'source_inventory', return_value=dict.fromkeys(range(4910), 'synthetic')), \
                patch.object(review.os, 'walk', return_value=[(str(source), [], ['asset'])]), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=0o555)), \
                patch.object(legacy, 'file_digest', side_effect=lambda path: binaries[path]), \
                patch.object(review.archives, 'pinned_json', return_value=joined) as receipt, \
                patch.object(review, '_validate_retained_compiler_join', side_effect=AssertionError('retained branch in migration')):
            review.source_identity(source, manifest)
            receipt.assert_called_once_with(selected['join_path'], selected['join_sha256'])
            receipt.return_value = rich_compiler_join()
            with self.assertRaises(legacy.Refused):
                review.source_identity(source, manifest)


if __name__ == '__main__':
    unittest.main(verbosity=2)
