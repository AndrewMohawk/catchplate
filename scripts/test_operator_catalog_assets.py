#!/usr/bin/env python3
"""Offline credential-first catalog asset checks; no app configuration or I/O."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import operator_demo_portal

ASSETS = ROOT / 'catchplate/operator_demo_web'


class Elements(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.items = []
        self.form = None
        self.in_navigation = False
        self.navigation = []
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.form = attrs.get('id')
        if tag == 'nav':
            self.in_navigation = True
        if self.in_navigation and tag == 'a':
            self.navigation.append(attrs)
        self.items.append((tag, attrs, self.form))

    def handle_endtag(self, tag):
        if tag == 'form':
            self.form = None
        if tag == 'nav':
            self.in_navigation = False


class OperatorCatalogAssets(unittest.TestCase):
    def setUp(self):
        operator_demo_portal.render.cache_clear()
        self.addCleanup(operator_demo_portal.render.cache_clear)

    def elements(self):
        return Elements(operator_demo_portal.render()).items

    def test_renderer_reads_only_public_assets_without_configuration_or_network(self):
        original = Path.read_text
        reads = []

        def read(path, *args, **kwargs):
            self.assertEqual(path.parent, ASSETS)
            self.assertIn(path.suffix, {'.html', '.css', '.js'})
            reads.append(path.name)
            return original(path, *args, **kwargs)

        with patch.object(Path, 'read_text', read), \
                patch('socket.socket', side_effect=AssertionError('network access')), \
                patch('os.getenv', side_effect=AssertionError('configuration access')):
            document = operator_demo_portal.render()
            self.assertEqual(document, operator_demo_portal.render())
        self.assertIn('index.html', reads)
        self.assertIn('style.css', reads)
        self.assertEqual(reads.count('workspace_npm.js'), 1)
        self.assertLess(reads.index('workspace_npm.js'), reads.index('workspace_connect.js'))
        self.assertLess(reads.index('workspace_npm.js'), reads.index('app.js'))
        self.assertEqual(reads.count('workspace_npm_publish.js'), 1)
        self.assertLess(reads.index('workspace_npm.js'), reads.index('workspace_npm_publish.js'))
        self.assertLess(reads.index('workspace_npm_publish.js'), reads.index('workspace_resources.js'))
        self.assertLess(reads.index('workspace_npm_publish.js'), reads.index('workspace_proxy_audit.js'))
        self.assertLess(reads.index('workspace_npm_publish.js'), reads.index('workspace_connect.js'))
        for provider in ('workspace_x.js', 'workspace_alchemy.js'):
            self.assertEqual(reads.count(provider), 1)
            self.assertLess(reads.index('workspace_core.js'), reads.index(provider))
            for consumer in ('workspace_resources.js', 'workspace_proxy_audit.js', 'workspace_connect.js', 'app.js'):
                self.assertLess(reads.index(provider), reads.index(consumer))
        self.assertEqual(reads.count('workspace_notifications.js'), 1)
        self.assertEqual(reads.count('workspace_inventory.js'), 1)
        self.assertLess(reads.index('workspace_inventory.js'), reads.index('workspace_resources.js'))
        self.assertLess(reads.index('workspace_inventory.js'), reads.index('workspace_applications.js'))
        self.assertEqual(reads.count('workspace_pending_actions.js'), 1)
        self.assertLess(reads.index('workspace_pending_actions.js'), reads.index('app.js'))
        self.assertEqual(reads.count('workspace_upstreams.js'), 1)
        self.assertLess(reads.index('workspace_upstreams.js'), reads.index('app.js'))
        self.assertNotIn('__OPERATOR_DEMO_', document)
        self.assertNotIn('catchplate.app', sys.modules)
        self.assertNotIn('catchplate.config', sys.modules)

    def test_unique_ids_and_separate_navigation_targets(self):
        items = self.elements()
        ids = [attrs['id'] for _, attrs, _ in items if 'id' in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        index = {attrs['id']: (tag, attrs) for tag, attrs, _ in items if 'id' in attrs}
        for name in ('overview', 'credentials', 'applications', 'access-rules', 'pending-actions', 'proxy', 'audit', 'notifications'):
            self.assertEqual(index[name][0], 'section')
            self.assertTrue(any(tag == 'a' and attrs.get('href') == '#' + name for tag, attrs, _ in items))

    def test_role_guidance_navigation_and_settings_are_separate(self):
        document = operator_demo_portal.render()
        index = {attrs['id']: (tag, attrs) for tag, attrs, _ in self.elements() if 'id' in attrs}
        self.assertEqual(index['workspace-menu-toggle'][1]['aria-expanded'], 'false')
        self.assertEqual(index['workspace-menu-toggle'][1]['type'], 'button')
        for target in index['workspace-menu-toggle'][1]['aria-controls'].split():
            self.assertIn(target, index)
        self.assertEqual(index['overview-developer-action'][1]['href'], '#proxy')
        self.assertEqual(index['proxy-settings-tab'][1]['href'], '#proxy-operator-settings')
        self.assertIn('hidden', index['proxy-operator-settings'][1])
        self.assertEqual(index['client-existing-settings'][0], 'details')
        self.assertNotIn('open', index['client-existing-settings'][1])
        self.assertLess(document.index('id="client-selection"'), document.index('id="ca-download"'))
        self.assertLess(document.index('id="download-config"'), document.index('id="provider-config-handoff"'))
        self.assertIn('No provider key or administrator account is needed', document)

    def test_mcp_help_is_a_static_local_client_guide_beside_private_config(self):
        document = operator_demo_portal.render()
        links = [(tag, attrs, form) for tag, attrs, form in self.elements() if attrs.get('id') == 'client-mcp-guide']
        self.assertEqual(len(links), 1)
        tag, attrs, form = links[0]
        self.assertEqual(tag, 'a')
        self.assertIsNone(form)
        self.assertEqual(attrs, {'id': 'client-mcp-guide',
            'href': 'https://github.com/AndrewMohawk/catchplate/blob/main/examples/mcp/README.md',
            'target': '_blank', 'rel': 'noopener noreferrer'})
        self.assertLess(document.index('id="download-config"'), document.index('id="client-mcp-help"'))
        self.assertLess(document.index('id="client-mcp-help"'), document.index('id="client-examples"'))
        self.assertIn('For selected supported presets, run the local MCP helper with your downloaded client config.', document)
        self.assertIn('Provider keys stay server-side; this is not a hosted MCP or admin endpoint.', document)

    def test_navigation_separates_credentials_clients_and_permissions_from_setup_action(self):
        document = operator_demo_portal.render()
        parsed = Elements(document)
        self.assertEqual([item['href'] for item in parsed.navigation], [
            '#overview', '#credentials', '#applications', '#access-rules',
            '#pending-actions', '#proxy', '#audit', '#notifications'])
        self.assertRegex(document, r'href="#credentials">Credentials</a>')
        self.assertRegex(document, r'href="#applications">Clients</a>')
        self.assertRegex(document, r'id="overview-connect-service"[^>]*>Set up access</a>')
        self.assertNotIn('Accounts &amp; keys', document)

    def test_one_instance_presentation_keeps_security_status_and_optional_diagnostics(self):
        document = operator_demo_portal.render()
        index = {attrs['id']: (tag, attrs) for tag, attrs, _ in self.elements() if 'id' in attrs}
        for previous in ('Explore synthetic demo', 'Connect a real service',
                'Separate operator-development profile', 'My test API key'):
            self.assertNotIn(previous, document)
        self.assertIn('Your Catchplate instance', document)
        self.assertIn('Host-trusted deployment', document)
        self.assertIn('Server administrators can access credentials and override controls.', document)
        self.assertNotIn('Development deployment', document)
        self.assertNotIn('not hardware-verified or production-ready', document)
        self.assertNotIn('Hardware verification and production commissioning are not established', document)
        self.assertEqual(index['instance-hardware-status'][0], 'p')
        self.assertEqual(index['instance-production-status'][0], 'p')
        self.assertIn('<strong>Hardware verification:</strong> Not enabled.', document)
        self.assertIn('<strong>Production readiness:</strong> Not assessed by this page.', document)
        self.assertIn('Hardware verification is optional for a host-trusted deployment.', document)
        self.assertEqual(index['overview-diagnostics'][0], 'details')
        self.assertNotIn('open', index['overview-diagnostics'][1])
        self.assertIn('Diagnostics (optional)', document)
        self.assertEqual(index['overview-try-demo'][1]['type'], 'button')
        self.assertEqual(index['overview-try-demo'][1]['aria-expanded'], 'false')
        self.assertIn('hidden', index['overview-demo-panel'][1])
        self.assertEqual(index['overview-connect-service'][1]['href'], '#connect')
        for name in ('connect-credential-name',):
            self.assertEqual(index[name][1]['placeholder'], 'My API key')
            self.assertNotIn('value', index[name][1])

    def test_credentials_open_one_shared_editor_without_a_duplicate_secret_form(self):
        index = {attrs['id']: (tag, attrs, form) for tag, attrs, form in self.elements() if 'id' in attrs}
        self.assertEqual(index['credential-add'][0], 'button')
        self.assertEqual(index['credential-add'][1]['type'], 'button')
        self.assertIsNone(index['credential-add'][2])
        for removed in ('credential-name', 'credential-auth-type', 'credential-header-name', 'credential-secret', 'credential-save'):
            self.assertNotIn(removed, index)
        self.assertEqual(index['connect-credential-secret'][2], 'connect-credential-form')
        self.assertEqual(index['connect-credential-secret'][1]['type'], 'password')
        self.assertIn('required', index['connect-credential-secret'][1])
        self.assertNotIn('value', index['connect-credential-secret'][1])
        self.assertIn('hidden', index['connect-credential-saved'][1])
        for name in ('connect-saved-use', 'connect-saved-done'):
            self.assertEqual(index[name][0], 'button')
            self.assertEqual(index[name][1]['type'], 'button')
            self.assertIsNone(index[name][2])

    def test_connection_method_choice_precedes_separate_hidden_forms(self):
        index = {attrs['id']: (tag, attrs, form) for tag, attrs, form in self.elements() if 'id' in attrs}
        for name in ('connect-google', 'connect-use-key', 'connect-use-saved'):
            self.assertEqual(index[name][0], 'button')
            self.assertIsNone(index[name][2])
            self.assertIn('disabled', index[name][1])
        for name in ('connect-credential-form', 'connect-google-slot', 'google-consent-panel'):
            self.assertIn('hidden', index[name][1])
        self.assertEqual(index['connect-credential-secret'][2], 'connect-credential-form')
        self.assertEqual(index['google-account-name'][2], 'google-start-form')
        self.assertIsNone(index['google-consent-use'][2])

    def test_application_has_explicit_bounded_lifetime_and_empty_one_time_token(self):
        index = {attrs['id']: (tag, attrs) for tag, attrs, _ in self.elements() if 'id' in attrs}
        self.assertEqual(index['application-token-ttl'][0], 'select')
        self.assertEqual(index['client-token'][1]['type'], 'password')
        self.assertIn('readonly', index['client-token'][1])
        self.assertIn('disabled', index['client-token'][1])
        self.assertNotIn('value', index['client-token'][1])
        self.assertIn('hidden', index['one-time-access'][1])

    def test_npm_is_explicit_metadata_only_and_keeps_notifications_separate(self):
        index = {attrs['id']: (tag, attrs, form) for tag, attrs, form in self.elements() if 'id' in attrs}
        self.assertEqual(index['connect-use-npm'][0], 'button')
        self.assertIsNone(index['connect-use-npm'][2])
        self.assertIn('disabled', index['connect-use-npm'][1])
        self.assertIn('hidden', index['connect-npm-packages-group'][1])
        self.assertEqual(index['connect-npm-packages'][2], 'connect-access-form')
        self.assertIn('disabled', index['connect-npm-packages'][1])
        self.assertNotIn('value', index['connect-credential-secret'][1])
        self.assertIn('hidden', index['npm-client-controls'][1])
        self.assertEqual(index['notifications'][0], 'section')
        npm = (ASSETS / 'workspace_npm.js').read_text()
        self.assertIn('Read package metadata', npm)
        self.assertIn('No install, publish, tarball', npm)
        self.assertNotIn('/api/operator-demo/notifications', npm)
        self.assertNotIn('workspace_notifications', npm)

    def test_upstreams_are_explicit_prepare_not_hot_apply_or_credential_settings(self):
        index = {attrs['id']: (tag, attrs, form) for tag, attrs, form in self.elements() if 'id' in attrs}
        self.assertEqual(index['proxy-upstreams'][0], 'article')
        self.assertIn('hidden', index['upstreams-form'][1])
        self.assertIn('hidden', index['upstreams-operation'][1])
        self.assertEqual(index['upstreams-proposed'][2], 'upstreams-form')
        self.assertIn('disabled', index['upstreams-fields'][1])
        self.assertIsNone(index['upstreams-review'][2])
        upstreams = (ASSETS / 'workspace_upstreams.js').read_text()
        self.assertNotIn('/api/operator-demo/credentials', upstreams)
        self.assertNotIn('/api/operator-demo/notifications', upstreams)
        self.assertNotIn('applications/rotate-token', upstreams)
        self.assertIn("element('proxy-operator-settings').append(panel)", upstreams)
        self.assertNotIn("home.insertBefore(panel, element('proxy-setup-content'))", upstreams)
        self.assertIn('JSON.stringify(receipt.target_settings.allowed_upstreams)', upstreams)

    def test_npm_publishing_is_a_separate_explicit_form_without_response_or_approval_fields(self):
        index = {attrs['id']: (tag, attrs, form) for tag, attrs, form in self.elements() if 'id' in attrs}
        self.assertIn('hidden', index['connect-npm-publish-group'][1])
        self.assertIn('hidden', index['npm-publish-client-controls'][1])
        for name in ('package', 'tag', 'hours', 'start', 'end'):
            item = index['connect-npm-publish-' + name]
            self.assertEqual(item[2], 'connect-access-form')
            self.assertIn('disabled', item[1])
        self.assertEqual(index['connect-npm-publish-tag'][1]['value'], 'latest')
        self.assertFalse(any(name.startswith('connect-npm-publish-') and
            attrs.get('type') == 'checkbox' for name, (_, attrs, _) in index.items()))
        source = (ASSETS / 'workspace_npm_publish.js').read_text()
        self.assertIn('catchplate.operatorNpmPublish/v1', source)
        self.assertIn('metadata at any time', source)
        for forbidden in ('fetch(', 'sessionStorage', 'localStorage', '/api/operator-demo/notifications'):
            self.assertNotIn(forbidden, source)

    def test_rules_reference_both_resources_and_keep_projection_out_of_credentials(self):
        items = self.elements()
        index = {attrs['id']: (tag, attrs, form) for tag, attrs, form in items if 'id' in attrs}
        for name in ('rule-application-id', 'rule-credential-id'):
            self.assertEqual(index[name][0], 'select')
            self.assertEqual(index[name][2], 'access-rule-form')
        self.assertIn('required', index['rule-response-fields'][1])
        methods = [attrs['value'] for tag, attrs, form in items
            if tag == 'input' and attrs.get('name') == 'rule-method' and form == 'access-rule-form']
        self.assertEqual(methods, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])

    def test_ca_and_uncertainty_controls_have_explicit_boundaries(self):
        index = {attrs['id']: (tag, attrs) for tag, attrs, _ in self.elements() if 'id' in attrs}
        self.assertEqual(index['ca-download'][1]['href'], '/ca.pem')
        self.assertEqual(index['ca-download'][1]['download'], 'catchplate-ca.pem')
        self.assertIn('hidden', index['mutation-review'][1])
        self.assertIn('disabled', index['mutation-review-confirm'][1])
        self.assertIn('disabled', index['credential-google-connect'][1])

    def test_no_persistent_secret_store_or_unsafe_rendering_transport(self):
        scripts = {path.name: path.read_text() for path in sorted(ASSETS.glob('*.js'))}
        script = '\n'.join(scripts.values())
        for forbidden in ('localStorage', 'indexedDB', 'innerHTML', '--insecure', '--proxy-insecure'):
            self.assertFalse(forbidden in script, forbidden + ' is not permitted in public assets')
        for name, source in scripts.items():
            if name not in {'workspace_core.js', 'workspace_google_reauthorization.js', 'workspace_google_configuration.js', 'workspace_x_configuration.js', 'workspace_x_accounts.js', 'workspace_notifications.js', 'workspace_upstreams.js', 'workspace_pending_actions.js', 'workspace_ecr_publications.js'}:
                self.assertFalse('sessionStorage' in source, name + ' must not persist client state')
        # Existing ECR recovery markers contain only a public publication ID,
        # not a token, key, review payload or provider response.
        ecr = scripts['workspace_ecr_publications.js']
        self.assertEqual(ecr.count('sessionStorage.setItem('), 2)
        self.assertIn('sessionStorage.setItem(marker(item.id), item.id)', ecr)
        self.assertIn('sessionStorage.setItem(retirementMarker(item.id), item.id)', ecr)
        self.assertNotIn('sessionStorage.clear', ecr)
        core = scripts['workspace_core.js']
        self.assertIn("const key = 'catchplate.operator.mutation.review.v1', value = 'required';", core)
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', core), ['key, value'])
        self.assertEqual(re.findall(r'sessionStorage\.removeItem\(([^)]*)\)', core), ['key'])
        self.assertNotIn('sessionStorage.clear', core)
        self.assertLess(core.index('if (!recovery.retain())'),
                        core.index("const pending = api('/api/operator-demo/' + path"))
        pending_actions = scripts['workspace_pending_actions.js']
        self.assertIn("sessionStorage.getItem('catchplate.approvalDecisionUncertain.' + id)", pending_actions)
        # Explicit host-trusted decisions retain only the public request ID so
        # a lost response cannot invite a duplicate decision. Metadata reads do
        # not write a review receipt, decision body, token or provider secret.
        self.assertIn("const key = 'catchplate.hostApprovalDecisionUncertain.' + item.id;", pending_actions)
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', pending_actions), ['key, item.id'])
        self.assertEqual(re.findall(r'sessionStorage\.removeItem\(([^)]*)\)', pending_actions),
                         ["'catchplate.hostApprovalDecisionUncertain.' + item.id"])
        self.assertNotIn('sessionStorage.clear', pending_actions)
        # Reauthorization retains only a public operation UUID for lost-response
        # recovery. Its existing browser suite checks the actual storage value;
        # no provider secret or application token may use this exception.
        recovery = scripts['workspace_google_reauthorization.js']
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', recovery), ['storageKey, id'])
        self.assertIn('reauthorizationUuid(id)', recovery)
        configuration = scripts['workspace_google_configuration.js']
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', configuration),
                         ['googleConfigurationKey, raw', 'googleConfigurationKey, priorRaw'])
        self.assertIn('const raw = JSON.stringify(next); sessionStorage.setItem(googleConfigurationKey, raw);', configuration)
        self.assertIn('reference = next; retainedRaw = raw; receipt = null;', configuration)
        self.assertIn('if (!googleConfigurationReference(parsed)) throw new Error(); reference = parsed; retainedRaw = raw;', configuration)
        self.assertIn("const selected = {operation_id: discovery.operation.operation_id, kind: 'prepare'};", configuration)
        self.assertIn('const priorRaw = retainedRaw;', configuration)
        self.assertIn('if (priorRaw !== null) sessionStorage.setItem(googleConfigurationKey, priorRaw);', configuration)
        self.assertIn("googleConfigurationKey = 'catchplate.operator.google.configuration.operation.v2'", configuration)
        self.assertIn("upstreamObject(value, ['operation_id', 'kind']) && upstreamUUID(value.operation_id)", configuration)
        self.assertIn("['prepare', 'cancel'].includes(value.kind)", configuration)
        self.assertIn('if (!retain({operation_id: payload.operation_id, kind}))', configuration)
        self.assertLess(configuration.index('if (!retain({operation_id: payload.operation_id, kind}))'),
                        configuration.index("const pending = request(googleConfigurationPath +"))
        # X first-save recovery stores the UUID string alone, not its client
        # settings, receipt or secret. Close every storage access, the single
        # save producer and confirmed retirement. Viewing history cannot write.
        def assert_x_public_reference(source):
            self.assertEqual(re.findall(r'\bsessionStorage\.([A-Za-z]+)\(([^)]*)\)', source),
                             [('getItem', 'xConfigurationKey'), ('setItem', 'xConfigurationKey, id'),
                              ('getItem', 'xConfigurationKey'), ('removeItem', 'xConfigurationKey'),
                              ('getItem', 'xConfigurationKey')])
            self.assertEqual(len(re.findall(r'\bsessionStorage\b', source)), 5)
            self.assertIn("xConfigurationKey = 'catchplate.operator.x.configuration.operation.v1'", source)
            self.assertIn('if (saved !== null) { if (!upstreamUUID(saved)) throw new Error(); operationId = saved; }', source)
            self.assertEqual(re.findall(r'\bretain\(([^()]*)\)', source),
                             ['id', 'payload.operation_id'])
            self.assertIn('operationId !== id || sessionStorage.getItem(xConfigurationKey) !== id', source)
            self.assertIn('if (sessionStorage.getItem(xConfigurationKey) !== null) throw new Error();', source)
            self.assertIn('if (!refreshed || !current())', source)
            self.assertIn('retire(operationId);', source)
            self.assertIn('const next = projectXConfiguration(await request(xConfigurationPath));', source)
            self.assertIn('payload = {operation_id: crypto.randomUUID(),', source)
            self.assertLess(source.index('if (!retain(payload.operation_id))'),
                            source.index('const pending = request(xConfigurationPath, payload);'))

        x_configuration = scripts['workspace_x_configuration.js']
        assert_x_public_reference(x_configuration)
        for original, replacement in (
                ('sessionStorage.setItem(xConfigurationKey, id)',
                 'sessionStorage.setItem(xConfigurationKey, JSON.stringify(payload))'),
                ('retain(payload.operation_id)', 'retain(payload.client_secret)'),
                ('if (!upstreamUUID(saved))', 'if (!saved)'),
                ('sessionStorage.setItem(xConfigurationKey, id)',
                 "sessionStorage['setItem'](xConfigurationKey, id)")):
            with self.subTest(x_storage_boundary=original):
                altered = x_configuration.replace(original, replacement)
                self.assertNotEqual(altered, x_configuration)
                with self.assertRaises(AssertionError):
                    assert_x_public_reference(altered)
        with self.assertRaises(AssertionError):
            assert_x_public_reference(x_configuration + '\nsessionStorage.setItem(xConfigurationKey, secret);')
        # Account consent/disconnect has its own raw public UUID reference.
        # Both producers are closed: validated callback UUID or generated UUID
        # retained before a POST. No OAuth state, URL, code or body is stored.
        def assert_x_account_reference(source):
            self.assertEqual(re.findall(r'\bsessionStorage\.setItem\(([^)]*)\)', source),
                             ['xAccountStorageKey, operationId', 'xAccountStorageKey, id'])
            accesses = re.findall(r'\bsessionStorage\.([A-Za-z]+)\(([^)]*)\)', source)
            self.assertEqual(len(re.findall(r'\bsessionStorage\b', source)), len(accesses))
            self.assertTrue(all(method in {'getItem', 'setItem', 'removeItem'} and
                                arguments.split(',')[0] == 'xAccountStorageKey' for method, arguments in accesses))
            self.assertIn("xAccountStorageKey = 'catchplate.operator.x.account.operation.v1'", source)
            self.assertIn('if (!upstreamUUID(saved)) throw new Error(); operationId = saved;', source)
            self.assertIn('callbackIds.length !== 1 || !upstreamUUID(callbackIds[0])', source)
            self.assertIn('operationId = callbackIds[0];', source)
            self.assertIn('if (!upstreamUUID(id) || operationId)', source)
            self.assertEqual(source.count('retain(crypto.randomUUID());'), 2)
            self.assertLess(source.index('retain(crypto.randomUUID());'), source.index('workspace.api(paths.start_path,'))
            self.assertLess(source.rindex('retain(crypto.randomUUID());'), source.index('workspace.api(paths.disconnect_path,'))
            self.assertIn('sessionStorage.getItem(xAccountStorageKey) !== operationId', source)
        x_accounts = scripts['workspace_x_accounts.js']
        assert_x_account_reference(x_accounts)
        for original, replacement in (
                ('sessionStorage.setItem(xAccountStorageKey, id)', 'sessionStorage.setItem(xAccountStorageKey, authorization)'),
                ('!upstreamUUID(callbackIds[0])', '!callbackIds[0]'),
                ('retain(crypto.randomUUID());', 'retain(secret);')):
            with self.subTest(x_account_storage_boundary=original):
                with self.assertRaises(AssertionError):
                    assert_x_account_reference(x_accounts.replace(original, replacement))
        # Notifications stores a different closed public recovery reference
        # before its one POST. Real browser fixtures check the exact stored
        # fields, secret clearing, uncertainty, 404 retention and no replay.
        notifications = scripts['workspace_notifications.js']
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', notifications),
                         ['notificationOperationKey, JSON.stringify(nextReference'])
        self.assertIn("notificationOperationKey = 'catchplate.operator.notifications.operation.v1'", notifications)
        self.assertIn("notificationObject(value, ['operation_id', 'kind', 'slot', 'expected_revision'])", notifications)
        reference = re.search(r'const nextReference = \{([^}]+)\};', notifications)
        self.assertIsNotNone(reference)
        self.assertEqual(re.findall(r'([a-z_]+):', reference.group(1)) +
                         re.findall(r'(?:^|,)\s*(kind)\s*(?:,|$)', reference.group(1)),
                         ['operation_id', 'slot', 'expected_revision', 'kind'])
        self.assertNotIn('url', reference.group(1))
        self.assertLess(notifications.index('sessionStorage.setItem(notificationOperationKey'),
                        notifications.index("const response = request(prefix +"))
        upstreams = scripts['workspace_upstreams.js']
        self.assertIn("upstreamOperationKey = 'catchplate.operator.upstreams.operation.v1'", upstreams)
        self.assertIn("upstreamObject(value, ['operation_id', 'kind'])", upstreams)
        self.assertIn("if (!retain({operation_id: body.operation_id, kind}))", upstreams)
        self.assertIn("request(upstreamSetupPath + '/' + reference.operation_id)", upstreams)
        self.assertNotIn('localStorage', upstreams)
        self.assertIn('BroadcastChannel', script)
        self.assertIn('/api/operator-demo/catalog', script)
        self.assertNotIn('/api/operator-demo/connections', script)

    def test_renderer_rejects_missing_and_duplicate_asset_markers(self):
        original = Path.read_text
        for marker in ('__OPERATOR_DEMO_STYLE__', '__OPERATOR_DEMO_SCRIPT__'):
            for replacement in ('', marker + marker):
                with self.subTest(marker=marker, copies=replacement.count(marker)):
                    operator_demo_portal.render.cache_clear()

                    def read(path, *args, **kwargs):
                        value = original(path, *args, **kwargs)
                        return value.replace(marker, replacement) if path.name == 'index.html' else value

                    with patch.object(Path, 'read_text', read), self.assertRaisesRegex(RuntimeError, 'marker is missing or duplicated'):
                        operator_demo_portal.render()

    def test_renderer_rejects_case_insensitive_raw_text_terminators(self):
        original = Path.read_text
        for filename, terminator in (('app.js', '</script>'), ('workspace_core.js', '</ScRiPt>'),
                                     ('style.css', '</style>'), ('style.css', '</StYlE>')):
            with self.subTest(filename=filename, terminator=terminator):
                operator_demo_portal.render.cache_clear()

                def read(path, *args, **kwargs):
                    value = original(path, *args, **kwargs)
                    return value + terminator if path.name == filename else value

                with patch.object(Path, 'read_text', read), self.assertRaisesRegex(RuntimeError, 'raw-text terminator'):
                    operator_demo_portal.render()


if __name__ == '__main__':
    unittest.main(verbosity=2)
