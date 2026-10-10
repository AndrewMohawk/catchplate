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
from serverware import operator_demo_portal

ASSETS = ROOT / 'serverware/operator_demo_web'


class Elements(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.items = []
        self.form = None
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.form = attrs.get('id')
        self.items.append((tag, attrs, self.form))

    def handle_endtag(self, tag):
        if tag == 'form':
            self.form = None


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
        self.assertNotIn('__OPERATOR_DEMO_', document)
        self.assertNotIn('serverware.app', sys.modules)
        self.assertNotIn('serverware.config', sys.modules)

    def test_unique_ids_and_separate_navigation_targets(self):
        items = self.elements()
        ids = [attrs['id'] for _, attrs, _ in items if 'id' in attrs]
        self.assertEqual(len(ids), len(set(ids)))
        index = {attrs['id']: (tag, attrs) for tag, attrs, _ in items if 'id' in attrs}
        for name in ('overview', 'credentials', 'applications', 'access-rules', 'proxy', 'audit', 'notifications'):
            self.assertEqual(index[name][0], 'section')
            self.assertTrue(any(tag == 'a' and attrs.get('href') == '#' + name for tag, attrs, _ in items))

    def test_credential_form_has_no_endpoint_application_or_response_requirements(self):
        fields = {attrs['id']: (tag, attrs) for tag, attrs, form in self.elements()
            if form == 'credential-form' and tag in {'input', 'select', 'textarea'} and 'id' in attrs}
        self.assertEqual(set(fields), {'credential-name', 'credential-auth-type', 'credential-header-name', 'credential-secret'})
        self.assertIn('required', fields['credential-name'][1])
        self.assertIn('required', fields['credential-secret'][1])
        self.assertEqual(fields['credential-secret'][1]['type'], 'password')
        self.assertNotIn('value', fields['credential-secret'][1])

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
        self.assertEqual(index['ca-download'][1]['download'], 'serverware-ca.pem')
        self.assertIn('hidden', index['mutation-review'][1])
        self.assertIn('disabled', index['mutation-review-confirm'][1])
        self.assertIn('disabled', index['credential-google-connect'][1])

    def test_no_persistent_secret_store_or_unsafe_rendering_transport(self):
        scripts = {path.name: path.read_text() for path in sorted(ASSETS.glob('*.js'))}
        script = '\n'.join(scripts.values())
        for forbidden in ('localStorage', 'indexedDB', 'innerHTML', '--insecure', '--proxy-insecure'):
            self.assertFalse(forbidden in script, forbidden + ' is not permitted in public assets')
        for name, source in scripts.items():
            if name not in {'workspace_google_reauthorization.js', 'workspace_notifications.js'}:
                self.assertFalse('sessionStorage' in source, name + ' must not persist client state')
        # Reauthorization retains only a public operation UUID for lost-response
        # recovery. Its existing browser suite checks the actual storage value;
        # no provider secret or application token may use this exception.
        recovery = scripts['workspace_google_reauthorization.js']
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', recovery), ['storageKey, id'])
        self.assertIn('reauthorizationUuid(id)', recovery)
        # Notifications stores a different closed public recovery reference
        # before its one POST. Real browser fixtures check the exact stored
        # fields, secret clearing, uncertainty, 404 retention and no replay.
        notifications = scripts['workspace_notifications.js']
        self.assertEqual(re.findall(r'sessionStorage\.setItem\(([^)]*)\)', notifications),
                         ['notificationOperationKey, JSON.stringify(nextReference'])
        self.assertIn("notificationOperationKey = 'serverware.operator.notifications.operation.v1'", notifications)
        self.assertIn("notificationObject(value, ['operation_id', 'kind', 'slot', 'expected_revision'])", notifications)
        reference = re.search(r'const nextReference = \{([^}]+)\};', notifications)
        self.assertIsNotNone(reference)
        self.assertEqual(re.findall(r'([a-z_]+):', reference.group(1)) +
                         re.findall(r'(?:^|,)\s*(kind)\s*(?:,|$)', reference.group(1)),
                         ['operation_id', 'slot', 'expected_revision', 'kind'])
        self.assertNotIn('url', reference.group(1))
        self.assertLess(notifications.index('sessionStorage.setItem(notificationOperationKey'),
                        notifications.index("const response = request(prefix +"))
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
