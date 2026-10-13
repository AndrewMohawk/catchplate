#!/usr/bin/env python3
"""Closed offline PKI/relay option tests, not TLS or proxy acceptance.

Real in-memory certificate generation runs; filesystem writes, socket binding
and CLI dispatch are replaced by recording sinks. No fixture is launched.
"""
from contextlib import ExitStack, redirect_stderr
import datetime as dt
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from scripts import operator_proxy_basic_fixture_setup as setup
from scripts import operator_proxy_basic_tls as relay


LEGACY = "proxy.operator-basic.example.test"
GMAIL = "serverware-gmail-proxy.example.com"
OUTPUTS = {"outer-ca.pem", "outer-cert.pem", "outer-key.pem", "inner-ca.pem", "requests-ca.pem"}


def inner_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Separate Inner CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256()))
    return cert, cert.public_bytes(serialization.Encoding.PEM)


class ProxyBasicTransportTests(unittest.TestCase):
    def test_actual_leaf_and_receipt_bind_each_closed_hostname_with_legacy_default(self):
        for selected, profile in ((None, None), (LEGACY, 'baseline'), (GMAIL, 'baseline'),
                (LEGACY, 'managed-x-post')):
            with self.subTest(selected=selected, profile=profile), ExitStack() as stack:
                inner, inner_pem = inner_certificate()
                files = {}
                directory = SimpleNamespace(st_mode=0o040700, st_uid=10001, st_gid=10001)
                for name, value in {"geteuid": 0, "umask": None, "open": 10, "fstat": directory,
                        "stat": directory, "fchown": None, "fsync": None, "close": None}.items():
                    stack.enter_context(patch.object(setup.os, name, return_value=value))
                stack.enter_context(patch.object(setup.os, "listdir", side_effect=[
                    list(setup._DIRECTORIES | {".private-fixture.json"}
                        | ({"x-custody"} if profile == 'managed-x-post' else set())), sorted(OUTPUTS), []]))
                stack.enter_context(patch.object(setup.socket, "if_nameindex", return_value=[(1, "lo")]))
                stack.enter_context(patch.object(setup, "_read_public_file", return_value=json.dumps({
                    "schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True}).encode()))
                stack.enter_context(patch.object(setup, "_inner_root", return_value=(inner, inner_pem)))
                fresh = stack.enter_context(patch.object(setup, "_fresh_directory", side_effect=[20, 30]))
                writes = stack.enter_context(patch.object(setup, "_write",
                    side_effect=lambda fd, name, value: files.__setitem__(name, value)))
                output = stack.enter_context(patch("builtins.print"))
                setup.prepare(**({} if selected is None else {"proxy_hostname": selected}),
                    **({} if profile is None else {"runtime_profile": profile}))
                hostname = LEGACY if selected is None else selected
                self.assertEqual(set(files), OUTPUTS)
                self.assertEqual([call.args for call in fresh.call_args_list], [(10, "basic-pki"), (10, "client-work")])
                self.assertTrue(all(call.args[0] == 20 for call in writes.call_args_list))
                leaf = x509.load_pem_x509_certificate(files["outer-cert.pem"])
                outer = x509.load_pem_x509_certificate(files["outer-ca.pem"])
                self.assertEqual(leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, hostname)
                self.assertEqual(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    .value.get_values_for_type(x509.DNSName), [hostname])
                self.assertEqual(leaf.issuer, outer.subject)
                outer.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
                self.assertNotEqual(outer.fingerprint(hashes.SHA256()), inner.fingerprint(hashes.SHA256()))
                self.assertEqual(files["requests-ca.pem"], files["outer-ca.pem"] + inner_pem)
                receipt = json.loads(output.call_args.args[0])
                self.assertEqual(receipt["proxyHostname"], hostname)
                self.assertEqual(receipt["outerLeafSha256"], "sha256:" + leaf.fingerprint(hashes.SHA256()).hex())
                self.assertIs(receipt["rootPrivateKeyPersisted"], False)

    def test_runtime_profile_refuses_missing_extra_symlink_and_wrong_owned_directory(self):
        baseline = {'app-data', 'gate-data', 'upstream-data', 'service-secrets', '.private-fixture.json'}
        cases = [
            ('baseline', baseline | {'x-custody'}, None),
            ('managed-x-post', baseline, None),
            ('managed-x-post', baseline | {'x-custody', 'extra'}, None),
            ('managed-x-post', baseline | {'x-custody', 'basic-pki'}, None),
            ('managed-x-post', baseline | {'x-custody', 'client-work'}, None),
        ]
        cases += [('managed-x-post', baseline | {'x-custody'}, value) for value in (
            SimpleNamespace(st_mode=0o040755, st_uid=10001, st_gid=10001),
            SimpleNamespace(st_mode=0o040700, st_uid=0, st_gid=10001),
            SimpleNamespace(st_mode=0o040700, st_uid=10001, st_gid=0),
            SimpleNamespace(st_mode=0o120700, st_uid=10001, st_gid=10001))]
        directory = SimpleNamespace(st_mode=0o040700, st_uid=10001, st_gid=10001)
        for profile, roster, bad in cases:
            with self.subTest(profile=profile, roster=sorted(roster), bad=bad), ExitStack() as stack:
                for name, value in {'geteuid': 0, 'umask': None, 'open': 10,
                        'fstat': directory, 'listdir': list(roster), 'close': None}.items():
                    stack.enter_context(patch.object(setup.os, name, return_value=value))
                observed = stack.enter_context(patch.object(setup.os, 'stat',
                    side_effect=lambda name, **kwargs: bad if name == 'x-custody' and bad is not None else directory))
                stack.enter_context(patch.object(setup.socket, 'if_nameindex', return_value=[(1, 'lo')]))
                marker = stack.enter_context(patch.object(setup, '_read_public_file'))
                inner = stack.enter_context(patch.object(setup, '_inner_root'))
                fresh = stack.enter_context(patch.object(setup, '_fresh_directory'))
                writes = stack.enter_context(patch.object(setup, '_write'))
                with self.assertRaisesRegex(ValueError, '^private Basic fixture setup refused$'):
                    setup.prepare(runtime_profile=profile)
                marker.assert_not_called(); inner.assert_not_called()
                fresh.assert_not_called(); writes.assert_not_called()
                self.assertTrue(all(call.kwargs == {'dir_fd': 10, 'follow_symlinks': False}
                    for call in observed.call_args_list))

    def test_unlisted_runtime_profile_refuses_before_environment_or_filesystem(self):
        for value in ('', 'managed-x', 'managed-x-post ', 'BASELINE', None, True, [], {}):
            with self.subTest(value=value), patch.object(setup.os, 'geteuid') as uid, \
                    patch.object(setup.os, 'open') as opened:
                with self.assertRaisesRegex(ValueError, '^private Basic fixture setup refused$'):
                    setup.prepare(runtime_profile=value)
                uid.assert_not_called(); opened.assert_not_called()

    def test_unlisted_hostname_refuses_before_environment_checks_or_writes(self):
        for value in ("", GMAIL + ".", GMAIL.upper(), "other.example.com", "https://" + GMAIL,
                "proxy.operator-basic.example.test:8443", None, True, [], {}):
            with self.subTest(value=value), patch.object(setup.os, "geteuid") as uid, \
                    patch.object(setup.os, "open") as opened, patch.object(setup, "_write") as write:
                with self.assertRaisesRegex(ValueError, "^private Basic fixture setup refused$"):
                    setup.prepare(proxy_hostname=value)
                uid.assert_not_called()
                opened.assert_not_called()
                write.assert_not_called()

    def test_cli_default_and_explicit_closed_hostname_dispatch_without_other_changes(self):
        prefix = ["setup", "--runtime-root", "/fixture-runtime", "--inner-ca-file", "/inner-ca.pem"]
        for value in (None, LEGACY, GMAIL):
            argv = prefix + ([] if value is None else ["--proxy-hostname", value])
            with self.subTest(value=value), patch("sys.argv", argv), \
                    patch.object(setup, "prepare") as prepare, patch.object(setup.signal, "alarm") as alarm:
                setup.main()
                prepare.assert_called_once_with(setup.RUNTIME_ROOT, setup.INNER_CA_FILE,
                    proxy_hostname=LEGACY if value is None else value, runtime_profile='baseline')
                self.assertEqual([call.args for call in alarm.call_args_list], [(20,), (0,)])
        with patch("sys.argv", prefix + ["--proxy-hostname", "other.example.com"]), \
                patch.object(setup, "prepare") as prepare, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                setup.main()
            self.assertEqual(caught.exception.code, 2)
            prepare.assert_not_called()

    def test_cli_runtime_profile_is_closed_and_explicit_without_resetting_alarm(self):
        prefix = ['setup', '--runtime-root', '/fixture-runtime', '--inner-ca-file', '/inner-ca.pem']
        for profile in ('baseline', 'managed-x-post'):
            with patch('sys.argv', prefix + ['--runtime-profile', profile]), \
                    patch.object(setup, 'prepare') as prepare, patch.object(setup.signal, 'alarm') as alarm:
                setup.main()
                prepare.assert_called_once_with(setup.RUNTIME_ROOT, setup.INNER_CA_FILE,
                    proxy_hostname=LEGACY, runtime_profile=profile)
                self.assertEqual([call.args for call in alarm.call_args_list], [(20,), (0,)])
        with patch('sys.argv', prefix + ['--runtime-profile', 'arbitrary']), \
                patch.object(setup, 'prepare') as prepare, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught: setup.main()
            self.assertEqual(caught.exception.code, 2)
            prepare.assert_not_called()

    def test_server_passes_only_default_or_explicit_closed_port_to_socket_binding(self):
        context = object()
        for port in (None, 8443, 443):
            with self.subTest(port=port), patch.object(relay.socketserver.TCPServer, "__init__",
                    autospec=True, return_value=None) as bind:
                server = relay.Server("127.0.0.2", "127.0.0.1", context, 30,
                    **({} if port is None else {"port": port}))
                bind.assert_called_once_with(server, ("127.0.0.2", 8443 if port is None else port), relay.Relay)
                self.assertEqual(server.gate, "127.0.0.1")
                self.assertIs(server.context, context)
                self.assertEqual(server.accepted, 0)
        self.assertEqual(relay.PROXY_PORT, 8443)
        self.assertEqual(relay.PROXY_HOST, LEGACY)

    def test_invalid_port_refuses_before_socket_binding(self):
        for port in (None, True, False, "443", 443.0, 8443.0, 0, -1, 80, 8444, 65536, [], {}):
            with self.subTest(port=port), patch.object(relay.socketserver.TCPServer, "__init__") as bind:
                with self.assertRaisesRegex(ValueError, "^private relay port must be 443 or 8443$"):
                    relay.Server("127.0.0.2", "127.0.0.1", object(), 30, port=port)
                bind.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
