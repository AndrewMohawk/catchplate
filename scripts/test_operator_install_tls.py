#!/usr/bin/env python3
"""Isolated installer TLS contracts; not installed-edge runtime acceptance.

Run in the bounded cached root test container, network none, no Docker socket.
OpenSSL and private filesystem operations are real; lifecycle seams are doubles.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from operator_install import config, lifecycle, process, state, tls


NOW = 1_800_000_000
HOSTS = ("console.example.com", "proxy.example.com")


def certificate(key, *, names=HOSTS, before=-1, after=30, common_name=None):
    instant = datetime.fromtimestamp(NOW, timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name or HOSTS[0])])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(instant + timedelta(days=before)).not_valid_after(instant + timedelta(days=after)))
    if names is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in names]), critical=False)
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def private_key(key, encryption=None):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        encryption or serialization.NoEncryption())


def identity(path):
    info = path.lstat()
    return (info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink,
        hashlib.sha256(path.read_bytes()).hexdigest())


class TlsInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or {name for _, name in socket.if_nameindex()} != {"lo"}:
            raise RuntimeError("TLS installer tests require the isolated root test container")
        if Path("/var/run/docker.sock").exists():
            raise RuntimeError("TLS installer tests must not receive a Docker socket")
        cls.old_key = ec.generate_private_key(ec.SECP256R1())
        cls.new_key = ec.generate_private_key(ec.SECP256R1())
        cls.old_certificate = certificate(cls.old_key)
        cls.new_certificate = certificate(cls.new_key)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="operator-install-tls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.instance = self.root / "instance"
        self.cert_path, self.key_path = self.root / "replacement.crt", self.root / "replacement.key"
        self.cert_path.write_bytes(self.new_certificate)
        self.key_path.write_bytes(private_key(self.new_key))
        self.cert_path.chmod(0o644)
        self.key_path.chmod(0o600)
        self.clock = patch.object(tls.time, "time", return_value=NOW)
        self.clock.start(); self.addCleanup(self.clock.stop)
        self.require_host = patch.object(process, "require_host")
        self.host = self.require_host.start(); self.addCleanup(self.require_host.stop)
        self.running_patch = patch.object(lifecycle, "edge_running", return_value=False)
        self.running = self.running_patch.start(); self.addCleanup(self.running_patch.stop)
        self.reload_patch = patch.object(lifecycle, "edge_reload", return_value={"reloaded": True})
        self.reload = self.reload_patch.start(); self.addCleanup(self.reload_patch.stop)
        self.probe_patch = patch.object(tls, "_probe_served_tls", return_value={"verified_hostnames": 2})
        self.probe = self.probe_patch.start(); self.addCleanup(self.probe_patch.stop)
        self.install_fixture()

    def install_fixture(self):
        configuration = config.validate({"schema": config.SCHEMA, "project_name": "catchplate-tls-test",
            "state_dir": str(self.instance), "console_origin": "https://" + HOSTS[0],
            "proxy_origin": "https://" + HOSTS[1], "allowed_upstreams": ["https://api.github.com"],
            "tls_certificate": str(self.cert_path), "tls_private_key": str(self.key_path),
            "paired_image": "sha256:" + "1" * 64, "edge_image": "sha256:" + "2" * 64})
        with state.instance_lock(self.instance, initialize=True):
            for directory in ("edge", "edge-secrets", "service-secrets", "app-data", "gate-data"):
                path = self.instance / directory; path.mkdir(mode=0o700); os.chown(path, 10001, 10001)
            contents = {name: b"synthetic installed artifact\n" for name in state.PINNED_FILES}
            contents.update({tls.TLS_FILES[0]: self.old_certificate, tls.TLS_FILES[1]: private_key(self.old_key)})
            for name, data in contents.items():
                state.write_file(self.instance / name, data, owner=0 if name == "compose.json" else 10001)
            self.manifest = {"schema": state.SCHEMA, "config": configuration,
                "instance_id": "11111111-1111-4111-8111-111111111111",
                "images": {key: {"id": configuration[key + "_image"]} for key in ("paired", "edge")},
                "artifact": {"schema": "catchplate.standaloneArtifact/v1", "sourceRevision": "a" * 40,
                    **{name: "sha256:" + "3" * 64 for name in ("sourceTreeDigest", "compilerInputsDigest", "dataPlaneBinaryDigest")}},
                "files": {name: state.digest(data) for name, data in contents.items()}}
            state.write_manifest(self.instance, self.manifest, exclusive=True)
            for name, data in (("app-data/catalog.sqlite", b"synthetic retained catalog bytes"),
                    ("app-data/mitm-ca.pem", b"synthetic unchanged interception CA"),
                    ("gate-data/high-water.json", b"synthetic retained policy high water")):
                state.write_file(self.instance / name, data, owner=10001)
        self.original = {name: (self.instance / name).read_bytes() for name in (*tls.TLS_FILES, "manifest.json")}
        protected = (state.PINNED_FILES - set(tls.TLS_FILES)) | {
            "app-data/catalog.sqlite", "app-data/mitm-ca.pem", "gate-data/high-water.json"}
        self.protected = {name: identity(self.instance / name) for name in protected}

    def unchanged_application(self):
        self.assertEqual({name: identity(self.instance / name) for name in self.protected}, self.protected)

    def replace(self):
        return tls.replace_tls(self.instance, self.cert_path, self.key_path)

    def test_shared_validator_accepts_public_certificate_private_key_and_both_dns_names(self):
        self.assertEqual(tls.validate_tls_pair(self.cert_path, self.key_path, *HOSTS),
            (self.new_certificate, private_key(self.new_key)))
        self.key_path.chmod(0o400)
        tls.validate_tls_pair(self.cert_path, self.key_path, *HOSTS)
        self.cert_path.write_bytes(certificate(self.new_key, names=("*.example.com",)))
        tls.validate_tls_pair(self.cert_path, self.key_path, *HOSTS)

    def test_wrong_missing_cn_only_partial_wildcard_and_invalid_dates_are_refused(self):
        candidates = [certificate(self.new_key, names=(HOSTS[0],)),
            certificate(self.new_key, names=None, common_name="*.example.com"),
            certificate(self.new_key, names=(HOSTS[0], "proxy*.example.com")),
            certificate(self.new_key, names=("wrong.example.com",)),
            certificate(self.new_key, before=-2, after=-1), certificate(self.new_key, before=1, after=2)]
        for candidate in candidates:
            with self.subTest(candidate=state.digest(candidate)):
                self.cert_path.write_bytes(candidate)
                with self.assertRaises(config.InstallError):
                    self.replace()
                self.assertFalse((self.instance / "tls-backups").exists())
                self.assertFalse((self.instance / tls.PENDING_FILE).exists())
                self.assertEqual(state.load_manifest(self.instance), self.manifest)
        self.reload.assert_not_called(); self.probe.assert_not_called(); self.unchanged_application()

    def test_mismatched_encrypted_malformed_and_oversized_inputs_are_refused_without_echo(self):
        invalid_pairs = [(self.new_certificate, private_key(self.old_key)),
            (self.new_certificate, private_key(self.new_key, serialization.BestAvailableEncryption(b"synthetic-private-password"))),
            (b"synthetic-private-certificate-error", private_key(self.new_key)),
            (self.new_certificate, b"synthetic-private-key-error"),
            (self.new_certificate * 17, private_key(self.new_key)),
            (b"x" * (tls.CERTIFICATE_LIMIT + 1), private_key(self.new_key)),
            (self.new_certificate, b"x" * (tls.PRIVATE_KEY_LIMIT + 1))]
        for cert, key in invalid_pairs:
            with self.subTest(certificate_bytes=len(cert), key_bytes=len(key)):
                self.cert_path.write_bytes(cert); self.key_path.write_bytes(key)
                output = io.StringIO()
                with redirect_stdout(output), self.assertRaises(config.InstallError) as error:
                    self.replace()
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("synthetic-private", str(error.exception))
                self.assertNotIn("BEGIN PRIVATE", str(error.exception))
                self.assertFalse((self.instance / "tls-backups").exists())
        self.unchanged_application()

    def test_unsafe_key_permissions_symlinks_and_hardlinks_are_refused(self):
        self.key_path.chmod(0o644)
        with self.assertRaises(config.InstallError): self.replace()
        self.key_path.chmod(0o600)
        alias = self.root / "alias.key"; alias.symlink_to(self.key_path)
        with self.assertRaises(config.InstallError): tls.validate_tls_pair(self.cert_path, alias, *HOSTS)
        linked = self.root / "linked.key"; os.link(self.key_path, linked)
        with self.assertRaises(config.InstallError): self.replace()
        self.assertFalse((self.instance / "tls-backups").exists()); self.unchanged_application()

    def test_stopped_edge_replacement_updates_only_tls_pins_and_keeps_recoverable_private_backup(self):
        result = self.replace()
        self.assertEqual(result["schema"], "catchplate.standaloneResult/v1")
        self.assertEqual(result["operation"], "replace-tls"); self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["services"], {"edge": "stopped_unchanged"}); self.assertIsNone(result["tls"])
        changed = state.load_manifest(self.instance)
        self.assertEqual({key: value for key, value in changed.items() if key != "files"},
            {key: value for key, value in self.manifest.items() if key != "files"})
        self.assertEqual({name for name in changed["files"] if changed["files"][name] != self.manifest["files"][name]}, set(tls.TLS_FILES))
        backup = Path(result["backup"])
        self.assertEqual(backup.parent, self.instance / "tls-backups")
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
        for saved, original in (("tls.crt", tls.TLS_FILES[0]), ("tls.key", tls.TLS_FILES[1]), ("manifest.json", "manifest.json")):
            self.assertEqual((backup / saved).read_bytes(), self.original[original])
            self.assertEqual((backup / saved).stat().st_uid, 0)
            self.assertEqual(stat.S_IMODE((backup / saved).stat().st_mode), 0o600)
        for name in tls.TLS_FILES:
            self.assertEqual((self.instance / name).stat().st_uid, 10001)
            self.assertEqual(stat.S_IMODE((self.instance / name).stat().st_mode), 0o600)
        self.assertFalse((self.instance / tls.PENDING_FILE).exists())
        self.reload.assert_not_called(); self.probe.assert_not_called(); self.unchanged_application()

    def test_running_edge_restarts_only_edge_then_requires_both_served_hostnames(self):
        self.running.return_value = True
        result = self.replace()
        self.assertEqual(result["status"], "ready"); self.assertEqual(result["services"], {"edge": "restarted"})
        self.reload.assert_called_once_with(self.instance, state.load_manifest(self.instance))
        self.probe.assert_called_once_with(state.load_manifest(self.instance), self.new_certificate)
        self.assertEqual(result["tls"], {"verified_hostnames": 2}); self.unchanged_application()

    def test_identical_material_does_not_restart_probe_or_create_backup(self):
        self.cert_path.write_bytes(self.old_certificate); self.key_path.write_bytes(private_key(self.old_key))
        result = self.replace()
        self.assertEqual(result["status"], "unchanged"); self.assertFalse(result["changed"])
        self.assertIsNone(result["backup"]); self.assertFalse((self.instance / "tls-backups").exists())
        self.running.assert_not_called(); self.reload.assert_not_called(); self.probe.assert_not_called()
        self.assertEqual((self.instance / "manifest.json").read_bytes(), self.original["manifest.json"])
        self.unchanged_application()

    def test_failed_restart_restores_previous_pair_and_manifest_without_application_reset(self):
        self.running.return_value = True
        self.reload.side_effect = [config.InstallError("synthetic failure"), {"reloaded": True}]
        with self.assertRaisesRegex(config.InstallError, "previous certificate, key and manifest were restored"):
            self.replace()
        self.assertEqual(self.reload.call_count, 2)
        self.probe.assert_called_once_with(self.manifest, self.old_certificate)
        for name, original in self.original.items(): self.assertEqual((self.instance / name).read_bytes(), original)
        self.assertFalse((self.instance / tls.PENDING_FILE).exists()); self.unchanged_application()

    def test_partial_pair_write_failure_restores_exact_previous_files_without_restart(self):
        write = state.write_file
        def fail_new_key(path, data, **kwargs):
            if path == self.instance / tls.TLS_FILES[1] and data == private_key(self.new_key):
                raise OSError("synthetic key replacement failure")
            return write(path, data, **kwargs)
        with patch.object(state, "write_file", side_effect=fail_new_key):
            with self.assertRaisesRegex(config.InstallError, "were restored"): self.replace()
        for name, original in self.original.items(): self.assertEqual((self.instance / name).read_bytes(), original)
        self.assertFalse((self.instance / tls.PENDING_FILE).exists())
        self.reload.assert_not_called(); self.probe.assert_not_called(); self.unchanged_application()

    def test_marker_completion_sync_failure_retains_marker_until_rollback_is_complete(self):
        sync = tls._sync_directory
        failed = False
        def fail_completion_once(directory):
            nonlocal failed
            if (directory == self.instance and not (self.instance / tls.PENDING_FILE).exists()
                    and (self.instance / tls.TLS_FILES[0]).read_bytes() == self.new_certificate and not failed):
                failed = True
                raise OSError("synthetic marker completion sync failure")
            return sync(directory)
        with patch.object(tls, "_sync_directory", side_effect=fail_completion_once):
            with self.assertRaisesRegex(config.InstallError, "were restored"): self.replace()
        self.assertTrue(failed)
        for name, original in self.original.items(): self.assertEqual((self.instance / name).read_bytes(), original)
        self.assertFalse((self.instance / tls.PENDING_FILE).exists()); self.unchanged_application()

    def test_failed_served_certificate_probe_rolls_back_and_checks_the_old_leaf(self):
        self.running.return_value = True
        self.probe.side_effect = [config.InstallError("wrong served leaf"), {"verified_hostnames": 2}]
        with self.assertRaisesRegex(config.InstallError, "were restored"): self.replace()
        self.assertEqual(self.reload.call_count, 2)
        self.assertEqual([call.args[1] for call in self.probe.call_args_list], [self.new_certificate, self.old_certificate])
        self.assertEqual(state.load_manifest(self.instance), self.manifest); self.unchanged_application()

    def test_failed_recovery_retains_marker_backup_and_refuses_automatic_replay(self):
        self.running.return_value = True
        self.reload.side_effect = config.InstallError("synthetic restart failure")
        with self.assertRaisesRegex(config.InstallError, "recovery could not be confirmed"): self.replace()
        marker = config.parse_json((self.instance / tls.PENDING_FILE).read_bytes())
        self.assertEqual(marker["instance_id"], self.manifest["instance_id"])
        backup = self.instance / marker["backup"]
        self.assertEqual((backup / "manifest.json").read_bytes(), self.original["manifest.json"])
        self.assertEqual((backup / "tls.key").read_bytes(), self.original[tls.TLS_FILES[1]])
        attempts = self.reload.call_count
        with self.assertRaisesRegex(config.InstallError, "No replay was attempted"): self.replace()
        self.assertEqual(self.reload.call_count, attempts); self.unchanged_application()

    def test_installed_pin_changes_are_not_adopted_or_overwritten(self):
        path = self.instance / "edge/nginx.conf"
        path.write_bytes(b"unreviewed changed configuration")
        with self.assertRaises(config.InstallError): self.replace()
        self.assertEqual(path.read_bytes(), b"unreviewed changed configuration")
        self.assertFalse((self.instance / "tls-backups").exists()); self.reload.assert_not_called()

    def test_probe_is_closed_local_tls_only_and_requires_exact_public_result(self):
        self.probe_patch.stop()
        expected_pin = tls._leaf_pin(self.new_certificate)
        expected = {"verified_hostnames": 2, "certificate_sha256": expected_pin}
        with patch.object(lifecycle, "_compose", return_value=json.dumps(expected).encode()) as compose:
            self.assertEqual(tls._probe_served_tls(self.manifest, self.new_certificate), expected)
            args = compose.call_args.args
            self.assertEqual(args[1:8], ("exec", "-T", "catchplate", "python", "-I", "-B", "-c"))
            self.assertEqual(json.loads(args[-1]), [list(HOSTS), expected_pin])
            self.assertIn("('edge',8443)", args[-2])
            self.assertIn("actual!=pin", args[-2])
            self.assertNotIn("send(", args[-2]); self.assertNotIn("sendall(", args[-2])
            self.assertNotIn("PRIVATE KEY", repr(args))
            for invalid in [{**expected, "verified_hostnames": 1}, {**expected, "certificate_sha256": "sha256:" + "0" * 64},
                    {**expected, "extra": True}, {}]:
                compose.return_value = json.dumps(invalid).encode()
                with self.assertRaises(config.InstallError): tls._probe_served_tls(self.manifest, self.new_certificate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
