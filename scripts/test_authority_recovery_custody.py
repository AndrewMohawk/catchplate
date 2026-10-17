"""Inert selection/descriptor components; no successful launch or DB fiction."""
from __future__ import annotations

import copy
import fcntl
import os
import unittest

from catchplate import authority_launcher as launcher
from catchplate import authority_recovery_configuration as configuration
from catchplate import authority_recovery_custody as custody


def fixture():
    policy = dict(rp_id="example.test", origin="https://example.test",
        allowed_authenticator_classes=["hardware"], authorization_policy_digest="sha256:" + "1" * 64,
        recovery_root_key_id="sha256:" + "2" * 64, recovery_root_provider="offline-root",
        recovery_audience="https://example.test/recovery")
    selected = dict(schema=configuration.SCHEMA, policy=policy, rootPublicPemSha256="sha256:" + "3" * 64,
        retentionPolicy=configuration.retention.project_policy(
            terminal_retention_seconds=7_776_000, maximum_retained=100_000),
        metadata=dict(database="metadata", clusterId="101", serverAddress="192.0.2.1", serverPort=5432,
            faultDomain="metadata-operator"),
        witness=dict(endpoint=dict(host="witness.example.test", address="192.0.2.2", port=5432, database="witness"),
            identity=dict(clusterId="102", serverAddress="192.0.2.2", serverPort=5432,
                faultDomain="independent-witness-operator", role="recovery_witness",
                clientDn="/CN=recovery_witness", clientSerial="17", issuerDn="/CN=witness-ca"),
            originals=dict(dsnSha256="sha256:" + "4" * 64, tlsRootSha256="sha256:" + "5" * 64,
                certificateSha256="sha256:" + "6" * 64, keySha256="sha256:" + "7" * 64)))
    webauthn = dict(rpId=policy["rp_id"], origin=policy["origin"],
        allowedAuthenticatorClasses=["hardware"], requireAttestationTrusted=True)
    return selected, webauthn


class RecoveryCustodyTests(unittest.TestCase):
    def test_signed_selection_is_closed_and_separation_is_not_a_verdict(self):
        selected, webauthn = fixture()
        self.assertIs(configuration.configuration(selected, webauthn=webauthn), selected)
        self.assertIsNone(configuration.configuration(None, webauthn=webauthn))
        self.assertEqual(configuration.CREDENTIAL_NAMES, launcher.RECOVERY_CREDENTIAL_DESCRIPTOR_NAMES)
        self.assertEqual(len(configuration.CREDENTIAL_NAMES), 5)
        self.assertFalse(configuration.CREDENTIAL_NAMES & launcher.ROLE_CREDENTIAL_DESCRIPTOR_NAMES["verifier"])
        for target, name, value in (
                ("identity", "clusterId", "101"), ("identity", "faultDomain", "metadata-operator"),
                ("policy", "rp_id", "other.test"), ("policy", "origin", "https://other.test"),
                ("policy", "allowed_authenticator_classes", ["software"]),
                ("policy", "recovery_root_key_id", "not-a-pin"),
                ("top", "verified", True)):
            with self.subTest(target=target, field=name):
                wrong = copy.deepcopy(selected)
                row = wrong if target == "top" else wrong["policy"] if target == "policy" else wrong["witness"]["identity"]
                row[name] = value
                with self.assertRaises(configuration.RecoveryConfigurationError):
                    configuration.configuration(wrong, webauthn=webauthn)
        wrong = copy.deepcopy(selected)
        wrong["witness"]["identity"]["serverAddress"] = selected["metadata"]["serverAddress"]
        with self.assertRaises(configuration.RecoveryConfigurationError):
            configuration.configuration(wrong, webauthn=webauthn)
        with self.assertRaises(TypeError):
            custody._RecoveryCustody()

    def test_real_sealed_fd_reuse_and_close_cannot_retain_original_identity(self):
        # This exercises the exact identity primitive at the fixture's UID.
        # Production _HeldOriginal fixes expected_uid=0; this test does not
        # manufacture a measured launch, root-owned credential or live owner.
        def sealed(name):
            fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                os.write(fd, b"public-synthetic-original")
                os.fchmod(fd, 0o400)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, custody._SEALS)
                return fd
            except BaseException:
                os.close(fd)
                raise
        first, second = sealed("recovery-first"), sealed("recovery-second")
        try:
            original = custody._fd_identity(first, 128, expected_uid=os.geteuid())
            custody._require_same_fd(first, original, 128, expected_uid=os.geteuid())
            with self.assertRaises(OSError):
                os.write(first, b"mutation")
            os.dup2(second, first, inheritable=False)
            with self.assertRaises(configuration.RecoveryConfigurationError):
                custody._require_same_fd(first, original, 128, expected_uid=os.geteuid())
            os.close(first)
            with self.assertRaises(OSError):
                custody._require_same_fd(first, original, 128, expected_uid=os.geteuid())
            first = None
        finally:
            if first is not None:
                os.close(first)
            os.close(second)


if __name__ == "__main__":
    unittest.main()
