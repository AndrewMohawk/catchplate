#!/usr/bin/env python3
"""Synthetic data-grammar controls for the frozen no-build verification lane.

No provider contact, signing authority, real secret or production claim exists
in these fixtures. This script is authored now and executed only after freeze.
"""
from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import oauth_retirement_values as values


def grant():
    digest = "sha256:" + "1" * 64
    return {"schema": "catchplate.oauthRevocationAuthorization/v1",
        "sourceRevision": "synthetic-source", "purpose": "retained-oauth-revocation",
        "authorizationId": "00000000-0000-4000-8000-000000000001",
        "configurationDigest": digest, "deploymentId": "synthetic:deployment-1",
        "exchangeId": "00000000-0000-4000-8000-000000000002", "exchangeRowSha256": digest,
        "workRowSha256": digest, "enrollmentSha256": digest, "historicalEnrollmentRootSpkiSha256": digest,
        "tokenEnvelopeSha256": digest, "tokenSecretSha256": digest, "providerId": "google",
        "clientId": "synthetic-client", "clientMaterialSha256": digest,
        "providerConfiguration": {"providerId": "google", "authorizationUrl": "https://example.invalid/authorize",
            "tokenUrl": "https://example.invalid/token", "revocationUrl": "https://example.invalid/revoke",
            "identityUrl": "https://example.invalid/identity?projection=subject", "tokenAuth": "client_secret_post",
            "defaultScopes": ["synthetic.read"], "authParams": {"prompt": "consent"},
            "metadataProvider": "synthetic", "tokenResponseScopeOptional": False},
        "tokenPurposes": ["refresh_token"], "issuedAtEpochNs": 1, "expiresAtEpochNs": 300_000_000_001}


def envelope():
    return {"encrypted_secret": "envelope:v2", "encrypted_dek": "synthetic-dek",
        "secret_nonce": "synthetic-nonce", "secret_ciphertext": "synthetic-ciphertext",
        "secret_kek_id": "synthetic-kek", "credential_version": 1,
        "secret_updated_at": "2026-09-29T00:00:00+00:00"}


class RetirementValuesTests(unittest.TestCase):
    def test_actual_native_receipt_policy_entrypoints_do_not_import_control_plane(self):
        # A fresh isolated interpreter prevents this process's module cache from
        # concealing a lazy control-plane import at the actual receipt seam.
        # This proves import separation/refusal only, not valid signed admission.
        worker = r'''
import builtins
import sys
sys.path.insert(0, sys.argv[1])
original_import = builtins.__import__
def isolated_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.startswith("catchplate.authority_") or (name == "catchplate" and any(
            item.startswith("authority_") for item in (fromlist or ()))):
        raise AssertionError("native receipt imported control-plane authority")
    return original_import(name, globals, locals, fromlist, level)
builtins.__import__ = isolated_import
from catchplate import native_oauth_capture_retirement, native_oauth_pending_retirement
for wire, claim_operation in (
        (native_oauth_capture_retirement, "oauth.measured-capture-retirement.claim"),
        (native_oauth_pending_retirement, "oauth.measured-pending-retirement.claim")):
    try:
        absent = wire.policy_key(None, {"roles": {"verifier": {"enabledOperations": []}}}, None)
    except ValueError:
        if wire is native_oauth_capture_retirement:
            raise
    else:
        assert wire is native_oauth_capture_retirement and absent is None
    try:
        wire.policy_key(None, {"roles": {"verifier": {"enabledOperations": [claim_operation]}}}, None)
    except ValueError:
        pass
    else:
        raise AssertionError("enabled retirement accepted missing policy")
    try:
        wire.verify_grant({}, key=None, configuration_digest="sha256:" + "1" * 64,
            source_revision="synthetic-source", deployment_id="synthetic", now_epoch_ns=1)
    except (ValueError, KeyError):
        pass
    else:
        raise AssertionError("missing grant accepted")
'''
        result = subprocess.run([sys.executable, "-I", "-B", "-c", worker,
            str(Path(__file__).resolve().parents[1])], stdin=subprocess.DEVNULL,
            capture_output=True, timeout=10, check=False, env={"LC_ALL": "C"})
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(result.stdout, b"")

    def test_known_data_is_preserved_without_mutation(self):
        original = grant()
        snapshot = copy.deepcopy(original)
        self.assertIs(values.revocation_payload(original), original)
        self.assertEqual(original, snapshot)
        sealed = envelope()
        result = values.envelope(sealed)
        self.assertEqual(result, sealed)
        self.assertIsNot(result, sealed)

    def test_grant_exact_shape_and_scalar_bounds(self):
        changes = {"schema": "wrong-purpose", "extra": None, "providerId": "unknown",
            "authorizationId": "00000000000040008000000000000001", "clientId": " client",
            "sourceRevision": "x" * 129, "deploymentId": "bad/identifier",
            "configurationDigest": "sha256:" + "0" * 64, "issuedAtEpochNs": True,
            "expiresAtEpochNs": 300_000_000_002}
        for name, invalid in changes.items():
            with self.subTest(field=name):
                candidate = grant()
                candidate[name] = invalid
                with self.assertRaises(ValueError):
                    values.revocation_payload(candidate)
        candidate = grant()
        del candidate["clientId"]
        with self.assertRaises(ValueError):
            values.revocation_payload(candidate)

    def test_provider_purpose_and_url_boundaries(self):
        candidate = grant()
        candidate["tokenPurposes"] = ["access_token", "refresh_token"]
        with self.assertRaises(ValueError):
            values.revocation_payload(candidate)
        candidate["providerId"] = candidate["providerConfiguration"]["providerId"] = "x"
        self.assertIs(values.revocation_payload(candidate), candidate)
        for invalid in ("http://example.invalid/token", "https://user:password@example.invalid/token",
                        "https://example.invalid/token#fragment"):
            with self.subTest(url=invalid):
                candidate = grant()
                candidate["providerConfiguration"]["tokenUrl"] = invalid
                with self.assertRaises(ValueError):
                    values.revocation_payload(candidate)

    def test_text_is_utf8_bounded_and_never_normalized(self):
        self.assertEqual(values.text("é", 2), "é")
        for invalid, bound in (("é", 1), ("", 4), (" a", 4), ("a ", 4), ("a\nb", 4), ("a\x7fb", 4), (1, 4)):
            with self.subTest(value=invalid, bound=bound):
                with self.assertRaises(ValueError):
                    values.text(invalid, bound)

    def test_envelope_requires_exact_version_utc_and_nonempty_fields(self):
        changes = {"credential_version": True, "encrypted_secret": "envelope:v3",
            "secret_updated_at": "2026-09-29T00:00:00+01:00", "encrypted_dek": "",
            "secret_nonce": " padded", "extra": None}
        for name, invalid in changes.items():
            with self.subTest(field=name):
                candidate = envelope()
                candidate[name] = invalid
                with self.assertRaises(ValueError):
                    values.envelope(candidate)
        with self.assertRaises(ValueError):
            values.timestamp("2026-09-29T00:00:00")

    def test_total_envelope_bound_counts_all_fields(self):
        candidate = envelope()
        candidate["secret_ciphertext"] = "x" * values.MAX_ENVELOPE_BYTES
        with self.assertRaises(ValueError):
            values.envelope(candidate)


if __name__ == "__main__":
    unittest.main()
