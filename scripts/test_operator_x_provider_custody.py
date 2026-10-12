#!/usr/bin/env python3
"""Offline actual-AES X envelope controls; no storage, activation or authority."""
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from serverware import operator_provider_custody as google
from serverware import operator_x_oauth_profile as profile
from serverware import operator_x_provider_custody as custody

KEY = bytes(range(32))
SECRET = "synthetic-X-application-secret-only"
OWNER_ID = "12345678-1234-4234-8234-123456789abc"


def no_network(event, _args):
    if event.startswith(("socket.", "subprocess.")):
        raise AssertionError("network and child processes forbidden in custody tests")


sys.addaudithook(no_network)


def owner(identifier=OWNER_ID):
    return google.admit_development_owner(identifier, operator_development=True,
        release_channel="dev", production_image=False, native_or_enrolled=False)


def binding(admitted, version=1, client="synthetic-X-client", origin="https://console.example.com"):
    return custody.bind_x(admitted, config_version=version,
        public_profile=profile.public_record(profile.build_profile(client_id=client, public_origin=origin)))


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.owner = owner()
        self.binding = binding(self.owner)

    def refused(self, function, *args, **kwargs):
        with self.assertRaises(custody.CustodyError) as caught:
            function(*args, **kwargs)
        self.assertEqual(str(caught.exception), "operator X provider custody refused")
        self.assertNotIn(SECRET, repr(caught.exception))

    def seal(self):
        return custody.seal_x(self.owner, self.binding, key=KEY, secret=SECRET)

    def test_actual_aes_roundtrip_redacted_material_and_fresh_nonce(self):
        envelope = self.seal()
        material = custody.open_x(self.owner, envelope, key=KEY)
        self.assertEqual(material.secret, SECRET)
        self.assertNotIn(SECRET, repr(material))
        self.assertNotIn(repr(envelope.nonce), repr(envelope))
        self.assertNotIn(repr(envelope.ciphertext), repr(envelope))
        self.assertNotEqual(envelope.nonce, self.seal().nonce)
        expected = {"schema": "serverware.operatorXProviderCustody/v1", "owner_id": OWNER_ID,
            "config_version": 1, "public_profile": json.loads(self.binding.profile_json), "secret_present": True}
        self.assertEqual(material.public_view(), expected)
        material.public_view()["public_profile"]["scopes"].append("other")
        self.assertEqual(material.public_view(), expected)
        self.assertNotIn(SECRET, json.dumps(expected))

    def test_independently_constructed_aad_matches_real_ciphertext(self):
        envelope = self.seal()
        aad = {"schema": "serverware.operatorXProviderCustodyAAD/v1", "owner_id": OWNER_ID,
            "config_version": 1, "public_profile": json.loads(self.binding.profile_json)}
        raw = json.dumps(aad, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(AESGCM(KEY).decrypt(envelope.nonce, envelope.ciphertext, raw), SECRET.encode())
        nonce = b"n" * 12
        independent = custody.XPrivateEnvelope(self.binding, nonce, AESGCM(KEY).encrypt(nonce, SECRET.encode(), raw))
        self.assertEqual(custody.open_x(self.owner, independent, key=KEY).secret, SECRET)

    def test_owner_version_client_and_callback_substitution_refused(self):
        envelope = self.seal()
        other = owner("22345678-1234-4234-8234-123456789abc")
        for admitted, changed in ((other, binding(other)), (self.owner, binding(self.owner, version=2)),
                (self.owner, binding(self.owner, client="different-client")),
                (self.owner, binding(self.owner, origin="https://other.example.com"))):
            self.refused(custody.open_x, admitted, replace(envelope, binding=changed), key=KEY)

    def test_google_and_x_are_distinct_types_and_aad_domains(self):
        public = google.google._record("123-synthetic.apps.googleusercontent.com",
            "https://console.example.com/api/oauth/callback/google")
        old_binding = google.bind_google(self.owner, config_version=1, public_profile=public)
        old_envelope = google.seal(self.owner, old_binding, key=KEY, secret=SECRET)
        self.refused(custody.bind_x, self.owner, config_version=1, public_profile=public)
        self.refused(custody.seal_x, self.owner, old_binding, key=KEY, secret=SECRET)
        self.refused(custody.open_x, self.owner, old_envelope, key=KEY)
        x_envelope = self.seal()
        self.refused(custody.open_x, self.owner,
            custody.XPrivateEnvelope(self.binding, old_envelope.nonce, old_envelope.ciphertext), key=KEY)
        with self.assertRaises(google.CustodyError):
            google.open_secret(self.owner,
                google.PrivateEnvelope(old_binding, x_envelope.nonce, x_envelope.ciphertext), key=KEY)
        self.assertEqual(google.open_secret(self.owner, old_envelope, key=KEY).secret, SECRET)

    def test_current_exact_owner_and_bounded_version_required(self):
        record = json.loads(self.binding.profile_json)
        for admitted in (None, replace(self.owner, uid=os.geteuid() + 1), replace(self.owner, pid=os.getpid() + 1),
                replace(self.owner, uid=True), replace(self.owner, owner_id="not-a-uuid")):
            self.refused(custody.bind_x, admitted, config_version=1, public_profile=record)
        for version in (0, 17, True, 1.0, "1", None):
            self.refused(custody.bind_x, self.owner, config_version=version, public_profile=record)
        self.assertEqual(binding(self.owner, version=16).config_version, 16)

    def test_malformed_key_envelope_and_modified_ciphertext_refused(self):
        envelope = self.seal()
        for key in (None, b"k" * 31, b"k" * 33, bytearray(KEY), "k" * 32):
            self.refused(custody.seal_x, self.owner, self.binding, key=key, secret=SECRET)
            self.refused(custody.open_x, self.owner, envelope, key=key)
        for changed in (replace(envelope, nonce=b"n" * 11), replace(envelope, nonce=bytearray(envelope.nonce)),
                replace(envelope, ciphertext=b"x" * 16), replace(envelope, ciphertext=b"x" * 4113),
                replace(envelope, ciphertext=envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]))):
            self.refused(custody.open_x, self.owner, changed, key=KEY)
        self.refused(custody.open_x, self.owner, envelope, key=b"x" * 32)

    def test_canonical_binding_and_closed_profile_are_revalidated(self):
        for raw in (self.binding.profile_json + " ", "{}", "x" * 4097,
                self.binding.profile_json.replace('"provider_id":"x"', '"provider_id":"x","provider_id":"x"'),
                self.binding.profile_json.replace("tweet.write", "tweet.delete")):
            self.refused(custody.seal_x, self.owner, replace(self.binding, profile_json=raw), key=KEY, secret=SECRET)
        self.refused(custody.seal_x, self.owner, replace(self.binding, owner_id="other"), key=KEY, secret=SECRET)

    def test_plaintext_bounds_and_authenticated_bad_plaintext_refuse(self):
        for secret in ("x" * 4096, "é" * 2048):
            envelope = custody.seal_x(self.owner, self.binding, key=KEY, secret=secret)
            self.assertEqual(custody.open_x(self.owner, envelope, key=KEY).secret, secret)
        for secret in ("", "x" * 4097, "é" * 2049, SECRET + "\n", "\ud800", None):
            self.refused(custody.seal_x, self.owner, self.binding, key=KEY, secret=secret)
        aad = json.dumps({"schema": "serverware.operatorXProviderCustodyAAD/v1", "owner_id": OWNER_ID,
            "config_version": 1, "public_profile": json.loads(self.binding.profile_json)},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        for raw in (b"\xff", b"x\x00", b" x", b"x\n"):
            nonce = b"n" * 12
            envelope = custody.XPrivateEnvelope(self.binding, nonce, AESGCM(KEY).encrypt(nonce, raw, aad))
            self.refused(custody.open_x, self.owner, envelope, key=KEY)

    def test_no_runtime_key_or_store_api_is_exposed(self):
        self.seal()
        for name in ("serverware.config", "serverware.db", "serverware.oauth", "serverware.operator_provider_key"):
            self.assertNotIn(name, sys.modules)
        for name in ("TABLE", "install_empty_store", "insert_secret", "read_secret", "initialize_first", "read_existing_master_key"):
            self.assertFalse(hasattr(custody, name))


if __name__ == "__main__":
    unittest.main()
