#!/usr/bin/env python3
"""Offline stored-envelope compatibility, not native custody or release proof.

Both existing producers run with public synthetic keys only. Imported shared
readers must retain each original string and admit only either canonical stored
representation. Native purpose-specific admission and channel codecs stay strict.
No database, service, provider, native owner or host key loader is started.
Run in the bounded network-none cached full-dependency test image.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if sys.flags.optimize:
    raise RuntimeError("stored credential codec tests require enabled assertions")


def no_network(event, _args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("stored credential codec tests forbid network")


sys.addaudithook(no_network)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator
from serverware import credential_ciphertext as projection
from serverware import crypto
from serverware import native_oauth_refresh as oauth_material
from serverware import native_secret_broker_helper as broker
from serverware import native_static_credential as static_material

IDENTIFIER = "12345678-1234-4234-8234-123456789abc"
KEY = bytes(range(32))  # Public synthetic test material, never deployed.
KEY_ID = "attested-memory-kek:" + "a" * 24
EPOCH_NS = 1_791_273_600_123_456_000
STAMP = "2026-10-06T00:00:00.123456+00:00"
READERS = (projection._encoded, broker._stored)


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii")


def row(envelope):
    return {"id": IDENTIFIER, "kind": "bearer", "credential_version": 1,
        "encrypted_secret": "envelope:v2", "secret_kek_id": KEY_ID,
        "secret_updated_at": STAMP, "lifecycle_status": "active", **envelope}


class StoredCredentialCodecTests(unittest.TestCase):
    def shared_readback(self, original, plaintext):
        before = deepcopy(original)
        transported = projection.row_projection(original)
        self.assertEqual(transported, {"credentialId": original["id"],
            "credentialVersion": original["credential_version"], "secretKekId": original["secret_kek_id"],
            "encryptedDek": original["encrypted_dek"], "secretNonce": original["secret_nonce"],
            "secretCiphertext": original["secret_ciphertext"], "secretUpdatedAt": original["secret_updated_at"]})
        # Decode through the actual helper codec, then independently authenticate
        # the known synthetic envelope. This is not a native owner/lease test.
        _, key_nonce, wrapped = transported["encryptedDek"].split(":")
        dek = AESGCM(KEY).decrypt(broker._stored(key_nonce, 12, 12), broker._stored(wrapped, 48, 48),
            f"serverware:dek:{IDENTIFIER}:v1".encode())
        actual = AESGCM(dek).decrypt(broker._stored(transported["secretNonce"][3:], 12, 12),
            broker._stored(transported["secretCiphertext"][3:], projection.MAX_CIPHERTEXT_BYTES),
            f"serverware:secret:{IDENTIFIER}:v1".encode())
        self.assertEqual(actual, plaintext)
        self.assertEqual(original, before)

    def test_both_canonical_forms_all_residues_and_component_bounds(self):
        # 17/18/19 cover every ciphertext padding length; 12/48 are exact
        # nonce/wrapped-key sizes. The upper limit includes the AEAD tag.
        for length in (1, 2, 3, 12, 17, 18, 19, 48, projection.MAX_CIPHERTEXT_BYTES):
            raw = b"\xff" * length
            for value in dict.fromkeys((encoded(raw), encoded(raw).rstrip("="))):
                for reader in READERS:
                    with self.subTest(reader=reader.__qualname__, length=length, padded=value.endswith("=")):
                        self.assertEqual(reader(value, maximum=length, exact=length), raw)

    def test_noncanonical_malformed_and_non_urlsafe_encodings_refused(self):
        invalid = (None, True, 1, b"Zg==", "", " ", "\tZg==", "Zg==\n", "Z g==",
            "Zg=", "Zg===", "=Zg=", "Z=g=", "====", "A", "AAAAA", "AAAA=", "é",
            "/w==", "/w", "+w==", "AA+/", "_x", "_x==", "__9", "__9=")
        for reader in READERS:
            for index, value in enumerate(invalid):
                with self.subTest(reader=reader.__qualname__, case=index), self.assertRaises(ValueError):
                    reader(value, maximum=64)

    def test_bounds_before_decode_and_exact_decoded_lengths(self):
        for reader in READERS:
            for value, maximum, exact in ((encoded(b"x" * 3), 2, None),
                    (encoded(b"x" * 11), 12, 12), (encoded(b"x" * 13), 13, 12),
                    (encoded(b"x" * 47), 48, 48), (encoded(b"x" * 49), 49, 48)):
                with self.subTest(reader=reader.__qualname__, maximum=maximum, exact=exact), self.assertRaises(ValueError):
                    reader(value, maximum=maximum, exact=exact)
            with patch.object(base64, "b64decode", side_effect=AssertionError("oversized input reached decoder")) as decode:
                with self.assertRaises(ValueError):
                    reader("A" * 17, maximum=12)
                decode.assert_not_called()

    def test_row_ciphertext_minimum_maximum_and_no_legacy_fallback(self):
        template = row({"encrypted_dek": "v1:" + encoded(b"n" * 12) + ":" + encoded(b"d" * 48),
            "secret_nonce": "v1:" + encoded(b"s" * 12), "secret_ciphertext": "v1:" + encoded(b"c" * 17)})
        for length in (17, 18, 19, projection.MAX_CIPHERTEXT_BYTES):
            for text in dict.fromkeys((encoded(b"c" * length), encoded(b"c" * length).rstrip("="))):
                original = {**template, "secret_ciphertext": "v1:" + text}
                before = deepcopy(original)
                self.assertEqual(projection.row_projection(original)["secretCiphertext"], original["secret_ciphertext"])
                self.assertEqual(original, before)
        invalid = [{"secret_ciphertext": "v1:" + encoded(b"c" * length)}
            for length in (0, 1, 16, projection.MAX_CIPHERTEXT_BYTES + 1)]
        invalid += [{"encrypted_secret": "legacy-secret"}, {"secret_ciphertext": "v2:" + encoded(b"c" * 17)},
            {"secret_nonce": "v1:" + encoded(b"s" * 11)}, {"encrypted_dek": template["encrypted_dek"] + "="}]
        for index, changes in enumerate(invalid):
            original = {**template, **changes}
            before = deepcopy(original)
            with self.subTest(case=index), self.assertRaises(ValueError):
                projection.row_projection(original)
            self.assertEqual(original, before)

    def test_actual_ordinary_writer_unpadded_roundtrip_retains_originals(self):
        with patch.object(crypto, "load_master_key", return_value=KEY), \
                patch.object(crypto, "local_kek_id", return_value=KEY_ID):
            for plaintext in ("x", "xx", "xxx"):
                envelope = crypto.encrypt_secret_envelope(plaintext, credential_id=IDENTIFIER, credential_version=1)
                self.assertFalse(envelope["secret_ciphertext"].endswith("="))
                original = row(envelope)
                self.shared_readback(original, plaintext.encode())
                self.assertEqual(crypto.decrypt_secret_envelope(original), plaintext)

    def test_actual_native_static_and_oauth_writers_keep_padded_originals(self):
        for material in (static_material, oauth_material):
            for plaintext in (b"x", b"xx", b"xxx"):
                with self.subTest(producer=material.__name__, length=len(plaintext)):
                    envelope = material.seal_original(IDENTIFIER, plaintext, 1, KEY_ID, AESGCM(KEY), EPOCH_NS)
                    padding = (-(len(plaintext) + 16)) % 3
                    self.assertEqual(len(envelope["secret_ciphertext"]) - len(envelope["secret_ciphertext"].rstrip("=")), padding)
                    self.shared_readback(row(envelope), plaintext)
                    self.assertEqual(material.open_original(IDENTIFIER, envelope, 1, KEY_ID, AESGCM(KEY)), plaintext)

    def test_native_admission_and_private_channel_remain_unmodified(self):
        for material in (static_material, oauth_material):
            envelope = material.seal_original(IDENTIFIER, b"x", 1, KEY_ID, AESGCM(KEY), EPOCH_NS)
            self.assertTrue(envelope["secret_ciphertext"].endswith("="))
            altered = {**envelope, "secret_ciphertext": envelope["secret_ciphertext"].rstrip("=")}
            with self.subTest(producer=material.__name__), self.assertRaises(ValueError):
                material.open_original(IDENTIFIER, altered, 1, KEY_ID, AESGCM(KEY))
        self.assertEqual(broker._decoded("_w", 1, 1), b"\xff")
        with self.assertRaises(ValueError):
            broker._decoded("_w==", 1, 1)

    def test_schema_smallest_unpadded_ciphertext_and_unchanged_maximum(self):
        document = json.loads((ROOT / "schemas/native-broker-credential-lease.common.schema.json").read_text())
        field = document["$defs"]["encryptedCredential"]["properties"]["secretCiphertext"]
        validator = Draft202012Validator(field)
        self.assertEqual(field["minLength"], 26)
        self.assertEqual(field["maxLength"], 1398127)
        for raw in (b"c" * 17, b"c" * projection.MAX_CIPHERTEXT_BYTES):
            for value in dict.fromkeys((encoded(raw), encoded(raw).rstrip("="))):
                self.assertTrue(validator.is_valid("v1:" + value))
        self.assertFalse(validator.is_valid("v1:" + encoded(b"c" * 16).rstrip("=")))
        self.assertFalse(validator.is_valid("v1:" + "A" * (field["maxLength"] - 2)))


if __name__ == "__main__":
    unittest.main()
