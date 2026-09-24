#!/usr/bin/env python3
"""Genuine PEM and public-identity components for writer startup provisioning.

These controls exercise the actual inert parser and Ed25519 serialization,
not MeasuredConfiguration.load, descriptor ownership, active launch, service
admission or HSM custody. The returned private key is not a proof token. No
signature, ACK, database action or request-work allowance is constructed.
Damaged-key wrappers are negative-only; successful parser observers return
the actual parsed key unchanged. All controls are authored source, not executed
preparation evidence.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_revocation_writer_signer as signer


def private_pem(key, encryption=None):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption() if encryption is None else encryption)


def spki_digest(key):
    # Independent standard DER serialization and hash, not the helper under test.
    encoded = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class SignerFixture:
    def __init__(self):
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.other_keys = tuple(Ed25519PrivateKey.from_private_bytes(bytes([value]) * 32)
            for value in (41, 42, 43, 44))
        self.launch_key = Ed25519PrivateKey.from_private_bytes(bytes([45]) * 32)
        self.pem = private_pem(self.key)
        self.arguments = {"response_spki_digest": spki_digest(self.key.public_key()),
            "other_response_spki_digests": tuple(spki_digest(key.public_key()) for key in self.other_keys),
            "launch_public_key": self.launch_key.public_key()}


class _PublicKey(Ed25519PublicKey):
    """Negative serializer observer; cryptographic operations remain genuine."""

    def __init__(self, key, *, transform=lambda value: value, callback=lambda: None):
        self.key, self.transform, self.callback = key, transform, callback

    def verify(self, signature, data):
        return self.key.verify(signature, data)

    def public_bytes(self, encoding, format):
        actual = self.key.public_bytes(encoding, format)
        self.callback()
        return self.transform(actual)

    def public_bytes_raw(self):
        return self.key.public_bytes_raw()

    def __copy__(self):
        return self


class _PrivateKey(Ed25519PrivateKey):
    """Negative-only derived-public observer around a genuinely parsed key."""

    def __init__(self, key, *, transform=lambda value: value, callback=lambda: None):
        self.key, self.transform, self.callback = key, transform, callback

    def public_key(self):
        actual = self.key.public_key()
        self.callback()
        return self.transform(actual)

    def sign(self, data):
        raise AssertionError("startup provisioning must not sign")

    def private_bytes(self, encoding, format, encryption_algorithm):
        return self.key.private_bytes(encoding, format, encryption_algorithm)

    def private_bytes_raw(self):
        return self.key.private_bytes_raw()

    def __copy__(self):
        return self


class RevocationWriterSignerTests(unittest.TestCase):
    def load(self, fixture, *, private_bytes=None, **changes):
        return signer._signer_from_pem(fixture.pem if private_bytes is None else private_bytes,
            **{**fixture.arguments, **changes})

    def test_genuine_unencrypted_pem_returns_the_actual_separately_pinned_key(self):
        fixture, parsed = SignerFixture(), []
        original = serialization.load_pem_private_key

        def observe(raw, *, password):
            key = original(raw, password=password)
            parsed.append(key)
            return key

        with patch.object(signer.serialization, "load_pem_private_key", side_effect=observe) as loader:
            actual = self.load(fixture)
        loader.assert_called_once_with(fixture.pem, password=None)
        self.assertIs(actual, parsed[0])
        self.assertIsInstance(actual, Ed25519PrivateKey)
        self.assertEqual(private_pem(actual), fixture.pem)
        self.assertEqual(spki_digest(actual.public_key()), fixture.arguments["response_spki_digest"])
        self.assertEqual(len(set(fixture.arguments["other_response_spki_digests"] + (
            fixture.arguments["response_spki_digest"], spki_digest(fixture.launch_key.public_key())))), 6)

    def test_exact_original_bytes_and_bounds_are_checked_before_real_parsing(self):
        class BytesSubclass(bytes):
            pass

        fixture = SignerFixture()
        for value in (None, False, "PEM", bytearray(fixture.pem), memoryview(fixture.pem),
                BytesSubclass(fixture.pem), b"", b"x", b"x" * 65537):
            with self.subTest(value_type=type(value), size=len(value) if hasattr(value, "__len__") else None):
                with patch.object(signer.serialization, "load_pem_private_key",
                        wraps=serialization.load_pem_private_key) as loader:
                    with self.assertRaises(signer.RevocationWriterSignerError):
                        signer._signer_from_pem(value, **fixture.arguments)
                self.assertEqual(loader.call_count, 0)
        # Exact endpoints pass only the raw bound, not PEM admission: the real
        # parser rejects both deliberately malformed bounded originals.
        for value in (b"xx", b"x" * 65536):
            with self.subTest(size=len(value)), patch.object(signer.serialization, "load_pem_private_key",
                    wraps=serialization.load_pem_private_key) as loader:
                with self.assertRaises(signer.RevocationWriterSignerError) as raised:
                    self.load(fixture, private_bytes=value)
            loader.assert_called_once_with(value, password=None)
            self.assertIsInstance(raised.exception.__cause__, ValueError)

    def test_pin_and_four_role_tuple_shapes_deny_before_any_key_callback(self):
        class StringSubclass(str):
            pass

        class TupleSubclass(tuple):
            pass

        fixture = SignerFixture()
        digest = fixture.arguments["response_spki_digest"]
        malformed = (None, True, b"sha256:" + b"0" * 64, "", "sha256:" + "0" * 63,
            "sha256:" + "0" * 65, "SHA256:" + "0" * 64, "sha256:" + "G" * 64,
            "sha256:" + "A" * 64, "sha256:" + "0" * 63 + "\n", StringSubclass(digest))
        changes = [{"response_spki_digest": value} for value in malformed]
        others = fixture.arguments["other_response_spki_digests"]
        changes.extend({"other_response_spki_digests": value} for value in (
            None, list(others), TupleSubclass(others), (), others[:3], others + (digest,)))
        for index in range(4):
            changes.extend({"other_response_spki_digests": others[:index] + (value,) + others[index + 1:]}
                for value in malformed)
        changes.extend({"launch_public_key": value} for value in (
            None, object(), fixture.launch_key, ec.derive_private_key(7, ec.SECP256R1()).public_key()))
        for index, change in enumerate(changes):
            with self.subTest(index=index), patch.object(signer.serialization, "load_pem_private_key",
                    wraps=serialization.load_pem_private_key) as loader:
                with self.assertRaises(signer.RevocationWriterSignerError): self.load(fixture, **change)
            self.assertEqual(loader.call_count, 0)

    def test_writer_pin_cannot_reuse_any_of_the_four_other_authority_roles(self):
        fixture = SignerFixture()
        for index, role in enumerate(("verifier", "planner", "issuer", "executor")):
            others = list(fixture.arguments["other_response_spki_digests"])
            others[index] = fixture.arguments["response_spki_digest"]
            with self.subTest(role=role), patch.object(signer.serialization, "load_pem_private_key",
                    wraps=serialization.load_pem_private_key) as loader:
                with self.assertRaisesRegex(signer.RevocationWriterSignerError, "another authority role"):
                    self.load(fixture, other_response_spki_digests=tuple(others))
            self.assertEqual(loader.call_count, 0)

    def test_real_parser_rejects_non_pem_encryption_and_non_ed25519_private_keys(self):
        fixture = SignerFixture()
        cases = {"raw32": fixture.key.private_bytes(serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw, serialization.NoEncryption()),
            "private_der": fixture.key.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            "public_pem": fixture.key.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo),
            "malformed": b"-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n",
            "encrypted": private_pem(fixture.key, serialization.BestAvailableEncryption(b"fixture-only-password")),
            "ecdsa": private_pem(ec.derive_private_key(7, ec.SECP256R1()))}
        for name, value in cases.items():
            with self.subTest(name=name), patch.object(signer.serialization, "load_pem_private_key",
                    wraps=serialization.load_pem_private_key) as loader:
                with self.assertRaises(signer.RevocationWriterSignerError) as raised:
                    self.load(fixture, private_bytes=value)
            loader.assert_called_once_with(value, password=None)
            if name == "ecdsa":
                self.assertIn("not Ed25519", str(raised.exception))
                self.assertIsNone(raised.exception.__cause__)
            else:
                self.assertIsInstance(raised.exception.__cause__, (TypeError, ValueError))

    def test_real_private_pin_mismatch_precedes_launch_comparison_and_launch_alias_denies(self):
        fixture = SignerFixture()
        launch = _PublicKey(fixture.launch_key.public_key(),
            callback=lambda: self.fail("launch export before private-key pin denial"))
        with self.assertRaisesRegex(signer.RevocationWriterSignerError, "differs from the measured pin"):
            self.load(fixture, private_bytes=private_pem(fixture.other_keys[0]), launch_public_key=launch)
        with self.assertRaisesRegex(signer.RevocationWriterSignerError, "launch identity"):
            self.load(fixture, launch_public_key=fixture.key.public_key())

    def test_negative_derived_and_launch_serializers_require_exact_canonical_der(self):
        class BytesSubclass(bytes):
            pass

        fixture = SignerFixture()
        original = serialization.load_pem_private_key
        transforms = (lambda actual: None, bytearray, BytesSubclass, lambda actual: actual[:-1],
            lambda actual: actual + b"x", lambda actual: b"\x31" + actual[1:])
        for stage in ("derived", "launch"):
            for index, transform in enumerate(transforms):
                changes = {}

                def load_negative(raw, *, password):
                    key = original(raw, password=password)
                    return (_PrivateKey(key, transform=lambda public: _PublicKey(public, transform=transform))
                        if stage == "derived" else key)

                if stage == "launch":
                    changes["launch_public_key"] = _PublicKey(fixture.launch_key.public_key(), transform=transform)
                with self.subTest(stage=stage, index=index), patch.object(signer.serialization,
                        "load_pem_private_key", side_effect=load_negative):
                    with self.assertRaisesRegex(signer.RevocationWriterSignerError, "not canonical Ed25519"):
                        self.load(fixture, **changes)
        for output in (None, object(), ec.derive_private_key(7, ec.SECP256R1()).public_key()):
            def wrong_type(raw, *, password):
                return _PrivateKey(original(raw, password=password), transform=lambda actual: output)
            with patch.object(signer.serialization, "load_pem_private_key", side_effect=wrong_type):
                with self.assertRaisesRegex(signer.RevocationWriterSignerError, "not Ed25519"):
                    self.load(fixture)

    def test_native_parser_and_key_callback_errors_propagate_without_success_or_repair(self):
        fixture = SignerFixture()
        original = serialization.load_pem_private_key
        for stage in ("parser", "derive", "writer_der", "launch_der"):
            failure = RuntimeError("native " + stage)

            def fail():
                raise failure

            def load_negative(raw, *, password):
                actual = original(raw, password=password)
                if stage == "parser": fail()
                if stage == "derive": return _PrivateKey(actual, callback=fail)
                if stage == "writer_der":
                    return _PrivateKey(actual, transform=lambda public: _PublicKey(public, callback=fail))
                return actual

            changes = ({"launch_public_key": _PublicKey(fixture.launch_key.public_key(), callback=fail)}
                if stage == "launch_der" else {})
            with self.subTest(stage=stage), patch.object(signer.serialization,
                    "load_pem_private_key", side_effect=load_negative):
                with self.assertRaises(RuntimeError) as raised: self.load(fixture, **changes)
            self.assertIs(raised.exception, failure)

    def test_parser_callback_cannot_rebind_already_supplied_immutable_inputs(self):
        fixture, parsed = SignerFixture(), []
        original = serialization.load_pem_private_key
        supplied = {"private_bytes": fixture.pem, **fixture.arguments}
        expected = dict(supplied)

        def mutate_caller(raw, *, password):
            actual = original(raw, password=password)
            parsed.append(actual)
            supplied.update(private_bytes=private_pem(fixture.other_keys[0]),
                response_spki_digest=fixture.arguments["other_response_spki_digests"][0],
                other_response_spki_digests=(fixture.arguments["response_spki_digest"],) * 4,
                launch_public_key=fixture.key.public_key())
            return actual

        with patch.object(signer.serialization, "load_pem_private_key", side_effect=mutate_caller) as loader:
            actual = signer._signer_from_pem(**supplied)
        self.assertIs(actual, parsed[0])
        self.assertEqual(private_pem(actual), expected["private_bytes"])
        self.assertEqual(spki_digest(actual.public_key()), expected["response_spki_digest"])
        loader.assert_called_once_with(expected["private_bytes"], password=None)
        self.assertNotEqual(supplied["response_spki_digest"], expected["response_spki_digest"])
        # This is the helper's immutable-argument property, not a claim that
        # this test executed the service's pre-descriptor configuration capture.

    def test_startup_interface_accepts_no_request_work_or_signing_admission_overrides(self):
        fixture = SignerFixture()
        for name in ("work", "configuration", "signer", "loader", "opener", "descriptor", "database"):
            with self.subTest(name=name), patch.object(signer.serialization, "load_pem_private_key",
                    wraps=serialization.load_pem_private_key) as loader:
                with self.assertRaises(TypeError): self.load(fixture, **{name: object()})
            self.assertEqual(loader.call_count, 0)


if __name__ == "__main__":
    unittest.main()
