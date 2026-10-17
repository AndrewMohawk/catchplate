#!/usr/bin/env python3
"""Real signed trust-bundle components; not installation or authority evidence.

Only the measured source schema is read as an explicit verification input.
The core receives no database, configuration, files, signer or ambient clock.
Independent JSON/hash expectations below do not use core serialization helpers.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import webauthn_trust_core as core


START = datetime(2020, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
END = datetime(2030, 1, 1, tzinfo=timezone.utc)
SCHEMA_SHA256 = "68752c1d4af1dfc994f8b3238e33f393da8a5c1c4368f5b1c6e5767856c0d975"
AAGUID = "2fc0579f-8113-47ea-b116-bb5a8db9202a"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def pretty(value):
    return (json.dumps(value, indent=2, sort_keys=True,
        ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class WebAuthnTrustCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = (ROOT / "schemas/webauthn-trust-bundle.v1.schema.json").read_bytes()
        cls.signer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        cls.other_signer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        cls.public_der = cls.signer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        certificate_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"\xa5" * 32)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "trust-core fixture root")])
        cls.certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(certificate_key.public_key()).serial_number(1234567)
            .not_valid_before(START).not_valid_after(END)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(certificate_key, algorithm=None))
        cls.certificate_der = cls.certificate.public_bytes(serialization.Encoding.DER)
        cls.certificate_pem = cls.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        cls.context = core.TrustVerificationContext(cls.public_der, cls.schema, NOW)

    def unsigned(self):
        return {
            "apiVersion": "catchplate.webauthnTrust/v1", "kind": "WebAuthnTrustBundle",
            "metadata": {"id": "fixture-é-雪-😀", "sequence": 7, "rollbackEpoch": 2,
                "validFrom": START.isoformat(), "validUntil": END.isoformat(),
                "signingKeyId": digest(self.public_der)},
            "roots": [{"id": "fixture-root", "authenticatorClass": "hardware",
                "certificatePem": self.certificate_pem,
                "certificateSha256": digest(self.certificate_der), "aaguids": [AAGUID]}],
        }

    def signed(self, unsigned=None, *, signer=None):
        value = copy.deepcopy(self.unsigned() if unsigned is None else unsigned)
        value["metadata"].pop("signature", None)
        value["metadata"]["signature"] = "ed25519:" + b64((signer or self.signer).sign(canonical(value)))
        return value

    def verify(self, value=None, *, raw=None, context=None):
        if raw is None:
            raw = canonical(self.signed() if value is None else value)
        return core.verify_bundle(raw, context or self.context)

    def state(self, result=None, **changes):
        result = self.verify() if result is None else result
        value = {"version": 1, "bundle_digest": result.bundle_digest,
            "sequence": result.sequence, "rollback_epoch": result.rollback_epoch,
            "updated_at": NOW.isoformat()}
        value.update(changes)
        return value

    def assert_rejected(self, value, message):
        with self.assertRaisesRegex(core.WebAuthnTrustError, message):
            self.verify(value)

    def test_signed_bundle_has_independently_derived_four_byte_commitments(self):
        unsigned = self.unsigned()
        signed = self.signed(unsigned)
        raw = (json.dumps(signed, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
        result = self.verify(raw=raw)
        expected_bytes = (raw, canonical(signed), canonical(unsigned), pretty(signed))
        self.assertEqual(len(set(expected_bytes)), 4)
        for byte_field, digest_field, expected in (
            ("input_bytes", "input_digest", expected_bytes[0]),
            ("canonical_envelope_bytes", "canonical_envelope_digest", expected_bytes[1]),
            ("signature_payload_bytes", "bundle_digest", expected_bytes[2]),
            ("installation_bytes", "installation_digest", expected_bytes[3]),
        ):
            with self.subTest(field=byte_field):
                self.assertEqual(getattr(result, byte_field), expected)
                self.assertEqual(getattr(result, digest_field), digest(expected))
        self.assertEqual(result.info_dict(), {"digest": digest(canonical(unsigned)),
            "sequence": 7, "rollback_epoch": 2, "signing_key_id": digest(self.public_der)})
        self.assertEqual(result.verified_at, NOW)
        root, = result.roots
        self.assertEqual((root.id, root.certificate_der, root.certificate_sha256,
            root.authenticator_class, root.aaguids), ("fixture-root", self.certificate_der,
            digest(self.certificate_der), "hardware", frozenset({AAGUID})))

    def test_verified_graph_is_immutable_and_projections_are_fresh(self):
        result = self.verify()
        with self.assertRaises(FrozenInstanceError):
            result.sequence = 8
        with self.assertRaises(FrozenInstanceError):
            result.roots[0].authenticator_class = "platform"
        value = result.bundle_dict()
        value["roots"][0]["aaguids"].clear()
        value["metadata"]["sequence"] = 999
        info = result.info_dict()
        info["sequence"] = 999
        self.assertEqual(result.bundle_dict(), self.signed())
        self.assertEqual(result.info_dict()["sequence"], 7)
        self.assertEqual(result.roots[0].aaguids, frozenset({AAGUID}))

    def test_original_representation_does_not_change_signed_or_installed_bytes(self):
        signed = self.signed()
        first = self.verify(signed)
        second = self.verify(raw=(json.dumps(signed, ensure_ascii=False, indent=4) + "\n").encode())
        self.assertNotEqual(first.input_digest, second.input_digest)
        for field in ("bundle_digest", "canonical_envelope_digest", "installation_digest",
            "signature_payload_bytes", "canonical_envelope_bytes", "installation_bytes"):
            self.assertEqual(getattr(first, field), getattr(second, field))
        installed = self.verify(raw=second.installation_bytes)
        self.assertEqual(installed.input_digest, second.installation_digest)
        self.assertEqual(installed.installation_bytes, second.installation_bytes)

    def test_empty_roots_is_a_real_signed_withdrawal_and_still_plans_checkpoint(self):
        value = self.unsigned()
        value["roots"] = []
        result = self.verify(self.signed(value))
        self.assertEqual(result.roots, ())
        self.assertEqual(result.bundle_dict()["roots"], [])
        self.assertEqual(core.plan_rollback(result, None, self.context), pretty(self.state(result)))

    def test_signature_and_independently_supplied_signer_are_enforced(self):
        self.verify()
        changed = self.signed()
        changed["metadata"]["id"] = "unsigned-substitution"
        self.assert_rejected(changed, "signature verification failed")
        self.assert_rejected(self.signed(signer=self.other_signer), "signature verification failed")
        other_der = self.other_signer.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(core.WebAuthnTrustError, "signing key mismatch"):
            self.verify(context=replace(self.context, public_key_der=other_der))
        changed = self.signed()
        changed["metadata"]["signature"] = "ed25519:" + b64(b"short")
        self.assert_rejected(changed, "signature encoding is invalid")
        unsigned = self.unsigned()
        unsigned["metadata"]["signingKeyId"] = digest(other_der)
        self.assert_rejected(self.signed(unsigned, signer=self.other_signer), "signing key mismatch")

    def test_measured_schema_and_exact_ed25519_spki_are_context_inputs(self):
        self.assertEqual(hashlib.sha256(self.schema).hexdigest(), SCHEMA_SHA256)
        self.assertEqual(core.TRUST_BUNDLE_SCHEMA_SHA256, SCHEMA_SHA256)
        for raw in (self.schema + b"\n", b'{"type":"object"}'):
            with self.subTest(schema=raw[:20]), self.assertRaisesRegex(
                core.WebAuthnTrustError, "schema does not match the measured source schema"):
                replace(self.context, schema_bytes=raw)
        wrong_type = ec.derive_private_key(11, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(core.WebAuthnTrustError, "public key must be Ed25519"):
            replace(self.context, public_key_der=wrong_type)
        with self.assertRaisesRegex(core.WebAuthnTrustError, "public key is not valid DER"):
            replace(self.context, public_key_der=b"not DER")
        changed = self.unsigned()
        changed["metadata"]["unreviewedField"] = True
        self.assert_rejected(self.signed(changed), "schema validation failed")

    def test_explicit_bundle_time_is_inclusive_and_missing_expiry_remains_legal(self):
        signed = self.signed()
        for instant in (START, NOW, END):
            self.assertEqual(self.verify(signed, context=replace(self.context,
                verified_at=instant)).verified_at, instant)
        for instant, message in ((START - timedelta(microseconds=1), "not valid yet"),
            (END + timedelta(microseconds=1), "expired")):
            with self.assertRaisesRegex(core.WebAuthnTrustError, message):
                self.verify(signed, context=replace(self.context, verified_at=instant))
        unsigned = self.unsigned()
        del unsigned["metadata"]["validUntil"]
        self.verify(self.signed(unsigned), context=replace(self.context,
            verified_at=END + timedelta(days=1)))

    def test_naive_context_and_signed_malformed_times_are_rejected(self):
        for instant in (NOW.replace(tzinfo=None), NOW.astimezone(timezone(timedelta(hours=1)))):
            with self.assertRaisesRegex(core.WebAuthnTrustError, "explicit aware UTC"):
                replace(self.context, verified_at=instant)
        for field in ("validFrom", "validUntil"):
            for value in ("2025-01-01T00:00:00", "not-a-time"):
                unsigned = self.unsigned()
                unsigned["metadata"][field] = value
                with self.subTest(field=field, value=value):
                    self.assert_rejected(self.signed(unsigned), field + " must be an aware timestamp")

    def test_real_signature_does_not_make_malformed_root_or_declared_digest_valid(self):
        valid = self.verify()
        for certificate, expected in (("not a certificate", "root certificate is invalid"),
            (self.certificate_pem * 2, "exactly one certificate")):
            unsigned = self.unsigned()
            unsigned["roots"][0]["certificatePem"] = certificate
            self.assert_rejected(self.signed(unsigned), expected)
        unsigned = self.unsigned()
        unsigned["roots"][0]["certificateSha256"] = digest(b"wrong DER")
        self.assert_rejected(self.signed(unsigned), "certificate digest mismatch")
        # A forged dataclass retaining an invalid signed input cannot bypass
        # verification to produce rollback state.
        forged = replace(valid, input_bytes=canonical(self.signed(unsigned)))
        with self.assertRaisesRegex(core.WebAuthnTrustError, "certificate digest mismatch"):
            core.plan_rollback(forged, None, self.context)

    def test_duplicate_json_keys_nonfinite_and_bad_unicode_are_denied(self):
        raw = canonical(self.signed())
        for changed, message in (
            (raw.replace(b'"sequence":7', b'"sequence":7,"sequence":7'), "duplicate keys"),
            (raw.replace(b'"sequence":7', b'"sequence":NaN'), "nonfinite value"),
            (raw.replace(b'"sequence":7', b'"sequence":Infinity'), "nonfinite value"),
        ):
            self.assertNotEqual(changed, raw)
            with self.assertRaisesRegex(core.WebAuthnTrustError, message):
                self.verify(raw=changed)
        unsigned = self.unsigned()
        unsigned["metadata"]["id"] = "\ud800"
        self.assert_rejected(self.signed(unsigned), "invalid Unicode")

    def test_counters_do_not_accept_json_schema_integer_coercion_or_overflow(self):
        self.verify()
        for field in ("sequence", "rollbackEpoch"):
            for value, message in ((True, "schema validation failed"), (False, "schema validation failed"),
                (0, "schema validation failed"), (-1, "schema validation failed"),
                ("7", "schema validation failed"), (7.0, "positive bounded integer"),
                (2**63, "positive bounded integer")):
                unsigned = self.unsigned()
                unsigned["metadata"][field] = value
                with self.subTest(field=field, value=value):
                    self.assert_rejected(self.signed(unsigned), message)
        unsigned = self.unsigned()
        unsigned["metadata"].update(sequence=2**63 - 1, rollbackEpoch=2**63 - 1)
        result = self.verify(self.signed(unsigned))
        self.assertEqual((result.sequence, result.rollback_epoch), (2**63 - 1, 2**63 - 1))

    def test_root_count_and_aaguid_bounds_fail_after_real_signature_verification(self):
        unsigned = self.unsigned()
        unsigned["roots"] = [copy.deepcopy(unsigned["roots"][0]) for _ in range(257)]
        self.assert_rejected(self.signed(unsigned), "root count exceeds the verification profile")
        unsigned = self.unsigned()
        unsigned["roots"][0]["aaguids"] = [f"00000000-0000-0000-0000-{index:012x}"
            for index in range(1025)]
        self.assert_rejected(self.signed(unsigned), "root AAGUID set is oversized")

    def test_transport_requires_utf8_and_bounded_immutable_input_bytes(self):
        raw = canonical(self.signed())
        self.verify(raw=raw)
        for label, changed in (("UTF16", raw.decode("ascii").encode("utf-16")),
            ("UTF32", raw.decode("ascii").encode("utf-32")),
            ("UTF8 BOM", b"\xef\xbb\xbf" + raw), ("invalid UTF8", b"\xff" + raw)):
            with self.subTest(label=label), self.assertRaisesRegex(core.WebAuthnTrustError,
                "bundle is not valid UTF-8 JSON"):
                self.verify(raw=changed)
        for label, changed in (("mutable", bytearray(raw)), ("empty", b""),
            ("oversized", b" " * (core.MAX_INPUT_BYTES + 1))):
            with self.subTest(label=label), self.assertRaisesRegex(core.WebAuthnTrustError,
                "bundle is invalid or oversized"):
                self.verify(raw=changed)

    def test_near_canonical_limit_accepts_its_larger_installation_bytes_on_retry(self):
        unsigned = self.unsigned()
        unsigned["metadata"]["id"] = "x"
        base = self.signed(unsigned)
        base_size = len(canonical(base))
        pretty_overhead = len(pretty(base)) - base_size
        self.assertGreater(pretty_overhead, 2)
        target_size = core.MAX_CANONICAL_BYTES - pretty_overhead // 2
        unsigned["metadata"]["id"] = "x" * (target_size - base_size + 1)
        signed = self.signed(unsigned)
        raw = canonical(signed)
        self.assertEqual(len(raw), target_size)
        self.assertGreater(len(pretty(signed)), core.MAX_CANONICAL_BYTES)
        self.assertLessEqual(len(pretty(signed)), core.MAX_INSTALLATION_BYTES)
        verified = self.verify(raw=raw)
        retried = self.verify(raw=verified.installation_bytes)
        self.assertEqual(retried.bundle_digest, verified.bundle_digest)
        self.assertEqual(retried.installation_bytes, verified.installation_bytes)
        self.assertIsNone(core.plan_rollback(retried, pretty(self.state(verified)), self.context))
        unsigned["metadata"]["id"] = "x" * (core.MAX_CANONICAL_BYTES - base_size + 2)
        oversized = self.signed(unsigned)
        self.assertEqual(len(canonical(oversized)), core.MAX_CANONICAL_BYTES + 1)
        self.assert_rejected(oversized, "canonical bundle exceeds 2 MiB")

    def test_signed_root_class_and_aaguid_spelling_are_retained_without_normalization(self):
        for authenticator_class in ("hardware", "yubikey", "platform"):
            unsigned = self.unsigned()
            unsigned["roots"][0].update(authenticatorClass=authenticator_class,
                aaguids=[AAGUID.upper()])
            with self.subTest(authenticator_class=authenticator_class):
                result = self.verify(self.signed(unsigned))
                self.assertEqual(result.roots[0].authenticator_class, authenticator_class)
                self.assertEqual(result.roots[0].aaguids, frozenset({AAGUID.upper()}))
                self.assertEqual(result.bundle_dict()["roots"][0]["aaguids"], [AAGUID.upper()])

    def test_initial_checkpoint_bytes_and_exact_retry_are_deterministic(self):
        result = self.verify()
        expected = pretty(self.state(result))
        for previous in (None, b'{"version":1}'):
            self.assertEqual(core.plan_rollback(result, previous, self.context), expected)
        self.assertIsNone(core.plan_rollback(result, expected, self.context))
        # Noop does not rewrite a valid historical updated_at to the new time.
        old = pretty(self.state(result, updated_at=START.isoformat()))
        self.assertIsNone(core.plan_rollback(result, old, self.context))

    def test_epoch_and_sequence_advancement_preserve_legacy_ordering(self):
        prior = pretty(self.state())
        for epoch, sequence in ((2, 8), (3, 1)):
            unsigned = self.unsigned()
            unsigned["metadata"].update(rollbackEpoch=epoch, sequence=sequence)
            result = self.verify(self.signed(unsigned))
            self.assertEqual(core.plan_rollback(result, prior, self.context), pretty(self.state(result)))
        for epoch, sequence, message in ((1, 999, "rollback epoch is stale"),
            (2, 6, "sequence is stale")):
            unsigned = self.unsigned()
            unsigned["metadata"].update(rollbackEpoch=epoch, sequence=sequence)
            with self.assertRaisesRegex(core.WebAuthnTrustError, message):
                core.plan_rollback(self.verify(self.signed(unsigned)), prior, self.context)

    def test_same_generation_real_signed_fork_is_rejected(self):
        prior = pretty(self.state())
        unsigned = self.unsigned()
        unsigned["roots"] = []
        result = self.verify(self.signed(unsigned))
        with self.assertRaisesRegex(core.WebAuthnTrustError, "content changed without advancing sequence"):
            core.plan_rollback(result, prior, self.context)

    def test_corrupt_rollback_state_is_not_silently_reset_to_bootstrap(self):
        result = self.verify()
        baseline = self.state(result)
        for raw, message in ((b"{", "not valid UTF-8 JSON"), (b"[]", "must be a JSON object"),
            (b'{"version":1,"version":1}', "duplicate keys"),
            (b'{"version":NaN}', "nonfinite value")):
            with self.subTest(raw=raw), self.assertRaisesRegex(core.WebAuthnTrustError, message):
                core.plan_rollback(result, raw, self.context)
        cases = [(dict(baseline, version=True), "state version is invalid"),
            (dict(baseline, version=2), "state version is invalid"),
            (dict(baseline, extra=1), "state fields are invalid"),
            ({key: value for key, value in baseline.items() if key != "bundle_digest"}, "state fields are invalid"),
            (dict(baseline, bundle_digest="not-a-digest"), "state bundle digest is invalid"),
            (dict(baseline, updated_at="2025-01-01T00:00:00"), "state updated_at must be an aware timestamp")]
        for field in ("sequence", "rollback_epoch"):
            for value in (True, 0, -1, 7.0, "7", 2**63):
                cases.append((dict(baseline, **{field: value}), "positive bounded integer"))
        for state, message in cases:
            with self.subTest(state=state), self.assertRaisesRegex(core.WebAuthnTrustError, message):
                core.plan_rollback(result, canonical(state), self.context)

    def test_forged_frozen_results_are_reverified_before_checkpoint_planning(self):
        result = self.verify()
        for changes in ({"input_digest": digest(b"other")}, {"bundle_digest": digest(b"other")},
            {"canonical_envelope_digest": digest(b"other")}, {"installation_digest": digest(b"other")},
            {"signature_payload_bytes": b"{}"}, {"installation_bytes": b"{}\n"},
            {"sequence": 8}, {"rollback_epoch": 3}, {"verified_at": START},
            {"roots": (replace(result.roots[0], authenticator_class="platform"),)}):
            with self.subTest(changes=changes), self.assertRaisesRegex(core.WebAuthnTrustError,
                "verified bundle does not match retained input"):
                core.plan_rollback(replace(result, **changes), None, self.context)
        with self.assertRaisesRegex(core.WebAuthnTrustError, "verified bundle does not match retained input"):
            core.plan_rollback(result, None, replace(self.context, verified_at=START))

    def test_mutable_and_bool_dataclass_substitutes_are_not_immutable_results(self):
        result = self.verify()
        for changes, message in (({"input_bytes": bytearray(result.input_bytes)}, "input bytes is invalid"),
            ({"roots": list(result.roots)}, "result roots are invalid"),
            ({"sequence": True}, "positive bounded integer"),
            ({"rollback_epoch": True}, "positive bounded integer")):
            with self.subTest(changes=changes), self.assertRaisesRegex(core.WebAuthnTrustError, message):
                replace(result, **changes)
        with self.assertRaisesRegex(core.WebAuthnTrustError, "root AAGUID set is invalid"):
            replace(result.roots[0], aaguids={AAGUID})
        with self.assertRaisesRegex(core.WebAuthnTrustError, "root certificate is invalid"):
            replace(result.roots[0], certificate_der=bytearray(self.certificate_der))

    def test_core_source_does_not_import_stateful_integration_or_read_a_clock(self):
        # Supplemental source boundary only; behavioral cases above call the
        # actual pure core. No AST result is authority or installed evidence.
        source = (ROOT / "catchplate/webauthn_trust_core.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = {"os", "pathlib", "time", "fcntl", "catchplate", "db", "config"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name.split(".")[0], forbidden)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn((node.module or "").split(".")[0], forbidden)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, {"open", "eval", "exec", "__import__"})
                elif isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, {"now", "utcnow", "time_ns", "monotonic_ns",
                        "read_bytes", "read_text", "write_bytes", "write_text"})


if __name__ == "__main__":
    unittest.main()
