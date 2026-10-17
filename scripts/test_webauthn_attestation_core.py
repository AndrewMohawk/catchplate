#!/usr/bin/env python3
"""Real local registration-crypto components, not DB/authority/hardware proof.

No registry stubs, credential DB, trust files or ambient clock are needed.
The final source-wiring test does not claim executed live-wrapper coverage.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import sys
import unittest
import uuid
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import webauthn_attestation_core as core


START = datetime(2020, 1, 1, tzinfo=timezone.utc)
END = datetime(2030, 1, 1, tzinfo=timezone.utc)
NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
RP = "registration.example.test"
ORIGIN = "https://registration.example.test"
AAGUID = uuid.UUID("2fc0579f-8113-47ea-b116-bb5a8db9202a").bytes


def certificate(name, key, *, issuer=None, issuer_key=None, ca=False, aaguid=None,
    not_before=START, not_after=END):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder().subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key()).serial_number(100 + len(name))
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if aaguid is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(core.FIDO_AAGUID_EXTENSION, aaguid), critical=False,
        )
    return builder.sign(issuer_key or key, hashes.SHA256())


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class RegistrationAttestationCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_key = ec.derive_private_key(11, ec.SECP256R1())
        cls.intermediate_key = ec.derive_private_key(12, ec.SECP256R1())
        cls.leaf_key = ec.derive_private_key(13, ec.SECP256R1())
        cls.credential_key = ec.derive_private_key(14, ec.SECP256R1())
        cls.root = certificate("root", cls.root_key, ca=True)
        cls.intermediate = certificate("intermediate", cls.intermediate_key,
            issuer=cls.root, issuer_key=cls.root_key, ca=True)
        cls.leaf = certificate("leaf", cls.leaf_key,
            issuer=cls.intermediate, issuer_key=cls.intermediate_key, aaguid=AAGUID)
        root_der = cls.root.public_bytes(serialization.Encoding.DER)
        cls.root_snapshot = core.TrustRootSnapshot(
            root_der, core.sha256_prefixed(root_der), "yubikey",
            frozenset({str(uuid.UUID(bytes=AAGUID))}),
            core.sha256_prefixed(b"fixture signed bundle"), 7, 2,
        )
        cls.scope = core.CeremonyScope("challenge-record", "opaque-challenge", "user:operator", "hardware key",
            b'{"mode":"bootstrap-token","payload_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        cls.context = core.VerificationContext(RP, ORIGIN, NOW, (cls.root_snapshot,))

    def response(self, *, fmt="packed", self_attested=False, uv=True, raw_client=None,
        rp_id=RP, aaguid=AAGUID, leaf=None, leaf_key=None, intermediate=None):
        numbers = self.credential_key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1,
            -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        credential_id = b"credential-id-exact-byte-value"
        auth_data = (hashlib.sha256(rp_id.encode()).digest()
            + bytes([core.UP_FLAG | core.AT_FLAG | (core.UV_FLAG if uv else 0)])
            + (1).to_bytes(4, "big") + aaguid
            + len(credential_id).to_bytes(2, "big") + credential_id + cose)
        if raw_client is None:
            raw_client = json.dumps({"type": "webauthn.create", "challenge": self.scope.challenge,
                "origin": ORIGIN, "crossOrigin": False}, separators=(",", ":")).encode()
        statement = {}
        if fmt in ("packed", "fido-u2f"):
            signer = self.credential_key if self_attested else (leaf_key or self.leaf_key)
            client_hash = hashlib.sha256(raw_client).digest()
            if fmt == "packed":
                signed = auth_data + client_hash
                statement["alg"] = -7
            else:
                signed = (b"\x00" + hashlib.sha256(rp_id.encode()).digest() + client_hash
                    + credential_id + b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))
            statement["sig"] = signer.sign(signed, ec.ECDSA(hashes.SHA256()))
            if not self_attested:
                statement["x5c"] = [cert.public_bytes(serialization.Encoding.DER)
                    for cert in (leaf or self.leaf, intermediate or self.intermediate)]
        raw_attestation = cbor2.dumps({"fmt": fmt, "authData": auth_data, "attStmt": statement})
        return raw_client, raw_attestation, b64(credential_id)

    def parsed(self, response=None, **kwargs):
        return core.parse_registration_data(*(response or self.response()),
            scope=kwargs.pop("scope", self.scope), rp_id=kwargs.pop("rp_id", RP),
            origin=kwargs.pop("origin", ORIGIN), transports=("usb",), **kwargs)

    def verify(self, response=None, context=None, **kwargs):
        return core.verify_registration_attestation(self.parsed(response, **kwargs), context or self.context)

    def test_real_packed_chain_retains_exact_bounded_immutable_result(self):
        response = self.response()
        result = self.verify(response)
        self.assertTrue(result.attestation.trusted)
        self.assertEqual(result.authenticator_class, "yubikey")
        self.assertEqual(result.attestation.trust_path, tuple(core.cert_digest(cert)
            for cert in (self.leaf, self.intermediate, self.root)))
        self.assertEqual(result.attestation.trust_bundle_digest, self.root_snapshot.bundle_digest)
        self.assertEqual(result.attestation.trust_bundle_sequence, 7)
        self.assertEqual(result.attestation.verified_at, NOW.isoformat())
        self.assertEqual(result.sign_count, 1)
        self.assertEqual(result.transports, ("usb",))
        self.assertEqual(result.client_data_sha256, core.sha256_prefixed(response[0]))
        self.assertEqual(result.attestation_object_sha256, core.sha256_prefixed(response[1]))
        self.assertEqual(result.ceremony_scope_sha256, self.scope.commitment())
        self.assertEqual(result.verification_context_sha256, self.context.commitment())
        with self.assertRaises(FrozenInstanceError):
            result.sign_count = 2
        projection = result.attestation.legacy_dict()
        projection["trust_path"].clear()
        self.assertEqual(len(result.attestation.trust_path), 3)

    def test_real_u2f_uses_explicit_rp_and_original_raw_bytes(self):
        response = self.response(fmt="fido-u2f")
        self.assertTrue(self.verify(response).attestation.trusted)
        changed_rp = "different.example.test"
        decoded = cbor2.loads(response[1])
        decoded["authData"] = hashlib.sha256(changed_rp.encode()).digest() + decoded["authData"][32:]
        changed = response[0], cbor2.dumps(decoded), response[2]
        with self.assertRaisesRegex(core.WebAuthnError, "^fido-u2f WebAuthn attestation signature invalid$"):
            self.verify(changed, context=replace(self.context, rp_id=changed_rp), rp_id=changed_rp)

    def test_untrusted_formats_and_ordinary_no_uv_remain_untrusted(self):
        empty = replace(self.context, trust_roots=())
        for fmt, self_attested in (("none", False), ("unrecognized-format", False), ("packed", True)):
            with self.subTest(fmt=fmt):
                parsed = self.parsed(self.response(fmt=fmt, self_attested=self_attested, uv=False))
                self.assertFalse(parsed.needs_trust_roots)
                result = core.verify_registration_attestation(parsed, empty)
                self.assertFalse(result.user_verified)
                self.assertFalse(result.attestation.trusted)
                self.assertEqual(result.authenticator_class, "unknown")
                self.assertEqual(result.attestation.trust_path, ())
                self.assertIsNone(result.attestation.verified_at)
        unknown = self.response(fmt="unknown")
        obj = cbor2.loads(unknown[1]); obj["attStmt"] = "opaque unsupported statement"
        self.assertFalse(self.verify((unknown[0], cbor2.dumps(obj), unknown[2]), context=empty).attestation.trusted)

    def test_original_client_json_representation_is_signed_not_reserialized(self):
        raw = b'{ "origin" : "https://registration.example.test", "challenge":"opaque-challenge", "type":"webauthn.create" }\n'
        response = self.response(raw_client=raw)
        self.assertTrue(self.verify(response).attestation.trusted)
        rewritten = json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode()
        self.assertNotEqual(raw, rewritten)
        with self.assertRaisesRegex(core.WebAuthnError, "^packed WebAuthn attestation signature invalid$"):
            self.verify((rewritten, response[1], response[2]))
        # Outer CBOR serialization is not the authenticator's signed preimage;
        # its exact original bytes nevertheless have their own returned hash.
        recoded = cbor2.dumps(cbor2.loads(response[1]), canonical=True)
        changed = self.verify((raw, recoded, response[2]))
        self.assertEqual(changed.attestation_object_sha256, core.sha256_prefixed(recoded))

    def test_bad_signature_and_internal_chain_fail_without_roots(self):
        empty = replace(self.context, trust_roots=())
        for fmt, self_attested, message in (
            ("packed", False, "packed WebAuthn attestation signature invalid"),
            ("packed", True, "packed self-attestation signature invalid"),
            ("fido-u2f", False, "fido-u2f WebAuthn attestation signature invalid"),
        ):
            response = self.response(fmt=fmt, self_attested=self_attested)
            obj = cbor2.loads(response[1]); obj["attStmt"]["sig"] = b"bad signature"
            with self.subTest(fmt=fmt, self_attested=self_attested), self.assertRaisesRegex(core.WebAuthnError, "^" + message + "$"):
                self.verify((response[0], cbor2.dumps(obj), response[2]), context=empty)
        wrong_key = ec.derive_private_key(99, ec.SECP256R1())
        invalid_leaf = certificate("leaf", self.leaf_key, issuer=self.intermediate,
            issuer_key=wrong_key, aaguid=AAGUID)
        with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn attestation certificate chain signature invalid$"):
            self.verify(self.response(leaf=invalid_leaf), context=empty)

    def test_certificate_time_inclusive_boundaries_use_only_explicit_time(self):
        response = self.response()
        for instant in (START, NOW, END):
            result = self.verify(response, context=replace(self.context, verified_at=instant))
            self.assertEqual(result.attestation.verified_at, instant.isoformat())
        for instant in (START - timedelta(microseconds=1), END + timedelta(microseconds=1)):
            with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn attestation certificate is not currently valid$"):
                self.verify(response, context=replace(self.context, verified_at=instant, trust_roots=()))
        with self.assertRaisesRegex(core.WebAuthnError, "explicit aware UTC"):
            replace(self.context, verified_at=NOW.replace(tzinfo=None))

    def test_root_metadata_aaguid_and_withdrawal_are_explicit_inputs(self):
        response = self.response()
        for roots in ((), (replace(self.root_snapshot, aaguids=frozenset({str(uuid.UUID(int=1))})),)):
            result = self.verify(response, context=replace(self.context, trust_roots=roots))
            self.assertFalse(result.attestation.trusted)
            self.assertEqual(result.authenticator_class, "unknown")
        legacy = replace(self.root_snapshot, bundle_digest=None, bundle_sequence=None, bundle_rollback_epoch=None)
        result = self.verify(response, context=replace(self.context, trust_roots=(legacy,)))
        self.assertTrue(result.attestation.trusted)
        self.assertIsNone(result.attestation.trust_bundle_digest)
        changed = replace(self.root_snapshot, bundle_sequence=8)
        result2 = self.verify(response, context=replace(self.context, trust_roots=(changed,)))
        self.assertEqual(result2.attestation.trust_bundle_sequence, 8)
        self.assertNotEqual(result.verification_context_sha256, result2.verification_context_sha256)
        with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn attestation certificate AAGUID mismatch$"):
            self.verify(self.response(aaguid=uuid.UUID(int=1).bytes))

    def test_chain_structure_root_time_and_chain_bounds_have_specific_guards(self):
        response = self.response()
        self.assertTrue(self.verify(response).attestation.trusted)
        ca_leaf = certificate("leaf", self.leaf_key, issuer=self.intermediate,
            issuer_key=self.intermediate_key, ca=True, aaguid=AAGUID)
        with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn attestation leaf certificate must not be a CA$"):
            self.verify(self.response(leaf=ca_leaf), context=replace(self.context, trust_roots=()))
        non_ca_intermediate = certificate("intermediate", self.intermediate_key,
            issuer=self.root, issuer_key=self.root_key, ca=False)
        with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn attestation intermediate certificate must be a CA$"):
            self.verify(self.response(intermediate=non_ca_intermediate), context=replace(self.context, trust_roots=()))
        # Only the separately supplied anchor has expired; leaf/intermediate
        # and their genuine signatures remain valid at NOW.
        expired_root = certificate("root", self.root_key, ca=True, not_after=NOW - timedelta(seconds=1))
        der = expired_root.public_bytes(serialization.Encoding.DER)
        expired = replace(self.root_snapshot, certificate_der=der, certificate_sha256=core.sha256_prefixed(der))
        with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn attestation certificate is not currently valid$"):
            self.verify(response, context=replace(self.context, trust_roots=(expired,)))
        for chain, message in (
            ([b"x"] * 6, "WebAuthn attestation x5c must be a certificate list"),
            ([b"x" * (core.MAX_ATTESTATION_CERTIFICATE_BYTES + 1)], "WebAuthn attestation x5c contains a non-certificate item"),
        ):
            with self.assertRaisesRegex(core.WebAuthnError, "^" + message + "$"):
                core.certs_from_x5c(chain)

    def test_raw_scope_and_authenticator_denials_precede_result(self):
        baseline = self.response()
        self.assertTrue(self.verify(baseline).attestation.trusted)
        for field, value, message in (
            ("challenge", "other", "registration challenge scope mismatch"),
            ("origin", "https://other.test", "WebAuthn origin mismatch"),
            ("type", "webauthn.get", "unexpected WebAuthn clientDataJSON type webauthn.get"),
            ("crossOrigin", True, "cross-origin WebAuthn assertions are not accepted"),
        ):
            client = json.loads(baseline[0]); client[field] = value
            response = self.response(raw_client=json.dumps(client).encode())
            with self.subTest(field=field), self.assertRaisesRegex(core.WebAuthnError, "^" + message + "$"):
                self.verify(response)
        with self.assertRaisesRegex(core.WebAuthnError, "^WebAuthn RP ID hash mismatch$"):
            self.verify(self.response(rp_id="other.test"))
        with self.assertRaisesRegex(core.WebAuthnError, "does not match attested credential id"):
            self.verify((baseline[0], baseline[1], b64(b"other")))
        for flag, message in ((core.UP_FLAG, "authenticator user presence flag missing"),
            (core.AT_FLAG, "registration missing attested credential data")):
            obj = cbor2.loads(baseline[1]); data = bytearray(obj["authData"]); data[32] &= ~flag; obj["authData"] = bytes(data)
            with self.assertRaisesRegex(core.WebAuthnError, "^" + message + "$"):
                self.verify((baseline[0], cbor2.dumps(obj), baseline[2]))

    def test_derived_projection_cannot_splice_values_types_or_mutable_buffers(self):
        parsed = self.parsed()
        self.assertTrue(core.verify_registration_attestation(parsed, self.context).attestation.trusted)
        changes = {
            "sign_count": (2, True), "user_verified": (False, 1),
            "needs_trust_roots": (False, 1),
            "public_key_cose": (b"other", bytearray(parsed.public_key_cose)),
            "auth_data": (bytearray(parsed.auth_data),),
            "credential_id_raw": (bytearray(parsed.credential_id_raw),),
            "aaguid_raw": (bytearray(parsed.aaguid_raw),),
        }
        for field, values in changes.items():
            for value in values:
                with self.subTest(field=field, value_type=type(value).__name__), self.assertRaisesRegex(
                    core.WebAuthnError, "^WebAuthn parsed registration binding changed$"
                ):
                    core.verify_registration_attestation(replace(parsed, **{field: value}), self.context)

    def test_context_commitments_do_not_claim_database_authority(self):
        response = self.response()
        baseline = self.verify(response)
        for change in ({"user_id": "other-user"}, {"label": "other label"},
            {"challenge_id": "other-record"}, {"authorization_json": b'{"mode":"other"}'}):
            # User/label/authorization provenance belongs to live DB admission;
            # a local core result only commits the exact supplied context.
            result = self.verify(response, scope=replace(self.scope, **change))
            self.assertNotEqual(baseline.ceremony_scope_sha256, result.ceremony_scope_sha256)
        self.assertFalse(hasattr(baseline, "signature"))
        self.assertFalse(hasattr(baseline, "evidence_digest"))

    def test_bounds_and_malformed_inputs_are_fail_closed(self):
        response = self.response()
        for client, attestation in ((b" " * (core.MAX_CLIENT_DATA_JSON_BYTES + 1), response[1]),
            (response[0], b"x" * (core.MAX_ATTESTATION_OBJECT_BYTES + 1)),
            (b"[]", response[1]), (response[0], cbor2.dumps([]))):
            with self.assertRaises(core.WebAuthnError):
                self.verify((client, attestation, response[2]))
        obj = cbor2.loads(response[1]); obj["authData"] = obj["authData"][:54]
        with self.assertRaisesRegex(core.WebAuthnError, "^registration authenticator data is truncated$"):
            self.verify((response[0], cbor2.dumps(obj), response[2]))
        for field, value in (("trust_roots", [self.root_snapshot]),
            ("trust_roots", (self.root_snapshot,) * (core.MAX_TRUST_ROOTS + 1))):
            with self.assertRaisesRegex(core.WebAuthnError, "trust snapshot is invalid or oversized"):
                replace(self.context, **{field: value})
        with self.assertRaisesRegex(core.WebAuthnError, "certificate digest mismatch"):
            replace(self.root_snapshot, certificate_sha256=core.sha256_prefixed(b"wrong"))
        with self.assertRaisesRegex(core.WebAuthnError, "AAGUID set is invalid or oversized"):
            replace(self.root_snapshot, aaguids=set())
        with self.assertRaisesRegex(core.WebAuthnError, "authorization context.*oversized"):
            replace(self.scope, authorization_json=b"x" * (core.MAX_AUTHORIZATION_BYTES + 1))
        with self.assertRaisesRegex(core.WebAuthnError, "transports are invalid or oversized"):
            core.parse_registration_data(*response, scope=self.scope, rp_id=RP, origin=ORIGIN, transports=("usb",) * 17)

    def test_compatibility_projection_keeps_recovery_stable_across_time(self):
        response = self.response()
        parsed = self.parsed(response)
        obj = cbor2.loads(response[1])
        projections = []
        for instant in (NOW, NOW + timedelta(seconds=1)):
            result = core.verify_attestation_statement(obj, parsed.auth_data, parsed.client_data_json,
                parsed.aaguid_raw, parsed.credential_id_raw, parsed.public_key_cose,
                context=replace(self.context, verified_at=instant)).legacy_dict()
            self.assertEqual(result.pop("verified_at"), instant.isoformat())
            projections.append(result)
        self.assertEqual(projections[0], projections[1])

    def test_source_wiring_preserves_live_guards_and_validate_before_stateful_load(self):
        # Static wiring only. Do not import the blocked DB/registry and do not
        # replace authority checks with stubs to manufacture an enrollment.
        root = Path(__file__).resolve().parents[1]
        pure_source = (root / "catchplate/webauthn_attestation_core.py").read_text()
        pure_tree = ast.parse(pure_source)
        imported = {node.module for node in ast.walk(pure_tree) if isinstance(node, ast.ImportFrom)}
        self.assertFalse(any(name and name.startswith("catchplate") for name in imported))
        self.assertNotIn("datetime.now(", pure_source)
        self.assertNotIn("open(", pure_source)
        live_source = (root / "catchplate/webauthn.py").read_text()
        functions = {node.name: node for node in ast.parse(live_source).body if isinstance(node, ast.FunctionDef)}
        registration = ast.get_source_segment(live_source, functions["verify_registration"])
        self.assertEqual([node.id for node in functions["verify_registration"].decorator_list], ["trust_read_locked"])
        markers = ("challenge = db.get_unused_webauthn_challenge(", "if expected_authorization is not None:",
            "parsed = attestation_core.parse_registration_data(", "if db.get_webauthn_credential(",
            "verified = _verify_with_live_trust(", "finalized = db.finalize_webauthn_registration(")
        positions = [registration.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("parsed.credential_id, include_revoked=True", registration)
        self.assertIn("authorization.get(field) != expected_value", registration)
        self.assertIn("if finalized is None:", registration)
        helper = ast.get_source_segment(live_source, functions["_verify_with_live_trust"])
        self.assertLess(helper.index("needs_roots=False"), helper.index("if not needs_roots:"))
        self.assertLess(helper.index("if not needs_roots:"), helper.index("needs_roots=True"))
        self.assertEqual(helper.count("datetime.now("), 1)
        self.assertEqual(helper.count("verified_at=verified_at"), 2)
        for name in ("_verify_x5c_chain", "_verify_packed_attestation", "_verify_fido_u2f_attestation", "_verify_attestation_statement"):
            body = ast.get_source_segment(live_source, functions[name])
            self.assertIn("_verify_with_live_trust(", body)
        recovery = ast.get_source_segment(live_source, functions["_verify_recovery_registration_candidate"])
        self.assertIn('if not parsed["user_verified"]:', recovery)
        self.assertIn("_verify_attestation_statement(", recovery)
        self.assertNotIn('attestation_result["verified_at"]', recovery)


if __name__ == "__main__":
    unittest.main()
