#!/usr/bin/env python3
"""Historical parser parity; no native provenance or current authorization.

Independent literal creation/rotation fixtures have genuine local Ed25519
signatures and deliberately non-Nitro quote bytes. The public parser delegates,
shared leaf and unchanged historical signature verifiers are exercised. No trust,
database roots, native process, hardware or live custody verifier is admitted.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_network(event, _args):
    if event.startswith("socket."):
        raise AssertionError("historical parser controls forbid sockets and DNS")


if __name__ == "__main__":
    sys.addaudithook(no_network)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_static_credential_custody as creation
from serverware import authority_static_credential_rotation_custody as rotation
from serverware import authority_static_credential_provenance as public
from serverware import static_credential_provenance_values as leaf


NOW = 123_000_000_000
IDENTIFIER = "12345678-1234-4234-8234-123456789abc"
CREATION_SCHEMA = "serverware.staticCredentialCreationProvenance/v1"
ROTATION_SCHEMA = "serverware.staticCredentialRotationProvenance/v1"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def fixture(rotated=False):
    key = Ed25519PrivateKey.from_private_bytes(b"s" * 32)  # Public synthetic key.
    public_key = key.public_key()
    key_id = sha(public_key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    boot = b"b" * 32
    statement = {name: sha(name.encode("ascii")) for name in (
        "controlPlaneResponseSigningKeyId", "controlPlaneConfigurationDigest",
        "intentSha256", "generationSha256", "inputSha256", "policyHash", "dataPlaneBinarySha256",
        "ingressLeafCertificateSha256", "ingressLeafSpkiSha256")}
    statement.update(apiVersion=("serverware.nativeStaticCredentialRotationStatement/v1" if rotated
        else "serverware.nativeStaticCredentialGenerationStatement/v1"),
        operation="credential.static.rotate" if rotated else "credential.static.create",
        holderId=sha(b"serverware/credential-currentness-holder/v1\0" + boot + bytes.fromhex(key_id[7:])),
        bootId=encoded(boot), keyId=key_id, deploymentId="fixture", instanceId="spiffe://fixture/native",
        actorId="oidc:synthetic", credentialId=IDENTIFIER, credentialVersion=2 if rotated else 1,
        secretKekId="attested-memory-kek:" + "a" * 24, generationCreatedAtEpochNs=NOW - 1,
        challenge=encoded(b"c" * 32), intakeOrigin="https://intake.example", portalOrigin="https://portal.example",
        issuedAtEpochNs=NOW, expiresAtEpochNs=NOW + 30_000_000_000)
    if rotated:
        statement.update(previousCredentialVersion=1, **{name: sha(name.encode("ascii")) for name in (
            "previousCredentialSha256", "previousCurrentnessOriginRequestDigest", "previousProvenanceSha256",
            "predecessorBarrierSha256", "predecessorCurrentnessRootSha256")})
    proof = {"statement": statement,
        "signature": "ed25519:" + encoded(key.sign(statement["apiVersion"].encode("ascii") + b"\0" + canonical(statement))),
        "nativeKeyEvidence": {"apiVersion": "serverware.nativeResponseProofKeyEvidence/v1",
            "responseProofPublicKey": encoded(public_key.public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw)), "attestationDocumentB64": encoded(b"synthetic-not-a-Nitro-quote")}}
    return proof


def original(proof, rotated=False):
    return canonical({"apiVersion": ROTATION_SCHEMA if rotated else CREATION_SCHEMA,
        "rotationRequestDigest" if rotated else "creationRequestDigest": sha(b"synthetic original request"),
        "nativeEvidenceOriginal": canonical(proof).decode("ascii")}).decode("ascii")


class StaticHistoricalParserTests(unittest.TestCase):
    def parsers(self, rotated):
        return (leaf.rotation_evidence, rotation.evidence) if rotated else (leaf.creation_evidence, creation.evidence)

    def assert_proof(self, proof, rotated=False):
        before = copy.deepcopy(proof)
        for parser in self.parsers(rotated):
            with self.subTest(parser=parser.__module__):
                self.assertEqual(parser(proof), proof)
        value = original(proof, rotated)
        self.assertEqual(leaf.generation_original(value), public.generation_original(value))
        self.assertEqual(leaf.generation_evidence(value), proof)
        self.assertEqual(public.generation_evidence(value), proof)
        self.assertEqual(leaf.request_digest(leaf.generation_original(value)), sha(b"synthetic original request"))
        if not rotated:
            self.assertEqual(leaf.original(value), public.original(value))
            self.assertEqual(leaf.evidence(value), public.evidence(value))
        self.assertEqual(proof, before)

    def refuse_proof(self, proof, rotated=False):
        for parser in self.parsers(rotated):
            with self.subTest(parser=parser.__module__), self.assertRaises(ValueError):
                parser(proof)
        value = original(proof, rotated)
        for parser in (leaf.generation_original, public.generation_original,
                leaf.generation_evidence, public.generation_evidence):
            with self.subTest(parser=parser.__name__), self.assertRaises(ValueError):
                parser(value)

    def test_independent_creation_rotation_shapes_and_originals_agree(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            self.assert_proof(proof, rotated)
            other = creation.evidence if rotated else rotation.evidence
            with self.assertRaises(ValueError):
                other(proof)
            self.assertEqual(public.request_digest(public.generation_original(original(proof, rotated))),
                sha(b"synthetic original request"))
        maximum = fixture(True)
        maximum["statement"].update(previousCredentialVersion=2**63 - 2, credentialVersion=2**63 - 1)
        self.assert_proof(maximum, True)  # Structural only; changed signature is not verified here.

    def test_closed_fields_at_each_level_preserve_refusal(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            for level in (None, "statement", "nativeKeyEvidence"):
                target = proof if level is None else proof[level]
                for field in (*target, "extra"):
                    value = copy.deepcopy(proof)
                    changed = value if level is None else value[level]
                    if field == "extra":
                        changed[field] = None
                    else:
                        del changed[field]
                    with self.subTest(rotated=rotated, level=level, field=field):
                        self.refuse_proof(value, rotated)

    def test_holder_digest_identity_and_text_type_checks_are_preserved(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            cases = (("holderId", sha(b"wrong holder")), ("keyId", "sha256:" + "A" * 64),
                ("keyId", "sha256:" + "0" * 64), ("bootId", encoded(bytes(32))),
                ("credentialId", IDENTIFIER.upper()), ("credentialId", "not-a-uuid"),
                ("actorId", "application:not-oidc"), ("actorId", "oidc:line\nfeed"),
                ("actorId", "oidc:" + "\u00e9" * 254), ("secretKekId", "attested-memory-kek:" + "A" * 24),
                ("deploymentId", "bad/slash"), ("deploymentId", "x" * 129),
                ("instanceId", "https://not-spiffe.example"), ("instanceId", "spiffe://" + "x" * 4096),
                ("inputSha256", None), ("operation", "credential.static.other"), ("apiVersion", "other"))
            for name, invalid in cases:
                value = copy.deepcopy(proof)
                value["statement"][name] = invalid
                with self.subTest(rotated=rotated, field=name):
                    self.refuse_proof(value, rotated)

    def test_exact_integer_generation_and_epoch_boundaries(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            for name in ("credentialVersion", "generationCreatedAtEpochNs", "issuedAtEpochNs", "expiresAtEpochNs"):
                for invalid in (True, 0, -1, "1", 1.0, 2**63):
                    value = copy.deepcopy(proof)
                    value["statement"][name] = invalid
                    with self.subTest(rotated=rotated, field=name, invalid=invalid):
                        self.refuse_proof(value, rotated)
            for changes in ({"generationCreatedAtEpochNs": NOW + 1}, {"expiresAtEpochNs": NOW},
                    {"expiresAtEpochNs": NOW + 30_000_000_001}):
                value = copy.deepcopy(proof)
                value["statement"].update(changes)
                self.refuse_proof(value, rotated)
        for previous, current in ((True, 2), (0, 1), (1, 1), (1, 3), (2**63 - 1, 2**63)):
            value = fixture(True)
            value["statement"].update(previousCredentialVersion=previous, credentialVersion=current)
            self.refuse_proof(value, True)

    def test_origins_remain_exact_https_separate_and_without_explicit_port(self):
        for rotated in (False, True):
            for invalid in ("http://intake.example", "https://INTAKE.example", "https://intake.example:443",
                    "https://intake.example/", "https://intake.example/path", "https://intake.example?q=1",
                    "https://intake.example#fragment", "https://user@intake.example", " https://intake.example",
                    "https://portal.example"):
                value = fixture(rotated)
                value["statement"]["intakeOrigin"] = invalid
                with self.subTest(rotated=rotated, origin=invalid):
                    self.refuse_proof(value, rotated)

    def test_canonical_unpadded_bytes_and_original_byte_caps(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            for name, invalid in (("challenge", encoded(bytes(32))), ("challenge", encoded(b"c" * 31)),
                    ("challenge", proof["statement"]["challenge"] + "="), ("bootId", "non+url/safe")):
                value = copy.deepcopy(proof)
                value["statement"][name] = invalid
                self.refuse_proof(value, rotated)
            for field, invalid in (("responseProofPublicKey", encoded(bytes(32))),
                    ("responseProofPublicKey", encoded(b"k" * 33)),
                    ("responseProofPublicKey", proof["nativeKeyEvidence"]["responseProofPublicKey"] + "="),
                    ("attestationDocumentB64", ""), ("attestationDocumentB64", encoded(b"q" * (12 * 1024 + 1)))):
                value = copy.deepcopy(proof)
                value["nativeKeyEvidence"][field] = invalid
                self.refuse_proof(value, rotated)
            for invalid in (None, "ed25519:" + encoded(b"s" * 63), proof["signature"] + "=", "rsa:" + encoded(b"s" * 64)):
                self.refuse_proof({**proof, "signature": invalid}, rotated)
            largest_quote = copy.deepcopy(proof)
            largest_quote["nativeKeyEvidence"]["attestationDocumentB64"] = encoded(b"q" * (12 * 1024))
            self.assert_proof(largest_quote, rotated)

    def test_literal_originals_duplicate_keys_nonfinite_nonascii_and_canonical_spacing_refuse(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            value = original(proof, rotated)
            parsed = json.loads(value)
            malformed = [None, value.encode(), "", value + "\n", " " + value,
                value.replace('{', '{"apiVersion":"duplicate",', 1),
                value.replace('{', '{"extra":NaN,', 1),
                canonical({**parsed, "extra": None}).decode(),
                canonical({**parsed, "apiVersion": "other"}).decode(), "x" * (40 * 1024 + 1),
                canonical({**parsed, "nativeEvidenceOriginal": canonical(proof).decode() + "\n"}).decode(),
                canonical({**parsed, "nativeEvidenceOriginal": "\u00e9"}).decode()]
            for index, invalid in enumerate(malformed):
                for parser in (leaf.generation_original, public.generation_original):
                    with self.subTest(rotated=rotated, control=index, parser=parser.__module__), self.assertRaises(ValueError):
                        parser(invalid)
            if rotated:
                for parser in (leaf.original, public.original):
                    with self.assertRaises(ValueError):
                        parser(value)

    def test_real_historical_signature_verifiers_are_not_replaced_by_structural_parsers(self):
        for rotated in (False, True):
            proof = fixture(rotated)
            value = original(proof, rotated)
            self.assertEqual(public.verify_generation_signature(value), proof["statement"])
            if not rotated:
                self.assertEqual(public.verify_native_signature(value), proof["statement"])
            # This remains structurally valid but fails the actual signature;
            # the arbitrary quote bytes were never admitted as Nitro evidence.
            changed = copy.deepcopy(proof)
            changed["signature"] = "ed25519:" + encoded(b"x" * 64)
            self.assert_proof(changed, rotated)
            with self.assertRaises(InvalidSignature):
                public.verify_generation_signature(original(changed, rotated))


if __name__ == "__main__":
    unittest.main(verbosity=2)
