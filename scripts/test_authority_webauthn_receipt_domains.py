#!/usr/bin/env python3
"""Real signed synthetic receipts and optional PostgreSQL component controls.

The actual service verifies an ephemeral ES256 assertion and signs its evidence
with Ed25519. Configuration, selected challenge/credential/trust rows and clock
are synthetic: this is NOT hardware trust, a launched authority, full writer
admission, JIT grant production or a migration. PostgreSQL runs the actual
shared predicate inside the complete extracted optional executor guard, using
the actual evidence DDL and wire/digest functions. No engine is started here.

Without --postgres-dsn only pure controls run. With it, pure and PG controls run
together; the external runner owns one disposable PG16/17 Unix-socket engine.
Import requires the existing metadata-bootstrap/dev offline validator mode.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
import uuid
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import authority_service as service
from catchplate import authority_webauthn_assertion as admission
from catchplate.authority_store import authorization_records
from catchplate.authority_store.webauthn_receipt_binding import receipt_evidence_binding_sql
from scripts import test_authority_executor_optional_evidence as source

NOW = 1_790_000_000_000_000_000
RECEIPT_DOMAIN = "catchplate.policyAuthorityWebAuthnReceipt/v1"
VERIFIED_DOMAIN = "catchplate.policyAuthorityVerifiedWebAuthnAssertionReceipt/v1"
EVIDENCE_DOMAIN = "catchplate.policyAuthorityWebAuthnAssertionEvidence/v1"
OPERATION = "webauthn.credential.revoke"
CONNECTION_PARAMETERS = None


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def framed(domain, *parts):
    return sha(domain.encode("ascii") + b"\0" + b"".join(
        len(part).to_bytes(8, "big") + part for part in parts))


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SignedFixture:
    def __init__(self):
        self.raw_key = ec.generate_private_key(ec.SECP256R1())
        self.verifier_key = Ed25519PrivateKey.generate()
        public = self.raw_key.public_key().public_numbers()
        request = sha(b"synthetic exact request")
        operation_id = framed("catchplate.policyAuthorityOperation/v2",
            OPERATION.encode("ascii"), request.encode("ascii"))
        self.challenge = {"operationId": operation_id,
            "challengeId": "synthetic-challenge", "challenge": b64(bytes(range(32))),
            "challengeRowDigest": sha(b"synthetic current challenge row"),
            "rpId": "synthetic.invalid", "origin": "https://synthetic.invalid",
            "issuedAtEpochNs": NOW - 1_000_000_000,
            "expiresAtEpochNs": NOW + 20_000_000_000}
        self.credential = {"credentialRecordId": "synthetic-credential-row",
            "credentialId": b64(b"synthetic credential ID"),
            "credentialBindingDigest": sha(b"synthetic credential binding"),
            "credentialPolicyDigest": sha(b"synthetic credential policy"),
            "trustHighWaterDigest": sha(b"synthetic trust high water"),
            "trustBundleSequence": 7, "rpId": self.challenge["rpId"],
            "origin": self.challenge["origin"], "authenticatorClass": "hardware",
            "attestationTrusted": True, "revoked": False, "signCount": 1,
            "publicKeyCoseBase64Url": b64(cbor2.dumps({1: 2, 3: -7, -1: 1,
                -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}))}
        client = canonical({"type": "webauthn.get", "challenge": self.challenge["challenge"],
            "origin": self.challenge["origin"], "crossOrigin": False})
        auth = hashlib.sha256(b"synthetic.invalid").digest() + b"\x05" + (2).to_bytes(4, "big")
        self.assertion = {"credentialId": self.credential["credentialId"],
            "clientDataJSON": b64(client), "authenticatorData": b64(auth),
            "signature": b64(self.raw_key.sign(auth + hashlib.sha256(client).digest(),
                ec.ECDSA(hashes.SHA256())))}
        # Deliberately NOT a constructed/admitted runtime owner. Only the
        # selected-row boundary is substituted; both cryptographic checks run.
        self.process = object.__new__(service.AuthorityProcess)
        self.process.configuration = service.MeasuredConfiguration(payload={"webauthn": {
            "rpId": "synthetic.invalid", "origin": "https://synthetic.invalid",
            "maximumChallengeAgeNs": 30_000_000_000,
            "allowedAuthenticatorClasses": ["hardware"], "requireAttestationTrusted": True}},
            digest=sha(b"synthetic configuration"), root_key=self.verifier_key.public_key())
        self.process.role_config = {"measurementDigest": sha(b"synthetic measurement"),
            "attestationReceiptDigest": sha(b"synthetic attestation observation")}
        self.process.signing_key = self.verifier_key
        self.arguments = dict(operation=OPERATION, operation_id=operation_id,
            request_digest=request, capability_id=sha(b"synthetic capability"),
            authorization_reference={"fixture": "selected originals only"},
            deadline_epoch_ns=NOW + 10_000_000_000, arguments={})
        self.evidence, self.receipt, self.receipt_digest = self.produce()
        self.row = authorization_records._assertion_storage_row(self.evidence)
        self.capability = {name: self.arguments[name] for name in
            ("operation", "operation_id", "request_digest", "capability_id")}
        self.capability.update(webauthn_receipt_json=canonical(self.receipt).decode("ascii"),
            webauthn_receipt_digest=self.receipt_digest,
            webauthn_trust_high_water_digest=self.credential["trustHighWaterDigest"])

    def produce(self):
        with patch.object(self.process, "_read_webauthn_authority", return_value=(
                self.challenge, self.credential, self.assertion)), patch.object(
                service.time, "time_ns", return_value=NOW):
            return self.process._build_v9_webauthn_evidence(**self.arguments)

    def verify(self, evidence=None, **overrides):
        bindings = dict(operation_id=self.arguments["operation_id"],
            request_digest=self.arguments["request_digest"], capability_id=self.arguments["capability_id"],
            verifier_identity={"sessionIdentityDigest": self.evidence["verifierSessionIdentityDigest"],
                "measurementDigest": self.process.role_config["measurementDigest"],
                "attestationReceiptDigest": self.process.role_config["attestationReceiptDigest"]},
            verifier_public_key=self.verifier_key.public_key(), now_epoch_ns=NOW,
            deadline_epoch_ns=self.arguments["deadline_epoch_ns"], maximum_age_ns=30_000_000_000)
        bindings.update(overrides)
        return admission.verify_revoke_assertion_evidence(
            self.evidence if evidence is None else evidence, **bindings)


class ReceiptDomainPureTests(unittest.TestCase):
    def test_actual_producer_emits_three_distinct_verified_commitments(self):
        fixture = SignedFixture()
        unsigned = {key: value for key, value in fixture.evidence.items() if key not in
            ("verifiedAssertionReceiptDigest", "verifierSignatureBase64url", "verifierSignatureDigest")}
        expected = (framed(RECEIPT_DOMAIN, canonical(fixture.receipt)),
            framed(VERIFIED_DOMAIN, canonical(unsigned)), framed(EVIDENCE_DOMAIN, canonical(fixture.evidence)))
        self.assertEqual(expected, (fixture.receipt_digest,
            fixture.evidence["verifiedAssertionReceiptDigest"], fixture.row["assertion_evidence_digest"]))
        self.assertEqual(len(set(expected)), 3)
        self.assertEqual(dict(fixture.verify()), fixture.evidence)
        fixture.verifier_key.public_key().verify(unb64(fixture.evidence["verifierSignatureBase64url"]),
            expected[1].encode("ascii"))
        self.assertEqual(sha(unb64(fixture.evidence["verifierSignatureBase64url"])),
            fixture.evidence["verifierSignatureDigest"])

    def test_raw_assertion_and_pinned_verifier_tampering_fail_without_success_stubs(self):
        fixture = SignedFixture()
        for section, field, value in (("assertion", "signature", b64(b"not an ES256 signature")),
                ("challenge", "operationId", sha(b"another operation")),
                ("challenge", "expiresAtEpochNs", NOW), ("credential", "signCount", 2)):
            target = getattr(fixture, section)
            with self.subTest(section=section, field=field), patch.dict(target, {field: value}), \
                    self.assertRaises(service.AuthorityServiceError):
                fixture.produce()
        for field, value in (("verifiedAssertionReceiptDigest", fixture.receipt_digest),
                ("verifierSignatureBase64url", b64(bytes(64))),
                ("verifierSignatureDigest", sha(b"wrong signature")),
                ("signatureBase64url", b64(b"changed raw signature")),
                ("verifiedAtEpochNs", NOW + 1)):
            with self.subTest(field=field), self.assertRaises(admission.AssertionEvidenceError):
                fixture.verify({**fixture.evidence, field: value})
        for override in ({"capability_id": sha(b"other")}, {"operation_id": sha(b"other")},
                {"request_digest": sha(b"other")}, {"now_epoch_ns": fixture.evidence["expiresAtEpochNs"]}):
            with self.subTest(override=override), self.assertRaises(admission.AssertionEvidenceError):
                fixture.verify(**override)

    def test_actual_executor_uses_shared_predicate_and_preserves_surrounding_joins(self):
        guard, old = source._guard_parts()
        self.assertIn(receipt_evidence_binding_sql(source.NAMESPACE), guard)
        self.assertIn("evidence.verified_assertion_receipt_digest = capability.webauthn_receipt_digest",
            " ".join(old.split()))
        for term in ("trust_publication.sequence", "computed_trust_high_water_digest",
                "now_epoch_ns < evidence.expires_at_epoch_ns", "evidence.challenge_id",
                "evidence.prior_counter", "evidence.counter", "evidence.credential_policy_digest"):
            self.assertIn(term, " ".join(guard.split()))
        for namespace in (None, "unquoted", '"x";SELECT 1', '"Upper"'):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                receipt_evidence_binding_sql(namespace)


class ReceiptDomainPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("real PostgreSQL controls require --postgres-dsn")
        cls.db = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=True)
        cls.addClassCleanup(cls.db.close)
        version, address = cls.db.execute("SELECT current_setting('server_version_num')::int, inet_server_addr()").fetchone()
        if version // 10000 not in (16, 17) or address is not None:
            raise RuntimeError("component requires PG16/17 over a private Unix socket")
        cls.schema = "receipt_domains_" + uuid.uuid4().hex
        cls.namespace = '"' + cls.schema + '"'
        cls.db.execute(f"CREATE SCHEMA {cls.namespace}")
        cls.addClassCleanup(cls.db.execute, f"DROP SCHEMA {cls.namespace} CASCADE")
        cls.db.execute(f"SET search_path = {cls.namespace}, pg_catalog")
        cls.db.execute(source._actual_table())
        for definition in source._actual_helpers(namespace=cls.namespace):
            cls.db.execute(definition)
        guard, _ = source._guard_parts(namespace=cls.namespace)
        cls.db.execute(f"""CREATE FUNCTION {cls.namespace}.check_evidence(
            cap jsonb, selected text, current_trust text, trust_sequence bigint,
            now_epoch_ns bigint, initialize_trust boolean DEFAULT true) RETURNS void
            LANGUAGE plpgsql SET search_path = pg_catalog AS $guard$
            DECLARE capability record; authorization_projection record; trust_publication record;
                computed_trust_high_water_digest text := current_trust;
            BEGIN
                SELECT * INTO capability FROM jsonb_to_record(cap) AS c(operation text,
                    operation_id text, request_digest text, capability_id text,
                    webauthn_receipt_json text, webauthn_receipt_digest text,
                    webauthn_trust_high_water_digest text);
                SELECT selected AS assertion_evidence_digest INTO authorization_projection;
                IF initialize_trust THEN SELECT trust_sequence AS sequence INTO trust_publication; END IF;
                {guard}
            END; $guard$""")

    def setUp(self):
        self.fixture = SignedFixture()
        self.reset()

    def reset(self, row=None):
        from psycopg import sql
        self.db.execute(f"TRUNCATE {self.namespace}.{source.TABLE}")
        row = self.fixture.row if row is None else row
        query = sql.SQL("INSERT INTO {}.{} ({}) VALUES ({})").format(
            sql.Identifier(self.schema), sql.Identifier(source.TABLE),
            sql.SQL(",").join(map(sql.Identifier, row)), sql.SQL(",").join(sql.Placeholder() for _ in row))
        self.db.execute(query, tuple(row.values()))

    def call(self, capability=None, **overrides):
        from psycopg.types.json import Jsonb
        args = dict(selected=self.fixture.row["assertion_evidence_digest"],
            current_trust=self.fixture.credential["trustHighWaterDigest"], trust_sequence=7,
            now=NOW + 1, initialize=True)
        args.update(overrides)
        self.db.execute(f"SELECT {self.namespace}.check_evidence(%s,%s,%s,%s,%s,%s)",
            (Jsonb(self.fixture.capability if capability is None else capability), *args.values()))

    def reject(self, *, row=None, capability=None, **overrides):
        import psycopg
        self.reset(row)
        # Legacy numeric casts may reject malformed JSON integer fields before
        # the closed-predicate error. Neither result may admit the operation.
        with self.assertRaises((psycopg.errors.RaiseException,
                psycopg.errors.InvalidTextRepresentation)) as refused:
            self.call(capability, **overrides)
        if isinstance(refused.exception, psycopg.errors.RaiseException):
            self.assertIn(source.DENIAL, str(refused.exception))

    def test_genuine_distinct_domains_pass_while_old_equality_is_false(self):
        self.call()
        old_equality = self.db.execute(f"SELECT verified_assertion_receipt_digest = %s "
            f"FROM {self.namespace}.{source.TABLE}", (self.fixture.receipt_digest,)).fetchone()[0]
        self.assertIs(old_equality, False)
        # Optional means truly absent, even with an unassigned trust RECORD.
        self.call(selected=None, initialize=False)

    def test_originals_digests_closed_keys_and_duplicate_keys_are_not_interchangeable(self):
        fixture = self.fixture
        for field in ("webauthn_receipt_digest", "webauthn_receipt_json"):
            bad = sha(b"wrong") if field.endswith("digest") else "{}"
            with self.subTest(capability=field):
                self.reject(capability={**fixture.capability, field: bad})
        for field in ("assertion_evidence_digest", "verified_assertion_receipt_digest", "evidence_json"):
            with self.subTest(evidence=field):
                self.reject(row={**fixture.row, field: "{}" if field == "evidence_json" else sha(b"wrong")})
        for receipt in ({**fixture.receipt, "extra": None},
                {key: value for key, value in fixture.receipt.items() if key != "challengeRowDigest"},
                {**fixture.receipt, "counter": True}, {**fixture.receipt, "verifiedAtEpochNs": NOW + 1}):
            raw = canonical(receipt)
            with self.subTest(receipt=raw):
                self.reject(capability={**fixture.capability, "webauthn_receipt_json": raw.decode(),
                    "webauthn_receipt_digest": framed(RECEIPT_DOMAIN, raw)})
        for duplicate in (False, True):
            raw = canonical(fixture.receipt)
            raw = b'{"schema":"catchplate.policyAuthorityWebAuthnReceipt/v1",' + raw[1:] if duplicate else b" " + raw
            with self.subTest(duplicate=duplicate):
                self.reject(capability={**fixture.capability, "webauthn_receipt_json": raw.decode(),
                    "webauthn_receipt_digest": framed(RECEIPT_DOMAIN, raw)})
        for change in ({"extra": None}, {"verifierSignatureDigest": sha(b"changed")},
                {"verifierSignatureBase64url": b64(bytes(64))}):
            raw = canonical({**fixture.evidence, **change})
            # A changed full signed document does not match the selected
            # assertion-evidence commitment, even if its unsigned body matches.
            self.reject(row={**fixture.row, "evidence_json": raw.decode()})

    def test_every_indexed_scalar_remains_bound_to_signed_original(self):
        for field, value in self.fixture.row.items():
            if field in ("source_revision", "evidence_json", "assertion_evidence_digest",
                    "user_present", "user_verified"):
                continue  # Fixed DDL constraints / separately tested commitments.
            changed = (0 if field == "prior_counter" else value + 1) if type(value) is int else value + "x"
            with self.subTest(field=field):
                self.reject(row={**self.fixture.row, field: changed})

    def test_scope_current_trust_missing_row_and_original_expiry_still_refuse(self):
        for field in ("operation", "operation_id", "request_digest", "capability_id",
                "webauthn_trust_high_water_digest"):
            with self.subTest(field=field):
                self.reject(capability={**self.fixture.capability, field: "different"})
        for changes in ({"trust_sequence": 8}, {"current_trust": sha(b"new current trust")},
                {"now": self.fixture.evidence["expiresAtEpochNs"]}, {"selected": sha(b"missing row")}):
            with self.subTest(changes=changes):
                self.reject(**changes)
        self.reset()
        self.call(now=self.fixture.evidence["expiresAtEpochNs"] - 1)

    def test_valid_other_signed_receipt_cannot_cross_join_original_capability(self):
        other = SignedFixture()
        self.reject(row=other.row, selected=other.row["assertion_evidence_digest"])
        self.reset(other.row)
        self.call(other.capability, selected=other.row["assertion_evidence_digest"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn")
    args = parser.parse_args()
    classes = [ReceiptDomainPureTests]
    if args.postgres_dsn is not None:
        from scripts.test_webauthn_trust_projection_postgres import local_connection_parameters
        CONNECTION_PARAMETERS = local_connection_parameters(args.postgres_dsn)
        classes.append(ReceiptDomainPostgresTests)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
