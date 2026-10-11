#!/usr/bin/env python3
"""Actual source-selected reader projection, not PostgreSQL/authority acceptance.

Only the reader's dictionary expressions and actual shared commitment helpers
are evaluated. Synthetic row values are not asserted to be admitted
credentials. No service import, connection, verifier, signer or native action.
The connected fixture separately exercises policy and evidence consumers.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "serverware" / "authority_service.py"


def no_network(event, _args):
    if event.startswith("socket."):
        raise RuntimeError("network is not part of this component test")


sys.addaudithook(no_network)
sys.path.insert(0, str(ROOT))

from serverware import authority_webauthn_bindings


def source_parts(binding="credential"):
    if binding not in {"credential", "challenge"}:
        raise AssertionError("projection fixture is not closed")
    if SOURCE.stat().st_size > 2 * 1024 * 1024:
        raise AssertionError("service source exceeds the explicit fixture bound")
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    owner, = [node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "AuthorityProcess"]
    reader, = [node for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == "_read_webauthn_authority"]
    projection, = [node.value for node in reader.body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
            and target.id == binding for target in node.targets)]
    query_assignment, = [node for node in ast.walk(reader)
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
            and target.id == binding + "_row" for target in node.targets)]
    # Actual cursor.execute's SQL argument, before the outer fetchall() call.
    sql = query_assignment.value.func.value.args[0]
    if not isinstance(projection, ast.Dict):
        raise AssertionError("reader projection inventory changed")
    namespace = {"authority_webauthn_bindings": authority_webauthn_bindings}
    return projection, sql, namespace


def row():
    return {"id": "synthetic-record", "credential_id": "synthetic-wire-id", "user_id": "synthetic-user",
        "public_key_cose": "synthetic-public-key-not-a-verification-fixture", "sign_count": 12,
        "aaguid": "00112233-4455-6677-8899-aabbccddeeff", "authenticator_class": "hardware",
        "attestation_trusted": 1, "attestation_leaf_sha256": None, "attestation_root_sha256": None,
        "attestation_trust_bundle_digest": "sha256:" + "1" * 64,
        "attestation_trust_bundle_sequence": 7, "revoked_at": None}


def project(value):
    expression, _, namespace = source_parts()
    namespace.update(credential_binding=value, credential_policy_digest="sha256:" + "2" * 64,
        trust_high_water_digest="sha256:" + "3" * 64,
        webauthn={"rpId": "synthetic.invalid", "origin": "https://synthetic.invalid"})
    return eval(compile(ast.Expression(expression), str(SOURCE), "eval"), namespace)


def binding_digest(value):
    # Independent oracle for the service's LENGTH-PREFIXED domain framing;
    # this is intentionally not the trust core's domain + NUL framing.
    domain = b"serverware.policyAuthorityWebAuthnCredentialBinding/v1"
    encoded = json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")
    framed = len(domain).to_bytes(8, "big") + domain + len(encoded).to_bytes(8, "big") + encoded
    return "sha256:" + hashlib.sha256(framed).hexdigest()


class WebAuthnReaderProjectionTests(unittest.TestCase):
    def test_query_already_selects_actual_columns_for_both_reference_forms(self):
        _, sql, _ = source_parts()
        expected = ["id", "credential_id", "user_id", "public_key_cose", "sign_count", "aaguid",
            "authenticator_class", "attestation_trusted", "attestation_leaf_sha256", "attestation_root_sha256",
            "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence", "revoked_at"]
        for column in ("id", "credential_id"):
            with self.subTest(column=column):
                value = eval(compile(ast.Expression(sql), str(SOURCE), "eval"), {"credential_column": column})
                selected, remainder = value.removeprefix("SELECT ").split(" FROM ", 1)
                self.assertEqual([part.strip() for part in selected.split(",")], expected)
                self.assertEqual(remainder,
                    "serverware_metadata.webauthn_credentials WHERE " + column + " = %s LIMIT 2")

    def test_exact_projection_carries_row_trust_without_changing_existing_fields(self):
        value = row()
        original = copy.deepcopy(value)
        self.assertEqual(project(value), {
            "credentialRecordId": "synthetic-record", "credentialId": "synthetic-wire-id", "userId": "synthetic-user",
            "publicKeyCoseBase64Url": "synthetic-public-key-not-a-verification-fixture", "signCount": 12,
            "aaguid": "00112233-4455-6677-8899-aabbccddeeff", "authenticatorClass": "hardware",
            "attestationTrusted": True, "trustBundleDigest": "sha256:" + "1" * 64, "trustBundleSequence": 7,
            "credentialPolicyDigest": "sha256:" + "2" * 64, "trustHighWaterDigest": "sha256:" + "3" * 64,
            "credentialBindingDigest": binding_digest(value), "rpId": "synthetic.invalid",
            "origin": "https://synthetic.invalid", "revoked": False})
        self.assertEqual(value, original)

    def test_each_trust_field_tracks_the_row_and_changes_its_existing_binding(self):
        value = row()
        before = project(value)
        for source, destination, changed in (
            ("aaguid", "aaguid", "ffeeddcc-bbaa-9988-7766-554433221100"),
            ("attestation_trust_bundle_digest", "trustBundleDigest", "sha256:" + "4" * 64),
            ("attestation_trust_bundle_sequence", "trustBundleSequence", 23),
        ):
            with self.subTest(source=source):
                current = dict(value, **{source: changed})
                actual = project(current)
                self.assertEqual(actual[destination], changed)
                self.assertEqual(actual["credentialBindingDigest"], binding_digest(current))
                self.assertNotEqual(actual["credentialBindingDigest"], before["credentialBindingDigest"])

    def test_missing_row_fields_have_no_projection_fallback(self):
        for name in ("aaguid", "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence"):
            current = row()
            del current[name]
            with self.subTest(field=name), self.assertRaises(KeyError):
                project(current)

    def test_nullable_aaguid_is_not_invented_and_each_result_is_detached(self):
        value = dict(row(), aaguid=None)
        first, second = project(value), project(value)
        self.assertIsNone(first["aaguid"])
        self.assertIsNot(first, second)
        first["trustBundleSequence"] = 99
        self.assertEqual(second["trustBundleSequence"], value["attestation_trust_bundle_sequence"])
        self.assertEqual(second["credentialBindingDigest"], binding_digest(value))

    def test_actual_challenge_projection_retains_exact_ten_column_null_domain_binding(self):
        expression, sql, namespace = source_parts("challenge")
        fields = ["id", "challenge", "challenge_type", "user_id", "scope_key", "approval_request_id",
            "payload_json", "expires_at", "used_at", "created_at"]
        query = eval(compile(ast.Expression(sql), str(SOURCE), "eval"))
        selected, remainder = query.removeprefix("SELECT ").split(" FROM ", 1)
        self.assertEqual([part.strip() for part in selected.split(",")], fields)
        self.assertEqual(remainder, "serverware_metadata.webauthn_challenges WHERE id = %s LIMIT 2")
        value = {"id": "synthetic-challenge", "challenge": "synthetic-challenge-bytes",
            "challenge_type": "policy_authority", "user_id": "synthetic-user", "scope_key": "synthetic-operation",
            "approval_request_id": None, "payload_json": '{"synthetic":"fixture"}',
            "expires_at": "2026-01-01T00:01:00+00:00", "used_at": None, "created_at": "2026-01-01T00:00:00+00:00"}
        namespace.update(challenge_binding=value, payload=json.loads(value["payload_json"]))
        actual = eval(compile(ast.Expression(expression), str(SOURCE), "eval"), namespace)
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False,
            sort_keys=True, separators=(",", ":")).encode("ascii")
        domain = b"serverware.policyAuthorityWebAuthnChallengeRow/v1"
        expected = "sha256:" + hashlib.sha256(domain + b"\0" + len(encoded).to_bytes(8, "big") + encoded).hexdigest()
        self.assertEqual(actual, {"synthetic": "fixture", "challengeId": value["id"],
            "challenge": value["challenge"], "challengeRowDigest": expected})
        # The retained row can contain non-binding custody fields; no new fields
        # may silently change the reader's historical selected-row commitment.
        self.assertEqual(authority_webauthn_bindings.challenge_row_digest(
            dict(value, synthetic_nonbinding_custody="not a selected column")), expected)
        self.assertNotEqual(authority_webauthn_bindings.challenge_row_digest(
            dict(value, challenge="different-synthetic-challenge")), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
