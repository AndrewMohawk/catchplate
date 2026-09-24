#!/usr/bin/env python3
"""Independent shared trust commitments; authored and not yet executed.

Fixed synthetic values prove no enrollment, SQL behavior or current root.
The service linkage check reads source and never imports the blocked service.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_webauthn_trust as trust
from serverware.authority_query_read_work import QueryReadValidationLimits, QueryReadWorkError, _ValidationWork


DOMAIN = "serverware.webauthnTrustHighWater/v1"


def document():
    return {"schema": DOMAIN, "rollbackEpoch": 0, "sequence": 7,
        "publicationDigest": "sha256:" + "1" * 64,
        "metadataBlobDigest": "sha256:" + "2" * 64,
        "revocationSetDigest": "sha256:" + "3" * 64,
        "witnessReceiptDigest": "sha256:" + "4" * 64, "witnessSequence": 11}


def wire(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def commitment(value, domain=DOMAIN):
    body = wire(value)
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0"
        + len(body).to_bytes(8, "big") + body).hexdigest()


def metrics(work):
    return work.hash_work, work.input_bytes, work.json_nodes


def credential():
    return {"id": "record-1", "credential_id": "credential-1", "user_id": "operator-1",
        "authenticator_class": "hardware", "aaguid": "fixture-aaguid", "attestation_trusted": 1,
        "attestation_trust_bundle_digest": "sha256:" + "1" * 64,
        "attestation_trust_bundle_sequence": 7, "attestation_leaf_sha256": None,
        "attestation_root_sha256": None, "public_key_cose": "synthetic-key-雪"}


def policy_document(row):
    return {"schema": "serverware.policyAuthorityCredentialPolicy/v1",
        "credentialRecordId": row["id"], "credentialId": row["credential_id"],
        "userId": row["user_id"], "authenticatorClass": row["authenticator_class"],
        "aaguid": row["aaguid"], "attestationTrusted": bool(row["attestation_trusted"]),
        "trustBundleDigest": row["attestation_trust_bundle_digest"],
        "trustBundleSequence": row["attestation_trust_bundle_sequence"],
        "attestationLeafDigest": row["attestation_leaf_sha256"],
        "attestationRootDigest": row["attestation_root_sha256"],
        "trustRollbackEpoch": 0, "trustHighWaterDigest": commitment(document()),
        "revocationSetDigest": "sha256:" + "3" * 64,
        "trustWitnessReceiptDigest": "sha256:" + "4" * 64,
        "publicKeyDigest": "sha256:" + hashlib.sha256(row["public_key_cose"].encode("utf-8")).hexdigest()}


class Text(str):
    pass


class Integer(int):
    pass


class WebAuthnTrustTests(unittest.TestCase):
    def test_document_is_exact_legacy_service_projection_and_detached(self):
        arguments = {"rollback_epoch": 0, "sequence": 7,
            "publication_digest": "sha256:" + "1" * 64,
            "metadata_blob_digest": "sha256:" + "2" * 64,
            "revocation_set_digest": "sha256:" + "3" * 64,
            "witness_receipt_digest": "sha256:" + "4" * 64, "witness_sequence": 11}
        first = trust.high_water_document(**arguments)
        self.assertEqual(first, document())
        first["sequence"] = 99
        self.assertEqual(trust.high_water_document(**arguments), document())

    def test_real_commitment_matches_independent_domain_null_length_framing(self):
        value = document()
        self.assertEqual(trust.high_water_digest(value), commitment(value))
        reversed_value = dict(reversed(tuple(value.items())))
        self.assertEqual(trust.high_water_digest(reversed_value), commitment(value))
        self.assertNotEqual(trust.high_water_digest({**value, "sequence": 8}), commitment(value))

    def test_malformed_closed_graphs_deny_before_any_hash_or_budget_work(self):
        value = document()
        for changed in ({}, {**value, "extra": None}, {k: v for k, v in value.items() if k != "sequence"},
                        MappingProxyType(value), list(value.items()),
                        {**value, "schema": DOMAIN + "x"}, {**value, "schema": Text(DOMAIN)}):
            work = _ValidationWork(QueryReadValidationLimits())
            with self.subTest(value=type(changed).__name__), \
                    patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(trust.WebAuthnTrustError):
                trust.high_water_digest(changed, work=work)
            self.assertEqual((hashes.call_count, metrics(work)), (0, (0, 0, 0)))

    def test_exact_signed64_integer_boundaries_and_boolean_rejection(self):
        for name, minimum in (("rollbackEpoch", 0), ("sequence", 1), ("witnessSequence", 1)):
            for value in (minimum, 2**63 - 1):
                current = {**document(), name: value}
                self.assertEqual(trust.high_water_digest(current), commitment(current))
            for value in (minimum - 1, 2**63, True, Integer(7), "7", None):
                with self.subTest(field=name, value=value), self.assertRaises(trust.WebAuthnTrustError):
                    trust.high_water_digest({**document(), name: value})

    def test_each_digest_requires_exact_canonical_text_without_coercion(self):
        for name in ("publicationDigest", "metadataBlobDigest", "revocationSetDigest", "witnessReceiptDigest"):
            for value in ("sha256:" + "A" * 64, "sha256:" + "0" * 63,
                          Text("sha256:" + "0" * 64), b"sha256:" + b"0" * 64, None):
                with self.subTest(field=name, value=value), self.assertRaises(trust.WebAuthnTrustError):
                    trust.high_water_digest({**document(), name: value})

    def test_actual_meter_matches_independent_pass_schedule_at_exact_limits(self):
        value = document()
        # Eight flat fields: dictionary + eight keys + eight scalar values.
        expected = (1, 3 * len(wire(value)) + 2 * len(DOMAIN) + 9, 2 * 17 + 2)
        work = _ValidationWork(QueryReadValidationLimits(*expected))
        with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
            actual = trust.high_water_digest(value, work=work)
        self.assertEqual(actual, commitment(value))
        self.assertEqual((hashes.call_count, metrics(work)), (1, expected))

    def test_one_less_byte_or_node_fails_without_unmetered_hash(self):
        expected = (1, 3 * len(wire(document())) + 2 * len(DOMAIN) + 9, 36)
        for index in (1, 2):
            limits = list(expected)
            limits[index] -= 1
            work = _ValidationWork(QueryReadValidationLimits(*limits))
            with self.subTest(index=index), patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(QueryReadWorkError):
                trust.high_water_digest(document(), work=work)
            self.assertEqual(hashes.call_count, 0)

    def test_prior_spending_is_not_reset_or_replaced(self):
        prior = (2, 23, 5)
        expected = (1, 3 * len(wire(document())) + 2 * len(DOMAIN) + 9, 36)
        total = tuple(left + right for left, right in zip(prior, expected))
        work = _ValidationWork(QueryReadValidationLimits(*total))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        with patch.object(_ValidationWork, "__init__", side_effect=AssertionError("replacement meter")):
            actual = trust.high_water_digest(document(), work=work)
        self.assertEqual(actual, commitment(document()))
        self.assertEqual(metrics(work), total)
        with self.assertRaises(QueryReadWorkError):
            trust.high_water_digest(document(), work=work)

    def test_wrong_work_carrier_is_not_an_alternate_allowance(self):
        for value in (False, {}, object(), QueryReadValidationLimits()):
            with self.assertRaises(QueryReadWorkError):
                trust.high_water_digest(document(), work=value)

    def test_policy_preserves_all_sixteen_service_fields_and_actual_public_key_hash(self):
        row = credential()
        expected = policy_document(row)
        self.assertEqual(len(expected), 16)
        actual = trust.credential_policy_document(credential=row, high_water=document(),
            trust_high_water_digest=commitment(document()))
        self.assertEqual(actual, expected)
        self.assertEqual(trust.credential_policy_digest(actual),
                         commitment(expected, "serverware.policyAuthorityCredentialPolicy/v1"))
        row["public_key_cose"] = "different-key"
        changed = trust.credential_policy_document(credential=row, high_water=document(),
            trust_high_water_digest=commitment(document()))
        self.assertNotEqual(changed["publicKeyDigest"], actual["publicKeyDigest"])
        self.assertNotEqual(trust.credential_policy_digest(changed), trust.credential_policy_digest(actual))

    def test_policy_constructor_rejects_nonstring_key_without_coercing_it(self):
        for key in (None, b"encoded", Text("encoded"), 123):
            with self.subTest(key=key), patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(trust.WebAuthnTrustError):
                trust.credential_policy_document(credential={**credential(), "public_key_cose": key},
                    high_water=document(), trust_high_water_digest="sha256:" + "0" * 64)
            self.assertEqual(hashes.call_count, 0)

    def test_policy_document_rejects_extra_missing_and_noncanonical_typed_values(self):
        expected = policy_document(credential())
        for changed in ({**expected, "extra": None}, {k: v for k, v in expected.items() if k != "aaguid"},
                        {**expected, "attestationTrusted": 1}, {**expected, "trustBundleSequence": True},
                        {**expected, "publicKeyDigest": "sha256:" + "F" * 64},
                        {**expected, "attestationRootDigest": "not-a-digest"}):
            with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(trust.WebAuthnTrustError):
                trust.credential_policy_digest(changed)
            self.assertEqual(hashes.call_count, 0)

    def test_actual_key_and_policy_share_exact_independent_budget(self):
        row = credential()
        expected = policy_document(row)
        domain = "serverware.policyAuthorityCredentialPolicy/v1"
        high_water = commitment(document())
        units = (2, 3 * len(row["public_key_cose"].encode("utf-8"))
                 + 3 * len(wire(expected)) + 2 * len(domain) + 9, 2 + 2 * 33 + 2)
        work = _ValidationWork(QueryReadValidationLimits(*units))
        with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
            actual = trust.credential_policy_document(credential=row, high_water=document(),
                trust_high_water_digest=high_water, work=work)
            result = trust.credential_policy_digest(actual, work=work)
        self.assertEqual(actual, expected)
        self.assertEqual(result, commitment(expected, domain))
        self.assertEqual((hashes.call_count, metrics(work)), (2, units))
        for index in range(3):
            less = list(units)
            less[index] -= 1
            work = _ValidationWork(QueryReadValidationLimits(*less))
            with self.subTest(index=index), self.assertRaises(QueryReadWorkError):
                actual = trust.credential_policy_document(credential=row, high_water=document(),
                    trust_high_water_digest=high_water, work=work)
                trust.credential_policy_digest(actual, work=work)

    def test_actual_service_calls_shared_worker_without_importing_service(self):
        path = ROOT / "serverware/authority_service.py"
        self.assertLess(path.stat().st_size, 2 * 1024 * 1024)
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "authority_webauthn_trust"]
        self.assertEqual(calls.count("high_water_document"), 1)
        self.assertEqual(calls.count("high_water_digest"), 1)
        self.assertEqual(calls.count("credential_policy_document"), 1)
        self.assertEqual(calls.count("credential_policy_digest"), 1)
        helper = ast.parse((ROOT / "serverware/authority_webauthn_trust.py").read_text(encoding="utf-8"))
        imports = {node.module for node in helper.body if isinstance(node, ast.ImportFrom)}
        self.assertTrue({"serverware.authority_service", "serverware.authority_planner",
                         "serverware.authority_transition_registry"}.isdisjoint(imports))


if __name__ == "__main__":
    unittest.main()
