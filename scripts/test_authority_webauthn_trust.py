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
import re
import sys
from types import MappingProxyType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_webauthn_trust as trust
from catchplate import authority_contract
from catchplate.authority_query_read_work import QueryReadValidationLimits, QueryReadWorkError, _ValidationWork
from catchplate.authority_store import mutation_sql
from catchplate.authority_store import webauthn_trust_sql as trust_sql


DOMAIN = "catchplate.webauthnTrustHighWater/v1"


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
    return {"schema": "catchplate.policyAuthorityCredentialPolicy/v1",
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


def source_tree(relative, maximum_bytes=2 * 1024 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum_bytes:
        raise AssertionError("source fixture input exceeds its explicit bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def source_function(tree, name):
    matches = [node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("source function inventory is not exact")
    return matches[0]


def source_assignment(tree, name):
    matches = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError("source assignment inventory is not exact")
    return matches[0]


def strings(tree):
    return [node.value for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and type(node.value) is str]


def sql_tokens(value):
    # The independently pinned expression contains no whitespace inside SQL
    # string literals. This comparison ignores layout, not SQL value spelling.
    return re.sub(r"\s+", "", value)


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
                         commitment(expected, "catchplate.policyAuthorityCredentialPolicy/v1"))
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
        domain = "catchplate.policyAuthorityCredentialPolicy/v1"
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
        path = ROOT / "catchplate/authority_service.py"
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
        helper = ast.parse((ROOT / "catchplate/authority_webauthn_trust.py").read_text(encoding="utf-8"))
        imports = {node.module for node in helper.body if isinstance(node, ast.ImportFrom)}
        self.assertTrue({"catchplate.authority_service", "catchplate.authority_planner",
                         "catchplate.authority_transition_registry"}.isdisjoint(imports))

    def test_nullable_and_text_aaguid_remain_exact_policy_values_and_commitments(self):
        observed = []
        for value in (None, "", "fixture-aaguid", "雪-aaguid"):
            row = {**credential(), "aaguid": value}
            expected = policy_document(row)
            actual = trust.credential_policy_document(credential=row, high_water=document(),
                trust_high_water_digest=commitment(document()))
            with self.subTest(aaguid=value):
                self.assertEqual(actual, expected)
                self.assertIs(type(actual["aaguid"]), type(value))
                result = trust.credential_policy_digest(actual)
                self.assertEqual(result, commitment(expected, "catchplate.policyAuthorityCredentialPolicy/v1"))
                observed.append(result)
                row["aaguid"] = "caller changed"
                self.assertEqual(actual["aaguid"], value)
        self.assertEqual(len(set(observed)), 4)

    def test_missing_and_nonstring_aaguid_are_not_nullable_validated_row_authority(self):
        high_digest = commitment(document())
        missing = {key: value for key, value in credential().items() if key != "aaguid"}
        for row, expected_hashes in ((missing, 0), *(({**credential(), "aaguid": value}, 1)
                for value in (False, 17, [], {}, b"aaguid", Text("aaguid")))):
            # The constructor hashes the genuine public-key text before its
            # final policy type guard; a missing required row field fails sooner.
            with self.subTest(aaguid=row.get("aaguid", "missing")), \
                    patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(trust.WebAuthnTrustError):
                trust.credential_policy_document(credential=row, high_water=document(),
                    trust_high_water_digest=high_digest)
            self.assertEqual(hashes.call_count, expected_hashes)
        for value in (False, 17, [], {}, b"aaguid", Text("aaguid")):
            changed = {**policy_document(credential()), "aaguid": value}
            with self.subTest(document_aaguid=value), \
                    patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    self.assertRaises(trust.WebAuthnTrustError):
                trust.credential_policy_digest(changed)
            self.assertEqual(hashes.call_count, 0)

    def test_sql_expression_has_exact_sixteen_literal_fields_and_json_aaguid_projection(self):
        expected = (
            ("schema", "'catchplate.policyAuthorityCredentialPolicy/v1'"),
            ("credentialRecordId", "assertion_evidence.credential_record_id"),
            ("credentialId", "assertion_evidence.credential_id"),
            ("userId", "credential_mutation.value->'expectedRow'->>'user_id'"),
            ("authenticatorClass", "credential_mutation.value->'expectedRow'->>'authenticator_class'"),
            ("aaguid", "credential_mutation.value->'expectedRow'->'aaguid'"),
            ("attestationTrusted", "(credential_mutation.value->'expectedRow'->>'attestation_trusted')::bigint = 1"),
            ("attestationLeafDigest", "credential_mutation.value->'expectedRow'->'attestation_leaf_sha256'"),
            ("attestationRootDigest", "credential_mutation.value->'expectedRow'->'attestation_root_sha256'"),
            ("trustBundleDigest", "trust_publication.bundle_digest"),
            ("trustBundleSequence", "trust_publication.sequence"),
            ("trustRollbackEpoch", "trust_publication.rollback_epoch"),
            ("trustHighWaterDigest", "computed_trust_high_water_digest"),
            ("revocationSetDigest", "trust_publication.revocation_set_digest"),
            ("trustWitnessReceiptDigest", "trust_publication.witness_receipt_digest"),
            ("publicKeyDigest", "'sha256:' || pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to("
                "credential_mutation.value->'expectedRow'->>'public_key_cose', 'UTF8')), 'hex')"),
        )
        self.assertEqual(len(expected), 16)
        self.assertEqual({name for name, _ in expected}, set(policy_document(credential())))
        with patch.object(hashlib, "sha256", side_effect=AssertionError("SQL rendering is hash-free")):
            actual = trust_sql.webauthn_credential_policy_sql()
        self.assertEqual(sql_tokens(actual), sql_tokens("pg_catalog.jsonb_build_object("
            + ",".join(f"'{name}', {value}" for name, value in expected) + ")"))
        for arguments in (("caller SQL",), ({"aaguid": "caller projection"},)):
            with self.assertRaises(TypeError):
                trust_sql.webauthn_credential_policy_sql(*arguments)
        _, tree = source_tree("catchplate/authority_store/webauthn_trust_sql.py")
        self.assertEqual([alias.name for node in tree.body if isinstance(node, ast.Import)
            for alias in node.names], ["re", "textwrap"])
        self.assertEqual([node.module for node in tree.body if isinstance(node, ast.ImportFrom)], ["__future__"])

    def test_active_executor_interpolates_the_real_shared_policy_inside_existing_digest_and_cas(self):
        source, tree = source_tree("catchplate/authority_store/executor_v9.py")
        aliases = [alias for node in tree.body if isinstance(node, ast.ImportFrom)
            and node.module == "catchplate.authority_store.webauthn_trust_sql" for alias in node.names]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
            [("locked_webauthn_trust_projection", None), ("webauthn_credential_policy_sql", None)])
        installer = source_function(tree, "install_authority_v9_executor")
        calls = [node for node in ast.walk(installer) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "webauthn_credential_policy_sql"]
        self.assertEqual(len(calls), 1)
        self.assertEqual((calls[0].args, calls[0].keywords), ([], []))
        owners = [node for node in ast.walk(installer) if isinstance(node, ast.JoinedStr)
            and any(isinstance(item, ast.FormattedValue) and item.value is calls[0] for item in node.values)]
        self.assertEqual(len(owners), 1)
        sql = "".join(item.value if isinstance(item, ast.Constant) else "{"
            + ast.unparse(item.value) + "}" for item in owners[0].values)
        active = sql.split("AS $catchplate_execute_v9$", 1)[1].split("$catchplate_execute_v9$;", 1)[0]
        self.assertIn(sql_tokens("catchplate_policy_authority_domain_digest("
            "'catchplate.policyAuthorityCredentialPolicy/v1', {namespace}."
            "catchplate_policy_authority_wire_json({webauthn_credential_policy_sql()})"
            ") = assertion_evidence.credential_policy_digest"), sql_tokens(active))
        self.assertIn("authority v9 WebAuthn CAS mutations are incomplete", active)
        self.assertIn("{apply_mutation_sql(namespace)}", active)
        mutation = mutation_sql.apply_mutation_sql('"catchplate_metadata"')
        self.assertIn("WHERE %s FOR UPDATE", mutation)
        self.assertIn("current_row IS DISTINCT FROM mutation->'expectedRow'", mutation)
        self.assertEqual(source.count("{webauthn_credential_policy_sql()}"), 1)

    def test_legacy_apply_and_begin_are_overridden_by_unconditional_v9_denial(self):
        _, tree = source_tree("catchplate/authority_store/executor_v9.py")
        literals = "\n".join(strings(source_function(tree, "install_authority_v9_executor")))
        for tag, message in (("catchplate_legacy_apply_v9", "legacy authority apply is disabled by schema v9"),
                             ("catchplate_legacy_begin_v9", "legacy controlled writer begin is disabled by schema v9"),
                             ("catchplate_legacy_finish_v9", "legacy controlled writer finish is disabled by schema v9")):
            bodies = re.findall(rf"AS \${tag}\$(.*?)\${tag}\$;", literals, re.DOTALL)
            self.assertEqual(len(bodies), 1)
            self.assertEqual(" ".join(bodies[0].split()), f"BEGIN RAISE EXCEPTION '{message}'; END;")
        source, db_tree = source_tree("catchplate/db.py", 16 * 1024 * 1024)
        calls = [node for node in ast.walk(db_tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "_authority_executor_v9" and node.func.attr == "install_authority_v9_executor"]
        self.assertEqual(len(calls), 1)
        prefix = "\n".join(source.splitlines()[:calls[0].lineno - 1])
        for tag in ("catchplate_owner_apply", "catchplate_begin_controlled_writer", "catchplate_finish_controlled_writer"):
            self.assertIn(f"${tag}$", prefix)

    def test_dormant_challenge_issuer_is_outside_exact_executor_grants(self):
        legacy = "catchplate_policy_authority_issue_webauthn_challenge"
        self.assertNotIn(legacy, {name for name, _, _ in authority_contract.EXECUTOR_FUNCTION_SIGNATURES})
        _, tree = source_tree("catchplate/db.py", 16 * 1024 * 1024)
        inventory = source_assignment(tree, "_POLICY_AUTHORITY_EXECUTOR_FUNCTION_SIGNATURES")
        self.assertIn("authority_contract.EXECUTOR_FUNCTION_SIGNATURES", ast.unparse(inventory))
        self.assertNotIn(legacy, strings(source_assignment(tree, "_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS")))
        seal = source_function(tree, "_seal_postgres_schema_acl")
        statements = [node.args[0] for node in ast.walk(seal) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "execute" and node.args]
        revokes = [node for node in statements if any("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA" in value
            for value in strings(node))]
        self.assertTrue(any("FROM PUBLIC" in value for node in revokes for value in strings(node)))
        for name in ("role_name", "executor_role_name", "verifier_role_name", "planner_writer_role_name"):
            self.assertTrue(any(name in {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
                for node in revokes), name)
        grants = [node for node in statements if any("GRANT EXECUTE ON FUNCTION" in value for value in strings(node))]
        self.assertEqual(len(grants), 3)
        self.assertFalse(any(legacy in value for node in grants for value in strings(node)))
        executor_loops = [node for node in ast.walk(seal) if isinstance(node, ast.For)
            and ast.unparse(node.iter) == "sorted(authority_executor_function_signatures)"]
        self.assertEqual(len(executor_loops), 1)
        executor_grants = [node for node in ast.walk(executor_loops[0]) if node in grants]
        self.assertEqual(len(executor_grants), 1)
        self.assertIn("executor_role_name", ast.unparse(executor_grants[0]))
        self.assertIn("authority_contract.EXECUTOR_ARGUMENT_TYPES", ast.unparse(executor_loops[0]))

    def test_current_service_challenge_producer_and_receipt_require_same_seven_fields(self):
        _, tree = source_tree("catchplate/authority_service.py")
        producer = source_function(tree, "_prepare_webauthn_challenge_writer")
        payload = source_assignment(producer, "challenge_payload")
        self.assertIsInstance(payload, ast.Dict)
        expected = {"schema", "operationId", "rpId", "origin", "issuedAtEpochNs", "expiresAtEpochNs", "credentialId"}
        names = [node.value for node in payload.keys]
        self.assertEqual((len(names), set(names)), (7, expected))
        self.assertEqual(ast.unparse(payload.values[names.index("credentialId")]), "credential_id")
        reader = source_function(tree, "_read_webauthn_authority")
        closures = [node for node in ast.walk(reader) if isinstance(node, ast.Compare)
            and ast.unparse(node.left) == "set(payload)" and len(node.ops) == 1
            and isinstance(node.ops[0], ast.NotEq)]
        self.assertEqual(len(closures), 1)
        self.assertEqual({node.value for node in closures[0].comparators[0].elts}, expected)
        self.assertIn("payload.get('credentialId') != credential_binding['credential_id']", ast.unparse(reader))
        producer_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "_prepare_webauthn_challenge_writer"]
        self.assertEqual(len(producer_calls), 1)
        self.assertFalse(any("catchplate_policy_authority_issue_webauthn_challenge" in value for value in strings(tree)))


if __name__ == "__main__":
    unittest.main()
