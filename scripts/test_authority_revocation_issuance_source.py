#!/usr/bin/env python3
"""Source-linked private issuer contracts, not native admission evidence.

Only registry-free contracts and the real inert SQL renderer are imported.
Rendering/AST inspection does not execute SQL, establish grants or mTLS, admit
an issuer connection, verify a signature, or activate a public v4 executor.
Genuine crypto and the admitted-connection statement model live separately in
test_authority_revocation_issuance.py; neither fixture substitutes for the
future actual PostgreSQL role/TLS/transaction integration lane.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import sys
from types import MappingProxyType
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract
from catchplate.authority_store import revocation_capability_sql as renderer


LOAD = "catchplate_policy_authority_load_revocation_issuance"
ISSUE = "catchplate_policy_authority_issue_revocation_capability"
SIGNATURES = {LOAD: ("text",) * 6, ISSUE: ("text",) * 8}
ISSUER_ARGUMENTS = ("supplied_issuer_measurement_digest", "supplied_issuer_attestation_receipt_digest",
    "supplied_issuer_credential_issuance_digest")
ARGUMENTS = {LOAD: ("supplied_planner_transaction_id", "supplied_execution_envelope_id",
    "supplied_capability_id", *ISSUER_ARGUMENTS), ISSUE: ("supplied_original_capability_base64url",
    "supplied_original_witness_request_base64url", "supplied_capability_record_digest",
    "supplied_signer_key_digest", "supplied_witness_key_digest", *ISSUER_ARGUMENTS)}
NAMESPACE = "fixture_metadata"
SQL_NAMESPACE = '"fixture_metadata"'
CONFIGURATION = {"issuer_role": "fixture_issuer", "owner_role": "fixture_owner",
    "issuer_measurement_digest": "sha256:" + "1" * 64,
    "issuer_attestation_receipt_digest": "sha256:" + "2" * 64,
    "issuer_credential_issuance_digest": "sha256:" + "3" * 64,
    "issuer_tls_client_dn": "CN=fixture-issuer", "issuer_tls_client_serial": "17",
    "issuer_tls_issuer_dn": "CN=fixture-issuer-ca"}


def read_source(relative, maximum=2 * 1024 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("issuance source exceeds its explicit inspection bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def named(tree, name):
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("issuance function is not unique: " + name)
    return matches[0]


def assignment(tree, name):
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError("issuance assignment is not unique: " + name)
    return matches[0]


def calls(tree, expression):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == expression), key=lambda node: (node.lineno, node.col_offset))


def compact(value):
    return " ".join(value.split())


class RevocationIssuanceSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql_source, cls.sql_tree = read_source("catchplate/authority_store/revocation_capability_sql.py")
        cls.owner_source, cls.owner_tree = read_source("catchplate/authority_store/revocation_capability.py")
        cls.db_source, cls.db_tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        cls.schema_source, cls.schema_tree = read_source("catchplate/authority_store/schema.py")
        cls.executor_source, cls.executor_tree = read_source("catchplate/authority_store/executor_v9.py")
        cls.service_source, cls.service_tree = read_source("catchplate/authority_service.py")
        cls.sql = renderer.revocation_capability_functions_sql(SQL_NAMESPACE, **CONFIGURATION)
        cls.functions = {}
        for name in (LOAD, ISSUE):
            matches = re.findall(r"CREATE OR REPLACE FUNCTION " + re.escape(SQL_NAMESPACE) + r"\." + name
                + r"\((.*?)\)\s*RETURNS pg_catalog\.jsonb LANGUAGE plpgsql SECURITY DEFINER VOLATILE"
                + r"\s*SET search_path = pg_catalog, " + re.escape(SQL_NAMESPACE) + r", pg_temp"
                + r"\s*AS \$catchplate_revocation_issuer\$(.*?)\$catchplate_revocation_issuer\$;",
                cls.sql, re.S)
            if len(matches) != 1:
                raise AssertionError("actual rendered issuer definition is not unique: " + name)
            # The actual renderer accepts only a quoted identifier. Normalize
            # this one fixed fixture namespace for the body substring checks;
            # the definition/search-path regex above pins its quoted spelling.
            arguments, body = matches[0]
            cls.functions[name] = (arguments, body.replace(SQL_NAMESPACE, NAMESPACE))

    def assert_shape(self, actual, expression):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expression.strip() + ")", mode="eval").body))

    def test_exact_six_and_eight_signature_maps_match_actual_rendered_arguments(self):
        self.assertIs(type(authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES), MappingProxyType)
        self.assertIs(type(authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_ARGUMENTS), MappingProxyType)
        self.assertEqual(dict(authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES), SIGNATURES)
        self.assertEqual(dict(authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_ARGUMENTS), ARGUMENTS)
        self.assertFalse(set(SIGNATURES) & set(authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES))
        for name, (arguments, _body) in self.functions.items():
            self.assertEqual(tuple(tuple(argument.strip().split()) for argument in arguments.split(",")),
                tuple(zip(ARGUMENTS[name], SIGNATURES[name])))
        self.assertEqual(self.sql.count("CREATE OR REPLACE FUNCTION"), 2)
        self.assertNotRegex(self.sql, r"\b(?:GRANT|COMMIT|ROLLBACK|SET ROLE)\b")
        with self.assertRaises(TypeError):
            authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES["caller_overload"] = ("text",)

    def test_renderer_rejects_unbounded_or_interpolated_configuration(self):
        for name, value in (("issuer_role", "issuer; DROP ROLE owner"), ("owner_role", CONFIGURATION["issuer_role"]),
                ("issuer_measurement_digest", "sha256:short"), ("issuer_tls_client_dn", "a\x00b"),
                ("issuer_tls_issuer_dn", "x" * 4097), ("issuer_tls_client_serial", "not a serial")):
            with self.subTest(field=name), self.assertRaises(ValueError):
                renderer.revocation_capability_functions_sql(SQL_NAMESPACE, **{**CONFIGURATION, name: value})
        for namespace in (None, "public; SELECT 1"):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                renderer.revocation_capability_functions_sql(namespace, **CONFIGURATION)
        quoted = renderer.revocation_capability_functions_sql(SQL_NAMESPACE,
            **{**CONFIGURATION, "issuer_tls_client_dn": "CN=issuer's fixture"})
        self.assertIn("'CN=issuer''s fixture'", quoted)

    def test_both_functions_repeat_exact_transaction_role_tls_and_timeout_admission(self):
        self.assertEqual((renderer.POSTGRES_MAJOR, renderer.LOCK_TIMEOUT, renderer.STATEMENT_TIMEOUT), (16, "500ms", "5s"))
        for name, (_arguments, source) in self.functions.items():
            body = compact(source)
            for clause in ("set_config('lock_timeout', '500ms', TRUE)",
                    "set_config('statement_timeout', '5s', TRUE)",
                    "session_user IS DISTINCT FROM 'fixture_issuer'", "current_user IS DISTINCT FROM 'fixture_owner'",
                    "current_setting('server_version_num')::integer / 10000 <> 16",
                    "current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'",
                    "current_setting('transaction_read_only') IS DISTINCT FROM 'off'",
                    "current_setting('transaction_deferrable') IS DISTINCT FROM 'off'",
                    "FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()",
                    "rvi_tls_active IS DISTINCT FROM TRUE", "rvi_tls_dn IS DISTINCT FROM 'CN=fixture-issuer'",
                    "rvi_tls_serial IS DISTINCT FROM '17'", "rvi_tls_issuer IS DISTINCT FROM 'CN=fixture-issuer-ca'"):
                self.assertIn(clause, body, (name, clause))
            for argument, pin in zip(ISSUER_ARGUMENTS, ("1", "2", "3")):
                self.assertIn(argument + " IS DISTINCT FROM 'sha256:" + pin * 64 + "'", body)
            self.assertLess(body.index("revocation issuer identity is not pinned"), body.index("SELECT * INTO STRICT fence_row"))
            self.assertIn("'catchplate.policyAuthorityCapabilityIssuerSession/v1', session_user, rvi_tls_dn, rvi_tls_serial, rvi_tls_issuer", body)

    def test_lock_order_uses_actual_fence_table_and_original_unused_parent_envelope(self):
        self.assertNotIn("policy_authority_replay_fences", self.sql)
        for name, (_arguments, source) in self.functions.items():
            body = compact(source)
            anchors = ("SELECT * INTO STRICT fence_row FROM fixture_metadata.policy_authority_fence_heads",
                "SELECT * INTO capability_row FROM fixture_metadata.policy_authority_writer_capabilities",
                "SELECT * INTO STRICT planner FROM fixture_metadata.policy_authority_planner_transactions",
                "SELECT * INTO STRICT execution_row FROM fixture_metadata.policy_authority_execution_envelopes")
            positions = [body.index(anchor) for anchor in anchors]
            self.assertEqual(positions, sorted(positions), name)
            self.assertIn("WHERE capability_id = rvi_capability_id FOR UPDATE NOWAIT", body)
            self.assertIn("WHERE authority_scope = 'controlled-writer' FOR UPDATE", body)
            for clause in ("planner.status IS DISTINCT FROM 'planned'", "planner.plan_protocol IS DISTINCT FROM 'revocation-v4'",
                    "execution_row.status IS DISTINCT FROM 'reserved'", "execution_row.purpose IS DISTINCT FROM 'execute-v9'",
                    "execution_row.parent_envelope_id IS DISTINCT FROM rvi_planner_id",
                    "capability_row.status IS DISTINCT FROM 'issued'", "capability_row.capability_record_digest IS NULL"):
                self.assertIn(clause, body)
            self.assertLess(body.index("revocation issuer execution reservation changed"), body.index("rv_retained" , body.index(anchors[-1]) + len(anchors[-1])))
            self.assertIn("rvi_now >= planner.deadline_epoch_ns", body)

    def test_actual_load_projects_closed_eight_rows_and_preserves_optional_prior_witness(self):
        function = named(self.sql_tree, "revocation_capability_functions_sql")
        projection = assignment(function, "projections").value
        self.assertIsInstance(projection, ast.Dict)
        self.assertEqual(tuple(key.value for key in projection.keys), (
            "planner", "retainedPlan", "execution", "assertion", "projection", "capability", "retainedCapability", "witness"))
        source = compact(self.functions[LOAD][1])
        self.assertIn("rvi_capability_present IS DISTINCT FROM rvi_retained_present", source)
        self.assertIn("IF rvi_capability_present AND (NOT rvi_witness_present", source)
        self.assertIn("ORDER BY witness_sequence LIMIT 2", source)
        self.assertIn("preliminary witness custody is ambiguous", source)
        self.assertNotIn("INSERT INTO", source)
        self.assertNotIn("UPDATE fixture_metadata.policy_authority_fence_heads", source)
        for name, flag in (("capability", "rvi_capability_present"),
                ("retainedCapability", "rvi_retained_present"), ("witness", "rvi_witness_present")):
            self.assertIn("'" + name + "', CASE WHEN " + flag + " THEN", source)
        authorization = ast.get_source_segment(self.sql_source, named(self.sql_tree, "_authorization"))
        self.assertNotIn("FOR UPDATE", authorization)
        self.assertNotIn("INSERT INTO", authorization)

    def test_original_transports_have_local_bounds_canonical_roundtrips_and_real_wire_walks(self):
        source = compact(self.functions[ISSUE][1])
        for prefix, maximum in (("rvi_envelope", 4 * 1024 * 1024), ("rvi_request", 64 * 1024)):
            self.assertIn("octet_length(" + prefix + "_bytes) NOT BETWEEN 2 AND " + str(maximum), source)
            self.assertIn("convert_to(rvi_canonical, 'UTF8') IS DISTINCT FROM " + prefix + "_bytes", source)
            self.assertIn("catchplate_policy_authority_wire_walk( " + prefix + ", 16, 4096, " + str(maximum) + ", FALSE)", source)
            self.assertIn("catchplate_policy_authority_wire_walk( " + prefix + ", 16, rv_measured.visited_nodes, rv_measured.emitted_bytes, TRUE)", source)
        self.assertEqual(source.count("revocation issuer signature transport is not exact"), 3)
        for literal in ("original transport is not ASCII", "original JSON is not canonical",
                "original transport is not exact", "revocation issuer original execution bytes changed"):
            self.assertIn(literal, source)
        self.assertIn("'exact_capability_base64url', supplied_original_capability_base64url", source)
        self.assertIn("'exact_witness_request_base64url', supplied_original_witness_request_base64url", source)
        self.assertNotRegex(source.lower(), r"ed25519|verify_signature|signature_verify")

    def test_full_record_header_receipt_and_original_row_commitments_precede_every_insert(self):
        storage = named(self.sql_tree, "_storage")
        header = assignment(storage, "header").value
        self.assertEqual(tuple(key.value for key in header.keys), ("schema", "sourceRevision", "capabilityProtocol",
            "capabilityId", "plannerTransactionId", "executionEnvelopeId", "retainedRecordDigest", "rootTransitionDigest",
            "authoritySnapshotDigest", "exactRequestBytesDigest", "capabilityDigest", "signerKeyDigest", "witnessKeyDigest",
            "envelopeDigest", "envelopeByteCount", "witnessRequestBytesDigest", "witnessRequestByteCount"))
        source = compact(self.functions[ISSUE][1])
        self.assertIn("catchplate_policy_authority_framed_digest('catchplate.policyAuthorityWebAuthnCredentialBinding/v1', rvi_webauthn_text)", source)
        self.assertIn("'catchplate.policyAuthorityWebAuthnChallengeRow/v1', rvi_canonical", source)
        self.assertIn("WHERE value->>'table' = 'webauthn_credentials'", source)
        self.assertIn("'aaguid', rvi_credential->'aaguid'", source)
        for anchor in ("revocation issuer capability payload binding changed",
                "rvi_record_digest IS DISTINCT FROM supplied_capability_record_digest",
                "revocation issuer existing witness is not exact"):
            self.assertLess(source.index(anchor), source.index("INSERT INTO"))
        self.assertIn("'recorded_at_epoch_ns', rvi_receipt->'issuedAtEpochNs'", source)
        self.assertIn("'signerKeyDigest', supplied_signer_key_digest", source)
        self.assertIn("'witnessKeyDigest', supplied_witness_key_digest", source)

    def test_retry_is_comparison_only_and_new_custody_advances_exact_fence_before_readback(self):
        source = compact(ast.get_source_segment(self.sql_source, named(self.sql_tree, "_storage")))
        retry = source.split("IF rvi_capability_present THEN", 1)[1].split("ELSE", 1)[0]
        self.assertIn("retry changed original capability custody", retry)
        self.assertNotIn("INSERT INTO", retry)
        self.assertNotIn("UPDATE", retry)
        actual = compact(self.functions[ISSUE][1])
        order = ("IF NOT rvi_witness_present THEN", "INSERT INTO fixture_metadata.policy_authority_external_witness_receipts",
            "INSERT INTO fixture_metadata.policy_authority_revocation_retained_capabilities",
            "INSERT INTO fixture_metadata.policy_authority_writer_capabilities",
            "UPDATE fixture_metadata.policy_authority_fence_heads", "GET DIAGNOSTICS rvi_count = ROW_COUNT",
            "revocation issuer replay fence did not advance", "SELECT * INTO STRICT capability_row")
        positions = [actual.index(anchor) for anchor in order]
        self.assertEqual(positions, sorted(positions))
        for clause in ("fence = fence_row.fence", "witness_sequence = fence_row.witness_sequence",
                "witness_head_digest = fence_row.witness_head_digest", "fence < planner.fence",
                "witness_sequence < (rvi_receipt->>'sequence')::bigint", "updated_at_epoch_ns <= planner.reserved_at_epoch_ns"):
            self.assertIn(clause, actual)
        self.assertLess(actual.index("revocation issuer inserted custody changed"), actual.rindex("reservation deadline expired"))
        self.assertLess(actual.rindex("reservation deadline expired"), actual.rindex("RETURN pg_catalog.jsonb_build_object"))

    def test_actual_installer_uses_validated_pins_after_executor_and_checks_fixed_limits(self):
        installer = named(self.db_tree, "_install_policy_candidate_authority_guards")
        rendered = calls(installer, "_revocation_capability_sql.revocation_capability_functions_sql")
        executor = calls(installer, "_authority_executor_v9.install_authority_v9_executor")
        self.assertEqual((len(rendered), len(executor)), (1, 1))
        self.assertLess(executor[0].lineno, rendered[0].lineno)
        self.assert_shape(rendered[0], """_revocation_capability_sql.revocation_capability_functions_sql(
            guard_namespace, issuer_role=_METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE,
            owner_role=_METADATA_STORE_AUTHORITY_OWNER_ROLE,
            issuer_measurement_digest=capability_issuer_measurement_digest,
            issuer_attestation_receipt_digest=capability_issuer_attestation_receipt_digest,
            issuer_credential_issuance_digest=capability_issuer_credential_issuance_digest,
            issuer_tls_client_dn=capability_issuer_tls_client_dn,
            issuer_tls_client_serial=capability_issuer_tls_client_serial,
            issuer_tls_issuer_dn=capability_issuer_tls_issuer_dn)""")
        checks = [node for node in ast.walk(installer) if isinstance(node, ast.If)
            and "_revocation_capability_sql.POSTGRES_MAJOR" in ast.unparse(node.test)]
        self.assertEqual(len(checks), 1)
        self.assertLess(checks[0].lineno, rendered[0].lineno)
        self.assert_shape(checks[0].test, """_revocation_capability_sql.POSTGRES_MAJOR != _POLICY_AUTHORITY_OWNER_POSTGRES_MAJOR
            or _revocation_capability_sql.LOCK_TIMEOUT != _POLICY_AUTHORITY_OWNER_LOCK_TIMEOUT
            or _revocation_capability_sql.STATEMENT_TIMEOUT != _POLICY_AUTHORITY_OWNER_STATEMENT_TIMEOUT""")
        executed = [node for node in calls(installer, "conn.execute") if rendered[0] in tuple(ast.walk(node))]
        self.assertEqual(len(executed), 1)
        pg = [node for node in ast.walk(installer) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "isinstance(conn, PostgresMetadataConnection)"
            and rendered[0] in tuple(ast.walk(node))]
        self.assertEqual(len(pg), 1)

    def test_signature_union_drives_actual_grants_and_source_contract_without_table_authority(self):
        signature = assignment(self.db_tree, "_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES")
        self.assert_shape(signature.value, """tuple((function_name, tuple(argument_types)) for function_name, argument_types
            in sorted({**authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES,
                **authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES}.items()))""")
        digest = named(self.schema_tree, "_policy_candidate_authority_source_contract_digest")
        for name, suffix in (("issuer_signatures", "SIGNATURES"), ("issuer_arguments", "ARGUMENTS")):
            self.assert_shape(assignment(digest, name).value,
                "{**authority_contract.CAPABILITY_ISSUER_FUNCTION_" + suffix
                + ", **authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_" + suffix + "}")
        digest_source = compact(ast.get_source_segment(self.schema_source, digest))
        self.assertIn("set(authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES) & set(authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES)", digest_source)
        self.assertIn("sorted(issuer_arguments.items())", digest_source)
        sealer = named(self.db_tree, "_seal_postgres_schema_acl")
        sealer_source = ast.get_source_segment(self.db_source, sealer)
        self.assertIn("issuer_function_identities", sealer_source)
        self.assertIn("GRANT EXECUTE ON FUNCTION", sealer_source)
        self.assertIn("oidvectortypes", sealer_source)
        self.assertIn('grant["is_grantable"] is False', sealer_source)
        self.assertNotIn("REVOCATION_CAPABILITY", ast.get_source_segment(self.db_source,
            assignment(self.db_tree, "_POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES")))

    def test_python_owner_has_one_real_replay_between_two_loads_inside_caller_owned_savepoint(self):
        owner = named(self.owner_tree, "_issue_on_connection")
        for expression, count in (("capability._capture_expectations", 1), ("store._parameters", 2),
                ("_load", 2), ("store._decode", 3), ("capability._verify_signed_capability_on_work", 1),
                ("_expected_rows", 1), ("_compare", 2), ("_fresh", 2)):
            self.assertEqual(len(calls(owner, expression)), count, expression)
        capture = calls(owner, "capability._capture_expectations")[0]
        callbacks = calls(owner, "store._callback")
        self.assertLess(capture.lineno, callbacks[0].lineno)
        replay = calls(owner, "capability._verify_signed_capability_on_work")[0]
        loads, checks, freshness = calls(owner, "_load"), calls(owner, "_compare"), calls(owner, "_fresh")
        stores = [call for call in calls(owner, "_query") if ast.unparse(call.args[3]) == "_STORE_SQL"]
        self.assertEqual(len(stores), 1)
        ordered = [loads[0].lineno, replay.lineno, checks[0].lineno, freshness[0].lineno,
            stores[0].lineno, loads[1].lineno, checks[1].lineno, freshness[1].lineno]
        self.assertEqual(ordered, sorted(ordered))
        self.assertEqual(next(keyword.value.id for keyword in replay.keywords if keyword.arg == "work"), "work")
        self.assertEqual({keyword.arg: ast.unparse(keyword.value) for keyword in replay.keywords
            if keyword.arg in {"retained_envelope_bytes", "evaluation_context_bytes", "execution_request_bytes"}},
            {"retained_envelope_bytes": "retained_bytes", "evaluation_context_bytes": "context_bytes",
             "execution_request_bytes": "execution_bytes"})
        scopes = calls(owner, "_scope")
        self.assertEqual([ast.unparse(call.args[-1]) for call in scopes], ["connection.transaction", "connection.cursor"])
        for scope in scopes:
            self.assertEqual([ast.unparse(value) for value in scope.args[:3]], ["connection", "original", "work"])
        self.assertFalse(calls(owner, "connection.commit"))
        self.assertFalse(calls(owner, "connection.close"))
        self.assertFalse(calls(owner, "_ValidationWork"))
        self.assert_shape(calls(owner, "store._parameters")[0].args[1], "_LOAD_FIELDS")

    def test_legacy_retry_witness_executor_and_failure_guards_precede_old_authority_paths(self):
        installer = ast.get_source_segment(self.executor_source,
            named(self.executor_tree, "install_authority_v9_executor"))
        writer = installer.split("AS $catchplate_issue_writer_capability_v3$", 1)[1].split(
            "$catchplate_issue_writer_capability_v3$", 1)[0]
        writer = compact(writer)
        self.assertLess(writer.index("legacy writer issuer requires v3 capability protocol"),
            writer.index("RETURN capability_value->>'capabilityId'"))
        witness_guard = installer.index("legacy witness recorder requires v3 capability protocol")
        self.assertLess(witness_guard, installer.index("RETURN computed_receipt_digest", witness_guard))
        second_guard = installer.index("legacy witness recorder requires v3 capability protocol", witness_guard + 1)
        self.assertLess(second_guard, installer.index("SELECT * INTO reservation", second_guard))
        executor_guard = installer.index("legacy authority executor requires v3 capability protocol")
        self.assertLess(executor_guard, installer.index("INTO STRICT execution_envelope", executor_guard))
        self.assertLess(executor_guard, installer.index("INTO STRICT planner", executor_guard))
        failure = named(self.executor_tree, "fail_authority_v9_transaction")
        failure_source = ast.get_source_segment(self.executor_source, failure)
        self.assertLess(failure_source.index("legacy authority failure worker requires v3 capability protocol"),
            failure_source.index("envelope = cursor.execute"))
        self.assertLess(failure_source.index("legacy authority failure worker requires v3 capability protocol"),
            failure_source.index("planner = cursor.execute"))
        for fragment in (writer, compact(failure_source)):
            self.assertIn("capability_record_digest", fragment)
            self.assertIn("v3", fragment)
        for tree in (self.service_tree, self.executor_tree):
            self.assertFalse(calls(tree, "_issue_on_connection"))
        self.assertNotIn("authority_store.revocation_capability", self.service_source)
        self.assertNotIn("catchplate_policy_authority_load_revocation_issuance", self.service_source)


if __name__ == "__main__":
    unittest.main()
