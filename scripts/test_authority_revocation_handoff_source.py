#!/usr/bin/env python3
"""Nonimporting source linkage for original signed revocation plan handoff.

These bounded AST assertions never import the helper, service or registry and
never execute extracted production code. They do not establish live service,
clock provenance, database admission or runtime signature/proof success. The
separate component fixture owns genuine cryptographic replay controls.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path, maximum=256 * 1024):
    target = ROOT / path
    if target.stat().st_size > maximum:
        raise AssertionError("revocation handoff source exceeds its inspection bound")
    source = target.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=path)


def definition(tree, name):
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name == name]
    if len(nodes) != 1:
        raise AssertionError("revocation handoff definition is not unique: " + name)
    return nodes[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == name), key=lambda node: (node.lineno, node.col_offset))


def call(tree, name):
    nodes = calls(tree, name)
    if len(nodes) != 1:
        raise AssertionError("revocation handoff call is not unique: " + name)
    return nodes[0]


def assigned(tree, name):
    nodes = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(nodes) != 1:
        raise AssertionError("revocation handoff assignment is not unique: " + name)
    return nodes[0]


def keywords(node):
    if any(item.arg is None for item in node.keywords):
        raise AssertionError("revocation handoff call has open keyword expansion")
    return {item.arg: item.value for item in node.keywords}


class RevocationHandoffSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper_source, cls.helper = read("serverware/authority_revocation_handoff.py", 64 * 1024)
        cls.worker = definition(cls.helper, "_verify_observed_plan_handoff_on_work")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_handoff_is_closed_original_data_without_clock_sql_or_success_callback(self):
        self.assertEqual(self.worker.args.args, [])
        self.assertEqual([item.arg for item in self.worker.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "expected_request", "context", "root_inventory",
            "planner_public_key", "verifier_public_key", "work"])
        self.assertTrue(all(value is None for value in self.worker.args.kw_defaults))
        self.assertIsNone(self.worker.args.kwarg)
        self.assertIsNone(self.worker.args.vararg)
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "psycopg.connect",
                "time.time_ns", "time.monotonic_ns", "datetime.now", "json.loads", "json.dumps",
                "eval", "exec"):
            self.assertEqual(calls(self.helper, forbidden), [])
        for text in ("authority_transition_registry", "authority_service", "authority_revocation_coordinator",
                "authority_revocation_issuance", "authority_revocation_persistence"):
            self.assertNotIn(text, self.helper_source)
        self.assertFalse(any(isinstance(node, ast.Import) for node in self.helper.body))
        imports = {(node.module, item.name) for node in self.helper.body
            if isinstance(node, ast.ImportFrom) for item in node.names}
        self.assertEqual(imports, {
            ("__future__", "annotations"), ("dataclasses", "dataclass"),
            ("datetime", "datetime"), ("datetime", "timedelta"), ("datetime", "timezone"),
            ("cryptography.exceptions", "InvalidSignature"),
            ("cryptography.hazmat.primitives.asymmetric.ed25519", "Ed25519PublicKey"),
            ("serverware.authority_query_read_work", "QueryReadValidationMetrics"),
            ("serverware.authority_query_read_work", "_ValidationWork"),
            *(('serverware', name) for name in (
                "authority_revocation_capability", "authority_revocation_observed",
                "authority_revocation_plan", "authority_revocation_retention", "authority_revocation_wire"))})

    def test_owned_context_and_full_inventory_precede_original_transport_and_key_callback(self):
        ledger = call(self.worker, "plan.capture._SharedLedger")
        self.shape(ledger, 'plan.capture._SharedLedger(work)')
        self.shape(assigned(self.worker, "owned"), '''observed.reads._CopyBudget(work).copy({
            "expectedRequest": expected_request, "context": context})''')
        captured = call(self.worker, "observed._capture_root_inventory")
        self.shape(captured, 'observed._capture_root_inventory(root_inventory, work=work)')
        partial = call(self.worker, "observed._validate_partial_context")
        self.shape(partial, 'observed._validate_partial_context(independent, work)')
        typed = call(self.worker, "plan.contract._request")
        self.shape(typed, 'plan.contract._request(request)')
        decoded = call(self.worker, "wire._decode_envelope")
        self.shape(decoded, 'wire._decode_envelope(envelope_bytes, work=work)')
        self.shape(call(self.worker, "plan.contract.validate_signed_envelope_shape"),
            'plan.contract.validate_signed_envelope_shape(envelope)')
        canonical = call(self.worker, "capability._canonical")
        self.shape(canonical, '''capability._canonical(envelope_bytes, envelope, ledger,
            plan.contract.MAX_PAYLOAD_BYTES, plan.contract.MAX_JSON_NODES)''')
        payload = call(self.worker, "capability._wire")
        self.shape(payload, '''capability._wire(payload, ledger,
            plan.contract.MAX_PAYLOAD_BYTES, plan.contract.MAX_JSON_NODES)''')
        authenticated = call(self.worker, "capability._signature")
        ordered = (ledger, assigned(self.worker, "owned"), captured, partial, typed,
                   decoded, canonical, payload, authenticated)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        for guard in (
                "type(expected_request) is not dict", "type(context) is not dict",
                "type(envelope_bytes) is not bytes", "not 2 <= len(envelope_bytes) <= plan.contract.MAX_PAYLOAD_BYTES",
                "type(evaluation_context_bytes) is not bytes",
                "not 2 <= len(evaluation_context_bytes) <= retention.MAX_CONTEXT_BYTES"):
            self.assertIn(guard, ast.unparse(self.worker))
        # The fourteen-field validator is the real source-owned validator, not
        # a fake expectedBefore graph used to make a full-context call succeed.
        _source, observed = read("serverware/authority_revocation_observed.py")
        self.shape(assigned(observed, "_PARTIAL_CONTEXT_FIELDS"), 'production._CONTEXT_FIELDS - {"expectedBefore"}')
        self.shape(call(definition(observed, "_validate_partial_context"), "plan._expectation_context"),
            'plan._expectation_context(context)')

    def test_real_signature_and_independent_source_identity_joins_precede_cutoff(self):
        authenticated = call(self.worker, "capability._signature")
        self.shape(authenticated, '''capability._signature(planner_public_key,
            envelope["signatureBase64Url"], plan.contract.SIGNED_MEASURED_PLAN_SCHEMA, payload_wire, ledger)''')
        bound = call(self.worker, "_bind_independent")
        self.shape(bound, '_bind_independent(envelope, request, independent, ledger)')
        cutoff = call(self.worker, "_authenticated_cutoff")
        self.assertLess(authenticated.lineno, bound.lineno)
        self.assertLess(bound.lineno, cutoff.lineno)
        joins = definition(self.helper, "_bind_independent")
        self.shape(call(joins, "plan._expectations"),
            'plan._expectations({"envelope": envelope, "expectedRequest": request, **context}, ledger)')
        self.shape(assigned(joins, "expected_source"), '''{
            "operationContractDigest": plan.authority_contract.OPERATION_MANIFEST_DIGEST,
            "operationManifestDigest": plan.authority_contract.OPERATION_MANIFEST_DIGEST,
            "handlerContractDigest": plan._HANDLER_DIGEST,
            "queryManifestDigest": plan._QUERY_MANIFEST_DIGEST,
            "operationId": request["operationId"], "requestDigest": request["requestDigest"]}''')
        self.shape(assigned(joins, "identity"), 'context["expectedVerifierIdentity"]')
        self.shape(assigned(joins, "expected_authorization"), '''{
            "verifierSessionIdentityDigest": identity["sessionIdentityDigest"],
            "verifierMeasurementDigest": identity["measurementDigest"],
            "verifierAttestationReceiptDigest": identity["attestationReceiptDigest"],
            "approverPolicyDigest": context["expectedApproverPolicyDigest"],
            "createdAtEpochNs": context["reservedAtEpochNs"],
            "expiresAtEpochNs": context["deadlineEpochNs"]}''')
        comparisons = calls(joins, "plan._same")
        self.assertEqual(len(comparisons), 2)
        self.shape(comparisons[0].args[0], '{name: measured[name] for name in expected_source}')
        self.shape(comparisons[0].args[1], 'expected_source')
        self.shape(comparisons[1].args[0], '{name: authorization[name] for name in expected_authorization}')
        self.shape(comparisons[1].args[1], 'expected_authorization')
        _source, capability = read("serverware/authority_revocation_capability.py")
        signature = definition(capability, "_signature")
        self.shape(call(signature, "key.verify"), 'key.verify(signature, message)')
        self.assertLess(call(signature, "key.verify").lineno,
            call(signature, "capture._SharedLedger").lineno)
        for guard in ("work.limits is not limits", "work.metrics != metrics"):
            self.assertIn(guard, ast.unparse(signature))

    def test_authenticated_cutoff_is_matching_signed_int64_and_exact_utc_without_resampling(self):
        cutoff = definition(self.helper, "_authenticated_cutoff")
        self.shape(assigned(cutoff, "cutoff"), 'payload["revocationProofBundle"]["inputs"]["cutoffUs"]')
        self.shape(assigned(cutoff, "transition_cutoff"), 'payload["rootTransition"]["cutoffUs"]')
        loop, = [node for node in cutoff.body if isinstance(node, ast.For)]
        self.shape(loop.iter, '(cutoff, transition_cutoff)')
        self.shape(loop.body[0].test, 'type(value) is not int or not -(2**63) <= value < 2**63')
        self.assertIsInstance(loop.body[0].body[0], ast.Raise)
        self.shape(call(cutoff, "plan._same"),
            'plan._same(cutoff, transition_cutoff, work, "authenticated planner cutoff fields disagree")')
        self.shape(assigned(self.helper, "_EPOCH"), 'datetime(1970, 1, 1, tzinfo=timezone.utc)')
        self.shape(assigned(cutoff, "instant"), '_EPOCH + timedelta(microseconds=cutoff)')
        guard, = [node for node in cutoff.body if isinstance(node, ast.If)]
        self.shape(guard.test, 'plan.semantics.complete.cutoff_microseconds(instant) != cutoff')
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.shape(cutoff.body[-1].value, 'instant')
        self.assertEqual(calls(cutoff, "float"), [])
        self.assertEqual(calls(cutoff, "datetime.fromtimestamp"), [])

    def test_signed_profile_hints_select_only_independent_values_before_genuine_effect_replay(self):
        project = definition(self.helper, "_project_independent")
        self.shape(assigned(project, "roles"),
            'tuple(query["role"] for query in payload["revocationProofBundle"]["inputs"]["queries"])')
        self.shape(assigned(project, "tables"), 'tuple(mutation["table"] for mutation in payload["mutationPlan"])')
        guards = [node.test for node in project.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 2)
        self.shape(guards[0], 'len(roles) != len(observed.complete.ROLES) or set(roles) != set(observed.complete.ROLES)')
        self.shape(guards[1], 'any(table not in observed._MUTATION_TABLES for table in tables)')
        self.shape(assigned(project, "selected"),
            '{observed.complete._role(observed.complete.OPERATION, role).index_id for role in roles}')
        self.shape(call(project, "selected.update"), '''selected.update(identity for table in tables
            for identity in observed.projection.index_ids_for_table(table))''')
        self.shape(assigned(project, "full"), 'observed._inventory_before(inventory)')
        self.shape(assigned(project, "before"), '''{
            "businessBeforeRoots": full["businessBeforeRoots"],
            "authorizationBeforeRoots": full["authorizationBeforeRoots"],
            "indexBeforeHeads": [row for row in full["indexBeforeHeads"] if row["indexId"] in selected]}''')
        self.shape(assigned(project, "projected"),
            'observed.reads._CopyBudget(work).copy({**context, "expectedBefore": before})')
        self.shape(call(project, "retention.production._validate_context"),
            'retention.production._validate_context(projected, work)')
        self.assertEqual(calls(self.helper, "observed._project_expected_context"), [])
        self.assertEqual(calls(self.helper, "observed._read_revocation_root_inventory_on_work"), [])
        # Matching candidate identifiers is not successful proof admission:
        # the unchanged real worker checks exact read/write union and effects.
        _source, mixed = read("serverware/authority_complete_read_write.py")
        verify = definition(mixed, "_verify")
        self.shape(assigned(verify, "expected_union"), 'tuple(sorted(set(read_ids) | set(write_ids)))')
        union_guard = next(node for node in verify.body if isinstance(node, ast.If))
        self.shape(union_guard.test, 'tuple(item["indexId"] for item in owned["countedBeforeHeads"]) != expected_union')
        self.assertIsInstance(union_guard.body[0], ast.Raise)
        _source, semantics = read("serverware/authority_revocation_semantics.py")
        replay = definition(semantics, "_verify")
        self.assertLess(call(replay, "retained._compute_and_package").lineno,
            call(replay, "_derive_revocation_effects").lineno)
        effect_compare = [node for node in calls(replay, "_canonical_equal")
            if ast.unparse(node.args[0]) == "mutations"]
        self.assertEqual(len(effect_compare), 1)
        self.shape(effect_compare[0].args[1], 'claimed_mutations')

    def test_original_bytes_and_same_work_reach_actual_retention_before_detached_result(self):
        replay = call(self.worker, "retention._verify_record_on_work")
        self.shape(assigned(self.worker, "expectations"),
            '{argument: expected_context[name] for name, argument in retention._CONTEXT_PAIRS}')
        self.shape(replay, '''retention._verify_record_on_work(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=request,
            planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
            database_now=database_now, work=work, **expectations)''')
        self.assertLess(call(self.worker, "_authenticated_cutoff").lineno,
            call(self.worker, "_project_independent").lineno)
        self.assertLess(call(self.worker, "_project_independent").lineno, replay.lineno)
        returned = call(self.worker, "_ObservedPlanHandoff")
        self.assertLess(replay.lineno, returned.lineno)
        self.shape(returned, '''_ObservedPlanHandoff(retained, database_now, expected_context,
            RevocationHandoffMetrics(captured, transported, authenticated, bound, projected, replayed,
                2, 1, work.hash_work, work.input_bytes, work.json_nodes))''')
        carrier = definition(self.helper, "_ObservedPlanHandoff")
        self.assertEqual([node.target.id for node in carrier.body if isinstance(node, ast.AnnAssign)],
            ["retained_record", "database_now", "expected_context", "metrics"])
        self.shape(carrier.decorator_list[0], 'dataclass(frozen=True, slots=True)')
        metrics = definition(self.helper, "RevocationHandoffMetrics")
        self.assertEqual([node.target.id for node in metrics.body if isinstance(node, ast.AnnAssign)], [
            "capture", "transport", "authentication", "bindings", "projection", "replay",
            "planner_signature_attempts", "semantic_replays", "total_hashes", "total_input_bytes", "total_json_nodes"])
        _source, retained = read("serverware/authority_revocation_retention.py")
        actual = definition(retained, "_verify_record_on_work")
        owns = call(actual, "capture._JSONCapture(ledger).visit")
        genuine = call(actual, "plan._verify_signed_revocation_plan_on_work")
        self.assertLess(owns.lineno, genuine.lineno)
        self.shape(genuine, '''plan._verify_signed_revocation_plan_on_work(
            envelope=envelope, original_envelope_bytes=envelope_bytes, work=work,
            expected_request=owned["expectedRequest"], planner_public_key=planner_key,
            verifier_public_key=verifier_key, database_now=database_now, **supplied)''')
        self.shape(call(actual, "plan._same"), '''plan._same(context, owned["context"], work,
            "retained context differs from independently supplied historical expectations")''')

    def test_actual_service_dispatch_and_role_credentials_do_not_activate_handoff(self):
        service_source, service = read("serverware/authority_service.py", 2 * 1024 * 1024)
        process = definition(service, "AuthorityProcess")
        handle = definition(process, "handle")
        admissions = calls(handle, "self._verify_internal_envelope")
        self.assertEqual(len(admissions), 3)
        self.shape(keywords(admissions[0])["allowed_purposes"], '{"plan-operation"}')
        self.shape(keywords(admissions[1])["allowed_purposes"], '''{
            "persist-measured-plan", "read-persisted-plan", "reserve-execution-envelope"}''')
        self.shape(keywords(admissions[2])["allowed_purposes"], '''
            {"issue-capability", "record-witness-receipt"} if self.role_name == "issuer" else {"execute-v9"}''')
        server = definition(service, "AuthorityServer")
        serving = definition(server, "_serve_connection")
        self.shape(assigned(serving, "request"), '_recv_message(connection)')
        self.shape(assigned(serving, "response"), 'self.process.handle(request)')
        credentials = definition(process, "_reject_wrong_credentials")
        self.shape(assigned(credentials, "allowed"), '''{
            "verifier": {"SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD"},
            "planner": {"SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD"},
            "planner-writer": {"SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD"},
            "issuer": {"SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD"},
            "executor": {"SERVERWARE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD"}}[self.role_name]''')
        self.assertNotIn("authority_revocation_handoff", service_source)
        self.assertNotIn("produce_observed_and_persist_with_cutoff", service_source)
        self.assertNotIn("RevocationPlanningCoordinator", service_source)


if __name__ == "__main__":
    unittest.main()
