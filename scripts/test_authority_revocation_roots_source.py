#!/usr/bin/env python3
"""Bounded nonimporting linkage for actual independent verifier root reads.

These controls inspect source, never extracted/evaluated production functions.
They are not positive PostgreSQL, measured-launch, root enrollment or service
admission evidence. Runtime recorder controls remain a separate component lane.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUSINESS = ("approval_grants", "control_plane_approvals", "metadata_audit_outbox",
    "oidc_browser_sessions", "policy_authority_bounded_aggregate_states",
    "webauthn_challenges", "webauthn_credentials")
AUTHORIZATION = ("webauthn_trust_publication_high_water", "webauthn_trust_publications")
HEADS = ("webauthn_control_approval_approved", "webauthn_credential_id",
    "webauthn_credential_live_trust", "webauthn_credential_user_history",
    "webauthn_grant_approver_active", "webauthn_publication_status",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status")
PRIMARY_FIELDS = ("table_name", "root_revision", "root_digest", "leaf_count",
    "tree_depth", "tree_radix", "manifest_digest", "updated_at_epoch_ns")


def read(path, maximum=256 * 1024):
    target = ROOT / path
    if target.stat().st_size > maximum:
        raise AssertionError("root-read source exceeds its inspection bound")
    source = target.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=path)


def definition(tree, name):
    values = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name]
    if len(values) != 1:
        raise AssertionError("root-read definition is not unique: " + name)
    return values[0]


def assigned(tree, name):
    values = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(values) != 1:
        raise AssertionError("root-read assignment is not unique: " + name)
    return values[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == name), key=lambda node: (node.lineno, node.col_offset))


class RevocationRootsSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker_source, cls.worker = read("serverware/authority_revocation_roots.py", 64 * 1024)
        cls.owner_source, cls.owner = read("serverware/authority_revocation_root_reader.py", 64 * 1024)
        cls.service_source, cls.service = read("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.run = definition(cls.worker, "_read_revocation_root_inventory_on_work")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_inventory_comes_from_exact_revoke_seven_plus_two_roots_and_nine_potential_heads(self):
        _source, contract = read("serverware/authority_contract.py")
        operations = assigned(contract, "_OPERATIONS")
        revoke = [value for key, value in zip(operations.keys, operations.values)
            if ast.literal_eval(key) == "webauthn.credential.revoke"]
        self.assertEqual(len(revoke), 1)
        options = {keyword.arg: keyword.value for keyword in revoke[0].keywords}
        self.assertEqual(tuple(sorted(ast.literal_eval(options["writes"]))), BUSINESS)
        self.shape(options["reads"], '_WEBAUTHN + ("approval_grants", "control_plane_approvals", "oidc_browser_sessions")')
        self.shape(options["webauthn"], '"bound-verified-assertion-receipt"')
        spec = definition(contract, "_spec")
        self.shape(assigned(spec, "assertion_authorization_reads").body,
            'assertion_business_writes | {"webauthn_trust_publications", "webauthn_trust_publication_high_water"}')
        self.shape(assigned(spec, "authorization_reads"),
            'tuple(sorted((declared_reads & _AUTHORIZATION_SOURCE_TABLES) - declared_writes))')
        declared = set(ast.literal_eval(assigned(contract, "_WEBAUTHN"))) | set(BUSINESS)
        declared.update(ast.literal_eval(options["reads"].right))
        declared |= ast.literal_eval(assigned(spec, "assertion_authorization_reads").body.right)
        authorization_sources = ast.literal_eval(assigned(contract, "_AUTHORIZATION_SOURCE_TABLES").args[0])
        classified = (declared & authorization_sources) - set(BUSINESS)
        self.assertEqual(tuple(sorted(classified)), AUTHORIZATION)
        self.assertEqual(tuple(sorted(declared - classified)), BUSINESS)
        self.shape(assigned(self.worker, "_CONTRACTS"), "primary.primary_table_contracts(OPERATION)")
        self.shape(assigned(self.worker, "_BUSINESS_TABLES"), 'tuple(item.table for item in _CONTRACTS if item.root_class == "business")')
        self.shape(assigned(self.worker, "_AUTHORIZATION_TABLES"), 'tuple(item.table for item in _CONTRACTS if item.root_class == "authorization")')
        _source, primary = read("serverware/authority_primary_contract.py")
        tables = definition(primary, "primary_table_contracts")
        self.shape(assigned(tables, "business"), 'set(spec["businessReads"]) | set(spec["businessWrites"])')
        self.shape(assigned(tables, "authorization"), 'set(spec["authorizationReads"])')
        _source, complete = read("serverware/authority_complete_query.py")
        self.shape(assigned(self.worker, "OPERATION"), "complete.OPERATION")
        self.assertEqual(ast.literal_eval(assigned(complete, "OPERATION")), "webauthn.credential.revoke")
        roles = assigned(complete, "_ROLES").elts
        self.assertEqual(len(roles), 6)
        read_ids = {ast.literal_eval(role.args[2]) for role in roles}
        self.assertEqual(len(read_ids), 5)
        _source, projection = read("serverware/authority_index_projection.py")
        profiles = [(ast.literal_eval(item.args[0]), ast.literal_eval(item.args[1]))
            for item in assigned(projection, "_DEFINITIONS").elts]
        self.assertEqual(tuple(sorted(read_ids | {name for name, table in profiles if table in BUSINESS})), HEADS)
        self.shape(assigned(self.worker, "_HEAD_IDS"), "heads.required_index_ids(OPERATION)")
        _source, heads = read("serverware/authority_index_heads.py")
        required = definition(heads, "required_index_ids")
        self.shape(assigned(required, "identities"), "{role.index_id for role in roles}")
        self.shape(calls(required, "identities.update")[0], "identities.update(projection.index_ids_for_table(table))")
        self.assertEqual(ast.literal_eval(assigned(self.worker, "_PRIMARY_FIELDS")), PRIMARY_FIELDS)
        self.assertIn("(7, 2, 9)", ast.unparse(self.run))

    def test_actual_sql_has_one_closed_primary_select_then_the_genuine_head_reader(self):
        self.assertEqual([argument.arg for argument in self.run.args.args], ["cursor"])
        self.assertEqual([argument.arg for argument in self.run.args.kwonlyargs],
            ["expected_query_manifest_digest", "work", "acquisition"])
        self.assertIsNone(self.run.args.kwarg)
        projection = assigned(self.worker, "_PRIMARY_SELECT")
        self.assertEqual(len(calls(projection, "reader._integer_sql")), 1)
        self.assertEqual(len(calls(projection, "reader._text_sql")), 1)
        self.shape(calls(projection, "reader._text_sql")[0],
            'reader._text_sql("root", name, 71 if name.endswith("digest") else 1, 71 if name.endswith("digest") else 128)')
        self.shape(calls(projection, "reader._integer_sql")[0], '''reader._integer_sql("root", name,
            authority.TREE_DEPTH if name == "tree_depth" else authority.TREE_RADIX if name == "tree_radix" else 0,
            authority.TREE_DEPTH if name == "tree_depth" else authority.TREE_RADIX if name == "tree_radix" else counted.I64_MAX)''')
        sql = assigned(self.worker, "_PRIMARY_SQL")
        literals = "".join(node.value for node in ast.walk(sql) if isinstance(node, ast.Constant) and type(node.value) is str)
        for text in ("serverware_metadata.", "WHERE root.table_name IN (", 'COLLATE "C" LIMIT %s'):
            self.assertIn(text, literals)
        self.assertIn("_PRIMARY_TABLES", ast.unparse(sql))
        physical = calls(self.run, "acquisition.read")
        actual_heads = calls(self.run, "heads.read_operation_index_heads")
        self.assertEqual((len(physical), len(actual_heads)), (1, 1))
        self.shape(physical[0], '''acquisition.read(PRIMARY_TABLE,
            {"profile": PRIMARY_READ_PROFILE, "tableNames": list(_PRIMARY_TABLES), "rowLimit": 10},
            _PRIMARY_SQL, (*_PRIMARY_TABLES, 10), 9)''')
        self.shape(actual_heads[0], "heads.read_operation_index_heads(cursor, operation=OPERATION, trace=trace, work=work, acquisition=acquisition)")
        self.assertLess(physical[0].lineno, actual_heads[0].lineno)
        self.shape(assigned(self.worker, "_ROOT_LIMITS"), '''reader._ReadAcquisitionLimits(max_sql_reads=2,
            max_parameter_bytes=_MAX_PARAMETER_BYTES, max_transport_bytes=_MAX_PRIMARY_BYTES + _MAX_HEAD_BYTES)''')
        self.shape(assigned(self.worker, "_MAX_PARAMETER_BYTES"),
            "sum(8 + len(name) for name in (*_PRIMARY_TABLES, *_HEAD_IDS)) + 2 * (8 + 2)")
        self.shape(assigned(self.worker, "_MAX_PRIMARY_BYTES"),
            'sum(9 * 8 + len("primary-root") + len(name) + 2 * 71 + 3 * 19 + 2 * 2 for name in _PRIMARY_TABLES)')
        self.shape(assigned(self.worker, "_MAX_HEAD_BYTES"), '''sum(9 * 8 + len("head") + len(name)
            + len(projection._definition(name).table) + len(counted.PROFILE) + 3 * 71 + 2 * 19 for name in _HEAD_IDS)''')
        self.assertIn("acquisition.sql_reads != 2", ast.unparse(self.run))
        self.assertIn("acquisition.returned_rows != 18", ast.unparse(self.run))
        for name in ("cursor.execute", "_ValidationWork", "PlannerTrace", "_read_root_set"):
            self.assertFalse(calls(self.run, name))

    def test_original_manifest_and_real_cold_empty_work_precede_owned_scalar_publication(self):
        self.shape(assigned(self.run, "manifest"), "_callback(work, primary.source_query_manifest_digest)")
        self.assertIn("manifest != expected_query_manifest_digest", ast.unparse(self.run))
        empty = calls(self.run, "_primary_empty_root")[0]
        self.assertLess(assigned(self.run, "manifest").lineno, empty.lineno)
        self.assertLess(empty.lineno, calls(self.run, "acquisition.read")[0].lineno)
        preparation = definition(self.worker, "_primary_empty_root")
        loops = [node for node in preparation.body if isinstance(node, ast.For)]
        self.assertEqual(len(loops), 2)
        self.shape(loops[1].iter, "range(authority.TREE_DEPTH - 1, -1, -1)")
        encoders = calls(preparation, "work.prepare_encoding")
        self.assertEqual(len(encoders), 1)
        self.shape(encoders[0], "work.prepare_encoding(children, ensure_ascii=False, shallow_copies=1)")
        charges = calls(preparation, "work.charge")
        self.assertEqual(len(charges), 2)
        self.shape(charges[0], "work.charge(hashes=1, input_bytes=16 + len(_EMPTY_LEAF_DOMAIN) + len(leaf_depth))")
        self.shape(charges[1], "work.charge(hashes=1, input_bytes=24 + len(_EMPTY_NODE_DOMAIN) + len(text) + size)")
        self.shape(assigned(preparation, "result"), "_callback(work, radix.empty_digest, 0)")
        self.assertLess(loops[1].end_lineno, assigned(preparation, "result").lineno)
        _source, authority = read("serverware/authority_contract.py")
        self.assertEqual(ast.literal_eval(assigned(authority, "TREE_DEPTH")), 64)
        self.assertEqual(ast.literal_eval(assigned(authority, "TREE_RADIX")), 16)
        row = definition(self.worker, "_owned_primary_row")
        ordered = [calls(row, name)[0] for name in ("acquisition.charge", "work.prepare_copy", "raw.copy", "_PrimaryObservation")]
        self.assertEqual([call.lineno for call in ordered], sorted(call.lineno for call in ordered))
        self.shape(ordered[0], 'acquisition.charge("primary-root", raw, _PRIMARY_FIELDS)')
        self.assertIn("raw['manifest_digest'] != manifest", ast.unparse(row))
        self.assertIn("len(raw[name]) != 71", ast.unparse(row))
        self.assertEqual([node.target.id for node in definition(self.worker, "_PrimaryObservation").body if isinstance(node, ast.AnnAssign)], list(PRIMARY_FIELDS))
        self.assertEqual([node.target.id for node in definition(self.worker, "_RootInventory").body if isinstance(node, ast.AnnAssign)],
            ["business_roots", "authorization_roots", "counted_heads"])
        self.assertIn("Fixed source global-manifest reconstruction/admission", self.worker_source)

    def test_callback_and_phase_guards_pin_actual_work_and_physical_objects_without_refund(self):
        callback = definition(self.worker, "_callback")
        validations = calls(callback, "batch._SharedLedger")
        invoked = calls(callback, "function")
        self.assertEqual((len(validations), len(invoked)), (2, 1))
        self.assertLess(validations[0].lineno, invoked[0].lineno)
        self.assertLess(invoked[0].lineno, validations[1].lineno)
        for expression in ("work.limits is not limits", "work.metrics != metrics", "limits.max_hashes"):
            self.assertIn(expression, ast.unparse(callback))
        same = definition(self.worker, "_same_physical_stamp")
        self.shape(same.body[-1].value, "before[0] is after[0] and before[1:] == after[1:]")
        cursor = definition(self.worker, "_RootCursor")
        called = definition(cursor, "_call")
        self.assertIn("self._cursor is not raw", ast.unparse(called))
        self.assertIn("self._work is not work", ast.unparse(called))
        self.assertIn("acquisition.failed = True", ast.unparse(called))
        self.shape(calls(definition(cursor, "execute"), "self._call")[0], "self._call(lambda: self._cursor.execute(*arguments))")
        trace = definition(self.worker, "_RootTrace")
        advanced = definition(trace, "_advance")
        self.assertIn("self._phase == 0", ast.unparse(advanced))
        self.assertIn("self._phase == 1", ast.unparse(advanced))
        self.assertEqual(len(calls(advanced, "heads.validate_head_trace_key")), 1)
        self.assertEqual(len(calls(self.run, "acquisition.read_phase")), 1)
        self.assertEqual(len(calls(self.run, "acquisition.scope")), 1)
        self.assertIn("acquisition.failed = True", ast.unparse(self.run))
        self.assertIn("trace._failed = True", ast.unparse(self.run))
        self.assertIn("value != 0", ast.unparse(self.run))
        for module in (self.worker, self.owner):
            self.assertFalse(calls(module, "_ValidationWork"))
            self.assertFalse(calls(module, "QueryReadValidationLimits"))

    def test_owner_admits_real_pg16_verifier_snapshot_before_creating_the_two_read_ledger(self):
        worker = definition(self.owner, "_read_on_configuration")
        mode = ast.literal_eval(assigned(self.owner, "_SET_TRANSACTION"))
        self.assertEqual(mode, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE")
        executed = calls(worker, "guarded.execute")
        self.assertEqual(len(executed), 3)
        self.shape(executed[0], "guarded.execute(_SET_TRANSACTION)")
        admitted = calls(worker, "_admit_identity")[0]
        privilege = calls(worker, "verifier_read_privilege_check")[0]
        ledger = calls(worker, "roots.reader._ReadAcquisitionBudget")[0]
        acquired = calls(worker, "roots._read_revocation_root_inventory_on_work")[0]
        self.assertLess(executed[0].lineno, admitted.lineno)
        self.assertLess(admitted.lineno, privilege.lineno)
        self.assertLess(privilege.lineno, ledger.lineno)
        self.assertLess(ledger.lineno, acquired.lineno)
        self.shape(privilege, 'verifier_read_privilege_check(role=configuration[2], namespace="serverware_metadata")')
        self.shape(ledger, "roots.reader._ReadAcquisitionBudget(guarded, trace, work=work, limits=roots._ROOT_LIMITS)")
        self.shape(acquired, "roots._read_revocation_root_inventory_on_work(guarded, expected_query_manifest_digest=configuration[6], work=work, acquisition=acquisition)")
        identity = definition(self.owner, "_admit_identity")
        for expression in ("160000 <= identity['server_version_num'] < 170000", "identity['ssl'] is not True", "identity['rolcanlogin'] is not True"):
            self.assertIn(expression, ast.unparse(identity))
        expected = assigned(identity, "expected")
        values = {ast.literal_eval(key): value for key, value in zip(expected.keys, expected.values)}
        self.shape(values["role"], "role")
        self.shape(values["session_role"], "role")
        for name, value in (("transaction_isolation", "serializable"), ("transaction_read_only", "on"), ("transaction_deferrable", "on")):
            self.assertEqual(ast.literal_eval(values[name]), value)
        connection = definition(self.owner, "_connection_identity")
        self.shape(assigned(connection, "identity"), "connection.pgconn")
        self.assertEqual(len([node for node in ast.walk(connection) if isinstance(node, ast.Attribute) and ast.unparse(node) == "connection.pgconn"]), 1)
        proxy = definition(definition(self.owner, "_ConnectionCursor"), "_call")
        self.assertEqual(len(calls(proxy, "self._require")), 4)
        public = definition(definition(self.owner, "RevocationRootReader"), "read")
        opened = calls(public, "psycopg.connect")
        self.assertEqual(len(opened), 1)
        self.shape(opened[0], "psycopg.connect(configuration[0], row_factory=dict_row, connect_timeout=configuration[1], autocommit=False, options='-c search_path=pg_catalog')")
        self.assertEqual([argument.arg for argument in public.args.kwonlyargs], ["work"])
        self.assertLess(assigned(public, "configuration").lineno, opened[0].lineno)
        self.assertIn("not 2 <= timeout <= 300", ast.unparse(definition(self.owner, "_validate_pins")))
        self.assertEqual(len(calls(worker, "_close_after_failure")), 1)

    def test_private_service_uses_measured_verifier_pins_and_real_descriptor_without_opening_dispatch(self):
        process = definition(self.service, "AuthorityProcess")
        method = definition(process, "_read_revocation_root_observations")
        self.assertEqual([argument.arg for argument in method.args.kwonlyargs], ["work"])
        self.assertIsNone(method.args.kwarg)
        self.assertIn("type(self.configuration) is not MeasuredConfiguration", ast.unparse(method))
        self.assertIn("self.role_name != 'verifier'", ast.unparse(method))
        self.assertIn("self.process_mode != 'policy-authority-verifier'", ast.unparse(method))
        self.assertIn("not 2 <= timeout <= 300", ast.unparse(method))
        self.shape(assigned(method, "pins"), '''(int(timeout), role["databaseRole"], role["tlsClientDn"],
            role["tlsClientSerial"], role["tlsIssuerDn"], payload["queryManifestDigest"])''')
        callbacks = calls(method, "authority_revocation_root_reader.roots._callback")
        self.assertEqual(len(callbacks), 2)
        self.shape(callbacks[0], 'authority_revocation_root_reader.roots._callback(work, authority_launch_guard.require_active, "verifier")')
        self.shape(callbacks[1], '''authority_revocation_root_reader.roots._callback(work, _read_dsn_descriptor,
            "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN")''')
        self.assertLess(assigned(method, "pins").lineno, callbacks[0].lineno)
        self.assertLess(callbacks[0].lineno, callbacks[1].lineno)
        self.shape(method.body[-1].value, "reader.read(work=work)")
        main = definition(self.service, "main")
        self.assertLess(calls(main, "MeasuredConfiguration.load")[0].lineno, calls(main, "AuthorityProcess")[0].lineno)
        loaded = definition(definition(self.service, "MeasuredConfiguration"), "load")
        self.assertEqual(len(calls(loaded, "root_key.verify")), 1)
        for dispatcher in (definition(process, "handle"), definition(definition(self.service, "AuthorityServer"), "_serve_connection")):
            for private in ("_read_revocation_root_observations", "RevocationRootReader", "authority_revocation_roots"):
                self.assertNotIn(private, ast.unparse(dispatcher))
        for tree in (self.worker, self.owner):
            imports = [ast.unparse(node) for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
            self.assertFalse(any("authority_planner" in item or "authority_transition_registry" in item or "import db" in item or "import time" in item for item in imports))
        registry, _tree = read("serverware/authority_transition_registry.py")
        self.assertNotIn("authority_revocation_roots", registry)
        self.assertNotIn("_read_revocation_root_observations", registry)


if __name__ == "__main__":
    unittest.main()
