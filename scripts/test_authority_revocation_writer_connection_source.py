#!/usr/bin/env python3
"""Nonimporting source linkage for configured v4 writer admission.

Inspect bounded source only. No DB/service/registry imports, extracted function
execution, successful-admission substitutes, or live PostgreSQL/TLS assertions.
Driver recorders and the separate native catalog query fixture retain their own
limited evidence boundaries; neither makes these AST controls a runtime proof.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRITER_ROLE = "catchplate_policy_authority_planner_writer"
IDENTITY_FIELDS = {
    "server_version_num", "role", "session_role", "transaction_isolation",
    "transaction_read_only", "transaction_deferrable", "ssl", "client_dn", "client_serial",
    "issuer_dn", "rolcanlogin", "rolsuper", "rolcreaterole", "rolcreatedb",
    "rolreplication", "rolbypassrls", "schema_create", "database_create", "database_temporary",
}
FALSE_FIELDS = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication",
    "rolbypassrls", "schema_create", "database_create", "database_temporary")


def source(relative, maximum=128 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("writer source exceeds its explicit fixture bound")
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text, filename=relative)


def definition(tree, name):
    matches = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("writer source definition is not unique: " + name)
    return matches[0]


def assigned(tree, name):
    matches = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError("writer source assignment is not unique: " + name)
    return matches[0]


def calls(tree, spelling):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) == spelling), key=lambda node: (node.lineno, node.col_offset))


def call(tree, spelling):
    matches = calls(tree, spelling)
    if len(matches) != 1:
        raise AssertionError("writer source call is not unique: " + spelling)
    return matches[0]


class RevocationWriterConnectionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("catchplate/authority_revocation_writer_connection.py")
        cls.persistence_text, cls.persistence = source("catchplate/authority_revocation_persistence.py")
        cls.runner_body = definition(cls.tree, "_run_on_connection")

    def assert_shape(self, node, expected):
        self.assertEqual(ast.dump(node), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_inert_module_uses_shared_real_guards_and_has_no_admission_switch(self):
        imports = [(node.module, tuple((alias.name, alias.asname) for alias in node.names))
            for node in self.tree.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [("__future__", (("annotations", None),)),
            ("catchplate", (("authority_revocation_root_reader", "reader"),)),
            ("catchplate.authority_store.planner_writer_sql", (("planner_writer_privilege_check", None),))])
        self.assertFalse(any(isinstance(node, ast.Import) for node in self.tree.body))
        self.assertEqual([item.arg for item in self.runner_body.args.args], ["connection"])
        self.assertEqual([item.arg for item in self.runner_body.args.kwonlyargs],
            ["database_identity", "work", "operation", "arguments", "expectations"])
        self.assertTrue(all(value is None for value in self.runner_body.args.kw_defaults))
        self.assertIsNone(self.runner_body.args.kwarg)
        self.assertEqual(assigned(self.tree, "_ROLE").value, WRITER_ROLE)
        self.assertEqual(assigned(self.tree, "_SET_TRANSACTION").value,
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")
        self.assert_shape(assigned(self.tree, "_IDENTITY_SQL"), "reader._IDENTITY_SQL")
        callback = definition(self.tree, "_callback")
        delegated = call(callback, "reader.roots._callback")
        self.assert_shape(delegated, "reader.roots._callback(work, callback, *args)")
        handler, = [node for node in ast.walk(callback) if isinstance(node, ast.ExceptHandler)]
        self.assert_shape(handler.type, "reader.roots.RevocationRootReadError")
        self.assert_shape(handler.body[0].exc, "RevocationWriterConnectionError(str(exc))")
        self.assert_shape(handler.body[0].cause, "exc")
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "eval", "exec", "getattr(db, operation)"):
            self.assertFalse(calls(self.tree, forbidden))
        self.assertFalse(any(isinstance(node, (ast.Global, ast.Nonlocal)) and
            any(name in {"admitted", "skip_admission", "_DB_GLOBALS"} for name in node.names)
            for node in ast.walk(self.tree)))

    def test_fixed_writer_identity_is_exact_owned_scalar_configuration(self):
        validator = definition(self.tree, "_validate_database_identity")
        self.assert_shape(validator.body[0].test, "type(identity) is not tuple or len(identity) != 4")
        loop = validator.body[1]
        self.assertIsInstance(loop, ast.For)
        self.assert_shape(loop.iter, "enumerate(identity)")
        self.assert_shape(loop.body[0].value, "63 if index == 0 else 4096")
        self.assert_shape(loop.body[1].test,
            r"type(value) is not str or not 1 <= len(value) <= maximum or '\x00' in value")
        utf8 = loop.body[2]
        self.assertIsInstance(utf8, ast.Try)
        self.assert_shape(utf8.body[0].test, "len(value.encode('utf-8')) > maximum")
        self.assert_shape(utf8.handlers[0].type, "UnicodeError")
        self.assert_shape(validator.body[-1].test, "identity[0] != _ROLE")
        self.assertFalse(calls(validator, "str"))
        self.assertFalse(calls(validator, "tuple"))
        self.assertFalse(calls(validator, "_callback"))

    def test_actual_closed_nineteen_field_query_checks_pg16_tls_role_and_writer_mode(self):
        _, reader = source("catchplate/authority_revocation_root_reader.py")
        false_fields = tuple(item.value for item in assigned(reader, "_FALSE_FIELDS").elts)
        self.assertEqual(false_fields, FALSE_FIELDS)
        fields = assigned(reader, "_IDENTITY_FIELDS").args[0]
        self.assertEqual({item.value for item in fields.elts if isinstance(item, ast.Constant)}
            | set(false_fields), IDENTITY_FIELDS)
        starred, = [item.value for item in fields.elts if isinstance(item, ast.Starred)]
        self.assert_shape(starred, "_FALSE_FIELDS")
        query = assigned(reader, "_IDENTITY_SQL").value
        for fragment in (
            "pg_catalog.current_setting('server_version_num')::integer AS server_version_num",
            "current_user AS role, session_user AS session_role",
            "pg_catalog.current_setting('transaction_isolation') AS transaction_isolation",
            "pg_catalog.current_setting('transaction_read_only') AS transaction_read_only",
            "pg_catalog.current_setting('transaction_deferrable') AS transaction_deferrable",
            "ssl.ssl, ssl.client_dn, ssl.client_serial::text AS client_serial, ssl.issuer_dn",
            "FROM pg_catalog.pg_stat_ssl AS ssl JOIN pg_catalog.pg_roles AS role_record",
            "ON role_record.oid = current_user::pg_catalog.regrole::oid",
            "WHERE ssl.pid = pg_catalog.pg_backend_pid()",
        ):
            self.assertIn(fragment, query)
        admission = definition(self.tree, "_admit_identity")
        self.assert_shape(admission.body[0].test,
            "type(row) is not dict or len(row) != len(reader._IDENTITY_FIELDS) "
            "or any(type(name) is not str for name in row) or set(row) != reader._IDENTITY_FIELDS")
        self.assert_shape(assigned(admission, "expected"), "{'role': role, 'session_role': role, "
            "'client_dn': client_dn, 'client_serial': client_serial, 'issuer_dn': issuer_dn, "
            "'transaction_isolation': 'serializable', 'transaction_read_only': 'off', 'transaction_deferrable': 'off'}")
        self.assert_shape(admission.body[-1].test,
            "type(row['server_version_num']) is not int or not 160000 <= row['server_version_num'] < 170000 "
            "or any(type(row[name]) is not str or row[name] != value for name, value in expected.items()) "
            "or row['ssl'] is not True or row['rolcanlogin'] is not True "
            "or any(row[name] is not False for name in reader._FALSE_FIELDS)")

    def test_all_three_real_admission_statements_precede_operation_on_the_same_proxy(self):
        transaction = call(self.runner_body, "reader.roots.batch._SharedLedger")
        self.assert_shape(transaction, "reader.roots.batch._SharedLedger(work)")
        initial = assigned(self.runner_body, "original")
        self.assert_shape(initial, "_callback(work, reader._connection_identity, connection, 0)")
        self.assertLess(call(self.runner_body, "_validate_database_identity").lineno, transaction.lineno)
        self.assertLess(transaction.lineno, initial.lineno)
        contexts = calls(self.runner_body, "reader._context")
        self.assertEqual([ast.unparse(node) for node in contexts],
            ["reader._context(connection, work)", "reader._context(transaction, work)"])
        self.assert_shape(assigned(self.runner_body, "guarded"), "_Connection(connection, original, work)")
        statements = calls(self.runner_body, "cursor.execute")
        self.assertEqual(len(statements), 3)
        self.assert_shape(statements[0], "cursor.execute(_SET_TRANSACTION)")
        self.assert_shape(statements[1], "cursor.execute(_IDENTITY_SQL)")
        self.assert_shape(statements[2],
            "cursor.execute(*planner_writer_privilege_check(role=database_identity[0], namespace='catchplate_metadata'))")
        identity = call(self.runner_body, "_admit_identity")
        self.assert_shape(identity, "_admit_identity(cursor.execute(_IDENTITY_SQL).fetchone(), database_identity)")
        denied, = [node for node in ast.walk(self.runner_body) if isinstance(node, ast.If)
            and any(item is statements[2] for item in ast.walk(node.test))]
        self.assert_shape(denied.test,
            "cursor.execute(*planner_writer_privilege_check(role=database_identity[0], "
            "namespace='catchplate_metadata')).fetchone() is not None")
        self.assert_shape(denied.body[0].exc,
            "RevocationWriterConnectionError('revocation writer effective privileges are not source exact')")
        operation = call(self.runner_body, "operation")
        self.assert_shape(operation, "operation(connection=db.PostgresMetadataConnection(guarded), "
            "work=work, **arguments, **expectations)")
        order = (statements[0], identity, statements[2], operation)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        operation_guards = calls(self.runner_body, "guarded._call")
        self.assertEqual(len(operation_guards), 2)
        self.assertTrue(all(ast.unparse(node) == "guarded._call(lambda: None)" for node in operation_guards))
        self.assertLess(operation_guards[0].lineno, operation.lineno)
        self.assertLess(operation.lineno, operation_guards[1].lineno)
        # The real operation may spend existing work: only driver metadata,
        # not the proof/store operation itself, uses no-spend callbacks.
        self.assertFalse(any(operation in list(ast.walk(node)) for node in calls(self.runner_body, "_callback")))

    def test_connection_and_info_getters_bind_actual_active_handle_before_and_after_callbacks(self):
        connection = definition(self.tree, "_Connection")
        self.assert_shape(assigned(connection, "__slots__"), "('_connection', '_original', '_work', '_binding')")
        self.assertEqual({node.name for node in connection.body if isinstance(node, ast.FunctionDef)},
            {"__init__", "_require", "_call", "info", "pgconn", "closed", "autocommit", "cursor", "transaction"})
        required = definition(connection, "_require")
        self.assert_shape(required.body[0].test,
            "self._binding is not binding or not _same_slots((self._connection, self._original, self._work), binding)")
        dispatch = definition(connection, "_call")
        self.assert_shape(dispatch.body[1].test, "type(binding) is not tuple or len(binding) != 3")
        invoked = definition(dispatch, "invoke")
        self.assertEqual([ast.unparse(node) for node in calls(invoked, "self._require")],
                         ["self._require(binding)"] * 4)
        self.assertEqual([ast.unparse(node) for node in calls(invoked, "_callback")],
            ["_callback(work, reader._require_connection, connection, original, 2)"] * 2)
        callback = call(invoked, "callback")
        guards = calls(invoked, "_callback")
        self.assertLess(guards[0].lineno, callback.lineno)
        self.assertLess(callback.lineno, guards[1].lineno)
        self.assert_shape(dispatch.body[-1].value, "_callback(work, invoke)")
        self.assert_shape(definition(connection, "info").body[-1].value,
                          "_Info(self._call(lambda: connection.info), self)")
        for name in ("pgconn", "closed", "autocommit"):
            self.assert_shape(definition(connection, name).body[-1].value,
                              "self._call(lambda: connection." + name + ")")
        self.assert_shape(definition(connection, "cursor").body[-1].value,
                          "_Cursor(self._call(lambda: connection.cursor()), self)")
        self.assert_shape(definition(connection, "transaction").body[-1].value,
                          "_Scope(self._call(lambda: connection.transaction()), self)")
        info = definition(definition(self.tree, "_Info"), "transaction_status")
        observed = definition(info, "observe")
        self.assert_shape(assigned(observed, "value"), "info.transaction_status")
        checks = [node for node in observed.body if isinstance(node, ast.If)]
        self.assertEqual(len(checks), 3)
        for guard in checks[:2]:
            self.assert_shape(guard.test,
                "self._binding is not binding or not _same_slots((self._info, self._connection), binding)")
        self.assert_shape(checks[-1].test, "not isinstance(value, int) or isinstance(value, bool) or value != 2")
        self.assert_shape(info.body[-1].value, "connection._call(observe)")
        _, reader = source("catchplate/authority_revocation_root_reader.py")
        physical = definition(reader, "_connection_identity")
        self.assert_shape(assigned(physical, "actual"), "connection.info.transaction_status")
        self.assert_shape(assigned(physical, "identity"), "connection.pgconn")
        self.assert_shape(physical.body[2].test,
            "connection.closed is not False or connection.autocommit is not False "
            "or not isinstance(actual, int) or isinstance(actual, bool) or actual != status or identity is None")
        self.assert_shape(definition(reader, "_require_connection").body[0].test,
                          "_connection_identity(connection, status) is not identity")

    def test_cursor_and_result_getters_stay_guarded_and_return_actual_integer_rowcounts(self):
        cursor = definition(self.tree, "_Cursor")
        self.assertEqual([ast.unparse(node) for node in cursor.bases], ["_Scope"])
        execute = definition(cursor, "execute")
        self.assert_shape(assigned(execute, "arguments"), "(sql,) if parameters is None else (sql, parameters)")
        self.assert_shape(assigned(execute, "result"), "self._call(lambda: cursor.execute(*arguments))")
        self.assert_shape(execute.body[-2].test, "result is not cursor")
        self.assert_shape(execute.body[-1].value, "_Result(result, self)")
        for name, arguments in (("fetchone", ""), ("fetchall", ""), ("fetchmany", "size")):
            self.assert_shape(definition(cursor, name).body[-1].value,
                              "self._call(lambda: cursor." + name + "(" + arguments + "))")
        rowcount = definition(cursor, "rowcount")
        self.assert_shape(assigned(rowcount, "value"), "self._call(lambda: cursor.rowcount)")
        self.assert_shape(rowcount.body[-2].test, "type(value) is not int")
        self.assert_shape(rowcount.body[-1].value, "value")
        result = definition(self.tree, "_Result")
        self.assert_shape(assigned(result, "__slots__"), "('_result', '_cursor', '_binding')")
        dispatch = definition(result, "_call")
        invoked = definition(dispatch, "invoke")
        self.assert_shape(assigned(invoked, "value"), "getattr(result, method)(*args)")
        checks = [node for node in invoked.body if isinstance(node, ast.If)]
        self.assertEqual(len(checks), 2)
        for guard in checks:
            self.assert_shape(guard.test,
                "self._binding is not binding or not _same_slots((self._result, self._cursor), binding)")
        self.assert_shape(dispatch.body[-1].value, "cursor._call(invoke)")
        for name, arguments in (("fetchone", ""), ("fetchall", ""), ("fetchmany", ", size")):
            self.assert_shape(definition(result, name).body[-1].value,
                              "self._call('" + name + "'" + arguments + ")")
        count = definition(result, "rowcount")
        self.assert_shape(assigned(count, "value"), "binding[1].rowcount")
        self.assert_shape(count.body[-2].test,
            "self._binding is not binding or not _same_slots((self._result, self._cursor), binding)")
        self.assert_shape(count.body[-1].value, "value")

    def test_scope_retains_original_entry_cleanup_when_working_bindings_change(self):
        scope = definition(self.tree, "_Scope")
        self.assert_shape(assigned(scope, "__slots__"),
            "('_manager', '_connection', '_binding', '_scope', '_state', '_entry_binding')")
        initializer = definition(scope, "__init__")
        self.assertEqual([ast.unparse(node) for node in initializer.body], [
            "self._manager, self._connection = (manager, connection)",
            "self._scope = reader._context(manager, connection._work)",
            "self._binding = (manager, connection, self._scope)",
            "self._state = 0", "self._entry_binding = None"])
        self.assert_shape(definition(scope, "_require").body[0].test,
            "self._binding is not binding or self._entry_binding is not binding "
            "or self._scope is not scope or self._state is not state "
            "or not _same_slots((self._manager, self._connection, self._scope), binding)")
        dispatch = definition(scope, "_call")
        invoked = definition(dispatch, "invoke")
        self.assertEqual([ast.unparse(node) for node in calls(invoked, "self._require")],
                         ["self._require(binding, scope, 1)"] * 2)
        self.assert_shape(dispatch.body[-1].value, "connection._call(invoke)")

        entering = definition(scope, "__enter__")
        self.assert_shape(assigned(entering, "binding"), "self._binding")
        reuse, = [node for node in entering.body if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "self._entry_binding is not None"]
        held, = [node for node in entering.body if isinstance(node, ast.Assign)
                 and any(ast.unparse(target) == "self._entry_binding" for target in node.targets)]
        self.assert_shape(held.value, "binding")
        enter = definition(entering, "enter")
        guards = calls(enter, "self._require")
        self.assertEqual([ast.unparse(node) for node in guards], ["self._require(binding, scope, 0)"] * 2)
        actual_enter = call(enter, "scope.__enter__")
        self.assert_shape(assigned(enter, "entered"), "True")
        self.assert_shape(enter.body[-2].test, "value is not manager")
        order = (reuse, held, guards[0], actual_enter, assigned(enter, "entered"), guards[1])
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        entered_try, = [node for node in entering.body if isinstance(node, ast.Try)]
        self.assert_shape(entered_try.body[0].value, "connection._call(enter)")
        self.assertEqual(ast.unparse(entered_try.body[1]), "self._state = 1")
        self.assert_shape(entered_try.body[2].value, "self")
        failed_enter, = entered_try.handlers
        self.assert_shape(failed_enter.type, "BaseException")
        self.assert_shape(failed_enter.body[0].test, "entered")
        self.assert_shape(call(failed_enter, "scope.__exit__"),
                          "scope.__exit__(type(exc), exc, exc.__traceback__)")
        self.assertEqual(ast.unparse(failed_enter.body[-2]), "self._state = 2")
        self.assertIsNone(failed_enter.body[-1].exc)

        exiting = definition(scope, "__exit__")
        self.assert_shape(assigned(exiting, "binding"), "self._entry_binding")
        self.assert_shape(assigned(exiting, "scope"),
                          "binding[2] if type(binding) is tuple and len(binding) == 3 else self._scope")
        failure, = [node for node in exiting.body if isinstance(node, ast.If)]
        self.assert_shape(failure.test, "kind is not None")
        self.assert_shape(call(failure, "scope.__exit__"), "scope.__exit__(kind, error, traceback)")
        self.assertFalse(calls(failure, "self._require"))
        self.assertFalse(calls(failure, "_callback"))
        self.assertEqual(ast.unparse(failure.body[-2]), "self._state = 2")
        self.assert_shape(failure.body[-1].value, "False")
        leave = definition(exiting, "leave")
        self.assert_shape(assigned(leave, "exited"), "True")
        self.assert_shape(assigned(leave, "value"), "scope.__exit__(None, None, None)")
        self.assertLess(assigned(leave, "exited").lineno, assigned(leave, "value").lineno)
        self.assertEqual([ast.unparse(node) for node in calls(leave, "self._require")],
                         ["self._require(binding, scope, 1)"] * 2)
        cleanup, = [node for node in exiting.body if isinstance(node, ast.Try)]
        self.assert_shape(call(cleanup, "binding[1]._call"), "binding[1]._call(leave)")
        self.assert_shape(cleanup.handlers[0].body[0].test, "not exited")
        self.assert_shape(call(cleanup.handlers[0], "scope.__exit__"),
                          "scope.__exit__(type(exc), exc, exc.__traceback__)")
        self.assertIsNone(cleanup.handlers[0].body[-1].exc)
        self.assertEqual([ast.unparse(node) for node in cleanup.finalbody], ["self._state = 2"])
        self.assert_shape(exiting.body[-1].value, "False")

    def test_outer_owner_closes_on_all_failures_and_never_retries_an_already_completed_exit(self):
        guarded, = [node for node in self.runner_body.body if isinstance(node, ast.Try)]
        self.assertEqual([ast.unparse(node.type) for node in guarded.handlers],
            ["reader.roots.RevocationRootReadError", "BaseException"])
        for handler in guarded.handlers:
            self.assert_shape(handler.body[0].value, "reader._close_after_failure(connection)")
        self.assert_shape(guarded.handlers[0].body[1].exc, "RevocationWriterConnectionError(str(exc))")
        self.assert_shape(guarded.handlers[0].body[1].cause, "exc")
        self.assertIsNone(guarded.handlers[1].body[1].exc)
        closed = guarded.body[-2]
        self.assert_shape(closed.test, "_callback(work, lambda: connection.closed) is not True")
        self.assert_shape(guarded.body[-1].value, "result")
        _, reader = source("catchplate/authority_revocation_root_reader.py")
        context = definition(reader, "_context")
        entered = definition(context, "enter")
        self.assert_shape(assigned(entered, "value"), "manager.__enter__()")
        self.assert_shape(assigned(entered, "entered"), "True")
        self.assertLess(assigned(entered, "value").lineno, assigned(entered, "entered").lineno)
        leave = next(node for node in ast.walk(context) if isinstance(node, ast.FunctionDef) and node.name == "leave")
        self.assert_shape(assigned(leave, "exited"), "True")
        self.assert_shape(leave.body[-1].value, "manager.__exit__(None, None, None)")
        self.assertLess(assigned(leave, "exited").lineno, leave.body[-1].lineno)
        self.assertEqual(len(calls(context, "roots._callback")), 2)
        self.assertEqual(ast.unparse(calls(context, "roots._callback")[-1]), "roots._callback(work, leave)")
        no_retry, = [node for node in ast.walk(context) if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "not exited"]
        self.assertEqual(len(calls(no_retry, "manager.__exit__")), 1)
        for forbidden in ("connection.commit", "connection.rollback", "connection.reset", "psycopg.connect"):
            self.assertFalse(calls(self.tree, forbidden))

    def test_real_runner_owns_inputs_and_checks_actual_db_role_before_opening(self):
        runner = definition(self.persistence, "_run_on_configuration")
        owned = call(runner, "_inputs_from_configuration")
        self.assert_shape(owned, "_inputs_from_configuration(configuration, expectations, work)")
        db_import, = [node for node in runner.body if isinstance(node, ast.ImportFrom)
            and node.module == "catchplate" and [(item.name, item.asname) for item in node.names] == [("db", None)]]
        role_guard, = [node for node in runner.body if isinstance(node, ast.If)]
        self.assert_shape(role_guard.test, "configuration[6][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE")
        self.assert_shape(role_guard.body[0].exc,
            "ValueError('revocation writer role differs from the actual database contract')")
        opening = call(runner, "_connect")
        self.assert_shape(opening, "_connect(work, lambda: psycopg.connect(dsn, row_factory=dict_row, "
            "connect_timeout=timeout, autocommit=False, options='-c search_path=pg_catalog'))")
        delegated = call(runner, "writer_connection._run_on_connection")
        self.assert_shape(delegated, "writer_connection._run_on_connection(connection, "
            "database_identity=configuration[6], work=work, operation=operation, arguments=arguments, expectations=owned)")
        order = (owned, db_import, role_guard, opening, delegated)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        self.assertFalse(calls(runner, "operation"))
        self.assertFalse(calls(runner, "_ValidationWork"))

    def test_issuer_connector_and_legacy_service_routes_are_not_repurposed(self):
        _, issuer = source("catchplate/authority_revocation_issuance.py")
        issuer_run = definition(issuer, "_run_on_configuration")
        self.assert_shape(call(issuer_run, "persistence._connect"), "persistence._connect(work, opener)")
        self.assertFalse(calls(issuer_run, "writer_connection._run_on_connection"))
        issuer_owner = definition(issuer, "RevocationCapabilityIssuer")
        for name in ("issue", "issue_authenticated"):
            method = definition(issuer_owner, name)
            self.assertEqual(len(calls(method, "db._policy_authority_capability_issuer_pg_connect_raw")), 1)
        _, service = source("catchplate/authority_service.py", 2 * 1024 * 1024)
        handle = definition(definition(service, "AuthorityProcess"), "handle")
        writer_branch, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        verification = call(writer_branch, "self._verify_internal_envelope")
        purposes, = [keyword.value for keyword in verification.keywords if keyword.arg == "allowed_purposes"]
        self.assert_shape(purposes, "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        self.assertFalse(calls(handle, "writer_connection._run_on_connection"))
        self.assertFalse(calls(handle, "RevocationPlannerPersistence"))
        # Do not describe the unchanged legacy gate as newly TLS-admitted.
        _, legacy = source("catchplate/authority_store/planner_connection.py")
        admission = definition(legacy, "_require_planner_writer")
        self.assertEqual([ast.unparse(node.func) for node in calls(admission, "_require_postgres_connection")],
                         ["_require_postgres_connection"])
        self.assertEqual(len(calls(admission, "_require_serializable")), 1)
        self.assertEqual(len(calls(admission, "_require_database_role")), 1)
        self.assertFalse(calls(admission, "planner_writer_privilege_check"))


if __name__ == "__main__":
    unittest.main()
