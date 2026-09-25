#!/usr/bin/env python3
"""Nonimporting linkage for the private measured writer-owner factory.

Bounded source inspection does not execute an extracted mapper, import the
active service/registry, or prove launch, TLS, ACL, transaction or retention
admission. The factory returns a configured owner, not an admitted action or
verification result. No original-byte transport or public route is enabled.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


class RevocationWriterConfigurationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_writer_configuration.py", 64 * 1024)
        cls.service_text, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.adapter = definition(cls.process, "_revocation_planner_persistence")
        cls.continuation = definition(cls.service, "_revocation_writer_from_owned_configuration")
        _, cls.persistence = source("serverware/authority_revocation_persistence.py", 64 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_factory_only_service_boundary_owns_full_configuration_before_ordered_callbacks(self):
        adapter = self.adapter
        self.assertEqual([item.arg for item in adapter.args.args], ["self"])
        self.assertEqual([item.arg for item in adapter.args.kwonlyargs], ["work"])
        self.assertEqual(adapter.args.kw_defaults, [None])
        self.assertIsNone(adapter.args.kwarg)
        self.assertIsNone(adapter.args.vararg)
        guards = [node for node in adapter.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 2)
        self.shape(guards[0].test, '''self.role_name != "planner-writer"
            or self.process_mode != "policy-authority-planner-writer"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.shape(assigned(adapter, "configuration"), "self.configuration")
        payload_pin, = [node for node in adapter.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                    == ["payload", "configuration_digest"] for target in node.targets)]
        self.shape(payload_pin.value, "(configuration.payload, configuration.digest)")
        ledger = call(adapter, "authority_revocation_configuration.capability.capture._SharedLedger")
        self.shape(ledger, "authority_revocation_configuration.capability.capture._SharedLedger(work)")
        digest = call(adapter, "authority_revocation_configuration.capability.shape._digest")
        self.shape(digest, "authority_revocation_configuration.capability.shape._digest(configuration_digest)")
        self.shape(guards[1].test, "type(payload) is not dict")
        owned = assigned(adapter, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        delegated = call(adapter, "_revocation_writer_from_owned_configuration")
        self.shape(delegated, '''_revocation_writer_from_owned_configuration(
            owned_payload=owned_payload, configuration_digest=configuration_digest, work=work)''')
        pair, = [node for node in adapter.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                    == ["persistence", "_held_launch"] for target in node.targets)]
        self.assertIs(pair.value, delegated)
        self.shape(adapter.body[-1].value, "persistence")
        self.assertFalse(calls(adapter, "authority_revocation_configuration.production._callback"))
        continuation = self.continuation
        self.assertEqual(continuation.args.args, [])
        self.assertEqual([item.arg for item in continuation.args.kwonlyargs],
                         ["owned_payload", "configuration_digest", "work"])
        self.assertIsNone(continuation.args.kwarg)
        self.assertIsNone(continuation.args.vararg)
        callbacks = calls(continuation, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(callbacks), 3)
        for actual, expected in zip(callbacks, (
                'authority_revocation_configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner-writer"))',
                '''authority_revocation_configuration.production._callback(work,
                    lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))''',
                'authority_revocation_configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))')):
            self.shape(actual, expected)
        self.assertIs(assigned(continuation, "persistence_dsn"), callbacks[1])
        self.assertIs(assigned(continuation, "generation"), callbacks[2])
        mapped = call(continuation, "authority_revocation_writer_configuration._persistence_from_configuration_on_work")
        self.shape(mapped, '''authority_revocation_writer_configuration._persistence_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest,
            generation=generation, persistence_dsn=persistence_dsn, work=work)''')
        self.assertIs(assigned(continuation, "persistence"), mapped)
        held = assigned(continuation, "held_launch")
        self.shape(held, '(generation["sequence"], generation["digest"])')
        self.shape(continuation.body[-1].value, "(persistence, held_launch)")
        self.assertLess(callbacks[2].lineno, held.lineno)
        self.assertLess(held.lineno, mapped.lineno)
        ordered = (guards[0], assigned(adapter, "configuration"), payload_pin, ledger,
                   digest, guards[1], owned, delegated)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertEqual([node.lineno for node in (*callbacks, mapped)],
                         sorted(node.lineno for node in (*callbacks, mapped)))
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == "self"
                             for node in ast.walk(continuation)))
        self.assertEqual([node.attr for node in sorted((node for node in ast.walk(adapter)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "self"), key=lambda node: (node.lineno, node.col_offset))],
            ["role_name", "process_mode", "configuration", "configuration"])
        for spelling in ("_ValidationWork", "QueryReadValidationLimits", "self._sign_internal",
                "_socket_request", "_socket_request_revocation_bytes", "time.time_ns", "time.monotonic_ns"):
            self.assertFalse(calls(adapter, spelling))
        self.assertFalse(calls(self.service, "self._revocation_planner_persistence"))

    def test_mapper_captures_shared_commitment_and_derives_only_measured_writer_connection_pins(self):
        imports = [(node.module, tuple((item.name, item.asname) for item in node.names))
            for node in self.tree.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(imports, [("__future__", (("annotations", None),)),
            ("serverware", (("authority_revocation_configuration", "configuration"),)),
            ("serverware", (("authority_revocation_persistence", "persistence"),)),
            ("serverware", (("authority_revocation_plan", "plan"),)),
            ("serverware", (("authority_revocation_writer_connection", "writer"),))])
        self.assertEqual([[item.name for item in node.names] for node in self.tree.body if isinstance(node, ast.Import)],
                         [["math"]])
        factory = definition(self.tree, "_persistence_from_configuration_on_work")
        self.assertEqual(factory.args.args, [])
        self.assertEqual([item.arg for item in factory.args.kwonlyargs],
            ["payload", "configuration_digest", "generation", "persistence_dsn", "work"])
        self.assertTrue(all(value is None for value in factory.args.kw_defaults))
        self.assertIsNone(factory.args.kwarg)
        self.assertIsNone(factory.args.vararg)
        body, = [node for node in factory.body if isinstance(node, ast.Try)]
        capture = call(factory, "configuration._capture_configuration_on_work")
        self.assertIs(body.body[0].value, capture)
        self.shape(capture, '''configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        dsn = call(factory, "writer.reader._bounded_text")
        self.shape(dsn, "writer.reader._bounded_text(persistence_dsn, 65536)")
        self.shape(body.body[2].test, r"'\n' in persistence_dsn or '\r' in persistence_dsn")
        self.shape(assigned(factory, "roles"), 'owned["roles"]')
        role_sources, = [node for node in ast.walk(factory) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                    == ["planner", "verifier", "writer_role"] for target in node.targets)]
        self.shape(role_sources.value, '(roles[name] for name in ("planner", "verifier", "planner-writer"))')
        roles, = [node for node in ast.walk(factory) if isinstance(node, ast.For)
                  and ast.unparse(node.target) == "(name, role)"]
        self.shape(roles.iter, '(("planner", planner), ("verifier", verifier), ("planner-writer", writer_role))')
        self.shape(roles.body[0].test, "type(role) is not dict")
        self.shape(call(roles, "plan.contract._literal"),
                   'plan.contract._literal(role["processMode"], "policy-authority-" + name)')
        fields, = [node for node in roles.body if isinstance(node, ast.For)]
        self.shape(fields.iter, '("measurementDigest", "attestationReceiptDigest", "responseSigningSpkiDigest")')
        timeouts = sorted((node for node in ast.walk(factory) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "timeout" for target in node.targets)),
            key=lambda node: node.lineno)
        self.assertEqual(len(timeouts), 2)
        self.shape(timeouts[0].value, 'writer_role["databaseConnectTimeoutSeconds"]')
        self.shape(timeouts[1].value, "int(timeout)")
        timeout_guard, = [node for node in ast.walk(factory) if isinstance(node, ast.If)
                         and "math.isfinite(timeout)" in ast.unparse(node.test)]
        self.shape(timeout_guard.test, '''type(timeout) not in (int, float)
            or (type(timeout) is float and not math.isfinite(timeout)) or not 2 <= timeout <= 300''')
        identity = assigned(factory, "database_identity")
        self.shape(identity, '''(writer_role["databaseRole"], writer_role["tlsClientDn"],
            writer_role["tlsClientSerial"], writer_role["tlsIssuerDn"])''')
        validated = call(factory, "writer._validate_database_identity")
        self.shape(validated, "writer._validate_database_identity(database_identity)")
        first_key = calls(factory, "configuration._key")[0]
        order = (capture, dsn, roles, timeouts[0], timeout_guard, timeouts[1], identity, validated, first_key)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        _, shared = source("serverware/authority_revocation_configuration.py", 64 * 1024)
        prefix = definition(shared, "_capture_configuration_on_work")
        self.shape(call(prefix, "capability.plan._same"), '''capability.plan._same(
            computed, configuration_digest, work, "issuer configuration commitment changed")''')
        self.shape(call(prefix, "_generation_binding"), "_generation_binding(owned, launch, configuration_digest, work)")
        _, connection = source("serverware/authority_revocation_writer_connection.py", 64 * 1024)
        self.assertEqual(assigned(connection, "_ROLE").value, "serverware_policy_authority_planner_writer")
        self.shape(definition(connection, "_validate_database_identity").body[-1].test, "identity[0] != _ROLE")

    def test_exact_planner_aliases_precede_two_real_keys_and_genuine_seven_setting_owner(self):
        factory = definition(self.tree, "_persistence_from_configuration_on_work")
        comparisons = calls(factory, "plan._same")
        self.assertEqual(len(comparisons), 3)
        self.shape(comparisons[0], '''plan._same(role["responseSigningSpkiDigest"],
            role["signingSpkiDigest"], work, "revocation writer key differs from its measured response pin")''')
        response_loop, = [node for node in ast.walk(factory) if isinstance(node, ast.For)
                         and any(item is comparisons[0] for item in ast.walk(node))]
        self.shape(response_loop.iter, "(planner, verifier)")
        self.shape(comparisons[1], '''plan._same(owned["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST,
            work, "revocation writer configuration differs from the source query manifest")''')
        self.shape(comparisons[2], '''plan._same(
            (writer_role["plannerSessionIdentityDigest"], writer_role["plannerSigningSpkiDigest"],
             writer_role["plannerSigningPublicKeyBase64Url"]),
            (planner["plannerSessionIdentityDigest"], planner["signingSpkiDigest"],
             planner["signingPublicKeyBase64Url"]), work,
            "revocation writer planner aliases differ from the configured planner")''')
        keys = calls(factory, "configuration._key")
        self.assertEqual(len(keys), 2)
        for node, role in zip(keys, ("planner", "verifier")):
            self.shape(node, 'configuration._key(' + role + '["signingPublicKeyBase64Url"], work, '
                       'expected_spki=' + role + '["signingSpkiDigest"])')
            self.assertIs(assigned(factory, role + "_key"), node)
        session = call(factory, "configuration._frame_text")
        self.shape(session, '''configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]), work)''')
        self.assertIs(assigned(factory, "verifier_session"), session)
        constructed = call(factory, "persistence.RevocationPlannerPersistence")
        self.shape(constructed, '''persistence.RevocationPlannerPersistence(
            persistence_dsn=persistence_dsn, connect_timeout_seconds=timeout,
            planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_planner_identity={"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
                "measurementDigest": planner["measurementDigest"], "attestationReceiptDigest": planner["attestationReceiptDigest"]},
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier["measurementDigest"], "attestationReceiptDigest": verifier["attestationReceiptDigest"]},
            writer_database_identity=database_identity)''')
        order = (*comparisons, *keys, session, constructed)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        body, = [node for node in factory.body if isinstance(node, ast.Try)]
        self.assertIs(body.body[-1].value, constructed)
        for spelling in ("_ValidationWork", "QueryReadValidationLimits", "_read_dsn_descriptor",
                "Ed25519PrivateKey.from_private_bytes", "time.time_ns", "time.monotonic_ns"):
            self.assertFalse(calls(self.tree, spelling))
        attributes = {node.attr for node in ast.walk(factory) if isinstance(node, ast.Attribute)}
        self.assertTrue(attributes.isdisjoint({"persist", "read", "reserve_execution", "sign", "commit", "rollback"}))

    def test_real_root_signed_loader_and_descriptor_admission_remain_upstream_requirements(self):
        main = definition(self.service, "main")
        loaded, constructed = call(main, "MeasuredConfiguration.load"), call(main, "AuthorityProcess")
        self.shape(loaded, "MeasuredConfiguration.load(role=args.role)")
        self.shape(constructed, "AuthorityProcess(role=args.role, configuration=configuration)")
        self.assertLess(loaded.lineno, constructed.lineno)
        loader = definition(definition(self.service, "MeasuredConfiguration"), "load")
        signature = call(loader, "root_key.verify")
        self.shape(signature, '''root_key.verify(_b64url_decode(envelope["signature"], size=64),
            _domain_digest(SIGNED_CONFIG_SCHEMA, payload_bytes).encode("ascii"))''')
        checks = [call(loader, "configuration." + name) for name in (
            "_verify_generation_binding", "_verify_role_topology", "_verify_runtime_closure", "_verify_attestation")]
        self.assertEqual([node.lineno for node in (signature, *checks)],
                         sorted(node.lineno for node in (signature, *checks)))
        descriptor = definition(self.service, "_read_dsn_descriptor")
        self.shape(call(descriptor, "_read_bounded_descriptor"), '''_read_bounded_descriptor(
            environment_name, maximum=64 * 1024, require_root_owned=False, require_descriptor=True)''')
        reject = definition(self.process, "_reject_wrong_credentials")
        allowed = assigned(reject, "allowed")
        self.assertIsInstance(allowed, ast.Subscript)
        self.shape(allowed.slice, "self.role_name")
        role_values = {key.value: value for key, value in zip(allowed.value.keys, allowed.value.values)}
        self.shape(role_values["planner-writer"], "{'SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD'}")
        self.shape(role_values["planner"], "{'SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD'}")
        self.shape(role_values["verifier"], "{'SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD'}")

    def test_constructed_owner_still_captures_external_fifteen_before_genuine_connection_admission(self):
        owner = definition(self.persistence, "RevocationPlannerPersistence")
        constructor = definition(owner, "__init__")
        self.assertEqual([item.arg for item in constructor.args.kwonlyargs], [
            "persistence_dsn", "connect_timeout_seconds", "planner_public_key", "verifier_public_key",
            "expected_planner_identity", "expected_verifier_identity", "writer_database_identity"])
        snapshot = definition(owner, "_snapshot_configuration")
        self.shape(snapshot.body[1].value, '''(self.persistence_dsn, self.connect_timeout_seconds,
            self.planner_public_key, self.verifier_public_key, self._planner_identity,
            self._verifier_identity, self._database_identity)''')
        inputs = definition(self.persistence, "_inputs_from_configuration")
        self.shape(inputs.body[1].test, "len(expectations) != len(_CALL_INPUTS) or set(expectations) != _CALL_INPUTS")
        self.shape(call(inputs, "store._owned_expectations"), "store._owned_expectations({**expectations, **pins}, work)")
        runner = definition(self.persistence, "_run_on_configuration")
        capture = call(runner, "_inputs_from_configuration")
        self.shape(capture, "_inputs_from_configuration(configuration, expectations, work)")
        db_import, = [node for node in runner.body if isinstance(node, ast.ImportFrom)
            and node.module == "serverware" and [(item.name, item.asname) for item in node.names] == [("db", None)]]
        opening = call(runner, "_connect")
        admission = call(runner, "writer_connection._run_on_connection")
        self.shape(admission, '''writer_connection._run_on_connection(connection,
            database_identity=configuration[6], work=work, operation=operation,
            arguments=arguments, expectations=owned)''')
        self.assertEqual([node.lineno for node in (capture, db_import, opening, admission)],
                         sorted(node.lineno for node in (capture, db_import, opening, admission)))
        # Factory creation does not itself run the old store or capture any
        # caller's future raw bytes, timestamp, independent roots or clocks.
        for spelling in ("store.persist_revocation_planner_record", "store.read_revocation_planner_record",
                "revocation_execution.reserve_revocation_execution_envelope", "_connect", "psycopg.connect"):
            self.assertFalse(calls(self.tree, spelling))
            self.assertFalse(calls(self.adapter, spelling))

    def test_public_dispatch_peer_topology_and_legacy_writer_gate_are_not_replaced(self):
        handle = definition(self.process, "handle")
        server = definition(self.service, "AuthorityServer")
        served = definition(server, "_serve_connection")
        for public in (handle, served):
            self.assertNotIn("_revocation_planner_persistence", ast.unparse(public))
            self.assertNotIn("authority_revocation_writer_configuration", ast.unparse(public))
        branch, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        self.shape(keywords(call(branch, "self._verify_internal_envelope"))["allowed_purposes"],
                   "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        self.assertEqual({node.func.attr for node in ast.walk(branch)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"},
            {"_verify_internal_envelope", "_handle_read_persisted_plan",
             "_handle_reserve_execution_envelope", "_handle_persist_measured_plan"})
        topology = definition(definition(self.service, "MeasuredConfiguration"), "_verify_role_topology")
        peer_join = '''(int(planner_writer.get("peerUid", -1)), int(planner_writer.get("peerGid", -1)))
            != (int(planner["serviceUid"]), int(planner["serviceGid"]))'''
        expected = ast.dump(ast.parse("(" + peer_join + ")", mode="eval").body)
        self.assertEqual(sum(ast.dump(node) == expected for node in ast.walk(topology)
                             if isinstance(node, ast.Compare)), 1)
        peer, = [node for node in ast.walk(served) if isinstance(node, ast.If)
                 and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid"]
        dispatch = call(served, "self.process.handle")
        self.assertLess(peer.lineno, dispatch.lineno)
        _, legacy = source("serverware/authority_store/planner_connection.py", 64 * 1024)
        gate = definition(legacy, "_require_planner_writer")
        self.shape(call(gate, "_require_postgres_connection"), "_require_postgres_connection(connection)")
        self.shape(call(gate, "_require_serializable"), "_require_serializable(raw)")
        self.shape(call(gate, "_require_database_role"),
                   "_require_database_role(raw, _db_value('_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE'))")
        self.assertFalse(calls(gate, "planner_writer_privilege_check"))
        self.assertFalse(calls(gate, "writer_connection._run_on_connection"))


if __name__ == "__main__":
    unittest.main()
