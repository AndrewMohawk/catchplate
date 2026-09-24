#!/usr/bin/env python3
"""Nonimporting linkage for private raw transport and configured issuance.

These controls inspect real source, not an admitted process or socket. They do
not prove root signatures, launch custody, PostgreSQL ACLs or a public route.
The inert mapping factory is not a replacement for measured service admission.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path, maximum=256 * 1024):
    target = ROOT / path
    if target.stat().st_size > maximum:
        raise AssertionError("private service source exceeds its inspection bound")
    source = target.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=path)


def definition(tree, name):
    found = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name]
    if len(found) != 1:
        raise AssertionError("private service definition is not unique: " + name)
    return found[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == name), key=lambda node: (node.lineno, node.col_offset))


def assigned(tree, name):
    values = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(values) != 1:
        raise AssertionError("private service assignment is not unique: " + name)
    return values[0]


class RevocationServiceSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw_source, cls.raw = read("serverware/authority_transport.py", 64 * 1024)
        cls.service_source, cls.service = read("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_fixed_raw_invocation_bounds_precede_body_allocation_without_parsing(self):
        receive = definition(self.raw, "_recv_revocation_invocation_bytes")
        send = definition(self.raw, "_socket_request_revocation_bytes")
        self.shape(receive.body[0].value,
            "_recv_message_bytes(connection, maximum_bytes=authority_contract.MAX_REQUEST_BYTES)")
        self.shape(send.body[0].value, """_socket_request_bytes(path, encoded,
            timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
            expected_peer_gid=expected_peer_gid, maximum_bytes=authority_contract.MAX_REQUEST_BYTES)""")
        self.assertEqual([argument.arg for argument in receive.args.args], ["connection"])
        self.assertEqual([argument.arg for argument in send.args.kwonlyargs],
            ["timeout_seconds", "expected_peer_uid", "expected_peer_gid"])
        framing = definition(self.raw, "_recv_message_bytes")
        self.shape(assigned(framing, "size"), "int.from_bytes(_recv_exact(connection, 8), 'big')")
        guard = [node for node in framing.body if isinstance(node, ast.If)]
        self.assertEqual(len(guard), 1)
        self.shape(guard[0].test, "not 2 <= size <= maximum_bytes")
        reads = calls(framing, "_recv_exact")
        self.assertEqual(len(reads), 2)
        self.assertLess(reads[0].lineno, guard[0].lineno)
        self.assertLess(guard[0].end_lineno, reads[1].lineno)
        self.shape(reads[1], "_recv_exact(connection, size)")
        limits = definition(self.raw, "_maximum_bytes")
        self.shape(limits.body[0].test,
            "type(maximum_bytes) is not int or not 2 <= maximum_bytes <= authority_contract.MAX_RESULT_BYTES")
        _source, authority = read("serverware/authority_contract.py")
        self.shape(assigned(authority, "MAX_REQUEST_BYTES"), "4 * 1024 * 1024")
        self.shape(assigned(authority, "MAX_RESULT_BYTES"), "64 * 1024 * 1024")
        imports = [node for node in self.raw.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual([ast.unparse(node) for node in imports], ["from __future__ import annotations",
            "import socket", "import struct", "from serverware import authority_contract"])
        for parser in ("json.loads", "_canonical", "bytes", "_verify_invocation_on_work"):
            self.assertFalse(calls(self.raw, parser))

    def test_actual_raw_socket_checks_peer_before_exact_send_and_closes_every_opened_path(self):
        worker = definition(self.raw, "_socket_request_bytes")
        opened = calls(worker, "socket.socket")
        self.assertEqual(len(opened), 1)
        self.shape(opened[0], "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
        guard = [node for node in worker.body if isinstance(node, ast.If)]
        self.assertEqual(len(guard), 1)
        self.shape(guard[0].test, "type(encoded) is not bytes or not 2 <= len(encoded) <= maximum_bytes")
        self.assertLess(guard[0].end_lineno, opened[0].lineno)
        scopes = [node for node in worker.body if isinstance(node, ast.Try)]
        self.assertEqual(len(scopes), 1)
        scope = scopes[0]
        self.assertEqual(scope.handlers, [])
        self.assertEqual(scope.orelse, [])
        self.assertEqual(len(scope.finalbody), 1)
        self.shape(scope.finalbody[0].value, "connection.close()")
        self.shape(scope.body[0].value, "connection.settimeout(timeout_seconds)")
        self.shape(scope.body[1].value, "connection.connect(path)")
        peer = calls(scope, "_peer_identity")
        self.assertEqual(len(peer), 1)
        denied = [node for node in scope.body if isinstance(node, ast.If)]
        self.assertEqual(len(denied), 1)
        self.shape(denied[0].test, "peer_uid != expected_peer_uid or peer_gid != expected_peer_gid")
        sent = calls(scope, "_send_encoded_message")
        self.assertEqual(len(sent), 1)
        self.shape(sent[0], "_send_encoded_message(connection, encoded, maximum_bytes=maximum_bytes)")
        self.assertLess(peer[0].lineno, denied[0].lineno)
        self.assertLess(denied[0].end_lineno, sent[0].lineno)
        self.shape(scope.body[-1].value, "_recv_message_bytes(connection, maximum_bytes=maximum_bytes)")
        self.assertFalse(any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(worker)))

    def test_service_helpers_delegate_actual_transport_and_translate_only_its_dedicated_error(self):
        for name in ("_peer_identity", "_recv_exact", "_recv_message_bytes", "_send_encoded_message",
                "_recv_revocation_invocation_bytes", "_socket_request_revocation_bytes"):
            with self.subTest(helper=name):
                wrapper = definition(self.service, name)
                scopes = [node for node in wrapper.body if isinstance(node, ast.Try)]
                self.assertEqual(len(scopes), 1)
                scope = scopes[0]
                self.assertEqual(len(scope.handlers), 1)
                self.shape(scope.handlers[0].type, "authority_transport.AuthorityTransportError")
                denial = scope.handlers[0].body[0]
                self.assertIsInstance(denial, ast.Raise)
                self.shape(denial.exc, "AuthorityServiceError(str(exc))")
                self.shape(denial.cause, "exc")
                self.assertEqual(len(calls(wrapper, "authority_transport." + name)), 1)
                self.assertFalse(calls(wrapper, "_canonical"))
                self.assertFalse(calls(wrapper, "json.loads"))
        legacy = definition(self.service, "_recv_message_with_bytes")
        self.shape(assigned(legacy, "encoded"), "_recv_message_bytes(connection)")
        self.shape(assigned(legacy, "value"), "json.loads(encoded)")
        self.shape(legacy.body[-1].value, "(encoded, value)")
        self.shape(definition(self.service, "_recv_message_bytes").args.kw_defaults[0], "MAX_MESSAGE_BYTES")
        self.shape(assigned(self.service, "MAX_MESSAGE_BYTES"), "authority_contract.MAX_RESULT_BYTES")

    def test_private_factory_is_linked_to_actual_measured_load_and_active_issuer_context(self):
        factory = definition(self.process, "_revocation_capability_issuer")
        self.assertEqual([argument.arg for argument in factory.args.args], ["self"])
        self.assertEqual([argument.arg for argument in factory.args.kwonlyargs], ["work"])
        self.assertIsNone(factory.args.kwarg)
        guards = [node for node in factory.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 1)
        self.shape(guards[0].test, '''self.role_name != "issuer"
            or self.process_mode != "policy-authority-issuer"
            or type(self.configuration) is not MeasuredConfiguration''')
        active = calls(factory, "authority_launch_guard.require_active")
        generation = calls(factory, "authority_launch_guard.generation")
        mapped = calls(factory, "authority_revocation_configuration._issuer_from_configuration_on_work")
        self.assertEqual((len(active), len(generation), len(mapped)), (1, 1, 1))
        self.shape(active[0], 'authority_launch_guard.require_active("issuer")')
        self.shape(assigned(factory, "generation"), "dict(authority_launch_guard.generation())")
        self.shape(mapped[0], """authority_revocation_configuration._issuer_from_configuration_on_work(
            payload=payload, configuration_digest=configuration_digest, generation=generation, work=work)""")
        self.assertLess(guards[0].end_lineno, active[0].lineno)
        self.assertLess(active[0].lineno, generation[0].lineno)
        self.assertLess(generation[0].lineno, mapped[0].lineno)
        main = definition(self.service, "main")
        loaded = calls(main, "MeasuredConfiguration.load")
        process = calls(main, "AuthorityProcess")
        self.assertEqual((len(loaded), len(process)), (1, 1))
        self.shape(loaded[0], "MeasuredConfiguration.load(role=args.role)")
        self.shape(process[0], "AuthorityProcess(role=args.role, configuration=configuration)")
        self.assertLess(loaded[0].lineno, process[0].lineno)
        load = definition(definition(self.service, "MeasuredConfiguration"), "load")
        verified = calls(load, "root_key.verify")
        self.assertEqual(len(verified), 1)
        checks = [calls(load, "configuration." + name)[0] for name in
            ("_verify_generation_binding", "_verify_role_topology", "_verify_runtime_closure", "_verify_attestation")]
        self.assertLess(verified[0].lineno, checks[0].lineno)
        self.assertEqual([call.lineno for call in checks], sorted(call.lineno for call in checks))
        self.assertLess(checks[-1].lineno, load.body[-1].lineno)
        # These links inspect the real admission chain; a constructed dataclass
        # in a component fixture is deliberately not a positive admission proof.
        self.assertFalse(calls(definition(self.process, "__init__"), "self._revocation_capability_issuer"))

    def test_factory_owns_original_config_and_launch_pins_with_configuration_only_float_support(self):
        _source, module = read("serverware/authority_revocation_configuration.py")
        factory = definition(module, "_issuer_from_configuration_on_work")
        self.assertEqual([argument.arg for argument in factory.args.kwonlyargs],
            ["payload", "configuration_digest", "generation", "work"])
        self.assertIsNone(factory.args.kwarg)
        self.assertEqual(ast.literal_eval(assigned(module, "_GENERATION_FIELDS")),
            ("schema", "sequence", "digest", "predecessorDigest", "minimumRollbackSequence",
             "operationManifestDigest", "configurationDigests"))
        self.assertEqual(ast.literal_eval(assigned(module, "MAX_CONFIGURATION_DIGESTS")), 4096)
        bounded = calls(factory, "capability.shape._bounded_object")
        self.assertEqual(len(bounded), 1)
        self.shape(bounded[0], 'capability.shape._bounded_object(generation, 20, "issuer launch context")')
        self.shape(assigned(factory, "owned"), "_ConfigurationCapture(ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)")
        self.shape(assigned(factory, "launch"), """capability.capture._JSONCapture(ledger,
            maximum_bytes=authority.MAX_REQUEST_BYTES).visit({name: generation[name] for name in _GENERATION_FIELDS})""")
        self.assertLess(bounded[0].lineno, assigned(factory, "launch").lineno)
        keys = calls(factory, "_key")
        self.assertEqual(len(keys), 3)
        self.shape(keys[0], '_key(planner["signingPublicKeyBase64Url"], work, expected_spki=planner["signingSpkiDigest"])')
        self.shape(keys[1], '_key(verifier["signingPublicKeyBase64Url"], work, expected_spki=verifier["signingSpkiDigest"])')
        self.shape(keys[2], '_key(witness["signingPublicKeyBase64Url"], work)')
        self.assertLess(assigned(factory, "owned").lineno, keys[0].lineno)
        self.assertLess(assigned(factory, "launch").lineno, keys[0].lineno)
        self.shape(assigned(factory, "encoded"), "_configuration_wire(owned, ledger)")
        self.shape(assigned(factory, "computed"), "capability.plan._frame(CONFIG_SCHEMA, (encoded,), work)")
        self.shape(assigned(factory, "verifier_session"), '''_frame_text(_VERIFIER_SESSION,
            (configuration_digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]), work)''')
        self.shape(assigned(factory, "issuer_session"), '''_frame_text(_ISSUER_SESSION,
            (issuer["databaseRole"], issuer["tlsClientDn"], issuer["tlsClientSerial"], issuer["tlsIssuerDn"],
             issuer["measurementDigest"], issuer["attestationReceiptDigest"], owned["issuerCredentialIssuanceDigest"]), work)''')
        owners = calls(factory, "configured.RevocationCapabilityIssuer")
        self.assertEqual(len(owners), 1)
        options = {keyword.arg: keyword.value for keyword in owners[0].keywords}
        self.assertEqual(set(options), {"planner_public_key", "verifier_public_key", "witness_public_key",
            "expected_planner_identity", "expected_verifier_identity", "expected_issuer_session_identity_digest",
            "issuer_pins", "expected_configuration_digest", "expected_witness_identity_digest",
            "expected_generation_sequence", "expected_generation_digest"})
        for name, value in (("planner_public_key", "planner_key"), ("verifier_public_key", "verifier_key"),
                ("witness_public_key", "witness_key"), ("expected_issuer_session_identity_digest", "issuer_session"),
                ("expected_configuration_digest", "configuration_digest"), ("expected_generation_sequence", 'launch["sequence"]'),
                ("expected_generation_digest", 'launch["digest"]')):
            self.shape(options[name], value)
        generation = definition(module, "_generation_binding")
        self.assertEqual(len(calls(generation, "work.prepare_scan")), 1)
        self.assertFalse(calls(generation, "sorted"))
        self.assertFalse(calls(generation, "set"))
        self.assertIn("previous >= digest", ast.unparse(generation))
        self.assertIn("digest == configuration_digest", ast.unparse(generation))
        self.shape(assigned(factory, "maximum_age_ns"), "min(issuer['maximumInternalAgeNs'], authority.VERIFIER_RESPONSE_MAX_AGE_NS)")
        self.shape(assigned(factory, "maximum_clock_skew_ns"), "authority.VERIFIER_MAX_CLOCK_SKEW_NS")
        _source, authority = read("serverware/authority_contract.py")
        self.shape(assigned(authority, "VERIFIER_RESPONSE_MAX_AGE_NS"), "30 * 1_000_000_000")
        self.shape(assigned(authority, "VERIFIER_MAX_CLOCK_SKEW_NS"), "5 * 1_000_000_000")
        _source, database = read("serverware/db.py", 4 * 1024 * 1024)
        self.shape(assigned(database, "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS"), "authority_contract.VERIFIER_RESPONSE_MAX_AGE_NS")
        self.shape(assigned(database, "_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS"), "authority_contract.VERIFIER_MAX_CLOCK_SKEW_NS")
        capture = definition(module, "_ConfigurationCapture")
        self.assertEqual([ast.unparse(base) for base in capture.bases], ["capability.capture._JSONCapture"])
        visit = definition(capture, "visit")
        self.shape(visit.body[0].test, "type(value) is float")
        self.shape(visit.body[0].body[0].test, "depth > capability.capture.MAX_JSON_DEPTH or not math.isfinite(value)")
        self.shape(visit.body[-1].value, "super().visit(value, depth, ancestors)")
        wire = definition(module, "_configuration_wire")
        self.shape(assigned(wire, "measured"), "_ConfigurationCapture(ledger, maximum_bytes=authority.MAX_REQUEST_BYTES, retain=False)")
        dumped = calls(wire, "json.dumps")
        self.assertEqual(len(dumped), 1)
        self.shape(dumped[0], 'json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)')
        charge = calls(wire, "ledger.charge")
        self.assertEqual(len(charge), 1)
        self.assertLess(calls(wire, "measured.visit")[0].lineno, charge[0].lineno)
        self.assertLess(charge[0].lineno, dumped[0].lineno)
        canonical = definition(self.service, "_canonical")
        service_dump = calls(canonical, "json.dumps")[0]
        options = {keyword.arg: keyword.value for keyword in service_dump.keywords}
        for name, value in (("ensure_ascii", "True"), ("sort_keys", "True"), ("allow_nan", "False"), ("separators", '(",", ":")')):
            self.shape(options[name], value)
        _source, proof = read("serverware/authority_complete_query_batch.py")
        proof_visit = definition(definition(proof, "_JSONCapture"), "visit")
        self.assertIn("kind not in (dict, list)", ast.unparse(proof_visit))
        self.assertFalse(any(isinstance(node, ast.Name) and node.id == "float" for node in ast.walk(proof_visit)))

    def test_private_original_byte_composition_does_not_register_or_open_a_public_route(self):
        private = definition(self.process, "_issue_revocation_invocation_bytes")
        self.assertEqual([argument.arg for argument in private.args.kwonlyargs], ["envelope_bytes", "work"])
        self.assertIsNone(private.args.kwarg)
        guards = [node for node in private.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 1)
        self.shape(guards[0].test, "type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= authority_contract.MAX_REQUEST_BYTES")
        factory = calls(private, "self._revocation_capability_issuer")
        issued = calls(private, "issuer.issue_authenticated")
        self.assertEqual((len(factory), len(issued)), (1, 1))
        self.shape(factory[0], "self._revocation_capability_issuer(work=work)")
        self.shape(issued[0], "issuer.issue_authenticated(envelope_bytes=envelope_bytes, work=work)")
        self.assertLess(guards[0].end_lineno, factory[0].lineno)
        self.assertLess(factory[0].lineno, issued[0].lineno)
        self.assertEqual(calls(self.process, "self._revocation_capability_issuer"), factory)
        self.assertEqual(calls(self.service, "issuer.issue_authenticated"), issued)
        for forbidden in ("_canonical", "json.loads", "_verify_internal_envelope", "_ValidationWork", "_socket_request"):
            self.assertFalse(calls(private, forbidden))
        server = definition(self.service, "AuthorityServer")
        for dispatcher in (definition(self.process, "handle"), definition(server, "_serve_connection")):
            for name in ("issue-revocation-capability", "_issue_revocation_invocation_bytes", "_revocation_capability_issuer",
                    "_recv_revocation_invocation_bytes", "issue_authenticated"):
                self.assertNotIn(name, ast.unparse(dispatcher))
        registry, _tree = read("serverware/authority_transition_registry.py")
        self.assertNotIn("issue-revocation-capability", registry)
        self.assertNotIn("authority_revocation_configuration", registry)


if __name__ == "__main__":
    unittest.main()
