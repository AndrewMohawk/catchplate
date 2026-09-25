#!/usr/bin/env python3
"""Nonimporting linkage for private measured-planner construction.

These bounded source assertions do not import the active service or registry,
execute extracted production bodies, or prove configuration, launch, database
or planning admission. The real loader and lazy planner gates remain required.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import (
    assigned, call, calls, definition, keywords, source,
)


class RevocationPlannerConfigurationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_planner_configuration.py", 64 * 1024)
        cls.service_text, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.adapter = definition(cls.process, "_produce_revocation_observed_plan")
        _, cls.planning = source("serverware/authority_revocation_planning.py", 64 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_private_adapter_snapshots_admitted_configuration_and_signer_before_owned_inputs(self):
        adapter = self.adapter
        self.assertEqual([item.arg for item in adapter.args.args], ["self"])
        self.assertEqual([item.arg for item in adapter.args.kwonlyargs],
            ["request", "evidence", "context", "root_inventory", "work"])
        self.assertTrue(all(value is None for value in adapter.args.kw_defaults))
        self.assertIsNone(adapter.args.kwarg)
        self.assertIsNone(adapter.args.vararg)
        guards = [node for node in adapter.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 3)
        self.shape(guards[0].test, '''self.role_name != "planner"
            or self.process_mode != "policy-authority-planner"
            or type(self.configuration) is not MeasuredConfiguration''')
        configuration = assigned(adapter, "configuration")
        self.shape(configuration, "self.configuration")
        pins = [node for node in adapter.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                == ["payload", "configuration_digest"] for target in node.targets)]
        self.assertEqual(len(pins), 1)
        self.shape(pins[0].value, "(configuration.payload, configuration.digest)")
        signer = assigned(adapter, "planner_private_key")
        self.shape(signer, "self.signing_key")
        self.shape(guards[1].test, "not isinstance(planner_private_key, Ed25519PrivateKey)")
        capture = call(adapter, "authority_revocation_planning._capture_planning_call_inputs")
        self.shape(capture, '''authority_revocation_planning._capture_planning_call_inputs(
            request=request, evidence=evidence, context=context, root_inventory=root_inventory, work=work)''')
        ledger = call(adapter, "authority_revocation_configuration.capability.capture._SharedLedger")
        self.shape(ledger, "authority_revocation_configuration.capability.capture._SharedLedger(work)")
        digest = call(adapter, "authority_revocation_configuration.capability.shape._digest")
        self.shape(digest, "authority_revocation_configuration.capability.shape._digest(configuration_digest)")
        self.shape(guards[2].test, "type(payload) is not dict")
        owned = assigned(adapter, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        ordered = (guards[0], configuration, pins[0], signer, guards[1], capture, ledger, digest, guards[2], owned)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertLess(owned.lineno, calls(adapter, "authority_revocation_configuration.production._callback")[0].lineno)
        self.assertEqual([node.attr for node in sorted((node for node in ast.walk(adapter)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "self"), key=lambda node: (node.lineno, node.col_offset))],
            ["role_name", "process_mode", "configuration", "configuration", "signing_key"])

    def test_guarded_active_read_descriptor_and_last_generation_feed_real_owner_on_same_work(self):
        adapter = self.adapter
        guarded = calls(adapter, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(guarded), 3)
        for actual, expected in zip(guarded, (
                'authority_revocation_configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner"))',
                '''authority_revocation_configuration.production._callback(work,
                    lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"))''',
                'authority_revocation_configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))')):
            self.shape(actual, expected)
        self.assertIs(assigned(adapter, "read_dsn"), guarded[1])
        self.assertIs(assigned(adapter, "generation"), guarded[2])
        factory = call(adapter, "authority_revocation_planner_configuration._planner_from_configuration_on_work")
        self.shape(factory, '''authority_revocation_planner_configuration._planner_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest,
            generation=generation, read_dsn=read_dsn, planner_private_key=planner_private_key, work=work)''')
        produced = call(adapter, "planner.produce_observed")
        self.shape(produced, '''planner.produce_observed(request=owned["request"], evidence=owned["evidence"],
            context=owned["context"], root_inventory=inventory, work=work)''')
        self.assertIs(adapter.body[-1].value, produced)
        generation_statement = next(index for index, node in enumerate(adapter.body)
            if isinstance(node, ast.Assign) and node.value is guarded[2])
        self.assertIs(adapter.body[generation_statement + 1].value, factory)
        self.assertEqual([node.lineno for node in (*guarded, factory, produced)],
            sorted(node.lineno for node in (*guarded, factory, produced)))
        owner = definition(self.planning, "RevocationObservedPlanner")
        method = definition(owner, "produce_observed")
        owned = call(method, "_capture_planning_inputs")
        read = call(method, "_produce_on_read_configuration")
        self.assertLess(owned.lineno, read.lineno)
        self.shape(keywords(read)["work"], "work")
        body = definition(self.planning, "_produce_on_read_configuration")
        self.shape(keywords(call(body, "program._produce_observed_revocation_plan"))["query_work"], "work")
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "_sign_internal", "self._sign_internal",
                "psycopg.connect", "_socket_request", "_socket_request_revocation_bytes"):
            self.assertFalse(calls(adapter, forbidden))
        self.assertNotIn("WRITER_POSTGRES_DSN", ast.unparse(adapter))

    def test_real_loader_and_planner_key_descriptor_precede_private_mapping_without_new_role(self):
        main = definition(self.service, "main")
        loaded = call(main, "MeasuredConfiguration.load")
        process = call(main, "AuthorityProcess")
        self.shape(loaded, "MeasuredConfiguration.load(role=args.role)")
        self.shape(process, "AuthorityProcess(role=args.role, configuration=configuration)")
        self.assertLess(loaded.lineno, process.lineno)
        measured = definition(self.service, "MeasuredConfiguration")
        loader = definition(measured, "load")
        signature = call(loader, "root_key.verify")
        self.shape(signature, '''root_key.verify(_b64url_decode(envelope["signature"], size=64),
            _domain_digest(SIGNED_CONFIG_SCHEMA, payload_bytes).encode("ascii"))''')
        checks = [call(loader, "configuration." + name) for name in (
            "_verify_generation_binding", "_verify_role_topology", "_verify_runtime_closure", "_verify_attestation")]
        self.assertEqual([node.lineno for node in (signature, *checks)],
            sorted(node.lineno for node in (signature, *checks)))
        constructor = definition(self.process, "__init__")
        branches = [node for node in ast.walk(constructor) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "role == 'planner'"]
        self.assertEqual(len(branches), 1)
        branch = branches[0]
        # The following writer elif has its own descriptor. Inspect only the
        # actual planner body while retaining its original parse/SPKI checks.
        planner_body = ast.Module(body=branch.body, type_ignores=[])
        descriptor = call(planner_body, "_read_bounded_descriptor")
        self.shape(descriptor, '''_read_bounded_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_SIGNING_KEY",
            maximum=64 * 1024, require_root_owned=True, require_descriptor=True)''')
        parsed = call(planner_body, "_load_ed25519_private_key")
        self.shape(parsed, "_load_ed25519_private_key(private_value)")
        checked = [node for node in branch.body if isinstance(node, ast.If)]
        self.assertEqual(len(checked), 1)
        self.shape(checked[0].test, '''_public_spki_digest(self.signing_key.public_key())
            != self.role_config.get("signingSpkiDigest")''')
        self.assertLess(descriptor.lineno, parsed.lineno)
        self.assertLess(parsed.lineno, checked[0].lineno)
        handle = definition(self.process, "handle")
        server = definition(self.service, "AuthorityServer")
        for public in (handle, definition(server, "_serve_connection")):
            self.assertNotIn("_produce_revocation_observed_plan", ast.unparse(public))
            self.assertNotIn("authority_revocation_planner_configuration", ast.unparse(public))

    def test_mapper_derives_only_planner_read_identity_and_matching_historical_policy(self):
        factory = definition(self.tree, "_planner_from_configuration_on_work")
        self.assertEqual([item.arg for item in factory.args.kwonlyargs], [
            "payload", "configuration_digest", "generation", "read_dsn", "planner_private_key", "work"])
        self.assertEqual(factory.args.args, [])
        self.assertIsNone(factory.args.kwarg)
        self.assertIsNone(factory.args.vararg)
        prefix = call(factory, "configuration._capture_configuration_on_work")
        self.shape(prefix, '''configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        descriptor = call(factory, "planning.reader._bounded_text")
        self.shape(descriptor, "planning.reader._bounded_text(read_dsn, 65536)")
        self.assertIn("'\\n' in read_dsn or '\\r' in read_dsn", ast.unparse(factory))
        self.assertIn("not isinstance(planner_private_key, Ed25519PrivateKey)", ast.unparse(factory))
        self.shape(assigned(factory, "roles"), 'owned["roles"]')
        role_loop = [node for node in ast.walk(factory) if isinstance(node, ast.For)
            and ast.unparse(node.target) == "(name, role)"]
        self.assertEqual(len(role_loop), 1)
        self.shape(role_loop[0].iter, '(("planner", planner), ("verifier", verifier))')
        self.shape(call(role_loop[0], "plan.contract._literal"),
            'plan.contract._literal(role["processMode"], "policy-authority-" + name)')
        self.shape(call(role_loop[0], "plan._same"), '''plan._same(
            role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
            "observed planner key differs from its measured response pin")''')
        comparisons = calls(factory, "plan._same")
        self.assertEqual(len(comparisons), 2)
        self.shape(comparisons[1], '''plan._same(owned["queryManifestDigest"], plan._QUERY_MANIFEST_DIGEST,
            work, "observed planner configuration differs from the source query manifest")''')
        timeouts = sorted((node for node in ast.walk(factory) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "timeout" for target in node.targets)),
            key=lambda node: node.lineno)
        self.assertEqual(len(timeouts), 2)
        self.shape(timeouts[0].value, 'planner["databaseConnectTimeoutSeconds"]')
        self.shape(timeouts[1].value, "int(timeout)")
        timeout_guard = [node for node in ast.walk(factory) if isinstance(node, ast.If)
            and "math.isfinite(timeout)" in ast.unparse(node.test)]
        self.assertEqual(len(timeout_guard), 1)
        self.shape(timeout_guard[0].test, '''type(timeout) not in (int, float)
            or (type(timeout) is float and not math.isfinite(timeout)) or not 2 <= timeout <= 300''')
        self.assertLess(timeouts[0].lineno, timeout_guard[0].lineno)
        self.assertLess(timeout_guard[0].lineno, timeouts[1].lineno)
        identity = assigned(factory, "database_identity")
        self.shape(identity, '''(planner["databaseRole"], planner["tlsClientDn"],
            planner["tlsClientSerial"], planner["tlsIssuerDn"], planner["plannerSessionIdentityDigest"],
            planner["measurementDigest"], planner["attestationReceiptDigest"])''')
        validated = call(factory, "planning._validate_read_configuration")
        self.shape(validated, "planning._validate_read_configuration((read_dsn, timeout, database_identity, planner_private_key))")
        self.shape(assigned(factory, "webauthn"), 'owned["webauthn"]')
        self.shape(assigned(factory, "assertion_age"), 'webauthn["maximumChallengeAgeNs"]')
        self.shape(assigned(factory, "plan_age"),
            'min(verifier["maximumInternalAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS)')
        self.shape(assigned(factory, "skew"), "authority.VERIFIER_MAX_CLOCK_SKEW_NS")
        integers = calls(factory, "plan.contract._integer")
        self.assertEqual(len(integers), 4)
        for actual, expected in zip(integers, (
                "plan.contract._integer(assertion_age, minimum=1)",
                'plan.contract._integer(verifier["maximumInternalAgeNs"], minimum=1)',
                "plan.contract._integer(plan_age, minimum=1)", "plan.contract._integer(skew)")):
            self.shape(actual, expected)
        first_key = calls(factory, "configuration._key")[0]
        order = (prefix, descriptor, role_loop[0], comparisons[1], timeouts[0],
                 timeout_guard[0], timeouts[1], identity, validated, *integers, first_key)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        _, authority = source("serverware/authority_contract.py")
        self.shape(assigned(authority, "VERIFIER_RESPONSE_MAX_AGE_NS"), "30 * 1_000_000_000")
        self.shape(assigned(authority, "VERIFIER_MAX_CLOCK_SKEW_NS"), "5 * 1_000_000_000")

    def test_two_source_pinned_keys_and_actual_raw_signer_pair_precede_exact_ten_setting_owner(self):
        factory = definition(self.tree, "_planner_from_configuration_on_work")
        keys = calls(factory, "configuration._key")
        self.assertEqual(len(keys), 2)
        self.shape(keys[0], '''configuration._key(planner["signingPublicKeyBase64Url"], work,
            expected_spki=planner["signingSpkiDigest"])''')
        self.shape(keys[1], '''configuration._key(verifier["signingPublicKeyBase64Url"], work,
            expected_spki=verifier["signingSpkiDigest"])''')
        session = assigned(factory, "verifier_session")
        self.shape(session, '''configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]), work)''')
        paired = call(factory, "_bind_signer")
        self.shape(paired, "_bind_signer(planner_private_key, planner_key, work)")
        owner = call(factory, "planning.RevocationObservedPlanner")
        self.shape(owner, '''planning.RevocationObservedPlanner(read_dsn=read_dsn, connect_timeout_seconds=timeout,
            database_identity=database_identity, planner_private_key=planner_private_key,
            planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier["measurementDigest"], "attestationReceiptDigest": verifier["attestationReceiptDigest"]},
            maximum_assertion_age_ns=assertion_age, maximum_plan_age_ns=plan_age, maximum_clock_skew_ns=skew)''')
        self.assertEqual(len(keywords(owner)), 10)
        self.assertEqual([node.lineno for node in (*keys, session, paired, owner)],
            sorted(node.lineno for node in (*keys, session, paired, owner)))
        binding = definition(self.tree, "_bind_signer")
        self.assertEqual([item.arg for item in binding.args.args], ["private_key", "public_key", "work"])
        reserved = call(binding, "work.charge")
        self.shape(reserved, "work.charge(input_bytes=128)")
        guarded = calls(binding, "configuration.production._callback")
        self.assertEqual(len(guarded), 3)
        for actual, expected in zip(guarded, (
                "configuration.production._callback(work, lambda: private_key.public_key())",
                "configuration.production._callback(work, lambda: derived.public_bytes(Encoding.Raw, PublicFormat.Raw))",
                "configuration.production._callback(work, lambda: public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))")):
            self.shape(actual, expected)
        checks = [node for node in binding.body if isinstance(node, ast.If)]
        self.assertEqual(len(checks), 3)
        self.shape(checks[0].test, "not isinstance(derived, Ed25519PublicKey)")
        self.shape(checks[1].test, "any(type(raw) is not bytes or len(raw) != 32 for raw in (actual, expected))")
        self.shape(checks[2].test, "actual != expected")
        self.assertEqual([node.lineno for node in (reserved, guarded[0], checks[0], *guarded[1:], *checks[1:])],
            sorted(node.lineno for node in (reserved, guarded[0], checks[0], *guarded[1:], *checks[1:])))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"sign", "verify", "produce_observed"} for node in ast.walk(self.tree)))

    def test_shared_full_commitment_launch_capture_and_real_spki_work_keep_inert_closure(self):
        _, shared = source("serverware/authority_revocation_configuration.py", 64 * 1024)
        prefix = definition(shared, "_capture_configuration_on_work")
        self.shape(assigned(prefix, "owned"), '''_ConfigurationCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)''')
        self.shape(assigned(prefix, "launch"), '''capability.capture._JSONCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(
                {name: generation[name] for name in _GENERATION_FIELDS})''')
        self.shape(assigned(shared, "_GENERATION_FIELDS"), '''("schema", "sequence", "digest",
            "predecessorDigest", "minimumRollbackSequence", "operationManifestDigest", "configurationPayloadBindings")''')
        bounded = call(prefix, "capability.shape._bounded_object")
        self.shape(bounded, 'capability.shape._bounded_object(generation, 21, "issuer launch context")')
        encoded = call(prefix, "_configuration_wire")
        self.shape(encoded, "_configuration_wire(owned, ledger)")
        committed = call(prefix, "capability.plan._frame")
        self.shape(committed, "capability.plan._frame(CONFIG_SCHEMA, (encoded,), work)")
        compared = call(prefix, "capability.plan._same")
        self.shape(compared, 'capability.plan._same(computed, configuration_digest, work, "issuer configuration commitment changed")')
        generation = call(prefix, "_generation_binding")
        self.shape(generation, "_generation_binding(owned, launch, configuration_digest, work)")
        order = (bounded, assigned(prefix, "owned"), assigned(prefix, "launch"), encoded, committed, compared, generation)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        key = definition(shared, "_key")
        self.shape(call(key, "invocation._decode"), "invocation._decode(encoded, 32, 32, work)")
        guarded = calls(key, "production._callback")
        self.assertEqual(len(guarded), 2)
        self.shape(guarded[0], "production._callback(work, lambda: Ed25519PublicKey.from_public_bytes(raw))")
        self.shape(guarded[1], "production._callback(work, lambda: key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))")
        charges = calls(key, "work.charge")
        self.assertEqual(len(charges), 2)
        self.shape(charges[0], "work.charge(input_bytes=44)")
        self.shape(charges[1], "work.charge(hashes=1, input_bytes=44)")
        self.assertLess(charges[0].lineno, guarded[1].lineno)
        self.assertLess(guarded[1].lineno, charges[1].lineno)
        imports = {(node.module, item.name) for node in self.tree.body
            if isinstance(node, ast.ImportFrom) for item in node.names}
        self.assertEqual(imports, {("__future__", "annotations"),
            ("cryptography.hazmat.primitives.asymmetric.ed25519", "Ed25519PrivateKey"),
            ("cryptography.hazmat.primitives.asymmetric.ed25519", "Ed25519PublicKey"),
            ("cryptography.hazmat.primitives.serialization", "Encoding"),
            ("cryptography.hazmat.primitives.serialization", "PublicFormat"),
            ("serverware", "authority_contract"), ("serverware", "authority_revocation_configuration"),
            ("serverware", "authority_revocation_plan"), ("serverware", "authority_revocation_planning")})
        self.assertEqual([ast.unparse(node) for node in self.tree.body if isinstance(node, ast.Import)], ["import math"])
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "psycopg.connect", "json.loads",
                "time.time_ns", "time.monotonic_ns", "eval", "exec", "_read_dsn_descriptor"):
            self.assertFalse(calls(self.tree, forbidden))
        for forbidden in ("authority_service", "authority_transition_registry", "authority_revocation_persistence",
                "authority_revocation_coordinator", "_issuer_from_configuration_on_work", "_verifier_from_configuration_on_work"):
            self.assertNotIn(forbidden, self.text)


if __name__ == "__main__":
    unittest.main()
