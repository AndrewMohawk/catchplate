#!/usr/bin/env python3
"""Nonimporting linkage for the private configured revocation verifier.

These bounded source assertions do not import the service or active registry,
execute extracted production bodies, or establish measured launch admission.
The real loader/adapter links remain prerequisites; plain component mappings
are not root-signed configuration or independently admitted database roots.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path, maximum=256 * 1024):
    target = ROOT / path
    if target.stat().st_size > maximum:
        raise AssertionError("revocation verifier source exceeds its inspection bound")
    source = target.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=path)


def definition(tree, name):
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name == name]
    if len(nodes) != 1:
        raise AssertionError("revocation verifier definition is not unique: " + name)
    return nodes[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == name), key=lambda node: (node.lineno, node.col_offset))


def call(tree, name):
    nodes = calls(tree, name)
    if len(nodes) != 1:
        raise AssertionError("revocation verifier call is not unique: " + name)
    return nodes[0]


def assigned(tree, name):
    nodes = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(nodes) != 1:
        raise AssertionError("revocation verifier assignment is not unique: " + name)
    return nodes[0]


def keywords(node):
    if any(item.arg is None for item in node.keywords):
        raise AssertionError("revocation verifier call has open keyword expansion")
    return {item.arg: item.value for item in node.keywords}


class RevocationVerifierSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service_source, cls.service = read("catchplate/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.source, cls.module = read("catchplate/authority_revocation_verifier.py", 64 * 1024)
        cls.owner = definition(cls.module, "RevocationPlanVerifier")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_private_adapter_owns_caller_and_full_config_before_launch_or_key_callbacks(self):
        adapter = definition(self.process, "_verify_revocation_plan_handoff")
        self.assertEqual([item.arg for item in adapter.args.args], ["self"])
        self.assertEqual([item.arg for item in adapter.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "expected_request", "context", "root_inventory", "work"])
        self.assertTrue(all(value is None for value in adapter.args.kw_defaults))
        self.assertIsNone(adapter.args.kwarg)
        self.assertIsNone(adapter.args.vararg)
        guards = [node for node in adapter.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 2)
        self.shape(guards[0].test, '''self.role_name != "verifier"
            or self.process_mode != "policy-authority-verifier"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.shape(assigned(adapter, "configuration"), "self.configuration")
        source_pins = [node for node in adapter.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                == ["payload", "configuration_digest"] for target in node.targets)]
        self.assertEqual(len(source_pins), 1)
        self.shape(source_pins[0].value, "(configuration.payload, configuration.digest)")
        capture = call(adapter, "authority_revocation_verifier._capture_handoff_inputs")
        self.shape(capture, '''authority_revocation_verifier._capture_handoff_inputs(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            expected_request=expected_request, context=context, root_inventory=root_inventory, work=work)''')
        self.shape(call(adapter, "authority_revocation_configuration.capability.capture._SharedLedger"),
            "authority_revocation_configuration.capability.capture._SharedLedger(work)")
        digest = call(adapter, "authority_revocation_configuration.capability.shape._digest")
        self.shape(digest, "authority_revocation_configuration.capability.shape._digest(configuration_digest)")
        self.shape(guards[1].test, "type(payload) is not dict")
        owned = assigned(adapter, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        guarded = calls(adapter, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(guarded), 2)
        self.shape(guarded[0], '''authority_revocation_configuration.production._callback(
            work, lambda: authority_launch_guard.require_active("verifier"))''')
        self.shape(guarded[1], '''authority_revocation_configuration.production._callback(
            work, lambda: dict(authority_launch_guard.generation()))''')
        factory = call(adapter, "authority_revocation_verifier._verifier_from_configuration_on_work")
        self.shape(factory, '''authority_revocation_verifier._verifier_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest, generation=generation, work=work)''')
        verified = call(adapter, "verifier.verify_handoff")
        self.shape(verified, '''verifier.verify_handoff(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=owned_request,
            context=owned_context, root_inventory=inventory, work=work)''')
        order = (guards[0], source_pins[0], capture, digest, guards[1], owned, *guarded, factory, verified)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        self.assertEqual(calls(adapter, "authority_launch_guard.require_active"), [guarded[0].args[1].body])
        self.assertEqual(calls(adapter, "authority_launch_guard.generation"),
            [guarded[1].args[1].body.args[0]])
        tail = ast.unparse(adapter)[ast.unparse(adapter).index("owned_request, owned_context, inventory ="):]
        self.assertNotIn("self.", tail)
        for forbidden in ("_read_dsn_descriptor", "_sign_internal", "_revocation_capability_issuer",
                "time.time_ns", "time.monotonic_ns", "_ValidationWork", "json.loads", "_canonical"):
            self.assertFalse(calls(adapter, forbidden))
        self.assertEqual(calls(self.service, "self._verify_revocation_plan_handoff"), [])

    def test_closed_caller_nine_are_owned_with_full_inventory_before_any_key_use(self):
        self.shape(assigned(self.module, "_CONFIGURED_CONTEXT_FIELDS"), '''frozenset({
            "expectedPlannerIdentity", "expectedVerifierIdentity", "maximumAssertionAgeNs",
            "maximumPlanAgeNs", "maximumClockSkewNs"})''')
        self.shape(assigned(self.module, "_CALL_CONTEXT_FIELDS"), '''
            handoff.retention.production._CONTEXT_FIELDS - _CONFIGURED_CONTEXT_FIELDS - {"expectedBefore"}''')
        _source, production = read("catchplate/authority_revocation_plan_production.py")
        complete = ast.literal_eval(assigned(production, "_CONTEXT_FIELDS").args[0])
        configured = ast.literal_eval(assigned(self.module, "_CONFIGURED_CONTEXT_FIELDS").args[0])
        self.assertEqual(complete - configured - {"expectedBefore"}, {
            "expectedCapabilityId", "expectedPlannerTransactionId", "expectedFence", "reservedAtEpochNs",
            "deadlineEpochNs", "deadlineMonotonicNs", "nowEpochNs", "nowMonotonicNs",
            "expectedApproverPolicyDigest"})
        capture = definition(self.module, "_capture_handoff_inputs")
        self.assertEqual([item.arg for item in capture.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "expected_request", "context", "root_inventory", "work"])
        self.assertIsNone(capture.args.kwarg)
        ledger = call(capture, "handoff.plan.capture._SharedLedger")
        self.shape(ledger, "handoff.plan.capture._SharedLedger(work)")
        guard = [node for node in capture.body if isinstance(node, ast.If)][0]
        self.shape(guard.test, '''type(envelope_bytes) is not bytes
            or not 2 <= len(envelope_bytes) <= handoff.plan.contract.MAX_PAYLOAD_BYTES
            or type(evaluation_context_bytes) is not bytes
            or not 2 <= len(evaluation_context_bytes) <= handoff.retention.MAX_CONTEXT_BYTES
            or type(expected_request) is not dict''')
        closed = call(capture, "handoff.plan.contract._object")
        self.shape(closed, 'handoff.plan.contract._object(context, _CALL_CONTEXT_FIELDS, "configured verifier context")')
        owned = assigned(capture, "owned")
        self.shape(owned, '''handoff.observed.reads._CopyBudget(work).copy(
            {"expectedRequest": expected_request, "context": context})''')
        inventory = call(capture, "handoff.observed._capture_root_inventory")
        self.shape(inventory, "handoff.observed._capture_root_inventory(root_inventory, work=work)")
        typed = call(capture, "handoff.plan.contract._request")
        self.shape(typed, "handoff.plan.contract._request(request)")
        loops = [node for node in capture.body if isinstance(node, ast.For)]
        self.assertEqual(len(loops), 2)
        self.shape(loops[0].iter, '("expectedCapabilityId", "expectedPlannerTransactionId")')
        self.shape(loops[1].iter, '''("expectedFence", "reservedAtEpochNs", "deadlineEpochNs",
            "deadlineMonotonicNs", "nowEpochNs", "nowMonotonicNs")''')
        self.shape(call(loops[0], "handoff.plan.contract._digest"), 'handoff.plan.contract._digest(context[name])')
        self.shape(call(loops[1], "handoff.plan.contract._integer"),
            'handoff.plan.contract._integer(context[name], minimum=1)')
        self.shape(capture.body[-1].value, "(request, context, inventory)")
        ordered = (ledger, guard, closed, owned, inventory, typed, *loops)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        for name in ("configuration._key", "configuration._capture_configuration_on_work",
                "handoff._verify_observed_plan_handoff_on_work"):
            self.assertFalse(calls(capture, name))

    def test_factory_derives_exact_roles_manifest_and_age_policy_before_two_real_key_callbacks(self):
        factory = definition(self.module, "_verifier_from_configuration_on_work")
        self.assertEqual([item.arg for item in factory.args.kwonlyargs],
            ["payload", "configuration_digest", "generation", "work"])
        self.assertIsNone(factory.args.kwarg)
        prefix = call(factory, "configuration._capture_configuration_on_work")
        self.shape(prefix, '''configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        self.shape(assigned(factory, "roles"), 'owned["roles"]')
        role_loop = [node for node in ast.walk(factory) if isinstance(node, ast.For)
            and ast.unparse(node.target) == "(name, role)"]
        self.assertEqual(len(role_loop), 1)
        self.shape(role_loop[0].iter, '(("planner", planner), ("verifier", verifier))')
        self.shape(call(role_loop[0], "handoff.plan.contract._literal"),
            'handoff.plan.contract._literal(role["processMode"], "policy-authority-" + name)')
        self.shape(call(role_loop[0], "handoff.plan._same"), '''handoff.plan._same(
            role["responseSigningSpkiDigest"], role["signingSpkiDigest"], work,
            "revocation verifier key differs from its measured response pin")''')
        manifest = [node for node in calls(factory, "handoff.plan._same")
            if ast.unparse(node.args[0]) == "owned['queryManifestDigest']"]
        self.assertEqual(len(manifest), 1)
        self.shape(manifest[0], '''handoff.plan._same(owned["queryManifestDigest"],
            handoff.plan._QUERY_MANIFEST_DIGEST, work,
            "revocation verifier configuration differs from the source query manifest")''')
        self.shape(assigned(factory, "webauthn"), 'owned["webauthn"]')
        self.shape(assigned(factory, "assertion_age"), 'webauthn["maximumChallengeAgeNs"]')
        self.shape(assigned(factory, "plan_age"),
            'min(verifier["maximumInternalAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS)')
        self.shape(assigned(factory, "skew"), "authority.VERIFIER_MAX_CLOCK_SKEW_NS")
        integers = calls(factory, "handoff.plan.contract._integer")
        self.assertEqual(len(integers), 4)
        for actual, expected in zip(integers, (
                "handoff.plan.contract._integer(assertion_age, minimum=1)",
                'handoff.plan.contract._integer(verifier["maximumInternalAgeNs"], minimum=1)',
                "handoff.plan.contract._integer(plan_age, minimum=1)",
                "handoff.plan.contract._integer(skew)")):
            self.shape(actual, expected)
        keys = calls(factory, "configuration._key")
        self.assertEqual(len(keys), 2)
        self.shape(keys[0], '''configuration._key(planner["signingPublicKeyBase64Url"], work,
            expected_spki=planner["signingSpkiDigest"])''')
        self.shape(keys[1], '''configuration._key(verifier["signingPublicKeyBase64Url"], work,
            expected_spki=verifier["signingSpkiDigest"])''')
        self.shape(assigned(factory, "verifier_session"), '''configuration._frame_text(
            configuration._VERIFIER_SESSION,
            (configuration_digest, verifier["measurementDigest"], verifier["attestationReceiptDigest"]), work)''')
        owner = call(factory, "RevocationPlanVerifier")
        self.shape(owner, '''RevocationPlanVerifier(planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_planner_identity={"sessionIdentityDigest": planner["plannerSessionIdentityDigest"],
                "measurementDigest": planner["measurementDigest"], "attestationReceiptDigest": planner["attestationReceiptDigest"]},
            expected_verifier_identity={"sessionIdentityDigest": verifier_session,
                "measurementDigest": verifier["measurementDigest"], "attestationReceiptDigest": verifier["attestationReceiptDigest"]},
            maximum_assertion_age_ns=assertion_age, maximum_plan_age_ns=plan_age, maximum_clock_skew_ns=skew,
            expected_configuration_digest=configuration_digest,
            expected_generation_sequence=launch["sequence"], expected_generation_digest=launch["digest"])''')
        order = (prefix, role_loop[0], manifest[0], *integers, *keys,
                 assigned(factory, "verifier_session"), owner)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        _source, authority = read("catchplate/authority_contract.py")
        self.shape(assigned(authority, "VERIFIER_RESPONSE_MAX_AGE_NS"), "30 * 1_000_000_000")
        self.shape(assigned(authority, "VERIFIER_MAX_CLOCK_SKEW_NS"), "5 * 1_000_000_000")
        # These are the existing real service policy sources, not caller pins.
        planner = definition(self.process, "_handle_plan")
        self.shape(keywords(call(planner, "authority_planner.MeasuredPlanner"))["maximum_assertion_age_ns"],
            'int(self.configuration.payload["webauthn"]["maximumChallengeAgeNs"])')

    def test_constructor_snapshot_and_configured_context_precede_original_same_work_replay(self):
        self.shape(self.owner.decorator_list[0], "dataclass(frozen=True, slots=True, init=False)")
        constructor = definition(self.owner, "__init__")
        self.assertEqual([item.arg for item in constructor.args.kwonlyargs], [
            "planner_public_key", "verifier_public_key", "expected_planner_identity", "expected_verifier_identity",
            "maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns",
            "expected_configuration_digest", "expected_generation_sequence", "expected_generation_digest"])
        self.shape(assigned(constructor, "values"), '''(planner_public_key, verifier_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns,
            expected_configuration_digest, expected_generation_sequence, expected_generation_digest)''')
        self.shape(call(constructor, "object.__setattr__"), 'object.__setattr__(self, "_configuration", values)')
        self.assertLess(call(constructor, "_validate_configuration").lineno,
            call(constructor, "object.__setattr__").lineno)
        validate = definition(self.module, "_validate_configuration")
        guards = [node for node in validate.body if isinstance(node, ast.If)]
        self.shape(guards[0].test, "type(values) is not tuple or len(values) != 10")
        self.shape(guards[-1].test, '''values[5] > authority.VERIFIER_RESPONSE_MAX_AGE_NS
            or values[6] != authority.VERIFIER_MAX_CLOCK_SKEW_NS''')
        snapshot = definition(self.owner, "_snapshot_configuration")
        self.shape(snapshot.body[0].test, "type(self) is not RevocationPlanVerifier")
        self.shape(assigned(snapshot, "values"), "self._configuration")
        self.shape(call(snapshot, "_validate_configuration"), "_validate_configuration(values)")
        self.shape(snapshot.body[-1].value, "values")
        verify = definition(self.owner, "verify_handoff")
        self.assertEqual([item.arg for item in verify.args.kwonlyargs], [
            "envelope_bytes", "evaluation_context_bytes", "expected_request", "context", "root_inventory", "work"])
        self.assertIsNone(verify.args.kwarg)
        self.shape(assigned(verify, "values"), "self._snapshot_configuration()")
        capture = call(verify, "_capture_handoff_inputs")
        self.shape(capture, '''_capture_handoff_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=expected_request,
            context=context, root_inventory=root_inventory, work=work)''')
        self.shape(assigned(verify, "actual_context"), '''{**owned,
            "expectedPlannerIdentity": dict(zip(_IDENTITY_FIELDS, values[2])),
            "expectedVerifierIdentity": dict(zip(_IDENTITY_FIELDS, values[3])),
            "maximumAssertionAgeNs": values[4], "maximumPlanAgeNs": values[5], "maximumClockSkewNs": values[6]}''')
        partial = call(verify, "handoff.observed._validate_partial_context")
        self.shape(partial, "handoff.observed._validate_partial_context(actual_context, work)")
        genuine = call(verify, "handoff._verify_observed_plan_handoff_on_work")
        self.shape(genuine, '''handoff._verify_observed_plan_handoff_on_work(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=request,
            context=actual_context, root_inventory=inventory,
            planner_public_key=values[0], verifier_public_key=values[1], work=work)''')
        order = (assigned(verify, "values"), capture, assigned(verify, "actual_context"), partial, genuine)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        self.assertEqual(calls(verify, "self._snapshot_configuration"), [assigned(verify, "values")])
        self.assertEqual(len(calls(self.module, "handoff._verify_observed_plan_handoff_on_work")), 1)

    def test_inert_helper_closure_reaches_real_signature_and_retained_replay_without_new_allowance(self):
        imports = {(node.module, item.name) for node in self.module.body
            if isinstance(node, ast.ImportFrom) for item in node.names}
        self.assertEqual(imports, {("__future__", "annotations"), ("dataclasses", "dataclass"),
            ("cryptography.hazmat.primitives.asymmetric.ed25519", "Ed25519PublicKey"),
            ("catchplate", "authority_contract"), ("catchplate", "authority_revocation_configuration"),
            ("catchplate", "authority_revocation_handoff")})
        self.assertFalse(any(isinstance(node, ast.Import) for node in self.module.body))
        for forbidden in ("_ValidationWork", "QueryReadValidationLimits", "psycopg.connect",
                "time.time_ns", "time.monotonic_ns", "datetime.now", "eval", "exec", "json.loads"):
            self.assertFalse(calls(self.module, forbidden))
        for forbidden in ("authority_service", "authority_transition_registry", "authority_revocation_coordinator",
                "Ed25519PrivateKey", "_issuer_from_configuration_on_work", "_read_dsn_descriptor"):
            self.assertNotIn(forbidden, self.source)
        _source, configured = read("catchplate/authority_revocation_configuration.py")
        key = definition(configured, "_key")
        guarded = calls(key, "production._callback")
        self.assertEqual(len(guarded), 2)
        self.shape(guarded[0], "production._callback(work, lambda: Ed25519PublicKey.from_public_bytes(raw))")
        self.shape(guarded[1], '''production._callback(work,
            lambda: key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))''')
        _source, handoff = read("catchplate/authority_revocation_handoff.py")
        worker = definition(handoff, "_verify_observed_plan_handoff_on_work")
        signature = call(worker, "capability._signature")
        cutoff = call(worker, "_authenticated_cutoff")
        replay = call(worker, "retention._verify_record_on_work")
        self.shape(signature, '''capability._signature(planner_public_key, envelope["signatureBase64Url"],
            plan.contract.SIGNED_MEASURED_PLAN_SCHEMA, payload_wire, ledger)''')
        self.assertLess(signature.lineno, cutoff.lineno)
        self.assertLess(cutoff.lineno, replay.lineno)
        replay_options = {item.arg: item.value for item in replay.keywords if item.arg is not None}
        for name in ("envelope_bytes", "evaluation_context_bytes", "work"):
            self.shape(replay_options[name], name)
        _source, retained = read("catchplate/authority_revocation_retention.py")
        genuine = call(definition(retained, "_verify_record_on_work"), "plan._verify_signed_revocation_plan_on_work")
        options = {item.arg: item.value for item in genuine.keywords if item.arg is not None}
        self.shape(options["original_envelope_bytes"], "envelope_bytes")
        self.shape(options["work"], "work")

    def test_actual_measured_loader_precedes_process_and_requires_root_launch_and_attestation(self):
        main = definition(self.service, "main")
        loaded = call(main, "MeasuredConfiguration.load")
        process = call(main, "AuthorityProcess")
        self.shape(loaded, "MeasuredConfiguration.load(role=args.role)")
        self.shape(process, "AuthorityProcess(role=args.role, configuration=configuration)")
        self.assertLess(loaded.lineno, process.lineno)
        configuration = definition(self.service, "MeasuredConfiguration")
        loader = definition(configuration, "load")
        descriptors = calls(loader, "_read_bounded_descriptor")
        self.assertEqual(len(descriptors), 2)
        self.shape(descriptors[0], '''_read_bounded_descriptor(
            "CATCHPLATE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY", maximum=64 * 1024,
            require_root_owned=True, require_descriptor=True)''')
        self.shape(descriptors[1], '''_read_bounded_descriptor(
            "CATCHPLATE_POLICY_AUTHORITY_CONFIG", maximum=MAX_CONFIG_BYTES,
            require_root_owned=True, require_descriptor=True)''')
        verified = call(loader, "root_key.verify")
        self.shape(verified, '''root_key.verify(_b64url_decode(envelope["signature"], size=64),
            _domain_digest(SIGNED_CONFIG_SCHEMA, payload_bytes).encode("ascii"))''')
        checks = [call(loader, "configuration." + name) for name in (
            "_verify_generation_binding", "_verify_role_topology", "_verify_runtime_closure", "_verify_attestation")]
        order = (*descriptors, verified, *checks)
        self.assertEqual([node.lineno for node in order], sorted(node.lineno for node in order))
        self.assertLess(checks[-1].lineno, loader.body[-1].lineno)
        self.shape(loader.body[-1].value, "configuration")
        closure = definition(configuration, "_verify_runtime_closure")
        self.shape(call(closure, "authority_launch_guard.require_active"),
            "authority_launch_guard.require_active(_launch_role)")
        self.assertIn("self.payload['roleBindingDigests'][_launch_role]", ast.unparse(closure))
        self.assertIn("self.payload['roleRuntimeClosureDigests'].get(_launch_role)", ast.unparse(closure))

    def test_existing_dispatch_credentials_and_signer_roles_are_not_expanded(self):
        handle = definition(self.process, "handle")
        admissions = calls(handle, "self._verify_internal_envelope")
        self.assertEqual(len(admissions), 3)
        self.shape(keywords(admissions[0])["allowed_purposes"], '{"plan-operation"}')
        self.shape(keywords(admissions[1])["allowed_purposes"], '''{
            "persist-measured-plan", "read-persisted-plan", "reserve-execution-envelope"}''')
        self.shape(keywords(admissions[2])["allowed_purposes"], '''
            {"issue-capability", "record-witness-receipt"} if self.role_name == "issuer" else {"execute-v9"}''')
        serving = definition(definition(self.service, "AuthorityServer"), "_serve_connection")
        self.shape(assigned(serving, "request"), "_recv_message(connection)")
        self.shape(assigned(serving, "response"), "self.process.handle(request)")
        for dispatcher in (handle, serving):
            for name in ("verify_handoff", "authority_revocation_verifier", "issue-revocation-capability"):
                self.assertNotIn(name, ast.unparse(dispatcher))
        credentials = definition(self.process, "_reject_wrong_credentials")
        self.shape(assigned(credentials, "allowed"), '''{
            "verifier": {"CATCHPLATE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD"},
            "planner": {"CATCHPLATE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN_FD"},
            "planner-writer": {"CATCHPLATE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD"},
            "issuer": {"CATCHPLATE_POLICY_AUTHORITY_CAPABILITY_ISSUER_POSTGRES_DSN_FD"},
            "executor": {"CATCHPLATE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD"}}[self.role_name]''')
        conditions = [node.test for node in credentials.body if isinstance(node, ast.If)]
        self.assertEqual(len(conditions), 3)
        self.shape(conditions[1], '''(self.role_name == "verifier" and (not signing_descriptor or signing_path))
            or (self.role_name != "verifier" and (signing_descriptor or signing_path))''')
        self.shape(conditions[2], '''(self.role_name == "planner" and (not planner_signing_descriptor or planner_signing_path))
            or (self.role_name != "planner" and (planner_signing_descriptor or planner_signing_path))''')
        for forbidden in ("authority_revocation_handoff", "RevocationPlanningCoordinator",
                "produce_observed_and_persist_with_cutoff"):
            self.assertNotIn(forbidden, self.service_source)
        registry, _tree = read("catchplate/authority_transition_registry.py")
        self.assertNotIn("authority_revocation_verifier", registry)
        self.assertNotIn("issue-revocation-capability", registry)


if __name__ == "__main__":
    unittest.main()
