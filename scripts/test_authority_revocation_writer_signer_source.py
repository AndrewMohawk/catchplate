#!/usr/bin/env python3
"""Nonimporting linkage for dedicated writer response-key startup binding.

These controls inspect bounded source only. They do not execute extracted
functions or establish measured configuration, descriptor provenance, native
launch, hardware custody, database admission, a signature or an ACK.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, source


WRITER_DESCRIPTOR = "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD"
WRITER_DESCRIPTORS = {
    "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
    "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
    "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
    WRITER_DESCRIPTOR,
    "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD",
}


def field(mapping, name):
    values = [value for key, value in zip(mapping.keys, mapping.values)
              if isinstance(key, ast.Constant) and key.value == name]
    if len(values) != 1:
        raise AssertionError("writer signer source field is not unique: " + name)
    return values[0]


class RevocationWriterSignerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.tree = source("serverware/authority_revocation_writer_signer.py", 64 * 1024)
        _, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        _, cls.launcher = source("serverware/authority_launcher.py", 256 * 1024)
        _, cls.entrypoint = source("serverware/authority_fd_entrypoint.py", 128 * 1024)
        _, cls.generator = source("scripts/authority/generate_artifact_bundle.py", 256 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_inert_closed_startup_api_bounds_original_pem_and_all_role_pins_before_crypto(self):
        signer = definition(self.tree, "_signer_from_pem")
        self.assertEqual([item.arg for item in signer.args.args], ["private_bytes"])
        self.assertEqual([item.arg for item in signer.args.kwonlyargs],
                         ["response_spki_digest", "other_response_spki_digests", "launch_public_key"])
        self.assertTrue(all(value is None for value in signer.args.kw_defaults))
        self.assertIsNone(signer.args.vararg)
        self.assertIsNone(signer.args.kwarg)
        self.shape(assigned(self.tree, "MAX_PRIVATE_BYTES"), "64 * 1024")
        self.shape(signer.body[1].test,
                   "type(private_bytes) is not bytes or not 2 <= len(private_bytes) <= MAX_PRIVATE_BYTES")
        self.shape(signer.body[2].value, "_digest(response_spki_digest)")
        self.shape(signer.body[3].test,
                   "type(other_response_spki_digests) is not tuple or len(other_response_spki_digests) != 4")
        self.shape(signer.body[4].iter, "other_response_spki_digests")
        self.shape(signer.body[4].body[0].value, "_digest(pin)")
        self.shape(signer.body[5].test, "response_spki_digest in other_response_spki_digests")
        self.shape(signer.body[6].test, "not isinstance(launch_public_key, Ed25519PublicKey)")
        digest = definition(self.tree, "_digest")
        self.shape(digest.body[0].test,
                   "type(value) is not str or len(value) != 71 or _DIGEST.fullmatch(value) is None")
        self.shape(assigned(self.tree, "_DIGEST"), 're.compile(r"sha256:[0-9a-f]{64}")')
        parser = call(signer, "serialization.load_pem_private_key")
        self.assertLess(signer.body[6].lineno, parser.lineno)
        self.assertEqual({node.name for node in self.tree.body if isinstance(node, ast.FunctionDef)},
                         {"_digest", "_public_spki_digest", "_signer_from_pem"})
        for node in self.tree.body:
            if isinstance(node, ast.Import):
                self.assertTrue(all(item.name in {"hashlib", "re"} for item in node.names))
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, {"__future__", "cryptography.hazmat.primitives",
                    "cryptography.hazmat.primitives.asymmetric.ed25519"})

    def test_actual_pem_and_canonical_der_binding_return_only_the_real_key_without_signing_or_request_work(self):
        signer = definition(self.tree, "_signer_from_pem")
        guarded = signer.body[7]
        self.assertIsInstance(guarded, ast.Try)
        self.shape(guarded.body[0].value, "serialization.load_pem_private_key(private_bytes, password=None)")
        self.shape(guarded.handlers[0].type, "(TypeError, ValueError)")
        self.assertIsInstance(guarded.handlers[0].body[0], ast.Raise)
        self.shape(signer.body[8].test, "not isinstance(private_key, Ed25519PrivateKey)")
        self.shape(assigned(signer, "observed"), "_public_spki_digest(private_key.public_key())")
        self.shape(signer.body[10].test, "observed != response_spki_digest")
        self.shape(signer.body[11].test, "observed == _public_spki_digest(launch_public_key)")
        self.shape(signer.body[-1].value, "private_key")
        self.assertEqual(len(signer.body), 13)
        public = definition(self.tree, "_public_spki_digest")
        self.shape(public.body[0].test, "not isinstance(key, Ed25519PublicKey)")
        self.shape(assigned(public, "encoded"),
                   "key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)")
        self.shape(public.body[2].test,
                   "type(encoded) is not bytes or len(encoded) != 44 or not encoded.startswith(_SPKI_PREFIX)")
        self.assertEqual(assigned(self.tree, "_SPKI_PREFIX").value,
                         b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00")
        self.shape(public.body[-1].value, '"sha256:" + hashlib.sha256(encoded).hexdigest()')
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {"sign", "verify", "execute", "connect", "time_ns", "monotonic_ns"})
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id, {"work", "_ValidationWork", "QueryReadValidationLimits", "_PackagingLedger"})

    def test_writer_startup_holds_measured_pins_before_its_descriptor_and_assigns_only_separate_slot(self):
        constructor = definition(self.process, "__init__")
        initial = [node for node in constructor.body if isinstance(node, ast.AnnAssign)
                   and ast.unparse(node.target) in {"self.signing_key", "self.writer_response_signing_key"}]
        self.assertEqual([ast.unparse(node.target) for node in initial],
                         ["self.signing_key", "self.writer_response_signing_key"])
        for node in initial:
            self.shape(node.value, "None")
        writer, = [node for node in ast.walk(constructor) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "role == 'planner-writer'"]
        self.assertEqual(writer.orelse, [])
        pin = assigned(writer, "response_spki_digest")
        others = assigned(writer, "other_response_spki_digests")
        launch = assigned(writer, "launch_public_key")
        self.shape(pin, 'self.role_config["responseSigningSpkiDigest"]')
        self.shape(others, '''tuple(configuration.role(name)["responseSigningSpkiDigest"]
            for name in ("verifier", "planner", "issuer", "executor"))''')
        self.shape(launch, "self.launch_identity_key.public_key()")
        descriptor = call(writer, "_read_bounded_descriptor")
        self.shape(descriptor, '''_read_bounded_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY",
            maximum=64 * 1024, require_root_owned=True, require_descriptor=True)''')
        bound = call(writer, "authority_revocation_writer_signer._signer_from_pem")
        self.shape(bound, '''authority_revocation_writer_signer._signer_from_pem(private_value,
            response_spki_digest=response_spki_digest, other_response_spki_digests=other_response_spki_digests,
            launch_public_key=launch_public_key)''')
        assignment, = [node for node in writer.body if isinstance(node, ast.Assign)
                       and any(ast.unparse(target) == "self.writer_response_signing_key" for target in node.targets)]
        self.assertIs(assignment.value, bound)
        ordered = (pin, others, launch, descriptor, bound)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertLess(writer.end_lineno, call(constructor, "self._reject_wrong_credentials").lineno)
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == "signing_key"
                             for node in ast.walk(writer)))
        self.assertFalse(any(isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Name) and node.value.id in {"self", "configuration"}
            and node.lineno > descriptor.lineno for node in ast.walk(writer)))
        uses = [node for node in ast.walk(self.service) if isinstance(node, ast.Attribute)
                and node.attr == "writer_response_signing_key"]
        self.assertEqual(len(uses), 3)
        self.assertEqual(sum(isinstance(node.ctx, ast.Store) for node in uses), 2)
        loaded, = [node for node in uses if isinstance(node.ctx, ast.Load)]
        adapter = definition(self.process, "_persist_and_reserve_revocation_commitments")
        self.assertIs(assigned(adapter, "writer_private_key"), loaded)
        self.assertLess(loaded.lineno, assigned(adapter, "owned_payload").lineno)

    def test_real_measured_loader_and_artifact_topology_both_reject_other_role_response_pin_reuse(self):
        measured = definition(self.service, "MeasuredConfiguration")
        topology = definition(measured, "_verify_role_topology")
        separated, = [node for node in topology.body if isinstance(node, ast.If)
                      and "roles[name]['responseSigningSpkiDigest']" in ast.unparse(node.test)]
        self.shape(separated.test, '''planner_writer["responseSigningSpkiDigest"] in {
            roles[name]["responseSigningSpkiDigest"] for name in ("verifier", "planner", "issuer", "executor")}''')
        self.assertIsInstance(separated.body[0], ast.Raise)
        role_loop, = [node for node in topology.body if isinstance(node, ast.For)
                      and ast.unparse(node.iter) == "PROCESS_MODES.items()"]
        self.assertLess(role_loop.end_lineno, separated.lineno)
        loader = definition(measured, "load")
        root_signature = call(loader, "root_key.verify")
        topology_call = call(loader, "configuration._verify_role_topology")
        self.assertLess(root_signature.lineno, topology_call.lineno)
        document = definition(self.generator, "_validate_configuration_document")
        generated, = [node for node in ast.walk(document) if isinstance(node, ast.If)
                      and "for other_role in" in ast.unparse(node.test)]
        self.shape(generated.test, '''any(planner_writer["responseSigningSpkiDigest"]
            == roles[other_role]["responseSigningSpkiDigest"]
            for other_role in ("verifier", "planner", "issuer", "executor"))''')
        self.assertIsInstance(generated.body[0], ast.Raise)
        self.assertLess(generated.lineno, assigned(document, "enabled_operations").lineno)
        main = definition(self.service, "main")
        self.shape(call(main, "MeasuredConfiguration.load"), "MeasuredConfiguration.load(role=args.role)")
        self.assertLess(call(main, "MeasuredConfiguration.load").lineno, call(main, "AuthorityProcess").lineno)

    def test_writer_fd_is_required_paths_and_wrong_roles_are_denied_and_runtime_inherits_no_role_signer(self):
        self.shape(assigned(self.service, "PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS"), '''{
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_PATH"}''')
        reject = definition(self.process, "_reject_wrong_credentials")
        self.shape(assigned(reject, "writer_signing_descriptor"),
            'bool(os.environ.get("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD", "").strip())')
        self.shape(assigned(reject, "writer_signing_path"),
            'bool(os.environ.get("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_PATH", "").strip())')
        denial = reject.body[-1]
        self.shape(denial.test, '''self.role_name == "planner-writer"
            and (not writer_signing_descriptor or writer_signing_path)
            or self.role_name != "planner-writer" and (writer_signing_descriptor or writer_signing_path)''')
        self.assertIsInstance(denial.body[0], ast.Raise)
        main = definition(self.service, "main")
        early, = [node for node in main.body if isinstance(node, ast.If)
                  and "PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS" in ast.unparse(node.test)]
        self.shape(early.test, '''args.role != "planner-writer" and any(os.environ.get(name, "").strip()
            for name in PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS)''')
        self.assertLess(early.lineno, call(main, "MeasuredConfiguration.load").lineno)
        runtime = definition(definition(self.service, "AuthorityRuntimeClient"), "from_environment")
        forbidden = assigned(runtime, "forbidden_environment")
        for name in ("VERIFIER_SIGNING_KEY_ENVIRONMENTS", "PLANNER_SIGNING_KEY_ENVIRONMENTS",
                     "PLANNER_WRITER_SIGNING_KEY_ENVIRONMENTS"):
            self.assertIn("name in " + name, ast.unparse(forbidden))
        rejected, = [node for node in runtime.body if isinstance(node, ast.If)
                     and ast.unparse(node.test) == "forbidden_environment"]
        self.assertIsInstance(rejected.body[0], ast.Raise)
        # FD provenance is supplied by the actual upstream launcher; this
        # service reader alone proves bounds/owner/mode, not retained membership.
        reader = definition(self.service, "_read_bounded_descriptor")
        self.shape(reader.body[2].test, "bool(descriptor_text) == bool(path_text)")
        self.shape(reader.body[3].test, "require_descriptor and not descriptor_text")
        descriptor_branch = reader.body[4]
        self.shape(descriptor_branch.test, "descriptor_text")
        self.shape(call(descriptor_branch, "os.fstat"), "os.fstat(descriptor)")
        self.shape(call(descriptor_branch, "os.dup"), "os.dup(descriptor)")
        self.shape(call(ast.Module(body=descriptor_branch.body, type_ignores=[]), "handle.read"), "handle.read(maximum + 1)")
        self.shape(reader.body[-2].test, "require_root_owned and metadata.st_uid != 0")

    def test_writer_only_descriptor_is_bound_by_launcher_entrypoint_and_artifact_manifests(self):
        inventory = assigned(self.launcher, "ROLE_CREDENTIAL_DESCRIPTOR_NAMES")
        writer = field(inventory, "planner-writer")
        self.assertEqual({item.value for item in writer.args[0].elts}, WRITER_DESCRIPTORS)
        self.assertEqual(len(writer.args[0].elts), 6)
        for key, value in zip(inventory.keys, inventory.values):
            if key.value != "planner-writer":
                self.assertNotIn(WRITER_DESCRIPTOR, [node.value for node in ast.walk(value)
                    if isinstance(node, ast.Constant)])
        sources = assigned(self.entrypoint, "ROLE_SOURCES")
        writer_sources = field(sources, "planner-writer")
        # Delivery includes separately admitted bootstrap control, whereas the
        # ordinary credential inventory cannot contain the manifest itself.
        self.assertEqual({item.elts[0].value for item in writer_sources.elts},
                         WRITER_DESCRIPTORS | {"SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD"})
        signer_source, = [item for item in writer_sources.elts if item.elts[0].value == WRITER_DESCRIPTOR]
        self.shape(signer_source, '''("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "/run/secrets/serverware-authority-planner-writer-signing-key")''')
        for key, value in zip(sources.keys, sources.values):
            if key.value != "planner-writer":
                self.assertNotIn(WRITER_DESCRIPTOR, [node.value for node in ast.walk(value)
                    if isinstance(node, ast.Constant)])
        requirements = assigned(self.generator, "ROLE_REQUIREMENTS")
        credentials = field(field(requirements, "planner-writer"), "credentialNames")
        self.assertEqual(ast.unparse(credentials.func), "sorted")
        self.assertEqual({item.value for item in credentials.args[0].elts}, WRITER_DESCRIPTORS)
        validation = definition(self.generator, "_validate_required_role_manifests")
        self.assertIn("manifest[field] != expected", ast.unparse(validation))
        entered = definition(self.launcher, "_enter")
        self.assertIn("{binding['environmentName'] for binding in credential_descriptors} != "
                      "ROLE_CREDENTIAL_DESCRIPTOR_NAMES[role]", ast.unparse(entered))
        normal = definition(self.entrypoint, "_normal_main")
        selected, = [node for node in ast.walk(normal) if isinstance(node, ast.For)
                     and ast.unparse(node.iter) == "ROLE_SOURCES[role]"]
        self.shape(assigned(selected, "descriptor"), '''_open_source(path, expected_owner_uid=0)
            if role == "control-plane" else _open_systemd_credential(os.path.basename(path))''')
        self.shape(normal.body[1].test, 'role != "control-plane" and not trusted_host_local')
        self.assertIsInstance(normal.body[1].body[0], ast.Raise)

    def test_new_key_has_no_signing_or_ack_path_and_preserves_real_mapper_and_public_gates(self):
        # Preserve this startup-era ID: only the fixed private .67 composition
        # may now consume the held slot. Generic and public paths remain closed.
        internal = definition(self.process, "_sign_internal")
        self.shape(internal.body[0].test, "self.signing_key is None")
        self.assertEqual(len(calls(internal, "self.signing_key.sign")), 1)
        consumption = definition(self.process, "_trusted_host_local_consumption_receipt")
        self.shape(assigned(consumption, "signing_key"),
                   'self.signing_key if self.role_name == "verifier" else self.launch_identity_key')
        _, mapper_tree = source("serverware/authority_revocation_writer_configuration.py", 64 * 1024)
        mapper = definition(mapper_tree, "_persistence_from_configuration_on_work")
        self.assertEqual(len(calls(mapper, "configuration._capture_configuration_on_work")), 1)
        self.assertEqual(len(calls(mapper, "configuration._key")), 2)
        self.assertEqual(len(calls(mapper, "configuration._frame_text")), 1)
        self.assertEqual(len(call(mapper, "persistence.RevocationPlannerPersistence").keywords), 7)
        self.assertNotIn("writer_response_signing_key", ast.unparse(mapper))
        self.assertNotIn("authority_revocation_writer_signer", ast.unparse(mapper_tree))
        adapter = definition(self.process, "_persist_and_reserve_revocation_commitments")
        self.shape(assigned(adapter, "writer_private_key"), "self.writer_response_signing_key")
        delegated = call(adapter, "authority_revocation_writer_composition._persist_commitments_on_configuration")
        private, = [item.value for item in delegated.keywords if item.arg == "writer_private_key"]
        self.shape(private, "writer_private_key")
        self.assertFalse(calls(adapter, "authority_revocation_writer_signer._signer_from_pem"))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == "sign"
                             for node in ast.walk(adapter)))
        handle = definition(self.process, "handle")
        writer, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        verification = call(writer, "self._verify_internal_envelope")
        purposes, = [item.value for item in verification.keywords if item.arg == "allowed_purposes"]
        self.shape(purposes, "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        for dispatcher in (handle, definition(definition(self.service, "AuthorityServer"), "_serve_connection")):
            for spelling in ("writer_response_signing_key", "authority_revocation_writer_signer",
                    "_persist_and_reserve_revocation_commitments", "authorize-revocation-writer-custody",
                    "relay-revocation-writer-custody"):
                self.assertNotIn(spelling, ast.unparse(dispatcher))
        topology = ast.unparse(definition(definition(self.service, "MeasuredConfiguration"), "_verify_role_topology"))
        self.assertIn("(int(planner_writer.get('peerUid', -1)), int(planner_writer.get('peerGid', -1))) != "
                      "(int(planner['serviceUid']), int(planner['serviceGid']))", topology)
        _, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        closed, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(closed.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(closed.body[0], ast.Raise)


if __name__ == "__main__":
    unittest.main()
