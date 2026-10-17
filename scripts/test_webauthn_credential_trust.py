#!/usr/bin/env python3
"""Pure credential-policy classification, not enrollment or root authority.

Independent branch dictionaries exercise the actual production core. Source
wiring controls are supplemental only: this file never imports the blocked
WebAuthn/database/application graph or substitutes an authority registry.
"""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import webauthn_credential_trust as core


ROOT_SHA = "sha256:" + "a" * 64
BUNDLE_SHA = "sha256:" + "b" * 64
OLD_BUNDLE_SHA = "sha256:" + "c" * 64
GUID = "2fc0579f-8113-47ea-b116-bb5a8db9202a"


def facts(**changes):
    values = {
        "enrollment_trusted": True, "authenticator_class": "hardware",
        "has_development_key": False, "root_sha256": ROOT_SHA, "aaguid": GUID,
        "enrolled_bundle_digest": OLD_BUNDLE_SHA, "enrolled_bundle_sequence": 3,
    }
    values.update(changes)
    return core.CredentialTrustFacts(**values)


def root(**changes):
    values = {
        "id": "root-first", "certificate_sha256": ROOT_SHA,
        "authenticator_class": "hardware", "aaguids": (GUID,),
        "bundle_digest": BUNDLE_SHA, "bundle_sequence": 7,
    }
    values.update(changes)
    return core.RootTrustPolicy(**values)


def policy(*roots, development_enabled=False):
    return core.CredentialTrustContext(tuple(roots), development_enabled)


def expected(reason, *, enrolled=True, trusted=False, effective="unknown",
             bundle=None, sequence=None, root_id=None, root_sha=None):
    result = {
        "enrollment_trusted": enrolled, "currently_trusted": trusted,
        "reason": reason, "effective_authenticator_class": effective,
        "current_trust_bundle_digest": bundle,
        "current_trust_bundle_sequence": sequence,
    }
    if root_id is not None:
        result["current_trust_root_id"] = root_id
        result["current_trust_root_sha256"] = root_sha
    return result


class CredentialTrustClassificationTests(unittest.TestCase):
    def test_current_root_success_preserves_exact_legacy_output_fields(self):
        actual = core.classify(facts(), policy(root())).as_dict()
        self.assertEqual(actual, expected(
            "trusted_by_current_root", trusted=True, effective="hardware",
            bundle=BUNDLE_SHA, sequence=7, root_id="root-first", root_sha=ROOT_SHA))
        self.assertEqual(len(actual), 8)

    def test_unattested_precedes_missing_or_matching_root_and_discards_enrolled_metadata(self):
        for digest in (None, "", ROOT_SHA):
            with self.subTest(digest=digest):
                actual = core.classify(facts(enrollment_trusted=False, root_sha256=digest), policy(root()))
                self.assertEqual(actual.as_dict(), expected("not_attested", enrolled=False))

    def test_missing_root_and_withdrawn_root_have_distinct_denial_reasons(self):
        for missing in (None, ""):
            with self.subTest(missing=missing):
                self.assertEqual(core.classify(facts(root_sha256=missing), policy(root())).as_dict(),
                                 expected("attestation_root_missing"))
        self.assertEqual(core.classify(facts(), policy()).as_dict(), expected("trust_root_withdrawn"))
        self.assertEqual(core.classify(facts(), policy(root(certificate_sha256="different"))).as_dict(),
                         expected("trust_root_withdrawn"))

    def test_aaguid_restriction_precedes_class_change_and_retains_current_bundle(self):
        actual = core.classify(facts(), policy(root(aaguids=("other",), authenticator_class="yubikey")))
        self.assertEqual(actual.as_dict(), expected(
            "aaguid_no_longer_trusted", bundle=BUNDLE_SHA, sequence=7))
        self.assertNotIn("current_trust_root_id", actual.as_dict())

    def test_class_change_is_literal_and_empty_or_none_root_class_is_unconstrained(self):
        for changed in ("Hardware", "yubikey"):
            with self.subTest(changed=changed):
                self.assertEqual(core.classify(facts(), policy(root(authenticator_class=changed))).as_dict(),
                                 expected("authenticator_class_changed", bundle=BUNDLE_SHA, sequence=7))
        for unconstrained in (None, ""):
            with self.subTest(unconstrained=unconstrained):
                actual = core.classify(facts(authenticator_class="custom-class"),
                                       policy(root(authenticator_class=unconstrained)))
                self.assertTrue(actual.currently_trusted)
                self.assertEqual(actual.effective_authenticator_class, "custom-class")

    def test_first_matching_root_wins_even_when_later_duplicate_would_allow(self):
        denied = root(aaguids=("other",), bundle_digest="first-bundle", bundle_sequence=1)
        allowed = root(id="root-second", bundle_digest="second-bundle", bundle_sequence=2)
        self.assertEqual(core.classify(facts(), policy(denied, allowed)).as_dict(), expected(
            "aaguid_no_longer_trusted", bundle="first-bundle", sequence=1))
        actual = core.classify(facts(), policy(allowed, denied)).as_dict()
        self.assertEqual(actual, expected(
            "trusted_by_current_root", trusted=True, effective="hardware",
            bundle="second-bundle", sequence=2, root_id="root-second", root_sha=ROOT_SHA))

    def test_aaguid_uses_lower_not_casefold_and_empty_policy_allows_missing_aaguid(self):
        self.assertTrue(core.classify(facts(aaguid=GUID.upper()), policy(root())).currently_trusted)
        self.assertTrue(core.classify(facts(), policy(root(aaguids=(GUID.upper(),)))).currently_trusted)
        self.assertTrue(core.classify(facts(aaguid=""), policy(root(aaguids=()))).currently_trusted)
        self.assertEqual(core.classify(facts(aaguid="ß"), policy(root(aaguids=("ss",)))).reason,
                         "aaguid_no_longer_trusted")
        self.assertTrue(core.classify(facts(aaguid="Σ"), policy(root(aaguids=("σ",)))).currently_trusted)

    def test_root_digest_comparison_is_literal_without_new_hash_or_uuid_policy(self):
        literal = root(certificate_sha256="Root-Literal", aaguids=("not-a-uuid",))
        accepted = core.classify(facts(root_sha256="Root-Literal", aaguid="NOT-A-UUID"), policy(literal))
        self.assertTrue(accepted.currently_trusted)
        self.assertEqual(accepted.current_trust_root_sha256, "Root-Literal")
        self.assertEqual(core.classify(facts(root_sha256="root-literal"), policy(literal)).reason,
                         "trust_root_withdrawn")

    def test_development_exception_requires_all_three_conditions(self):
        for enabled, has_key, stored_class in ((True, True, "dev"), (False, True, "dev"),
                                               (True, False, "dev"), (True, True, "Dev")):
            with self.subTest(enabled=enabled, has_key=has_key, stored_class=stored_class):
                actual = core.classify(facts(authenticator_class=stored_class, has_development_key=has_key),
                                       policy(development_enabled=enabled)).as_dict()
                if enabled and has_key and stored_class == "dev":
                    self.assertEqual(actual, expected(
                        "development_authenticator", trusted=True, effective="dev",
                        bundle=OLD_BUNDLE_SHA, sequence=3))
                else:
                    self.assertEqual(actual, expected("trust_root_withdrawn"))

    def test_unattested_development_exception_retains_only_enrolled_bundle_metadata(self):
        actual = core.classify(facts(enrollment_trusted=False, authenticator_class="dev",
                                    has_development_key=True, root_sha256=None),
                               policy(development_enabled=True))
        self.assertEqual(actual.as_dict(), expected(
            "not_attested", enrolled=False, bundle=OLD_BUNDLE_SHA, sequence=3))
        self.assertEqual(len(actual.as_dict()), 6)

    def test_needs_current_roots_matches_all_lazy_load_branches(self):
        for enrolled in (False, True):
            for digest in (None, "", ROOT_SHA):
                for enabled in (False, True):
                    for has_key in (False, True):
                        for stored_class in ("dev", "hardware"):
                            with self.subTest(enrolled=enrolled, digest=digest, enabled=enabled,
                                              has_key=has_key, stored_class=stored_class):
                                wanted = (enrolled and bool(digest)
                                          and not (stored_class == "dev" and enabled and has_key))
                                actual = core.needs_current_roots(
                                    facts(enrollment_trusted=enrolled, root_sha256=digest,
                                          has_development_key=has_key, authenticator_class=stored_class),
                                    development_enabled=enabled)
                                self.assertIs(actual, wanted)

    def test_context_owns_nested_roots_and_result_projection_is_fresh(self):
        original = root()
        context = policy(original)
        self.assertIsNot(context.roots[0], original)
        self.assertEqual(context.roots[0], original)
        object.__setattr__(original, "id", "changed-original")
        object.__setattr__(original, "aaguids", ("changed-original",))
        actual = core.classify(facts(), context)
        self.assertTrue(actual.currently_trusted)
        self.assertEqual(actual.current_trust_root_id, "root-first")
        first, second = actual.as_dict(), actual.as_dict()
        self.assertIsNot(first, second)
        first["currently_trusted"] = False
        first["current_trust_root_id"] = "changed-output"
        self.assertTrue(second["currently_trusted"])
        self.assertEqual(actual.current_trust_root_id, "root-first")
        for item, name, value in ((actual, "currently_trusted", False),
                                  (context, "development_enabled", True),
                                  (context.roots[0], "id", "changed"),
                                  (facts(), "enrollment_trusted", False)):
            with self.subTest(kind=type(item)), self.assertRaises(FrozenInstanceError):
                setattr(item, name, value)

    def test_fact_and_policy_types_are_closed_without_secret_or_certificate_fields(self):
        self.assertEqual(tuple(field.name for field in fields(core.CredentialTrustFacts)), (
            "enrollment_trusted", "authenticator_class", "has_development_key", "root_sha256",
            "aaguid", "enrolled_bundle_digest", "enrolled_bundle_sequence"))
        self.assertEqual(tuple(field.name for field in fields(core.RootTrustPolicy)), (
            "id", "certificate_sha256", "authenticator_class", "aaguids", "bundle_digest", "bundle_sequence"))
        for item in (facts(), root(), policy(root()), core.classify(facts(), policy(root()))):
            self.assertFalse(hasattr(item, "__dict__"))
            self.assertFalse(hasattr(item, "dev_private_key_pem"))
            self.assertFalse(hasattr(item, "certificate"))
        with self.assertRaises(TypeError):
            core.CredentialTrustFacts(**{field.name: getattr(facts(), field.name)
                                        for field in fields(core.CredentialTrustFacts)},
                                      dev_private_key_pem="private bytes must not enter")

    def test_malformed_boolean_collections_text_and_unicode_are_rejected(self):
        for field in ("enrollment_trusted", "has_development_key"):
            for value in (0, 1, None, "true"):
                with self.subTest(field=field, value=value), self.assertRaises(core.CredentialTrustError):
                    facts(**{field: value})
        for value in (0, 1, None, "true"):
            with self.subTest(enabled=value), self.assertRaises(core.CredentialTrustError):
                policy(development_enabled=value)
        for value in ([GUID], {GUID}, (1,), ("\x00",), ("\ud800",)):
            with self.subTest(aaguids=value), self.assertRaises(core.CredentialTrustError):
                root(aaguids=value)
        with self.assertRaises(core.CredentialTrustError):
            core.CredentialTrustContext([root()], False)
        for field in ("authenticator_class", "aaguid", "root_sha256", "enrolled_bundle_digest"):
            for value in (b"text", 1, "with\x00nul", "\ud800"):
                with self.subTest(field=field, value=value), self.assertRaises(core.CredentialTrustError):
                    facts(**{field: value})
        for field in ("id", "certificate_sha256", "authenticator_class", "bundle_digest"):
            with self.subTest(field=field), self.assertRaises(core.CredentialTrustError):
                root(**{field: b"not text"})

    def test_nullable_signed64_sequence_metadata_is_preserved_without_coercion(self):
        for sequence in (None, -(1 << 63), 0, (1 << 63) - 1):
            with self.subTest(sequence=sequence):
                self.assertEqual(core.classify(facts(), policy(root(bundle_sequence=sequence)))
                                 .current_trust_bundle_sequence, sequence)
                self.assertEqual(core.classify(
                    facts(authenticator_class="dev", has_development_key=True,
                          enrolled_bundle_sequence=sequence), policy(development_enabled=True))
                    .current_trust_bundle_sequence, sequence)
        for sequence in (True, 1.0, "1", -(1 << 63) - 1, 1 << 63):
            with self.subTest(sequence=sequence):
                with self.assertRaises(core.CredentialTrustError):
                    facts(enrolled_bundle_sequence=sequence)
                with self.assertRaises(core.CredentialTrustError):
                    root(bundle_sequence=sequence)

    def test_root_count_and_aaguid_count_bounds_are_exact_not_truncated(self):
        self.assertEqual((core.MAX_ROOTS, core.MAX_ROOT_AAGUIDS, core.MAX_INPUT_BYTES), (256, 1024, 2097152))
        full = policy(*(root(id=str(index)) for index in range(256)))
        self.assertEqual(len(full.roots), 256)
        self.assertEqual(core.classify(facts(), full).current_trust_root_id, "0")
        with self.assertRaises(core.CredentialTrustError):
            policy(*(root(id=str(index)) for index in range(257)))
        many_aaguids = root(aaguids=(GUID,) * 1024)
        self.assertEqual(len(many_aaguids.aaguids), 1024)
        self.assertTrue(core.classify(facts(), policy(many_aaguids)).currently_trusted)
        with self.assertRaises(core.CredentialTrustError):
            root(aaguids=(GUID,) * 1025)

    def test_root_input_byte_count_is_utf8_lossless_and_revalidates_each_field(self):
        # UTF8 byte counts: ID2 + digest3 + class8 + AAGUIDs(2+2+1)
        # + bundle2 =20. Duplicate AAGUID entries are charged, not deduplicated.
        for sequence, counter_bytes in ((None, 0), (-(1 << 63), 8), (0, 8), ((1 << 63) - 1, 8)):
            with self.subTest(sequence=sequence):
                descriptor = core.RootTrustPolicy("é", "根", "hardware", ("é", "é", "A"), "ß", sequence)
                size = descriptor.input_size_bytes()
                self.assertIs(type(size), int)
                self.assertEqual(size, 20 + counter_bytes)
        nullable = core.RootTrustPolicy("é", "根", None, ("é", "é", "A"), None, None)
        self.assertEqual(nullable.input_size_bytes(), 10)
        exact = core.RootTrustPolicy("x" * (2097152 - 1), "r", None, (), None, None)
        self.assertEqual(exact.input_size_bytes(), 2097152)
        for field, value in (("id", "bad\x00id"), ("certificate_sha256", b"bytes"),
                             ("authenticator_class", 1), ("aaguids", [GUID]),
                             ("bundle_digest", "\ud800"), ("bundle_sequence", True)):
            with self.subTest(field=field):
                poisoned = root()
                object.__setattr__(poisoned, field, value)
                with self.assertRaises(core.CredentialTrustError):
                    poisoned.input_size_bytes()
        object.__setattr__(exact, "id", "x" * 2097152)
        with self.assertRaises(core.CredentialTrustError):
            exact.input_size_bytes()
        with self.assertRaises(core.CredentialTrustError):
            object.__new__(core.RootTrustPolicy).input_size_bytes()

    def test_combined_input_byte_bound_counts_facts_roots_flags_and_utf8(self):
        # Minimal facts are two booleans. Context is one boolean. Root below
        # has one certificate-digest byte and N ID bytes, no other payload.
        minimal = core.CredentialTrustFacts(False, "", False, None, "", None, None)
        fill = "x" * (2097152 - 4)
        exact = core.RootTrustPolicy(fill, "r", None, (), None, None)
        self.assertEqual(core.classify(minimal, policy(exact)).as_dict(), expected("not_attested", enrolled=False))
        over = core.RootTrustPolicy(fill + "x", "r", None, (), None, None)
        with self.assertRaisesRegex(core.CredentialTrustError, "aggregate byte bound"):
            core.classify(minimal, policy(over))
        with self.assertRaises(core.CredentialTrustError):
            facts(aaguid="é" * 1048577)

    def test_near_limit_unattested_development_metadata_survives_result_labels(self):
        # Two fact booleans + 'dev' (3 bytes) + one context boolean = 6.
        retained = "x" * (2097152 - 6)
        exact = core.CredentialTrustFacts(False, "dev", True, None, "", retained, None)
        actual = core.classify(exact, policy(development_enabled=True))
        self.assertEqual(actual.as_dict(), expected("not_attested", enrolled=False, bundle=retained))
        self.assertEqual(core.MAX_RESULT_BYTES, 2097152 + 128)
        too_much = replace(exact, enrolled_bundle_digest=retained + "x")
        with self.assertRaisesRegex(core.CredentialTrustError, "aggregate byte bound"):
            core.classify(too_much, policy(development_enabled=True))

    def test_bypassed_dataclasses_are_revalidated_at_actual_classification_boundaries(self):
        poisoned_facts = facts()
        object.__setattr__(poisoned_facts, "enrollment_trusted", 1)
        with self.assertRaises(core.CredentialTrustError):
            core.classify(poisoned_facts, policy(root()))
        with self.assertRaises(core.CredentialTrustError):
            core.needs_current_roots(poisoned_facts, development_enabled=False)
        poisoned_policy = policy(root())
        object.__setattr__(poisoned_policy.roots[0], "aaguids", [GUID])
        with self.assertRaises(core.CredentialTrustError):
            core.classify(facts(), poisoned_policy)
        context = policy(root())
        object.__setattr__(context, "development_enabled", 1)
        with self.assertRaises(core.CredentialTrustError):
            core.classify(facts(), context)
        result = core.classify(facts(), policy(root()))
        object.__setattr__(result, "currently_trusted", 1)
        with self.assertRaises(core.CredentialTrustError):
            result.as_dict()
        with self.assertRaises(core.CredentialTrustError):
            core.classify({}, policy())
        with self.assertRaises(core.CredentialTrustError):
            core.classify(facts(), {})
        with self.assertRaises(core.CredentialTrustError):
            core.classify(object.__new__(core.CredentialTrustFacts), policy())
        with self.assertRaises(core.CredentialTrustError):
            core.classify(facts(), object.__new__(core.CredentialTrustContext))
        with self.assertRaises(core.CredentialTrustError):
            policy(object.__new__(core.RootTrustPolicy))


class CredentialTrustSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repository = Path(__file__).resolve().parents[1]
        cls.web = ast.parse((repository / "catchplate/webauthn.py").read_text())
        cls.app = ast.parse((repository / "catchplate/app.py").read_text())

    def function(self, tree, name):
        matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        self.assertEqual(len(matches), 1)
        return matches[0]

    @staticmethod
    def calls(node, name):
        return [call for call in ast.walk(node) if isinstance(call, ast.Call)
                and ast.unparse(call.func) == name]

    @staticmethod
    def expression(value):
        return ast.dump(ast.parse(value, mode="eval").body)

    def test_pure_core_has_no_ambient_configuration_clock_io_or_wrapper_import(self):
        source = Path(core.__file__).read_text()
        tree = ast.parse(source)
        modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(modules, {"__future__", "dataclasses"})
        self.assertEqual(imports, set())
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(calls.isdisjoint({"open", "eval", "exec", "__import__"}))

    def test_live_context_wrapper_projects_only_bounded_primitive_root_descriptors(self):
        capture = self.function(self.web, "credential_trust_context")
        constructors = self.calls(capture, "credential_trust_core.RootTrustPolicy")
        self.assertEqual(len(constructors), 1)
        self.assertEqual(constructors[0].args, [])
        self.assertEqual({keyword.arg: ast.dump(keyword.value) for keyword in constructors[0].keywords}, {
            "id": self.expression("root.id"),
            "certificate_sha256": self.expression("root.certificate_sha256"),
            "authenticator_class": self.expression("root.authenticator_class"),
            "aaguids": self.expression("tuple(root.aaguids)"),
            "bundle_digest": self.expression("root.bundle_digest"),
            "bundle_sequence": self.expression("root.bundle_sequence"),
        })
        conditions = {ast.dump(node.test) for node in ast.walk(capture) if isinstance(node, ast.If)}
        self.assertIn(self.expression("type(trust_roots) is not list or len(trust_roots) > credential_trust_core.MAX_ROOTS"), conditions)
        self.assertIn(self.expression("type(root) is not TrustRoot"), conditions)
        self.assertIn(self.expression("type(root.aaguids) is not frozenset or len(root.aaguids) > credential_trust_core.MAX_ROOT_AAGUIDS"), conditions)
        root_loop = [node for node in ast.walk(capture) if isinstance(node, ast.For)]
        self.assertEqual(len(root_loop), 1)
        self.assertEqual(ast.dump(root_loop[0].iter), self.expression("trust_roots"))
        # The outer wrapper must reject cumulative work before appending or
        # advancing to the next root, not only when constructing final context.
        projections = [node for node in root_loop[0].body if isinstance(node, ast.Assign)
                       and node.value is constructors[0]]
        self.assertEqual(len(projections), 1)
        self.assertEqual(len(projections[0].targets), 1)
        self.assertIsInstance(projections[0].targets[0], ast.Name)
        projected_name = projections[0].targets[0].id
        charges = [node for node in root_loop[0].body if isinstance(node, ast.AugAssign)]
        self.assertEqual(len(charges), 1)
        charge = charges[0]
        self.assertIsInstance(charge.op, ast.Add)
        self.assertIsInstance(charge.target, ast.Name)
        self.assertEqual(ast.dump(charge.value), self.expression(projected_name + ".input_size_bytes()"))
        budget_name = charge.target.id
        initializers = [node for node in ast.walk(capture) if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == budget_name
                                for target in node.targets)]
        self.assertEqual(len(initializers), 1)
        self.assertEqual(ast.dump(initializers[0].value), self.expression("1"))
        self.assertLess(initializers[0].lineno, root_loop[0].lineno)
        guards = [node for node in root_loop[0].body if isinstance(node, ast.If)
                  and ast.dump(node.test) == self.expression(
                      budget_name + " > credential_trust_core.MAX_INPUT_BYTES")]
        self.assertEqual(len(guards), 1)
        self.assertTrue(any(isinstance(node, ast.Raise) for node in guards[0].body))
        self.assertEqual(len(self.calls(guards[0], "credential_trust_core.CredentialTrustError")), 1)
        appends = self.calls(root_loop[0], "roots.append")
        self.assertEqual(len(appends), 1)
        self.assertEqual([ast.dump(value) for value in appends[0].args],
                         [self.expression(projected_name)])
        self.assertLess(projections[0].lineno, charge.lineno)
        self.assertLess(charge.lineno, guards[0].lineno)
        self.assertLess(guards[0].lineno, appends[0].lineno)
        contexts = self.calls(capture, "credential_trust_core.CredentialTrustContext")
        self.assertEqual(len(contexts), 1)
        self.assertEqual([ast.dump(value) for value in contexts[0].args],
                         [self.expression("tuple(roots)"), self.expression("development_enabled")])
        catches = [ast.unparse(node.type) for node in ast.walk(capture) if isinstance(node, ast.ExceptHandler)]
        self.assertIn("(credential_trust_core.CredentialTrustError, AttributeError)", catches)
        self.assertEqual(len(self.calls(capture, "WebAuthnTrustError")), 1)

    def test_live_status_wrapper_keeps_legacy_fact_normalization_and_lazy_root_load(self):
        wrapper = self.function(self.web, "credential_trust_status")
        constructors = self.calls(wrapper, "credential_trust_core.CredentialTrustFacts")
        self.assertEqual(len(constructors), 1)
        self.assertEqual(constructors[0].args, [])
        expressions = {
            "enrollment_trusted": "bool(credential.get('attestation_trusted'))",
            "authenticator_class": "str(credential.get('authenticator_class') or 'unknown')",
            "has_development_key": "bool(credential.get('dev_private_key_pem'))",
            "root_sha256": "credential.get('attestation_root_sha256')",
            "aaguid": "str(credential.get('aaguid') or '')",
            "enrolled_bundle_digest": "credential.get('attestation_trust_bundle_digest')",
            "enrolled_bundle_sequence": "credential.get('attestation_trust_bundle_sequence')",
        }
        self.assertEqual({keyword.arg: ast.dump(keyword.value) for keyword in constructors[0].keywords},
                         {key: self.expression(value) for key, value in expressions.items()})
        branches = [node for node in ast.walk(wrapper) if isinstance(node, ast.If)]
        self.assertIn(self.expression("trust_roots is not None and trust_context is not None"),
                      {ast.dump(node.test) for node in branches})
        context_branch = next(node for node in branches if ast.dump(node.test) == self.expression("trust_context is None"))
        self.assertEqual(len(self.calls(wrapper, "_load_trust_roots_cached")), 1)
        self.assertEqual(len(self.calls(context_branch, "_load_trust_roots_cached")), 1)
        lazy = [node for node in ast.walk(context_branch) if isinstance(node, ast.IfExp)]
        self.assertEqual(len(lazy), 1)
        self.assertEqual(ast.dump(lazy[0].test), self.expression(
            "credential_trust_core.needs_current_roots(facts, development_enabled=development_enabled)"))
        self.assertEqual(ast.dump(lazy[0].body), self.expression("_load_trust_roots_cached()"))
        self.assertEqual(ast.dump(lazy[0].orelse), self.expression("[]"))
        returned = [node.value for node in ast.walk(wrapper) if isinstance(node, ast.Return)]
        self.assertEqual([ast.dump(node) for node in returned],
                         [self.expression("credential_trust_core.classify(facts, trust_context).as_dict()")])
        catches = [ast.unparse(node.type) for node in ast.walk(wrapper) if isinstance(node, ast.ExceptHandler)]
        self.assertEqual(catches, ["credential_trust_core.CredentialTrustError"])

    def test_descriptor_loop_reuses_one_context_and_preserves_early_root_load_predicate(self):
        function = self.function(self.web, "_credential_descriptors_for_policy")
        captures = self.calls(function, "credential_trust_context")
        loops = [node for node in ast.walk(function) if isinstance(node, ast.For)]
        self.assertEqual(len(captures), 1)
        self.assertEqual(len(loops), 1)
        self.assertLess(captures[0].lineno, loops[0].lineno)
        self.assertEqual(self.calls(loops[0], "credential_trust_context"), [])
        selected = self.calls(loops[0], "_allowed_authenticator")
        self.assertEqual(len(selected), 1)
        self.assertEqual({keyword.arg: ast.dump(keyword.value) for keyword in selected[0].keywords},
                         {"trust_context": self.expression("trust_context")})
        predicates = [node for node in ast.walk(function) if isinstance(node, ast.GeneratorExp)]
        self.assertEqual(len(predicates), 1)
        self.assertEqual(ast.dump(predicates[0].elt), self.expression(
            "item.get('attestation_trusted') and not (item.get('authenticator_class') == 'dev' "
            "and development_enabled and item.get('dev_private_key_pem'))"))
        allowed = self.function(self.web, "_allowed_authenticator")
        trust_calls = self.calls(allowed, "credential_trust_status")
        self.assertEqual(len(trust_calls), 1)
        self.assertEqual({keyword.arg: ast.dump(keyword.value) for keyword in trust_calls[0].keywords},
                         {"trust_roots": self.expression("trust_roots"),
                          "trust_context": self.expression("trust_context")})

    def test_withdrawal_enumeration_and_both_publish_passes_reuse_captured_policy(self):
        impact = self.function(self.app, "_webauthn_trust_withdrawal_impact")
        captures = self.calls(impact, "credential_trust_context")
        loops = [node for node in ast.walk(impact) if isinstance(node, ast.For)]
        self.assertEqual(len(captures), 1)
        self.assertEqual(len(loops), 1)
        self.assertLess(captures[0].lineno, loops[0].lineno)
        self.assertEqual(ast.dump(loops[0].iter), self.expression("db.list_webauthn_credentials()"))
        self.assertEqual(self.calls(loops[0], "credential_trust_context"), [])
        status = self.calls(loops[0], "credential_trust_status")
        self.assertEqual(len(status), 1)
        self.assertEqual({keyword.arg: ast.dump(keyword.value) for keyword in status[0].keywords},
                         {"trust_context": self.expression("trust_context")})
        publish = self.function(self.app, "webauthn_trust_publish")
        snapshots = self.calls(publish, "credential_trust_context")
        impacts = self.calls(publish, "_webauthn_trust_withdrawal_impact")
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(len(impacts), 2)
        self.assertEqual([ast.dump(value) for value in snapshots[0].args],
                         [self.expression("candidate_roots")])
        snapshot_assignment = [node for node in ast.walk(publish) if isinstance(node, ast.Assign)
                               and node.value is snapshots[0]]
        self.assertEqual(len(snapshot_assignment), 1)
        self.assertEqual([ast.dump(target) for target in snapshot_assignment[0].targets],
                         [ast.dump(ast.Name(id="candidate_context", ctx=ast.Store()))])
        for call in impacts:
            self.assertLess(snapshots[0].lineno, call.lineno)
            self.assertEqual(call.args, [])
            self.assertEqual({keyword.arg: ast.dump(keyword.value) for keyword in call.keywords},
                             {"trust_context": self.expression("candidate_context")})
            guarded = [node for node in ast.walk(publish) if isinstance(node, ast.Try)
                       and any(call is child for statement in node.body for child in ast.walk(statement))]
            self.assertTrue(any(
                isinstance(handler.type, ast.Name) and handler.type.id == "WebAuthnTrustError"
                and any(isinstance(raised.exc, ast.Call) and isinstance(raised.exc.func, ast.Name)
                        and raised.exc.func.id == "HTTPException"
                        and any(keyword.arg == "status_code" and isinstance(keyword.value, ast.Constant)
                                and keyword.value.value == 409 for keyword in raised.exc.keywords)
                        for raised in ast.walk(handler) if isinstance(raised, ast.Raise))
                for scope in guarded for handler in scope.handlers))


if __name__ == "__main__":
    unittest.main()
