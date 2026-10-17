"""Signed-selection/factory controls, not measured/native admission.

Real source configuration commitments and Ed25519 key pairing use synthetic
originals. The generator's actual narrow projection is extracted verbatim to
keep this component independent of unrelated unfinished operation admission.
Service6/local-signing reachability is source-checked, not simulated as live.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import unittest
from unittest import mock

from catchplate import authority_recovery_invalidation_configuration as source
from catchplate import authority_recovery_retention_policy as policy
from catchplate.authority_query_read_work import QueryReadValidationLimits
from test_authority_jit_original_configuration import Fixture as ConfigurationFixture, digest, work
from test_authority_recovery_custody import fixture as recovery_fixture


ROOT = Path(__file__).resolve().parents[1]
READ_DSN = "host=synthetic.invalid dbname=synthetic"


class Fixture(ConfigurationFixture):
    def __init__(self):
        super().__init__()
        recovery, webauthn = recovery_fixture()
        self.payload[source.recovery.FIELD] = recovery
        self.payload["webauthn"] = webauthn
        self.payload["roles"]["planner"]["enabledOperations"] = [source.OPERATION]
        self.seal()

    def arguments(self, **changes):
        result = dict(payload=self.payload, configuration_digest=self.digest,
            generation=self.generation, runtime_role_identities=self.runtime,
            read_dsn=READ_DSN, planner_private_key=self.private, work=work())
        result.update(changes)
        return result


def projection():
    path = ROOT / "scripts/authority/generate_artifact_bundle.py"
    tree = ast.parse(path.read_text())
    definitions = [node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        and node.name in {"GeneratorError", "_recovery_selection"}]
    if len(definitions) != 2:
        raise AssertionError("actual generator projection definitions changed")
    namespace = {"recovery_configuration": source.recovery}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace["_recovery_selection"]


class RecoveryInvalidationConfigurationControls(unittest.TestCase):
    def test_recovery_policy_is_closed_explicit_and_uses_real_recovery_bounds(self):
        for seconds, maximum in ((86_400, 100), (31_536_000, 1_000_000), (1_234_567, 3456)):
            selected = policy.project_policy(terminal_retention_seconds=seconds, maximum_retained=maximum)
            meter = work()
            captured = policy.capture_policy(selected, work=meter)
            self.assertIsNot(captured, selected)
            self.assertEqual(captured, {"schema": policy.SCHEMA,
                "terminalRetentionSeconds": seconds, "maximumRetained": maximum})
            self.assertGreater(meter.input_bytes, 0)
            self.assertGreater(meter.json_nodes, 0)
        for name, values in (("terminalRetentionSeconds", (True, 1.0, 60, 86_399, 31_536_001)),
                ("maximumRetained", (True, 100.0, 99, 1_000_001))):
            for value in values:
                selected = policy.project_policy(terminal_retention_seconds=86_400, maximum_retained=100)
                selected[name] = value
                with self.subTest(field=name, value=value), self.assertRaises(policy.RecoveryRetentionPolicyError):
                    policy.capture_policy(selected, work=work())
        for change in (lambda value: value.update(schema="catchplate.policyAuthorityChallengeMaintenancePolicy/v1"),
                lambda value: value.update(verified=True), lambda value: value.pop("maximumRetained")):
            selected = policy.project_policy(terminal_retention_seconds=86_400, maximum_retained=100)
            change(selected)
            with self.assertRaises(policy.RecoveryRetentionPolicyError):
                policy.capture_policy(selected, work=work())
        with self.assertRaises(TypeError):
            policy.project_policy(terminal_retention_seconds=86_400)

    def test_generator_projects_explicit_originals_without_migration_or_mutation(self):
        project = projection()
        selected, webauthn = recovery_fixture()
        original = copy.deepcopy(selected)
        self.assertIs(project(selected, webauthn=webauthn), selected)
        self.assertEqual(selected, original)
        self.assertIsNone(project(None, webauthn=webauthn))
        del selected[policy.FIELD]
        with self.assertRaises(source.recovery.RecoveryConfigurationError):
            project(selected, webauthn=webauthn)
        self.assertNotIn(policy.FIELD, selected)
        selected = copy.deepcopy(original)
        selected[policy.FIELD]["terminalRetentionSeconds"] = True
        with self.assertRaises(source.recovery.RecoveryConfigurationError):
            project(selected, webauthn=webauthn)
        self.assertIs(selected[policy.FIELD]["terminalRetentionSeconds"], True)

    def test_real_inert_owner_captures_exact_signed_policy_read_identity_and_key(self):
        fixture, meter = Fixture(), work()
        with mock.patch.object(source.planning.physical, "_connect", side_effect=AssertionError("native open")):
            result = source._producer_from_configuration_on_work(**fixture.arguments(work=meter))
        self.assertIs(type(result), source.owner.RecoveryInvalidationPlanOwner)
        self.assertEqual(result.operation, "webauthn.recovery.invalidate")
        configured = result._snapshot()
        self.assertIs(type(configured[0]), source.planning.RecoveryInvalidationReadPlanner)
        self.assertIs(configured[1], configured[0]._configured)
        planner = fixture.payload["roles"]["planner"]
        identity = (planner["plannerSessionIdentityDigest"], planner["measurementDigest"],
            fixture.runtime["roles"]["planner"]["attestationReceiptDigest"])
        self.assertEqual(configured[1], (READ_DSN, 2,
            (planner["databaseRole"], planner["tlsClientDn"], planner["tlsClientSerial"],
                planner["tlsIssuerDn"], *identity), 7_776_000, 100_000))
        self.assertIs(configured[2], fixture.private)
        self.assertEqual(configured[4:7], (identity, planner["signingSpkiDigest"], fixture.digest))
        self.assertEqual(configured[7], (9_000_000_000, source.evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS))
        self.assertGreater(meter.hash_work, 0)
        self.assertGreater(meter.input_bytes, 0)

    def test_explicit_nondefault_recovery_policy_is_the_only_retention_selection(self):
        fixture = Fixture()
        fixture.payload[source.recovery.FIELD][policy.FIELD] = policy.project_policy(
            terminal_retention_seconds=123_456, maximum_retained=4321)
        fixture.payload["webauthnChallengeMaintenance"] = {"terminalRetentionSeconds": 60,
            "maximumRetained": 999_999}
        fixture.seal()
        with mock.patch("os.getenv", side_effect=AssertionError("ambient setting read")):
            result = source._producer_from_configuration_on_work(**fixture.arguments())
        self.assertEqual(result._snapshot()[1][3:], (123_456, 4321))

    def test_invalid_originals_refuse_before_any_key_constructor(self):
        for kind in ("commitment", "generation", "runtime", "query", "disabled", "missing",
                "legacy", "wrong-policy", "rp", "age", "dsn", "signer"):
            fixture, options = Fixture(), {}
            if kind == "commitment": fixture.payload["roles"]["planner"]["tlsClientDn"] = "CN=changed"
            if kind == "generation": fixture.generation["digest"] = digest(b"other generation")
            if kind == "runtime": fixture.runtime["roles"]["planner"]["measurementDigest"] = digest(b"other")
            if kind == "query": fixture.payload["queryManifestDigest"] = digest(b"other query")
            if kind == "disabled": fixture.payload["roles"]["planner"]["enabledOperations"] = []
            if kind == "missing": del fixture.payload[source.recovery.FIELD]
            if kind == "legacy": del fixture.payload[source.recovery.FIELD][policy.FIELD]
            if kind == "wrong-policy": fixture.payload[source.recovery.FIELD][policy.FIELD]["maximumRetained"] = True
            if kind == "rp": fixture.payload["webauthn"]["rpId"] = "other.test"
            if kind == "age": fixture.payload["roles"]["verifier"]["maximumInternalAgeNs"] = True
            if kind == "dsn": options["read_dsn"] = "host=synthetic.invalid\ncaller=value"
            if kind == "signer": options["planner_private_key"] = object()
            if kind not in ("commitment", "generation", "runtime"):
                fixture.seal()
            with self.subTest(kind=kind), mock.patch.object(source.configuration, "_key",
                    side_effect=AssertionError("invalid selection reached key callback")), \
                    self.assertRaises(source.RecoveryInvalidationConfigurationError):
                source._producer_from_configuration_on_work(**fixture.arguments(**options))

    def test_all_configuration_selections_are_detached_before_first_key_callback(self):
        fixture = Fixture()
        original_digest = fixture.digest
        actual = source.configuration._key
        visited = []
        def construct(*args, **kwargs):
            visited.append(True)
            fixture.payload[source.recovery.FIELD][policy.FIELD]["maximumRetained"] = 999_999
            fixture.payload["roles"]["planner"]["databaseRole"] = "caller"
            fixture.payload["roles"]["planner"]["enabledOperations"] = []
            fixture.runtime["roles"]["planner"]["attestationReceiptDigest"] = digest(b"caller")
            return actual(*args, **kwargs)
        with mock.patch.object(source.configuration, "_key", side_effect=construct):
            result = source._producer_from_configuration_on_work(**fixture.arguments())
        self.assertEqual(visited, [True])
        configured = result._snapshot()
        self.assertEqual(configured[6], original_digest)
        self.assertEqual(configured[1][4], 100_000)
        self.assertEqual(configured[1][2][0], "catchplate_policy_authority_planner")

    def test_real_key_pair_original_work_and_cancellation_are_not_substituted(self):
        fixture = Fixture()
        with self.assertRaises(source.RecoveryInvalidationConfigurationError):
            source._producer_from_configuration_on_work(
                **fixture.arguments(planner_private_key=fixture.verifier_private))
        with mock.patch.object(source.configuration, "_key", side_effect=AssertionError("budget reached key")), \
                self.assertRaises(source.RecoveryInvalidationConfigurationError):
            source._producer_from_configuration_on_work(**fixture.arguments(work=work(max_input_bytes=8191)))
        actual = source.configuration._key
        for change in ("reset", "limits"):
            meter = work()
            def changed(*args, **kwargs):
                result = actual(*args, **kwargs)
                if change == "reset": meter.hash_work = meter.input_bytes = meter.json_nodes = 0
                else: meter.limits = QueryReadValidationLimits()
                return result
            with self.subTest(change=change), mock.patch.object(source.configuration, "_key", side_effect=changed), \
                    self.assertRaises(source.RecoveryInvalidationConfigurationError):
                source._producer_from_configuration_on_work(**fixture.arguments(work=meter))
        with mock.patch.object(source.configuration, "_key", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            source._producer_from_configuration_on_work(**fixture.arguments())

    def test_same_recovery_admission_is_reached_by_actual_generator_service_and_local_signer(self):
        generator = ast.parse((ROOT / "scripts/authority/generate_artifact_bundle.py").read_text())
        validator = next(node for node in generator.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_configuration_payload")
        calls = {ast.unparse(node.func) for node in ast.walk(validator) if isinstance(node, ast.Call)}
        self.assertIn("_recovery_selection", calls)
        self.assertIn("canonical_json_bytes", calls)
        self.assertIn("payload_bytes = canonical_json_bytes(payload)", ast.unparse(validator))
        for name in ("authority_service.py", "authority_local_configuration.py"):
            tree = ast.parse((ROOT / "catchplate" / name).read_text())
            calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
            self.assertIn("recovery_configuration.configuration", calls)
        tree = ast.parse((ROOT / "catchplate/authority_recovery_invalidation_configuration.py").read_text())
        calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        self.assertIn("planning.RecoveryInvalidationReadPlanner", calls)
        self.assertIn("owner.RecoveryInvalidationPlanOwner", calls)
        self.assertIn("recovery.retention.capture_policy", calls)
        self.assertFalse(any(value.endswith((".connect", ".getenv", ".open_window", ".acquire_originals", ".produce"))
            for value in calls))
        self.assertNotIn("_ValidationWork", calls)


if __name__ == "__main__":
    unittest.main()
