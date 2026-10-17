"""Inert actual mapper controls, not measured launch/TLS/current-root admission.

Synthetic configuration commitments and runtime originals exercise the real
capture, generation, role, key and native-constructor joins. No successful
replay DTO, database connection, MeasuredConfiguration or launch is simulated.
"""
from __future__ import annotations

import ast
import base64
import copy
from dataclasses import FrozenInstanceError
import hashlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_configuration as source
from catchplate import authority_challenge_planning as planning
from catchplate import authority_challenge_service as service
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_challenge_manifest import context


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def frame(domain, raw):
    return digest(domain.encode("ascii") + b"\x00" + len(raw).to_bytes(8, "big") + raw)


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


class Fixture:
    def __init__(self):
        config = source.configuration
        self.private = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)
        roles, runtime_roles = {}, {}
        for number, name in enumerate(config._ROLE_NAMES, 1):
            public = (self.private if name == "planner" else
                Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)).public_key()
            measurement, attestation = digest((name + " measurement").encode()), digest((name + " actual cohort").encode())
            spki = digest(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            roles[name] = dict(processMode="policy-authority-" + name, measurementDigest=measurement,
                signingPublicKeyBase64Url=base64.urlsafe_b64encode(public.public_bytes(
                    Encoding.Raw, PublicFormat.Raw)).decode("ascii").rstrip("="),
                signingSpkiDigest=spki, responseSigningSpkiDigest=spki)
            runtime_roles[name] = dict(measurementDigest=measurement,
                responseSigningSpkiDigest=spki, attestationReceiptDigest=attestation)
        roles["planner"].update(plannerSessionIdentityDigest=digest(b"planner session"),
            maximumInternalAgeNs=12_000_000_000, enabledOperations=sorted(source._OPERATIONS),
            databaseConnectTimeoutSeconds=2.75, databaseRole="catchplate_policy_authority_planner",
            tlsClientDn="CN=synthetic-planner", tlsClientSerial="17", tlsIssuerDn="CN=synthetic-ca")
        selected = {"schema": source.policy.SCHEMA,
            **{name: bounds[0] for name, bounds in source.policy._BOUNDS.items()}}
        self.payload = dict(schema=config.CONFIG_SCHEMA, sourceRevision=planning.authority.SOURCE_REVISION,
            roles=roles, generationSequence=3, generationBindingDigest=digest(b"generation binding"),
            generationPredecessorDigest=digest(b"predecessor"), generationMinimumRollbackSequence=2,
            roleBindingDigests={name: digest((name + " binding").encode()) for name in config._ROLE_NAMES},
            roleRuntimeClosureDigests={name: digest((name + " closure").encode()) for name in config._ROLE_NAMES},
            queryManifestDigest=config.capability.plan._QUERY_MANIFEST_DIGEST,
            **{source.policy.FIELD: selected})
        self.generation = dict(schema=config.GENERATION_SCHEMA, sequence=3, digest=digest(b"generation"),
            predecessorDigest=self.payload["generationPredecessorDigest"], minimumRollbackSequence=2,
            operationManifestDigest=planning.authority.OPERATION_MANIFEST_DIGEST,
            configurationBindingDigest=self.payload["generationBindingDigest"],
            roleBindingDigests=self.payload["roleBindingDigests"].copy(), configurationPayloadBindings=[])
        self.runtime = dict(schema=config.RUNTIME_ROLE_IDENTITIES_SCHEMA,
            configurationDigest=digest(b"pending"), generationSequence=3,
            generationDigest=self.generation["digest"], cohortDigest=digest(b"actual cohort"), roles=runtime_roles)
        self.seal()

    def seal(self):
        self.digest = frame(source.configuration.CONFIG_SCHEMA, canonical(self.payload))
        self.generation["configurationPayloadBindings"] = [dict(fileDigest=digest(b"synthetic original file"),
            payloadDigest=self.digest, payloadSchema=source.configuration.CONFIG_SCHEMA, role="authority-service")]
        self.runtime["configurationDigest"] = self.digest

    def arguments(self, *, meter=None):
        return dict(operation="webauthn.challenge.maintain", payload=self.payload,
            configuration_digest=self.digest, generation=self.generation,
            runtime_role_identities=self.runtime, work=work() if meter is None else meter)

    def verifier(self, *, meter=None):
        return source._verifier_from_configuration_on_work(**self.arguments(meter=meter))

    def context(self):
        selected = context()
        selected.update(configurationDigest=self.digest,
            retentionUs=self.payload[source.policy.FIELD]["terminalRetentionSeconds"] * 1_000_000,
            maximumRetained=self.payload[source.policy.FIELD]["maximumRetained"])
        return selected


class ChallengeConfigurationControls(unittest.TestCase):
    def test_actual_inert_factories_bind_complete_source_runtime_key_and_read_settings(self):
        fixture, meter = Fixture(), work()
        dsn = "host=synthetic.invalid dbname=synthetic"
        with mock.patch.object(planning.physical, "_connect", side_effect=AssertionError("connection opened")):
            producer = source._producer_from_configuration_on_work(**fixture.arguments(meter=meter),
                read_dsn=dsn, planner_private_key=fixture.private)
            verifier = fixture.verifier(meter=meter)
        self.assertIs(type(producer), planning.MaintenancePlanner)
        self.assertIs(type(verifier), source.MaintenanceVerifier)
        held = producer._configured
        planner, runtime = fixture.payload["roles"]["planner"], fixture.runtime["roles"]["planner"]
        identity = (planner["plannerSessionIdentityDigest"], planner["measurementDigest"], runtime["attestationReceiptDigest"])
        self.assertEqual(held[:3], ("webauthn.challenge.maintain", dsn, 2))
        self.assertEqual(held[3], (planner["databaseRole"], planner["tlsClientDn"], planner["tlsClientSerial"],
            planner["tlsIssuerDn"], *identity))
        self.assertIs(held[4], fixture.private)
        self.assertEqual((held[6], held[7], held[8]), (identity, planner["signingSpkiDigest"], fixture.digest))
        self.assertEqual(verifier._pins[2:5], (identity, planner["signingSpkiDigest"], fixture.digest))
        self.assertEqual(verifier._pins[6:], (12_000_000_000, planning.authority.VERIFIER_MAX_CLOCK_SKEW_NS))
        prior = dict(verifier._pins[5])
        fixture.payload[source.policy.FIELD]["maximumRetained"] += 1
        self.assertEqual(dict(verifier._pins[5]), prior)
        self.assertGreater(meter.input_bytes, 0)

    def test_configuration_commitment_generation_runtime_and_optional_policy_do_not_fallback(self):
        def changed_payload(fixture):
            fixture.payload["roles"]["planner"]["tlsClientDn"] = "CN=other"
        def changed_generation(fixture):
            fixture.generation["digest"] = digest(b"other generation")
        def changed_runtime(fixture):
            fixture.runtime["roles"]["planner"]["responseSigningSpkiDigest"] = digest(b"other key")
        for mutate in (changed_payload, changed_generation, changed_runtime):
            fixture = Fixture()
            mutate(fixture)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                fixture.verifier()
        for change in ("absent-policy", "disabled", "query", "malformed-policy"):
            fixture = Fixture()
            if change == "absent-policy":
                del fixture.payload[source.policy.FIELD]
            elif change == "disabled":
                fixture.payload["roles"]["planner"]["enabledOperations"] = []
            elif change == "query":
                fixture.payload["queryManifestDigest"] = digest(b"other query")
            else:
                fixture.payload[source.policy.FIELD]["maximumRetained"] = True
            fixture.seal()
            with self.subTest(change=change), self.assertRaises(ValueError):
                fixture.verifier()

    def test_verifier_has_only_exact_immutable_pins_and_owned_policy_context(self):
        fixture = Fixture()
        verifier = fixture.verifier()
        pins = verifier._pins
        constructor = (*pins[:5], dict(pins[5]), *pins[6:])
        for slot, value in ((0, []), (1, object()), (2, list(pins[2])), (3, "other"),
                (4, True), (6, True), (6, 0), (7, -1)):
            changed = list(constructor)
            changed[slot] = value
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                source.MaintenanceVerifier(pins=tuple(changed))
        with self.assertRaises(FrozenInstanceError):
            verifier._pins = ()
        selected = fixture.context()
        held, expected = verifier._expectations(context=selected, now_epoch_ns=5_000_000_000,
            deadline_epoch_ns=6_000_000_000, work=work())
        self.assertIs(held, pins)
        selected["indexHeads"].clear()
        self.assertEqual(len(expected["context"]["indexHeads"]), 9)
        self.assertEqual(expected["plannerIdentity"], dict(zip(source._IDENTITY_FIELDS, pins[2])))
        for name, value in (("retentionUs", 1), ("maximumRetained", 101),
                ("configurationDigest", digest(b"other")), ("operation", "webauthn.challenge.create")):
            selected = fixture.context()
            selected[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                verifier._expectations(context=selected, now_epoch_ns=5_000_000_000,
                    deadline_epoch_ns=6_000_000_000, work=work())

    def test_both_verification_paths_use_real_bytes_not_a_successful_replay_input(self):
        fixture = Fixture()
        verifier = fixture.verifier()
        callbacks = []
        arguments = dict(envelope_bytes=b"{}", request_bytes=b"{}", manifest_bytes=b"{}",
            context=fixture.context(), now_epoch_ns=5_000_000_000, deadline_epoch_ns=6_000_000_000,
            read_original=lambda *args: callbacks.append("read"), check=lambda stage: callbacks.append("check"),
            observe_effect=lambda *args: callbacks.append("effect"))
        with self.assertRaises(ValueError):
            verifier.verify(**arguments, work=work())
        with self.assertRaises(ValueError):
            verifier.verify_vector(**arguments, before_vector_bytes=b"{}", work=work())
        self.assertEqual(callbacks, [])
        class DifferentOwner(source.MaintenanceVerifier):
            def _expectations(self, **unused):
                raise AssertionError("polymorphic expectations used")
        other = DifferentOwner(pins=(*verifier._pins[:5], dict(verifier._pins[5]), *verifier._pins[6:]))
        with self.assertRaises(ValueError):
            other.verify(**arguments, work=work())
        with self.assertRaises(ValueError):
            other.verify_vector(**arguments, before_vector_bytes=b"{}", work=work())

    def test_unsupported_service_operation_refuses_before_protected_reads_and_live_callbacks(self):
        with mock.patch.object(service.measured, "_measured_context_on_work",
                side_effect=AssertionError("measured descriptor looked up")):
            for operation in ("webauthn.challenge.claim", True, "other"):
                for factory in (service._producer_on_work, service._verifier_on_work):
                    with self.subTest(operation=operation, factory=factory), self.assertRaises(ValueError):
                        factory(object(), operation=operation, work=work())
        tree = ast.parse(inspect.getsource(service))
        for name, role, signing, descriptor in (("_producer_on_work", "planner", True,
                "CATCHPLATE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN"),
                ("_verifier_on_work", "verifier", False, None)):
            node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == name)
            call = next(item for item in ast.walk(node) if isinstance(item, ast.Call)
                and ast.unparse(item.func) == "measured._measured_context_on_work")
            keywords = {item.arg: item.value for item in call.keywords}
            self.assertEqual((ast.literal_eval(keywords["role"]), ast.literal_eval(keywords["signing"]),
                ast.literal_eval(keywords["read_descriptor"])), (role, signing, descriptor))

    def test_same_remaining_work_and_actual_vector_caller_api_are_preserved(self):
        fixture = Fixture()
        for limits in (dict(max_input_bytes=128), dict(max_json_nodes=8), dict(max_hashes=1)):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                fixture.verifier(meter=work(**limits))
        tree = ast.parse(inspect.getsource(source.MaintenanceVerifier))
        for name, callee in (("verify", "plan.verify_maintenance_parent"),
                ("verify_vector", "current_root.replay_to_complete_vector")):
            node = next(item for item in tree.body[0].body if isinstance(item, ast.FunctionDef) and item.name == name)
            calls = [item for item in ast.walk(node) if isinstance(item, ast.Call)]
            self.assertIn("MaintenanceVerifier._expectations", [ast.unparse(item.func) for item in calls])
            call = next(item for item in calls if ast.unparse(item.func) == callee)
            keywords = {item.arg: ast.unparse(item.value) for item in call.keywords}
            self.assertEqual(keywords["expectations"], "expectations")
            self.assertEqual(keywords["planner_public_key"], "pins[1]")
            self.assertEqual(keywords["work"], "work")
            self.assertEqual(keywords["observe_effect"], "observe_effect")
            self.assertNotIn("replay", keywords)


if __name__ == "__main__":
    unittest.main()
