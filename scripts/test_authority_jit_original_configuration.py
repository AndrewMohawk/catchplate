"""Real inert configuration capture with synthetic role originals, not admission."""
from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from catchplate import authority_jit_original_configuration as source
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")


class Fixture:
    """Raw synthetic Service6/cohort documents; no measured-owner substitution.

    Build these originals directly instead of importing a maintenance planner
    fixture and its unrelated, deliberately unfinished transition registry.
    All commitments, native keys and actual production captures remain real.
    """

    def __init__(self):
        config = source.configuration
        self.private = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)
        self.verifier_private = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
        roles, runtime_roles = {}, {}
        for number, name in enumerate(config._ROLE_NAMES, 1):
            public = (self.private if name == "planner" else
                self.verifier_private if name == "verifier" else
                Ed25519PrivateKey.from_private_bytes(bytes([number]) * 32)).public_key()
            measurement = digest((name + " measurement").encode())
            attestation = digest((name + " actual cohort").encode())
            spki = digest(public.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
            roles[name] = dict(processMode="policy-authority-" + name, measurementDigest=measurement,
                signingPublicKeyBase64Url=base64.urlsafe_b64encode(public.public_bytes(
                    Encoding.Raw, PublicFormat.Raw)).decode("ascii").rstrip("="),
                signingSpkiDigest=spki, responseSigningSpkiDigest=spki)
            runtime_roles[name] = dict(measurementDigest=measurement,
                responseSigningSpkiDigest=spki, attestationReceiptDigest=attestation)
        roles["planner"].update(plannerSessionIdentityDigest=digest(b"planner session"),
            enabledOperations=["jit.assertion.issue"], databaseConnectTimeoutSeconds=2.75,
            databaseRole="catchplate_policy_authority_planner", tlsClientDn="CN=synthetic-planner",
            tlsClientSerial="17", tlsIssuerDn="CN=synthetic-ca", peerUid=65520, peerGid=65520)
        for name, uid, maximum in (("planner", 65518, 12_000_000_000),
                ("verifier", 65520, 9_000_000_000), ("planner-writer", 65519, 10_000_000_000)):
            roles[name].update(serviceUid=uid, serviceGid=uid, maximumInternalAgeNs=maximum,
                requestTimeoutSeconds=0.75, socketPath="/run/synthetic/" + name + ".sock")
        roles["planner-writer"].update(peerUid=65518, peerGid=65518,
            plannerSessionIdentityDigest=roles["planner"]["plannerSessionIdentityDigest"],
            plannerSigningSpkiDigest=roles["planner"]["signingSpkiDigest"],
            plannerSigningPublicKeyBase64Url=roles["planner"]["signingPublicKeyBase64Url"],
            databaseConnectTimeoutSeconds=2.75, databaseRole="catchplate_policy_authority_planner_writer",
            tlsClientDn="CN=synthetic-writer", tlsClientSerial="19", tlsIssuerDn="CN=synthetic-ca")
        self.payload = dict(schema=config.CONFIG_SCHEMA,
            sourceRevision=source.evidence.authority.SOURCE_REVISION, roles=roles,
            generationSequence=3, generationBindingDigest=digest(b"generation binding"),
            generationPredecessorDigest=digest(b"predecessor"), generationMinimumRollbackSequence=2,
            roleBindingDigests={name: digest((name + " binding").encode()) for name in config._ROLE_NAMES},
            roleRuntimeClosureDigests={name: digest((name + " closure").encode()) for name in config._ROLE_NAMES},
            queryManifestDigest=config.capability.plan._QUERY_MANIFEST_DIGEST)
        self.generation = dict(schema=config.GENERATION_SCHEMA, sequence=3, digest=digest(b"generation"),
            predecessorDigest=self.payload["generationPredecessorDigest"], minimumRollbackSequence=2,
            operationManifestDigest=source.evidence.authority.OPERATION_MANIFEST_DIGEST,
            configurationBindingDigest=self.payload["generationBindingDigest"],
            roleBindingDigests=self.payload["roleBindingDigests"].copy(), configurationPayloadBindings=[])
        self.runtime = dict(schema=config.RUNTIME_ROLE_IDENTITIES_SCHEMA,
            configurationDigest=digest(b"pending"), generationSequence=3,
            generationDigest=self.generation["digest"], cohortDigest=digest(b"actual cohort"), roles=runtime_roles)
        self.seal()

    def seal(self):
        raw = canonical(self.payload)
        self.digest = digest(source.configuration.CONFIG_SCHEMA.encode("ascii") + b"\x00"
            + len(raw).to_bytes(8, "big") + raw)
        self.generation["configurationPayloadBindings"] = [dict(fileDigest=digest(b"synthetic original file"),
            payloadDigest=self.digest, payloadSchema=source.configuration.CONFIG_SCHEMA, role="authority-service")]
        self.runtime["configurationDigest"] = self.digest

    def capture(self, role="planner", **changes):
        arguments = dict(local_role=role, payload=self.payload, configuration_digest=self.digest,
            generation=self.generation, runtime_role_identities=self.runtime, work=work())
        if role == "planner-writer":
            arguments["writer_dsn"] = "host=synthetic.invalid dbname=synthetic"
        else:
            arguments["private_key"] = self.private if role == "planner" else self.verifier_private
        arguments.update(changes)
        return source._from_configuration_on_work(**arguments)


class JitOriginalConfigurationControls(unittest.TestCase):
    def test_real_three_role_capture_is_inert_with_writer_only_descriptor(self):
        fixture = Fixture()
        with mock.patch.object(source.page_persistence, "_connect", side_effect=AssertionError("native open")):
            observed = {role: fixture.capture(role) for role in source._ROLES}
        for role, configured in observed.items():
            self.assertIs(source._snapshot(configured), configured._original)
            self.assertEqual(configured.local_role, role)
            self.assertEqual(configured.configuration_digest, fixture.digest)
            self.assertEqual(configured.planner_endpoint, ("/run/synthetic/planner.sock", 65518, 65518))
            self.assertEqual(configured.writer_endpoint, ("/run/synthetic/planner-writer.sock", 65519, 65519))
            with self.assertRaises(FrozenInstanceError):
                configured.local_role = "caller"
        self.assertIsNone(observed["planner"].persistence)
        self.assertIsNone(observed["verifier"].persistence)
        self.assertIsNone(observed["planner-writer"].private_key)
        self.assertIs(type(observed["planner-writer"].persistence), source.page_persistence.JitOriginalPersistence)
        for role, changes in (("planner", {"writer_dsn": "host=synthetic.invalid"}),
                ("verifier", {"writer_dsn": "host=synthetic.invalid"}),
                ("planner-writer", {"private_key": fixture.private})):
            with self.assertRaises(ValueError):
                fixture.capture(role, **changes)

    def test_enabled_literal_source_query_and_fixed_topology_precede_key_construction(self):
        for kind in ("disabled", "query", "peer", "age", "path"):
            fixture = Fixture()
            roles = fixture.payload["roles"]
            if kind == "disabled": roles["planner"]["enabledOperations"].remove("jit.assertion.issue")
            if kind == "query": fixture.payload["queryManifestDigest"] = digest(b"wrong query")
            if kind == "peer": roles["planner-writer"]["peerUid"] = 65520
            if kind == "age": roles["verifier"]["maximumInternalAgeNs"] = True
            if kind == "path": roles["planner"]["socketPath"] = "/" + "\u00e9" * 60
            fixture.seal()
            with self.subTest(kind=kind), mock.patch.object(source.configuration, "_key",
                    side_effect=AssertionError("invalid config reached key constructor")):
                with self.assertRaises(ValueError):
                    fixture.capture()

    def test_actual_commitment_generation_runtime_and_private_pair_are_required(self):
        for kind in ("commitment", "generation", "runtime", "private"):
            fixture = Fixture()
            options = {}
            if kind == "commitment": fixture.payload["roles"]["planner"]["serviceUid"] += 1
            if kind == "generation": fixture.generation["digest"] = digest(b"other generation")
            if kind == "runtime": fixture.runtime["roles"]["planner"]["measurementDigest"] = digest(b"other role")
            if kind == "private": options["private_key"] = fixture.verifier_private
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                fixture.capture(**options)
        configured = Fixture().capture()
        object.__setattr__(configured, "writer_endpoint", ("/caller.sock", 1, 1))
        with self.assertRaises(ValueError):
            source._snapshot(configured)

    def test_all_scalar_selection_is_detached_before_first_key_callback(self):
        fixture = Fixture()
        expected = fixture.digest
        native = source.configuration._key
        once = False
        def construct(*args, **kwargs):
            nonlocal once
            if not once:
                once = True
                fixture.payload["roles"]["planner"]["socketPath"] = "/caller.sock"
                fixture.payload["roles"]["planner"]["enabledOperations"] = []
                fixture.runtime["roles"]["planner"]["measurementDigest"] = digest(b"caller measurement")
            return native(*args, **kwargs)
        with mock.patch.object(source.configuration, "_key", side_effect=construct):
            captured = fixture.capture()
        self.assertTrue(once)
        self.assertEqual(captured.configuration_digest, expected)
        self.assertEqual(captured.planner_endpoint, ("/run/synthetic/planner.sock", 65518, 65518))


if __name__ == "__main__":
    unittest.main()
