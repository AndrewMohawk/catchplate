"""Synthetic signed-original and source-boundary controls; no DB/owner admission."""
import ast
from copy import deepcopy
from pathlib import Path
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_primary_contract as primary
from serverware import authority_rbac_currentness as subject

ROOT = Path(__file__).resolve().parents[1]


def fixture():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pin = lambda text: subject.sha256(text.encode("ascii"))
    roots = [dict(table=name, rootRevision=0, rootDigest=pin(name), leafCount=0)
        for name in subject.TABLES]
    state = dict(generation=0, roots=roots, stateDigest=subject.state_digest(
        subject.state_material(0, roots[1], primary.source_query_manifest_digest())))
    identity = lambda role: dict(role="serverware_rbac_witness_" + role,
        clientDn="/CN=test-" + role, clientSerial="1", issuerDn="/CN=test-ca",
        certificateSha256=pin(role))
    payload = dict(schema=subject.LOCAL_ENROLLMENT_SCHEMA, sourceRevision="synthetic-source",
        enrollmentId="test-only", databaseId=subject.sha256(b"serverware/rbac-metadata-identity/v1\0" +
            subject.canonical(dict(clusterId="1", database="metadata"))), deploymentId="test-only",
        configurationDigests=[pin("configuration")], metadataClusterId="1", witnessClusterId="2",
        metadataDatabase="metadata", metadataFaultDomain="test-metadata-volume",
        witnessFaultDomain="test-witness-volume", reader=identity("reader"), writer=identity("writer"),
        initialState=state, issuedAtEpochNs=1, expiresAtEpochNs=1000000001, maximumRecords=2,
        endpoint=dict(host="test.invalid", address="127.0.0.1", port=5432, database="witness"),
        tlsRootSha256=pin("ca"), assurance=dict(subject.LOCAL_ASSURANCE))
    return payload, key


def source(path):
    return ast.parse((ROOT / path).read_text())


def function(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name)


class LocalRbacWitnessTests(unittest.TestCase):
    def test_signed_local_original_and_existing_head_chain(self):
        payload, key = fixture()
        raw = subject.sign_enrollment(payload, key)
        self.assertEqual(subject.enrollment(raw, key.public_key()), payload)
        self.assertEqual(subject.document(raw)["schema"], subject.LOCAL_SIGNED_ENROLLMENT_SCHEMA)
        head = subject.initial_head(subject.sha256(raw), payload)
        self.assertIsNone(head["previousHeadSha256"])
        self.assertEqual(head["state"], payload["initialState"])

    def test_local_claims_cannot_promote_or_coerce_assurance(self):
        payload, key = fixture()
        for name in ("hardwareBacked", "independentlyAdministered", "jointRollbackResistant"):
            changed = deepcopy(payload); changed["assurance"][name] = True
            with self.assertRaises(ValueError): subject.sign_enrollment(changed, key)
        changed = deepcopy(payload); changed["assurance"]["coLocated"] = 1
        with self.assertRaises(ValueError): subject.sign_enrollment(changed, key)
        changed = deepcopy(payload); changed["assurance"]["unsignedExtra"] = False
        with self.assertRaises(ValueError): subject.sign_enrollment(changed, key)

    def test_independent_v1_v2_remain_closed_and_distinct(self):
        payload, key = fixture()
        payload.pop("assurance"); payload["schema"] = subject.ENROLLMENT_SCHEMA
        first = subject.sign_enrollment(payload, key)
        self.assertEqual(subject.enrollment(first, key.public_key()), payload)
        payload["schema"] = subject.ENROLLMENT_V2_SCHEMA
        recovery = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
        import base64
        payload["recoveryPublicKeyBase64Url"] = base64.urlsafe_b64encode(recovery.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).rstrip(b"=").decode("ascii")
        second = subject.sign_enrollment(payload, key)
        self.assertEqual(subject.enrollment(second, key.public_key()), payload)
        payload["assurance"] = dict(subject.LOCAL_ASSURANCE)
        with self.assertRaises(ValueError): subject.sign_enrollment(payload, key)

    def test_local_signature_cannot_be_relabelled_independent(self):
        payload, key = fixture()
        envelope = subject.document(subject.sign_enrollment(payload, key))
        envelope["schema"] = subject.SIGNED_ENROLLMENT_SCHEMA
        envelope["payload"]["schema"] = subject.ENROLLMENT_SCHEMA
        envelope["payload"].pop("assurance")
        with self.assertRaises(InvalidSignature): subject.enrollment(subject.canonical(envelope), key.public_key())

    def test_distinct_cluster_and_storage_labels_still_required(self):
        payload, key = fixture()
        for name, value in (("witnessClusterId", payload["metadataClusterId"]),
                ("witnessFaultDomain", payload["metadataFaultDomain"])):
            changed = deepcopy(payload); changed[name] = value
            with self.assertRaises(ValueError): subject.sign_enrollment(changed, key)

    def test_local_admission_requires_real_owner_and_production_refusal(self):
        tree = source("serverware/control_plane_rbac_currentness.py")
        gate = ast.unparse(function(tree, "_require_local_owner"))
        for exact in ("profile.require_local_development()", "client._snapshot(owner.custody) is owner.binding",
                "startup.require_started() is owner.custody", "client._receipt_now(owner.binding)",
                "type(owner.process) is service.AuthorityProcess", "launch.require_active(owner.process.role_name)",
                "launch.launch_assurance()", "owner.configuration.payload.get('credentialReleaseTrust')"):
            self.assertIn(exact, gate)
        self.assertIn("_require_local_owner(value)", ast.unparse(function(tree, "_initialize")))
        self.assertIn("_require_local_owner(self)", ast.unparse(function(tree, "check")))
        production = ast.unparse(function(source("serverware/authority_rbac_currentness.py"), "require_local_development"))
        self.assertIn("not config.PRODUCTION_IMAGE", production)
        self.assertIn("config.RELEASE_CHANNEL", production)
        self.assertIn("SERVERWARE_PRODUCTION_IMAGE", production)

    def test_provision_and_delivery_keep_local_schema_explicit(self):
        provision = ast.unparse(function(source("serverware/authority_rbac_witness.py"), "provision"))
        self.assertIn("policy['schema'] == wire.LOCAL_ENROLLMENT_SCHEMA", provision)
        self.assertLess(provision.index("wire.require_local_development()"), provision.index("with connection.transaction()"))
        delivered = ast.unparse(function(source("serverware/authority_fd_entrypoint.py"), "_open_rbac_witness_material"))
        self.assertIn("profile.LOCAL_STARTUP_SCHEMA", delivered)
        admitted = ast.unparse(function(source("serverware/control_plane_rbac_currentness.py"), "_initialize"))
        self.assertIn("profile.LOCAL_ENROLLMENT_SCHEMA if value.local", admitted)
        self.assertIn("root.public_bytes", admitted)
        self.assertIn("independent_root.public_bytes", admitted)


if __name__ == "__main__":
    unittest.main()
