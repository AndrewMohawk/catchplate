"""Synthetic signed-original and source-boundary controls; no DB/owner admission."""
import ast
import fcntl
from copy import deepcopy
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_primary_contract as primary
from serverware import authority_rbac_currentness as subject
from serverware import authority_fd_entrypoint as entry

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
    def test_actual_fixed_descriptor_delivery_preserves_originals(self):
        self.assertEqual((os.geteuid(), os.getegid()), (0, 0), "isolated root descriptor control required")
        self.assertEqual(list(entry.LOCAL_RBAC_DESCRIPTORS.values()), [240, 241, 242, 243])
        owner = entry._LocalRbacSlots.open("verifier", ())
        try:
            before = {fd: os.fstat(fd).st_ino for fd in entry.LOCAL_RBAC_DESCRIPTORS.values()}
            with tempfile.TemporaryDirectory() as directory:
                raw = {}
                for name, path in entry.ROLE_SOURCES["verifier"]:
                    if name in entry.LOCAL_RBAC_DESCRIPTORS:
                        raw[name] = ("synthetic-delivery-only:" + name).encode("ascii")
                        target = Path(directory) / Path(path).name
                        target.write_bytes(raw[name]); target.chmod(0o400)
                with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": directory}):
                    for name, fd in entry.LOCAL_RBAC_DESCRIPTORS.items():
                        self.assertEqual(owner.install(name), fd)
                        self.assertEqual(os.pread(fd, 4096, 0), raw[name])
                        self.assertNotEqual(os.fstat(fd).st_ino, before[fd])
                        self.assertTrue(os.get_inheritable(fd))
                    owner.require_complete()
                    with self.assertRaises(entry._LocalRbacSlotsError): owner.install(next(iter(raw)))
                    self.assertTrue(owner.failed)
                    with self.assertRaises(RuntimeError): owner.require_complete()
        finally:
            owner.close()

    def test_existing_or_inherited_descriptor_is_not_adopted(self):
        original = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        occupied = None
        try:
            occupied = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 240)
            self.assertEqual(occupied, 240, "do not overwrite an existing test-runner descriptor")
            identity = os.fstat(occupied)
            with self.assertRaises(entry._LocalRbacSlotsError) as caught:
                entry._LocalRbacSlots.open("verifier", ())
            self.assertFalse(caught.exception.owner.held)
            caught.exception.owner.close()
            self.assertEqual(os.fstat(occupied), identity)
        finally:
            if occupied is not None: os.close(occupied)
            os.close(original)
        with self.assertRaises(entry._LocalRbacSlotsError) as caught:
            entry._LocalRbacSlots.open("verifier", (241,))
        self.assertFalse(caught.exception.owner.held)
        caught.exception.owner.close()

    def test_fixed_delivery_selected_only_after_local_setup_before_credentials(self):
        tree = source("serverware/authority_fd_entrypoint.py")
        main = ast.unparse(function(tree, "_normal_main"))
        self.assertIn("local_admission is not None and role in {'verifier', 'planner', 'executor'}", main)
        self.assertLess(main.index("_local_admission_sources(role, local_admission)"), main.index("_LocalRbacSlots.open("))
        self.assertLess(main.index("_LocalRbacSlots.open("), main.index("_open_systemd_credential("))
        self.assertIn("rbac_slots.install(environment_name)", main)
        self.assertIn("rbac_slots.require_complete()", main)
        self.assertIn("rbac_slots.close()", main)

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

    def test_authority_expiry_uses_receipt_payload_and_original_bounds(self):
        # Execute only the genuine calculation nodes on synthetic contract
        # data. This neither fabricates an admitted owner nor contacts a DB.
        initialize = function(source("serverware/control_plane_rbac_currentness.py"), "_initialize")
        branch = next(node for node in ast.walk(initialize)
            if isinstance(node, ast.If) and ast.unparse(node.test) == "process is None")
        selected = [node for node in branch.orelse if isinstance(node, ast.Assign)
            and ast.unparse(node.targets[0]) in {"evidence", "maximum_expiry", "value.attestation_expires"}]
        selected += [node for node in ast.walk(initialize) if isinstance(node, ast.Assign)
            and ast.unparse(node.targets[0]) in {"value.expires_epoch", "value.deadline"}]
        self.assertEqual(len(selected), 6)
        code = compile(ast.Module(body=selected, type_ignores=[]), "<actual-rbac-expiry-calculation>", "exec")
        receipt_schema = ast.literal_eval(next(node.value
            for node in source("serverware/authority_service.py").body
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                and target.id == "TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA" for target in node.targets)))

        def calculate(evidence, archive_end, policy_end):
            value = SimpleNamespace(policy={"expiresAtEpochNs": policy_end}, recovery=None)
            configuration = SimpleNamespace(attestation_evidence=evidence,
                history_archive=SimpleNamespace(valid_until_epoch_ns=archive_end))
            namespace = dict(process=SimpleNamespace(configuration=configuration), value=value,
                opening_mono=2000, current_epoch=100,
                authority_service=SimpleNamespace(TRUSTED_HOST_LOCAL_ATTESTATION_SCHEMA=receipt_schema))
            exec(code, namespace)
            return value

        receipt = dict(schema=receipt_schema,
            payload=dict(expiresAtEpochNs=900), signature="synthetic-not-admitted")
        self.assertNotIn("expiresAtEpochNs", receipt)
        for archive_end, policy_end, expected_end in ((500, 700, 500), (1000, 700, 700), (1000, 1200, 900),
                (90, 1200, 90)):
            with self.subTest(archive_end=archive_end, policy_end=policy_end):
                value = calculate(receipt, archive_end, policy_end)
                self.assertEqual(value.attestation_expires, min(900, archive_end))
                self.assertEqual(value.expires_epoch, expected_end)
                self.assertEqual(value.deadline, 2000 + expected_end - 100)
        for changed in ({"schema": receipt["schema"], "expiresAtEpochNs": 900},
                {"schema": receipt["schema"], "payload": {}, "expiresAtEpochNs": 900}):
            with self.assertRaises(KeyError): calculate(changed, 1000, 1200)

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
