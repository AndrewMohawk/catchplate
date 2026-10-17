"""Approval/FD/refusal controls only: no admitted owner, DB, or new signature."""
import ast
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_local_retained_rbac as subject
from catchplate import authority_primary_contract as primary


def pin(label):
    return subject.wire.sha256(label.encode("ascii"))


def fixture():
    # Public codec inputs only, never a forged LocalCohortIssuer positive.
    public = bytes(range(32))
    selected = dict(schema=subject.local.RETAINED_SCHEMA, bootIdDigest=pin("boot"),
        configurationRootPublicKeyBase64Url=subject.local.spec.strict_base64url_encode(public),
        historicalArchiveSha256=pin("archive"), issuedAtBoottimeNs=100, deadlineBoottimeNs=300,
        issuedAtUnixNanos=100, expiresAtUnixNanos=300,
        runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=400))
    context = dict(selected=selected, rootPublic=public, configurationDigest=pin("config"),
        generationDigest=pin("generation"), generationInterval=(100, 400))
    kwargs = dict(context=context, cohort_raw=b"public-codec-cohort", cohort_approval_raw=b"public-codec-approval",
        archive_interval=(110, 290), nonce=b"n" * 32, boot=pin("boot"), now_boot=180, now_epoch=180)
    value = dict(schema=subject.SCHEMA, purpose=subject.PURPOSE, rootDelegation=subject.DELEGATION,
        nonce=subject.local.spec.strict_base64url_encode(kwargs["nonce"]), bootIdDigest=pin("boot"),
        configurationRootPublicKeyBase64Url=selected["configurationRootPublicKeyBase64Url"],
        cohortApprovalSha256=subject.wire.sha256(kwargs["cohort_approval_raw"]),
        cohortSha256=subject.wire.sha256(kwargs["cohort_raw"]), historicalArchiveSha256=pin("archive"),
        configurationDigest=pin("config"), generationDigest=pin("generation"),
        startupSha256=pin("startup"), enrollmentSha256=pin("enrollment"),
        issuedAtBoottimeNs=150, deadlineBoottimeNs=250, issuedAtUnixNanos=150, expiresAtUnixNanos=250)
    return value, kwargs


class RetainedRbacReaderControls(unittest.TestCase):
    def test_closed_local_approval_original_bindings_and_clock_bounds(self):
        value, kwargs = fixture()
        raw = subject.wire.canonical(value)
        self.assertEqual(subject._approval(raw, **kwargs), value)
        changes = [dict(value, extra=True), dict(value, schema="production"),
            dict(value, purpose="write"), dict(value, rootDelegation="independent"),
            dict(value, nonce=subject.local.spec.strict_base64url_encode(b"x" * 32))]
        for name in ("cohortApprovalSha256", "cohortSha256", "historicalArchiveSha256",
                "configurationDigest", "generationDigest", "bootIdDigest"):
            changes.append(dict(value, **{name: pin("other")}))
        for name, wrong in (("issuedAtBoottimeNs", True), ("issuedAtBoottimeNs", 99),
                ("issuedAtBoottimeNs", 181), ("deadlineBoottimeNs", 180),
                ("deadlineBoottimeNs", 301), ("issuedAtUnixNanos", 109),
                ("expiresAtUnixNanos", 291), ("expiresAtUnixNanos", 2**63)):
            changes.append(dict(value, **{name: wrong}))
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                subject._approval(subject.wire.canonical(changed), **kwargs)
        for change in ({"nonce": b"short"}, {"cohort_raw": b"different"},
                {"archive_interval": (160, 290)}, {"archive_interval": (110, 240)},
                {"now_boot": 250}, {"now_epoch": 250}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject._approval(raw, **dict(kwargs, **change))
        for schema in (subject.local.SCHEMA, subject.local.RUNTIME_SCHEMA):
            changed = deepcopy(kwargs); changed["context"]["selected"]["schema"] = schema
            with self.assertRaises(ValueError): subject._approval(raw, **changed)

        # Owner validation may exceed 30s, but cannot extend any original window.
        value, kwargs = fixture()
        duration = subject.MAX_READ_NS + 1
        for first, last in (("issuedAtBoottimeNs", "deadlineBoottimeNs"),
                ("issuedAtUnixNanos", "expiresAtUnixNanos")):
            value[first], value[last] = 150, 150 + duration
            kwargs["context"]["selected"][last] = 200 + duration
        kwargs["context"]["selected"]["runtimeValidity"]["expiresAtEpochNs"] = 300 + duration
        kwargs["context"]["generationInterval"] = (100, 300 + duration)
        kwargs["archive_interval"] = (110, 300 + duration)
        self.assertEqual(subject._approval(subject.wire.canonical(value), **kwargs), value)
        value["deadlineBoottimeNs"] = 150 + subject.local.LOCAL_SETUP_MAX_NS + 1
        kwargs["context"]["selected"]["deadlineBoottimeNs"] = value["deadlineBoottimeNs"]
        with self.assertRaises(ValueError): subject._approval(subject.wire.canonical(value), **kwargs)

    def test_exact_sealed_original_not_byte_equivalent_copy_and_owned_close(self):
        self.assertEqual(os.getresuid(), (0, 0, 0), "isolated root FD control required")
        raw = b"public-synthetic-reader-material"
        descriptors = []
        def sealed():
            fd = os.memfd_create("retained-rbac-control", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            os.write(fd, raw); os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, subject.io.SEALS)
            return fd
        # Only the duplicate/close primitive is exercised, not open/admission.
        holder = subject.LocalRetainedRbacReader()
        holder.owned, holder.originals, holder.closed = [], {}, False
        try:
            original, copied = sealed(), sealed()
            offset = os.lseek(original, 0, os.SEEK_CUR)
            duplicate = holder._duplicate(original)
            self.assertTrue(fcntl.fcntl(duplicate, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            row = dict(size=len(raw), sha256=subject.wire.sha256(raw))
            retained = subject._observed_original(duplicate, original, row, 4096, private=True)
            self.assertEqual(retained.raw, raw)
            self.assertEqual(os.lseek(original, 0, os.SEEK_CUR), offset)
            with self.assertRaises(ValueError): subject._observed_original(copied, original, row, 4096)
            with self.assertRaises(ValueError): subject._observed_original(duplicate, original,
                dict(row, sha256=pin("wrong")), 4096)
            holder.close()
            with self.assertRaises(OSError): os.fstat(duplicate)
            self.assertEqual(os.pread(original, len(raw), 0), raw)
            holder.close()
        finally:
            holder.close()
            for fd in descriptors: os.close(fd)

    def test_startup_uses_real_enrollment_signature_before_tls_or_connect(self):
        _, kwargs = fixture(); context = kwargs["context"]
        root = Ed25519PublicKey.from_public_bytes(b"r" * 32)
        root_raw = root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        roots = [dict(table=name, rootRevision=0, rootDigest=pin(name), leafCount=0)
            for name in subject.wire.TABLES]
        state = dict(generation=0, roots=roots, stateDigest=subject.wire.state_digest(
            subject.wire.state_material(0, roots[1], primary.source_query_manifest_digest())))
        identity = lambda role: dict(role="catchplate_rbac_witness_" + role,
            clientDn="/CN=synthetic-" + role, clientSerial="1", issuerDn="/CN=synthetic-ca",
            certificateSha256=pin(role))
        policy = dict(schema=subject.wire.LOCAL_ENROLLMENT_SCHEMA,
            sourceRevision=subject.local.cohort.authority.SOURCE_REVISION,
            enrollmentId="synthetic", deploymentId="synthetic", metadataClusterId="1", witnessClusterId="2",
            metadataDatabase="metadata", databaseId=subject.wire.sha256(
                b"catchplate/rbac-metadata-identity/v1\0" + subject.wire.canonical(dict(clusterId="1", database="metadata"))),
            metadataFaultDomain="synthetic-metadata", witnessFaultDomain="synthetic-witness",
            configurationDigests=[context["configurationDigest"]], reader=identity("reader"), writer=identity("writer"),
            initialState=state, issuedAtEpochNs=100, expiresAtEpochNs=300, maximumRecords=2,
            endpoint=dict(host="synthetic.invalid", address="127.0.0.1", port=5432, database="witness"),
            tlsRootSha256=pin("ca"), assurance=dict(subject.wire.LOCAL_ASSURANCE))
        enrollment = dict(schema=subject.wire.LOCAL_SIGNED_ENROLLMENT_SCHEMA, payload=policy,
            signatureBase64Url=subject.local.spec.strict_base64url_encode(bytes(64)))
        materials = {name: SimpleNamespace(raw=raw) for name, raw in {
            "root": root_raw, "tlsRoot": b"public-ca", "clientCertificate": b"public-certificate",
            "clientKey": b"not-a-private-key"}.items()}
        rows = [{"name": row[0], "fd": 100 + index} for index, row in enumerate(subject.INPUTS.values())]
        context["contexts"] = {subject.ROLE: dict(observed=dict(credentials=rows))}
        slots = {row["name"]: row["fd"] for row in rows}
        startup = dict(schema=subject.wire.LOCAL_STARTUP_SCHEMA,
            sourceRevision=subject.local.cohort.authority.SOURCE_REVISION,
            configurationDigest=context["configurationDigest"], enrollment=enrollment)
        for name, original in materials.items():
            startup[name] = dict(fd=slots[subject.INPUTS[name][0]], sha256=subject.wire.sha256(original.raw))
        materials["startup"] = SimpleNamespace(raw=subject.wire.canonical(startup))
        approval = dict(startupSha256=subject.wire.sha256(materials["startup"].raw),
            enrollmentSha256=subject.wire.sha256(subject.wire.canonical(enrollment)))
        with patch.object(subject.x509, "load_pem_x509_certificate") as tls, patch.object(subject, "Connection") as connect:
            with self.assertRaises(InvalidSignature):
                subject._startup(materials, context=context, approval=approval)
            tls.assert_not_called(); connect.assert_not_called()
            startup["clientKey"]["fd"] += 1
            materials["startup"].raw = subject.wire.canonical(startup)
            approval["startupSha256"] = subject.wire.sha256(materials["startup"].raw)
            with self.assertRaises(ValueError): subject._startup(materials, context=context, approval=approval)

    def test_no_dto_admission_no_writer_no_retry_after_refused_attempt(self):
        with patch.object(subject.os, "fstat") as inspect_fd, patch.object(subject, "Connection") as connect:
            with self.assertRaises(ValueError):
                subject.LocalRetainedRbacReader.open(cohort=object(), approval_fd=3,
                    approval_sha256=pin("approval"), nonce=b"n" * 32, original_fds={})
            inspect_fd.assert_not_called(); connect.assert_not_called()
        # A deliberately closed non-admitted shell cannot connect or authorize.
        owner = subject.LocalRetainedRbacReader(); owner.closed = True; owner.used = False
        self.assertIs(owner.writer, False)
        with self.assertRaises(AttributeError): owner.writer = True
        with self.assertRaises(ValueError): owner.require_writer()
        with patch.object(subject, "Connection") as connect:
            with self.assertRaises(ValueError): owner.read_head()
            self.assertTrue(owner.used)
            with self.assertRaises(ValueError): owner.read_head()
            connect.assert_not_called()

    def test_source_retains_real_read_only_connection_and_all_live_guards(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        read = ast.unparse(methods["read_head"])
        self.assertIn("connection.head(allow_pending=False)", read)
        self.assertIn("require(pending is None)", read)
        self.assertEqual(read.count("self.cohort.verify_live()"), 2)
        self.assertEqual(read.count("self.check()"), 2)
        self.assertIn("remaining = min(MAX_READ_NS,", read)
        self.assertIn("operation_deadline = min(self.deadline, time.monotonic_ns() + remaining)", read)
        self.assertLess(read.index("self.used = True"), read.index("Connection(self, operation_deadline)"))
        opening = ast.unparse(methods["open"])
        self.assertIn("type(cohort) is local.LocalCohortIssuer", opening)
        self.assertIn("cohort.verify_live()", opening)
        self.assertIn("observer._child_fd(row['fd'])", opening)
        check = ast.unparse(methods["check"])
        for guard in ("self.cohort.check()", "self.last_boot <= now_boot", "self.last_epoch <= now_epoch",
                "local.launch._boot_identity_digest() == self.boot", "original.check()", "fcntl.FD_CLOEXEC",
                "not self.cohort.publication_started", "not any((name.startswith('PG') for name in os.environ))"):
            self.assertIn(guard, check)
        calls = {node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {"issue", "publish", "provision", "reserve", "complete", "sign"})
        self.assertIs(subject.LocalRetainedRbacReader.connection_parameters, subject._TlsOwner.connection_parameters)


if __name__ == "__main__":
    unittest.main()
