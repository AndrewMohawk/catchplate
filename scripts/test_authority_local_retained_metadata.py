"""Local codec/FD/preconnect controls, not an admitted cohort or live DB proof.

No authority signature or enrollment is produced. Positive pure-codec and
descriptor fixtures must not be treated as successful reader.open() admission.
Named-file controls need isolated root plus CHOWN for synthetic 65520 files.
"""
import ast
from copy import deepcopy
import fcntl
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_local_retained_metadata as subject


def pin(label):
    return subject.wire.sha256(label.encode("ascii"))


def fixture():
    public = bytes(range(32))
    selected = dict(schema=subject.local.RETAINED_SCHEMA, bootIdDigest=pin("boot"),
        configurationRootPublicKeyBase64Url=subject.local.spec.strict_base64url_encode(public),
        historicalArchiveSha256=pin("archive"), issuedAtBoottimeNs=100, deadlineBoottimeNs=400,
        issuedAtUnixNanos=100, expiresAtUnixNanos=400,
        runtimeValidity=dict(issuedAtEpochNs=100, expiresAtEpochNs=400))
    configuration = dict(selected, issuedAtBoottimeNs=120, deadlineBoottimeNs=320,
                         issuedAtUnixNanos=120, expiresAtUnixNanos=320)
    anchors = {name: pin(name) for name in ("cohortApprovalSha256", "cohortSha256",
        "historicalArchiveSha256", "configurationApprovalSha256", "serviceConfigurationSha256",
        "verifierIssuanceSha256", "configurationDigest", "generationDigest")}
    anchors["historicalArchiveSha256"] = selected["historicalArchiveSha256"]
    originals = {name: dict(identity=[1, 2 + index, 0o100400, 0, 0, 1, 64, 100, 100], sha256=pin(name))
                 for index, name in enumerate(subject.INPUTS)}
    context = dict(selected=selected, rootPublic=public, generationInterval=(110, 390),
        configurationDigest=anchors["configurationDigest"], generationDigest=anchors["generationDigest"])
    kwargs = dict(context=context, configuration_approval=configuration, anchors=anchors, originals=originals,
        archive_interval=(130, 310), certificate_interval=(140, 300), nonce=b"n" * 32,
        boot=pin("boot"), now_boot=180, now_epoch=180)
    value = dict(schema=subject.SCHEMA, purpose=subject.PURPOSE, rootDelegation=subject.DELEGATION,
        nonce=subject.local.spec.strict_base64url_encode(kwargs["nonce"]), bootIdDigest=pin("boot"),
        configurationRootPublicKeyBase64Url=selected["configurationRootPublicKeyBase64Url"],
        **anchors, originals=deepcopy(originals), issuedAtBoottimeNs=150, deadlineBoottimeNs=250,
        issuedAtUnixNanos=150, expiresAtUnixNanos=250)
    return value, kwargs


def inert_holder():
    # Exercise descriptor cleanup only, not a substitute for open()/admission.
    holder = object.__new__(subject.LocalRetainedMetadataReader)
    holder.owned, holder.originals, holder.closed = {}, {}, False
    holder.used, holder.pid = False, os.getpid()
    return holder


class RetainedMetadataReaderControls(unittest.TestCase):
    def test_closed_approval_binds_originals_and_all_existing_intervals(self):
        value, kwargs = fixture()
        raw = subject.wire.canonical(value)
        self.assertEqual(subject._approval(raw, **kwargs), value)
        changed = [dict(value, expectedDatabaseRoot=pin("forbidden")), dict(value, purpose="restart"),
            dict(value, rootDelegation="independent-production"), dict(value, nonce="wrong")]
        for name in kwargs["anchors"]:
            changed.append(dict(value, **{name: pin("other")}))
        for name, wrong in (("issuedAtBoottimeNs", 119), ("deadlineBoottimeNs", 321),
                ("issuedAtUnixNanos", 139), ("expiresAtUnixNanos", 301),
                ("deadlineBoottimeNs", 180), ("expiresAtUnixNanos", 180), ("issuedAtUnixNanos", True)):
            changed.append(dict(value, **{name: wrong}))
        for name in subject.INPUTS:
            candidate = deepcopy(value)
            candidate["originals"][name]["identity"][1] += 1
            changed.append(candidate)
            candidate = deepcopy(value)
            candidate["originals"][name]["sha256"] = pin("changed")
            changed.append(candidate)
        for candidate in changed:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                subject._approval(subject.wire.canonical(candidate), **kwargs)
        for replacement in ({"nonce": b"short"}, {"now_boot": 250}, {"now_epoch": 250},
                {"archive_interval": (160, 310)}, {"certificate_interval": (140, 240)}):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                subject._approval(raw, **dict(kwargs, **replacement))
        other = deepcopy(kwargs)
        other["context"]["selected"]["schema"] = subject.local.RUNTIME_SCHEMA
        with self.assertRaises(ValueError): subject._approval(raw, **other)
        for remaining in (-1, 0, 1_999_999_999):
            with self.assertRaises(ValueError): subject._connect_timeout(5, remaining)
        self.assertEqual(subject._connect_timeout(5, 2_999_999_999), 2)
        self.assertEqual(subject._connect_timeout(3, 60_000_000_000), 3)
        self.assertEqual(subject._connect_timeout(300, 60_000_000_000), 5)
        with self.assertRaises(ValueError): subject._connect_timeout(True, 3_000_000_000)

    def test_same_observed_sealed_inode_and_owned_projection_cleanup(self):
        self.assertEqual(os.getresuid(), (0, 0, 0))
        holder, fds = inert_holder(), []
        raw = b"host=synthetic.invalid dbname=synthetic"
        try:
            for _index in range(2):
                fd = os.memfd_create("synthetic-retained-dsn", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                fds.append(fd)
                os.write(fd, raw); os.fchmod(fd, 0o400)
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, subject.io.SEALS)
            duplicate = holder._duplicate(fds[0])
            offset = os.lseek(fds[0], 0, os.SEEK_CUR)
            row = dict(size=len(raw), sha256=subject.wire.sha256(raw))
            original = subject.retained._observed_original(duplicate, fds[0], row, 65536, private=True)
            self.assertEqual(original.raw, raw)
            self.assertEqual(os.lseek(fds[0], 0, os.SEEK_CUR), offset)
            with self.assertRaises(ValueError):
                subject.retained._observed_original(fds[1], fds[0], row, 65536, private=True)
            projection = holder._projection(b"synthetic-private-tls-bytes")
            self.assertEqual(fcntl.fcntl(projection.fd, fcntl.F_GET_SEALS), subject.io.SEALS)
            self.assertTrue(fcntl.fcntl(projection.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            before = set(holder.owned)
            with patch.object(subject.os, "write", side_effect=OSError("synthetic write refusal")):
                with self.assertRaises(OSError): holder._projection(b"synthetic-incomplete-projection")
            incomplete = set(holder.owned) - before
            self.assertEqual(len(incomplete), 1)  # Registered before its failing write.
            holder.deadline = 0  # Closing owned FDs must not require unexpired approval.
            holder.close()
            for fd in (duplicate, projection.fd, *incomplete):
                with self.assertRaises(OSError): os.fstat(fd)
            self.assertEqual(os.pread(fds[0], len(raw), 0), raw)
            holder.close()
        finally:
            holder.close()
            for fd in fds: os.close(fd)

    def test_real_named_verifier_file_identity_mutation_and_borrowed_fd_survival(self):
        holder, borrowed = inert_holder(), []
        with tempfile.TemporaryDirectory(prefix="retained-metadata-control-") as temporary:
            path = Path(temporary) / "ca.pem"
            writer = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC, 0o600)
            borrowed.append(writer)
            os.write(writer, b"synthetic-public-ca")
            os.fchmod(writer, 0o400)
            original = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            borrowed.append(original)
            os.fchown(writer, *subject.local.launch.ROLE_IDENTITIES["verifier"])
            try:
                with patch.object(subject, "TLS_DIRECTORY", temporary):
                    retained = subject._NamedTlsOriginal(holder._duplicate(original), "tlsRoot")
                    self.assertEqual(retained.identity[3:6], (65520, 65520, 1))
                    retained.check()
                    with self.assertRaises(ValueError): subject._NamedTlsOriginal(writer, "tlsRoot")
                    os.pwrite(writer, b"changed", 0)
                    with self.assertRaises(ValueError): retained.check()
                holder.close()
                self.assertEqual(os.pread(original, 7, 0), b"changed")
            finally:
                holder.close()
                for fd in borrowed: os.close(fd)

    def test_real_issuance_refusal_and_synthetic_preconnect_join_negatives(self):
        with patch.object(subject.serialization, "load_pem_private_key") as key_loader:
            with self.assertRaises(ValueError): subject._tls_and_dsn({}, b"{}", {})
            key_loader.assert_not_called()
        # Pure joining unit only: no positive custody/cohort or certificate-
        # signature admission is claimed from these parsed synthetic values.
        key = ec.derive_private_key(1, ec.SECP256R1())
        other = ec.derive_private_key(2, ec.SECP256R1())
        identity = dict(databaseRole="synthetic_verifier", tlsClientDn="/CN=synthetic_verifier",
            tlsClientSerial="1", tlsIssuerDn="/CN=synthetic", notBeforeEpochNs=100, expiresAtEpochNs=300)
        issued = dict(intendedOwner=dict(uid=65520, gid=65520), runtimeDirectory=subject.TLS_DIRECTORY,
            host="synthetic.invalid", port=5432, database="synthetic", caCertificateOriginal="synthetic-ca",
            certificateOriginal="synthetic-certificate")
        expected = dict(host=issued["host"], port="5432", dbname="synthetic", user="synthetic_verifier",
            sslmode="verify-full", sslrootcert=subject.TLS_DIRECTORY + "/ca.pem",
            sslcert=subject.TLS_DIRECTORY + "/certificate.pem", sslkey=subject.TLS_DIRECTORY + "/private-key.pem",
            connect_timeout="5")
        materials = {name: SimpleNamespace(raw=raw) for name, raw in {
            "tlsRoot": b"synthetic-ca", "clientCertificate": b"synthetic-certificate",
            "clientKey": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()),
            "dsn": subject.make_conninfo(**expected).encode("ascii")}.items()}
        service = dict(roles=dict(verifier=identity))
        with patch.object(subject.credentials, "issuance", return_value=identity), patch.object(
                subject.x509, "load_pem_x509_certificate", return_value=SimpleNamespace(public_key=key.public_key)):
            self.assertEqual(subject._tls_and_dsn(materials, subject.wire.canonical(issued), service), (expected, (100, 300)))
            for changed in (dict(expected, host="other.invalid"), dict(expected, user="writer"),
                            dict(expected, service="ambient"), dict(expected, options="-c statement_timeout=0")):
                materials["dsn"].raw = subject.make_conninfo(**changed).encode("ascii")
                with self.assertRaises(ValueError): subject._tls_and_dsn(materials, subject.wire.canonical(issued), service)
            materials["dsn"].raw = subject.make_conninfo(**expected).encode("ascii")
            materials["clientKey"].raw = other.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            with self.assertRaises(ValueError): subject._tls_and_dsn(materials, subject.wire.canonical(issued), service)
            materials["tlsRoot"].raw = b"other-ca"
            with self.assertRaises(ValueError): subject._tls_and_dsn(materials, subject.wire.canonical(issued), service)

    def test_no_dto_admission_no_retry_and_exact_source_reader_guards(self):
        with self.assertRaises(TypeError): subject.LocalRetainedMetadataReader()
        with patch.object(subject.os, "fstat") as inspect_fd, patch.object(subject.reader, "CurrentRootReader") as connect:
            with self.assertRaises(ValueError):
                subject.LocalRetainedMetadataReader.open(cohort=object(), configuration_custody=object(),
                    approval_fd=3, approval_sha256=pin("approval"), nonce=b"n" * 32, original_fds={})
            inspect_fd.assert_not_called(); connect.assert_not_called()
        holder = inert_holder(); holder.close()
        with patch.object(subject.reader, "CurrentRootReader") as connect:
            with self.assertRaises(ValueError): holder.read_once(work=object())
            self.assertTrue(holder.used)
            with self.assertRaises(ValueError): holder.read_once(work=object())
            connect.assert_not_called()
        tree = ast.parse(Path(subject.__file__).read_text())
        methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        opening, check, read = (ast.unparse(methods[name]) for name in ("open", "check", "read_once"))
        # Select the public owner's check, not the named-original helper.
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LocalRetainedMetadataReader")
        check = ast.unparse(next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "check"))
        for text in ("type(cohort) is local.LocalCohortIssuer", "type(configuration_custody) is IssuedConfigurationCustody",
                     "self.service_raw == self.context['serviceOriginal']", "._child_fd(row['fd'])"):
            self.assertIn(text, opening)
        for text in ("self.cohort.verify_live()", "self.custody.check()", "not self.cohort.publication_started",
                     "original.check()", "self._approval_now() == self.approval", "name.startswith('PG')"):
            self.assertIn(text, check)
        self.assertEqual(read.count("self.check()"), 2)
        self.assertIn("reader.CurrentRootReader(", read)
        self.assertIn("configured.read(work=work)", read)
        self.assertIn("self._release(fd)", read)
        self.assertLess(read.index("self.used = True"), read.index("self.check()"))
        calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {"issue", "publish", "provision", "sign", "execute", "commit"})
        make = (Path(subject.__file__).resolve().parents[1] / "Makefile").read_text()
        self.assertEqual(make.count("scripts/test_authority_local_retained_metadata.py"), 1)
        self.assertEqual(make.count("serverware/authority_local_retained_metadata.py"), 2)


if __name__ == "__main__":
    unittest.main()
