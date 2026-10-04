"""Synthetic signed-original and source-boundary controls; no DB/owner admission."""
import ast
import contextlib
import fcntl
from copy import deepcopy
import os
from pathlib import Path
import stat
import tempfile
import time
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_primary_contract as primary
from serverware import authority_rbac_currentness as subject
from serverware import authority_fd_entrypoint as entry
from serverware import authority_launcher as launcher
from serverware import authority_rbac_witness as witness
from serverware import control_plane_rbac_currentness as currentness
from serverware.oauth_application_owner import _Original, OAuthApplicationError

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


class _TlsProjectionControl:
    """Only the projection/transport seam; never an admitted RBAC owner."""
    connection_parameters = currentness._Owner.connection_parameters

    def __init__(self, originals):
        self.originals = originals
        self.tls_root, self.certificate, self.key = originals
        self.writer = False
        self.deadline = time.monotonic_ns() + 10_000_000_000
        self.policy = dict(endpoint=dict(host="synthetic.invalid", address="127.0.0.1",
            port=5432, database="synthetic"), reader=dict(role="synthetic_reader"))

    def check(self):
        for original in self.originals: original.check()


@contextlib.contextmanager
def tls_projection_control():
    # Genuine protected-original checks, synthetic bytes, no TLS/DB admission.
    with contextlib.ExitStack() as cleanup:
        originals = []
        for index, raw in enumerate((b"synthetic-ca", b"synthetic-certificate", b"synthetic-private-key")):
            fd = launcher._seal_bytes("synthetic-rbac-original", raw)
            cleanup.callback(os.close, fd)
            originals.append(_Original(fd, 16384 if index == 2 else 65536, private=index == 2))
        yield _TlsProjectionControl(tuple(originals))


@contextlib.contextmanager
def timed_tls_projection_control(*, remaining_ns, projection_ns=0):
    """Real original/projection checks; a clocked transport seam, not DB admission."""
    clock = [10_000_000_000]
    with patch.object(witness.time, "monotonic_ns", side_effect=lambda: clock[0]), \
            patch.dict(os.environ, {}, clear=True), tls_projection_control() as owner:
        owner.deadline = clock[0] + 60_000_000_000
        connection = witness.Connection(owner, clock[0] + remaining_ns)
        projected = []
        original_parameters = owner.connection_parameters

        @contextlib.contextmanager
        def delayed_parameters():
            with original_parameters() as parameters:
                projected.extend(int(parameters[name].rsplit("/", 1)[1])
                    for name in ("sslrootcert", "sslcert", "sslkey"))
                clock[0] += projection_ns
                yield parameters

        with patch.object(owner, "connection_parameters", side_effect=delayed_parameters):
            yield owner, connection, clock, projected


class LocalRbacWitnessTests(unittest.TestCase):
    def assert_descriptors_closed(self, descriptors):
        self.assertTrue(descriptors)
        for fd in descriptors:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_connection_parameters_omit_service_and_keep_explicit_identity(self):
        from psycopg.conninfo import conninfo_to_dict, make_conninfo
        with patch.dict(os.environ, {}, clear=True), tls_projection_control() as owner:
            with owner.connection_parameters() as parameters:
                self.assertNotIn("service", parameters)
                parsed = conninfo_to_dict(make_conninfo(**parameters))
                self.assertNotIn("service", parsed)
                for name, expected in {
                    "host": "synthetic.invalid", "hostaddr": "127.0.0.1",
                    "port": "5432", "dbname": "synthetic", "user": "synthetic_reader",
                    "sslmode": "verify-full", "ssl_min_protocol_version": "TLSv1.3",
                    "ssl_max_protocol_version": "TLSv1.3", "passfile": "/dev/null",
                    "password": "", "gssencmode": "disable",
                    "application_name": "serverware-rbac-witness-v1",
                }.items():
                    self.assertEqual(parsed[name], expected)
                descriptors = [int(parameters[name].rsplit("/", 1)[1])
                    for name in ("sslrootcert", "sslcert", "sslkey")]
            self.assert_descriptors_closed(descriptors)
            owner.check()

    def test_ambient_postgres_options_refused_before_tls_projection(self):
        for name in ("PGSERVICE", "PGSERVICEFILE", "PGSYSCONFDIR", "PGPASSWORD",
                "PGPASSFILE", "PGSSLMODE", "PGOPTIONS", "PGHOST", "PGUSER"):
            for value in ("", "synthetic-override"):
                with self.subTest(name=name, empty=not value), tls_projection_control() as owner:
                    with patch.dict(os.environ, {name: value}, clear=True), \
                            patch.object(os, "memfd_create") as create:
                        with self.assertRaisesRegex(ValueError, "ambient PostgreSQL"):
                            with owner.connection_parameters():
                                self.fail("ambient settings reached connection parameters")
                        create.assert_not_called()
                    owner.check()

    def test_role_can_reopen_only_scoped_sealed_tls_projections(self):
        self.assertEqual((os.geteuid(), os.getegid()), (0, 0), "isolated root/drop control required")
        with tls_projection_control() as owner:
            pid = os.fork()
            if pid == 0:
                result = 1
                try:
                    os.setgroups([]); os.setresgid(65522, 65522, 65522); os.setresuid(65522, 65522, 65522)
                    owner.check()
                    offsets = [os.lseek(original.fd, 0, os.SEEK_CUR) for original in owner.originals]
                    with self.assertRaises(PermissionError): os.open("/proc/self/fd/" + str(owner.key.fd), os.O_RDONLY)
                    self.assertEqual(os.pread(owner.key.fd, 16385, 0), owner.key.raw)
                    projected = []
                    with owner.connection_parameters() as parameters:
                        for name, original in zip(("sslrootcert", "sslcert", "sslkey"), owner.originals, strict=True):
                            fd = int(parameters[name].rsplit("/", 1)[1]); projected.append(fd)
                            self.assertNotIn(fd, [value.fd for value in owner.originals])
                            info = os.fstat(fd)
                            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                                (65522, 65522, 0o400, 0))
                            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS),
                                fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
                            self.assertTrue(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
                            with open(parameters[name], "rb") as reopened:
                                self.assertEqual(reopened.read(original.maximum + 1), original.raw)
                    self.assert_descriptors_closed(projected)
                    owner.check()
                    self.assertEqual([os.lseek(original.fd, 0, os.SEEK_CUR) for original in owner.originals], offsets)
                    result = 0
                except BaseException:
                    traceback.print_exc()
                finally:
                    os._exit(result)
            observed, status = os.waitpid(pid, 0)
            self.assertEqual(observed, pid)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            owner.check()

    def test_partial_tls_projection_failure_closes_acquired_descriptors(self):
        with tls_projection_control() as owner:
            created, writes = [], 0
            create, write = os.memfd_create, os.write
            def recording_create(*args, **kwargs):
                fd = create(*args, **kwargs); created.append(fd); return fd
            def fail_second_write(fd, raw):
                nonlocal writes
                writes += 1
                if writes == 2: raise OSError("synthetic second projection failure")
                return write(fd, raw)
            with patch.object(os, "memfd_create", side_effect=recording_create), patch.object(os, "write", side_effect=fail_second_write):
                with self.assertRaisesRegex(OSError, "synthetic second projection failure"):
                    with owner.connection_parameters(): self.fail("incomplete projection reached connect")
            self.assertEqual(len(created), 2)
            self.assert_descriptors_closed(created)
            owner.check()

    def test_connect_and_post_connect_original_failure_close_all_resources(self):
        import psycopg
        for after_connect in (False, True):
            with self.subTest(after_connect=after_connect), \
                    patch.object(witness.time, "monotonic_ns", return_value=10_000_000_000), \
                    tls_projection_control() as owner:
                projected = []
                closed = []
                connection = SimpleNamespace(close=lambda: closed.append(True))
                def connect(**parameters):
                    projected.extend(int(parameters[name].rsplit("/", 1)[1]) for name in ("sslrootcert", "sslcert", "sslkey"))
                    self.assertEqual(parameters["connect_timeout"], 10)
                    self.assertEqual(parameters["options"], "-c search_path=pg_catalog")
                    self.assertFalse(parameters["autocommit"])
                    if not after_connect: raise RuntimeError("synthetic connect refusal")
                    # Genuine original identity check must reject this change
                    # after connect returns, and close the returned connection.
                    os.fchmod(owner.key.fd, 0o600)
                    return connection
                close = os.close
                def close_then_report(fd):
                    close(fd)
                    if projected and fd == projected[-1]: raise OSError("synthetic cleanup error")
                with patch.object(psycopg, "connect", side_effect=connect), patch.object(os, "close", side_effect=close_then_report):
                    with self.assertRaises(OAuthApplicationError if after_connect else RuntimeError) as caught:
                        witness.Connection(owner, owner.deadline).__enter__()
                if not after_connect:
                    self.assertEqual(str(caught.exception), "synthetic connect refusal")
                    owner.check()
                self.assert_descriptors_closed(projected)
                self.assertEqual(closed, [True] if after_connect else [])

    def test_connect_timeout_uses_original_remainder_after_tls_projection(self):
        import psycopg
        cases = ((10_750_000_000, 2_500_000_000, 8),
            (50_900_000_000, 2_000_000_000, 30),
            (2_999_999_999, 0, 2), (2_000_000_000, 0, 2), (1, 0, 2))
        for remaining, projection, expected in cases:
            with self.subTest(remaining_ns=remaining, projection_ns=projection), \
                    timed_tls_projection_control(remaining_ns=remaining, projection_ns=projection) as fixture:
                owner, connection, clock, projected = fixture
                deadlines = owner.deadline, connection.deadline

                def connect(**parameters):
                    self.assertEqual(clock[0], 10_000_000_000 + projection)
                    self.assertEqual(len(projected), 3)
                    for fd in projected: os.fstat(fd)
                    self.assertIs(type(parameters["connect_timeout"]), int)
                    self.assertEqual(parameters["connect_timeout"], expected)
                    self.assertGreaterEqual(parameters["connect_timeout"], 2)
                    self.assertLessEqual(parameters["connect_timeout"], 30)
                    self.assertEqual(parameters["options"], "-c search_path=pg_catalog")
                    self.assertFalse(parameters["autocommit"])
                    raise RuntimeError("synthetic transport refusal")

                with patch.object(psycopg, "connect", side_effect=connect) as transport:
                    with self.assertRaisesRegex(RuntimeError, "^synthetic transport refusal$"):
                        connection.__enter__()
                transport.assert_called_once()
                self.assertIsNone(connection.connection)
                self.assertEqual((owner.deadline, connection.deadline), deadlines)
                self.assert_descriptors_closed(projected)
                owner.check()

    def test_expired_after_projection_refuses_without_connect_or_retry(self):
        import psycopg
        for projection in (1_000_000_000, 1_000_000_001):
            with self.subTest(projection_ns=projection), \
                    timed_tls_projection_control(remaining_ns=1_000_000_000, projection_ns=projection) as fixture:
                owner, connection, _clock, projected = fixture
                deadlines = owner.deadline, connection.deadline
                with patch.object(psycopg, "connect") as transport:
                    with self.assertRaises(ValueError): connection.__enter__()
                transport.assert_not_called()
                self.assertIsNone(connection.connection)
                self.assertEqual((owner.deadline, connection.deadline), deadlines)
                self.assert_descriptors_closed(projected)
                owner.check()

    def test_subsecond_connect_return_keeps_deadline_and_closes_before_late_sql(self):
        import psycopg
        for offset in (-1, 0, 1):
            with self.subTest(return_offset_ns=offset), \
                    timed_tls_projection_control(remaining_ns=1_500_000_000, projection_ns=1_000_000_000) as fixture:
                owner, connection, clock, projected = fixture
                deadlines = owner.deadline, connection.deadline
                closed, statements = [], []

                def close():
                    closed.append(True)
                    returned.closed = True

                def execute(*args):
                    statements.append(args)
                    # Stop at the first SQL boundary: never fabricate catalog
                    # rows, a successful admitted connection, or a DB outcome.
                    raise RuntimeError("synthetic first SQL boundary")

                returned = SimpleNamespace(closed=False, close=close, execute=execute)

                def connect(**parameters):
                    self.assertEqual(parameters["connect_timeout"], 2)
                    clock[0] = connection.deadline + offset
                    return returned

                with patch.object(psycopg, "connect", side_effect=connect) as transport:
                    if offset < 0:
                        with self.assertRaisesRegex(RuntimeError, "^synthetic first SQL boundary$"):
                            connection.__enter__()
                    else:
                        with self.assertRaises(ValueError): connection.__enter__()
                transport.assert_called_once()
                self.assertEqual(len(statements), 1 if offset < 0 else 0)
                if statements:
                    self.assertTrue(statements[0][0].startswith("SELECT pg_catalog.set_config('statement_timeout'"))
                self.assertEqual(closed, [True])
                self.assertTrue(returned.closed)
                self.assertEqual((owner.deadline, connection.deadline), deadlines)
                self.assert_descriptors_closed(projected)
                owner.check()

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
