"""Root-signed local COLD successor principals, not running-process attestation.

The source-fixed roster is a measured association, not a complete runtime
closure. Actual protected TLS key custody is checked here; future owner/SQL
admission, catalog checks and one-use execution remain unchanged. The database
uses these historic enrollment digests as explicit cold pins, not as a TEE
verdict or a freshly observed service identity. No database is contacted.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import resource
import signal
import stat
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_local_configuration as config
from serverware import authority_local_database_credentials as credentials
from serverware import authority_local_artifact_measure as measure

io, spec, launch = config.io, config.spec, config.launcher
canonical, sha = spec.canonical_json_bytes, config.sha
APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalSuccessorColdEnrollmentApproval/v1"
SCHEMA = "serverware.authorityTrustedHostLocalSuccessorColdEnrollment/v1"
BUNDLE_SCHEMA = "serverware.authorityTrustedHostLocalSuccessorColdEnrollments/v1"
MEASUREMENT_DOMAIN = "serverware.authorityTrustedHostLocalSuccessorSourceRoster/v1"
PURPOSE = "enroll-three-measured-cold-successor-principals"
DELEGATION = "configuration-root-signs-local-cold-successor-principal-enrollment-v1"
ROLES = {"successor-issuer": ("ISSUER", "SuccessorExecutionIssuer"),
         "successor-executor": ("EXECUTOR", "SuccessorExecutionExecutor"),
         "successor-recovery": ("RECOVERY", "SuccessorExecutionRecoveryReader")}
SOURCE_PATHS = tuple(sorted("serverware/" + name for name in (
    "authority_successor_execution_owner.py", "authority_successor_execution_attempts.py",
    "authority_revocation_root_reader.py", "authority_store/successor_execution_sql.py",
    "authority_store/successor_execution_privileges.py", "authority_public_revocation_terminal.py",
    "registration_execution_sql_startup.py", "registration_execution_completion_startup.py",
    "registration_finalization_sql_startup.py", "registration_finalization_completion_startup.py",
    "oidc_session_activation_execution_sql_startup.py", "oidc_session_activation_completion_startup.py",
    "oidc_session_activation_delivery_execution_sql_startup.py", "oidc_session_activation_delivery_completion_startup.py",
    "oidc_session_activation_release_proof_startup.py", "oidc_session_activation_release_proof_input_issuer_startup.py")))
CLAIMS = dict(trustMode="trusted-host-local", coLocated=True, independentlyAdministered=False,
              hardwareBacked=False, runningProcessObserved=False, completeRuntimeClosure=False,
              databaseSessionObserved=False, databaseAuthorityInstalled=False)
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "configurationRootPublicKeyBase64Url",
    "sourceRoot", "sourceFiles", "issuanceOriginals", "bootIdDigest", "issuedAtBoottimeNs",
    "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})
CANCEL = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
MAX_SOURCE = 2 * 1024 * 1024


def require(value):
    if not value:
        raise ValueError("local successor cold enrollment refused")


def prepare(raw, *, boot, now_boottime_ns, now_unix_ns):
    value = config.document(raw, io.MAX_PUBLIC)
    require(set(value) == FIELDS and value["schema"] == APPROVAL_SCHEMA
        and value["purpose"] == PURPOSE and value["rootDelegation"] == DELEGATION
        and value["bootIdDigest"] == boot)
    spec._require_digest(boot, name="cold enrollment boot")
    root = config._public(value["configurationRootPublicKeyBase64Url"])
    for first, last, now in (("issuedAtBoottimeNs", "deadlineBoottimeNs", now_boottime_ns),
                             ("issuedAtUnixNanos", "expiresAtUnixNanos", now_unix_ns)):
        require(type(now) is int and type(value[first]) is type(value[last]) is int
            and 0 < value[first] <= now < value[last] < 2**63
            and value[last] - value[first] <= 300_000_000_000)
    directory = value["sourceRoot"]
    require(type(directory) is dict and set(directory) == {"device", "inode"}
        and type(directory["device"]) is type(directory["inode"]) is int
        and 0 <= directory["device"] < 2**64 and 0 < directory["inode"] < 2**64)
    require(type(value["sourceFiles"]) is dict and set(value["sourceFiles"]) == set(SOURCE_PATHS))
    for row in value["sourceFiles"].values():
        require(type(row) is dict and set(row) == {"sha256", "size"}
            and type(row["size"]) is int and 0 < row["size"] <= MAX_SOURCE)
        spec._require_digest(row["sha256"], name="cold source original")
    require(type(value["issuanceOriginals"]) is dict and set(value["issuanceOriginals"]) == set(ROLES))
    identities, targets, certs, authorities = {}, set(), set(), set()
    for role, original in value["issuanceOriginals"].items():
        require(type(original) is str and original.isascii())
        literal = original.encode("ascii")
        identity = credentials.issuance(literal, purpose=role)
        issued = config.document(literal, io.MAX_PUBLIC)
        require(issued["issuedAtUnixNanos"] <= value["issuedAtUnixNanos"]
            and identity["notBeforeEpochNs"] <= value["issuedAtUnixNanos"]
            and value["expiresAtUnixNanos"] <= identity["expiresAtEpochNs"])
        identities[role] = identity
        targets.add((issued["database"], issued["host"], issued["port"], issued["approvalSha256"]))
        certs.add(identity["certificateSha256"]); authorities.add(identity["caCertificateSha256"])
    require(len(targets) == len(authorities) == 1 and len(certs) == 3)
    return dict(value=value, rootPublic=root, identities=identities, original=raw)


def _payload(context, role):
    selected, identity = context["value"], context["identities"][role]
    measured = dict(sourceFiles=selected["sourceFiles"], ownerModule="serverware.authority_successor_execution_owner",
        ownerClass=ROLES[role][1], completeRuntimeClosure=False)
    return dict(schema=SCHEMA, purpose=role, rootDelegation=DELEGATION, claims=dict(CLAIMS),
        approvalSha256=sha(context["original"]), configurationRootPublicKeyBase64Url=selected["configurationRootPublicKeyBase64Url"],
        sourceMeasurement=measured, measurementDigest=spec.domain_digest(MEASUREMENT_DOMAIN, canonical(measured)),
        credentialIssuanceOriginal=selected["issuanceOriginals"][role], credentialIdentity=identity,
        privateKeyCustody="matching-sealed-private-original-held-at-cold-enrollment",
        sourceRoot=selected["sourceRoot"], **{name: selected[name] for name in
            ("bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")})


def signature_message(payload):
    return spec.domain_digest(SCHEMA, canonical(payload)).encode("ascii")


def _matching_tls_public(private_original, issuance_original):
    """Key/certificate equality only; custody is the live owner's responsibility."""
    require(type(private_original) is bytes and 0 < len(private_original) <= 8192)
    private = serialization.load_pem_private_key(private_original, password=None)
    original = config.document(issuance_original, io.MAX_PUBLIC)
    cert = x509.load_pem_x509_certificate(original["certificateOriginal"].encode("ascii"))
    require(isinstance(private, ec.EllipticCurvePrivateKey) and isinstance(private.curve, ec.SECP256R1)
        and credentials._public_key(private.public_key()) == credentials._public_key(cert.public_key()))
    return credentials._public_key(private.public_key())


def _projections(envelopes):
    environment, owners = {}, {}
    for role, envelope in envelopes.items():
        payload = envelope["payload"]
        identity = payload["credentialIdentity"]
        values = (payload["measurementDigest"], spec.domain_digest(SCHEMA, canonical(envelope)),
            identity["credentialIssuanceDigest"], identity["tlsClientDn"], identity["tlsClientSerial"], identity["tlsIssuerDn"])
        prefix = "SERVERWARE_POLICY_AUTHORITY_SUCCESSOR_" + ROLES[role][0] + "_"
        for suffix, value in zip(("MEASUREMENT_SHA256", "ATTESTATION_RECEIPT_SHA256", "CREDENTIAL_ISSUANCE_SHA256",
                                 "TLS_CLIENT_DN", "TLS_CLIENT_SERIAL", "TLS_ISSUER_DN"), values):
            environment[prefix + suffix] = value
        owners[role] = dict(ownerClass=ROLES[role][1], databaseRole=identity["databaseRole"],
            tls_client_dn=identity["tlsClientDn"], tls_client_serial=identity["tlsClientSerial"],
            tls_issuer_dn=identity["tlsIssuerDn"], expectedStructureManifestStillRequired=True)
    return environment, owners


def verify_bundle(raw, *, root_public, boot, now_boottime_ns, now_unix_ns):
    """Admit exact cold pins before bootstrap; never a replacement DB owner."""
    value = config.document(raw, io.MAX_PUBLIC)
    require(set(value) == {"schema", "approvalOriginal", "enrollments", "environment", "ownerBindings"}
        and value["schema"] == BUNDLE_SCHEMA and type(value["approvalOriginal"]) is str
        and value["approvalOriginal"].isascii() and type(root_public) is bytes)
    context = prepare(value["approvalOriginal"].encode("ascii"), boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    require(context["rootPublic"] == root_public and type(value["enrollments"]) is dict
        and set(value["enrollments"]) == set(ROLES))
    verifier = Ed25519PublicKey.from_public_bytes(root_public)
    for role, envelope in value["enrollments"].items():
        require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signature"}
            and envelope["schema"] == SCHEMA and envelope["payload"] == _payload(context, role))
        verifier.verify(spec.strict_base64url_decode(envelope["signature"], name="cold signature", decoded_size=64),
            signature_message(envelope["payload"]))
    environment, owners = _projections(value["enrollments"])
    require(value["environment"] == environment and value["ownerBindings"] == owners)
    return value


class ColdEnrollmentError(ValueError):
    def __init__(self, owner):
        super().__init__("local successor cold enrollment refused; owner retained")
        self.owner = owner


class LocalSuccessorColdEnrollment:
    def __init__(self, *, approval_fd, approval_sha256, source_directory_fd, signing_key_fd,
                 issuer_tls_key_fd, executor_tls_key_fd, recovery_tls_key_fd):
        self.handles, self.handle_identities, self.sources = [], {}, {}
        self.used, self.closed, self.closing = False, False, False
        try:
            io._process()
            self.pid = os.getpid(); self.start = launch._process_identity(self.pid)[0]
            self.fd, self.root_fd, self.key_fd = approval_fd, source_directory_fd, signing_key_fd
            self.tls = dict(zip(ROLES, (issuer_tls_key_fd, executor_tls_key_fd, recovery_tls_key_fd)))
            inputs = [approval_fd, source_directory_fd, signing_key_fd, *self.tls.values()]
            require(all(type(fd) is int and fd >= 3 for fd in inputs) and len(set(inputs)) == 6)
            self.approval_identity = io._input(self.fd, io.MAX_PUBLIC)
            self.raw = io.read_public(self.fd, io.MAX_PUBLIC); require(sha(self.raw) == approval_sha256)
            self.boot = launch._boot_identity_digest(); self.previous_boot, self.previous_unix = io._clock(), time.time_ns()
            self.context = prepare(self.raw, boot=self.boot, now_boottime_ns=self.previous_boot, now_unix_ns=self.previous_unix)
            self.root_identity = io._identity(os.fstat(self.root_fd))
            self._directory(self.root_fd)
            expected = self.context["value"]["sourceRoot"]
            require(self.root_identity[:2] == (expected["device"], expected["inode"]))
            self.key_identities = {fd: io._input(fd, 32 if fd == self.key_fd else 8192, private=True)
                for fd in (self.key_fd, *self.tls.values())}
            require(len({row[:2] for row in [self.approval_identity, self.root_identity, *self.key_identities.values()]}) == 6)
            for path in SOURCE_PATHS:
                current = self.root_fd
                for index, part in enumerate(path.split("/")):
                    directory = index < len(path.split("/")) - 1
                    mask = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL)
                    try:
                        fd = os.open(part, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                            | (os.O_DIRECTORY if directory else 0), dir_fd=current)
                        self.handles.append(fd)
                        self.handle_identities[fd] = io._identity(os.fstat(fd))
                    finally:
                        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                    if directory: self._directory(fd)
                    current = fd
                identity = io._identity(os.fstat(current))
                require(stat.S_ISREG(identity[2]) and identity[3:5] == (0, 0)
                    and not stat.S_IMODE(identity[2]) & 0o222 and identity[5] == 1)
                measure._frozen(current)
                self.sources[path] = (current, identity)
            self.check()
        except BaseException as error:
            raise ColdEnrollmentError(self) from error

    def _directory(self, fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        require(not flags & os.O_PATH and flags & os.O_ACCMODE == os.O_RDONLY)
        os.set_inheritable(fd, False)
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
        measure._frozen(fd)

    def check(self):
        io._process()
        require(not self.closed and not self.closing and os.getpid() == self.pid
            and launch._process_identity(self.pid)[0] == self.start and launch._boot_identity_digest() == self.boot)
        now, unix = io._clock(), time.time_ns()
        selected = self.context["value"]
        require(self.previous_boot <= now < selected["deadlineBoottimeNs"]
            and self.previous_unix <= unix < selected["expiresAtUnixNanos"])
        self.previous_boot, self.previous_unix = now, unix
        require(io._input(self.fd, io.MAX_PUBLIC) == self.approval_identity
            and io.read_public(self.fd, io.MAX_PUBLIC) == self.raw
            and io._identity(os.fstat(self.root_fd)) == self.root_identity)
        self._directory(self.root_fd)
        for fd, identity in self.key_identities.items():
            require(io._input(fd, 32 if fd == self.key_fd else 8192, private=True) == identity)
        for fd, identity in self.sources.values():
            require(io._identity(os.fstat(fd)) == identity); measure._frozen(fd)

    def issue(self):
        try:
            self.check(); require(not self.used); self.used = True
            for path, (fd, identity) in self.sources.items():
                expected = self.context["value"]["sourceFiles"][path]
                require(identity[6] == expected["size"])
                raw = bytearray()
                while len(raw) < identity[6]:
                    self.check()
                    part = os.pread(fd, min(65536, identity[6] - len(raw)), len(raw)); require(bool(part)); raw.extend(part)
                require(sha(bytes(raw)) == expected["sha256"] and not os.pread(fd, 1, len(raw)))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            libc = ctypes.CDLL(None); require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0)
            public_keys = set()
            for role, fd in self.tls.items():
                self.check()
                public_keys.add(_matching_tls_public(os.pread(fd, 8193, 0),
                    self.context["value"]["issuanceOriginals"][role].encode("ascii")))
            require(len(public_keys) == 3)
            self.check()
            key = io.signing_key(self.key_fd)
            require(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == self.context["rootPublic"])
            envelopes = {}
            for role in ROLES:
                self.check(); payload = _payload(self.context, role)
                envelopes[role] = dict(schema=SCHEMA, payload=payload,
                    signature=spec.strict_base64url_encode(key.sign(signature_message(payload))))
            del key
            environment, owners = _projections(envelopes)
            raw = canonical(dict(schema=BUNDLE_SCHEMA, approvalOriginal=self.raw.decode("ascii"),
                enrollments=envelopes, environment=environment, ownerBindings=owners))
            self.check()
            verify_bundle(raw, root_public=self.context["rootPublic"], boot=self.boot,
                now_boottime_ns=self.previous_boot, now_unix_ns=self.previous_unix)
            return raw
        except BaseException as error:
            raise ColdEnrollmentError(self) from error

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self.context["value"]["deadlineBoottimeNs"], check=self.check)

    def close(self):
        if self.closed: return
        require(not self.closing and os.getpid() == self.pid and launch._process_identity(self.pid)[0] == self.start)
        self.closing = True
        while self.handles:
            fd = self.handles[-1]
            require(io._identity(os.fstat(fd)) == self.handle_identities.get(fd))
            os.close(fd); self.handles.pop()
        self.closed = True
