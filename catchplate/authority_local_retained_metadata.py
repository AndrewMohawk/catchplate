"""One locally delegated, unsigned metadata-root observation, not restart truth.

Admission borrows a genuine unpublished v4 cohort and public configuration
custody. Neither signed history nor a database result selects an expected root.
The independent root-owned approval authorizes one read under original bounds;
the in-process latch is not a persistent replay ledger. CurrentRootReader has
no hard in-query cancellation: a bounded connect timeout and expiry checks do
not make its point-in-time observation current or fresh when returned.
"""
from __future__ import annotations

import fcntl
import os
import stat
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from catchplate import authority_current_root_reader as reader
from catchplate import authority_local_database_credentials as credentials
from catchplate import authority_local_retained_rbac as retained
from catchplate.authority_local_configuration import IssuedConfigurationCustody
from catchplate.oauth_application_owner import _Original

local, io, pair, wire = retained.local, retained.io, retained.pair, retained.wire
SCHEMA = "catchplate.trustedHostLocalRetainedMetadataReadApproval/v1"
PURPOSE = "read-one-retained-local-metadata-root-vector"
DELEGATION = "host-root-delegates-read-only-observed-local-metadata-verifier-v1"
DSN_NAME = "CATCHPLATE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN_FD"
TLS_DIRECTORY = credentials.RUNTIME_DIRECTORY + "/verifier"
INPUTS = {"dsn": 65536, "tlsRoot": 65536, "clientCertificate": 65536, "clientKey": 16384}
TLS_NAMES = {"tlsRoot": "ca.pem", "clientCertificate": "certificate.pem", "clientKey": "private-key.pem"}
ANCHORS = frozenset({"cohortApprovalSha256", "cohortSha256", "historicalArchiveSha256",
    "configurationApprovalSha256", "serviceConfigurationSha256", "verifierIssuanceSha256",
    "configurationDigest", "generationDigest"})
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "nonce", "bootIdDigest",
    "configurationRootPublicKeyBase64Url", "cohortApprovalSha256", "cohortSha256",
    "historicalArchiveSha256", "configurationApprovalSha256", "serviceConfigurationSha256",
    "verifierIssuanceSha256", "configurationDigest", "generationDigest", "originals",
    "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})


def require(value):
    if not value:
        raise ValueError("local retained metadata read refused")


def _approval(raw, *, context, configuration_approval, anchors, originals,
        archive_interval, certificate_interval, nonce, boot, now_boot, now_epoch):
    """Closed codec; its positive inputs alone cannot construct an owner."""
    value = wire.document(raw, 16384)
    selected = context["selected"]
    require(type(value) is dict and set(value) == FIELDS and value["schema"] == SCHEMA
        and value["purpose"] == PURPOSE and value["rootDelegation"] == DELEGATION
        and selected["schema"] == local.RETAINED_SCHEMA
        and type(nonce) is bytes and len(nonce) == 32
        and value["nonce"] == local.spec.strict_base64url_encode(nonce)
        and value["bootIdDigest"] == boot == selected["bootIdDigest"] == configuration_approval["bootIdDigest"]
        and value["configurationRootPublicKeyBase64Url"] == selected["configurationRootPublicKeyBase64Url"]
        == configuration_approval["configurationRootPublicKeyBase64Url"]
        and local.configuration._public(value["configurationRootPublicKeyBase64Url"]) == context["rootPublic"]
        and type(value["originals"]) is dict and set(value["originals"]) == set(INPUTS)
        and set(anchors) == ANCHORS
        and value["historicalArchiveSha256"] == selected["historicalArchiveSha256"]
        and value["configurationDigest"] == context["configurationDigest"]
        and value["generationDigest"] == context["generationDigest"])
    for name, row in value["originals"].items():
        require(type(row) is dict and set(row) == {"identity", "sha256"}
            and type(row["identity"]) is list and len(row["identity"]) == 9
            and all(type(item) is int and 0 <= item < 2**64 for item in row["identity"])
            and 0 < row["identity"][6] <= INPUTS[name])
        wire.digest(row["sha256"])
    if originals is not None:
        require(value["originals"] == originals)
    for name, expected in anchors.items():
        require(wire.digest(value[name]) == expected)
    require(type(now_boot) is type(now_epoch) is int)
    for first, last, now in (("issuedAtBoottimeNs", "deadlineBoottimeNs", now_boot),
            ("issuedAtUnixNanos", "expiresAtUnixNanos", now_epoch)):
        require(type(value[first]) is type(value[last]) is int
            and 0 < max(selected[first], configuration_approval[first]) <= value[first] <= now < value[last]
            <= min(selected[last], configuration_approval[last]) < 2**63
            and value[last] - value[first] <= local.LOCAL_SETUP_MAX_NS)
    intervals = (local.runtime_interval(selected), context["generationInterval"],
                 local.history._interval(*archive_interval), certificate_interval)
    require(max(first for first, _last in intervals) <= value["issuedAtUnixNanos"]
        < value["expiresAtUnixNanos"] <= min(last for _first, last in intervals))
    return value


class _NamedTlsOriginal:
    """Protected verifier-owned named file, not a sealed credential memfd."""
    def __init__(self, fd, name):
        self.fd, self.path, self.maximum = fd, TLS_DIRECTORY + "/" + TLS_NAMES[name], INPUTS[name]
        self.identity = self._identity()
        self.raw = os.pread(fd, self.maximum + 1, 0)
        require(len(self.raw) == self.identity[6])
        self.check()

    def _identity(self):
        info = os.fstat(self.fd)
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400
            and (info.st_uid, info.st_gid) == local.launch.ROLE_IDENTITIES["verifier"]
            and info.st_nlink == 1 and 0 < info.st_size <= self.maximum
            and not flags & os.O_PATH and flags & os.O_ACCMODE == os.O_RDONLY
            and fcntl.fcntl(self.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
            and os.readlink("/proc/self/fd/" + str(self.fd)) == self.path)
        result = io._identity(info)
        require(io._identity(os.stat(self.path, follow_symlinks=False)) == result)
        return result

    def check(self):
        require(self._identity() == self.identity
            and os.pread(self.fd, self.maximum + 1, 0) == self.raw
            and self._identity() == self.identity)


def _tls_and_dsn(originals, issuance_raw, service):
    """Join held files to custody-authenticated issuance, never caller hashes."""
    identity = credentials.issuance(issuance_raw, purpose="verifier")
    issued = local.configuration.document(issuance_raw, credentials.MAX_DOCUMENT)
    role = service["roles"]["verifier"]
    require(issued["intendedOwner"] == dict(zip(("uid", "gid"), local.launch.ROLE_IDENTITIES["verifier"]))
        and issued["runtimeDirectory"] == TLS_DIRECTORY)
    for name in ("databaseRole", "tlsClientDn", "tlsClientSerial", "tlsIssuerDn"):
        require(role[name] == identity[name])
    require(originals["tlsRoot"].raw == issued["caCertificateOriginal"].encode("ascii")
        and originals["clientCertificate"].raw == issued["certificateOriginal"].encode("ascii"))
    certificate = x509.load_pem_x509_certificate(originals["clientCertificate"].raw)
    key = serialization.load_pem_private_key(originals["clientKey"].raw, password=None)
    require(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        == certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    del key
    expected = dict(host=issued["host"], port=str(issued["port"]), dbname=issued["database"],
        user=identity["databaseRole"], sslmode="verify-full", sslrootcert=TLS_DIRECTORY + "/ca.pem",
        sslcert=TLS_DIRECTORY + "/certificate.pem", sslkey=TLS_DIRECTORY + "/private-key.pem", connect_timeout="5")
    raw = originals["dsn"].raw
    require(b"\n" not in raw and b"\r" not in raw and conninfo_to_dict(raw.decode("ascii")) == expected)
    return expected, (identity["notBeforeEpochNs"], identity["expiresAtEpochNs"])


def _connect_timeout(configured, remaining_ns):
    require(type(configured) in (int, float) and 0 < configured < 2**63
        and type(remaining_ns) is int)
    seconds = int(min(5, configured, remaining_ns // 1_000_000_000))
    require(2 <= seconds <= 300)
    return seconds


class LocalRetainedMetadataReader:
    def __init__(self):
        raise TypeError("retained metadata reader requires actual held owners and originals")

    @classmethod
    def open(cls, *, cohort, configuration_custody, approval_fd, approval_sha256, nonce, original_fds):
        self = object.__new__(cls)
        self.owned, self.originals = {}, {}
        self.closed, self.used, self.pid = False, False, os.getpid()
        try:
            io._process()
            wire.require_local_development()
            require(cls is LocalRetainedMetadataReader and type(cohort) is local.LocalCohortIssuer
                and type(configuration_custody) is IssuedConfigurationCustody
                and not any(name.startswith("PG") for name in os.environ))
            cohort.verify_live()
            configuration_custody.check()
            require(cohort.issued and not cohort.publication_started and not cohort.released
                and cohort.value["schema"] == local.RETAINED_SCHEMA)
            self.cohort, self.custody, self.context = cohort, configuration_custody, cohort.context
            self.service_raw = configuration_custody.service_original()
            require(self.service_raw == self.context["serviceOriginal"])
            self.configuration_raw = configuration_custody.approval_original()
            self.issuance_raw = configuration_custody.verifier_issuance_original()
            self.configuration_approval = local.configuration.document(self.configuration_raw, io.MAX_PUBLIC)
            self.service = local.configuration.document(self.service_raw, local.configuration.MAX_CONFIGURATION)["payload"]
            self.cohort_raw, self.cohort_approval_raw = cohort.cohort_raw, cohort.raw
            self.archive_interval, self.boot = cohort.archive_interval, cohort.boot
            self.start = local.launch._process_identity(self.pid)[0]
            self.last_boot, self.last_epoch = io._clock(), time.time_ns()
            self.opening_mono, self.nonce = time.monotonic_ns(), nonce
            require(type(original_fds) is dict and set(original_fds) == set(INPUTS))
            fds = [approval_fd, *original_fds.values()]
            require(all(type(fd) is int and fd >= 3 for fd in fds) and len(set(fds)) == len(fds)
                and len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fds}) == len(fds))
            self.approval_fd = self._duplicate(approval_fd)
            self.approval_identity = io._input(self.approval_fd, 16384)
            self.approval_raw = io.read_public(self.approval_fd, 16384)
            require(wire.sha256(self.approval_raw) == wire.digest(approval_sha256))
            self.anchors = dict(cohortApprovalSha256=wire.sha256(self.cohort_approval_raw),
                cohortSha256=wire.sha256(self.cohort_raw), historicalArchiveSha256=cohort.value["historicalArchiveSha256"],
                configurationApprovalSha256=wire.sha256(self.configuration_raw),
                serviceConfigurationSha256=wire.sha256(self.service_raw), verifierIssuanceSha256=wire.sha256(self.issuance_raw),
                configurationDigest=self.context["configurationDigest"], generationDigest=self.context["generationDigest"])
            certificate = credentials.issuance(self.issuance_raw, purpose="verifier")
            self.certificate_interval = (certificate["notBeforeEpochNs"], certificate["expiresAtEpochNs"])
            # Authenticate purpose, scope and original intervals before reading
            # private TLS bytes; join actual FD identities/bytes immediately below.
            approved = _approval(self.approval_raw, context=self.context, configuration_approval=self.configuration_approval,
                anchors=self.anchors, originals=None, archive_interval=self.archive_interval,
                certificate_interval=self.certificate_interval, nonce=nonce, boot=self.boot,
                now_boot=io._clock(), now_epoch=time.time_ns())
            rows = {row["name"]: row for row in self.context["contexts"]["verifier"]["observed"]["credentials"]}
            row = rows[DSN_NAME]
            self.originals["dsn"] = retained._observed_original(self._duplicate(original_fds["dsn"]),
                cohort.observers["verifier"]._child_fd(row["fd"]), row, INPUTS["dsn"], private=True)
            for name in TLS_NAMES:
                self.originals[name] = _NamedTlsOriginal(self._duplicate(original_fds[name]), name)
            self.parameters, self.certificate_interval = _tls_and_dsn(self.originals, self.issuance_raw, self.service)
            self.approval = self._approval_now()
            require(self.approval == approved)
            self.deadline = self.opening_mono + min(self.approval["deadlineBoottimeNs"] - self.last_boot,
                self.approval["expiresAtUnixNanos"] - self.last_epoch)
            self.check()
            return self
        except BaseException:
            self.close()
            raise

    def _hold(self, fd):
        try:
            self.owned[fd] = io._identity(os.fstat(fd))[:2]
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _duplicate(self, fd):
        with pair._owning():
            return self._hold(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3))

    def _approval_now(self):
        originals = {name: dict(identity=list(original.identity[:9]), sha256=wire.sha256(original.raw))
                     for name, original in self.originals.items()}
        return _approval(self.approval_raw, context=self.context, configuration_approval=self.configuration_approval,
            anchors=self.anchors, originals=originals, archive_interval=self.archive_interval,
            certificate_interval=self.certificate_interval, nonce=self.nonce, boot=self.boot,
            now_boot=io._clock(), now_epoch=time.time_ns())

    def check(self):
        io._process()
        wire.require_local_development()
        require(type(self) is LocalRetainedMetadataReader and not self.closed and os.getpid() == self.pid
            and local.launch._process_identity(self.pid)[0] == self.start
            and local.launch._boot_identity_digest() == self.boot
            and not any(name.startswith("PG") for name in os.environ))
        self.cohort.verify_live()
        self.custody.check()
        require(self.cohort.context is self.context and self.cohort.issued
            and not self.cohort.publication_started and not self.cohort.released
            and self.cohort.raw == self.cohort_approval_raw and self.cohort.cohort_raw == self.cohort_raw
            and self.cohort.archive_interval == self.archive_interval
            and self.custody.service_original() == self.service_raw == self.context["serviceOriginal"]
            and self.custody.approval_original() == self.configuration_raw
            and self.custody.verifier_issuance_original() == self.issuance_raw)
        require(local.configuration.document(self.configuration_raw, io.MAX_PUBLIC) == self.configuration_approval
            and local.configuration.document(self.service_raw, local.configuration.MAX_CONFIGURATION)["payload"] == self.service)
        require(self.last_boot <= io._clock() and self.last_epoch <= time.time_ns()
            and time.monotonic_ns() < self.deadline
            and io._input(self.approval_fd, 16384) == self.approval_identity
            and io.read_public(self.approval_fd, 16384) == self.approval_raw)
        for name, original in self.originals.items():
            original.check()
            require(fcntl.fcntl(original.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        row = next(row for row in self.context["contexts"]["verifier"]["observed"]["credentials"] if row["name"] == DSN_NAME)
        require(self.originals["dsn"].identity[:9] == io._identity(os.fstat(
            self.cohort.observers["verifier"]._child_fd(row["fd"]))))
        require(_tls_and_dsn(self.originals, self.issuance_raw, self.service)
            == (self.parameters, self.certificate_interval) and self._approval_now() == self.approval)
        now_boot, now_epoch = io._clock(), time.time_ns()
        require(self.last_boot <= now_boot < self.approval["deadlineBoottimeNs"]
            and self.last_epoch <= now_epoch < self.approval["expiresAtUnixNanos"]
            and time.monotonic_ns() < self.deadline)
        self.last_boot, self.last_epoch = now_boot, now_epoch

    def _projection(self, raw):
        with pair._owning():
            fd = self._hold(os.memfd_create("retained-metadata-tls", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING))
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0)
            offset += count
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, io.SEALS)
        original = _Original(fd, 65536, private=True)
        require(original.raw == raw)
        return original

    def read_once(self, *, work):
        """Consume one attempt; there is no hard in-query cancellation guarantee."""
        require(type(self) is LocalRetainedMetadataReader and not self.used)
        self.used = True
        self.check()
        projections = []
        original_fds = set(self.owned)
        try:
            parameters = dict(self.parameters)
            for key, name in (("sslrootcert", "tlsRoot"), ("sslcert", "clientCertificate"), ("sslkey", "clientKey")):
                with pair._owning():
                    original = self._projection(self.originals[name].raw)
                    projections.append(original)
                parameters[key] = "/proc/self/fd/" + str(original.fd)
            role = self.service["roles"]["verifier"]
            remaining = min(self.deadline - time.monotonic_ns(), self.approval["deadlineBoottimeNs"] - io._clock(),
                            self.approval["expiresAtUnixNanos"] - time.time_ns())
            timeout = _connect_timeout(role["databaseConnectTimeoutSeconds"], remaining)
            parameters.update(connect_timeout=str(timeout), passfile="/dev/null", password="", gssencmode="disable",
                              ssl_min_protocol_version="TLSv1.3", ssl_max_protocol_version="TLSv1.3")
            configured = reader.CurrentRootReader(dsn=make_conninfo(**parameters), connect_timeout_seconds=timeout,
                database_role=role["databaseRole"], tls_client_dn=role["tlsClientDn"],
                tls_client_serial=role["tlsClientSerial"], tls_issuer_dn=role["tlsIssuerDn"],
                query_manifest_digest=self.service["queryManifestDigest"])
            result = configured.read(work=work)
            for original in projections:
                original.check()
            self.check()
            require(type(result) is bytes)
            return result
        finally:
            with pair._owning():
                # Includes acquisition/write failures before a projection can
                # be returned or appended; borrowed originals remain held.
                for fd in reversed(tuple(self.owned)):
                    if fd not in original_fds:
                        self._release(fd)

    def _release(self, fd):
        require(io._identity(os.fstat(fd))[:2] == self.owned[fd])
        del self.owned[fd]
        os.close(fd)

    def close(self):
        if self.closed:
            return
        require(os.getpid() == self.pid)
        with pair._owning():
            for fd in reversed(tuple(self.owned)):
                self._release(fd)
            self.originals.clear()
            self.closed = True
