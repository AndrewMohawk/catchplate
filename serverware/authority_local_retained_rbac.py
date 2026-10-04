"""One trusted-host-local RBAC head read under explicit root delegation.

This does not establish metadata/policy currentness, approve retained startup,
publish a cohort, or create/renew an enrollment. The caller supplies a fresh,
independently approved nonce and protected approval original; this process has
only a one-attempt latch, not a persistent replay ledger. A returned head is
point-in-time data, never a restart/readiness receipt. No action runs on import.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_local_cohort as local
from serverware import authority_rbac_currentness as wire
from serverware.authority_rbac_witness import Connection
from serverware.control_plane_rbac_currentness import _Owner as _TlsOwner
from serverware.oauth_application_owner import _Original

io, pair = local.io, local.pair
SCHEMA = "serverware.trustedHostLocalRetainedRbacReadApproval/v1"
PURPOSE = "read-one-retained-local-rbac-head"
DELEGATION = "host-root-delegates-read-only-observed-local-rbac-reader-v1"
MAX_READ_NS = 30_000_000_000
ROLE = "planner"
INPUTS = {
    "startup": ("SERVERWARE_RBAC_WITNESS_CONFIG_FD", 96 * 1024),
    "root": ("SERVERWARE_RBAC_WITNESS_ROOT_FD", 4096),
    "tlsRoot": ("SERVERWARE_RBAC_WITNESS_TLS_ROOT_FD", 65536),
    "clientCertificate": ("SERVERWARE_RBAC_WITNESS_CLIENT_CERTIFICATE_FD", 65536),
    "clientKey": ("SERVERWARE_RBAC_WITNESS_CLIENT_KEY_FD", 16384),
}
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "nonce", "bootIdDigest",
    "configurationRootPublicKeyBase64Url", "cohortApprovalSha256", "cohortSha256",
    "historicalArchiveSha256", "configurationDigest", "generationDigest",
    "startupSha256", "enrollmentSha256", "issuedAtBoottimeNs", "deadlineBoottimeNs",
    "issuedAtUnixNanos", "expiresAtUnixNanos"})


def require(value):
    if not value:
        raise ValueError("local retained RBAC read refused")


def _approval(raw, *, context, cohort_raw, cohort_approval_raw, archive_interval,
        nonce, boot, now_boot, now_epoch):
    """Closed approval codec; only open() supplies a genuinely admitted context."""
    value = wire.document(raw, 16384)
    selected = context["selected"]
    require(type(value) is dict and set(value) == FIELDS
        and value["schema"] == SCHEMA and value["purpose"] == PURPOSE
        and value["rootDelegation"] == DELEGATION and selected["schema"] == local.RETAINED_SCHEMA
        and type(nonce) is bytes and len(nonce) == 32
        and value["nonce"] == local.spec.strict_base64url_encode(nonce)
        and value["bootIdDigest"] == boot == selected["bootIdDigest"]
        and value["configurationRootPublicKeyBase64Url"] == selected["configurationRootPublicKeyBase64Url"]
        and local.configuration._public(value["configurationRootPublicKeyBase64Url"]) == context["rootPublic"])
    for name in ("cohortApprovalSha256", "cohortSha256", "historicalArchiveSha256",
            "configurationDigest", "generationDigest", "startupSha256", "enrollmentSha256"):
        wire.digest(value[name])
    require(value["cohortApprovalSha256"] == wire.sha256(cohort_approval_raw)
        and value["cohortSha256"] == wire.sha256(cohort_raw)
        and value["historicalArchiveSha256"] == selected["historicalArchiveSha256"]
        and value["configurationDigest"] == context["configurationDigest"]
        and value["generationDigest"] == context["generationDigest"])
    require(type(now_boot) is type(now_epoch) is int)
    for first, last, now in (("issuedAtBoottimeNs", "deadlineBoottimeNs", now_boot),
            ("issuedAtUnixNanos", "expiresAtUnixNanos", now_epoch)):
        require(type(value[first]) is type(value[last]) is int
            and 0 < selected[first] <= value[first] <= now < value[last] <= selected[last] < 2**63
            and value[last] - value[first] <= local.LOCAL_SETUP_MAX_NS)
    start, end = local.runtime_interval(selected)
    generation_start, generation_end = context["generationInterval"]
    archive_start, archive_end = local.history._interval(*archive_interval)
    require(max(start, generation_start, archive_start) <= value["issuedAtUnixNanos"]
        < value["expiresAtUnixNanos"] <= min(end, generation_end, archive_end))
    return value


def _observed_original(fd, observed_fd, row, maximum, *, private=False):
    identity = io._input(fd, maximum, private=True)
    # Same held original inode, not a caller-created byte-equivalent copy.
    require(identity == io._identity(os.fstat(observed_fd)))
    original = _Original(fd, maximum, private=private)
    require(len(original.raw) == row["size"] and wire.sha256(original.raw) == row["sha256"])
    return original


def _startup(originals, *, context, approval):
    """Authenticate the exact observed reader material, never a writer profile."""
    startup = wire.document(originals["startup"].raw, INPUTS["startup"][1])
    require(type(startup) is dict and set(startup) == {"schema", "sourceRevision",
        "configurationDigest", "root", "enrollment", "tlsRoot", "clientCertificate", "clientKey"}
        and startup["schema"] == wire.LOCAL_STARTUP_SCHEMA
        and startup["sourceRevision"] == local.cohort.authority.SOURCE_REVISION
        and startup["configurationDigest"] == context["configurationDigest"]
        and wire.sha256(originals["startup"].raw) == approval["startupSha256"])
    observed = {row["name"]: row for row in context["contexts"][ROLE]["observed"]["credentials"]}
    for name in INPUTS.keys() - {"startup"}:
        item = startup[name]
        require(type(item) is dict and set(item) == {"fd", "sha256"}
            and type(item["fd"]) is int and 32 <= item["fd"] <= 1023
            and item["fd"] == observed[INPUTS[name][0]]["fd"]
            and wire.sha256(originals[name].raw) == wire.digest(item["sha256"]))
    root = serialization.load_pem_public_key(originals["root"].raw)
    require(isinstance(root, Ed25519PublicKey)
        and root.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            == originals["root"].raw
        and root.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != context["rootPublic"])
    enrollment_raw = wire.canonical(startup["enrollment"])
    require(wire.sha256(enrollment_raw) == approval["enrollmentSha256"])
    policy = wire.enrollment(enrollment_raw, root)
    require(policy["schema"] == wire.LOCAL_ENROLLMENT_SCHEMA
        and policy["sourceRevision"] == local.cohort.authority.SOURCE_REVISION
        and context["configurationDigest"] in policy["configurationDigests"]
        and policy["issuedAtEpochNs"] <= approval["issuedAtUnixNanos"]
        < approval["expiresAtUnixNanos"] <= policy["expiresAtEpochNs"]
        and wire.sha256(originals["tlsRoot"].raw) == policy["tlsRootSha256"]
        and wire.sha256(originals["clientCertificate"].raw) == policy["reader"]["certificateSha256"])
    certificate = x509.load_pem_x509_certificate(originals["clientCertificate"].raw)
    key = serialization.load_pem_private_key(originals["clientKey"].raw, password=None)
    require(certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        == key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    del key
    return policy, enrollment_raw


class LocalRetainedRbacReader:
    # Reuse the existing bounded sealed TLS projection, not its global admission.
    connection_parameters = _TlsOwner.connection_parameters

    @property
    def writer(self):
        return False

    @classmethod
    def open(cls, *, cohort, approval_fd, approval_sha256, nonce, original_fds):
        self = cls()
        self.owned, self.originals = [], {}
        self.closed, self.used = False, False
        try:
            io._process()
            wire.require_local_development()
            require(not any(name.startswith("PG") for name in os.environ)
                and type(cohort) is local.LocalCohortIssuer)
            cohort.verify_live()
            require(cohort.issued and not cohort.publication_started and not cohort.released
                and cohort.value["schema"] == local.RETAINED_SCHEMA)
            self.cohort, self.context = cohort, cohort.context
            self.cohort_raw, self.cohort_approval_raw = cohort.cohort_raw, cohort.raw
            self.archive_interval = cohort.archive_interval
            require(type(self.cohort_raw) is bytes and type(self.cohort_approval_raw) is bytes)
            self.pid, self.start, self.boot = os.getpid(), local.launch._process_identity(os.getpid())[0], cohort.boot
            self.opening_mono = time.monotonic_ns()
            self.last_boot, self.last_epoch = io._clock(), time.time_ns()
            self.nonce = nonce
            require(type(original_fds) is dict and set(original_fds) == set(INPUTS))
            inputs = [approval_fd, *original_fds.values()]
            require(all(type(fd) is int and 3 <= fd < 2**31 for fd in inputs)
                and len(set(inputs)) == len(inputs)
                and len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in inputs}) == len(inputs))
            self.approval_fd = self._duplicate(approval_fd)
            self.approval_identity = io._input(self.approval_fd, 16384)
            self.approval_raw = io.read_public(self.approval_fd, 16384)
            require(wire.sha256(self.approval_raw) == wire.digest(approval_sha256))
            self.approval = _approval(self.approval_raw, context=self.context, cohort_raw=self.cohort_raw,
                cohort_approval_raw=self.cohort_approval_raw, archive_interval=self.archive_interval,
                nonce=nonce, boot=self.boot,
                now_boot=self.last_boot, now_epoch=self.last_epoch)
            observed = {row["name"]: row for row in self.context["contexts"][ROLE]["observed"]["credentials"]}
            observer = cohort.observers[ROLE]
            for name, (environment_name, maximum) in INPUTS.items():
                row = observed[environment_name]
                fd = self._duplicate(original_fds[name])
                self.originals[name] = _observed_original(fd, observer._child_fd(row["fd"]),
                    row, maximum, private=name == "clientKey")
            self.policy, self.enrollment_original = _startup(self.originals, context=self.context, approval=self.approval)
            self.policy_raw = wire.canonical(self.policy)
            self.enrollment_sha256 = wire.sha256(self.enrollment_original)
            self.tls_root, self.certificate, self.key = (self.originals[name]
                for name in ("tlsRoot", "clientCertificate", "clientKey"))
            self.deadline = self.opening_mono + min(
                self.approval["deadlineBoottimeNs"] - self.last_boot,
                self.approval["expiresAtUnixNanos"] - self.last_epoch)
            self.check()
            return self
        except BaseException:
            self.close()
            raise

    def _duplicate(self, fd):
        with pair._owning():
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
            try:
                self.owned.append(duplicate)
            except BaseException:
                os.close(duplicate)
                raise
        return duplicate

    def check(self):
        io._process()
        wire.require_local_development()
        require(not self.closed and os.getpid() == self.pid
            and local.launch._process_identity(self.pid)[0] == self.start
            and local.launch._boot_identity_digest() == self.boot
            and not any(name.startswith("PG") for name in os.environ))
        self.cohort.check()
        require(self.cohort.context is self.context and self.cohort.issued
            and not self.cohort.publication_started and not self.cohort.released
            and self.cohort.raw == self.cohort_approval_raw and self.cohort.cohort_raw == self.cohort_raw
            and self.cohort.archive_interval == self.archive_interval)
        now_boot, now_epoch = io._clock(), time.time_ns()
        require(self.last_boot <= now_boot and self.last_epoch <= now_epoch
            and time.monotonic_ns() < self.deadline
            and fcntl.fcntl(self.approval_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
            and io._input(self.approval_fd, 16384) == self.approval_identity
            and io.read_public(self.approval_fd, 16384) == self.approval_raw)
        require(_approval(self.approval_raw, context=self.context, cohort_raw=self.cohort_raw,
            cohort_approval_raw=self.cohort_approval_raw, archive_interval=self.archive_interval,
            nonce=self.nonce, boot=self.boot,
            now_boot=now_boot, now_epoch=now_epoch) == self.approval)
        for name, original in self.originals.items():
            original.check()
            require(fcntl.fcntl(original.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                and io._input(original.fd, INPUTS[name][1], private=True) == original.identity[:9])
        require(wire.canonical(self.policy) == self.policy_raw
            and wire.sha256(self.enrollment_original) == self.enrollment_sha256)
        self.last_boot, self.last_epoch = now_boot, now_epoch

    def require_writer(self):
        raise ValueError("local retained RBAC reader never authorizes writes")

    def read_head(self):
        """One real TLS/ACL/head query, refusing any pending transition.

        Full source verification consumes the original approved owner window,
        not the transport's 30s budget. Slow post-read checks cannot make these
        point-in-time bytes fresh at return or establish whole-store currentness.
        """
        require(not self.used)
        self.used = True
        self.check()
        self.cohort.verify_live()
        remaining = min(MAX_READ_NS, self.approval["deadlineBoottimeNs"] - io._clock(),
            self.approval["expiresAtUnixNanos"] - time.time_ns())
        operation_deadline = min(self.deadline, time.monotonic_ns() + remaining)
        with Connection(self, operation_deadline) as connection:
            head, pending = connection.head(allow_pending=False)
            require(pending is None)
            raw = wire.canonical(wire.head(head))
        self.check()
        self.cohort.verify_live()
        return raw

    def close(self):
        if self.closed:
            return
        with pair._owning():
            for fd in reversed(self.owned):
                with contextlib.suppress(OSError):
                    os.close(fd)
            self.owned.clear()
            self.originals.clear()
            self.tls_root = self.certificate = self.key = None
            self.closed = True
