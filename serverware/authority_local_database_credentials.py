"""Issue actual local database TLS material; never provision database authority.

The operator selects the existing roles, original certificate interval and exact
empty output directory. Keys are generated locally, not hardware protected.
Outputs are staging originals, not installed credentials or observed PG sessions.
No connection, SQL, password, role membership or grant is created here.
"""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import ipaddress
import os
import re
import resource
import signal
import stat
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from scripts.authority import native_pilot_authority_io as io
from serverware.authority_artifact_spec import canonical_json_bytes as canonical
from serverware.authority_local_artifacts import document, sha
from serverware.authority_local_snapshot import _boot
from serverware.authority_witness_journal import _rename_noreplace
from serverware.authority_store.planner_read_sql import ROLE as PLANNER_ROLE

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalDatabaseCredentialApproval/v2"
ISSUANCE_SCHEMA = "serverware.authorityTrustedHostLocalDatabaseCredentialIssuance/v2"
INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalDatabaseCredentialInventory/v2"
LEGACY_ISSUANCE_SCHEMA = "serverware.authorityTrustedHostLocalDatabaseCredentialIssuance/v1"
RUNTIME_DIRECTORY = "/run/serverware/database-tls"
MAX_DOCUMENT = 65536
MAX_OPERATION_NS = 300_000_000_000
MAX_CERTIFICATE_SECONDS = 7 * 86400
CA_NAME = "serverware-local-database-ca"
FIXED_ROLES = {
    "planner": PLANNER_ROLE,
    "planner-writer": "serverware_policy_authority_planner_writer",
    "issuer": "serverware_policy_capability_issuer",
    "completion-reader": "serverware_policy_authority_completion_reader",
    "successor-issuer": "serverware_policy_authority_successor_issuer",
    "successor-executor": "serverware_policy_authority_successor_executor",
    "successor-recovery": "serverware_policy_authority_successor_recovery",
    "file-materializer": "serverware_policy_file_materializer",
    "genesis-materializer": "serverware_policy_file_genesis_materializer",
}
AUDIT_READER = "serverware_local_audit_inclusion_reader"
CANCEL = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
CLAIMS = dict(trustMode="trusted-host-local", coLocated=True, hardwareBacked=False,
              independentlyAdministered=False, databaseRoleObserved=False,
              credentialInstalled=False, databaseSessionObserved=False)


def require(value):
    if not value:
        raise ValueError("local database credential issuance refused")


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is not None)
    return value


def dns_name(value):
    require(type(value) is str and len(value) <= 253
        and re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", value) is not None
        and all(len(label) <= 63 for label in value.split(".")))
    try: ipaddress.ip_address(value)
    except ValueError: pass
    else: raise ValueError("a DNS identity, not an IP-literal certificate, is required")
    return value


def role_roster(value):
    require(value["schema"] == APPROVAL_SCHEMA)
    roles = value["databaseRoles"]
    require(type(roles) is dict and set(roles) == {"metadata", "audit", "verifier", "executor"})
    for item in roles.values(): identifier(item)
    selected = dict(FIXED_ROLES, **{"metadata-runtime": roles["metadata"],
        "audit-runtime": roles["audit"], "verifier": roles["verifier"], "executor": roles["executor"]})
    require(len(set(selected.values())) == 13 and "serverware_policy_authority_owner" not in selected.values())
    require(type(value["includeAuditReader"]) is bool)
    if value["includeAuditReader"]:
        require(AUDIT_READER not in selected.values())
        selected["audit-inclusion-reader"] = AUDIT_READER
    return dict(sorted(selected.items()))


def approval(raw):
    value = document(raw, MAX_DOCUMENT)
    require(set(value) == {"schema", "database", "databaseRoles", "includeAuditReader", "host", "port",
        "clientNetwork", "intendedOwners", "outputDirectory", "bootIdDigest", "issuedAtBoottimeNs",
        "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos", "certificateNotBefore", "certificateNotAfter"}
        and value["schema"] == APPROVAL_SCHEMA)
    identifier(value["database"])
    dns_name(value["host"])
    require(type(value["port"]) is int and 1 <= value["port"] <= 65535)
    require(type(value["clientNetwork"]) is str)
    network = ipaddress.ip_network(value["clientNetwork"], strict=True)
    require(str(network) == value["clientNetwork"] and network.prefixlen > 0 and not network.is_multicast)
    require(type(value["bootIdDigest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["bootIdDigest"]) is not None)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        require(type(value[start]) is type(value[end]) is int and 0 < value[start] < value[end] < 2**63
            and value[end] - value[start] <= MAX_OPERATION_NS)
    before, after = value["certificateNotBefore"], value["certificateNotAfter"]
    require(type(before) is type(after) is int and 0 < before <= value["issuedAtUnixNanos"] // 10**9
        and value["expiresAtUnixNanos"] < after * 10**9 and 0 < after - before <= MAX_CERTIFICATE_SECONDS)
    directory = value["outputDirectory"]
    require(type(directory) is dict and set(directory) == {"device", "inode"}
        and all(type(item) is int and 0 <= item < 2**64 for item in directory.values()) and directory["inode"] > 0)
    owners = value["intendedOwners"]
    require(type(owners) is dict and set(owners) == set(role_roster(value)) | {"server"})
    for owner in owners.values():
        require(type(owner) is dict and set(owner) == {"uid", "gid"}
            and all(type(item) is int and 0 <= item < 2**31 for item in owner.values()))
    return value


def _public_key(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _name(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def issuance(raw, *, purpose=None, require_current=False):
    """Authenticate originals; v1 decoding retains its historical planner meaning.

    Fresh consumers require v2 explicitly. Neither version proves ownership,
    installation or PostgreSQL admission, and v1 is never relabelled as v2.
    """
    value = document(raw, MAX_DOCUMENT)
    require(type(require_current) is bool)
    require(set(value) == {"schema", "purpose", "databaseRole", "database", "host", "port", "intendedOwner",
        "runtimeDirectory", "approvalSha256", "issuedAtUnixNanos", "caCertificateOriginal", "certificateOriginal", "claims"}
        and value["schema"] in {ISSUANCE_SCHEMA, LEGACY_ISSUANCE_SCHEMA}
        and (not require_current or value["schema"] == ISSUANCE_SCHEMA)
        and canonical(value["claims"]) == canonical(CLAIMS))
    current = value["schema"] == ISSUANCE_SCHEMA
    fixed = FIXED_ROLES if current else {name: role for name, role in FIXED_ROLES.items() if name != "planner"}
    allowed = set(fixed) | {"planner", "audit-runtime", "verifier", "executor", "audit-inclusion-reader"}
    if current: allowed.add("metadata-runtime")
    require(value["purpose"] in allowed and (purpose is None or value["purpose"] == purpose))
    role = identifier(value["databaseRole"])
    if value["purpose"] in fixed: require(role == fixed[value["purpose"]])
    if value["purpose"] == "audit-inclusion-reader": require(role == AUDIT_READER)
    require(value["runtimeDirectory"] == RUNTIME_DIRECTORY + "/" + value["purpose"])
    identifier(value["database"])
    dns_name(value["host"])
    require(type(value["port"]) is int and 1 <= value["port"] <= 65535)
    owner = value["intendedOwner"]
    require(type(owner) is dict and set(owner) == {"uid", "gid"}
        and all(type(item) is int and 0 <= item < 2**31 for item in owner.values()))
    require(type(value["approvalSha256"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["approvalSha256"]) is not None)
    certs = []
    for name in ("caCertificateOriginal", "certificateOriginal"):
        pem = value[name]
        require(type(pem) is str and len(pem) <= 8192 and pem.isascii())
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        require(_pem(cert) == pem and isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
            and isinstance(cert.public_key().curve, ec.SECP256R1)
            and isinstance(cert.signature_hash_algorithm, hashes.SHA256))
        certs.append(cert)
    ca, client = certs
    require(ca.subject == ca.issuer == _name(CA_NAME) and client.issuer == ca.subject
        and client.subject == _name(role) and client.serial_number != ca.serial_number
        and _public_key(client.public_key()) != _public_key(ca.public_key()))
    ca.verify_directly_issued_by(ca)
    client.verify_directly_issued_by(ca)
    require(ca.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(ca=True, path_length=0)
        and client.extensions.get_extension_for_class(x509.BasicConstraints).value == x509.BasicConstraints(ca=False, path_length=None)
        and list(client.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH])
    require(ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
        and client.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
        and not client.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
    before = int(client.not_valid_before_utc.timestamp()) * 10**9
    after = int(client.not_valid_after_utc.timestamp()) * 10**9
    require(client.not_valid_before_utc == ca.not_valid_before_utc and client.not_valid_after_utc == ca.not_valid_after_utc
        and type(value["issuedAtUnixNanos"]) is int and before <= value["issuedAtUnixNanos"] < after
        and 0 < after - before <= MAX_CERTIFICATE_SECONDS * 10**9)
    # PostgreSQL's pg_stat_ssl exposes its slash-form X509 name, not RFC4514.
    # These certificates have exactly one validated, restricted-ASCII CN, so
    # this is an exact backend projection, not permissive DN normalization.
    return dict(purpose=value["purpose"], databaseRole=role, tlsClientDn="/CN=" + role,
        tlsClientSerial=str(client.serial_number), tlsIssuerDn="/CN=" + CA_NAME,
        credentialIssuanceDigest=sha(raw), certificateSha256=sha(client.public_bytes(serialization.Encoding.DER)),
        caCertificateSha256=sha(ca.public_bytes(serialization.Encoding.DER)), notBeforeEpochNs=before, expiresAtEpochNs=after)


def _certificate(subject, key, ca, ca_key, selected, *, server=False):
    is_ca = ca is None
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject if is_ca else ca.subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.fromtimestamp(selected["certificateNotBefore"], timezone.utc))
        .not_valid_after(datetime.fromtimestamp(selected["certificateNotAfter"], timezone.utc))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=is_ca, crl_sign=is_ca,
            encipher_only=None, decipher_only=None), critical=True))
    if not is_ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
    if server: builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(selected["host"])]), critical=False)
    return builder.sign(key if is_ca else ca_key, hashes.SHA256())


def material(selected, *, approval_sha256, issued_at_unix_ns, check):
    """Generate genuine material; pure callers cannot claim runtime installation."""
    require(selected["schema"] == APPROVAL_SCHEMA
        and selected["issuedAtUnixNanos"] <= issued_at_unix_ns < selected["expiresAtUnixNanos"])
    result, records = {}, {}
    def pair(name, subject, ca=None, ca_key=None, *, server=False):
        check()
        key = ec.generate_private_key(ec.SECP256R1())
        cert = _certificate(subject, key, ca, ca_key, selected, server=server)
        require(_public_key(key.public_key()) == _public_key(cert.public_key()))
        result[name + ".key.pem"] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        result[name + ".cert.pem"] = cert.public_bytes(serialization.Encoding.PEM)
        check()
        return key, cert
    ca_key, ca = pair("ca", _name(CA_NAME))
    pair("server", _name(selected["host"]), ca, ca_key, server=True)
    from psycopg.conninfo import make_conninfo
    for purpose, role in role_roster(selected).items():
        key, cert = pair(purpose, _name(role), ca, ca_key)
        del key
        path = RUNTIME_DIRECTORY + "/" + purpose
        raw = canonical(dict(schema=ISSUANCE_SCHEMA, purpose=purpose, databaseRole=role,
            database=selected["database"], host=selected["host"], port=selected["port"],
            intendedOwner=selected["intendedOwners"][purpose], runtimeDirectory=path,
            approvalSha256=approval_sha256, issuedAtUnixNanos=issued_at_unix_ns,
            caCertificateOriginal=_pem(ca), certificateOriginal=_pem(cert), claims=CLAIMS))
        records[purpose] = issuance(raw, purpose=purpose)
        result[purpose + ".issuance.json"] = raw
        result[purpose + ".dsn"] = make_conninfo(host=selected["host"], port=selected["port"],
            dbname=selected["database"], user=role, sslmode="verify-full", sslrootcert=path + "/ca.pem",
            sslcert=path + "/certificate.pem", sslkey=path + "/private-key.pem", connect_timeout=5).encode("ascii")
    del ca_key
    result["pg_hba.fragment"] = ("".join("hostssl " + selected["database"] + " " + role + " " + selected["clientNetwork"] + " cert clientname=CN\n"
        for role in role_roster(selected).values()) + "hostnossl " + selected["database"] + " all " + selected["clientNetwork"] + " reject\n").encode("ascii")
    result["postgresql.fragment"] = ("ssl = on\nssl_cert_file = '" + RUNTIME_DIRECTORY + "/server/certificate.pem'\nssl_key_file = '"
        + RUNTIME_DIRECTORY + "/server/private-key.pem'\nssl_ca_file = '" + RUNTIME_DIRECTORY + "/server/ca.pem'\nssl_min_protocol_version = 'TLSv1.3'\n").encode("ascii")
    result["inventory.json"] = canonical(dict(schema=INVENTORY_SCHEMA, approvalSha256=approval_sha256,
        claims=CLAIMS, identities=records, files={name: dict(bytes=len(raw), sha256=sha(raw), stagingMode=256)
            for name, raw in sorted(result.items())}, intendedOwners=selected["intendedOwners"]))
    check()
    return result


class CredentialIssuanceError(ValueError):
    def __init__(self, owner):
        super().__init__("local database credential issuance failed; partial private staging retained")
        self.owner = owner


class LocalDatabaseCredentialIssuer:
    def __init__(self, *, approval_fd, approval_sha256, output_directory_fd):
        io._process()
        from serverware import config
        require(not config.PRODUCTION_IMAGE and os.environ.get("SERVERWARE_PROCESS_MODE") == "metadata-bootstrap"
            and os.environ.get("SERVERWARE_RELEASE_CHANNEL") == "dev")
        require(type(approval_fd) is type(output_directory_fd) is int and approval_fd >= 3
            and output_directory_fd >= 3 and approval_fd != output_directory_fd)
        self.approval_fd, self.directory = approval_fd, output_directory_fd
        self.raw = io.read_public(approval_fd, MAX_DOCUMENT)
        require(sha(self.raw) == approval_sha256)
        self.selected, self.pin = approval(self.raw), approval_sha256
        self.source_identity = io._input(approval_fd, MAX_DOCUMENT)
        info = os.fstat(output_directory_fd)
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
            and self.selected["outputDirectory"] == dict(device=info.st_dev, inode=info.st_ino)
            and (info.st_dev, info.st_ino) != self.source_identity[:2])
        self.directory_identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        require(not os.listdir(output_directory_fd))
        self.pid, self.environment = os.getpid(), dict(os.environ)
        self.boot_ns, self.unix_ns = self.selected["issuedAtBoottimeNs"], self.selected["issuedAtUnixNanos"]
        self.handles, self.completed = [], []
        self.used, self.closed, self.uncertain = False, False, False
        self.check()

    def check(self):
        io._process()
        require(not self.closed and not self.uncertain and os.getpid() == self.pid and dict(os.environ) == self.environment
            and _boot() == self.selected["bootIdDigest"] and io._input(self.approval_fd, MAX_DOCUMENT) == self.source_identity
            and io.read_public(self.approval_fd, MAX_DOCUMENT) == self.raw)
        info = os.fstat(self.directory)
        require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) == self.directory_identity)
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.boot_ns <= boot < self.selected["deadlineBoottimeNs"] and self.unix_ns <= unix < self.selected["expiresAtUnixNanos"])
        self.boot_ns, self.unix_ns = boot, unix
        for name, fd, identity, digest in self.completed:
            require(io._identity(os.fstat(fd)) == identity
                and io._identity(os.stat(name, dir_fd=self.directory, follow_symlinks=False)) == identity
                and sha(os.pread(fd, MAX_DOCUMENT + 1, 0)) == digest)

    def _publish(self, name, raw):
        require(re.fullmatch(r"[a-z][a-z0-9._-]{0,80}", name) is not None and 0 < len(raw) <= MAX_DOCUMENT)
        self.check()
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL)
        try:
            fd = os.open("." + name + ".pending", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory)
            self.handles.append(fd)
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        offset = 0
        while offset < len(raw):
            self.check()
            written = os.write(fd, raw[offset:offset + 65536])
            require(written > 0)
            offset += written
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        require(os.pread(fd, len(raw) + 1, 0) == raw)
        self.check()
        _rename_noreplace(self.directory, "." + name + ".pending", name)
        os.fsync(self.directory)
        identity = io._identity(os.fstat(fd))
        require((identity[3], identity[4], stat.S_IMODE(identity[2]), identity[5]) == (0, 0, 0o400, 1))
        self.completed.append((name, fd, identity, sha(raw)))
        self.check()

    def run(self):
        require(not self.used)
        self.used = True
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            require(ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) == 0)
            self.check()
            values = material(self.selected, approval_sha256=self.pin, issued_at_unix_ns=self.unix_ns, check=self.check)
            for name in sorted(set(values) - {"inventory.json"}): self._publish(name, values[name])
            self._publish("inventory.json", values["inventory.json"])
            del values
            self.check()
        except BaseException as error:
            raise CredentialIssuanceError(self) from error

    def close(self):
        if self.closed: return
        require(os.getpid() == self.pid and not self.uncertain)
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL)
        try:
            while self.handles:
                try: os.close(self.handles[-1])
                except BaseException as error:
                    self.uncertain = True
                    raise CredentialIssuanceError(self) from error
                self.handles.pop()
            self.closed = True
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)
