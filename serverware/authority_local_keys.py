"""Create the fixed local pilot key files; never grant authority to those keys.

Private seeds remain on the explicitly selected private directory. Inventory and
stdout contain public material only. Local root can access these keys: neither
hardware custody nor independent administration or reliable memory erasure is
claimed. Partial files persist on every failure; there is no reset or retry.
"""
from __future__ import annotations

import contextlib
import ctypes
import fcntl
import os
import resource
import signal
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from scripts.authority import native_pilot_authority_io as io
from serverware import authority_local_trust as trust

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalKeyProvisioningApproval/v1"
INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalKeyInventory/v1"
PURPOSE = "create-fixed-local-artifact-configuration-service-keys"
GENESIS_AUDIT_APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalGenesisAuditKeyProvisioningApproval/v1"
GENESIS_AUDIT_INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalGenesisAuditKeyInventory/v1"
GENESIS_AUDIT_PURPOSE = "create-fixed-local-genesis-audit-key"
ENROLLMENT_APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalEnrollmentKeyProvisioningApproval/v1"
ENROLLMENT_INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalEnrollmentKeyInventory/v1"
ENROLLMENT_PURPOSE = "create-fixed-local-registration-enrollment-keys"
CHAIN_APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalRegistrationChainKeyProvisioningApproval/v1"
CHAIN_INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalRegistrationChainKeyInventory/v1"
CHAIN_PURPOSE = "create-fixed-local-first-registration-chain-keys"
STARTUP_APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalStartupKeyProvisioningApproval/v1"
STARTUP_INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalStartupKeyInventory/v1"
STARTUP_PURPOSE = "create-fixed-local-launch-and-rbac-enrollment-keys"
SERVICE_ROLES = ("verifier", "planner", "planner-writer", "issuer", "executor", "witness")
MAX_APPROVAL = 8192
MAX_GENESIS_AUDIT_APPROVAL = 65536
MAX_PUBLIC = 65536
CANCEL = frozenset({signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
CLAIMS = dict(keyCreationOnly=True, hardwareBacked=False, independentAdministration=False,
    trustGranted=False, installationAccepted=False)
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
_LIBC.renameat2.restype = ctypes.c_int


def require(value):
    if not value: raise ValueError("local key provisioning refused")


def roster():
    rows = [dict(family="artifact", purpose=purpose, keyId=trust.key_id(purpose),
        publicPath="keys/artifact/"+purpose+".pub", privatePath="private/artifact/"+purpose+".seed")
        for purpose in trust.PURPOSES]
    rows.append(dict(family="configuration", purpose="configuration-root", keyId="local-configuration-root-v1",
        publicPath="keys/configuration/root.pub", privatePath="private/configuration/root.seed"))
    rows.extend(dict(family="service", purpose=role, keyId="local-service-"+role+"-v1",
        publicPath="keys/service/"+role+".pub", privatePath="private/service/"+role+".seed") for role in SERVICE_ROLES)
    require(len(rows) == 20)
    return tuple(rows)


def genesis_audit_roster():
    return (dict(family="genesis", purpose="audit-inclusion", keyId="local-genesis-audit-inclusion-v1",
        publicPath="keys/genesis/audit-inclusion.pub", privatePath="private/genesis/audit-inclusion.seed"),)


def enrollment_roster():
    return tuple(dict(family="enrollment", purpose=name, keyId="local-enrollment-" + name + "-v1",
        publicPath="keys/enrollment/" + name + ".pub", privatePath="private/enrollment/" + name + ".seed")
        for name in ("authorization", "registration-evidence"))


def chain_roster():
    return tuple(dict(family="registration-chain", purpose=name, keyId="local-registration-chain-" + name + "-v1",
        publicPath="keys/registration-chain/" + name + ".pub", privatePath="private/registration-chain/" + name + ".seed")
        for name in ("execution-caller", "finalization-caller", "computation", "completion", "state", "grant-authorizer"))


def startup_roster():
    purposes = tuple("launch-" + role for role in ("runtime", *SERVICE_ROLES)) + ("rbac-enrollment-root",)
    return tuple(dict(family="startup", purpose=name, keyId="local-startup-" + name + "-v1",
        publicPath="keys/startup/" + name + ".pub", privatePath="private/startup/" + name + ".seed")
        for name in purposes)


def _selected_roster(value):
    if (value["schema"], value["purpose"]) == (APPROVAL_SCHEMA, PURPOSE):
        return roster()
    if (value["schema"], value["purpose"]) == (ENROLLMENT_APPROVAL_SCHEMA, ENROLLMENT_PURPOSE):
        return enrollment_roster()
    if (value["schema"], value["purpose"]) == (CHAIN_APPROVAL_SCHEMA, CHAIN_PURPOSE):
        return chain_roster()
    if (value["schema"], value["purpose"]) == (STARTUP_APPROVAL_SCHEMA, STARTUP_PURPOSE):
        return startup_roster()
    require((value["schema"], value["purpose"]) == (GENESIS_AUDIT_APPROVAL_SCHEMA, GENESIS_AUDIT_PURPOSE))
    return genesis_audit_roster()


def _pilot_inventory(original):
    """Validate the literal public fixed20 inventory; confer no trust grant."""
    require(type(original) is str and original.isascii())
    value = trust.document(original.encode("ascii"), MAX_PUBLIC)
    require(set(value) == {"schema", "approvalSha256", "directory", "publicRosterSha256", "keys", "claims"}
        and value["schema"] == INVENTORY_SCHEMA and value["claims"] == CLAIMS
        and type(value["keys"]) is list and len(value["keys"]) == 20)
    for name in ("approvalSha256", "publicRosterSha256"):
        trust.spec._require_digest(value[name], name="existing key inventory pin")
    directory = value["directory"]
    require(type(directory) is dict and set(directory) == {"device", "inode"})
    for name, minimum in (("device", 0), ("inode", 1)):
        require(type(directory[name]) is int and minimum <= directory[name] < 2**64)
    seen, public_roster = set(), {}
    for row, expected in zip(value["keys"], roster(), strict=True):
        require(type(row) is dict and set(row) == set(expected) | {
            "publicKeyBase64Url", "publicKeySha256", "publicKeySpkiSha256"}
            and all(row[name] == item for name, item in expected.items()))
        raw = trust.spec.strict_base64url_decode(row["publicKeyBase64Url"], name="existing public key", decoded_size=32)
        public = Ed25519PublicKey.from_public_bytes(raw)
        require(raw not in seen and trust.sha(raw) == row["publicKeySha256"]
            and trust.sha(public.public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)) == row["publicKeySpkiSha256"])
        seen.add(raw)
        if row["family"] == "artifact":
            public_roster[row["purpose"]] = row["publicKeyBase64Url"]
    public_raw = trust.spec.canonical_json_bytes(public_roster)
    trust.public_roster(public_raw)
    require(trust.sha(public_raw) == value["publicRosterSha256"])
    return value, seen


def _extra_inventory(original, *, schema, expected_rows, pins, prior_keys):
    """Closed fixed-purpose public inventories; not key custody or trust admission."""
    require(type(original) is str and original.isascii())
    value = trust.document(original.encode("ascii"), MAX_PUBLIC)
    require(set(value) == {"schema", "approvalSha256", "directory", "publicRosterSha256", "keys", "claims"} | set(pins)
        and value["schema"] == schema and value["claims"] == CLAIMS
        and all(value[name] == expected for name, expected in pins.items())
        and type(value["keys"]) is list and len(value["keys"]) == len(expected_rows))
    for name in ("approvalSha256", "publicRosterSha256"):
        trust.spec._require_digest(value[name], name="extra key inventory pin")
    require(type(value["directory"]) is dict and set(value["directory"]) == {"device", "inode"})
    for name, minimum in (("device", 0), ("inode", 1)):
        require(type(value["directory"][name]) is int and minimum <= value["directory"][name] < 2**64)
    seen, public_roster = set(prior_keys), {}
    for row, expected in zip(value["keys"], expected_rows, strict=True):
        require(type(row) is dict and set(row) == set(expected) | {"publicKeyBase64Url", "publicKeySha256", "publicKeySpkiSha256"}
            and all(row[name] == item for name, item in expected.items()))
        raw = trust.spec.strict_base64url_decode(row["publicKeyBase64Url"], name="extra public key", decoded_size=32)
        require(raw not in seen and trust.sha(raw) == row["publicKeySha256"]
            and trust.sha(Ed25519PublicKey.from_public_bytes(raw).public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)) == row["publicKeySpkiSha256"])
        seen.add(raw); public_roster[row["purpose"]] = row["publicKeyBase64Url"]
    require(trust.sha(trust.spec.canonical_json_bytes(public_roster)) == value["publicRosterSha256"])
    return value, seen


def genesis_audit_inventory(original, pilot_original):
    pilot, prior = _pilot_inventory(pilot_original)
    value, seen = _extra_inventory(original, schema=GENESIS_AUDIT_INVENTORY_SCHEMA,
        expected_rows=genesis_audit_roster(), pins={"pilotKeyInventorySha256": trust.sha(pilot_original.encode("ascii"))},
        prior_keys=prior)
    require(value["directory"] != pilot["directory"])
    return value, seen


def enrollment_inventory(original, pilot_original, audit_original):
    pilot, _ = _pilot_inventory(pilot_original)
    audit, prior = genesis_audit_inventory(audit_original, pilot_original)
    value, seen = _extra_inventory(original, schema=ENROLLMENT_INVENTORY_SCHEMA,
        expected_rows=enrollment_roster(), pins={"pilotKeyInventorySha256": trust.sha(pilot_original.encode("ascii")),
            "genesisAuditKeyInventorySha256": trust.sha(audit_original.encode("ascii"))}, prior_keys=prior)
    require(value["directory"] not in (pilot["directory"], audit["directory"]))
    return value, seen


def chain_inventory(original, pilot_original, audit_original, enrollment_original):
    pilot, _ = _pilot_inventory(pilot_original)
    audit, _ = genesis_audit_inventory(audit_original, pilot_original)
    enrollment, prior = enrollment_inventory(enrollment_original, pilot_original, audit_original)
    value, seen = _extra_inventory(original, schema=CHAIN_INVENTORY_SCHEMA,
        expected_rows=chain_roster(), pins={"pilotKeyInventorySha256": trust.sha(pilot_original.encode("ascii")),
            "genesisAuditKeyInventorySha256": trust.sha(audit_original.encode("ascii")),
            "enrollmentKeyInventorySha256": trust.sha(enrollment_original.encode("ascii"))}, prior_keys=prior)
    require(value["directory"] not in (pilot["directory"], audit["directory"], enrollment["directory"]))
    return value, seen


def startup_inventory(original, pilot_original, audit_original, enrollment_original, chain_original):
    prior_inventories = (
        _pilot_inventory(pilot_original)[0],
        genesis_audit_inventory(audit_original, pilot_original)[0],
        enrollment_inventory(enrollment_original, pilot_original, audit_original)[0],
    )
    chain, prior = chain_inventory(chain_original, pilot_original, audit_original, enrollment_original)
    pins = dict(pilotKeyInventorySha256=trust.sha(pilot_original.encode("ascii")),
        genesisAuditKeyInventorySha256=trust.sha(audit_original.encode("ascii")),
        enrollmentKeyInventorySha256=trust.sha(enrollment_original.encode("ascii")),
        registrationChainKeyInventorySha256=trust.sha(chain_original.encode("ascii")))
    value, seen = _extra_inventory(original, schema=STARTUP_INVENTORY_SCHEMA,
        expected_rows=startup_roster(), pins=pins, prior_keys=prior)
    require(all(value["directory"] != old["directory"] for old in (*prior_inventories, chain)))
    return value, seen


def approval(raw):
    value = trust.document(raw, MAX_GENESIS_AUDIT_APPROVAL)
    fields = {"schema", "purpose", "directory", "bootIdDigest", "issuedAtBoottimeNs",
        "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
    if value.get("schema") == STARTUP_APPROVAL_SCHEMA:
        require(set(value) == fields | {"pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal",
            "enrollmentKeyInventoryOriginal", "registrationChainKeyInventoryOriginal"}
            and value["purpose"] == STARTUP_PURPOSE)
        prior = (
            _pilot_inventory(value["pilotKeyInventoryOriginal"])[0],
            genesis_audit_inventory(value["genesisAuditKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"])[0],
            enrollment_inventory(value["enrollmentKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"],
                value["genesisAuditKeyInventoryOriginal"])[0],
            chain_inventory(value["registrationChainKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"],
                value["genesisAuditKeyInventoryOriginal"], value["enrollmentKeyInventoryOriginal"])[0],
        )
        require(all(value["directory"] != old["directory"] for old in prior))
    elif value.get("schema") == CHAIN_APPROVAL_SCHEMA:
        require(set(value) == fields | {"pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal", "enrollmentKeyInventoryOriginal"}
            and value["purpose"] == CHAIN_PURPOSE)
        pilot, _ = _pilot_inventory(value["pilotKeyInventoryOriginal"])
        audit, _ = genesis_audit_inventory(value["genesisAuditKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"])
        enrollment, _ = enrollment_inventory(value["enrollmentKeyInventoryOriginal"],
            value["pilotKeyInventoryOriginal"], value["genesisAuditKeyInventoryOriginal"])
        require(value["directory"] not in (pilot["directory"], audit["directory"], enrollment["directory"]))
    elif value.get("schema") == ENROLLMENT_APPROVAL_SCHEMA:
        require(set(value) == fields | {"pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal"}
            and value["purpose"] == ENROLLMENT_PURPOSE)
        pilot, _ = _pilot_inventory(value["pilotKeyInventoryOriginal"])
        audit, _ = genesis_audit_inventory(value["genesisAuditKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"])
        require(value["directory"] not in (pilot["directory"], audit["directory"]))
    elif value.get("schema") == GENESIS_AUDIT_APPROVAL_SCHEMA:
        require(set(value) == fields | {"pilotKeyInventoryOriginal"} and value["purpose"] == GENESIS_AUDIT_PURPOSE)
        pilot, _ = _pilot_inventory(value["pilotKeyInventoryOriginal"])
        require(value["directory"] != pilot["directory"])
    else:
        require(len(raw) <= MAX_APPROVAL and set(value) == fields
            and value["schema"] == APPROVAL_SCHEMA and value["purpose"] == PURPOSE)
    trust.spec._require_digest(value["bootIdDigest"], name="key provisioning boot")
    directory = value["directory"]
    require(type(directory) is dict and set(directory) == {"device", "inode"})
    for name, minimum in (("device", 0), ("inode", 1)):
        require(type(directory[name]) is int and minimum <= directory[name] < 2**64)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        require(type(value[start]) is type(value[end]) is int and 0 < value[start] < value[end] < 2**63
            and value[end]-value[start] <= trust.MAX_OPERATION_NS)
    return value


def _directory(info):
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == info.st_gid == 0 and info.st_nlink > 0)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


@contextlib.contextmanager
def _owning():
    old = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL)
    try: yield
    finally: signal.pthread_sigmask(signal.SIG_SETMASK, old)


class LocalKeyProvisionerError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local key provisioning failed; partial state and actual owner retained; no retry")
        self.owner = owner


class LocalKeyProvisioner:
    """Takes custody of the two supplied FDs and every actual created handle."""

    def __init__(self, *, approval_fd, approval_sha256, directory_fd):
        self.handles, self.identities, self.directories, self.completed = [], {}, {}, []
        self.closed = self.uncertain = self.used = False
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        self.selected = None
        try:
            io._process()
            require(type(approval_fd) is type(directory_fd) is int and 3 <= approval_fd < 2**31
                and 3 <= directory_fd < 2**31 and approval_fd != directory_fd)
            with _owning():
                self.handles.extend((approval_fd, directory_fd))
                for fd in self.handles:
                    self.identities[fd] = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                    os.set_inheritable(fd, False)
            self.approval_fd, self.directory_fd = approval_fd, directory_fd
            self.raw = io.read_public(approval_fd, MAX_GENESIS_AUDIT_APPROVAL)
            trust.spec._require_digest(approval_sha256, name="key approval pin")
            require(trust.sha(self.raw) == approval_sha256)
            self.pin, self.selected = approval_sha256, approval(self.raw)
            require(trust.empty_directory(directory_fd) == self.selected["directory"])
            self.directories[""] = (directory_fd, _directory(os.fstat(directory_fd)))
            self.previous_boot, self.previous_unix = self.selected["issuedAtBoottimeNs"], self.selected["issuedAtUnixNanos"]
            self.check()
        except BaseException as error: raise LocalKeyProvisionerError(self) from error

    def _origin(self):
        io._process()
        require(os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment and not self.uncertain)

    def check_clock(self):
        self._origin()
        require(self.selected is not None and trust._boot() == self.selected["bootIdDigest"])
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.previous_boot <= boot < self.selected["deadlineBoottimeNs"]
            and self.previous_unix <= unix < self.selected["expiresAtUnixNanos"])
        self.previous_boot, self.previous_unix = boot, unix

    def check(self):
        self.check_clock(); require(not self.closed)
        require(io.read_public(self.approval_fd, MAX_GENESIS_AUDIT_APPROVAL) == self.raw)
        for fd, identity in self.identities.items():
            info = os.fstat(fd); require((info.st_dev, info.st_ino) == identity)
        for path, (fd, identity) in self.directories.items():
            require(_directory(os.fstat(fd)) == identity)
            if path:
                parent, leaf = path.rsplit("/", 1) if "/" in path else ("", path)
                require(_directory(os.stat(leaf, dir_fd=self.directories[parent][0], follow_symlinks=False)) == identity)
        for row in self.completed:
            parent, name, fd, identity, expected, private = row
            require(io._identity(os.fstat(fd)) == identity
                and io._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
            if private:
                seed = os.pread(fd, 33, 0)
                require(len(seed) == 32)
                key = Ed25519PrivateKey.from_private_bytes(seed)
                try:
                    require(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == expected)
                finally: del seed, key
            else: require(os.pread(fd, len(expected)+1, 0) == expected)

    def _hold(self, fd):
        self.handles.append(fd)
        info = os.fstat(fd)
        self.identities[fd] = info.st_dev, info.st_ino
        return fd

    def _mkdir(self, path):
        self.check()
        parent, name = path.rsplit("/", 1) if "/" in path else ("", path)
        parent_fd = self.directories[parent][0]
        with _owning():
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            fd = self._hold(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd))
            os.fchmod(fd, 0o700)
            self.directories[path] = fd, _directory(os.fstat(fd))
        os.fsync(fd); os.fsync(parent_fd)
        self.check()

    def _publish(self, path, raw, *, public=None):
        allowed = {name for row in _selected_roster(self.selected) for name in (row["publicPath"], row["privatePath"])} | {"public-roster.json", "inventory.json"}
        require(path in allowed and type(raw) is bytes and 0 < len(raw) <= MAX_PUBLIC)
        require((public is not None) == path.startswith("private/"))
        self.check()
        parent, name = path.rsplit("/", 1) if "/" in path else ("", path)
        parent_fd, _ = self.directories[parent]
        pending = "." + name + ".pending"
        with _owning():
            fd = self._hold(os.open(pending, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=parent_fd))
        offset = 0
        while offset < len(raw):
            self.check()
            count = os.write(fd, memoryview(raw)[offset:offset+65536]); require(count > 0); offset += count
        os.fchmod(fd, 0o400); os.fsync(fd)
        require(os.pread(fd, len(raw)+1, 0) == raw)
        self.check()
        if _LIBC.renameat2(parent_fd, os.fsencode(pending), parent_fd, os.fsencode(name), 1) != 0:
            raise OSError(ctypes.get_errno(), "fixed no-replace key publication refused")
        os.fsync(parent_fd)
        identity = io._identity(os.fstat(fd))
        require(stat.S_ISREG(identity[2]) and stat.S_IMODE(identity[2]) == 0o400
            and identity[3] == identity[4] == 0 and identity[5] == 1)
        self.completed.append((parent_fd, name, fd, identity, public if public is not None else raw, public is not None))
        self.check()

    def run(self):
        try:
            require(not self.used and not self.closed)
            self.used = True
            self.check()
            require(trust.empty_directory(self.directory_fd) == self.selected["directory"])
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            require(_LIBC.prctl(4, 0, 0, 0, 0) == 0 and _LIBC.prctl(3, 0, 0, 0, 0) == 0)
            # No key exists before core files and process dumpability are off.
            genesis_audit = self.selected["schema"] == GENESIS_AUDIT_APPROVAL_SCHEMA
            enrollment = self.selected["schema"] == ENROLLMENT_APPROVAL_SCHEMA
            chain = self.selected["schema"] == CHAIN_APPROVAL_SCHEMA
            startup = self.selected["schema"] == STARTUP_APPROVAL_SCHEMA
            paths = (("keys", "private", "keys/startup", "private/startup") if startup else
                ("keys", "private", "keys/registration-chain", "private/registration-chain") if chain else
                ("keys", "private", "keys/enrollment", "private/enrollment") if enrollment else
                ("keys", "private", "keys/genesis", "private/genesis") if genesis_audit else
                ("keys", "private", "keys/artifact", "private/artifact", "keys/configuration",
                 "private/configuration", "keys/service", "private/service"))
            for path in paths:
                self._mkdir(path)
            seen = (chain_inventory(self.selected["registrationChainKeyInventoryOriginal"], self.selected["pilotKeyInventoryOriginal"],
                self.selected["genesisAuditKeyInventoryOriginal"], self.selected["enrollmentKeyInventoryOriginal"])[1] if startup else
                enrollment_inventory(self.selected["enrollmentKeyInventoryOriginal"], self.selected["pilotKeyInventoryOriginal"],
                self.selected["genesisAuditKeyInventoryOriginal"])[1] if chain else
                genesis_audit_inventory(self.selected["genesisAuditKeyInventoryOriginal"],
                self.selected["pilotKeyInventoryOriginal"])[1] if enrollment else
                _pilot_inventory(self.selected["pilotKeyInventoryOriginal"])[1] if genesis_audit else set())
            rows, public_roster = [], {}
            for selected in _selected_roster(self.selected):
                self.check()
                private = Ed25519PrivateKey.generate()
                seed = None
                try:
                    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    require(public not in seen); seen.add(public)
                    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
                    self._publish(selected["privatePath"], seed, public=public)
                    self._publish(selected["publicPath"], public)
                    encoded = trust.spec.strict_base64url_encode(public)
                    rows.append(dict(selected, publicKeyBase64Url=encoded, publicKeySha256=trust.sha(public),
                        publicKeySpkiSha256=trust.sha(private.public_key().public_bytes(
                            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))))
                    if selected["family"] == "artifact" or genesis_audit or enrollment or chain or startup:
                        public_roster[selected["purpose"]] = encoded
                finally: del private, seed
            public_raw = trust.spec.canonical_json_bytes(public_roster)
            if startup:
                require(set(public_roster) == {row["purpose"] for row in startup_roster()} and len(rows) == 8)
            elif chain:
                require(set(public_roster) == {row["purpose"] for row in chain_roster()} and len(rows) == 6)
            elif enrollment:
                require(set(public_roster) == {"authorization", "registration-evidence"} and len(rows) == 2)
            elif genesis_audit:
                require(set(public_roster) == {"audit-inclusion"} and len(rows) == 1)
            else:
                trust.public_roster(public_raw)
            self._publish("public-roster.json", public_raw)
            inventory = dict(schema=STARTUP_INVENTORY_SCHEMA if startup else CHAIN_INVENTORY_SCHEMA if chain else ENROLLMENT_INVENTORY_SCHEMA if enrollment else GENESIS_AUDIT_INVENTORY_SCHEMA if genesis_audit else INVENTORY_SCHEMA,
                approvalSha256=self.pin, directory=self.selected["directory"],
                publicRosterSha256=trust.sha(public_raw), keys=rows, claims=CLAIMS)
            if genesis_audit or enrollment or chain or startup:
                inventory["pilotKeyInventorySha256"] = trust.sha(self.selected["pilotKeyInventoryOriginal"].encode("ascii"))
            if enrollment or chain or startup:
                inventory["genesisAuditKeyInventorySha256"] = trust.sha(self.selected["genesisAuditKeyInventoryOriginal"].encode("ascii"))
            if chain or startup:
                inventory["enrollmentKeyInventorySha256"] = trust.sha(self.selected["enrollmentKeyInventoryOriginal"].encode("ascii"))
            if startup:
                inventory["registrationChainKeyInventorySha256"] = trust.sha(self.selected["registrationChainKeyInventoryOriginal"].encode("ascii"))
            raw = trust.spec.canonical_json_bytes(inventory)
            self._publish("inventory.json", raw)  # Last durable completion marker.
            self.check()
            return raw
        except BaseException as error: raise LocalKeyProvisionerError(self) from error

    def close(self):
        if self.closed: return
        if not self.handles and not self.uncertain:
            require(os.getpid() == self.pid)
            self.closed = True
            return
        self._origin()
        try:
            with _owning():
                while self.handles:
                    fd = self.handles[-1]
                    if fd in self.identities:
                        info = os.fstat(fd); require((info.st_dev, info.st_ino) == self.identities[fd])
                    self.uncertain = True
                    os.close(fd)
                    self.handles.pop(); self.identities.pop(fd, None)
                    self.uncertain = False
                self.closed = True
        except BaseException as error: raise LocalKeyProvisionerError(self) from error
