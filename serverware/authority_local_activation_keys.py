"""Create only the fixed local activation keys, never enroll or authorize them.

This independent profile leaves every existing local-key schema unchanged.
Its ten Ed25519 seeds and five raw encryption keys have different codecs.
Only public keys and encryption-key commitments leave the private directory.
Root custody, not hardware custody or reliable memory erasure, is claimed.
Partial files survive failure; neither this owner nor its CLI retries a run.
"""
from __future__ import annotations

import ctypes
import os
import resource
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_local_keys as prior


io, trust = prior.io, prior.trust
APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalActivationKeyProvisioningApproval/v1"
INVENTORY_SCHEMA = "serverware.authorityTrustedHostLocalActivationKeyInventory/v1"
PURPOSE = "create-fixed-local-activation-keys"
MAX_APPROVAL = 128 * 1024
MAX_PUBLIC = 64 * 1024
CLAIMS = dict(prior.CLAIMS)
SIGNING_PURPOSES = (
    "activation-caller", "consume-caller", "release-intent-caller",
    "activation-planner", "consume-planner", "activation-grant-authorizer",
    "consume-grant-authorizer", "current-root-computation", "current-root-completion",
    "release-proof",
)
ENCRYPTION_PURPOSES = (
    "activation-delivery", "activation-journal", "activation-bundle",
    "consume-journal", "consume-execution-bundle",
)
PRIOR_FIELDS = (
    "pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal",
    "enrollmentKeyInventoryOriginal", "registrationChainKeyInventoryOriginal",
    "startupKeyInventoryOriginal",
)
_CLOCK_FIELDS = ("bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs",
    "issuedAtUnixNanos", "expiresAtUnixNanos")
_DIRECTORIES = ("keys", "private", "keys/activation", "private/activation-signing",
    "private/activation-encryption")


def require(value):
    if not value:
        raise ValueError("local activation key provisioning refused")


def roster():
    """Return fresh fixed metadata, not mutable caller-selected purposes."""
    signing = tuple(dict(family="activation-signing", keyType="Ed25519", purpose=name,
        keyId="local-activation-" + name + "-v1",
        publicPath="keys/activation/" + name + ".pub",
        privatePath="private/activation-signing/" + name + ".seed") for name in SIGNING_PURPOSES)
    encryption = tuple(dict(family="activation-encryption", keyType="raw32", purpose=name,
        keyId="local-activation-" + name + "-v1",
        privatePath="private/activation-encryption/" + name + ".key") for name in ENCRYPTION_PURPOSES)
    return signing + encryption


def _directory(value):
    require(type(value) is dict and set(value) == {"device", "inode"})
    for field, minimum in (("device", 0), ("inode", 1)):
        require(type(value[field]) is int and minimum <= value[field] < 2**64)


def _priors(originals):
    require(type(originals) is tuple and len(originals) == len(PRIOR_FIELDS))
    pilot, audit, enrollment, chain, startup = originals
    # These actual existing validators check every canonical byte commitment,
    # purpose, SPKI, prior-inventory link, directory separation and public key.
    first, _ = prior._pilot_inventory(pilot)
    second, _ = prior.genesis_audit_inventory(audit, pilot)
    third, _ = prior.enrollment_inventory(enrollment, pilot, audit)
    fourth, _ = prior.chain_inventory(chain, pilot, audit, enrollment)
    fifth, keys = prior.startup_inventory(startup, pilot, audit, enrollment, chain)
    require(len(keys) == 37)
    directories = tuple((value["directory"]["device"], value["directory"]["inode"])
        for value in (first, second, third, fourth, fifth))
    pins = {name.removesuffix("Original") + "Sha256": trust.sha(raw.encode("ascii"))
        for name, raw in zip(PRIOR_FIELDS, originals, strict=True)}
    return directories, frozenset(keys), pins


def approval(raw):
    selected = trust.document(raw, MAX_APPROVAL)
    require(set(selected) == {"schema", "purpose", "directory", *_CLOCK_FIELDS, *PRIOR_FIELDS}
        and selected["schema"] == APPROVAL_SCHEMA and selected["purpose"] == PURPOSE)
    _directory(selected["directory"])
    trust.spec._require_digest(selected["bootIdDigest"], name="activation key boot")
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"),
            ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        require(type(selected[start]) is type(selected[end]) is int
            and 0 < selected[start] < selected[end] < 2**63
            and selected[end] - selected[start] <= trust.MAX_OPERATION_NS)
    directories, _keys, _pins = _priors(tuple(selected[name] for name in PRIOR_FIELDS))
    require((selected["directory"]["device"], selected["directory"]["inode"]) not in directories)
    return selected


def _public_record(row):
    if row["keyType"] == "Ed25519":
        return dict(keyType="Ed25519", publicKeyBase64Url=row["publicKeyBase64Url"])
    return dict(keyType="raw32", keySha256=row["keySha256"], byteCount=32)


def inventory(raw, *, prior_originals):
    """Validate public creation facts only, never custody, trust or a grant."""
    directories, old_keys, pins = _priors(prior_originals)
    value = trust.document(raw, MAX_PUBLIC)
    require(set(value) == {"schema", "approvalSha256", "directory", "publicRosterSha256",
        "keys", "claims", *pins} and value["schema"] == INVENTORY_SCHEMA
        and value["claims"] == CLAIMS and all(value[name] == pin for name, pin in pins.items()))
    _directory(value["directory"])
    require((value["directory"]["device"], value["directory"]["inode"]) not in directories)
    for name in ("approvalSha256", "publicRosterSha256"):
        trust.spec._require_digest(value[name], name="activation public inventory pin")
    require(type(value["keys"]) is list and len(value["keys"]) == 15)
    seen = {trust.sha(key) for key in old_keys}
    for row, expected in zip(value["keys"], roster(), strict=True):
        extra = ({"publicKeyBase64Url", "publicKeySha256", "publicKeySpkiSha256"}
            if expected["keyType"] == "Ed25519" else {"byteCount", "keySha256"})
        require(type(row) is dict and set(row) == set(expected) | extra
            and all(row[name] == item for name, item in expected.items()))
        if expected["keyType"] == "Ed25519":
            public = trust.spec.strict_base64url_decode(row["publicKeyBase64Url"],
                name="activation public key", decoded_size=32)
            digest = trust.sha(public)
            require(row["publicKeySha256"] == digest and row["publicKeySpkiSha256"] == trust.sha(
                Ed25519PublicKey.from_public_bytes(public).public_bytes(serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)))
        else:
            require(type(row["byteCount"]) is int and row["byteCount"] == 32)
            digest = row["keySha256"]
            trust.spec._require_digest(digest, name="raw encryption-key commitment")
        require(digest not in seen)
        seen.add(digest)
    public = {row["purpose"]: _public_record(row) for row in value["keys"]}
    require(value["publicRosterSha256"] == trust.sha(trust.spec.canonical_json_bytes(public)))
    return value


class LocalActivationKeyProvisionerError(RuntimeError):
    def __init__(self, owner):
        super().__init__("activation key provisioning failed; partial files and actual owner retained; no retry")
        self.owner = owner


class LocalActivationKeyProvisioner:
    """Own the supplied FDs and every created handle; expose public bytes only."""

    def __init__(self, *, approval_fd, approval_sha256, directory_fd):
        self.handles, self.identities, self.directories, self.completed = [], {}, {}, []
        self.closed = self.uncertain = self.used = False
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        self._original = None
        try:
            io._process()
            require(type(approval_fd) is type(directory_fd) is int and 3 <= approval_fd < 2**31
                and 3 <= directory_fd < 2**31 and approval_fd != directory_fd)
            with prior._owning():
                for descriptor in (approval_fd, directory_fd):
                    self._hold(descriptor)
                    os.set_inheritable(descriptor, False)
            raw = io.read_public(approval_fd, MAX_APPROVAL)
            trust.spec._require_digest(approval_sha256, name="activation key approval")
            require(trust.sha(raw) == approval_sha256)
            selected = approval(raw)
            require(trust.empty_directory(directory_fd) == selected["directory"])
            originals = tuple(selected[name] for name in PRIOR_FIELDS)
            self._original = (approval_fd, directory_fd, approval_sha256, raw,
                tuple(selected[name] for name in _CLOCK_FIELDS), originals,
                (selected["directory"]["device"], selected["directory"]["inode"]))
            self.directories[""] = directory_fd, prior._directory(os.fstat(directory_fd))
            self.previous_boot, self.previous_unix = selected["issuedAtBoottimeNs"], selected["issuedAtUnixNanos"]
            self.check()
        except BaseException as error:
            raise LocalActivationKeyProvisionerError(self) from error

    @property
    def deadline_boottime_ns(self):
        return self._original[4][2]

    def _origin(self):
        io._process()
        require(os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment
            and not self.uncertain)

    def check_clock(self):
        self._origin()
        require(self._original is not None)
        boot_id, _start_boot, end_boot, _start_unix, end_unix = self._original[4]
        require(trust._boot() == boot_id)
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.previous_boot <= boot < end_boot and self.previous_unix <= unix < end_unix)
        self.previous_boot, self.previous_unix = boot, unix

    def check(self):
        self.check_clock()
        require(not self.closed)
        approval_fd, directory_fd, _pin, raw, _clock, _priors_raw, directory = self._original
        require(io.read_public(approval_fd, MAX_APPROVAL) == raw
            and prior._directory(os.fstat(directory_fd))[:2] == directory)
        for fd, identity in self.identities.items():
            value = os.fstat(fd)
            require((value.st_dev, value.st_ino) == identity and not os.get_inheritable(fd))
        for path, (fd, identity) in self.directories.items():
            require(prior._directory(os.fstat(fd)) == identity)
            if path:
                parent, leaf = path.rsplit("/", 1) if "/" in path else ("", path)
                require(prior._directory(os.stat(leaf, dir_fd=self.directories[parent][0],
                    follow_symlinks=False)) == identity)
        for parent, name, fd, identity, kind, expected in self.completed:
            require(io._identity(os.fstat(fd)) == identity
                and io._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
            if kind == "public":
                require(os.pread(fd, len(expected) + 1, 0) == expected)
            else:
                secret = os.pread(fd, 33, 0)
                try:
                    require(len(secret) == 32)
                    if kind == "Ed25519":
                        key = Ed25519PrivateKey.from_private_bytes(secret)
                        try:
                            require(key.public_key().public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw) == expected)
                        finally:
                            del key
                    else:
                        require(kind == "raw32" and trust.sha(secret) == expected)
                finally:
                    del secret
        self.check_clock()

    # Reuse only descriptor ownership and protected fixed-directory creation;
    # the old schema selector, secret codec and producer are never invoked.
    _hold = prior.LocalKeyProvisioner._hold
    _mkdir = prior.LocalKeyProvisioner._mkdir

    def _publish(self, path, raw, *, kind="public", expected=None):
        rows = roster()
        private = {row["privatePath"]: row["keyType"] for row in rows}
        public = {row["publicPath"] for row in rows if "publicPath" in row} | {
            "public-roster.json", "inventory.json"}
        require(type(raw) is bytes and 0 < len(raw) <= MAX_PUBLIC)
        if path in private:
            require(kind == private[path] and len(raw) == 32)
            if kind == "Ed25519":
                require(type(expected) is bytes and len(expected) == 32)
            else:
                require(expected == trust.sha(raw))
        else:
            require(path in public and kind == "public" and expected is None)
            expected = raw
        self.check()
        parent, name = path.rsplit("/", 1) if "/" in path else ("", path)
        parent_fd = self.directories[parent][0]
        pending = "." + name + ".pending"
        with prior._owning():
            fd = self._hold(os.open(pending, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                | os.O_CLOEXEC, 0o600, dir_fd=parent_fd))
        offset = 0
        while offset < len(raw):
            self.check()
            count = os.write(fd, memoryview(raw)[offset:offset + 65536])
            require(count > 0)
            offset += count
        os.fchmod(fd, 0o400)
        os.fsync(fd)
        require(os.pread(fd, len(raw) + 1, 0) == raw)
        self.check()
        if prior._LIBC.renameat2(parent_fd, os.fsencode(pending), parent_fd, os.fsencode(name), 1) != 0:
            raise OSError(ctypes.get_errno(), "fixed no-replace activation key publication refused")
        os.fsync(parent_fd)
        identity = io._identity(os.fstat(fd))
        require(stat.S_ISREG(identity[2]) and stat.S_IMODE(identity[2]) == 0o400
            and identity[3] == identity[4] == 0 and identity[5] == 1)
        self.completed.append((parent_fd, name, fd, identity, kind, expected))
        self.check()

    def run(self):
        try:
            require(not self.used and not self.closed)
            self.used = True
            self.check()
            require(trust.empty_directory(self._original[1]) == dict(zip(("device", "inode"), self._original[6])))
            _directories, old_keys, pins = _priors(self._original[5])
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            require(prior._LIBC.prctl(4, 0, 0, 0, 0) == 0 and prior._LIBC.prctl(3, 0, 0, 0, 0) == 0)
            for path in _DIRECTORIES:
                self._mkdir(path)
            # Private seed commitments stay only in this call, never inventory.
            seen_public = set(old_keys)
            seen_raw = {trust.sha(key) for key in old_keys}
            rows = []
            for selected in roster():
                self.check()
                secret = private = None
                try:
                    if selected["keyType"] == "Ed25519":
                        private = Ed25519PrivateKey.generate()
                        public = private.public_key().public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)
                        secret = private.private_bytes(serialization.Encoding.Raw,
                            serialization.PrivateFormat.Raw, serialization.NoEncryption())
                        require(public not in seen_public and trust.sha(public) not in seen_raw
                            and trust.sha(secret) not in seen_raw and secret != public)
                        seen_public.add(public)
                        seen_raw.update((trust.sha(public), trust.sha(secret)))
                        self._publish(selected["privatePath"], secret, kind="Ed25519", expected=public)
                        self._publish(selected["publicPath"], public)
                        rows.append(dict(selected, publicKeyBase64Url=trust.spec.strict_base64url_encode(public),
                            publicKeySha256=trust.sha(public), publicKeySpkiSha256=trust.sha(
                                private.public_key().public_bytes(serialization.Encoding.DER,
                                    serialization.PublicFormat.SubjectPublicKeyInfo))))
                    else:
                        secret = os.urandom(32)
                        require(type(secret) is bytes and len(secret) == 32 and trust.sha(secret) not in seen_raw)
                        digest = trust.sha(secret)
                        seen_raw.add(digest)
                        self._publish(selected["privatePath"], secret, kind="raw32", expected=digest)
                        rows.append(dict(selected, byteCount=32, keySha256=digest))
                finally:
                    del secret, private
                self.check()
            public_raw = trust.spec.canonical_json_bytes({row["purpose"]: _public_record(row) for row in rows})
            self._publish("public-roster.json", public_raw)
            value = dict(schema=INVENTORY_SCHEMA, approvalSha256=self._original[2],
                directory=dict(zip(("device", "inode"), self._original[6])),
                publicRosterSha256=trust.sha(public_raw), keys=rows, claims=CLAIMS, **pins)
            raw = trust.spec.canonical_json_bytes(value)
            require(inventory(raw, prior_originals=self._original[5]) == value)
            self._publish("inventory.json", raw)  # Last durable completion marker.
            self.check()
            return raw
        except BaseException as error:
            raise LocalActivationKeyProvisionerError(self) from error

    def close(self):
        try:
            prior.LocalKeyProvisioner.close(self)
        except BaseException as error:
            raise LocalActivationKeyProvisionerError(self) from error
