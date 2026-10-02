"""One actual immutable trusted-host-local package installation.

An independently provisioned named trust state and authorized signing key are
inputs, never generated or advanced here. Failure preserves all partial files;
there is no retry, rollback, unlink, activation or production-profile fallback.
Kernel/filesystem stalls require an independent operator-owned watchdog.
"""
from __future__ import annotations

import array
import contextlib
import ctypes
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import signal
import stat
import struct
import threading
import time

from cryptography.hazmat.primitives import serialization
from scripts.authority import atomic_provisioner_contract as contract
from scripts.authority import native_pilot_authority_io as protected
from serverware import authority_artifact_spec as artifact

CONFIGURATION_SCHEMA = "serverware.authorityTrustedHostLocalInstallation/v1"
MAX_CONFIGURATION = 16384
TRUST_NAME = "trust-state.json"
MAX_SECONDS = 3600
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_IMMUTABLE = 0x10
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long
_LIBC.renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
_TOKEN, _LIVE = object(), None


class LocalInstallError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local installation refused; partial installation retained; no automatic retry or cleanup")
        self.owner = owner


def _require(value):
    if not value:
        raise ValueError("local installation contract refused")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _document(raw, maximum=contract.MAX_DOCUMENT_BYTES):
    def pairs(rows):
        result = {}
        for key, value in rows:
            _require(key not in result); result[key] = value
        return result
    def invalid(_value):
        raise ValueError("noninteger JSON refused")
    _require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    _require(type(value) is dict and artifact.canonical_json_bytes(value) == raw)
    return value


def configuration(raw):
    value = _document(raw, MAX_CONFIGURATION)
    _require(set(value) == {"schema", "destination", "trustStateSha256", "packageSha256",
        "verificationReceiptSha256", "keyId", "executorMeasurementDigest", "requestId", "transitionId",
        "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
        and value["schema"] == CONFIGURATION_SCHEMA)
    destination = value["destination"]
    _require(type(destination) is dict and set(destination) == {"path", "device", "inode"})
    path = contract._runtime_path(destination["path"], name="destination")
    _require(path not in {"/", "/etc", "/usr", "/var", "/runtime", "/home"}
        and 1 <= len(PurePosixPath(path).parts) - 1 <= 16)
    for key, minimum in (("device", 0), ("inode", 1)):
        contract._integer(destination[key], name=key, minimum=minimum, maximum=2**64 - 1)
    for key in ("trustStateSha256", "packageSha256", "verificationReceiptSha256", "executorMeasurementDigest", "bootIdDigest"):
        contract._digest(value[key], name=key)
    for key in ("keyId", "requestId", "transitionId"):
        contract._identifier(value[key], name=key)
    for key in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        contract._integer(value[key], name=key, minimum=1, maximum=2**63 - 1)
    _require(0 < value["deadlineBoottimeNs"] - value["issuedAtBoottimeNs"] <= MAX_SECONDS * 10**9
        and 0 < value["expiresAtUnixNanos"] - value["issuedAtUnixNanos"] <= MAX_SECONDS * 10**9)
    return value


def _boot():
    with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
        raw = stream.read(128).strip()
    _require(len(raw) == 36 and all(character in b"0123456789abcdef-" for character in raw))
    return artifact.domain_digest("serverware.policyAuthorityBootIdentity/v1", raw)


def _timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unix_limit(value):
    return int(contract._timestamp(value, name="original expiry").timestamp()) * 10**9


@contextlib.contextmanager
def _owning():
    before = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, before)


def _generation(fd):
    value = array.array("l", [0])
    fcntl.ioctl(fd, 0x80087601, value, True)
    _require(0 < value[0] < 2**64)
    return value[0]


def _flags(fd):
    value = array.array("l", [0])
    fcntl.ioctl(fd, 0x80086601, value, True)
    return value[0]


def _immutable(fd):
    flags = array.array("l", [_flags(fd) | _IMMUTABLE])
    fcntl.ioctl(fd, 0x40086602, flags, True)
    _require(_flags(fd) & _IMMUTABLE)


def _frozen(fd):
    # A readonly ancestor mount does not imply a same-device bind child is readonly.
    _require(os.fstatvfs(fd).f_flag & os.ST_RDONLY or _flags(fd) & _IMMUTABLE)


def _verity(fd):
    # Linux fsverity_enable_arg: SHA256, 4096-byte blocks, no salt/signature.
    enable = struct.pack("=IIIIQIIQ11Q", 1, 1, 4096, 0, 0, 0, 0, 0, *([0] * 11))
    _require(len(enable) == 128)
    fcntl.ioctl(fd, 0x40806685, enable)
    measured = bytearray(struct.pack("=HH64s", 0, 64, bytes(64)))
    fcntl.ioctl(fd, 0xC0046686, measured, True)
    algorithm, length, digest = struct.unpack("=HH64s", measured)
    _require(algorithm == 1 and length == 32)
    return "sha256:" + digest[:32].hex()


def _identity(fd):
    info = os.fstat(fd)
    return dict(device=info.st_dev, inode=info.st_ino, generation=_generation(fd),
        mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)


def _mount_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", "rt", encoding="ascii") as stream:
        rows = [line.split()[1] for line in stream.read(16384).splitlines() if line.startswith("mnt_id:")]
    _require(len(rows) == 1)
    return int(rows[0])


def _open_beneath(parent, name, flags, mode=0):
    contract._relative_path(name, name="relative installation path")
    how = struct.pack("=QQQ", flags, mode, 0x0E)  # BENEATH, NO_SYMLINKS, NO_MAGICLINKS.
    buffer = ctypes.create_string_buffer(how)
    fd = _LIBC.syscall(437, parent, name.encode("ascii"), buffer, len(how))
    if fd < 0:
        error = ctypes.get_errno(); raise OSError(error, os.strerror(error))
    return fd


def _rename(parent, source, target_parent, target):
    if _LIBC.renameat2(parent, source.encode("ascii"), target_parent, target.encode("ascii"), 1):
        error = ctypes.get_errno(); raise OSError(error, os.strerror(error))


class LocalAuthorityInstaller:
    def __init__(self, token):
        _require(token is _TOKEN)
        self.pid = os.getpid()
        self.handles, self.sources, self.links, self.directories = [], {}, [], {}
        self.value = self.plan = self.verified = self.state = self.receipt = None
        self.lock = self.root = self.source_root = self.key_fd = None
        self.closed = self.closing = self.failed = self.started = self.uncertain = False
        self.stage, self.published = "opening", False
        self.epoch_limit = 2**63 - 1
        self.last_boot, self.last_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()

    @classmethod
    def open(cls, *, configuration_fd, configuration_sha256, package_fd, package_sha256,
             verification_fd, verification_sha256, source_root_fd, signing_key_fd):
        global _LIVE
        _require(cls is LocalAuthorityInstaller and _LIVE is None)
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            fds = [configuration_fd, package_fd, verification_fd, source_root_fd, signing_key_fd]
            _require(all(type(fd) is int and 3 <= fd < 2**31 for fd in fds) and len(set(fds)) == len(fds))
            for name, fd, pin, limit in (("configuration", configuration_fd, configuration_sha256, MAX_CONFIGURATION),
                    ("package", package_fd, package_sha256, contract.MAX_DOCUMENT_BYTES),
                    ("verification", verification_fd, verification_sha256, contract.MAX_DOCUMENT_BYTES)):
                with _owning(): held = owner._hold(os.dup(fd))
                raw = protected.read_public(held, limit)
                _require(sha(raw) == pin)
                owner.sources[name] = held, protected._identity(os.fstat(held)), raw
            owner.value = configuration(owner.sources["configuration"][2])
            _require(owner.value["packageSha256"] == package_sha256 and owner.value["verificationReceiptSha256"] == verification_sha256)
            with _owning():
                owner.source_root = owner._hold(os.dup(source_root_fd))
                owner.key_fd = owner._hold(os.dup(signing_key_fd))
            protected._input(owner.key_fd, 32, private=True)
            _require(len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in owner.handles}) == len(owner.handles))
            _require(stat.S_ISDIR(os.fstat(owner.source_root).st_mode))
            owner.check()
            owner.root = owner._destination()
            _require((os.fstat(owner.root).st_dev, os.fstat(owner.root).st_ino) !=
                (os.fstat(owner.source_root).st_dev, os.fstat(owner.source_root).st_ino))
            owner.check()
            return owner
        except BaseException as error:
            owner.failed = True
            raise LocalInstallError(owner) from error

    def _origin(self):
        protected._process()
        _require(_LIVE is self and not self.closed and not self.closing and not self.uncertain
            and self.pid == os.getpid() and threading.current_thread() is threading.main_thread()
            and os.uname().machine == "x86_64" and ctypes.sizeof(ctypes.c_void_p) == 8)

    def _hold(self, fd):
        self.handles.append(fd)
        os.set_inheritable(fd, False)
        return fd

    def _drop(self, fd):
        _require(fd in self.handles)
        with _owning():
            self.uncertain = True
            os.close(fd)
            self.handles.remove(fd)
            self.uncertain = False

    def check(self):
        self._origin(); _require(not self.failed)
        now_boot, now_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        value = self.value
        _require(value is not None and value["bootIdDigest"] == _boot()
            and value["issuedAtBoottimeNs"] <= self.last_boot <= now_boot < value["deadlineBoottimeNs"]
            and value["issuedAtUnixNanos"] <= self.last_epoch <= now_epoch < min(value["expiresAtUnixNanos"], self.epoch_limit))
        self.last_boot, self.last_epoch = now_boot, now_epoch
        for fd, identity, raw in self.sources.values():
            _require(protected._identity(os.fstat(fd)) == identity)
        for parent, name, fd, identity in self.links:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            actual = os.fstat(fd)
            _require((info.st_dev, info.st_ino) == identity == (actual.st_dev, actual.st_ino)
                and actual.st_uid == actual.st_gid == 0 and not actual.st_mode & 0o022)
        if getattr(self, "source_identity", None) is not None:
            _require(_identity(self.source_root) == self.source_identity)
            _frozen(self.source_root)

    def _destination(self):
        with _owning(): current = self._hold(os.open("/", _READ | os.O_DIRECTORY))
        for name in PurePosixPath(self.value["destination"]["path"]).parts[1:]:
            self.check()
            with _owning(): fd = self._hold(_open_beneath(current, name, _READ | os.O_DIRECTORY))
            info = os.fstat(fd)
            _require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            self.links.append((current, name, fd, (info.st_dev, info.st_ino)))
            current = fd
        info = os.fstat(current); pin = self.value["destination"]
        _require((info.st_dev, info.st_ino) == (pin["device"], pin["inode"]) and stat.S_IMODE(info.st_mode) == 0o750)
        _identity(current)  # Fail before mutation when filesystem generations are unavailable.
        return current

    def _directory(self, parent, name, *, absent=False):
        self.check()
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            _require(not absent)
        with _owning(): fd = self._hold(_open_beneath(parent, name, _READ | os.O_DIRECTORY))
        info = os.fstat(fd)
        _require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_dev == os.fstat(self.root).st_dev)
        self.links.append((parent, name, fd, (info.st_dev, info.st_ino)))
        return fd

    def _publish(self, name, raw):
        self.check(); _require(0 < len(raw) <= contract.MAX_DOCUMENT_BYTES)
        parent = self.directories["receipts"]
        temporary = ".pending-" + name
        with _owning(): fd = self._hold(_open_beneath(parent, temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600))
        self._write(fd, raw)
        os.fchmod(fd, 0o400); os.fsync(fd)
        _require(os.pread(fd, len(raw) + 1, 0) == raw)
        self.check(); _rename(parent, temporary, parent, name); os.fsync(parent)
        _require((os.stat(name, dir_fd=parent, follow_symlinks=False).st_dev,
            os.stat(name, dir_fd=parent, follow_symlinks=False).st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino))
        self.check(); self._drop(fd)

    def _write(self, fd, raw):
        offset = 0
        while offset < len(raw):
            self.check()
            count = os.write(fd, raw[offset:offset + 1024 * 1024]); _require(count > 0); offset += count

    def _state(self, status, *, receipt_raw=None):
        prior = self.state
        if prior is None:
            value = dict(schema=contract.PROVISIONING_STATE_SCHEMA,
                stateId=artifact.domain_digest("serverware.authorityLocalInstallationState/v1", self.sources["configuration"][2]),
                revision=0, status=status, requestId=self.value["requestId"], transitionId=self.value["transitionId"],
                packageDigest=self.verified.package_digest, generationDigest=self.verified.generation_digest,
                planDigest=contract.provisioning_plan_digest(self.plan),
                sourceRootIdentityDigest=artifact.domain_digest("serverware.authorityProvisioningSourceIdentity/v1",
                    artifact.canonical_json_bytes(self.plan["sourceRoot"])), previousStateDigest=None,
                preparedAt=_timestamp(), publishedAt=None, terminalAt=None, publishedIdentityDigest=None,
                terminalReceiptDigest=None, terminalReceiptBytesBase64Url=None, abortReasonDigest=None)
        else:
            value = dict(prior, status=status, revision=prior["revision"] + 1, previousStateDigest=prior["recordDigest"])
            value.pop("recordDigest")
        if status == "Published":
            value.update(publishedAt=_timestamp(), publishedIdentityDigest=artifact.domain_digest(
                "serverware.authorityProvisionedGenerationIdentity/v1", artifact.canonical_json_bytes(_identity(self.tree))))
        if status == "Receipted":
            value.update(terminalAt=_timestamp(), terminalReceiptDigest=artifact.domain_digest(
                "serverware.authorityExactTerminalReceiptBytes/v1", receipt_raw),
                terminalReceiptBytesBase64Url=artifact.strict_base64url_encode(receipt_raw))
        value["recordDigest"] = artifact.domain_digest(contract.PROVISIONING_STATE_DIGEST_DOMAIN, artifact.canonical_json_bytes(value))
        contract.validate_provisioning_state(value)
        if prior is not None: contract.validate_provisioning_transition(prior, value)
        self._publish(self.name + f".state-{value['revision']}.json", artifact.canonical_json_bytes(value))
        self.state = value

    def _authenticate(self):
        self.check()
        with _owning(): fd = self._hold(_open_beneath(self.root, TRUST_NAME, _READ))
        raw = protected.read_public(fd, contract.MAX_DOCUMENT_BYTES)
        _require(sha(raw) == self.value["trustStateSha256"])
        self.sources["trust"] = fd, protected._identity(os.fstat(fd)), raw
        info = os.fstat(fd); self.links.append((self.root, TRUST_NAME, fd, (info.st_dev, info.st_ino)))
        self.verified = artifact.verify_signed_artifact_package(_document(self.sources["package"][2]),
            trust_state=_document(raw), validation_time=_timestamp())
        _require(self.verified.trust_mode == "trusted-host-local" and
            self.verified.stage_zero_contract == artifact.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA)
        self.verification = _document(self.sources["verification"][2])
        contract.verify_verification_receipt(self.verification, verified_package=self.verified,
            validation_time=_timestamp(), accepted_receipt_digests=())
        root = self.verified.package["bundle"]["stableSnapshotReceipt"]["payload"]["rootIdentity"]
        _require({**_identity(self.source_root), "mountId": _mount_id(self.source_root)} ==
            {key: value for key, value in root.items() if key != "runtimePath"})
        _require((os.stat(root["runtimePath"], follow_symlinks=False).st_dev,
            os.stat(root["runtimePath"], follow_symlinks=False).st_ino) == (root["device"], root["inode"]))
        self.source_identity = _identity(self.source_root)
        self._source_tree()
        self.plan = contract.build_provisioning_plan(self.verified, self.verification,
            validation_time=_timestamp(), source_root_fd=self.source_root,
            destination_root=self.value["destination"]["path"], owner_uid=0, owner_gid=0, trusted_host_local=True)
        signer = self.verified.require_key(self.value["keyId"], "artifact-provisioner", at=_timestamp())
        bundle = self.verified.package["bundle"]
        self.epoch_limit = min(_unix_limit(value) for value in (
            self.verified.package["generation"]["validUntil"], self.verification["validUntil"], signer.not_after,
            bundle["stableSnapshotReceipt"]["payload"]["expiresAt"], bundle["closureReceipt"]["payload"]["expiresAt"]))
        self.authorization = signer.authorization_digest
        # This is an actual local Python measurement, not a native/TEE attestation.
        measured = []
        for path in ("/proc/self/exe", __file__):
            with _owning(): held = self._hold(os.open(path, os.O_RDONLY | os.O_CLOEXEC))
            info = os.fstat(held); _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and 0 < info.st_size <= 256 * 1024 * 1024)
            digest = hashlib.sha256(); offset = 0
            while offset < info.st_size:
                self.check(); block = os.pread(held, min(1024 * 1024, info.st_size - offset), offset)
                _require(bool(block)); digest.update(block); offset += len(block)
            _require(protected._identity(os.fstat(held)) == protected._identity(info))
            measured.append("sha256:" + digest.hexdigest()); self._drop(held)
        self.measurement = artifact.domain_digest("serverware.authorityLocalInstallerMeasurement/v1", artifact.canonical_json_bytes(measured))
        _require(self.measurement == self.value["executorMeasurementDigest"])
        self.signer = protected.signing_key(self.key_fd)
        _require(self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == signer.public_key)
        self.check()

    def _source_tree(self):
        files = {row["path"] for row in self.verified.package["bundle"]["files"]}
        _require(all(len(PurePosixPath(path).parts) <= 64 for path in files))
        directories = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != "."}
        _require(len(directories) <= 64 * contract.MAX_FILES)
        seen_files, seen_directories = set(), set()
        def visit(fd, prefix):
            self.check()
            _frozen(fd)
            with os.scandir(fd) as entries:
                for entry in entries:
                    self.check(); path = prefix + entry.name
                    _require(path in files or path in directories)
                    with _owning(): child = self._hold(_open_beneath(fd, entry.name, _READ))
                    info = os.fstat(child)
                    _require(info.st_dev == self.source_identity["device"])
                    _frozen(child)
                    if path in files:
                        _require(stat.S_ISREG(info.st_mode)); seen_files.add(path)
                    else:
                        _require(stat.S_ISDIR(info.st_mode)); seen_directories.add(path); visit(child, path + "/")
                    self._drop(child)
        visit(self.source_root, "")
        _require(seen_files == files and seen_directories == directories)

    def _copy(self, entry, parents):
        self.check(); path = entry["path"]; parent_path, _, leaf = path.rpartition("/")
        if parent_path not in parents:
            parts = parent_path.split("/"); parent = self.tree
            for index, part in enumerate(parts):
                key = "/".join(parts[:index + 1])
                if key not in parents: parents[key] = self._directory(parent, part, absent=True)
                parent = parents[key]
        parent = parents[parent_path]
        with _owning():
            source = self._hold(_open_beneath(self.source_root, path, _READ))
            target = self._hold(_open_beneath(parent, leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600))
        before = os.fstat(source)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == entry["size"]
            and (stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid) == (entry["mode"], entry["uid"], entry["gid"]))
        _frozen(source)
        digest = hashlib.sha256(); offset = 0
        while offset < before.st_size:
            self.check(); raw = os.pread(source, min(1024 * 1024, before.st_size - offset), offset)
            _require(bool(raw)); digest.update(raw); self._write(target, raw); offset += len(raw)
        _require("sha256:" + digest.hexdigest() == entry["sourceSha256"]
            and protected._identity(os.fstat(source)) == protected._identity(before))
        _frozen(source)
        os.fchown(target, entry["uid"], entry["gid"]); os.fchmod(target, entry["mode"]); os.fsync(target)
        self._drop(target); self._drop(source)
        with _owning(): target = self._hold(_open_beneath(parent, leaf, _READ))
        readback = hashlib.sha256(); offset = 0
        while offset < entry["size"]:
            self.check(); raw = os.pread(target, min(1024 * 1024, entry["size"] - offset), offset)
            _require(bool(raw)); readback.update(raw); offset += len(raw)
        _require("sha256:" + readback.hexdigest() == entry["sourceSha256"] and os.fstat(target).st_size == entry["size"])
        verity = _verity(target); _immutable(target); os.fsync(target)
        info = os.fstat(target)
        row = dict(path=path, sha256=entry["sourceSha256"], fsVerityDigest=verity, **_identity(target),
            size=info.st_size, immutable=bool(_flags(target) & _IMMUTABLE))
        self._drop(target); self.check()
        return row

    def run(self):
        try:
            self.check(); _require(not self.started); self.started = True
            self.stage = "locking"
            with _owning():
                try: fd = _open_beneath(self.root, ".authority-generation.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
                except FileExistsError: fd = _open_beneath(self.root, ".authority-generation.lock", os.O_RDWR | os.O_CLOEXEC)
                self.lock = self._hold(fd)
            info = os.fstat(self.lock)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
            self.links.append((self.root, ".authority-generation.lock", self.lock, (info.st_dev, info.st_ino)))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB); os.fsync(self.root)
            self.stage = "authenticating"; self._authenticate()
            for name in (".incoming", "generations", "receipts"):
                self.directories[name] = self._directory(self.root, name)
            self.name = self.plan["destination"]["generationDirectory"]
            # No exact-retry or recovery shortcut: every prior attempt remains visible.
            for parent, name in ((self.directories["generations"], self.name),
                    (self.directories[".incoming"], self.name), (self.directories["receipts"], self.name + ".plan.json")):
                try: os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: pass
                else: raise ValueError("existing installation attempt refused")
            self._publish(self.name + ".plan.json", artifact.canonical_json_bytes(self.plan))
            self._state("Prepared")
            self.tree = self._directory(self.directories[".incoming"], self.name, absent=True)
            self.stage = "copying"
            parents = {"": self.tree}
            installed = [self._copy(entry, parents) for entry in self.plan["entries"]]
            self.stage = "freezing"
            for path in sorted(parents, key=lambda name: (name.count("/"), name), reverse=True):
                self.check(); fd = parents[path]
                os.fchmod(fd, 0o750); os.fsync(fd)
                if path: _immutable(fd); os.fsync(fd)
            self.check()
            _rename(self.directories[".incoming"], self.name, self.directories["generations"], self.name)
            self.published = True
            self.links = [row for row in self.links if row[2] != self.tree]
            info = os.fstat(self.tree)
            self.links.append((self.directories["generations"], self.name, self.tree, (info.st_dev, info.st_ino)))
            _immutable(self.tree); os.fsync(self.tree); os.fsync(self.directories["generations"]); os.fsync(self.directories[".incoming"])
            self.stage = "published"; self._state("Published")
            self.check()
            # Recheck current package/key/receipt validity immediately before signing.
            _require(protected.read_public(self.sources["trust"][0], contract.MAX_DOCUMENT_BYTES) == self.sources["trust"][2])
            artifact.verify_signed_artifact_package(dict(self.verified.package), trust_state=_document(self.sources["trust"][2]), validation_time=_timestamp())
            contract.verify_verification_receipt(self.verification, verified_package=self.verified, validation_time=_timestamp(), accepted_receipt_digests=())
            self.verified.require_key(self.value["keyId"], "artifact-provisioner", at=_timestamp())
            receipt = dict(schema=contract.LOCAL_PROVISIONING_RECEIPT_SCHEMA,
                planDigest=contract.provisioning_plan_digest(self.plan), planId=self.plan["planId"],
                generationDigest=self.plan["generationDigest"], generationSequence=self.plan["generationSequence"],
                destinationRootIdentity=_identity(self.root), generationDirectoryIdentity=_identity(self.tree),
                installedEntries=installed, stepContractDigest=self.plan["stepContractDigest"],
                completedSteps=list(contract.LOCAL_PROVISIONING_STEPS), activated=False, completedAt=_timestamp(),
                executorIdentity="trusted-host-local-python-installer", executorMeasurementDigest=self.measurement,
                signatureKeyId=self.value["keyId"], signatureAuthorizationDigest=self.authorization,
                signatureAlgorithm="Ed25519", signatureBase64Url="")
            receipt["signatureBase64Url"] = artifact.strict_base64url_encode(self.signer.sign(contract.provisioning_receipt_signature_message(receipt)))
            contract.verify_provisioning_receipt(receipt, plan=self.plan, verified_package=self.verified, validation_time=_timestamp())
            raw = artifact.canonical_json_bytes(receipt)
            self._publish(self.name + ".receipt.json", raw)
            self._state("Receipted", receipt_raw=raw)
            self.check(); self.receipt = raw
            self.stage = "receipted"
            self.close()
            _require(self.last_boot <= time.clock_gettime_ns(time.CLOCK_BOOTTIME) < self.value["deadlineBoottimeNs"]
                and self.last_epoch <= time.time_ns() < min(self.value["expiresAtUnixNanos"], self.epoch_limit))
            return dict(status="installed-not-activated", generationDigest=self.plan["generationDigest"],
                planSha256=sha(artifact.canonical_json_bytes(self.plan)), receiptSha256=sha(raw),
                generationDirectory=self.value["destination"]["path"] + "/generations/" + self.name)
        except BaseException as error:
            self.failed = True
            raise LocalInstallError(self) from error

    def close(self):
        if self.closed: return
        _require(not self.closing and not self.uncertain and self.pid == os.getpid())
        self.closing = True
        with _owning():
            while self.handles:
                fd = self.handles[-1]
                self.uncertain = True
                os.close(fd)
                self.handles.pop(); self.uncertain = False
        self.closed = True
