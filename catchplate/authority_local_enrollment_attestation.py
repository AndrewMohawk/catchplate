"""Observe selected static signer material and issue the existing local receipt.

This root-delegated assertion measures actual retained files, public key,
activated listener and empty replay directory. It is not a live-process
attestation, complete import/ELF closure, installed authority package, TEE or
independent-administrator claim. No future PID is selected. The actual fixed
signer entrypoint later independently admits its bootstrap, key and handles.
The existing receipt interval limits that entire signer lifetime, not just
bootstrap, and may never be renewed by this owner.
"""
from __future__ import annotations

import hashlib
import os
import socket
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_local_enrollment_configuration as configuration
from catchplate import registration_evidence_signer_entrypoint as entrypoint

keys, signer, io, spec = configuration.keys, configuration.signer, configuration.io, configuration.spec
canonical, document, sha = configuration.canonical, configuration.document, configuration.sha
SCHEMA = "catchplate.authorityTrustedHostLocalEnrollmentSignerAttestationApproval/v1"
PURPOSE = "attest-observed-static-local-registration-signer"
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 128, 64 * 1024 * 1024, 512 * 1024 * 1024
FIELDS = frozenset({"schema", "purpose", "pilotKeyInventoryOriginal", "genesisAuditKeyInventoryOriginal",
    "enrollmentKeyInventoryOriginal", "runtimeFiles", "listener", "replay", "bootIdDigest",
    "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})
REQUIRED_MODULES = frozenset({"registration_evidence_signer_launcher.py", "registration_evidence_signer_entrypoint.py",
    "registration_evidence_signer_runner.py", "registration_evidence_signer_startup.py",
    "registration_evidence_signer_bootstrap.py", "authority_webauthn_registration_signer_service.py"})
NATIVE_PATHS = frozenset({"/usr/local/bin/python3.11", "/usr/local/lib/libpython3.11.so.1.0",
    "/runtime/python/bin/python3", "/runtime/python/lib/libpython3.11.so.1.0"})
FILE_ROOTS = ("/run/source/catchplate/", "/app/catchplate/")


def require(value):
    if not value:
        raise ValueError("local registration signer attestation refused")


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def approval(raw):
    value = document(raw, io.MAX_PUBLIC)
    require(set(value) == FIELDS and value["schema"] == SCHEMA and value["purpose"] == PURPOSE)
    keys._pilot_inventory(value["pilotKeyInventoryOriginal"])
    keys.enrollment_inventory(value["enrollmentKeyInventoryOriginal"], value["pilotKeyInventoryOriginal"],
        value["genesisAuditKeyInventoryOriginal"])
    spec._require_digest(value["bootIdDigest"], name="attestation boot")
    for first, last in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        require(type(value[first]) is type(value[last]) is int and 0 < value[first] < value[last] < 2**63
            and value[last] - value[first] <= signer.MAX_RECEIPT_AGE_NS)
    for name in ("listener", "replay"):
        item = value[name]
        require(type(item) is dict and set(item) == ({"descriptor", "path"} if name == "listener" else {"device", "inode"}))
        for identity in (item["descriptor"], item["path"]) if name == "listener" else (item,):
            require(type(identity) is dict and set(identity) == {"device", "inode"})
            for field, minimum in (("device", 0), ("inode", 1)):
                require(type(identity[field]) is int and minimum <= identity[field] < 2**64)
    rows = value["runtimeFiles"]
    require(type(rows) is list and 3 <= len(rows) <= MAX_FILES)
    paths, total = [], 0
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "kind", "bytes", "sha256"})
        path = spec._require_runtime_path(row["path"], name="observed static file")
        require(row["kind"] in ("python", "native") and (
            row["kind"] == "native" and path in NATIVE_PATHS or row["kind"] == "python"
            and any(path.startswith(prefix) for prefix in FILE_ROOTS) and path.endswith(".py")))
        require(type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_FILE_BYTES)
        total += row["bytes"]
        spec._require_digest(row["sha256"], name="observed file pin")
        paths.append(path)
    require(paths == sorted(set(paths)) and total <= MAX_TOTAL_BYTES
        and REQUIRED_MODULES <= {path.rsplit("/", 1)[-1] for path in paths}
        and any(path in paths for path in ("/usr/local/bin/python3.11", "/runtime/python/bin/python3"))
        and any(path in paths for path in ("/usr/local/lib/libpython3.11.so.1.0", "/runtime/python/lib/libpython3.11.so.1.0")))
    return value


class EnrollmentAttestationError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local registration signer attestation failed; actual partial owner retained")
        self.owner = owner


class LocalEnrollmentSignerAttestationIssuer:
    """Borrow supplied descriptors; retain every actually opened static handle."""

    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd, signer_public_key_fd, listener_fd, replay_directory_fd):
        self.handles, self.files, self.directories, self.links = [], [], [], []
        self.handle_identities = {}
        self.closed = self.uncertain = self.used = False
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        try:
            io._process()
            from catchplate import config
            require(not config.PRODUCTION_IMAGE and os.environ.get("CATCHPLATE_PROCESS_MODE") == "metadata-bootstrap"
                and os.environ.get("CATCHPLATE_RELEASE_CHANNEL") == "dev")
            borrowed = (approval_fd, signing_key_fd, signer_public_key_fd, listener_fd, replay_directory_fd)
            require(all(type(fd) is int and 3 <= fd < 2**31 for fd in borrowed) and len(set(borrowed)) == len(borrowed))
            self.borrowed = {fd: _directory_identity(os.fstat(fd)) for fd in borrowed}
            require(len({identity[:2] for identity in self.borrowed.values()}) == len(borrowed))
            self.approval_fd, self.key_fd, self.public_fd = approval_fd, signing_key_fd, signer_public_key_fd
            self.listener_fd, self.replay_fd = listener_fd, replay_directory_fd
            self.raw = io.read_public(approval_fd, io.MAX_PUBLIC)
            require(sha(self.raw) == approval_sha256)
            self.selected = approval(self.raw)
            self.previous_boot, self.previous_unix = self.selected["issuedAtBoottimeNs"], self.selected["issuedAtUnixNanos"]
            self.public = io.read_public(signer_public_key_fd, 32)
            inventory, _ = keys.enrollment_inventory(self.selected["enrollmentKeyInventoryOriginal"],
                self.selected["pilotKeyInventoryOriginal"], self.selected["genesisAuditKeyInventoryOriginal"])
            self.signer_pin = next(row for row in inventory["keys"] if row["purpose"] == "registration-evidence")
            require(spec.strict_base64url_encode(self.public) == self.signer_pin["publicKeyBase64Url"])
            # Decode and retain the exact real listener, never a claimed socket DTO.
            with keys._owning():
                self.listener = socket.fromfd(listener_fd, socket.AF_UNIX, socket.SOCK_STREAM)
                self._hold(self.listener)
            self.listener_parent, self.listener_leaf = self._parent(entrypoint.LISTENER_PATH)
            self.replay_parent, self.replay_leaf = self._parent(entrypoint.REPLAY_PATH)
            self.check()
            for row in self.selected["runtimeFiles"]:
                parent, leaf = self._parent(row["path"])
                with keys._owning():
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                    self._hold(fd)
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1
                    and not stat.S_IMODE(before.st_mode) & 0o022 and before.st_size == row["bytes"]
                    and (not stat.S_IMODE(before.st_mode) & 0o222 or os.fstatvfs(fd).f_flag & os.ST_RDONLY))
                identity = io._identity(before)
                self.files.append((fd, parent, leaf, identity, row))
                require(self._hash(fd, row["bytes"]) == row["sha256"])
                require(os.pread(fd, 4, 0) == b"\x7fELF" if row["kind"] == "native" else b"\0" not in os.pread(fd, row["bytes"], 0))
                self.check()
            self.check()
        except BaseException as error:
            raise EnrollmentAttestationError(self) from error

    def _hold(self, handle):
        self.handles.append(handle)
        fd = handle.fileno() if isinstance(handle, socket.socket) else handle
        info = os.fstat(fd)
        self.handle_identities[fd] = (info.st_dev, info.st_ino)

    def _parent(self, path):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        with keys._owning():
            fd = os.open("/", flags); self._hold(fd)
        parts = path.split("/")[1:]
        for part in parts[:-1]:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
            self.directories.append((fd, _directory_identity(info)))
            with keys._owning():
                child = os.open(part, flags, dir_fd=fd); self._hold(child)
            self.links.append((fd, part, child))
            fd = child
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022)
        self.directories.append((fd, _directory_identity(info)))
        return fd, parts[-1]

    def _hash(self, fd, size):
        digest, offset = hashlib.sha256(), 0
        while offset < size:
            self.check()
            raw = os.pread(fd, min(65536, size - offset), offset)
            require(raw); digest.update(raw); offset += len(raw)
        require(not os.pread(fd, 1, size))
        return "sha256:" + digest.hexdigest()

    def _clock(self):
        io._process()
        require(os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment and not self.uncertain
            and configuration.configuration.launcher._boot_identity_digest() == self.selected["bootIdDigest"])
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.previous_boot <= boot < self.selected["deadlineBoottimeNs"]
            and self.previous_unix <= unix < self.selected["expiresAtUnixNanos"])
        self.previous_boot, self.previous_unix = boot, unix

    def check(self):
        self._clock(); require(not self.closed)
        require(io.read_public(self.approval_fd, io.MAX_PUBLIC) == self.raw and io.read_public(self.public_fd, 32) == self.public)
        for fd, identity in self.borrowed.items(): require(_directory_identity(os.fstat(fd)) == identity)
        for fd, identity in self.directories: require(_directory_identity(os.fstat(fd)) == identity)
        for parent, leaf, child in self.links:
            require(_directory_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == _directory_identity(os.fstat(child)))
        for fd, parent, leaf, identity, _row in self.files:
            require(io._identity(os.fstat(fd)) == identity
                and io._identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) == identity)
        listener = self.listener
        current = os.fstat(self.listener_fd)
        named = os.stat(self.listener_leaf, dir_fd=self.listener_parent, follow_symlinks=False)
        require(stat.S_ISSOCK(current.st_mode) and dict(device=current.st_dev, inode=current.st_ino) == self.selected["listener"]["descriptor"]
            and stat.S_ISSOCK(named.st_mode) and named.st_nlink == 1 and stat.S_IMODE(named.st_mode) == 0o660
            and (named.st_uid, named.st_gid) == (entrypoint.SIGNER_UID, entrypoint.PEER_GID)
            and dict(device=named.st_dev, inode=named.st_ino) == self.selected["listener"]["path"]
            and listener.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
            and listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
            and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
            and listener.getsockname() == entrypoint.LISTENER_PATH and not os.get_blocking(self.listener_fd))
        replay = os.fstat(self.replay_fd)
        require(stat.S_ISDIR(replay.st_mode) and (replay.st_uid, replay.st_gid) == (entrypoint.SIGNER_UID, entrypoint.SIGNER_GID)
            and stat.S_IMODE(replay.st_mode) == 0o700 and not os.listdir(self.replay_fd)
            and dict(device=replay.st_dev, inode=replay.st_ino) == self.selected["replay"]
            and _directory_identity(os.stat(self.replay_leaf, dir_fd=self.replay_parent, follow_symlinks=False)) == _directory_identity(replay))

    def issue(self):
        try:
            require(not self.used); self.used = True
            self.check()
            rows = []
            for fd, _parent, _leaf, identity, row in self.files:
                require(self._hash(fd, row["bytes"]) == row["sha256"])
                rows.append(dict(row, device=identity[0], inode=identity[1], mode=stat.S_IMODE(identity[2]),
                    uid=identity[3], gid=identity[4], readOnlyFilesystem=bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)))
            closure = dict(meaning="observed-selected-runtime-files-not-complete-import-closure", files=rows,
                sourceRevision=signer.authority.SOURCE_REVISION)
            closure_digest = spec.domain_digest("catchplate.localRegistrationSignerSelectedClosure/v1", canonical(closure))
            measurement = dict(meaning="observed-static-local-registration-signer-measurement-not-live-process",
                role=signer.ROLE, runtimeClosureDigest=closure_digest, signingSpkiDigest=self.signer_pin["publicKeySpkiSha256"])
            measurement_digest = spec.domain_digest("catchplate.localRegistrationSignerSelectedMeasurement/v1", canonical(measurement))
            session = dict(meaning="observed-static-local-registration-session-not-live-process",
                bootIdDigest=self.selected["bootIdDigest"], listener=self.selected["listener"], replay=self.selected["replay"],
                runtimeClosureDigest=closure_digest, measurementDigest=measurement_digest,
                signingSpkiDigest=self.signer_pin["publicKeySpkiSha256"],
                issuedAtEpochNs=self.selected["issuedAtUnixNanos"], expiresAtEpochNs=self.selected["expiresAtUnixNanos"])
            self.observation_original = canonical(dict(closure=closure, measurement=measurement, session=session,
                liveProcessObserved=False, completeImportClosure=False, authorityPackageInstalled=False))
            claims = dict(schema=signer.ATTESTATION_PAYLOAD_SCHEMA, sourceRevision=signer.authority.SOURCE_REVISION,
                role=signer.ROLE, processMode=signer.PROCESS_MODE,
                sessionIdentityDigest=spec.domain_digest("catchplate.localRegistrationSignerStaticSession/v1", canonical(session)),
                measurementDigest=measurement_digest, runtimeClosureDigest=closure_digest,
                signingSpkiDigest=self.signer_pin["publicKeySpkiSha256"], issuedAtEpochNs=self.selected["issuedAtUnixNanos"],
                expiresAtEpochNs=self.selected["expiresAtUnixNanos"], trustMode="trusted-host-local", coLocated=True,
                hardwareBacked=False, nativeStageZero=False, hsmBackedKeys=False, teeVerified=False, externalWitnessVerified=False)
            pilot, _ = keys._pilot_inventory(self.selected["pilotKeyInventoryOriginal"])
            root_encoded = next(row["publicKeyBase64Url"] for row in pilot["keys"] if row["family"] == "configuration")
            root = Ed25519PublicKey.from_public_bytes(configuration.configuration._public(root_encoded))
            self.check()
            private = io.signing_key(self.key_fd)
            try:
                require(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    == configuration.configuration._public(root_encoded))
                result = signer._produce_attestation_on_work(claims=claims, root_private_key=private, root_public_key=root,
                    work=configuration._ValidationWork(configuration.QueryReadValidationLimits(max_hashes=32,
                        max_input_bytes=2 * 1024 * 1024, max_json_nodes=16384)))
            finally: del private
            self.check()
            return result
        except BaseException as error:
            raise EnrollmentAttestationError(self) from error

    def close(self):
        if self.closed: return
        require(os.getpid() == self.pid and not self.uncertain)
        try:
            with keys._owning():
                while self.handles:
                    handle = self.handles[-1]
                    fd = handle.fileno() if isinstance(handle, socket.socket) else handle
                    require(fd in self.handle_identities)
                    info = os.fstat(fd)
                    require((info.st_dev, info.st_ino) == self.handle_identities[fd])
                    self.uncertain = True
                    handle.close() if isinstance(handle, socket.socket) else os.close(handle)
                    self.handles.pop(); self.handle_identities.pop(fd); self.uncertain = False
                self.closed = True
        except BaseException as error:
            self.uncertain = True
            raise EnrollmentAttestationError(self) from error

    def publish(self):
        raw = self.issue()
        self.check()
        self.close()
        self._clock()
        io.write_public(raw, deadline_boottime_ns=self.selected["deadlineBoottimeNs"], check=self._clock)
