"""Commit only an actually installed local artifact generation zero.

This is cooperative local-root CAS, not hostile-root rollback resistance or
activation. The prior trust file is independently provisioned. Existing signed
evidence is consumed, never issued here. A fixed pending file preserves the old
state after RENAME_EXCHANGE; partial effects are never deleted, restored or
automatically retried. Kernel stalls require an external watchdog.
"""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import fcntl
import os
from pathlib import PurePosixPath
import stat
import struct
import time

from scripts.authority import atomic_provisioner_contract as contract
from scripts.authority import native_pilot_authority_io as io
from serverware import authority_artifact_spec as spec
from serverware import authority_local_artifact_witness as witness
from serverware import authority_local_install as install
from serverware.authority_local_limits import LOCAL_SETUP_MAX_NS

SCHEMA = "serverware.authorityTrustedHostLocalTrustCommitApproval/v1"
PURPOSE = "commit-installed-first-generation"
PENDING_NAME = ".trust-state-commit.pending"
MAX_APPROVAL, MAX_RETAINED = 8192, 128 * 1024 * 1024
MAX_OPERATION_NS = LOCAL_SETUP_MAX_NS
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
sha, document = install.sha, install._document


def require(value):
    if not value:
        raise ValueError("local artifact trust commit refused")


class LocalArtifactTrustCommitError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local trust commit refused; preserve partial state; no retry or activation")
        self.owner = owner


def approval(raw):
    value = document(raw, MAX_APPROVAL)
    pins = ("priorTrustSha256", "packageSha256", "verificationReceiptSha256", "planSha256",
            "provisioningReceiptSha256", "terminalStateSha256", "witnessHeadSha256", "bootIdDigest")
    clocks = ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos")
    require(set(value) == {"schema", "purpose", "destination", "witnessDirectory", "requestId", "transitionId", *pins, *clocks}
        and value["schema"] == SCHEMA and value["purpose"] == PURPOSE)
    for field in pins:
        spec._require_digest(value[field], name=field)
    for field in ("requestId", "transitionId"):
        contract._identifier(value[field], name=field)
    for field in ("destination", "witnessDirectory"):
        row = value[field]
        require(type(row) is dict and set(row) == ({"path", "device", "inode"} if field == "destination" else {"device", "inode"}))
        for key, minimum in (("device", 0), ("inode", 1)):
            require(type(row[key]) is int and minimum <= row[key] < 2**64)
    path = contract._runtime_path(value["destination"]["path"], name="destination")
    require(path not in {"/", "/etc", "/usr", "/var", "/runtime", "/home"}
        and 1 <= len(PurePosixPath(path).parts) - 1 <= 16)
    for field in clocks:
        require(type(value[field]) is int and 0 < value[field] < 2**63)
    for start, end in ((clocks[0], clocks[1]), (clocks[2], clocks[3])):
        require(0 < value[end] - value[start] <= MAX_OPERATION_NS)
    return value


def initial_state(raw):
    value = document(raw)
    state = spec.validate_trust_state(value)
    require(state["currentSequence"] == -1 and state["minimumRollbackSequence"] == 0
        and not state["acceptedPackageDigests"] and not state["acceptedGenerationDigests"]
        and not state["acceptedEvidenceDigests"] and not state["revokedKeyIds"])
    return value


def terminal_chain(states, *, plan, receipt_raw, request_id, transition_id, validation_time):
    """Validate literal durable installer states, not a synthesized completion."""
    require(type(states) is list and len(states) == 3)
    for index, value in enumerate(states):
        contract.validate_provisioning_state(value)
        require(value["revision"] == index and value["status"] == ("Prepared", "Published", "Receipted")[index]
            and value["requestId"] == request_id and value["transitionId"] == transition_id
            and value["packageDigest"] == plan["packageDigest"] and value["generationDigest"] == plan["generationDigest"]
            and value["planDigest"] == contract.provisioning_plan_digest(plan)
            and value["sourceRootIdentityDigest"] == spec.domain_digest(
                "serverware.authorityProvisioningSourceIdentity/v1", spec.canonical_json_bytes(plan["sourceRoot"])))
        if index:
            contract.validate_provisioning_transition(states[index-1], value)
    final = states[-1]
    require(states[0]["preparedAt"] <= final["publishedAt"] <= final["terminalAt"] <= validation_time
        and contract.exact_retry_receipt_bytes(final, request_id=request_id,
            transition_id=transition_id, package_digest=plan["packageDigest"]) == receipt_raw)
    receipt = document(receipt_raw)
    require(final["publishedAt"] <= receipt["completedAt"] <= final["terminalAt"]
        and final["publishedIdentityDigest"] == spec.domain_digest(
            "serverware.authorityProvisionedGenerationIdentity/v1",
            spec.canonical_json_bytes(receipt["generationDirectoryIdentity"])))


def _next_state(prior, verified, *, validation_time):
    require(isinstance(verified, spec.VerifiedArtifactPackage) and verified.disposition == "Successor"
        and verified.generation_sequence == 0 and verified.predecessor_digest is None
        and verified.minimum_rollback_sequence == 0 and verified.trust_mode == "trusted-host-local"
        and verified.stage_zero_contract == spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA)
    initial_state(spec.canonical_json_bytes(prior))
    keys = [dict(keyId=key.key_id, purposes=sorted(key.purposes),
        publicKeyBase64Url=spec.strict_base64url_encode(key.public_key), keyFileSha256=key.key_file_sha256,
        authorizationDigest=key.authorization_digest, notBefore=key.not_before, notAfter=key.not_after)
        for _, key in sorted(verified.keys.items())]
    bundle = verified.package["bundle"]
    value = dict(prior, currentGenerationSequence=0, currentGenerationDigest=verified.generation_digest,
        currentPackageDigest=verified.package_digest, minimumRollbackSequence=0,
        acceptedPackageDigests=[verified.package_digest], acceptedGenerationDigests=[verified.generation_digest],
        acceptedEvidenceDigests=sorted({spec.snapshot_receipt_digest(bundle["stableSnapshotReceipt"]),
                                      spec.closure_receipt_digest(bundle["closureReceipt"])}),
        currentKeys=keys, revokedKeyIds=sorted(verified.revoked_key_ids),
        witness=dict(prior["witness"], currentSequence=0, currentCheckpointDigest=verified.witness_checkpoint_digest,
            currentRootDigest=verified.witness_root_digest, currentTreeSize=verified.witness_tree_size))
    # This is the actual unchanged downstream consumer, not a bypass or DTO flag.
    accepted = spec.verify_signed_artifact_package(dict(verified.package), trust_state=value, validation_time=validation_time)
    require(accepted.disposition == "CurrentExactRetry" and accepted.package_digest == verified.package_digest)
    return spec.canonical_json_bytes(value)


def _exchange(root):
    if install._LIBC.renameat2(root, PENDING_NAME.encode("ascii"), root, install.TRUST_NAME.encode("ascii"), 2):
        error = ctypes.get_errno()
        raise OSError(error, "atomic trust exchange refused")


def _measure_verity(fd):
    value = bytearray(struct.pack("=HH64s", 0, 64, bytes(64)))
    fcntl.ioctl(fd, 0xC0046686, value, True)
    algorithm, size, digest = struct.unpack("=HH64s", value)
    require(algorithm == 1 and size == 32)
    return "sha256:" + digest[:32].hex()


def _directory(fd, mode):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
        and info.st_uid == info.st_gid == 0 and info.st_nlink > 0
        and fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


class LocalArtifactTrustCommit:
    def __init__(self, token):
        require(token is _TOKEN)
        self._pid, self.stage = os.getpid(), "opening"
        self._fds, self._fd_ids, self._public, self._stamps, self._records = [], {}, {}, {}, {}
        self._links, self._installed, self._locks = [], [], []
        self._selected = None
        self._closed = self._closing = self._uncertain = self._used = self._failed = False
        self.exchange_attempted = self.committed = False
        self._epoch_limit = 2**63 - 1
        self._last_boot, self._last_epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()

    @classmethod
    def open(cls, *, approval_fd, approval_sha256, trust_fd, trust_sha256,
             package_fd, package_sha256, verification_fd, verification_sha256,
             destination_fd, witness_directory_fd):
        require(cls is LocalArtifactTrustCommit)
        owner = cls(_TOKEN)
        try:
            owner._origin()
            fds = (approval_fd, trust_fd, package_fd, verification_fd, destination_fd, witness_directory_fd)
            require(all(type(fd) is int and 3 <= fd < 2**31 for fd in fds) and len(set(fds)) == len(fds))
            held = []
            with install._owning():
                for fd in fds:
                    held.append(owner._hold(os.dup(fd)))
            require(len(set(owner._fd_ids.values())) == len(held))
            owner._root, owner._witness = held[-2:]
            originals = []
            for fd, pin, maximum in zip(held[:4], (approval_sha256, trust_sha256, package_sha256, verification_sha256),
                                       (MAX_APPROVAL, io.MAX_PUBLIC, io.MAX_PUBLIC, io.MAX_PUBLIC)):
                spec._require_digest(pin, name="public original pin")
                raw = owner._public_read(fd, maximum)
                require(sha(raw) == pin); originals.append(raw)
            owner._selected = approval(originals[0])
            owner._prior_raw, owner._package_raw, owner._verification_raw = originals[1:]
            selected = owner._selected
            require((selected["priorTrustSha256"], selected["packageSha256"], selected["verificationReceiptSha256"])
                == (trust_sha256, package_sha256, verification_sha256))
            initial_state(owner._prior_raw)
            owner._root_identity, owner._witness_identity = _directory(owner._root, 0o750), _directory(owner._witness, 0o700)
            require(owner._root_identity[:2] == (selected["destination"]["device"], selected["destination"]["inode"])
                and owner._witness_identity[:2] == (selected["witnessDirectory"]["device"], selected["witnessDirectory"]["inode"]))
            owner._bind_path()
            owner.check()
            owner.stage = "prepared"
            return owner
        except BaseException as error:
            owner._failed = True
            raise LocalArtifactTrustCommitError(owner) from error

    def _origin(self):
        io._process()
        require(os.getpid() == self._pid and os.uname().machine == "x86_64"
            and not self._closed and not self._closing and not self._uncertain)

    def _hold(self, fd):
        self._fds.append(fd)  # Retain before any fallible FD inspection.
        os.set_inheritable(fd, False)
        info = os.fstat(fd); self._fd_ids[fd] = (info.st_dev, info.st_ino)
        return fd

    def _drop(self, fd):
        require(fd in self._fds)
        with install._owning():
            require((os.fstat(fd).st_dev, os.fstat(fd).st_ino) == self._fd_ids[fd])
            self._uncertain = True
            os.close(fd)
            self._fds.remove(fd); del self._fd_ids[fd]
            self._uncertain = False

    def _clock(self):
        selected = self._selected
        boot, epoch = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(selected is not None and install._boot() == selected["bootIdDigest"]
            and selected["issuedAtBoottimeNs"] <= self._last_boot <= boot < selected["deadlineBoottimeNs"]
            and selected["issuedAtUnixNanos"] <= self._last_epoch <= epoch < min(selected["expiresAtUnixNanos"], self._epoch_limit))
        self._last_boot, self._last_epoch = boot, epoch

    def _tick(self):
        self._origin(); require(not self._failed); self._clock()

    def _instant(self):
        self._tick()
        return datetime.fromtimestamp(self._last_epoch // 10**9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _public_read(self, fd, maximum=io.MAX_PUBLIC):
        raw = io.read_public(fd, maximum)
        require(sum(map(len, self._public.values())) + len(raw) <= MAX_RETAINED)
        self._public[fd], self._stamps[fd] = raw, io._identity(os.fstat(fd))
        return raw

    def _named(self, parent, name, maximum=io.MAX_PUBLIC):
        self._tick()
        with install._owning(): fd = self._hold(install._open_beneath(parent, name, _READ))
        raw = self._public_read(fd, maximum)
        self._records[(parent, name)] = fd
        return raw

    def _subdirectory(self, parent, name, mode):
        self._tick()
        with install._owning(): fd = self._hold(install._open_beneath(parent, name, _READ | os.O_DIRECTORY))
        identity = _directory(fd, mode)
        self._links.append((parent, name, fd, identity))
        return fd

    def _bind_path(self):
        with install._owning(): current = self._hold(os.open("/", _READ | os.O_DIRECTORY))
        for name in PurePosixPath(self._selected["destination"]["path"]).parts[1:]:
            self._tick()
            with install._owning(): fd = self._hold(install._open_beneath(current, name, _READ | os.O_DIRECTORY))
            info = os.fstat(fd)
            require(info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)
            self._links.append((current, name, fd, (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)))
            current = fd
        require(self._fd_ids[current] == self._fd_ids[self._root])

    def _lock(self, parent, name):
        self._tick()
        with install._owning(): fd = self._hold(install._open_beneath(parent, name, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW))
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 0)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._locks.append((parent, name, fd, io._identity(info)))

    def check(self):
        self._tick()
        require(_directory(self._root, 0o750) == self._root_identity
            and _directory(self._witness, 0o700) == self._witness_identity)
        for parent, name, fd, identity in self._links:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            require((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) == identity
                and (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid) == identity)
        for (parent, name), fd in self._records.items():
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(io._identity(info) == self._stamps[fd])
        for fd, raw in self._public.items():
            self._tick()
            require(io._identity(os.fstat(fd)) == self._stamps[fd] and io.read_public(fd, io.MAX_PUBLIC) == raw)
        for parent, name, fd, identity in self._locks:
            require(io._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity
                and io._identity(os.fstat(fd)) == identity)
        for fd, identity, size, verity in self._installed:
            self._tick()
            require(install._identity(fd) == identity and install._flags(fd) & install._IMMUTABLE)
            if verity is not None:
                require(os.fstat(fd).st_size == size and os.fstat(fd).st_nlink == 1 and _measure_verity(fd) == verity)
        self._tick()

    def _authenticate(self):
        self.stage = "authenticating"
        named_prior = self._named(self._root, install.TRUST_NAME)
        require(named_prior == self._prior_raw)
        prior_fd = self._records[(self._root, install.TRUST_NAME)]
        require(any(fd != prior_fd and raw == self._prior_raw and self._fd_ids[fd] == self._fd_ids[prior_fd]
            for fd, raw in self._public.items()))
        prior = initial_state(self._prior_raw)
        verified = spec.verify_signed_artifact_package(document(self._package_raw), trust_state=prior, validation_time=self._instant())
        require(verified.disposition == "Successor" and verified.generation_sequence == 0
            and verified.predecessor_digest is None and verified.minimum_rollback_sequence == 0
            and verified.trust_mode == "trusted-host-local" and verified.stage_zero_contract == spec.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA)
        self._verified = verified
        name = contract._generation_directory_name(0, verified.generation_digest)
        receipts = self._subdirectory(self._root, "receipts", 0o700)
        generations = self._subdirectory(self._root, "generations", 0o700)
        incoming = self._subdirectory(self._root, ".incoming", 0o700)
        require(os.listdir(generations) == [name] and os.listdir(incoming) == [])
        names = {name + suffix for suffix in (".plan.json", ".receipt.json", ".state-0.json", ".state-1.json", ".state-2.json")}
        require(set(os.listdir(receipts)) == names)
        plan_raw = self._named(receipts, name + ".plan.json")
        receipt_raw = self._named(receipts, name + ".receipt.json")
        state_raws = [self._named(receipts, name + f".state-{index}.json") for index in range(3)]
        selected = self._selected
        require((sha(plan_raw), sha(receipt_raw), sha(state_raws[-1])) ==
            (selected["planSha256"], selected["provisioningReceiptSha256"], selected["terminalStateSha256"]))
        plan, receipt, verification = document(plan_raw), document(receipt_raw), document(self._verification_raw)
        contract.validate_provisioning_plan(plan)
        prepared = ({"prepared_static": plan["preparedStatic"]}
            if plan["schema"] == contract.LOCAL_PREPARED_PROVISIONING_PLAN_SCHEMA else {})
        require(plan == contract.build_provisioning_plan(verified, verification, validation_time=self._instant(),
            source_root_fd=plan["sourceRoot"]["fd"], destination_root=selected["destination"]["path"],
            owner_uid=0, owner_gid=0, trusted_host_local=True, **prepared))
        contract.verify_provisioning_receipt(receipt, plan=plan, verified_package=verified, validation_time=self._instant())
        states = [document(raw) for raw in state_raws]
        terminal_chain(states, plan=plan, receipt_raw=receipt_raw, request_id=selected["requestId"],
            transition_id=selected["transitionId"], validation_time=self._instant())
        require(verification["verifiedAt"] <= states[0]["preparedAt"]
            and install._identity(self._root) == receipt["destinationRootIdentity"])
        self._plan, self._receipt, self._verification = plan, receipt, verification
        self._witness_records(prior, verified)
        self._tree = self._subdirectory(generations, name, plan["destination"]["directoryMode"])
        require(install._identity(self._tree) == receipt["generationDirectoryIdentity"])
        self._installation(receipt)
        bundle = verified.package["bundle"]
        self._epoch_limit = min(install._unix_limit(value) for value in (
            verified.package["generation"]["validUntil"], verification["validUntil"],
            bundle["stableSnapshotReceipt"]["payload"]["expiresAt"], bundle["closureReceipt"]["payload"]["expiresAt"],
            *(key.not_after for key in verified.keys.values())))
        self._next_raw = _next_state(prior, verified, validation_time=self._instant())
        self.check()

    def _witness_records(self, prior, verified):
        names = {witness.LOCK_NAME, witness.BASE_NAME, witness.HEAD_NAME, witness._name(0)}
        require(set(os.listdir(self._witness)) == names)
        base = self._named(self._witness, witness.BASE_NAME)
        generation_raw = self._named(self._witness, witness._name(0))
        head = self._named(self._witness, witness.HEAD_NAME, 8192)
        require(base == self._prior_raw and sha(head) == self._selected["witnessHeadSha256"]
            and generation_raw == spec.canonical_json_bytes(verified.package["generation"])
            and document(head) == witness._head(base, generation_raw))
        old = spec.validate_trust_state(prior)["witness"]
        previous = dict(sequence=-1, generationDigest=None, minimumRollbackSequence=0,
            checkpointDigest=old["currentCheckpointDigest"], rootDigest=old["currentRootDigest"],
            treeSize=0, issuedAt="0001-01-01T00:00:00Z")
        witness._verify_record(document(generation_raw), previous, old, now=self._instant())
        key = verified.require_key(old["keyId"], "witness-checkpoint", at=self._instant())
        require(key.public_key == old["publicKey"] and key.authorization_digest == old["authorizationDigest"])

    def _installation(self, receipt):
        rows = {row["path"]: row for row in receipt["installedEntries"]}
        require(all(len(PurePosixPath(path).parts) <= 64 for path in rows))
        directories = {str(parent) for name in rows for parent in PurePosixPath(name).parents if str(parent) != "."}
        require(len(directories) <= contract.MAX_FILES * 64)
        seen = set()
        def visit(fd, prefix):
            self._tick()
            identity = install._identity(fd)
            require(install._flags(fd) & install._IMMUTABLE and identity["device"] == receipt["generationDirectoryIdentity"]["device"])
            self._installed.append((fd, identity, None, None))
            with os.scandir(fd) as entries:
                for entry in entries:
                    self._tick(); path = prefix + entry.name
                    require(path in rows or path in directories)
                    with install._owning(): child = self._hold(install._open_beneath(fd, entry.name, _READ))
                    if path in directories:
                        _directory(child, self._plan["destination"]["directoryMode"]); visit(child, path + "/")
                    else:
                        row, info = rows[path], os.fstat(child)
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == row["size"]
                            and install._identity(child) == {key: row[key] for key in ("device", "inode", "generation", "mode", "uid", "gid")}
                            and install._flags(child) & install._IMMUTABLE and _measure_verity(child) == row["fsVerityDigest"])
                        self._installed.append((child, install._identity(child), row["size"], row["fsVerityDigest"]))
                        seen.add(path)
        visit(self._tree, "")
        require(seen == set(rows))

    def _publish(self):
        self.stage = "preparing-commit"
        self.check()
        with install._owning(): writer = self._hold(install._open_beneath(self._root, PENDING_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600))
        offset = 0
        while offset < len(self._next_raw):
            self._tick()
            count = os.write(writer, self._next_raw[offset:offset+65536]); require(count > 0); offset += count
        os.fchmod(writer, 0o400); os.fsync(writer)
        writer_id = self._fd_ids[writer]
        self._drop(writer)
        require(self._named(self._root, PENDING_NAME) == self._next_raw)
        new_fd = self._records[(self._root, PENDING_NAME)]
        old_fd = self._records[(self._root, install.TRUST_NAME)]
        require(self._fd_ids[new_fd] == writer_id)
        os.fsync(self._root)
        # Exact named and held bytes, all installed handles, both locks and the
        # original clocks remain checked immediately before the atomic effect.
        self.check()
        spec.verify_signed_artifact_package(dict(self._verified.package), trust_state=document(self._prior_raw), validation_time=self._instant())
        contract.verify_verification_receipt(self._verification, verified_package=self._verified,
            validation_time=self._instant(), accepted_receipt_digests=())
        contract.verify_provisioning_receipt(self._receipt, plan=self._plan, verified_package=self._verified, validation_time=self._instant())
        require(_next_state(document(self._prior_raw), self._verified, validation_time=self._instant()) == self._next_raw)
        self.check()
        self.stage = "exchanging"
        with install._owning():
            self.exchange_attempted = True
            _exchange(self._root)
            self._records[(self._root, install.TRUST_NAME)] = new_fd
            self._records[(self._root, PENDING_NAME)] = old_fd
            for fd in self._public:
                if self._fd_ids[fd] in (self._fd_ids[old_fd], self._fd_ids[new_fd]):
                    before, after = self._stamps[fd], io._identity(os.fstat(fd))
                    require(before[:8] == after[:8])  # Rename may change ctime only.
                    self._stamps[fd] = after
        os.fsync(self._root)
        self.check()
        require(io.read_public(old_fd, io.MAX_PUBLIC) == self._prior_raw
            and io.read_public(new_fd, io.MAX_PUBLIC) == self._next_raw)
        self.committed = True
        self.stage = "committed-not-activated"

    def run(self):
        try:
            self._tick(); require(not self._used); self._used = True
            self._lock(self._root, ".authority-generation.lock")
            self._lock(self._witness, witness.LOCK_NAME)
            self._authenticate()
            self._publish()
            result = dict(status="committed-not-activated", trustStateSha256=sha(self._next_raw),
                generationDigest=self._verified.generation_digest, generationSequence=0)
            self.check(); self.close(); self._clock()
            return result
        except BaseException as error:
            self._failed = True
            raise LocalArtifactTrustCommitError(self) from error

    def close(self):
        if self._closed:
            return
        require(os.getpid() == self._pid and not self._closing and not self._uncertain)
        self._closing = True
        with install._owning():
            while self._fds:
                fd = self._fds[-1]
                # Partially acquired/written descriptors remain owned even if
                # an earlier inspection failed. Cleanup never renews authority.
                if fd not in self._fd_ids:
                    info = os.fstat(fd); self._fd_ids[fd] = (info.st_dev, info.st_ino)
                self._drop(fd)
        self._closed = True
