"""Sign a measured, parked local process's existing manifest/certificate pair.

This is a trusted-host, root-operated issuer, not independent administration or
native attestation. The configuration root is deliberately delegated to the
existing launch-manifest domain. The artifact-authorized certificate issuer is
a different key. Service-role cohort evidence is NOT produced here.

The exact unsigned payload is independently selected. No identity, installed
inode, mapping, key, deadline, command or authority is invented by this issuer.
The existing launcher still performs its own admission after publication.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import PurePosixPath
import ctypes
import fcntl
import hashlib
import os
import select
import socket
import stat
import struct
import time

from cryptography.hazmat.primitives import serialization

from scripts.authority import atomic_provisioner_contract as provision
from scripts.authority import native_pilot_authority_io as io
from serverware import authority_artifact_spec as spec
from serverware import authority_launcher as launch
from serverware import authority_stage_zero_contract as stage
from serverware.authority_local_configuration import document
from serverware.authority_local_install import _generation, _frozen, _owning
from serverware.authority_local_artifacts import sha
from serverware.authority_local_limits import LOCAL_SETUP_MAX_NS

SCHEMA = "serverware.authorityTrustedHostLocalLaunchAuthorizationApproval/v1"
PURPOSE = "authorize-exact-observed-local-launch-pair"
DELEGATION = "configuration-root-also-signs-local-launch-manifest-v7"
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "configurationRootPublicKeyBase64Url",
    "payloadOriginal", "payloadSha256", "observationSha256", "launchPublicKeyBase64Url",
    "exchangeDirectory", "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs",
    "issuedAtUnixNanos", "expiresAtUnixNanos"})
PAYLOAD_FIELDS = frozenset({"schema", "role", "processMode", "runtimeUid", "runtimeGid",
    "supplementaryGids", "socketPath", "pythonExecutable", "bootstrapSha256", "closure",
    "packageVersions", "nativeExecutableMappings", "retainedCredentialDescriptors", "artifactPackage",
    "artifactTrustState", "artifactVerificationReceipt", "provisioningPlan", "provisioningReceipt",
    "stageZeroRequest"})
OBSERVATION_FIELDS = frozenset({"schema", "role", "setupSha256", "process", "listener", "bootstrap",
    "interpreter", "retainedFiles", "retainedDirectories", "mutableStateDescriptors", "credentials",
    "argv", "environment", "execution", "startupDescriptors", "deadlineBoottimeNs", "expiresAtUnixNanos"})
ROOT_NAME = "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD"
OUTPUT_NAMES = ("certificate.json", "manifest.json")
LATE_LIMITS = {"certificate.json": 1024 * 1024, "manifest.json": io.MAX_PUBLIC,
    "evidence.json": 4 * 1024 * 1024}


def require(value):
    if not value:
        raise ValueError("local launch authorization refused")


def _pidfd_pending(fd):
    """Descriptor-safe liveness; readiness or invalid custody is not live."""
    require(type(fd) is int and fd >= 3)
    pending = select.poll()
    pending.register(fd, select.POLLIN)
    events = pending.poll(0)
    require(not any(flags & select.POLLNVAL for _descriptor, flags in events))
    return not events


def _public(value):
    return spec.strict_base64url_decode(value, name="local launch public key", decoded_size=32)


def _instant(epoch):
    return datetime.fromtimestamp(epoch // 1_000_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value):
    delta = spec._require_timestamp(value, name="original launch interval") - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000


def _effective_environment(initial, request, observed):
    """Join validated descriptor argv additions after exact live argv readback."""
    assignments = {row["name"]: str(row["fd"]) for row in request["credentials"]}
    assignments[stage.BOOTSTRAP_CONTROL_NAME] = str(request["bootstrapControl"]["fd"])
    if request["runtimeEvidence"] is not None:
        assignments[stage.RUNTIME_EVIDENCE_NAME] = str(request["runtimeEvidence"]["fd"])
    require(not set(initial) & set(assignments))
    environment = dict(initial, **assignments)
    require(not set(environment) - launch.LOCAL_EXEC_ENVIRONMENT - {row["name"] for row in request["credentials"]}
        and {name: value for name, value in environment.items() if name in launch.LOCAL_EXEC_ENVIRONMENT} == observed)
    return environment


def bind_observation(payload, observed):
    """Literal binding only; live measurements are mandatory in the owner below."""
    require(type(observed) is dict and set(observed) == OBSERVATION_FIELDS
        and observed["schema"] == launch.LOCAL_OBSERVATION_SCHEMA and observed["role"] == payload["role"])
    request = payload["stageZeroRequest"]
    process = observed["process"]
    require(type(process) is dict and set(process) == {"pid", "uid", "gid", "startTimeTicks", "parentPid",
        "bootIdDigest", "pidNamespaceInode", "pidfd"} and process["uid"] == process["gid"] == 0)
    for name in ("pid", "startTimeTicks", "parentPid", "pidNamespaceInode"):
        require(type(process[name]) is int and process[name] > 0)
    require(request["schema"] == stage.LOCAL_STAGE_ZERO_REQUEST_SCHEMA
        and request["process"] == dict(processId=process["pid"], processStartTicks=process["startTimeTicks"],
            bootIdDigest=process["bootIdDigest"], pidfd=process["pidfd"])
        and request["listener"] == observed["listener"]
        and request["startupDescriptors"] == observed["startupDescriptors"]
        and request["mutableStateDescriptors"] == observed["mutableStateDescriptors"]
        and request["execution"]["argv"] == observed["argv"]
        and request["environment"]["values"] == observed["environment"]
        and observed["execution"] == {name: request["execution"][name] for name in ("cwd", "noNewPrivileges")}
        and request["startupDescriptors"]["setup"]["sha256"] == observed["setupSha256"])
    require(all(request["stageZero"][name] == observed["bootstrap"][name] for name in ("fd", "size", "sha256"))
        and request["stageZero"]["interpreter"]["runtimePath"] == observed["interpreter"]["path"]
        and request["stageZero"]["interpreter"]["sha256"] == observed["interpreter"]["sha256"]
        and request["execution"]["executableFd"] == observed["interpreter"]["fd"])
    for name in ("retainedFiles", "retainedDirectories"):
        declared = {row["fd"]: row for row in request[name]}
        require(len(declared) == len(request[name]) == len(observed[name])
            and set(declared) == {row["fd"] for row in observed[name]})
        for row in observed[name]:
            require(all(declared[row["fd"]][key] == value for key, value in row.items()))
    declared = {row["name"]: row for row in request["credentials"]}
    require(len(declared) == len(observed["credentials"]) and set(declared) == {row["name"] for row in observed["credentials"]})
    for row in observed["credentials"]:
        require(all(declared[row["name"]][key] == row[source] for key, source in (
            ("fd", "fd"), ("size", "size"), ("sha256", "sha256"), ("mode", "mode"), ("ownerUid", "uid"), ("seals", "seals"))))


def _static(payload, verified, instant):
    request, role = payload["stageZeroRequest"], payload["role"]
    require(set(payload) == PAYLOAD_FIELDS and payload["schema"] == launch.LAUNCH_PAYLOAD_SCHEMA
        and role in launch.PROCESS_MODES and payload["processMode"] == launch.PROCESS_MODES[role]
        and (payload["runtimeUid"], payload["runtimeGid"]) == launch.ROLE_IDENTITIES[role]
        and payload["supplementaryGids"] == list(launch.ROLE_SUPPLEMENTARY_GIDS[role])
        and payload["socketPath"] == launch.ROLE_SOCKET_PATHS[role]
        and payload["pythonExecutable"] == request["stageZero"]["interpreter"]["runtimePath"]
        and payload["bootstrapSha256"] == request["stageZero"]["sha256"]
        and request["role"]["role"] == role and request["trustMode"] == "trusted-host-local")
    kwargs = dict(verified_package=verified, expected_listen_pid=request["process"]["processId"],
        expected_peer_pid=request["process"]["processId"], expected_peer_start_ticks=request["process"]["processStartTicks"],
        validation_time=instant)
    stage.validate_stage_zero_request(request, **kwargs)
    provision.validate_provisioning_plan(payload["provisioningPlan"])
    for function, original, extra in ((provision.verify_verification_receipt, payload["artifactVerificationReceipt"], {}),
            (provision.verify_provisioning_receipt, payload["provisioningReceipt"], {"plan": payload["provisioningPlan"]})):
        function(original, verified_package=verified, validation_time=instant, accepted_receipt_digests=(), **extra)
    destination = payload["provisioningPlan"]["destination"]
    root = PurePosixPath(destination["root"]) / destination["generationsDirectory"] / destination["generationDirectory"]
    installed = {row["path"]: row for row in payload["provisioningReceipt"]["installedEntries"]}
    roots = [row for row in request["retainedDirectories"] if row["purpose"] == "artifact-generation-root"]
    require(len(roots) == 1 and roots[0]["runtimePath"] == str(root)
        and {name: roots[0][name] for name in ("device", "inode", "generation", "mode", "uid", "gid")}
            == payload["provisioningReceipt"]["generationDirectoryIdentity"])
    retained = {row["runtimePath"]: row for row in request["retainedFiles"]}
    require(len(retained) == len(request["retainedFiles"]))
    installation_paths = spec.retained_installation_paths(bundle=verified.package["bundle"],
        generation_root=str(root), retained_files=request["retainedFiles"], launch_closure=payload["closure"])
    for path, row in retained.items():
        original = installed[installation_paths[path]]
        require(all(row[name] == original[name] for name in
            ("device", "inode", "generation", "mode", "uid", "gid", "size", "sha256", "fsVerityDigest")))
    require(any(row["purpose"] == "role-manifest" and row["runtimePath"] == str(root / request["role"]["path"])
        and row["sha256"] == request["role"]["sha256"] for row in retained.values()))
    imports = {row["module"]: row for row in verified.package["bundle"]["pythonImportClosure"]}
    seen, paths = set(), set()
    require(type(payload["closure"]) is list and 0 < len(payload["closure"]) <= launch.MAX_CLOSURE_FILES)
    for row in payload["closure"]:
        require(type(row) is dict and set(row) == {"path", "sha256", "size", "module", "kind", "isPackage"}
            and row["path"] not in paths and row["kind"] in {"source", "extension", "data", "runtime"}
            and type(row["isPackage"]) is bool and type(row["module"]) is str)
        paths.add(row["path"])
        require(all(row[name] == retained[row["path"]][name] for name in ("sha256", "size")))
        if row["kind"] in {"source", "extension"}:
            require(row["module"] not in seen and all(row[name] == imports[row["module"]][name]
                for name in ("sha256", "kind", "isPackage")))
            seen.add(row["module"])
    require(any(row["path"] == str(root / request["role"]["path"])
        and row["sha256"] == request["role"]["sha256"] for row in payload["closure"]))
    require(seen == set(imports) and {"serverware.authority_artifact_spec", "serverware.authority_stage_zero_contract",
        "scripts.authority.atomic_provisioner_contract"} <= seen)
    packages = payload["packageVersions"]
    require(type(packages) is dict and 0 < len(packages) <= 4096 and all(
        type(part) is str and part.isascii() and 0 < len(part) <= 256
        for pair in packages.items() for part in pair))
    credentials = {row["name"]: row for row in request["credentials"]}
    bindings = payload["retainedCredentialDescriptors"]
    require(type(bindings) is list and len(bindings) == len(credentials)
        and {row["environmentName"] for row in bindings} == set(credentials))
    for row in bindings:
        require(type(row) is dict and set(row) == {"environmentName", "descriptor", "kind", "ownerUid", "mode", "size", "sha256"}
            and type(row["kind"]) is str and row["kind"] and all(row[key] == credentials[row["environmentName"]][source]
                for key, source in (("descriptor", "fd"), ("ownerUid", "ownerUid"), ("mode", "mode"), ("size", "size"), ("sha256", "sha256"))))
    return kwargs


def prepare(approval_raw, observation_raw, *, boot, now_boottime_ns, now_unix_ns):
    selected = document(approval_raw, io.MAX_PUBLIC)
    require(set(selected) == FIELDS and selected["schema"] == SCHEMA and selected["purpose"] == PURPOSE
        and selected["rootDelegation"] == DELEGATION and selected["bootIdDigest"] == boot
        and type(selected["exchangeDirectory"]) is dict and set(selected["exchangeDirectory"]) == {"device", "inode"})
    require(all(type(selected["exchangeDirectory"][name]) is int and
        0 <= selected["exchangeDirectory"][name] < 2**64 for name in ("device", "inode"))
        and selected["exchangeDirectory"]["inode"] > 0)
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        require(type(selected[name]) is int and 0 < selected[name] < 2**63)
    require(selected["issuedAtBoottimeNs"] <= now_boottime_ns < selected["deadlineBoottimeNs"]
        and selected["issuedAtUnixNanos"] <= now_unix_ns < selected["expiresAtUnixNanos"]
        and selected["deadlineBoottimeNs"] - selected["issuedAtBoottimeNs"] <= LOCAL_SETUP_MAX_NS
        and selected["expiresAtUnixNanos"] - selected["issuedAtUnixNanos"] <= LOCAL_SETUP_MAX_NS
        and sha(observation_raw) == selected["observationSha256"])
    require(type(selected["payloadOriginal"]) is str and selected["payloadOriginal"].isascii())
    raw = selected["payloadOriginal"].encode("ascii")
    require(sha(raw) == selected["payloadSha256"])
    payload = document(raw, io.MAX_PUBLIC)
    observed = launch._local_document(observation_raw, launch.MAX_LOCAL_OBSERVATION)
    bind_observation(payload, observed)
    require(observed["process"]["bootIdDigest"] == boot
        and selected["deadlineBoottimeNs"] <= observed["deadlineBoottimeNs"]
        and selected["expiresAtUnixNanos"] <= observed["expiresAtUnixNanos"])
    instant = _instant(now_unix_ns)
    verified = spec.verify_signed_artifact_package(payload["artifactPackage"],
        trust_state=payload["artifactTrustState"], validation_time=instant)
    require(verified.disposition == "CurrentExactRetry" and verified.trust_mode == "trusted-host-local"
        and verified.stage_zero_contract == stage.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA)
    kwargs = _static(payload, verified, instant)
    request = payload["stageZeroRequest"]
    issuer = verified.require_key(request["launch"]["identityIssuerKeyId"], "launch-certificate-issuer", at=instant)
    root_public, launch_public = _public(selected["configurationRootPublicKeyBase64Url"]), _public(selected["launchPublicKeyBase64Url"])
    require(len({root_public, launch_public, issuer.public_key}) == 3
        and _epoch(request["launch"]["validFrom"]) <= selected["issuedAtUnixNanos"]
        and selected["expiresAtUnixNanos"] <= _epoch(request["launch"]["validUntil"])
        and selected["expiresAtUnixNanos"] <= _epoch(issuer.not_after))
    # The complete two envelopes must fit their consumers and the public IO cap.
    require(len(raw) + 512 <= min(io.MAX_PUBLIC, launch.MAX_MANIFEST_BYTES))
    return dict(selected=selected, payload=payload, observed=observed, verified=verified,
        kwargs=kwargs, issuer=issuer, rootPublic=root_public, launchPublic=launch_public)


def certificate_payload(request, public, kwargs):
    generation, role, host = request["generation"], request["role"], request["hostEvidence"]
    # Reuse only this invocation's fully validated request digest. The final
    # certificate validator still independently checks the complete payload.
    request_digest = stage.stage_zero_request_digest(request, **kwargs)
    public_key = stage._base64url(public, name="launch public key", decoded_size=32)
    result = dict(schema=stage.LOCAL_LAUNCH_IDENTITY_PAYLOAD_SCHEMA,
        launchId=stage._launch_id_from_request_digest(request, request_digest, public_key), generationSequence=generation["sequence"],
        generationDigest=generation["digest"], roleManifestDigest=role["sha256"], publicKeyAlgorithm="Ed25519",
        launchPublicKeyBase64Url=public, issuedAt=request["launch"]["validFrom"], expiresAt=request["launch"]["validUntil"],
        trustMode="trusted-host-local", coLocated=True, hardwareBacked=False)
    for field in ("packageDigest", "predecessorDigest", "artifactBundleDigest", "operationManifestDigest", "stageZeroDigest",
            "stageZeroContract", "roleSetDigest", "keyAuthorizationsDigest", "keyRevocationsDigest", "witnessCheckpointDigest"):
        result[field] = generation[field]
    for field in ("role", "processMode", "runtimeUid", "runtimeGid", "supplementaryGids"):
        result[field] = role[field]
    for field in ("bootIdDigest", "kernelReleaseDigest", "kernelCommandLineDigest", "vdsoDigest"):
        result[field] = host[field]
    for field in ("processId", "processStartTicks"):
        result[field] = request["process"][field]
    for field, function, value in (("listenerIdentityDigest", stage.listener_identity_digest, request["listener"]),
            ("credentialSetDigest", stage.credential_set_digest, request["credentials"]),
            ("mutableStateSetDigest", stage.mutable_state_set_digest, request["mutableStateDescriptors"]),
            ("pidfdIdentityDigest", stage.pidfd_identity_digest, request["process"]["pidfd"]),
            ("argvDigest", stage.argument_vector_digest, request["execution"]["argv"]),
            ("environmentDigest", stage.environment_digest, request["environment"]),
            ("cwdDigest", stage.working_directory_digest, request["execution"]["cwd"])):
        result[field] = function(value)
    result["executableDigest"] = request["execution"]["executableDigest"]
    result["requestDigest"] = request_digest
    stage.validate_launch_identity_payload(result, request=request, **kwargs)
    return result


def publish_late_original(directory, name, raw, *, hold, check, linked):
    """Fixed late names only; anonymous complete bytes, no replace or retry.

    ``linked`` records the irreversible release before cancellation is unmasked.
    Subsequent checks must retain sources/clocks, not demand a released child
    still occupy its parked boundary. The caller retains every acquired FD.
    """
    require(name in LATE_LIMITS and type(raw) is bytes and 0 < len(raw) <= LATE_LIMITS[name])
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    def acquire(path, open_flags, *, parent=None, mode=0o600):
        fd = os.open(path, open_flags, mode, dir_fd=parent)
        hold(fd)
        return fd
    def readback(fd):
        parts = []
        for offset in range(0, len(raw), 65536):
            check()
            parts.append(os.pread(fd, min(65536, len(raw) - offset), offset))
        require(b"".join(parts) == raw and not os.pread(fd, 1, len(raw)))
    with _owning():
        check()
        fd = acquire(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC, parent=directory)
        offset = 0
        while offset < len(raw):
            check()
            count = os.write(fd, memoryview(raw)[offset:offset + 65536])
            require(count > 0); offset += count
        os.fchmod(fd, 0o400); os.fsync(fd); readback(fd)
        libc = ctypes.CDLL(None, use_errno=True)
        proc = acquire("/proc", flags)
        buffer = ctypes.create_string_buffer(256)
        require(libc.fstatfs(proc, ctypes.byref(buffer)) == 0
            and ctypes.c_long.from_buffer(buffer).value & 0xffffffff == 0x9fa0
            and os.readlink("self", dir_fd=proc) == str(os.getpid()))
        process = acquire(str(os.getpid()), flags, parent=proc)
        descriptors = acquire("fd", flags, parent=process)
        source = str(fd).encode("ascii")
        require(io._identity(os.stat(source, dir_fd=descriptors, follow_symlinks=True)) == io._identity(os.fstat(fd)))
        check()
        require(libc.linkat(descriptors, ctypes.c_char_p(source), directory,
            ctypes.c_char_p(name.encode("ascii")), 0x400) == 0)
        linked()
        os.fsync(directory)
        require(io._identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == io._identity(os.fstat(fd)))
        readback(fd); check()
        return fd


class LocalLaunchAuthorizationError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local launch authorization refused; owner retained")
        self.owner = owner


class LocalLaunchAuthorizationIssuer:
    @classmethod
    def open(cls, *, approval_fd, approval_sha256, exchange_directory_fd, root_key_fd, certificate_key_fd):
        return cls._acquire(approval_fd=approval_fd, approval_sha256=approval_sha256,
            exchange_directory_fd=exchange_directory_fd, key_fds=(root_key_fd, certificate_key_fd))

    @classmethod
    def open_observer(cls, *, approval_fd, approval_sha256, exchange_directory_fd):
        """Same real observation custody, with no pair-signing key authority."""
        return cls._acquire(approval_fd=approval_fd, approval_sha256=approval_sha256,
            exchange_directory_fd=exchange_directory_fd, key_fds=())

    @classmethod
    def _acquire(cls, *, approval_fd, approval_sha256, exchange_directory_fd, key_fds):
        self = cls()
        self.handles, self.links, self.child_handles, self.owned = [], [], {}, {}
        self.link_by_fd, self.mapping_fds = {}, set()
        self.closed = self.closing = self.used = False
        self.pid, self.start = os.getpid(), launch._process_identity(os.getpid())[0]
        self.pidfd = None
        self.context = None
        self.source = self.directory = self.root_key = self.certificate_key = None
        try:
            io._process()
            fds = (approval_fd, exchange_directory_fd, *key_fds)
            require(all(type(fd) is int and fd >= 3 for fd in fds) and len(set(fds)) == len(fds))
            self.source, self.directory = fds[:2]
            if key_fds:
                self.root_key, self.certificate_key = key_fds
            self.borrowed = {fd: io._identity(os.fstat(fd)) for fd in fds}
            require(len({value[:2] for value in self.borrowed.values()}) == len(fds))
            self.raw = io.read_public(approval_fd, io.MAX_PUBLIC)
            require(sha(self.raw) == approval_sha256)
            self.directory_identity = self._directory()
            self.observation_fd = self._open("observation.json", directory_fd=self.directory, nofollow=True)
            self.observation_raw = io.read_public(self.observation_fd, launch.MAX_LOCAL_OBSERVATION)
            self.boot = launch._boot_identity_digest()
            self.last_boot, self.last_epoch = io._clock(), time.time_ns()
            self.context = prepare(self.raw, self.observation_raw, boot=self.boot,
                now_boottime_ns=self.last_boot, now_unix_ns=self.last_epoch)
            require(self.directory_identity == self.context["selected"]["exchangeDirectory"])
            observed = self.context["observed"]["process"]
            self.child_pid, self.child_start = observed["pid"], observed["startTimeTicks"]
            with _owning():
                self.pidfd = os.pidfd_open(self.child_pid, 0)
                self._hold(self.pidfd)
            self.check()
            for fd in key_fds:
                io._input(fd, 32, private=True)
            self.verify_live()
            return self
        except BaseException as error:
            raise LocalLaunchAuthorizationError(self) from error

    def _open(self, path, *, directory_fd=None, nofollow=False):
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | (os.O_NOFOLLOW if nofollow else 0)
        with _owning():
            fd = os.open(path, flags, dir_fd=directory_fd)
            self._hold(fd)
        return fd

    @staticmethod
    def _owned_identity(fd):
        info = os.fstat(fd)
        return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid, info.st_gid)

    def _hold(self, fd):
        self.handles.append(fd)
        self.owned[fd] = self._owned_identity(fd)

    def _directory(self):
        info = os.fstat(self.directory)
        require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700))
        return dict(device=info.st_dev, inode=info.st_ino)

    def check_sources(self):
        """Original sources/clocks remain held even after the child is released."""
        io._process()
        require(not self.closed and not self.closing and os.getpid() == self.pid
            and launch._process_identity(self.pid)[0] == self.start and launch._boot_identity_digest() == self.boot)
        selected = self.context["selected"]
        now_boot, now_epoch = io._clock(), time.time_ns()
        require(self.last_boot <= now_boot < selected["deadlineBoottimeNs"]
            and self.last_epoch <= now_epoch < selected["expiresAtUnixNanos"])
        self.last_boot, self.last_epoch = now_boot, now_epoch
        for fd, identity in self.borrowed.items():
            # The output directory's times/size legitimately change on publication.
            current = io._identity(os.fstat(fd))
            require(current[:6] == identity[:6] if fd == self.directory else current == identity)
        require(self._directory() == self.directory_identity
            and io._identity(os.stat("observation.json", dir_fd=self.directory, follow_symlinks=False))
                == io._identity(os.fstat(self.observation_fd)))

    def _check_live(self):
        self.check_sources()
        require(_pidfd_pending(self.pidfd)
            and launch._process_identity(self.child_pid)[:2] == (self.child_start, self.context["observed"]["process"]["pidNamespaceInode"]))

    def _check_link(self, fd):
        require(fd in self.link_by_fd)
        path, identity = self.link_by_fd[fd]
        require(io._identity(os.fstat(fd)) == identity and io._identity(os.stat(path)) == identity)

    def check(self):
        self._check_live()
        for fd, path, identity in self.links:
            require(io._identity(os.fstat(fd)) == identity and io._identity(os.stat(path)) == identity)

    def _read(self, fd, maximum, *, mapping=False):
        require(type(mapping) is bool and fd in self.owned)
        require(fd in self.mapping_fds and fd not in self.link_by_fd if mapping
            else fd in self.link_by_fd and fd not in self.mapping_fds)
        before = io._identity(os.fstat(fd))
        require(stat.S_ISREG(before[2]) and before[6] <= maximum)
        def check_active():
            self._check_live()
            require(self._owned_identity(fd) == self.owned[fd])
            if not mapping:
                self._check_link(fd)
            require(io._identity(os.fstat(fd)) == before)
        raw = bytearray()
        # Full-roster sweeps remain at admission/signing/publication boundaries;
        # each read retains original live guards and the exact active FD link.
        while True:
            check_active()
            part = os.pread(fd, min(65536, before[6] - len(raw)) if len(raw) < before[6] else 1, len(raw))
            check_active()
            if len(raw) == before[6]:
                require(not part)
                return bytes(raw)
            require(bool(part)); raw.extend(part)

    def _proc(self, suffix, maximum):
        # Proc pseudo-files have zero st_size; always bound the actual read.
        fd = self._open(f"/proc/{self.child_pid}/{suffix}")
        value = bytearray()
        while True:
            self._check_live()
            part = os.read(fd, min(65536, maximum + 1 - len(value)))
            self._check_live()
            if not part:
                return bytes(value)
            value.extend(part)
            require(len(value) <= maximum)

    def _child_fd(self, number):
        require(type(number) is int and number >= 3)
        self._check_live()
        if number in self.child_handles:
            fd = self.child_handles[number]
            self._check_link(fd)
            return fd
        path = f"/proc/{self.child_pid}/fd/{number}"
        fd = self._open(path)
        identity = io._identity(os.fstat(fd))
        require(io._identity(os.stat(path)) == identity and fd not in self.link_by_fd and fd not in self.mapping_fds)
        self.links.append((fd, path, identity))
        self.link_by_fd[fd] = (path, identity)
        self.child_handles[number] = fd
        self._check_live()
        self._check_link(fd)
        return fd

    def _duplicate(self, number):
        # Unlike opening /proc/.../fd, pidfd_getfd also duplicates sockets and
        # proves that the socket currently belongs to this exact live process.
        libc = ctypes.CDLL(None, use_errno=True)
        with _owning():
            fd = libc.syscall(438, self.pidfd, number, 0)
            if fd < 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            self._hold(fd)
        return fd

    @staticmethod
    def _measured_verity(fd):
        measured = bytearray(struct.pack("=HH64s", 0, 64, bytes(64)))
        fcntl.ioctl(fd, 0xC0046686, measured, True)
        algorithm, length, digest = struct.unpack("=HH64s", measured)
        require(algorithm == 1 and length == 32)
        return "sha256:" + digest[:32].hex()

    def _row(self, row, *, regular, native_measurements=None):
        fd = self._child_fd(row["fd"])
        info = os.fstat(fd)
        actual = dict(device=info.st_dev, inode=info.st_ino, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        require((stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode))
            and all(actual[name] == row[name] for name in actual))
        if "generation" in row:
            require(_generation(fd) == row["generation"])
            _frozen(fd)
        if regular:
            raw = self._read(fd, launch.MAX_CLOSURE_FILE_BYTES)
            require(len(raw) == row["size"] and sha(raw) == row["sha256"])
            verity = None
            if row.get("fsVerityDigest") is not None:
                verity = LocalLaunchAuthorizationIssuer._measured_verity(fd)
                require(verity == row["fsVerityDigest"])
            if (native_measurements is not None and "generation" in row and verity is not None
                    and info.st_size <= launch.MAX_NATIVE_MAPPING_BYTES):
                self._check_live(); self._check_link(fd)
                require(io._identity(os.fstat(fd)) == io._identity(info)
                    and self._owned_identity(fd) == self.owned[fd]
                    and _generation(fd) == row["generation"]
                    and row["runtimePath"] not in native_measurements)
                _frozen(fd)
                native_measurements[row["runtimePath"]] = (
                    fd, row["fd"], io._identity(info), row["generation"], verity, row["sha256"])
        return fd

    def _retained_mapping_digest(self, fd, measured):
        # Only the fully read, verity-measured original from this verify_live
        # call is reusable; neither the record nor its FD gains new ownership.
        held, number, identity, generation, verity, digest = measured
        def check():
            self._check_live()
            require(fd in self.mapping_fds and fd not in self.link_by_fd
                and held not in self.mapping_fds and self.child_handles.get(number) == held
                and fd in self.owned and held in self.owned
                and self._owned_identity(fd) == self.owned[fd]
                and self._owned_identity(held) == self.owned[held])
            self._check_link(held)
            require(io._identity(os.fstat(fd)) == identity == io._identity(os.fstat(held))
                and stat.S_ISREG(identity[2]) and 0 <= identity[6] <= launch.MAX_NATIVE_MAPPING_BYTES)
            for original in (held, fd):
                require(_generation(original) == generation)
                _frozen(original)
                require(self._measured_verity(original) == verity)
            self._check_live(); self._check_link(held)
            require(io._identity(os.fstat(fd)) == identity == io._identity(os.fstat(held)))
        check()
        end = os.pread(fd, 1, identity[6])
        check()
        require(not end)
        return digest

    def _mappings(self, native_measurements=None):
        raw = self._proc("maps", 1024 * 1024)
        mappings, inodes = {}, {}
        memory = None
        for line in raw.decode("ascii").splitlines():
            fields = line.split(maxsplit=5)
            require(len(fields) >= 5)
            if "x" not in fields[1]:
                continue
            require("w" not in fields[1] and len(fields) == 6)
            address, _, _, device, inode, path = fields
            require(path != "[vsyscall]")
            if path == "[vdso]":
                start, end = (int(value, 16) for value in address.split("-"))
                require(0 < end - start <= 1024 * 1024)
                if memory is None:
                    memory = self._open(f"/proc/{self.child_pid}/mem")
                self.check()
                value = os.pread(memory, end - start, start)
                require(len(value) == end - start)
                digest, identity = sha(value), (device, inode)
            else:
                require(path.startswith("/") and not path.endswith(" (deleted)"))
                fd = self._open(f"/proc/{self.child_pid}/map_files/{address}")
                info = os.fstat(fd)
                major, minor = (int(value, 16) for value in device.split(":"))
                require((os.major(info.st_dev), os.minor(info.st_dev), info.st_ino) == (major, minor, int(inode)))
                self.mapping_fds.add(fd)
                measured = None if native_measurements is None else native_measurements.get(path)
                digest = (self._retained_mapping_digest(fd, measured) if measured is not None
                    else sha(self._read(fd, launch.MAX_NATIVE_MAPPING_BYTES, mapping=True)))
                identity = (device, inode)
            require(path not in mappings or (mappings[path], inodes[path]) == (digest, identity))
            mappings[path], inodes[path] = digest, identity
        require("[vdso]" in mappings and self._proc("maps", 1024 * 1024) == raw)
        return mappings

    def verify_live(self):
        self.check()
        payload, observed = self.context["payload"], self.context["observed"]
        request = payload["stageZeroRequest"]
        status = dict(line.split(":", 1) for line in self._proc("status", 16384).decode("ascii").splitlines() if ":" in line)
        require(status["Uid"].split() == status["Gid"].split() == ["0"] * 4
            and status["NoNewPrivs"].strip() == "1" and int(status["PPid"]) == observed["process"]["parentPid"])
        for namespace in ("pid", "mnt", "user", "time"):
            require(os.stat(f"/proc/{self.child_pid}/ns/{namespace}").st_ino == os.stat(f"/proc/self/ns/{namespace}").st_ino)
        require(self._proc("cmdline", stage.MAX_ARGUMENT_BYTES).split(b"\0")[:-1] == [value.encode("ascii") for value in observed["argv"]]
            and os.readlink(f"/proc/{self.child_pid}/cwd") == request["execution"]["cwd"]
            and os.readlink(f"/proc/{self.child_pid}/exe") == payload["pythonExecutable"])
        environment = {}
        for entry in self._proc("environ", 1024 * 1024).split(b"\0"):
            if entry:
                name, value = entry.decode("ascii").split("=", 1)
                require(name not in environment); environment[name] = value
        environment = _effective_environment(environment, request, observed["environment"])
        native_measurements = {}
        for row in request["retainedFiles"]:
            self._row(row, regular=True, native_measurements=(native_measurements
                if row["runtimePath"] in payload["nativeExecutableMappings"] else None))
        for row in request["retainedDirectories"]:
            self._row(row, regular=False)
        self._row(observed["bootstrap"], regular=True)
        for row in observed["credentials"]:
            fd = self._row(row, regular=True)
            require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == row["seals"] == io.SEALS
                and environment[row["name"]] == str(row["fd"]))
            if row["name"] == ROOT_NAME:
                require(self._read(fd, 32) == self.context["rootPublic"])
        role_root = {"witness": "SERVERWARE_POLICY_AUTHORITY_WITNESS_ROOT_PUBLIC_KEY_FD",
            "runtime": "SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY_FD"}.get(
                payload["role"], "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD")
        roots = {row["name"]: row for row in observed["credentials"]}
        require({ROOT_NAME, role_root} <= set(roots)
            and self._read(self._child_fd(roots[role_root]["fd"]), 32) == self.context["rootPublic"])
        private_fd = self._child_fd(request["launch"]["privateKeyTargetFd"])
        private = io.signing_key(private_fd)
        require(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == self.context["launchPublic"])
        del private
        for purpose in (("manifest", "certificate", "evidence") if payload["role"] in launch.RUNTIME_EVIDENCE_ROLES else ("manifest", "certificate")):
            fd = self._child_fd(launch.LOCAL_SLOTS[purpose])
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink) == (0, 0, 0o400, 0, 0)
                and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == io.SEALS)
        for row in [request["process"]["pidfd"], *request["startupDescriptors"].values()]:
            info = os.stat(f"/proc/{self.child_pid}/fd/{row['fd']}")
            require((info.st_dev, info.st_ino) == (row["device"], row["inode"]))
            if "processId" in row:
                fdinfo = dict(line.split(":", 1) for line in self._proc(f"fdinfo/{row['fd']}", 16384).decode("ascii").splitlines() if ":" in line)
                require(int(fdinfo["Pid"]) == row["processId"]
                    and launch._process_identity(row["processId"])[0] == row["processStartTicks"])
        setup = request["startupDescriptors"]["setup"]
        require(sha(self._read(self._child_fd(setup["fd"]), launch.MAX_LOCAL_SETUP)) == setup["sha256"])
        channel_fd = self._duplicate(request["startupDescriptors"]["channel"]["fd"])
        with _owning():
            channel = socket.socket(fileno=channel_fd)
            try:
                require(channel.family == socket.AF_UNIX and channel.type == socket.SOCK_SEQPACKET
                    and struct.unpack("=iII", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        == (observed["process"]["parentPid"], 0, 0))
            finally:
                channel.detach()
        listener = request["listener"]
        listener_fd = self._duplicate(listener["fd"])
        with _owning():
            connection = socket.socket(fileno=listener_fd)
            try:
                require(connection.family == socket.AF_UNIX and connection.type == socket.SOCK_STREAM
                    and connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
                    and connection.getsockname() == listener["runtimePath"])
            finally:
                connection.detach()  # The retained issuer, not this wrapper, owns it.
        info = os.stat(listener["runtimePath"], follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            == tuple(listener[name] for name in ("device", "inode", "uid", "gid", "mode")))
        for row in request["mutableStateDescriptors"]:
            # Mutable witness state is deliberately NOT frozen by this issuer.
            fd = self._child_fd(row["fd"]); info = os.fstat(fd)
            named = os.stat(row["runtimePath"], follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (named.st_dev, named.st_ino)
                and stat.S_IMODE(info.st_mode) == row["mode"]
                and all(getattr(info, field) == row[name] for field, name in (("st_dev", "device"), ("st_ino", "inode"), ("st_uid", "uid"), ("st_gid", "gid"))))
            details = self._proc(f"fdinfo/{row['fd']}", 16384).decode("ascii").splitlines()
            mounts = [line.split()[1] for line in details if line.startswith("mnt_id:")]
            locks = [line.split()[1:] for line in details if line.startswith("lock:")]
            require(mounts == [str(row["mountId"])] and len(locks) == 1 and len(locks[0]) == 8
                and locks[0][1:4] == ["FLOCK", "ADVISORY", "WRITE"]
                and locks[0][4] in {str(self.child_pid), str(observed["process"]["parentPid"])}
                and locks[0][-2:] == ["0", "EOF"])
        mappings = self._mappings(native_measurements)
        require(mappings == payload["nativeExecutableMappings"])
        host = request["hostEvidence"]
        # This local issuer defines these pins as literal kernel pseudo-file bytes.
        release_fd = self._open("/proc/sys/kernel/osrelease")
        command_fd = self._open("/proc/cmdline")
        release, command = os.read(release_fd, 4097), os.read(command_fd, 65537)
        require(len(release) <= 4096 and len(command) <= 65536 and b"vsyscall=none" in command.split()
            and [token for token in command.split() if token.startswith(b"ima_appraise=")] == [b"ima_appraise=off"]
            and host == dict(bootIdDigest=self.boot, kernelReleaseDigest=sha(release), kernelCommandLineDigest=sha(command),
                vdsoDigest=mappings["[vdso]"], vsyscallMode="none", imaAppraisal="not-enforced",
                teeEvidenceDigest=None, externalWitnessCheckpointDigest=None))
        require(io.read_public(self.source, io.MAX_PUBLIC) == self.raw
            and io.read_public(self.observation_fd, launch.MAX_LOCAL_OBSERVATION) == self.observation_raw)
        self.check()

    def issue(self):
        try:
            require(not self.used and self.root_key is not None and self.certificate_key is not None)
            self.used = True
            self.verify_live()
            context, request = self.context, self.context["payload"]["stageZeroRequest"]
            root = io.signing_key(self.root_key)
            issuer = io.signing_key(self.certificate_key)
            require(root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == context["rootPublic"]
                and issuer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == context["issuer"].public_key)
            certificate = certificate_payload(request, context["selected"]["launchPublicKeyBase64Url"], context["kwargs"])
            signature = issuer.sign(stage.launch_certificate_signature_message(certificate, request=request, **context["kwargs"]))
            certificate = dict(schema=stage.LOCAL_SIGNED_LAUNCH_IDENTITY_SCHEMA, payload=certificate,
                issuerKeyId=context["issuer"].key_id, algorithm="Ed25519", signatureBase64Url=spec.strict_base64url_encode(signature))
            stage.validate_signed_launch_identity(certificate, request=request, **context["kwargs"])
            manifest = dict(schema=launch.LAUNCH_MANIFEST_SCHEMA, payload=context["payload"],
                signature=spec.strict_base64url_encode(root.sign(launch._domain_digest(launch.LAUNCH_MANIFEST_SCHEMA,
                    spec.canonical_json_bytes(context["payload"])).encode("ascii"))))
            root.public_key().verify(spec.strict_base64url_decode(manifest["signature"], name="manifest signature", decoded_size=64),
                launch._domain_digest(launch.LAUNCH_MANIFEST_SCHEMA, spec.canonical_json_bytes(manifest["payload"])).encode("ascii"))
            del root, issuer
            self.verify_live()
            return tuple(spec.canonical_json_bytes(value) for value in (certificate, manifest))
        except BaseException as error:
            raise LocalLaunchAuthorizationError(self) from error

    def publish(self):
        try:
            for name in OUTPUT_NAMES:
                try:
                    os.stat(name, dir_fd=self.directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("local launch output already exists")
            originals = self.issue()
            released = False
            def check():
                self.check_sources() if released else self.check()
            def linked_last():
                nonlocal released
                released = True
            for name, raw in zip(OUTPUT_NAMES, originals):
                publish_late_original(self.directory, name, raw, hold=self._hold, check=check,
                    linked=linked_last if name == OUTPUT_NAMES[-1] else lambda: None)
            # The parent may immediately deliver/replace reservations after the
            # last publication. Do not incorrectly require the parked phase now.
            return {name: sha(raw) for name, raw in zip(OUTPUT_NAMES, originals)}
        except BaseException as error:
            raise LocalLaunchAuthorizationError(self) from error

    def close(self):
        if self.closed:
            return
        require(not self.closing and os.getpid() == self.pid and launch._process_identity(self.pid)[0] == self.start)
        self.closing = True
        with _owning():
            while self.handles:
                require(self._owned_identity(self.handles[-1]) == self.owned[self.handles[-1]])
                os.close(self.handles[-1]); self.handles.pop()
        self.closed = True
