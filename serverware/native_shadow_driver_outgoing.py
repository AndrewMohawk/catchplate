"""Retained, unconnected outgoing resources for the actual native bridge.

Creation grants no endpoint or signing permission. Independently signed C9 and
phase-two originals must bind these exact resources before one-shot transfer.
Only the actual post-drop Rust bridge connects them; this module never contacts
an endpoint or fabricates a peer measurement.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import os
import socket
import stat
import threading

from serverware import native_shadow_driver_bootstrap as bootstrap

p = bootstrap.p
_TOKEN = object()
CONFIGURATION = "/etc/serverware/native-shadow-driver-outgoing.json"
_DIRECTORY_PREFIX = "bridge-outgoing-directory-"
_SERVICES = frozenset(bootstrap.ROLES)
_SIGNERS = frozenset(("ingress-admission", "unavailable-ingress", "dispatch-barrier", "active-effect-barrier",
    "active-effect-commit", "terminal-append", "ledger-append", "spool-compaction", "publication-reconciliation",
    "activation-publication"))
_PROOFS = {
    "retrieval": ("/run/serverware-shadow-retrieval/listener.sock", "retrieval-peer-directory"),
    "persistence": ("/run/serverware-shadow-persistence/listener.sock", "persistence-peer-directory"),
    "trusted-time": ("/run/serverware-shadow-trusted-time/listener.sock", "trusted-time-peer-directory"),
    "generation-install-envelope": ("/run/serverware-shadow-generation-install/listener.sock", "shadow-generation-install-directory"),
}
_NATIVE_SIGNERS = {
    "ledger-append": ("/run/serverware-shadow-commit-request/listener.sock", "commit-request-peer-directory"),
    "ingress-admission": ("/run/serverware-shadow-ingress-admission/listener.sock", "ingress-admission-peer-directory"),
    "terminal-append": ("/run/serverware-shadow-terminal-append/listener.sock", "terminal-append-peer-directory"),
}
_RUNTIME_FIELDS = ("apiVersion", "startupTimeoutMillis", "listenerSocketPath", "expectedFacadePeer",
    "journalDirectoryIdentity", "expectedHelperEndpointRoles", "expectedDriverProcessIdentitySha256",
    "expectedDriverConfigurationGenerationSha256", "expectedOperationGeneration", "expectedSharedConfigurationSha256",
    "expectedServiceConfigurationSha256", "expectedServiceSigningCredentialSha256", "expectedServiceRestartEpoch",
    "expectedServiceReadinessEpoch", "expectedServiceAuthorityHistoryManifestSha256",
    "expectedProductionDispatchProtocolSetSha256", "expectedMaximumDurabilityWorkerNanos", "serviceSessions",
    "histories", "parentSignerEndpoints", "proofEndpoints", "generationAdmission")
_PEER_FIELDS = ("uid", "gid", "pid", "processIdentitySha256", "startTimeTicks", "executableDevice", "executableInode",
    "executableLength", "executableSha256", "cgroupPathSha256", "cgroupMountId", "cgroupInode",
    "securityLabelSha256", "configurationGenerationSha256")


def _name(value):
    p.require(type(value) is str and value.isascii() and 1 <= len(value) <= 64
        and all(c.isalnum() or c in "-_." for c in value))
    return value


def _pin(value):
    value = p.fields(value, ("path", "sha256")); p.digest(value["sha256"])
    p.require(type(value["path"]) is str and value["path"].isascii() and value["path"].startswith("/")
        and "\0" not in value["path"] and len(value["path"]) <= 4096
        and all(part not in {"", ".", ".."} for part in value["path"].split("/")[1:]))
    return value


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _directory(info):
    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022)


def _peer(value, bridge_uid):
    value = p.fields(value, _PEER_FIELDS)
    p.require(0 < p.integer(value["uid"]) < 2**32 - 1 and value["uid"] != bridge_uid
        and 0 < p.integer(value["gid"]) < 2**32 - 1 and 1 < p.integer(value["pid"]) <= 2**31 - 1)
    for key in ("startTimeTicks", "executableDevice", "executableInode", "executableLength", "cgroupMountId", "cgroupInode"):
        p.require(0 < p.integer(value[key]) < 2**64)
    for key in ("processIdentitySha256", "executableSha256", "cgroupPathSha256", "securityLabelSha256", "configurationGenerationSha256"):
        p.digest(value[key])
    return value


def _selection(raw, launch_version, bridge_uid):
    """Closed native purpose selection, not a substitute for Rust admission."""
    suffix = {"serverware.nativeProofBridgeLaunch/v1": 5, "serverware.nativeProofBridgeLaunch/v2": 6,
        "serverware.nativeProofBridgeLaunch/v3": 7, "serverware.nativeProofBridgeLaunch/v4": 8}.get(launch_version)
    p.require(suffix is not None)
    fields = _RUNTIME_FIELDS + (("commitRequest",) if suffix >= 6 else ()) + (("spool",) if suffix >= 7 else ())
    runtime = p.fields(p.document(raw, 65536), fields)
    p.require(runtime["apiVersion"] == f"serverware.policyCustodyProductionRpcRuntime/v{suffix}"
        and 0 < p.integer(runtime["startupTimeoutMillis"]) <= 30000)
    generation = p.fields(runtime["generationAdmission"], ("apiVersion", "grants"))
    p.require(generation["apiVersion"] == "serverware.custodyGenerationServices/v1")
    p.fields(generation["grants"], _SERVICES)
    for digest in generation["grants"].values():
        p.digest(digest)
    if suffix >= 6:
        commitment = p.fields(runtime["commitRequest"], ("apiVersion", "serviceGrantOriginals"))
        p.require(commitment["apiVersion"] == "serverware.nativeCommitRequestServices/v1")
        p.fields(commitment["serviceGrantOriginals"], ("durable-recovery-store", "current-signature-authority"))
        for value in commitment["serviceGrantOriginals"].values():
            p.require(type(value) is str and value.isascii()); p.document(value.encode("ascii"), 65536)
    if suffix >= 7:
        spool = p.fields(runtime["spool"], ("apiVersion", "headGrantOriginal", "currentGrantOriginal", "originFdName"))
        p.require(spool["apiVersion"] == ("serverware.nativeSpoolServices/v2" if suffix == 8 else "serverware.nativeSpoolServices/v1")
            and spool["originFdName"] == "generation-origin")
        for key in ("headGrantOriginal", "currentGrantOriginal"):
            p.require(type(spool[key]) is str and spool[key].isascii()); p.document(spool[key].encode("ascii"), 65536)
    outgoing, names, roles, excluded = {}, {"production-listener", "production-journal", "generation-origin"}, set(), set()
    sessions = runtime["serviceSessions"]
    p.require(type(sessions) is list and len(sessions) == 5)
    for entry in sessions:
        p.fields(entry, ("serviceRole", "activationFdName", "expectedSocketPath", "expectedPeer", "handshakes"))
        role, name = entry["serviceRole"], _name(entry["activationFdName"])
        p.require(role in _SERVICES and role not in roles and name not in names
            and type(entry["handshakes"]) is list and bool(entry["handshakes"]))
        roles.add(role); names.add(name); _peer(entry["expectedPeer"], bridge_uid)
        outgoing[name] = entry
    signers, roles = runtime["parentSignerEndpoints"], set()
    p.require(type(signers) is list and len(signers) == 10)
    selected_signers = {5: set(), 6: {"ledger-append"}, 7: {"ledger-append", "ingress-admission"},
        8: {"ledger-append", "ingress-admission", "terminal-append"}}[suffix]
    for entry in signers:
        p.fields(entry, ("signerRole", "authorityBindingCredential", "activationFdName", "expectedSocketPath", "expectedPeer", "authorityKeyId", "authorityKeySpkiSha256"))
        role, name = entry["signerRole"], _name(entry["activationFdName"])
        p.require(role in _SIGNERS and role not in roles and name not in names)
        roles.add(role); names.add(name); _peer(entry["expectedPeer"], bridge_uid)
        _name(entry["authorityBindingCredential"]); p.digest(entry["authorityKeyId"]); p.digest(entry["authorityKeySpkiSha256"])
        if role in selected_signers:
            path, directory_name = _NATIVE_SIGNERS[role]
            p.require(entry["expectedSocketPath"] == path and directory_name not in names)
            excluded.add(name); names.add(directory_name)
        else:
            outgoing[name] = entry
    proofs, roles = runtime["proofEndpoints"], set()
    p.require(type(proofs) is list and len(proofs) == 4)
    for entry in proofs:
        p.fields(entry, ("endpointKind", "authorityBindingCredential", "activationFdName", "expectedSocketPath", "expectedPeer", "authorityKeyId", "authorityKeySpkiSha256"))
        role, name = entry["endpointKind"], _name(entry["activationFdName"])
        p.require(role in _PROOFS and role not in roles and name not in names)
        path, directory_name = _PROOFS[role]
        p.require(entry["expectedSocketPath"] == path and directory_name not in names)
        roles.add(role); names.add(name); names.add(directory_name); excluded.add(name)
        _peer(entry["expectedPeer"], bridge_uid)
        _name(entry["authorityBindingCredential"]); p.digest(entry["authorityKeyId"]); p.digest(entry["authorityKeySpkiSha256"])
    p.require(len(outgoing) == {5: 15, 6: 14, 7: 13, 8: 12}[suffix])
    for ordinal in range(len(outgoing)):
        p.require(_DIRECTORY_PREFIX + str(ordinal) not in names)
    return runtime, tuple((name, outgoing[name]) for name in sorted(outgoing)), frozenset(excluded)


class _Directory:
    def __init__(self, path, server_uid, bridge_gid):
        self.fds, self.parents = [], []
        try:
            p.require(type(path) is str and path.isascii() and path.startswith("/") and "\0" not in path
                and len(path) < 108 and all(part not in {"", ".", ".."} for part in path.split("/")[1:]))
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            root = os.open("/", flags); self.fds.append(root); _directory(os.fstat(root))
            self.root_identity = _identity(os.fstat(root))
            parent = root
            for name in path.split("/")[1:-1]:
                child = os.open(name, flags, dir_fd=parent); self.fds.append(child)
                _directory(os.fstat(child))
                self.parents.append((parent, name, child, _identity(os.fstat(child))))
                parent = child
            self.fd, self.leaf = parent, path.rsplit("/", 1)[1]
            self.path, self.identity = path, _identity(os.fstat(parent))
            leaf = os.stat(self.leaf, dir_fd=parent, follow_symlinks=False)
            p.require(stat.S_ISSOCK(leaf.st_mode) and stat.S_IMODE(leaf.st_mode) == 0o660
                and (leaf.st_uid, leaf.st_gid) == (server_uid, bridge_gid))
            self.leaf_identity = _identity(leaf)
            self.check()
        except BaseException:
            self.close(); raise

    def check(self):
        p.require(bool(self.fds) and _identity(os.fstat(self.fds[0])) == self.root_identity
            and _identity(os.stat("/", follow_symlinks=False)) == self.root_identity)
        for parent, name, child, identity in self.parents:
            p.require(_identity(os.fstat(child)) == identity
                and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        p.require(_identity(os.fstat(self.fd)) == self.identity
            and _identity(os.stat(self.leaf, dir_fd=self.fd, follow_symlinks=False)) == self.leaf_identity)
        for fd in self.fds:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            p.require(not os.get_inheritable(fd) and flags & os.O_ACCMODE == os.O_RDONLY and not flags & os.O_PATH)
            _directory(os.fstat(fd))

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class OutgoingResources:
    def __init__(self, token, driver):
        p.require(token is _TOKEN)
        self._driver, self._originals, self._directories, self._sockets = driver, [], [], []
        self._descriptors, self._records = {}, {}
        self._closed = self._begun = False
        self._inputs = None

    @classmethod
    def prepare(cls, driver):
        p.require(cls is OutgoingResources and type(driver) is bootstrap.DriverBootstrap
            and threading.current_thread() is threading.main_thread()
            and not hasattr(driver, "_outgoing_resources") and not hasattr(driver, "_prepared_inputs"))
        driver.check()
        p.require(not driver._attempted and driver._config["apiVersion"] in (
            "serverware.nativeShadowDriverBootstrapConfiguration/v3", "serverware.nativeShadowDriverBootstrapConfiguration/v4"))
        owner = cls(_TOKEN, driver)
        driver._outgoing_resources = owner  # Single allocation; failures do not reset the invocation.
        try:
            original = bootstrap.mechanics._Original(CONFIGURATION, 8192)
            owner._originals.append(original)
            selected = p.fields(p.document(original.raw, 8192), ("apiVersion", "driverConfigurationSha256", "driverWindowSha256",
                "driverObservationSha256", "invocationId", "deliveryConfiguration", "runtime", "bridgeLaunchVersion"))
            p.require(selected["apiVersion"] == "serverware.nativeShadowDriverOutgoingInputs/v1"
                and selected["driverConfigurationSha256"] == driver._config_sha and selected["driverWindowSha256"] == driver._window_sha
                and selected["driverObservationSha256"] == p.sha(driver._observation_raw)
                and selected["invocationId"] == driver._window["invocationId"]
                and _pin(selected["deliveryConfiguration"]) == driver._config["deliveryConfiguration"])
            cold_pin, runtime_pin = selected["deliveryConfiguration"], _pin(selected["runtime"])
            cold_original = bootstrap.mechanics._Original(cold_pin["path"], 65536, cold_pin["sha256"])
            owner._originals.append(cold_original)
            cold = p.document(cold_original.raw, 65536)
            p.require(cold["apiVersion"] == "serverware.policyCustodyGuestConfiguration/v1" and cold["serviceRole"] == "production-bridge"
                and (cold["uid"], cold["gid"]) == (driver._config["uid"], driver._config["gid"]))
            runtime_original = bootstrap.mechanics._Original(runtime_pin["path"], 65536, runtime_pin["sha256"])
            owner._originals.append(runtime_original)
            owner._runtime_raw, owner._launch_version = runtime_original.raw, selected["bridgeLaunchVersion"]
            owner._delivery_pin = copy.deepcopy(cold_pin)
            _, entries, owner._excluded = _selection(owner._runtime_raw, owner._launch_version, cold["uid"])
            for ordinal, (name, entry) in enumerate(entries):
                driver.check()
                directory = _Directory(entry["expectedSocketPath"], entry["expectedPeer"]["uid"], cold["gid"])
                owner._directories.append(directory)
                wire = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                owner._sockets.append(wire)
                os.fchown(wire.fileno(), cold["uid"], cold["gid"])
                wire.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                wire.setsockopt(socket.SOL_SOCKET, 76, 0)  # Ordinary ancillary grammar: no SCM_PIDFD.
                owner._descriptors[name] = wire.fileno()
                owner._descriptors[_DIRECTORY_PREFIX + str(ordinal)] = directory.fd
            identities = set()
            for name, fd in owner._descriptors.items():
                identity = _identity(os.fstat(fd))
                p.require(identity[:2] not in identities); identities.add(identity[:2])
                owner._records[name] = identity
            owner.check(); driver.check()
            return owner
        except BaseException:
            owner._close(); raise

    def check(self):
        p.require(not self._closed)
        self._driver._origin()  # No recursive DriverBootstrap.check from its retained input owner.
        p.require(bootstrap.mechanics._clock() < (self._driver._lifetime if self._driver._constructed else self._driver._startup))
        for original in self._originals:
            original.check()
        for directory in self._directories:
            directory.check()
        p.require({name: _identity(os.fstat(fd)) for name, fd in self._descriptors.items()} == self._records)
        for wire in self._sockets:
            p.require(not os.get_inheritable(wire.fileno())
                and fcntl.fcntl(wire.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                and wire.getsockopt(socket.SOL_SOCKET, 76) == 0)
            if not self._begun:
                p.require(wire.getsockname() == "")
                try:
                    wire.getpeername()
                except OSError as error:
                    p.require(error.errno == errno.ENOTCONN)
                else:
                    raise ValueError("outgoing resource was connected before native drop")

    def activation_originals(self):
        """Real identities for the independent C9 signer, never ready claims."""
        self.check(); p.require(not self._begun)
        return tuple(dict(name=name, device=value[0], inode=value[1], mode=value[2], uid=value[3], gid=value[4])
            for name, value in sorted(self._records.items()))

    def _associate(self, inputs, driver, runtime_raw, launch, delivery):
        self.check()
        p.require(driver is self._driver and self._inputs is None and not self._begun
            and runtime_raw == self._runtime_raw and launch["apiVersion"] == self._launch_version
            and launch["keyAdmission"]["deliveryConfiguration"] == self._delivery_pin
            and delivery["runtimeConfig"]["sha256"] == p.sha(self._runtime_raw))
        names = {entry["name"] for entry in delivery["activation"]}
        expected_directories = {_DIRECTORY_PREFIX + str(i) for i in range(len(self._sockets))}
        p.require({name for name in names if name.startswith(_DIRECTORY_PREFIX)} == expected_directories
            and set(self._descriptors) <= names and not self._excluded.intersection(self._descriptors))
        self._inputs = inputs

    def _begin(self, inputs):
        self.check(); p.require(self._inputs is inputs and not self._begun)
        self._begun = True  # Before the original caller's one irreversible send.

    def _close_after_exit(self, inputs):
        p.require(self._inputs is inputs and (not self._begun
            or bootstrap.mechanics._terminal(self._driver._pidfd)))
        if self._begun and self._driver._config["apiVersion"].endswith("/v4"):
            p.require(self._driver._subtree_terminal_original is not None)
        self._close()

    def _close_after_driver_exit(self, driver):
        p.require(driver is self._driver and (driver._child_pid is None
            or bootstrap.mechanics._terminal(driver._pidfd)))
        if self._closed:
            return
        p.require(not self._begun and self._inputs is None)
        self._close()

    def _close(self):
        if self._closed:
            return
        for wire in reversed(self._sockets):
            wire.close()
        for directory in reversed(self._directories):
            directory.close()
        for original in reversed(self._originals):
            original.close()
        self._closed = True
