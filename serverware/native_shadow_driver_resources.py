"""Fixed pilot bridge resources from the actual retained v4 driver.

The production listener is already listening as its Rust consumer requires.
The ten native endpoint client sockets remain unconnected until final native
admission. Resource identities are data for independent C9/runtime authoring,
never admission, journal records, signing permission, or a ready observation.
"""
from __future__ import annotations

import copy
import errno
import fcntl
import os
import socket
import stat
import threading

from serverware import custody_generation_originals as o
from serverware import native_shadow_driver_bootstrap as bootstrap
from serverware import native_shadow_driver_outgoing as outgoing_module
from serverware.custody_generation_inputs import _persistent
from serverware.native_shadow_persistence_inputs import PersistenceInputs

p = bootstrap.p
_TOKEN = object()
LISTENER_PATH = "/run/serverware-native-pilot-bridge/listener.sock"
JOURNAL_PARENT = ("var", "lib", "serverware", "native-pilot-bridge")
JOURNAL_NAME = "production-journal"


class BridgeResources:
    def __init__(self, token, driver):
        p.require(token is _TOKEN)
        self._driver = driver
        self._fds, self._parents, self._directories, self._sockets = [], [], [], []
        self._descriptors, self._records = {}, {}
        self._outgoing = self._spool = self._inputs = None
        self._closed = self._begun = self._ready = self._poisoned = False
        self._peers_attempted = self._peers_ready = False

    _parent = PersistenceInputs._parent

    @classmethod
    def prepare(cls, driver):
        p.require(cls is BridgeResources and type(driver) is bootstrap.DriverBootstrap
            and threading.current_thread() is threading.main_thread()
            and getattr(driver, "_bridge_resources", None) is None
            and not hasattr(driver, "_prepared_inputs"))
        driver.check()
        p.require(driver._config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4"
            and driver._gate_binding is not None and not driver._attempted)
        owner = cls(_TOKEN, driver)
        driver._bridge_resources = owner  # Partial effects remain owned; no reset/retry.
        owner._uid, owner._gid = driver._config["uid"], driver._config["gid"]
        owner._gate_gid = driver._gate_binding["binding"]["gid"]
        p.require(owner._uid > 0 and owner._gid > 0 and owner._gate_gid > 0)
        owner._listener_parent = owner._parent(("run", "serverware-native-pilot-bridge"))
        try:
            os.stat("listener.sock", dir_fd=owner._listener_parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("pilot bridge listener exists; reconciliation required")
        owner._listener = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        owner._sockets.append(owner._listener)
        os.fchown(owner._listener.fileno(), owner._uid, owner._gid)
        owner._listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        owner._listener.setsockopt(socket.SOL_SOCKET, 76, 0)  # Ordinary gate framing forbids SCM_PIDFD.
        owner._listener.bind(LISTENER_PATH)
        os.chown("listener.sock", owner._uid, owner._gate_gid,
            dir_fd=owner._listener_parent, follow_symlinks=False)
        os.chmod("listener.sock", 0o660, dir_fd=owner._listener_parent, follow_symlinks=False)
        owner._listener.listen(4)  # Production validate_listener requires SO_ACCEPTCONN=1.
        owner._listener_path_identity = o.identity(os.stat("listener.sock",
            dir_fd=owner._listener_parent, follow_symlinks=False))
        owner._journal_parent = owner._parent(JOURNAL_PARENT)
        _persistent(owner._journal_parent)
        os.mkdir(JOURNAL_NAME, 0o700, dir_fd=owner._journal_parent)
        owner._journal = os.open(JOURNAL_NAME, o.FLAGS | os.O_DIRECTORY, dir_fd=owner._journal_parent)
        owner._fds.append(owner._journal)
        os.fchown(owner._journal, owner._uid, owner._gid)
        os.fchmod(owner._journal, 0o700)
        _persistent(owner._journal)
        p.require(o.names(owner._journal) == ())
        os.fsync(owner._journal); os.fsync(owner._journal_parent)
        owner._journal_identity = o.directory_identity(owner._journal)
        owner._descriptors = {"production-listener": owner._listener.fileno(), "production-journal": owner._journal}
        owner._records = {name: o.structural(os.fstat(fd)) for name, fd in owner._descriptors.items()}
        owner._ready = True
        owner.check()
        return owner

    def _origin(self):
        self._driver._origin()  # Never recurse through DriverBootstrap.check/OperationalInputs.
        p.require(self._driver._bridge_resources is self
            and self._driver._config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4"
            and (self._uid, self._gid) == (self._driver._config["uid"], self._driver._config["gid"])
            and self._driver._gate_binding["binding"]["gid"] == self._gate_gid
            and bootstrap.mechanics._clock() < (self._driver._lifetime if self._driver._constructed else self._driver._startup))

    def prepare_native_peers(self, *, outgoing, spool):
        from serverware.native_shadow_spool_inputs import SpoolInputs
        self.check()
        p.require(type(outgoing) is outgoing_module.OutgoingResources and outgoing._driver is self._driver
            and self._driver._outgoing_resources is outgoing and type(spool) is SpoolInputs
            and not self._peers_attempted and self._inputs is None and not self._begun)
        outgoing.check(); spool.check()
        cohort = spool._cohort
        p.require(cohort._spool_resources is spool and cohort.effects_selected()
            and cohort._external_driver is not None and cohort._external_driver.driver is self._driver
            and outgoing._launch_version == "serverware.nativeProofBridgeLaunch/v5"
            and outgoing._inputs is None and not outgoing._begun)
        self._peers_attempted = True
        self._outgoing, self._spool = outgoing, spool
        self._runtime_raw = bytes(outgoing._runtime_raw)
        runtime, _, excluded = outgoing_module._selection(self._runtime_raw, outgoing._launch_version, self._uid)
        p.require(runtime["apiVersion"] == "serverware.policyCustodyProductionRpcRuntime/v9"
            and runtime["listenerSocketPath"] == LISTENER_PATH
            and runtime["journalDirectoryIdentity"] == self._journal_identity)
        selected = [(entry, outgoing_module._PROOFS[entry["endpointKind"]]) for entry in runtime["proofEndpoints"]]
        selected += [(entry, outgoing_module._NATIVE_SIGNERS[entry["signerRole"]])
            for entry in runtime["parentSignerEndpoints"] if entry["signerRole"] in outgoing_module._NATIVE_SIGNERS]
        p.require(len(selected) == 10 and {entry["activationFdName"] for entry, _ in selected} == excluded)
        for entry, (path, directory_name) in selected:
            self._origin(); outgoing.check()
            name = entry["activationFdName"]
            p.require(entry["expectedSocketPath"] == path
                and name not in self._descriptors and directory_name not in self._descriptors)
            directory = outgoing_module._Directory(path, entry["expectedPeer"]["uid"], self._gid)
            self._directories.append(directory)
            p.require(stat.S_IMODE(os.fstat(directory.fd).st_mode) == 0o711)
            wire = socket.socket(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            self._sockets.append(wire)
            os.fchown(wire.fileno(), self._uid, self._gid)
            wire.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            wire.setsockopt(socket.SOL_SOCKET, 76, 1)
            self._descriptors[name], self._descriptors[directory_name] = wire.fileno(), directory.fd
        # Borrow only the genuine origin channel; native directories were
        # opened above exactly once from the selected fixed endpoint inventory.
        origin = dict(spool.additions("bridge"))["generation-origin"]
        p.require(origin == spool._remote.fileno())
        self._origin_fd = fcntl.fcntl(origin, fcntl.F_DUPFD_CLOEXEC, 128)
        self._fds.append(self._origin_fd)
        self._origin_identity = o.structural(os.fstat(origin))
        self._descriptors["generation-origin"] = self._origin_fd
        self._records = {name: o.structural(os.fstat(fd)) for name, fd in self._descriptors.items()}
        p.require(len(self._descriptors) == 23 and not set(self._descriptors).intersection(outgoing._descriptors))
        self._peers_ready = True
        self.check()
        return self

    def check(self):
        p.require(not self._closed and self._ready and not self._poisoned)
        self._poisoned = True
        self._origin()
        for parent, name, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022
                and o.structural(os.fstat(child)) == expected
                and o.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected)
        for fd in (self._listener_parent, self._journal_parent):
            info = os.fstat(fd)
            p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
        p.require(o.directory_identity(self._journal) == self._journal_identity
            and o.structural(os.stat(JOURNAL_NAME, dir_fd=self._journal_parent, follow_symlinks=False))
                == o.structural(os.fstat(self._journal)))
        _persistent(self._journal)
        p.require(not os.fstatvfs(self._journal).f_flag & os.ST_RDONLY)
        if not self._begun:
            p.require(o.names(self._journal) == ())
        p.require(o.identity(os.stat("listener.sock", dir_fd=self._listener_parent, follow_symlinks=False))
            == self._listener_path_identity and self._listener.getsockname() == LISTENER_PATH)
        p.require({name: o.structural(os.fstat(fd)) for name, fd in self._descriptors.items()} == self._records)
        for wire in self._sockets:
            p.require(not os.get_inheritable(wire.fileno())
                and fcntl.fcntl(wire.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == (1 if wire is self._listener else 0)
                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                and wire.getsockopt(socket.SOL_SOCKET, 76) == (0 if wire is self._listener else 1))
            if wire is not self._listener and not self._begun:
                p.require(wire.getsockname() == "")
                try:
                    wire.getpeername()
                except OSError as error:
                    p.require(error.errno == errno.ENOTCONN)
                else:
                    raise ValueError("native peer resource connected before admission")
        for directory in self._directories:
            directory.check()
            p.require(stat.S_IMODE(os.fstat(directory.fd).st_mode) == 0o711)
        p.require(all(not os.get_inheritable(fd) for fd in self._fds))
        if self._peers_attempted:
            p.require(self._peers_ready and self._outgoing._driver is self._driver)
            self._outgoing.check()
            p.require(self._outgoing._runtime_raw == self._runtime_raw and not self._spool._closed
                and self._spool._cohort._spool_resources is self._spool
                and self._spool._cohort._external_driver.driver is self._driver
                and o.structural(os.fstat(self._origin_fd)) == self._origin_identity
                == o.structural(os.fstat(self._spool._remote.fileno())))
            # Full preparation checks precede association. After association,
            # SpoolInputs.check -> external driver.check would recurse here.
            if self._inputs is None:
                self._spool.check(preparation=not self._spool._cohort._release_sent)
            else:
                self._spool._cohort._origin(); self._spool._cohort._child_live()
        self._origin()
        self._poisoned = False

    def journal_identity(self):
        self.check()
        return copy.deepcopy(self._journal_identity)

    def activation_originals(self):
        """Actual metadata only, before independently signed C9 admission."""
        self.check(); p.require(not self._begun)
        return tuple(dict(name=name, device=value[0], inode=value[1], mode=value[2], uid=value[3], gid=value[4])
            for name, value in sorted(self._records.items()))

    def _associate(self, inputs, driver, runtime_raw, launch, delivery):
        from serverware.native_shadow_driver_inputs import OperationalInputs
        self.check()
        p.require(type(inputs) is OperationalInputs and inputs._driver is driver and driver._prepared_inputs is inputs
            and inputs._outgoing is self._outgoing
            and driver is self._driver and self._inputs is None and not self._begun and self._peers_ready
            and runtime_raw == self._runtime_raw and launch["apiVersion"] == "serverware.nativeProofBridgeLaunch/v5"
            and launch["keyAdmission"]["deliveryConfiguration"] == driver._config["deliveryConfiguration"]
            and delivery["runtimeConfig"]["sha256"] == p.sha(self._runtime_raw))
        runtime, _, _ = outgoing_module._selection(runtime_raw, launch["apiVersion"], self._uid)
        p.require(runtime["listenerSocketPath"] == LISTENER_PATH
            and runtime["journalDirectoryIdentity"] == self._journal_identity)
        expected = dict(self._descriptors)
        p.require(not set(expected).intersection(self._outgoing._descriptors))
        expected.update(self._outgoing._descriptors)
        entries = delivery["activation"]
        p.require(type(entries) is list and len(entries) == len(expected) == 41
            and {entry["name"] for entry in entries} == set(expected))
        identities = set()
        for target, entry in enumerate(entries, 6):
            p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
            actual = o.structural(os.fstat(expected[entry["name"]]))
            p.require(entry["fd"] == target and actual == tuple(entry[name]
                for name in ("device", "inode", "mode", "uid", "gid")) and actual[:2] not in identities)
            identities.add(actual[:2])
        self._inputs = inputs

    def _begin(self, inputs):
        self.check()
        p.require(self._inputs is inputs and not self._begun and self._peers_ready)
        self._begun = True

    def _require_exit(self):
        # A terminal parent alone is not settlement of its actual v4 subtree.
        p.require(self._driver._pidfd is not None and self._driver._driver_pidfd is not None
            and bootstrap.mechanics._terminal(self._driver._pidfd)
            and bootstrap.mechanics._terminal(self._driver._driver_pidfd)
            and self._driver._subtree_terminal_original is not None)

    def _close_after_exit(self, inputs):
        if self._closed:
            return
        p.require(self._inputs is inputs)
        self._require_exit(); self._close()

    def _close_after_driver_exit(self, driver):
        p.require(driver is self._driver)
        if self._closed:
            return
        self._require_exit(); self._close()

    def _close(self):
        self._require_exit()
        for wire in reversed(self._sockets):
            wire.close()
        for directory in reversed(self._directories):
            directory.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        self._closed = True
        # No unlink or journal destruction. Existing/partial state requires
        # explicit operator reconciliation, never automatic replay.
