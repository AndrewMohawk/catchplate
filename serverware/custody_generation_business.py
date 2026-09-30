"""Fresh actual ordinary-service business resources and generation handoff.

No journal record, signature, genesis receipt or process measurement is invented.
Protected provisioning chooses the intended client C9 identity independently.
"""
import fcntl
import os
import socket
import stat
import threading

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware.custody_generation_inputs import GenerationInputs, _persistent
from serverware.custody_generation_launch import FiveServiceLaunch

p = g.p
_TOKEN = object()
CONFIGURATION = "/etc/serverware/custody-generation-business.json"
COMMITMENT_CONFIGURATION = "/etc/serverware/custody-commitment-business.json"
RUN = "/run/serverware-custody-business"
STORE = "/var/lib/serverware/custody-business"


def _protected(info):
    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
        and stat.S_IMODE(info.st_mode) == 0o711)


def _same_name(parent, name, fd):
    p.require(o.structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == o.structural(os.fstat(fd)))


class BusinessResources:
    def __init__(self, token, launcher):
        p.require(token is _TOKEN)
        self._launcher = launcher
        self._fds, self._originals, self._sockets, self._roles = [], [], [], {}
        self._inputs = None
        self._closed = self._taken = False

    @classmethod
    def prepare(cls, launcher):
        p.require(type(launcher) is FiveServiceLaunch and not launcher._commitment)
        return cls._prepare(launcher)

    @classmethod
    def prepare_commitment(cls, launcher):
        p.require(type(launcher) is FiveServiceLaunch and launcher._commitment)
        return cls._prepare(launcher)

    @classmethod
    def _prepare(cls, launcher):
        p.require(cls is BusinessResources)
        p.require(type(launcher) is FiveServiceLaunch and threading.current_thread() is threading.main_thread()
            and launcher._business_resources is None and launcher._input_owner is None and not launcher._attempted)
        launcher.check()
        owner = cls(_TOKEN, launcher)
        try:
            original = o.Original(COMMITMENT_CONFIGURATION if launcher._commitment else CONFIGURATION, 65536)
            owner._originals.append(original)
            config = p.fields(g.document(original.read(), 65536),
                ("apiVersion", "launchConfigurationSha256", "invocationId", "clientConfiguration"))
            version = "serverware.custodyFiveServiceBusinessInputs/v2" if launcher._commitment else "serverware.custodyFiveServiceBusinessInputs/v1"
            p.require(config["apiVersion"] == version
                and config["launchConfigurationSha256"] == p.sha(launcher._originals[0].read())
                and config["invocationId"] == launcher._invocation)
            g.c9._pin(config["clientConfiguration"])
            client = o.Original(config["clientConfiguration"]["path"], 65536,
                sha=config["clientConfiguration"]["sha256"])
            owner._originals.append(client)
            owner._client = g.c9.configuration(client.read(), client.sha)
            for role in g.ROLES:
                cold = launcher._configurations[role][1]
                p.require(owner._client["uid"] != cold["uid"] and owner._client["gid"] != cold["gid"])
            owner._run = o.directory(RUN); owner._fds.append(owner._run)
            owner._store = o.directory(STORE); owner._fds.append(owner._store)
            for fd in (owner._run, owner._store):
                _protected(os.fstat(fd)); fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                p.require(o.names(fd) == ())
            _persistent(owner._store)
            owner._roots = (o.structural(os.fstat(owner._run)), o.structural(os.fstat(owner._store)))
            identities = {value[:2] for value in owner._roots}
            p.require(len(identities) == 2)
            for role in g.ROLES:
                launcher.check()
                cold = launcher._configurations[role][1]
                # Exclusive fresh namespace creation; no old role directory,
                # listener, lock, state file or journal can be adopted here.
                os.mkdir(role, 0o711, dir_fd=owner._run)
                run = os.open(role, o.FLAGS | os.O_DIRECTORY, dir_fd=owner._run); owner._fds.append(run)
                os.fchown(run, 0, 0); os.fchmod(run, 0o711)
                os.mkdir(role, 0o711, dir_fd=owner._store)
                store = os.open(role, o.FLAGS | os.O_DIRECTORY, dir_fd=owner._store); owner._fds.append(store)
                os.fchown(store, 0, 0); os.fchmod(store, 0o711)
                _persistent(store)
                fcntl.flock(run, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(store, fcntl.LOCK_EX | fcntl.LOCK_NB)
                directories = {}
                for name in g.BUSINESS[role][1:]:
                    os.mkdir(name, 0o700, dir_fd=store)
                    fd = os.open(name, o.FLAGS | os.O_DIRECTORY, dir_fd=store); owner._fds.append(fd)
                    os.fchown(fd, cold["uid"], cold["gid"]); os.fchmod(fd, 0o700)
                    _persistent(fd); p.require(o.names(fd) == ())
                    # This directory lock belongs to the preparation. Existing
                    # service writers still own their own journal lock files.
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    os.fsync(fd)
                    directories[name] = fd
                path = f"{RUN}/{role}/listener.sock"
                p.require(len(path.encode("ascii")) < 108)
                listener = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                owner._sockets.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                # SO_PASSPIDFD is deliberately not enabled: the ordinary
                # receiver's ancillary grammar is credentials+rights, while
                # its actual peer PIDFD is obtained separately with SO_PEERPIDFD.
                listener.bind(path)
                p.require(stat.S_ISSOCK(os.stat("listener.sock", dir_fd=run, follow_symlinks=False).st_mode))
                os.chown("listener.sock", cold["uid"], owner._client["gid"], dir_fd=run, follow_symlinks=False)
                # The fresh root-owned non-writable directory excludes leaf
                # replacement; do not depend on Python's optional lchmod API.
                os.chmod("listener.sock", 0o660, dir_fd=run)
                named = os.stat("listener.sock", dir_fd=run, follow_symlinks=False)
                p.require(stat.S_ISSOCK(named.st_mode) and stat.S_IMODE(named.st_mode) == 0o660
                    and named.st_uid == cold["uid"] and named.st_gid == owner._client["gid"])
                listener.listen(1)
                for fd in (run, store):
                    os.fsync(fd)
                values = [("run", run), ("store", store), *directories.items(), ("listener", listener.fileno())]
                for _, fd in values:
                    observed = o.structural(os.fstat(fd))[:2]
                    p.require(observed not in identities); identities.add(observed)
                owner._roles[role] = dict(run=run, store=store, directories=directories, listener=listener,
                    path=path, run_identity=o.structural(os.fstat(run)), store_identity=o.structural(os.fstat(store)),
                    socket_identity=o.structural(os.fstat(listener.fileno())),
                    path_identity=o.identity(os.stat("listener.sock", dir_fd=run, follow_symlinks=False)),
                    directory_identities={name: o.structural(os.fstat(fd)) for name, fd in directories.items()})
            os.fsync(owner._run); os.fsync(owner._store)
            launcher._business_resources = owner
            owner.check()
            return owner
        except BaseException:
            owner.close(); raise

    def _check_resources(self):
        # Called by the genuine launch watchdog as well as the operator. Never
        # call launcher.check() recursively from this local resource check.
        p.require(not self._closed and len(self._roles) == 5)
        for original in self._originals:
            original.check()
        for path, fd, expected in zip((RUN, STORE), (self._run, self._store), self._roots):
            _protected(os.fstat(fd))
            p.require(o.structural(os.fstat(fd)) == expected
                and o.structural(os.stat(path, follow_symlinks=False)) == expected
                and o.names(fd) == tuple(sorted(g.ROLES)))
        released = self._inputs is not None and self._inputs._released
        for role, item in self._roles.items():
            cold = self._launcher._configurations[role][1]
            for root, name, fd, expected in ((self._run, role, item["run"], item["run_identity"]),
                    (self._store, role, item["store"], item["store_identity"])):
                _same_name(root, name, fd); _protected(os.fstat(fd))
                p.require(o.structural(os.fstat(fd)) == expected)
            p.require(o.names(item["run"]) == ("listener.sock",)
                and o.names(item["store"]) == tuple(sorted(g.BUSINESS[role][1:])))
            listener = item["listener"]
            p.require(o.structural(os.fstat(listener.fileno())) == item["socket_identity"]
                and o.identity(os.stat("listener.sock", dir_fd=item["run"], follow_symlinks=False)) == item["path_identity"]
                and listener.getsockname() == item["path"] and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                and fcntl.fcntl(listener.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
            for name, fd in item["directories"].items():
                _same_name(item["store"], name, fd)
                info = os.fstat(fd)
                p.require(o.structural(info) == item["directory_identities"][name]
                    and info.st_uid == cold["uid"] and info.st_gid == cold["gid"] and stat.S_IMODE(info.st_mode) == 0o700)
                if not released:
                    p.require(o.names(fd) == ())
        for fd in self._fds:
            p.require(not os.get_inheritable(fd))
        for listener in self._sockets:
            p.require(not os.get_inheritable(listener.fileno()))

    def check(self):
        p.require(not self._closed and self._launcher._business_resources is self)
        self._launcher.check()

    def runtime_inputs(self, role):
        """Actual public observations only; not an approved runtime or peer."""
        self.check(); p.require(role in g.ROLES)
        item = self._roles[role]
        return dict(listenerSocketPath=item["path"], activationDirectoryIdentities={
            name: o.directory_identity(fd) for name, fd in item["directories"].items()})

    def _require_runtime_peer(self, runtime):
        self.check()
        p.require(runtime["expectedPeer"]["uid"] == self._client["uid"]
            and runtime["expectedPeer"]["gid"] == self._client["gid"])
        # Remaining exact peer fields remain independently supplied/admitted;
        # intended C9 IDs do not manufacture an observed final process identity.

    def generation_inputs(self):
        p.require(not self._launcher._commitment)
        return self._inputs_for_profile()

    def commitment_inputs(self):
        p.require(self._launcher._commitment)
        return self._inputs_for_profile()

    def _inputs_for_profile(self):
        self.check(); p.require(not self._taken and threading.current_thread() is threading.main_thread())
        self._taken = True
        descriptors = {role: {"listener": self._roles[role]["listener"].fileno(),
            **self._roles[role]["directories"]} for role in g.ROLES}
        try:
            if self._launcher._commitment:
                from serverware.custody_commitment_inputs import prepare
                inputs = prepare(self._launcher, business_descriptors=descriptors)
            else:
                inputs = GenerationInputs.prepare(self._launcher, business_descriptors=descriptors)
            inputs._business_owner = self
            self._inputs = inputs
            self.check()
            return inputs
        except BaseException:
            self.close(); raise

    def _close_after_reap(self):
        if self._closed:
            return
        p.require(self._launcher._closed and all(item["reaped"] for item in self._launcher._children.values()))
        self._closed = True
        for listener in self._sockets:
            listener.close()
        for fd in reversed(self._fds):
            os.close(fd)
        for original in reversed(self._originals):
            original.close()
        # No unlink/rmdir/reset. Partial or completed outputs need independent
        # reconciliation, not an automatic source-level restart ceremony.

    def close(self):
        p.require(threading.current_thread() is threading.main_thread())
        if self._closed:
            return
        if self._inputs is not None and not self._inputs._closed:
            self._inputs.close()
        else:
            self._launcher.close(); self._close_after_reap()
