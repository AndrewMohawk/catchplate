"""Actual held originals/FD transfer for the explicit driver continuation.

No signing, key generation, decryption, child identity prediction, or resource
creation occurs here. Independent authorities supply their existing originals;
the real resource producers supply actual live activation descriptors.
"""
from __future__ import annotations
import copy
import fcntl
import os
import stat
from serverware import native_shadow_driver_bootstrap as bootstrap

p = bootstrap.p
_TOKEN = object()


def _pin(value):
    value = p.fields(value, ("path", "sha256"))
    p.digest(value["sha256"])
    p.require(type(value["path"]) is str and value["path"].startswith("/"))
    return value


def _record(name, fd):
    s = os.fstat(fd)
    p.require(not os.get_inheritable(fd))
    return dict(name=name, device=s.st_dev, inode=s.st_ino, mode=s.st_mode,
        uid=s.st_uid, gid=s.st_gid, length=s.st_size)


class _Credential:
    """Protected path/FD metadata only: root never reads credential content."""
    def __init__(self, pin, uid, gid, length):
        self.fds, self.parents = [], []
        try:
            path = _pin(pin)["path"]
            p.require(path.isascii() and len(path) <= 4096 and "\0" not in path
                and all(x not in {"", ".", ".."} for x in path.split("/")[1:]))
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            parent = os.open("/", flags | os.O_DIRECTORY); self.fds.append(parent)
            parts = path[1:].split("/")
            for name in parts[:-1]:
                s = os.fstat(parent)
                p.require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, uid) and not s.st_mode & 0o022)
                child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent); self.fds.append(child)
                self.parents.append((parent, name, child, bootstrap.mechanics._structural(os.fstat(child))))
                parent = child
            s = os.fstat(parent)
            p.require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, uid) and not s.st_mode & 0o022)
            self.parent, self.name = parent, parts[-1]
            self.fd = os.open(self.name, flags, dir_fd=parent); self.fds.append(self.fd)
            s = os.fstat(self.fd)
            p.require(stat.S_ISREG(s.st_mode) and (s.st_uid, s.st_gid) == (uid, gid)
                and stat.S_IMODE(s.st_mode) == 0o400 and s.st_nlink == 1 and s.st_size == length)
            self.identity = bootstrap.originals._identity(s)
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, child, identity in self.parents:
            p.require(bootstrap.mechanics._structural(os.fstat(child)) == identity
                and bootstrap.mechanics._structural(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        p.require(bootstrap.originals._identity(os.fstat(self.fd)) == self.identity
            and bootstrap.originals._identity(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity
            and all(not os.get_inheritable(fd) for fd in self.fds))

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class OperationalInputs:
    def __init__(self, token, driver):
        p.require(token is _TOKEN)
        self._driver, self._files, self._activation = driver, [], []
        self._descriptors = {}
        self._begun = self._closed = False
        self._outgoing = None

    def _public(self, name, pin, maximum):
        pin = _pin(pin)
        owner = bootstrap.mechanics._Original(pin["path"], maximum, pin["sha256"])
        self._files.append(owner)
        p.require(name not in self._descriptors)
        self._descriptors[name] = owner.fd
        return owner.raw

    @classmethod
    def prepare(cls, driver, *, launch_pin, activation_fds, production):
        # Original direct inventory caller remains unchanged and does not
        # silently select the new resource creator or spool bridge purpose.
        return cls._prepare(driver, launch_pin=launch_pin, activation_fds=activation_fds,
            production=production, outgoing=None)

    @classmethod
    def prepare_outgoing(cls, driver, *, outgoing, launch_pin, activation_fds, production):
        """Join real allocated sockets/directories to the independently signed C9.

        activation_fds contains only the other actual native/business resources;
        it cannot replace or select this owner's fixed outgoing inventory.
        """
        from serverware.native_shadow_driver_outgoing import OutgoingResources
        p.require(cls is OperationalInputs and type(outgoing) is OutgoingResources
            and outgoing._driver is driver and type(activation_fds) is dict)
        outgoing.check()
        p.require(not outgoing._begun and outgoing._inputs is None
            and not set(activation_fds).intersection(outgoing._descriptors))
        combined = dict(activation_fds)
        combined.update(outgoing._descriptors)
        return cls._prepare(driver, launch_pin=launch_pin, activation_fds=combined,
            production=production, outgoing=outgoing)

    @classmethod
    def _prepare(cls, driver, *, launch_pin, activation_fds, production, outgoing):
        p.require(type(driver) is bootstrap.DriverBootstrap)
        driver.check()
        p.require(driver._config["apiVersion"] in ("serverware.nativeShadowDriverBootstrapConfiguration/v2", "serverware.nativeShadowDriverBootstrapConfiguration/v3", "serverware.nativeShadowDriverBootstrapConfiguration/v4")
            and not driver._attempted and not hasattr(driver, "_prepared_inputs"))
        owner = cls(_TOKEN, driver)
        owner._outgoing = outgoing
        driver._prepared_inputs = owner  # no second preparation/reset for this bootstrap
        try:
            launch = p.fields(p.document(owner._public("launch", launch_pin, 32768), 32768),
                ("apiVersion", "keyAdmission", "trustedTime"))
            allowed = ("serverware.nativeProofBridgeLaunch/v1", "serverware.nativeProofBridgeLaunch/v2")
            p.require(launch["apiVersion"] in allowed
                or (outgoing is not None and launch["apiVersion"] in ("serverware.nativeProofBridgeLaunch/v3",
                    "serverware.nativeProofBridgeLaunch/v4", "serverware.nativeProofBridgeLaunch/v5")))
            inner = p.fields(launch["keyAdmission"], ("apiVersion", "deliveryConfiguration", "delivery", "trust", "timeBootstrap",
                "assignment", "closure", "keys", "encryptedKeys", "admission", "verifierTransport"))
            p.require(inner["apiVersion"] == "serverware.nativeShadowGuestLaunch/v1"
                and inner["deliveryConfiguration"] == driver._config["deliveryConfiguration"])
            cold = p.document(owner._public("c9-configuration", inner["deliveryConfiguration"], 65536), 65536)
            p.require(cold["apiVersion"] == "serverware.policyCustodyGuestConfiguration/v1"
                and cold["serviceRole"] == "production-bridge" and (cold["uid"], cold["gid"]) == (driver._config["uid"], driver._config["gid"]))
            owner._delivery_raw = owner._public("c9-delivery", inner["delivery"], 65536)
            delivery = p.fields(p.document(owner._delivery_raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
            p.require(delivery["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
            payload = delivery["payload"]
            bootstrap._key(cold["authority"]).verify(p.decoded(delivery["signatureBase64url"], size=64),
                b"serverware.policyCustodyGuestDelivery.signature/v1\0" + p.canonical(payload))
            p.require(payload["configurationSha256"] == inner["deliveryConfiguration"]["sha256"]
                and payload["authorityKeyId"] == cold["authority"]["keyId"] and payload["serviceRole"] == cold["serviceRole"]
                and (payload["uid"], payload["gid"]) == (cold["uid"], cold["gid"]))
            for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
                    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId"):
                p.require(payload[name] == driver._window[name])
            owner._runtime_raw = owner._public("c9-runtime", payload["runtimeConfig"], 65536)
            if outgoing is not None:
                outgoing._associate(owner, driver, owner._runtime_raw, launch, payload)
            if driver._config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4":
                p.require(driver._gate_binding is not None)
                gate = driver._gate_binding["binding"]
                expected = p.document(owner._runtime_raw, 65536)["expectedFacadePeer"]
                p.require((expected["pid"], expected["startTimeTicks"], expected["uid"], expected["gid"])
                    == (gate["gateProcessId"], gate["gateStartTimeTicks"], gate["uid"], gate["gid"])
                    and expected["executableSha256"] == driver._gate_binding["gateExecutableSha256"])
            for name, field, bound in (("trust", "trust", 1024 * 1024), ("time", "timeBootstrap", 65536),
                    ("assignment", "assignment", 4 * 1024 * 1024), ("closure", "closure", 1024 * 1024),
                    ("keys", "keys", 65536), ("encrypted", "encryptedKeys", 65536), ("admission", "admission", 65536),
                    ("verifier", "verifierTransport", 32768)):
                owner._public(name, inner[field], bound)
            p.require(inner["verifierTransport"]["path"] == "/etc/serverware/native-shadow-public-exchange.json")
            owner._public("time-grant", launch["trustedTime"], 65536)
            p.require(type(payload["credentials"]) is list and 1 <= len(payload["credentials"]) <= 64)
            total = 0
            for entry in payload["credentials"]:
                p.fields(entry, ("name", "original", "length", "signing"))
                p.require(type(entry["name"]) is str and len(entry["name"]) <= 128)
                length = p.integer(entry["length"]); total += length
                p.require(0 < length <= 4 * 1024 * 1024 and total <= 16 * 1024 * 1024)
                credential = _Credential(entry["original"], cold["uid"], cold["gid"], length)
                owner._files.append(credential)
                name = "credential:" + entry["name"]; p.require(name not in owner._descriptors)
                owner._descriptors[name] = credential.fd
            p.require(type(activation_fds) is dict and type(payload["activation"]) is list
                and 1 <= len(payload["activation"]) <= 64
                and set(activation_fds) == {v["name"] for v in payload["activation"]})
            for index, entry in enumerate(payload["activation"]):
                p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
                p.require(entry["fd"] == index + 6 and type(activation_fds[entry["name"]]) is int)
                fd = fcntl.fcntl(activation_fds[entry["name"]], fcntl.F_DUPFD_CLOEXEC, 128)
                owner._activation.append(fd)
                name = "activation:" + entry["name"]
                record = _record(name, fd)
                p.require(all(record[key] == entry[key] for key in ("device", "inode", "mode", "uid", "gid"))
                    and stat.S_IFMT(record["mode"]) in (stat.S_IFSOCK, stat.S_IFDIR) and name not in owner._descriptors)
                owner._descriptors[name] = fd
            production = p.fields(copy.deepcopy(production), ("signerBackendSha256", "persistenceBackendSha256", "retrievalBackendSha256",
                "dispatcherProtocolSetSha256", "maximumRpcNanos", "cleanupReserveNanos", "maximumInFlightCalls", "maximumAsyncDurabilityNanos",
                "expectedConfigurationBindingSha256"))
            for name in ("signerBackendSha256", "persistenceBackendSha256", "retrievalBackendSha256", "dispatcherProtocolSetSha256", "expectedConfigurationBindingSha256"):
                p.digest(production[name])
            for name in ("maximumRpcNanos", "cleanupReserveNanos", "maximumInFlightCalls", "maximumAsyncDurabilityNanos"):
                p.require(p.integer(production[name]) > 0)
            records = [_record(name, fd) for name, fd in sorted(owner._descriptors.items())]
            p.require(len(records) <= 94 and len({(v["device"], v["inode"]) for v in records}) == len(records))
            owner._records = records
            owner._operation = p.canonical(dict(apiVersion="serverware.nativeShadowDriverOperation/v1",
                launch=copy.deepcopy(_pin(launch_pin)), descriptors=records, production=production))
            owner.check(); driver.check()
            return owner
        except BaseException:
            owner._close_unreleased()
            raise

    def check(self):
        p.require(not self._closed)
        self._driver._origin()  # never recursively calls DriverBootstrap.check
        for original in self._files:
            original.check()
        if self._outgoing is not None:
            self._outgoing.check()
        p.require([_record(name, fd) for name, fd in sorted(self._descriptors.items())] == self._records)

    def operation_original(self):
        self.check(); p.require(not self._begun)
        return bytes(self._operation)  # data for the independent phase-two signer

    def _begin(self, driver):
        self.check(); p.require(driver is self._driver and not self._begun)
        if self._outgoing is not None:
            self._outgoing._begin(self)
        self._begun = True
        return tuple(fd for _, fd in sorted(self._descriptors.items()))

    def _close_unreleased(self):
        p.require(not self._begun)
        self._close()

    def _close_after_exit(self, driver):
        p.require(driver is self._driver and (driver._child_pid is None or bootstrap.mechanics._terminal(driver._pidfd)))
        self._close()

    def _close(self):
        if self._closed:
            return
        for fd in reversed(self._activation):
            os.close(fd)
        for original in reversed(self._files):
            original.close()
        if self._outgoing is not None:
            if self._outgoing._inputs is self:
                self._outgoing._close_after_exit(self)
            else:
                p.require(not self._outgoing._begun and self._outgoing._inputs is None)
                self._outgoing._close()
        self._closed = True
