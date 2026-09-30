"""Purpose-fixed TrustedTime listener preparation and original C9 handoff.

No clock, key, assignment or peer identity is invented. A separate independent
operator must authorize the actual parked peers before signing/release.
"""
from __future__ import annotations

import re
import fcntl
import os
import socket
import stat
import time

from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_artifacts as artifacts
from serverware import native_shadow_key_admission_profile as admission
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from serverware.native_shadow_retrieval_store import READ_FLAGS, _identity

p = delivery.p
SOCKET_PATH = "/run/serverware-shadow-trusted-time/listener.sock"
_TOKEN = object()


def _structural(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class TrustedTimeActivation:
    """Retains actual originals; serialized projections cannot construct one."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._parents = [], []
        self._socket = None
        self._closed = self._sign_attempted = self._taken = False
        self._signed = None

    @classmethod
    def prepare(cls, *, configuration_raw, configuration_sha256, peer_raw, peer_sha256,
                startup_deadline_boottime_ns):
        p.require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
        cold = delivery.configuration(configuration_raw, configuration_sha256)
        peer = artifacts._peer(peer_raw)
        p.require(p.sha(peer_raw) == p.digest(peer_sha256) and peer["uid"] != cold["uid"])
        deadline = p.ns(startup_deadline_boottime_ns)
        p.require(_clock() < deadline <= _clock() + 30_000_000_000)
        owner = cls(_TOKEN)
        try:
            owner._pid, owner._start, owner._boot = os.getpid(), originals._start(), originals._boot()
            owner._deadline, owner._configuration_raw = deadline, configuration_raw
            owner._configuration_sha256, owner._uid, owner._peer_gid = configuration_sha256, cold["uid"], peer["gid"]
            parent = os.open("/", READ_FLAGS | os.O_DIRECTORY)
            owner._fds.append(parent)
            for component in ("run", "serverware-shadow-trusted-time"):
                info = os.fstat(parent)
                p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
                child = os.open(component, READ_FLAGS | os.O_DIRECTORY, dir_fd=parent)
                owner._fds.append(child)
                owner._parents.append((parent, component, child, _structural(os.fstat(child))))
                parent = child
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
            owner._path_directory = parent
            # This advisory lock serializes cooperating preparations only; the
            # protected directory and exclusive kernel bind remain mandatory.
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.stat("listener.sock", dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("trusted-time listener already exists; reconciliation required")
            owner._socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
            owner._socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner._socket.setsockopt(socket.SOL_SOCKET, 76, 1)  # mandatory Linux SO_PASSPIDFD
            owner._socket.bind(SOCKET_PATH)
            os.chown("listener.sock", owner._uid, owner._peer_gid, dir_fd=parent, follow_symlinks=False)
            os.chmod("listener.sock", 0o660, dir_fd=parent, follow_symlinks=False)
            owner._path_identity = _identity(os.stat("listener.sock", dir_fd=parent, follow_symlinks=False))
            p.require(stat.S_ISSOCK(owner._path_identity[2]) and stat.S_IMODE(owner._path_identity[2]) == 0o660
                and owner._path_identity[3:5] == (owner._uid, owner._peer_gid))
            owner._socket_identity = _identity(os.fstat(owner._socket.fileno()))
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def check(self):
        p.require(not self._closed and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and _clock() < self._deadline)
        for parent, component, child, expected in self._parents:
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0
                and _structural(os.fstat(child)) == expected
                and _structural(os.stat(component, dir_fd=parent, follow_symlinks=False)) == expected)
        p.require(_identity(os.stat("listener.sock", dir_fd=self._path_directory, follow_symlinks=False)) == self._path_identity
            and _identity(os.fstat(self._socket.fileno())) == self._socket_identity
            and self._socket.getsockname() == SOCKET_PATH
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
            and self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and self._socket.getsockopt(socket.SOL_SOCKET, 76) == 1
            and fcntl.fcntl(self._socket.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
        for fd in (self._socket.fileno(),):
            p.require(not os.get_inheritable(fd))

    def activation(self):
        self.check()
        entries = []
        for target, (name, fd) in enumerate((("trusted-time-listener", self._socket.fileno()),), 6):
            info = os.fstat(fd)
            entries.append({"name": name, "fd": target, "device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid})
        self.check()
        return entries

    def sign_delivery(self, *, payload_raw, signing_key):
        self.check()
        p.require(not self._sign_attempted and not self._taken)
        self._sign_attempted = True
        signed = _sign_delivery(configuration_raw=self._configuration_raw,
            configuration_sha256=self._configuration_sha256, payload_raw=payload_raw, signing_key=signing_key,
            activation=self.activation(), boot=self._boot, startup_deadline=self._deadline, now=_clock())
        self.check()
        self._signed = signed
        return signed

    def take_for_launch(self, *, signed_delivery_sha256):
        """One ownership transfer of actual dup FDs; caller owns successful FDs.

        Target6 must be installed by the separately supervised launcher. No
        descriptor number, tuple or returned signature proves that launch ran.
        """
        self.check()
        p.require(not self._taken and self._signed is not None
            and p.sha(self._signed) == p.digest(signed_delivery_sha256))
        self._taken = True
        owned = []
        try:
            for fd in (self._socket.fileno(),):
                owned.append(fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128))
            self.check()
            return ((6, owned[0]),)
        except BaseException:
            for fd in owned:
                os.close(fd)
            raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._socket is not None:
            self._socket.close()
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        # Intentionally no unlink/rmdir, including failed preparation.

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        self.close()


def _sign_delivery(*, configuration_raw, configuration_sha256, payload_raw, signing_key,
                            activation, boot, startup_deadline, now):
    """Sign exact approved bytes; observed activation arguments are data only.

    The actual retained activation owner supplies these observations. Native
    admission independently verifies every original descriptor and credential.
    This function by itself does not assert that any runtime owner exists.
    """
    cold = delivery.configuration(configuration_raw, configuration_sha256)
    payload = p.fields(p.document(payload_raw, delivery.MAX_DELIVERY), delivery.FIELDS)
    p.require(payload["configurationSha256"] == configuration_sha256
        and payload["authorityKeyId"] == cold["authority"]["keyId"]
        and all(payload[name] == cold[name] for name in ("serviceRole", "uid", "gid")))
    delivery._pin(payload["runtimeConfig"])
    p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
    p.integer(payload["timeNamespaceDevice"]); p.integer(payload["timeNamespaceInode"])
    p.require(type(payload["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", payload["invocationId"])
        and payload["invocationId"] != "0" * 32)
    issued, startup, lifetime = (p.ns(payload[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= now < startup <= lifetime and startup == startup_deadline
        and startup - issued <= 30_000_000_000
        and (payload["bootIdBase64url"], payload["timeNamespaceDevice"], payload["timeNamespaceInode"]) == boot)
    p.require(type(activation) is list and len(activation) == 1 and payload["activation"] == activation)
    for index, (entry, name) in enumerate(zip(activation, ("trusted-time-listener",)), 6):
        p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(entry["name"] == name and entry["fd"] == index)
        p.integer(entry["device"], minimum=0); p.integer(entry["inode"])
        p.integer(entry["mode"], maximum=(1 << 32) - 1)
        for field in ("uid", "gid"):
            p.integer(entry[field], minimum=0, maximum=(1 << 32) - 1)
    credentials = payload["credentials"]
    p.require(type(credentials) is list and 1 <= len(credentials) <= 64)
    names, total = set(), 0
    for entry in credentials:
        p.fields(entry, ("name", "original", "length", "signing"))
        name = entry["name"]
        p.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) and name not in names)
        names.add(name)
        delivery._pin(entry["original"])
        total += p.integer(entry["length"], maximum=4 * 1024 * 1024)
        if entry["signing"] is not None:
            assigned = p.fields(entry["signing"], ("publicKeyBase64url", "keyId"))
            public = p.decoded(assigned["publicKeyBase64url"], size=32)
            p.digest(assigned["keyId"])
            p.require(entry["length"] == 32 and public != bytes(32)
                and assigned["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
                and assigned["keyId"] != cold["authority"]["keyId"])
            Ed25519PublicKey.from_public_bytes(public)
    p.require(total <= 16 * 1024 * 1024 and isinstance(signing_key, Ed25519PrivateKey))
    actual = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(actual) == cold["authority"]["publicKeyBase64url"])
    signature = signing_key.sign(delivery.DOMAIN + payload_raw)
    signing_key.public_key().verify(signature, delivery.DOMAIN + payload_raw)
    result = p.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1",
        "payload": payload, "signatureBase64url": p.encoded(signature)})
    p.require(len(result) <= delivery.MAX_DELIVERY)
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in
        {"deliverySha256", "runtimeConfigurationSha256"}}
    guest.update(deliverySha256=p.sha(result), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    p.guest(guest)
    return result

GRANT_DOMAIN = "serverware.nativeShadowTrustedTimeServiceAssignment.signature/v1"


def sign_service_grant(*, configuration_original, configuration_sha256,
                       bootstrap_original, bootstrap_sha256, peer_original, peer_sha256,
                       issued_at, expires_at, now, signing_key):
    """Sign independently approved originals with the existing supervisor key.

    The signer checks actual independently pinned full18 authorization. The
    native service independently repeats authority/currentness and clock checks.
    These bytes are not a measured runtime owner or an attestation result.
    """
    p.require(type(configuration_original) is bytes and 1 <= len(configuration_original) <= p.MAX_CONFIG
        and type(bootstrap_original) is bytes and 1 <= len(bootstrap_original) <= 65536
        and type(peer_original) is bytes and 1 <= len(peer_original) <= 4096)
    p.require(p.sha(configuration_original) == p.digest(configuration_sha256)
        and p.sha(bootstrap_original) == p.digest(bootstrap_sha256)
        and p.sha(peer_original) == p.digest(peer_sha256))
    configuration = p.document(configuration_original, p.MAX_CONFIG)
    admitted, keys = admission.authorization(configuration, now)
    bootstrap = p.fields(p.document(bootstrap_original, 65536),
        ("apiVersion", "guest", "signingKeyId", "parentPort", "maximumBracketNanos",
         "timestampErrorNanos", "maximumClockRateErrorPpm"))
    p.require(bootstrap["apiVersion"] == "serverware.nativeShadowGuestTimeBootstrap/v1"
        and bootstrap["guest"] == admitted["guest"])
    p.guest(bootstrap["guest"])
    p.digest(bootstrap["signingKeyId"])
    p.integer(bootstrap["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    p.require(p.ns(bootstrap["maximumBracketNanos"]) <= 1_000_000_000)
    p.integer(bootstrap["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
    p.integer(bootstrap["maximumClockRateErrorPpm"], minimum=0, maximum=10_000)
    peer = artifacts._peer(peer_original)
    guest = admitted["guest"]
    p.require(guest["serviceRole"] == "production-bridge" and guest["uid"] != peer["uid"]
        and "custody-trusted-time-response" in configuration["authorization"]["payload"]["localRoles"])
    p.freshness(issued_at, expires_at, now)
    p.require(expires_at <= min(configuration[name]["payload"]["expiresAtUnixNanos"]
        for name in ("authorization", "admissionAuthorization")))
    supervisor = keys[-1]
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == supervisor["publicKeyBase64url"]
        and bootstrap["signingKeyId"] not in {key["keyId"] for key in keys})
    checkpoint = configuration["trustCheckpoint"]
    payload = {"apiVersion": "serverware.nativeShadowTrustedTimeServiceAssignment/v1",
        "purpose": "native-shadow-trusted-time-response", "guest": guest,
        "assignmentPayloadSha256": admitted["assignmentPayloadSha256"],
        "keyAuthorizationSha256": admitted["keyAuthorizationSha256"],
        "clockBootstrapSha256": bootstrap_sha256, "expectedPeer": peer,
        "trustCheckpointId": checkpoint["checkpointId"], "revocationGeneration": checkpoint["revocationGeneration"],
        "revocationRootSha256": checkpoint["revocationRootSha256"], "issuedAtUnixNanos": issued_at,
        "expiresAtUnixNanos": expires_at, "signingKeyId": supervisor["keyId"],
        "signingKeySpkiSha256": supervisor["keySpkiSha256"]}
    signature = signing_key.sign(p.preimage(GRANT_DOMAIN, payload))
    p.public_key(supervisor).verify(signature, p.preimage(GRANT_DOMAIN, payload))
    result = p.canonical({"payload": payload, "signature": p.encoded(signature)})
    p.require(len(result) <= 65536)
    return result
