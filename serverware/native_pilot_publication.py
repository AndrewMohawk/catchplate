"""Exclusive publication of source-fixed native-pilot public originals.

The independent operator supplies the exact original and its approved hash.
Closed shape and byte-integrity checks are not signature verification: actual
cohort/driver consumers still authenticate the original authority and lifetime.
No root creation, replacement, adoption, repair, deletion or retry is provided.
Blocking filesystem calls require an independently operated process watchdog.
"""
from __future__ import annotations

import os
import re
import stat
import threading

from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_proof_cohort_assignment as cohort
from serverware import native_pilot_publication_profiles as profiles
from serverware.native_shadow_proof_cohort_control import _Original

MAX_BYTES = 16 * 1024 * 1024  # Largest versioned public bundle; other per-purpose bounds are unchanged.
MAX_ORIGINALS = 128
MAX_PUBLIC_BYTES = 32 * 1024 * 1024
DESTINATIONS = {
    "cohort-precreation": "/etc/serverware/native-shadow-proof-cohort-precreation.json",
    "cohort-release": "/etc/serverware/native-pilot-inputs/cohort-release.json",
    "driver-scope": "/etc/serverware/native-pilot-inputs/driver-scope.json",
    **profiles.DESTINATIONS,
}
LIMITS = {purpose: profiles.PROFILES[purpose][2] if purpose in profiles.PROFILES else 32768
          for purpose in DESTINATIONS}
_ROOTS = ("/", "/etc", "/etc/serverware", "/etc/serverware/native-pilot-inputs")
_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
_ORDINARY = ("bounded-cleanup-helper", "cleanup-authorization-consumer", "current-signature-authority",
             "durable-recovery-store", "recovery-target-provider")
_SCOPE = ("apiVersion", "configurationSha256", "windowSha256", "observationSha256",
          "kernelDriverIdentitySha256", "invocationId", "startupDeadlineBoottimeNs",
          "lifetimeDeadlineBoottimeNs", "originals", "publicBundleSha256", "signingKeyId", "operation")


def _invocation(value):
    p.require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None
              and value != "0" * 32)


def _operation(value):
    """Closed public grammar only; no descriptor or production authority."""
    p.fields(value, ("apiVersion", "launch", "descriptors", "production"))
    p.require(value["apiVersion"] == "serverware.nativeShadowDriverOperation/v1")
    delivery._pin(value["launch"])
    descriptors = value["descriptors"]
    p.require(type(descriptors) is list and 1 <= len(descriptors) <= 94)
    names, identities = [], set()
    for item in descriptors:
        p.fields(item, ("name", "device", "inode", "mode", "uid", "gid", "length"))
        name = item["name"]
        p.require(type(name) is str and name.isascii() and 1 <= len(name) <= 256)
        names.append(name)
        for field in ("device", "inode", "length"):
            p.integer(item[field], minimum=0, maximum=p.MAX_U64)
        for field in ("mode", "uid", "gid"):
            p.integer(item[field], minimum=0, maximum=(1 << 32) - 1)
        pair = (item["device"], item["inode"])
        p.require(pair not in identities)
        identities.add(pair)
    p.require(names == sorted(set(names)))
    production = p.fields(value["production"], ("signerBackendSha256", "persistenceBackendSha256",
        "retrievalBackendSha256", "dispatcherProtocolSetSha256", "maximumRpcNanos", "cleanupReserveNanos",
        "maximumInFlightCalls", "maximumAsyncDurabilityNanos", "expectedConfigurationBindingSha256"))
    for field in ("signerBackendSha256", "persistenceBackendSha256", "retrievalBackendSha256",
                  "dispatcherProtocolSetSha256", "expectedConfigurationBindingSha256"):
        p.digest(production[field])
    p.integer(production["maximumRpcNanos"], minimum=250_000_000, maximum=1_000_000_000)
    p.integer(production["cleanupReserveNanos"], maximum=5_000_000_000)
    p.integer(production["maximumInFlightCalls"], maximum=64)
    p.integer(production["maximumAsyncDurabilityNanos"], maximum=production["maximumRpcNanos"])


def _shape(purpose, raw):
    if purpose in profiles.PROFILES:
        profiles.shape(purpose, raw)
        return
    signed = p.document(raw, LIMITS[purpose])  # Exact canonical ASCII, no terminal LF.
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url")
             if purpose == "cohort-precreation" else ("payload", "signatureBase64url"))
    p.decoded(signed["signatureBase64url"], size=64)
    value = signed["payload"]
    if purpose == "cohort-precreation":
        p.require(signed["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
        p.fields(value, cohort.WINDOW_FIELDS)
        p.digest(value["configurationSha256"])
        p.digest(value["authorityKeyId"])
        p.require(p.decoded(value["bootIdBase64url"], size=16) != bytes(16))
        for field in ("timeNamespaceDevice", "timeNamespaceInode"):
            p.integer(value[field], maximum=p.MAX_U64)
        issued, startup, lifetime = (p.ns(value[field]) for field in
            ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
        p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000)
    elif purpose == "cohort-release":
        adopted = value.get("apiVersion") == "serverware.nativeShadowProofCohortRelease/v7"
        roles = cohort.ADOPTED_ENDPOINT_ROLES if adopted else cohort.ENDPOINT_ROLES
        p.fields(value, ("apiVersion", "configurationSha256", "precreationSha256", "observationSha256",
            "invocationId", "signingKeyId", "externalDriverSha256") + roles)
        p.require(adopted or value["apiVersion"] == "serverware.nativeShadowProofCohortRelease/v6")
        for field in ("configurationSha256", "precreationSha256", "observationSha256",
                      "signingKeyId", "externalDriverSha256"):
            p.digest(value[field])
        for role in roles:
            row = p.fields(value[role], ("launch", "image"))
            delivery._pin(row["launch"])
            delivery._pin(row["image"])
    else:
        p.require(purpose == "driver-scope")
        p.fields(value, _SCOPE)
        p.require(value["apiVersion"] == "serverware.nativeShadowDriverScope/v4")
        for field in ("configurationSha256", "windowSha256", "observationSha256",
                      "kernelDriverIdentitySha256", "publicBundleSha256", "signingKeyId"):
            p.digest(value[field])
        p.require(p.ns(value["startupDeadlineBoottimeNs"]) <= p.ns(value["lifetimeDeadlineBoottimeNs"]))
        pins = p.fields(value["originals"], ("runtimeSha256", "deliverySha256", "generationGrants"))
        p.digest(pins["runtimeSha256"])
        p.digest(pins["deliverySha256"])
        for digest in p.fields(pins["generationGrants"], _ORDINARY).values():
            p.digest(digest)
        _operation(value["operation"])
    _invocation(value["invocationId"])


def _structural(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _file_identity(info):
    return _structural(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _protected(info):
    p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
              and info.st_mode & 0o022 == 0)


class PublicPublisher:
    """One-use purpose slots, retaining every published original and ancestor."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid = os.getpid()
        self._roots, self._files, self._pending = {}, {}, []
        self._attempted = set()
        self._bytes = 0
        self._closed = self._failed = False

    @classmethod
    def open(cls):
        p.require(cls is PublicPublisher)
        owner = cls(_TOKEN)
        try:
            owner._origin()
            for path in _ROOTS:
                if path == "/":
                    descriptor = os.open(path, _FLAGS | os.O_DIRECTORY)
                else:
                    parent, name = path.rsplit("/", 1)
                    descriptor = os.open(name, _FLAGS | os.O_DIRECTORY,
                                         dir_fd=owner._roots[parent or "/"][0])
                owner._pending.append(descriptor)
                info = os.fstat(descriptor)
                _protected(info)
                owner._roots[path] = (descriptor, _structural(info))
                owner._pending.remove(descriptor)
            owner.check()
            return owner
        except BaseException:
            owner.close()
            raise

    def _origin(self):
        p.require(not self._closed and not self._failed and os.getpid() == self._pid
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def check(self):
        self._origin()
        for path, (descriptor, expected) in self._roots.items():
            actual = os.fstat(descriptor)
            _protected(actual)
            if path == "/":
                named = os.stat(path, follow_symlinks=False)
            else:
                parent, name = path.rsplit("/", 1)
                named = os.stat(name, dir_fd=self._roots[parent or "/"][0], follow_symlinks=False)
            p.require(_structural(actual) == expected == _structural(named)
                      and not os.get_inheritable(descriptor))
        p.require(len(self._files) <= MAX_ORIGINALS
            and self._bytes == sum(len(original.raw) for original in self._files.values())
            and self._bytes <= MAX_PUBLIC_BYTES)
        for original in self._files.values():
            original.check()

    def publish(self, *, purpose, raw, expected_sha256):
        return self._publish(purpose=purpose, raw=raw, expected_sha256=expected_sha256, adopted=False)

    def publish_adopted(self, *, purpose, raw, expected_sha256):
        """Separate source-fixed adopted slots; never widens legacy publish."""
        return self._publish(purpose=purpose, raw=raw, expected_sha256=expected_sha256, adopted=True)

    def _publish(self, *, purpose, raw, expected_sha256, adopted):
        from serverware import native_pilot_launch_publication as launch
        destinations = launch.ADOPTED_DESTINATIONS if adopted else DESTINATIONS
        limits = launch.ADOPTED_PURPOSES if adopted else LIMITS
        self.check()
        p.require(type(purpose) is str and purpose in destinations and purpose not in self._attempted)
        self._attempted.add(purpose)  # Consumed before validation or any write.
        try:
            maximum = limits[purpose]
            p.require(type(raw) is bytes and 0 < len(raw) <= maximum
                and len(self._files) < MAX_ORIGINALS and self._bytes + len(raw) <= MAX_PUBLIC_BYTES)
            p.require(p.sha(raw) == p.digest(expected_sha256))
            (launch.shape_adopted if adopted else _shape)(purpose, raw)
            self.check()
            path = destinations[purpose]
            parent, name = path.rsplit("/", 1)
            parent_fd = self._roots[parent][0]
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                                 | os.O_NOFOLLOW, 0o400, dir_fd=parent_fd)
            self._pending.append(descriptor)
            info = os.fstat(descriptor)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
                and info.st_nlink == 1 and info.st_size == 0)
            os.fchmod(descriptor, 0o400)  # Only this newly created file.
            offset = 0
            while offset < len(raw):
                written = os.pwrite(descriptor, raw[offset:], offset)
                p.require(written > 0)
                offset += written
            os.fsync(descriptor)
            p.require(os.pread(descriptor, maximum + 1, 0) == raw)
            written_identity = os.fstat(descriptor)
            p.require(stat.S_IMODE(written_identity.st_mode) == 0o400
                and written_identity.st_nlink == 1 and written_identity.st_size == len(raw)
                and _file_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
                == _file_identity(written_identity))
            os.close(descriptor)
            self._pending.remove(descriptor)
            os.fsync(parent_fd)
            # Existing reader owns the exact protected file, bytes, hash and
            # all named ancestors. Keep only its read-only descriptors.
            original = _Original(path, maximum, expected_sha256, mode=0o400)
            self._files[purpose] = original
            self._bytes += len(raw)
            p.require(original.raw == raw and _file_identity(os.fstat(original.fd))
                      == _file_identity(written_identity))
            self.check()
            return {"path": path, "sha256": expected_sha256}
        except BaseException:
            self._failed = True
            # The name is deliberately retained even after a partial write.
            # No overwrite, unlink or implicit second publication is allowed.
            for descriptor in self._pending:
                os.close(descriptor)
            self._pending.clear()
            raise

    def require_absent(self, purposes):
        """Preflight a fixed bundle before writes; O_EXCL still decides races.

        This reserves no name and approves no input. A later concurrent create
        can still leave a partial bundle, which must never be retried or rolled
        back automatically. Existing objects are neither read nor adopted.
        """
        return self._require_absent(purposes, adopted=False)

    def require_absent_adopted(self, purposes):
        return self._require_absent(purposes, adopted=True)

    def _require_absent(self, purposes, *, adopted):
        from serverware import native_pilot_launch_publication as launch
        destinations = launch.ADOPTED_DESTINATIONS if adopted else DESTINATIONS
        self.check()
        p.require(type(purposes) is tuple and 0 < len(purposes) <= MAX_ORIGINALS
            and all(type(purpose) is str and purpose in destinations for purpose in purposes)
            and len(set(purposes)) == len(purposes)
            and not self._attempted.intersection(purposes))
        for purpose in purposes:
            parent, name = destinations[purpose].rsplit("/", 1)
            try:
                os.stat(name, dir_fd=self._roots[parent][0], follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("native pilot publication destination already exists")
        self.check()

    def close(self):
        """Release only this publisher's descriptors; never remove originals."""
        if self._closed:
            return
        p.require(os.getpid() == self._pid and threading.current_thread() is threading.main_thread())
        self._closed = True
        for descriptor in self._pending:
            os.close(descriptor)
        self._pending.clear()
        for original in self._files.values():
            original.close()
        self._files.clear()
        for descriptor, _ in reversed(tuple(self._roots.values())):
            os.close(descriptor)
        self._roots.clear()
