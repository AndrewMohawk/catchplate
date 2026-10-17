"""Purpose-key custody attached to an actual measured authority process.

No public signing API is provided. Loading a key does not admit a reviewer,
execute a transition, or prove commit. The private service continuations must
perform those operations before borrowing the matching key. In particular the
commit key is not the executor's generic response key.

Absent policy preserves old launches without reading a new descriptor. New
keys require their separately pinned, retained, read-only cold descriptors and
native stage-zero admission; a trusted-host-local launch cannot select them.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
import stat
import threading

from cryptography.hazmat.primitives import serialization

from catchplate import authority_native_jit_review_open_custody as custody


_SLOTS = {
    "planner": ("authorizerKey", "CATCHPLATE_NATIVE_JIT_REVIEW_AUTHORIZER_KEY"),
    "executor": ("commitOwnerKey", "CATCHPLATE_NATIVE_JIT_REVIEW_COMMIT_KEY"),
}
_LOCK = threading.RLock()
_OWNERS = {}


class ReviewSignerError(RuntimeError):
    def __init__(self):
        super().__init__("Native review purpose signer is unavailable")


def _require(value):
    if not value:
        raise ReviewSignerError()


def _metadata(descriptor):
    value = os.fstat(descriptor)
    _require(stat.S_ISREG(value.st_mode) and value.st_uid == 0
        and stat.S_IMODE(value.st_mode) == 0o400 and value.st_nlink in (0, 1)
        and 0 < value.st_size <= 64 * 1024
        and fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
    if value.st_nlink == 0:
        # Anonymous delivery must be an immutable sealed memfd, not an
        # unlinked ordinary file still writable through another handle.
        required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        _require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required == required)
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _descriptor(environment, retained):
    text = os.environ.get(environment + "_FD", "")
    _require(type(text) is str and text.isascii() and text.isdecimal()
        and len(text) <= 10 and str(int(text)) == text and int(text) >= 3
        and not os.environ.get(environment + "_PATH", ""))
    descriptor = int(text)
    _require(descriptor in retained)
    return descriptor


def _public_bytes(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(slots=True, repr=False, eq=False)
class _Held:
    process: object
    configuration: object
    configuration_original: bytes
    configuration_digest: str
    root_public_bytes: bytes
    generation: dict
    role: str
    pid: int
    uid: int
    gid: int
    descriptor: int
    descriptor_identity: tuple
    environment: str
    private: object
    failed: bool = False

    def check(self):
        from catchplate import authority_service as service
        from catchplate import authority_launch_guard as launch

        try:
            _require(not self.failed and _OWNERS.get(self.process) is self
                and type(self.process) is service.AuthorityProcess
                and self.process.configuration is self.configuration
                and self.process.role_name == self.role
                and self.process.process_mode == "policy-authority-" + self.role
                and (os.getpid(), os.getuid(), os.getgid()) == (self.pid, self.uid, self.gid))
            launch.require_active(self.role)
            assurance = launch.launch_assurance()
            _require(assurance.get("trustMode") in ("external-production", "tee-hardware")
                and assurance.get("nativeStageZero") is True
                and dict(launch.generation()) == self.generation
                and self.configuration.digest == self.configuration_digest
                and _public_bytes(self.configuration.root_key) == self.root_public_bytes
                and service._canonical(self.configuration.payload) == self.configuration_original
                and _descriptor(self.environment, launch.retained_descriptors()) == self.descriptor
                and _metadata(self.descriptor) == self.descriptor_identity)
        except BaseException:
            self.failed = True
            raise ReviewSignerError() from None


def initialize(process):
    """Called once by genuine AuthorityProcess startup after launch admission."""
    from catchplate import authority_service as service
    from catchplate import authority_launch_guard as launch

    with _LOCK:
        _require(type(process) is service.AuthorityProcess
            and type(process.configuration) is service.MeasuredConfiguration
            and process not in _OWNERS)
        role, configuration = process.role_name, process.configuration
        policy = configuration.payload.get(custody.FIELD)
        slot = _SLOTS.get(role) if policy is not None else None
        for candidate in _SLOTS.values():
            if candidate != slot:
                _require(not any(os.environ.get(candidate[1] + suffix, "")
                    for suffix in ("_FD", "_PATH")))
        if slot is None:
            return
        launch.require_active(role)
        assurance = launch.launch_assurance()
        _require(assurance.get("trustMode") in ("external-production", "tee-hardware")
            and assurance.get("nativeStageZero") is True)
        field, environment = slot
        # Configuration.load already authenticated the root-selected policy;
        # take immutable pins before opening the purpose key descriptor.
        configuration_original = service._canonical(configuration.payload)
        configuration_digest = configuration.digest
        root_public_bytes = _public_bytes(configuration.root_key)
        public = custody.purpose_key(policy[field])
        generation = dict(launch.generation())
        descriptor = _descriptor(environment, launch.retained_descriptors())
        metadata = _metadata(descriptor)
        private = service._load_ed25519_private_key(
            service._read_descriptor_original(descriptor, 64 * 1024))
        _require(_public_bytes(private.public_key()) == _public_bytes(public)
            and _metadata(descriptor) == metadata)
        held = _Held(process, configuration, configuration_original, configuration_digest,
            root_public_bytes, generation, role,
            os.getpid(), os.getuid(), os.getgid(), descriptor, metadata, environment, private)
        _OWNERS[process] = held
        try:
            held.check()
        except BaseException:
            del _OWNERS[process]
            raise


@contextmanager
def _borrow(process, *, purpose):
    """Internal fixed-role key use; never a reviewed/committed result carrier."""
    role = {"authorize": "planner", "committed-disclosure": "executor"}.get(purpose)
    with _LOCK:
        held = _OWNERS.get(process)
        _require(role is not None and held is not None and held.role == role)
        held.check()
        try:
            yield held.private
        finally:
            held.check()
