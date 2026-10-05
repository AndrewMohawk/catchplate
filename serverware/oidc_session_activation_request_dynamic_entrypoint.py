"""One freshly staged activation planner per cold process, without file replacement.

The external socket owner retains both listeners across independent processes.
This process accepts one root staging exchange, seals actual originals, opens
private resources only after admission, and drops permanently to the genuine
planner. Its ACK is not readiness, currentness, SQL or a retry instruction.
"""
from __future__ import annotations

import fcntl
import os
import select
import socket
import stat
import threading
import time
from types import MethodType

from serverware import authority_fd_entrypoint as native
from serverware import current_root_state_entrypoint as inventory
from serverware import oidc_session_activation_planner_entrypoint as fixed
from serverware import oidc_session_activation_release_entrypoint as ownership
from serverware import authority_oidc_session_activation_request_issuance as issuance
from serverware import authority_oidc_session_activation_request_staging_transport as transport


TRUST_PATH = "/run/serverware/oidc-session-activation-request-issuance-trust"
ROOT_PATH, POLICY_PATH = TRUST_PATH + "/root-public-key.pem", TRUST_PATH + "/policy.json"
_PUBLIC = {ROOT_PATH: fixed.MAX_ROOT_BYTES, POLICY_PATH: issuance.policy.MAX_BYTES}
MAX_ORIGINAL_BYTES = issuance.policy.authority.MAX_RESULT_BYTES
ENVIRONMENT = {"PATH": "/runtime/python/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "TZ": "UTC",
    "LD_LIBRARY_PATH": "/runtime/python/lib", "PYTHONDONTWRITEBYTECODE": "1",
    "SERVERWARE_PROCESS_MODE": fixed.PROCESS_MODE,
    fixed.ROOT_ENV: str(fixed.ROOT_FD), fixed.BOOTSTRAP_ENV: str(fixed.BOOTSTRAP_FD)}
_PID, _THREAD, _used, _continuation = os.getpid(), threading.get_ident(), False, None


class _Lifetime:
    """Restrictive clock/ledger continuity; never an admission input."""

    def __init__(self, work):
        self.work, self.limits, self.metrics = work, work.limits, work.metrics
        self.ceilings = (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes)
        before, epoch, after = issuance.policy.clock._sample_on_work(work)
        age, skew = (issuance.policy.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            issuance.policy.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
        self.window = issuance.policy.clock._validate((epoch, before, after,
            epoch + age, before + age, age, skew))
        self.bound, self.epoch, self.monotonic = self.window[4], epoch, after
        self.interval = None

    def current(self):
        issuance.capture._SharedLedger(self.work)
        now = self.work.metrics
        if (self.work.limits is not self.limits
                or self.ceilings != (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
                or any(a < b for a, b in zip((now.hash_work, now.input_bytes, now.json_nodes),
                    (self.metrics.hash_work, self.metrics.input_bytes, self.metrics.json_nodes)))):
            raise RuntimeError("activation dynamic work allowance changed")
        self.metrics = now
        epoch = issuance.policy.clock._check_on_work(self.window, work=self.work)
        monotonic = issuance.production._callback(self.work, time.monotonic_ns)
        if (type(epoch) is not int or type(monotonic) is not int
                or epoch < self.epoch or monotonic < self.monotonic
                or epoch >= self.window[3] or monotonic >= self.bound
                or self.interval is not None and not self.interval[0] <= epoch < self.interval[1]):
            raise RuntimeError("activation dynamic original clocks expired or reversed")
        self.epoch, self.monotonic = epoch, monotonic
        return epoch

    def continuity(self, epoch, monotonic):
        issuance.shape._integer(epoch, minimum=1)
        issuance.shape._integer(monotonic, minimum=1)
        self.epoch, self.monotonic = max(epoch, self.epoch), max(monotonic, self.monotonic)
        self.current()
        return self.epoch, self.monotonic

    def narrow(self, issued, expires):
        from serverware import authority_successor_execution_window as processing
        self.current()
        self.window = processing._narrow(self.window, deadline_epoch_ns=expires,
            maximum_lifetime_ns=self.window[5], maximum_clock_skew_ns=self.window[6])
        self.bound, self.interval = min(self.bound, self.window[4]), (issued, expires)
        self.current()


def _parent(path):
    if path not in (*_PUBLIC, transport.LISTENER_PATH):
        raise RuntimeError("activation dynamic public path is not source fixed")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for component in (None, *path.split("/")[1:-1]):
            if component is not None:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            value = os.fstat(descriptor)
            if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
                raise RuntimeError("activation dynamic ancestor is not protected root custody")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_public(path, *, owned, work, current):
    maximum = _PUBLIC[path]
    parent, descriptor = _parent(path), None
    try:
        descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_NONBLOCK
            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        ownership._claim(descriptor, owned)
        value = os.fstat(descriptor)
        identity = native._material_identity(value)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 1
                or stat.S_IMODE(value.st_mode) != 0o444 or not 2 <= value.st_size <= maximum
                or native._material_identity(os.stat(os.path.basename(path),
                    dir_fd=parent, follow_symlinks=False)) != identity):
            raise RuntimeError("activation dynamic public original protection differs")
        work.charge(input_bytes=value.st_size)
        current()
        raw = native._read_exact_source(descriptor, value.st_size)
        current()
        if (native._material_identity(os.fstat(descriptor)) != identity
                or native._material_identity(os.stat(os.path.basename(path),
                    dir_fd=parent, follow_symlinks=False)) != identity):
            raise RuntimeError("activation dynamic public original changed during read")
        return raw
    finally:
        try:
            if descriptor is not None and not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("activation dynamic original close is uncertain")
        finally:
            os.close(parent)


def _seal_original(raw, maximum, *, owned, work, current):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise RuntimeError("activation dynamic sealing requires bounded immutable originals")
    work.charge(input_bytes=len(raw))
    current()
    descriptor = os.memfd_create("serverware-activation-request-original",
        flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    ownership._claim(descriptor, owned)
    try:
        offset = 0
        while offset < len(raw):
            current()
            size = os.write(descriptor, raw[offset:offset + 4096])
            ownership._claim(descriptor, owned)
            current()
            if size <= 0:
                raise RuntimeError("activation dynamic sealed write was incomplete")
            offset += size
        os.fchmod(descriptor, 0o444)
        ownership._claim(descriptor, owned)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        ownership._claim(descriptor, owned)
        fixed._sealed_identity(descriptor, maximum)
        current()
        return descriptor
    except BaseException:
        if not ownership._close_owned_descriptor(descriptor, owned):
            raise RuntimeError("activation dynamic sealing cleanup is uncertain")
        raise


def _staging_listener(descriptor):
    value = os.fstat(descriptor)
    observed = socket.fromfd(descriptor, socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if (not stat.S_ISSOCK(value.st_mode) or os.get_blocking(descriptor)
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_UNIX
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or observed.getsockname() != transport.LISTENER_PATH):
            raise RuntimeError("activation dynamic staging listener differs")
    finally:
        observed.close()
    parent = _parent(transport.LISTENER_PATH)
    try:
        named = os.stat(os.path.basename(transport.LISTENER_PATH), dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISSOCK(named.st_mode) or named.st_nlink != 1
                or (named.st_uid, named.st_gid, stat.S_IMODE(named.st_mode)) != (0, 0, 0o600)):
            raise RuntimeError("activation dynamic staging path differs from root-only custody")
        return value.st_dev, value.st_ino, named.st_dev, named.st_ino
    finally:
        os.close(parent)


def _close_socket(observed, owned):
    descriptor = observed.fileno()
    return descriptor >= 0 and observed.detach() == descriptor and ownership._close_owned_descriptor(descriptor, owned)


class _DeliveryContinuation:
    __slots__ = ("work", "lifetime", "sealed", "tls", "resources", "originals",
        "binding", "pins", "closed")

    def __init__(self):
        raise RuntimeError("activation dynamic continuation requires actual cold delivery")

    def current(self):
        if (self is not _continuation or type(self) is not _DeliveryContinuation or self.closed
                or os.getpid() != _PID or threading.get_ident() != _THREAD
                or any(a is not b for a, b in zip((self.work, self.lifetime, self.sealed,
                    self.tls, self.resources, self.originals, self.binding), self.pins, strict=True))):
            raise RuntimeError("activation dynamic original owner changed")
        self.work.charge(input_bytes=8192)
        for descriptor, maximum, private, identity in self.sealed:
            if fixed._sealed_identity(descriptor, maximum, private=private) != identity:
                raise RuntimeError("activation dynamic sealed identity changed")
        if (fixed._listener(fixed.LISTENER_FD), fixed._journal(fixed.JOURNAL_FD),
                fixed._execution_store(fixed.EXECUTION_STORE_FD)) != self.resources:
            raise RuntimeError("activation dynamic held resources changed")
        fixed._tls_unchanged(self.tls)
        return self.lifetime.current()


def _binding_on_work(current, work, window, bound):
    if (type(current) is not MethodType or current.__func__ is not _DeliveryContinuation.current
            or current.__self__ is not _continuation or type(_continuation) is not _DeliveryContinuation
            or _continuation.work is not work):
        raise RuntimeError("activation planner requires its actual private delivery continuation")
    selected = _continuation
    current()
    window = issuance.policy.clock._validate(window)
    original = selected.lifetime.window
    if (type(bound) is not int or not 0 < bound <= min(window[4], selected.lifetime.bound)
            or window[:3] != original[:3] or any(a > b for a, b in zip(window[3:], original[3:]))):
        raise RuntimeError("activation planner widened its original dynamic allowance")
    return selected.binding


def main():
    global _used, _continuation
    if (_used or os.getpid() != _PID or threading.get_ident() != _THREAD
            or os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0)
            or os.environ.get("LISTEN_PID") != str(_PID) or os.environ.get("LISTEN_FDS") != "2"):
        raise RuntimeError("activation dynamic delivery requires one fresh root socket activation")
    _used = True
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    if len(names) != 2 or set(names) != {transport.LISTENER_NAME, fixed.LISTENER_NAME}:
        raise RuntimeError("activation dynamic listeners are not the exact staging/planner pair")
    activated = dict(zip(names, (3, 4), strict=True))
    staging_fd, planner_fd = activated[transport.LISTENER_NAME], activated[fixed.LISTENER_NAME]
    inventory._require_inventory((3, 4))
    owned, reservations = {}, {}
    staging = connection = None
    try:
        ownership._claim(3, owned)
        ownership._claim(4, owned)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
        from serverware import oidc_session_activation_planner_runner as runner

        work = _ValidationWork(QueryReadValidationLimits())
        lifetime = _Lifetime(work)
        current = lifetime.current
        os.set_blocking(staging_fd, False)
        os.set_blocking(planner_fd, False)
        staging_pins = _staging_listener(staging_fd)
        fixed._listener(planner_fd)
        for target in fixed.INHERITED_DESCRIPTORS:
            descriptor = fcntl.fcntl(planner_fd, fcntl.F_DUPFD_CLOEXEC, target)
            ownership._claim(descriptor, owned)
            if descriptor != target:
                raise RuntimeError("activation dynamic inherited slot is occupied")
            reservations[target] = owned[descriptor]
        root_raw, policy_raw = tuple(_read_public(path, owned=owned, work=work, current=current)
            for path in _PUBLIC)
        work.charge(input_bytes=len(root_raw))
        root = issuance.production._callback(work, lambda: serialization.load_pem_public_key(root_raw))
        if not isinstance(root, Ed25519PublicKey):
            raise RuntimeError("activation dynamic root original is not Ed25519")
        admitted = issuance.policy._verify_on_work(policy_bytes=policy_raw, root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=lifetime.continuity)
        lifetime.narrow(admitted.payload["issuedAtEpochNs"], admitted.payload["expiresAtEpochNs"])
        held = len(root_raw) + len(policy_raw)
        maximum = min(transport.MAX_ORIGINAL_BYTES, MAX_ORIGINAL_BYTES - held
            - sum(item[2] for item in fixed._KEY_FILES) - sum(item[2] for item in fixed._TLS_FILES))
        staging = socket.socket(fileno=staging_fd)
        while connection is None:
            current()
            remaining = (lifetime.bound - lifetime.monotonic) / 1_000_000_000
            ready, _, exceptional = select.select((staging,), (), (staging,), min(1.0, remaining))
            current()
            if exceptional:
                raise RuntimeError("activation dynamic staging readiness failed")
            if ready:
                connection, _ = staging.accept()
                ownership._claim(connection.fileno(), owned)
                connection.setblocking(False)
                connection.set_inheritable(False)
        originals = transport._recv_request(connection, deadline_ns=lifetime.bound,
            work=work, current=current, maximum_original_bytes=maximum)
        originals = issuance._verify_planning_on_work(policy_bytes=policy_raw, request_bytes=originals[0],
            originals=originals, root_public_key=root, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
        request = issuance._read_request(originals[0], work)["payload"]
        lifetime.narrow(request["issuedAtEpochNs"], request["expiresAtEpochNs"])
        material = issuance.planner._verify_on_work(bootstrap_bytes=originals[3], root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
        current()
        launch = material.launch
        listener_pins = tuple(launch[name] for name in ("listenerSocketDevice", "listenerSocketInode",
            "listenerPathDevice", "listenerPathInode"))
        journal_pins = launch["journalDirectoryDevice"], launch["journalDirectoryInode"]
        store_pins = launch["executionStoreDirectoryDevice"], launch["executionStoreDirectoryInode"]
        if fixed._listener(planner_fd) != listener_pins or journal_pins == store_pins:
            raise RuntimeError("activation dynamic actual listener or distinct stores differ")
        for raw, target, maximum in ((root_raw, fixed.ROOT_FD, fixed.MAX_ROOT_BYTES),
                (originals[3], fixed.BOOTSTRAP_FD, fixed.MAX_BOOTSTRAP_BYTES)):
            descriptor = _seal_original(raw, maximum, owned=owned, work=work, current=current)
            ownership._retain(descriptor, target, reservations, owned)
            if not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("activation dynamic original duplicate close is uncertain")
        # Genuine root policy/raw7 admission precedes every private resource.
        for path, target, maximum in fixed._KEY_FILES:
            current()
            work.charge(input_bytes=maximum)
            descriptor = fixed._open_material(path, maximum, private=True)
            ownership._claim(descriptor, owned)
            current()
            ownership._retain(descriptor, target, reservations, owned)
            if not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("activation dynamic key duplicate close is uncertain")
        fixed._keys_on_work(material, work)
        current()
        work.charge(hashes=len(material.tls_files),
            input_bytes=sum(item["byteCount"] for item in material.tls_files.values()))
        tls = fixed._tls_identity(material.tls_files)
        current()
        for target, opener, pins in ((fixed.JOURNAL_FD, fixed._journal_directory, journal_pins),
                (fixed.EXECUTION_STORE_FD, fixed._execution_store_directory, store_pins)):
            work.charge(input_bytes=4096)
            descriptor = opener(*pins)
            ownership._claim(descriptor, owned)
            current()
            ownership._retain(descriptor, target, reservations, owned)
            if not ownership._close_owned_descriptor(descriptor, owned):
                raise RuntimeError("activation dynamic directory duplicate close is uncertain")
        ownership._retain(planner_fd, fixed.LISTENER_FD, reservations, owned)
        if not ownership._close_owned_descriptor(planner_fd, owned) or reservations:
            raise RuntimeError("activation dynamic inherited handoff is incomplete")
        sealed = tuple((descriptor, maximum, private,
            fixed._sealed_identity(descriptor, maximum, private=private))
            for descriptor, maximum, private in ((fixed.ROOT_FD, fixed.MAX_ROOT_BYTES, False),
                (fixed.BOOTSTRAP_FD, fixed.MAX_BOOTSTRAP_BYTES, False),
                *((descriptor, maximum, True) for _path, descriptor, maximum in fixed._KEY_FILES)))
        retained = held + sum(map(len, originals)) + len(root_raw) + len(originals[3])
        for graph in (admitted.payload, material.configuration_payload, material.generation,
                material.runtime_role_identities, material.launch, material.tls_files):
            measured = issuance.policy.configuration._ConfigurationCapture(
                issuance.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES, retain=False)
            measured.visit(graph)
            retained += measured.bytes
        retained += sum(item[2] for item in fixed._KEY_FILES) + sum(item[2] for item in fixed._TLS_FILES)
        if retained >= MAX_ORIGINAL_BYTES:
            raise RuntimeError("activation dynamic retained originals exceed the source ceiling")
        selected = object.__new__(_DeliveryContinuation)
        selected.work, selected.lifetime = work, lifetime
        selected.sealed, selected.tls, selected.resources = sealed, tls, (listener_pins, journal_pins, store_pins)
        selected.originals, selected.binding = originals, (retained, request["plannerRequestDigest"], originals[3])
        selected.closed = False
        selected.pins = (work, lifetime, sealed, tls, selected.resources, originals, selected.binding)
        _continuation = selected
        selected.current()
        if _staging_listener(staging_fd) != staging_pins:
            raise RuntimeError("activation staging listener changed before ACK")
        identity = transport._identity(originals, deadline_ns=lifetime.bound, work=work, current=selected.current)
        inventory._require_inventory(tuple(owned))
        transport._send_response(connection, (b"staged", identity),
            deadline_ns=lifetime.bound, work=work, current=selected.current)
        closing, connection = connection, None
        if not _close_socket(closing, owned):
            raise RuntimeError("activation staging connection close is uncertain")
        closing, staging = staging, None
        if not _close_socket(closing, owned):
            raise RuntimeError("activation staging listener close is uncertain")
        inventory._require_inventory(fixed.INHERITED_DESCRIPTORS)
        selected.current()
        os.setgroups([])
        os.setresgid(fixed.SERVICE_GID, fixed.SERVICE_GID, fixed.SERVICE_GID)
        os.setresuid(fixed.SERVICE_UID, fixed.SERVICE_UID, fixed.SERVICE_UID)
        native._require_unprivileged_process()
        if (os.getresuid() != (fixed.SERVICE_UID,) * 3 or os.getresgid() != (fixed.SERVICE_GID,) * 3 or os.getgroups()):
            raise RuntimeError("activation dynamic permanent identity drop retained privilege")
        os.environ.clear()
        os.environ.update(ENVIRONMENT)
        selected.current()
        return runner._run_on_work(work=work, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, delivery_current=selected.current)
    finally:
        if _continuation is not None:
            _continuation.closed = True
        complete = True
        for observed in (connection, staging):
            if observed is not None:
                try:
                    complete = _close_socket(observed, owned) and complete
                except BaseException:
                    complete = False
        if not ownership._close_all_owned(owned) or not complete:
            raise RuntimeError("activation dynamic cleanup uncertain; replaced descriptors were not closed")
