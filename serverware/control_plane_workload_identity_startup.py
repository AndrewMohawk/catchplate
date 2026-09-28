"""Optional public-only workload issuer owner under admitted custody startup.

No runtime inventory is rescanned, no CA key or journal descriptor is opened,
and no socket is contacted during startup. Production requires an explicit
signed null or enabled configuration; only genuinely unconfigured development
may opt out. Each request opens its actual work/window before HTTP body one.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
import stat
import threading


BOOTSTRAP_FD_ENVIRONMENT = "SERVERWARE_CONTROL_PLANE_WORKLOAD_IDENTITY_BOOTSTRAP_FD"
MAX_BOOTSTRAP_BYTES = 256 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
_PREFIX = "SERVERWARE_CONTROL_PLANE_WORKLOAD_IDENTITY_"
_DEVELOPMENT = frozenset({"dev", "development", "local", "test"})
_PID = os.getpid()
_LOCK = threading.RLock()
_CONSTRUCTION = object()
_state = "new"
_namespace = None
_owner = None
_scopes = set()
_MATERIAL_FIELDS = ("original_bytes", "configuration_digest", "enabled", "issuer_root_bytes",
    "issuer_root_public_key", "issuer_bootstrap_bytes", "issuer_material", "endpoint",
    "peer_uid", "peer_gid", "request_timeout_ns", "maximum_original_bytes",
    "valid_from_epoch_ns", "valid_until_epoch_ns")
_OWNER_FIELDS = ("_material", "_custody", "_binding", "_descriptor", "_descriptor_pin",
    "_identity", "_material_pin")
_SCOPE_FIELDS = ("owner", "material", "work", "original_reservation_bytes",
    "issuer_root_public_key", "issuer_bootstrap_bytes", "endpoint", "peer_uid", "peer_gid",
    "_budget", "_opening")


class WorkloadIdentityStartupError(RuntimeError):
    pass


def _fail(message):
    raise WorkloadIdentityStartupError(message)


def _pid():
    if os.getpid() != _PID:
        _fail("forked process cannot use workload issuer caller authority")


def _environment():
    return (os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower(),
        tuple(sorted((name, value) for name, value in os.environ.items() if name.startswith(_PREFIX))))


def _descriptor(namespace):
    settings = namespace[1]
    if len(settings) != 1 or settings[0][0] != BOOTSTRAP_FD_ENVIRONMENT:
        _fail("workload caller permits only its fixed bootstrap FD setting")
    value = settings[0][1]
    if (type(value) is not str or not 1 <= len(value) <= 4
            or not value.isascii() or not value.isdecimal()):
        _fail("workload caller bootstrap FD is not canonical decimal")
    descriptor = int(value)
    if not 3 <= descriptor <= 1023 or str(descriptor) != value:
        _fail("workload caller bootstrap FD is outside its inherited range")
    return descriptor


def _descriptor_identity(descriptor):
    value = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    name = os.readlink("/proc/self/fd/" + str(descriptor))
    required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_nlink != 0
            or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= value.st_size <= MAX_BOOTSTRAP_BYTES
            or seals & required != required or not name.startswith("/memfd:")
            or not name.endswith(" (deleted)")):
        _fail("workload caller bootstrap is not bounded root-owned sealed memfd material")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns, seals, name)


def _owner_identity(owner):
    _pid()
    from serverware import control_plane_workload_identity_bootstrap as bootstrap

    if (type(owner) is not _CallerOwner or owner is not _owner or _state != "started"
            or owner._closed is not False or _environment() != _namespace
            or (os.geteuid(), os.getegid()) != owner._identity
            or type(owner._material) is not bootstrap._CallerMaterial
            or any(getattr(owner, name) is not value for name, value in zip(_OWNER_FIELDS, owner._seal))
            or len(owner._seal) != len(_OWNER_FIELDS)
            or any(getattr(owner._material, name) is not value
                for name, value in zip(_MATERIAL_FIELDS, owner._material_pin))):
        _fail("workload caller lost its exact cold owner or process scope")


def _owner_current(owner):
    _owner_identity(owner)
    from serverware import control_plane_custody_client as client
    from serverware import control_plane_custody_startup as custody

    if (custody.require_started() is not owner._custody
            or client._snapshot(owner._custody) is not owner._binding
            or _descriptor_identity(owner._descriptor) != owner._descriptor_pin):
        _fail("workload caller's original custody or sealed public configuration changed")
    now = client._receipt_now(owner._binding)
    material = owner._material
    if not material.valid_from_epoch_ns <= now < material.valid_until_epoch_ns:
        _fail("workload caller's original signed authority interval expired")
    # Deliberately do not call issuer_material.live: it is the already-finished
    # cold processing window, not a reusable permission or a request deadline.
    _owner_identity(owner)
    return now


class _CallerOwner:
    __slots__ = (*_OWNER_FIELDS, "_closed", "_seal")

    def __init__(self):
        _fail("workload caller owner requires actual cold startup")

    @property
    def enabled(self):
        _owner_current(self)
        return self._material.enabled

    def current(self):
        return _owner_current(self)


def initialize_from_environment():
    global _state, _namespace, _owner
    _pid()
    with _LOCK:
        if _state in ("started", "disabled"):
            return require_started()
        if _state != "new":
            _fail("workload caller startup cannot repeat after failure or shutdown")
        _namespace, _state = _environment(), "initializing"
        try:
            if _namespace[0] in _DEVELOPMENT and not _namespace[1]:
                _state = "disabled"
                return None
            descriptor = _descriptor(_namespace)
            from serverware import control_plane_custody_client as client
            from serverware import control_plane_custody_startup as custody
            from serverware import control_plane_workload_identity_bootstrap as bootstrap
            from serverware import workload_identity_issuer_bootstrap as issuer
            from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

            actual = custody.require_started()
            binding = client._snapshot(actual)
            if descriptor not in binding.inherited_descriptors:
                _fail("workload caller bootstrap is absent from the original admitted FD inventory")
            identity = os.geteuid(), os.getegid()
            work = _ValidationWork(QueryReadValidationLimits())
            window = issuer.clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
                maximum_lifetime_ns=min(binding.maximum_deadline_ns, issuer._MAX_TIMEOUT_NS),
                maximum_clock_skew_ns=0, work=work)

            def current():
                if (_environment() != _namespace or (os.geteuid(), os.getegid()) != identity
                        or custody.require_started() is not actual or client._snapshot(actual) is not binding):
                    _fail("workload caller cold context changed")
                work.charge(input_bytes=1)
                receipt_now = client._receipt_now(binding)
                now = issuer.clock._check_on_work(window, work=work)
                if now < receipt_now:
                    _fail("workload caller cold receipt clock reversed")
                return now

            # Work and the original clock are open before public body one.
            current()
            pin = _descriptor_identity(descriptor)
            if 8 * pin[6] + 128 * 1024 > MAX_ORIGINAL_BYTES:
                _fail("workload caller cold capture exceeds its original capacity")
            work.charge(input_bytes=2 * pin[6])
            body = bytearray()
            while len(body) < pin[6]:
                current()
                piece = os.pread(descriptor, min(4096, pin[6] - len(body)), len(body))
                if not piece:
                    _fail("workload caller sealed configuration was truncated")
                body.extend(piece)
                current()
            if os.pread(descriptor, 1, pin[6]) or _descriptor_identity(descriptor) != pin:
                _fail("workload caller sealed configuration changed during read")
            original = bytes(body)
            material = bootstrap._admit_on_work(bootstrap_bytes=original,
                runtime_root_public_key=binding.runtime_root_public_key,
                expected_configuration_digest=binding.configuration_digest,
                expected_uid=binding.caller_uid, expected_gid=binding.caller_gid,
                live_window=window, transport_deadline_ns=window[4], work=work, _current=current)
            current()
            if _descriptor_identity(descriptor) != pin:
                _fail("workload caller configuration changed after cold admission")
            owner = object.__new__(_CallerOwner)
            owner._material, owner._custody, owner._binding = material, actual, binding
            owner._descriptor, owner._descriptor_pin, owner._identity = descriptor, pin, identity
            owner._material_pin = tuple(getattr(material, field) for field in _MATERIAL_FIELDS)
            owner._closed = False
            owner._seal = tuple(getattr(owner, field) for field in _OWNER_FIELDS)
            _owner, _state = owner, "started"
            _owner_current(owner)
            return owner
        except BaseException:
            if _owner is not None:
                _owner._closed = True
            _owner, _state = None, "failed"
            raise


def require_started():
    _pid()
    with _LOCK:
        current_namespace = _environment()
        if (_state == "new" and current_namespace[0] in _DEVELOPMENT
                and not current_namespace[1]):
            # Direct development ASGI/library use has no enabled issuer and
            # performs neither lazy admission nor a lifecycle state change.
            return None
        if current_namespace != _namespace:
            _fail("workload caller configuration changed after startup")
        if _state == "disabled" and _namespace[0] in _DEVELOPMENT and not _namespace[1]:
            return None
        if _state != "started" or _owner is None:
            _fail("workload caller requires its original cold startup")
        _owner_current(_owner)
        return _owner


def _scope_identity(scope):
    _pid()
    if (type(scope) is not _CallerScope or scope not in _scopes or scope._closed is not False
            or len(scope._seal) != len(_SCOPE_FIELDS)
            or any(getattr(scope, name) is not value for name, value in zip(_SCOPE_FIELDS, scope._seal))
            or type(scope._exchange_spent) is not bool or type(scope._guards) is not tuple):
        _fail("workload request lost its exact source-owned live context")
    _owner_identity(scope.owner)
    window = scope._budget.window
    if (window[:3] != scope._opening[:3] or window[3] > scope._opening[3]
            or window[4] > scope._opening[4] or window[5] > scope._opening[5]
            or window[6] > scope._opening[6] or scope._budget.bound > window[4]):
        _fail("workload request attempted to renew its original processing window")


class _CallerScope:
    __slots__ = (*_SCOPE_FIELDS, "_seal", "_closed", "_exchange_spent", "_guards")

    def __init__(self, construction, owner, *, additional):
        if construction is not _CONSTRUCTION:
            _fail("workload request context is privately constructed")
        from serverware import workload_identity_issuer_bootstrap as issuer
        from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

        _owner_current(owner)
        material = owner._material
        if material.enabled is not True:
            _fail("workload issuance caller is explicitly disabled")
        issuer._integer(additional, MAX_ORIGINAL_BYTES)
        original_bytes = (len(material.original_bytes) + len(material.issuer_root_bytes)
            + len(material.issuer_bootstrap_bytes) + len(material.issuer_material.issuer_certificate_bytes)
            + len(material.issuer_material.packet_signing_key_bytes)
            + len(material.issuer_material.authorization_key_bytes))
        reservation = 8 * original_bytes + 128 * 1024 + additional
        if reservation >= MAX_ORIGINAL_BYTES:
            _fail("workload request cold and HTTP captures exhaust the original capacity")
        work = _ValidationWork(QueryReadValidationLimits())
        window = issuer.clock._open_on_work(
            deadline_epoch_ns=min(material.valid_until_epoch_ns, owner._binding.attestation_interval[1]),
            maximum_lifetime_ns=min(material.request_timeout_ns, owner._binding.maximum_deadline_ns),
            maximum_clock_skew_ns=0, work=work)

        def original_current():
            work.charge(input_bytes=1)
            return _owner_current(owner)

        self.owner, self.material, self.work = owner, material, work
        self.original_reservation_bytes = reservation
        self.issuer_root_public_key, self.issuer_bootstrap_bytes = material.issuer_root_public_key, material.issuer_bootstrap_bytes
        self.endpoint, self.peer_uid, self.peer_gid = material.endpoint, material.peer_uid, material.peer_gid
        self._budget = issuer._Budget(work, window, window[4], original_current)
        self._opening = window
        self._closed, self._exchange_spent, self._guards = False, False, ()
        self._seal = tuple(getattr(self, name) for name in _SCOPE_FIELDS)

    @property
    def window(self):
        _scope_identity(self)
        return self._budget.window

    @property
    def deadline_ns(self):
        _scope_identity(self)
        return self._budget.bound

    def base_current(self):
        _scope_identity(self)
        now = self._budget.current()
        _scope_identity(self)
        return now

    def current(self):
        from serverware import workload_identity_issuer_bootstrap as issuer

        now = self.base_current()
        for guard in self._guards:
            observed = issuer._guard_on_work(guard, self.work)
            if type(observed) is not int or observed < now:
                _fail("workload request descendant currentness reversed")
            now = self.base_current()
            if now < observed:
                _fail("workload request original clock reversed after a descendant")
        return now

    def _retain_current(self, current, window, bound):
        from serverware import workload_identity_issuer_bootstrap as issuer

        self.current()
        issuer.clock._validate(window)
        issuer._integer(bound, min(self.deadline_ns, window[4]), 1)
        if (not callable(current) or window[:3] != self.window[:3]
                or any(window[index] > self.window[index] for index in (3, 4, 5, 6))):
            _fail("workload request descendant changed the original processing context")
        self._budget.window, self._budget.bound = window, bound
        self._guards = (*self._guards, current)
        self.current()

    def _claim_exchange(self):
        _pid()
        with _LOCK:
            self.current()
            if self._exchange_spent:
                _fail("workload request issuer exchange is already spent")
            self._exchange_spent = True
            self.current()


def _require_context(scope):
    _scope_identity(scope)
    scope.current()
    _scope_identity(scope)
    return scope


@contextmanager
def _request_on_owner(owner, *, _additional_original_bytes=0):
    _pid()
    with _LOCK:
        _owner_current(owner)
        scope = _CallerScope(_CONSTRUCTION, owner, additional=_additional_original_bytes)
        _scopes.add(scope)
    try:
        scope.current()
        yield scope
        scope.current()
    finally:
        with _LOCK:
            scope._closed = True
            scope._guards = ()
            _scopes.discard(scope)


def close():
    global _state, _owner
    _pid()
    with _LOCK:
        for scope in tuple(_scopes):
            scope._closed = True
            scope._guards = ()
        _scopes.clear()
        if _owner is not None:
            _owner._closed = True
        _owner, _state = None, "closed"
