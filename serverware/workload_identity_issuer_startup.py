"""Actual software CA owner, continuing original fixed-profile root delivery.

No application process imports a signing capability from this owner. It is
constructed only by the exact same-PID fixed launcher after permanent UID drop.
"""
from __future__ import annotations

import hashlib
import os
import socket
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from serverware import workload_identity_issuer_entrypoint as delivery
from serverware import workload_identity_issuer_bootstrap as bootstrap
from serverware import workload_identity_issuer_journal as journals


_PID, _THREAD = os.getpid(), threading.get_ident()
_CONSTRUCTION = object()
_state, _owner = "new", None


def _process():
    if (os.getpid() != _PID or threading.get_ident() != _THREAD
            or tuple(sorted(os.environ.items())) != tuple(sorted(delivery.ENVIRONMENT.items()))
            or os.getresuid() != (delivery.SERVICE_UID,) * 3
            or os.getresgid() != (delivery.SERVICE_GID,) * 3 or os.getgroups()):
        raise RuntimeError("workload issuer process or closed environment changed")
    delivery.delivery._require_unprivileged_process()


class _IssuerOwner:
    __slots__ = ("material", "root_public_key", "ca_private_key", "journal", "listener", "work",
        "window", "deadline_ns", "original_reservation_bytes", "_base", "_active", "_service_spent",
        "_service_lifetime", "_material_pin", "_exchanges", "_request", "_seal")

    def __init__(self, construction, *, launch, key, journal, listener, current):
        if construction is not _CONSTRUCTION or _state != "starting":
            raise RuntimeError("workload issuer owner is privately constructed")
        self.material, self.root_public_key, self.ca_private_key = launch.material, launch.root_public_key, key
        self.journal, self.listener, self.work = journal, listener, launch.work
        self.window, self.deadline_ns = launch.window, launch.deadline_ns
        self._service_lifetime = launch.service_lifetime
        if self._service_lifetime is not None:
            self.deadline_ns = self._service_lifetime.deadline_ns
        self.original_reservation_bytes = launch.original_reservation_bytes
        self._base, self._active, self._service_spent = current, True, False
        self._material_pin = (self.material.profile, self.material.bootstrap_bytes,
            self.material.service_maximum_exchanges)
        self._exchanges, self._request = 0, None
        self._seal = tuple(getattr(self, name) for name in _FIELDS)

    def current(self):
        _identity(self)
        _process()
        now = self._base()
        _identity(self)
        return now

    def claim_service(self):
        self.current()
        if self._service_spent:
            raise RuntimeError("workload issuer service invocation is already spent")
        self._service_spent = True
        self.current()


_FIELDS = ("material", "root_public_key", "ca_private_key", "journal", "listener", "work",
    "window", "deadline_ns", "original_reservation_bytes", "_base", "_service_lifetime", "_material_pin")


def _identity(value):
    if (type(value) is not _IssuerOwner or _owner is not value or _state != "ready"
            or value._active is not True or type(value._service_spent) is not bool
            or type(value._seal) is not tuple or len(value._seal) != len(_FIELDS)
            or any(getattr(value, name) is not expected for name, expected in zip(_FIELDS, value._seal))
            or type(value.material) is not bootstrap._IssuerMaterial
            or len(value._material_pin) != 3 or any(actual is not original for actual, original in zip(
                (value.material.profile, value.material.bootstrap_bytes,
                    value.material.service_maximum_exchanges), value._material_pin))
            or type(value._exchanges) is not int
            or not 0 <= value._exchanges <= value.material.service_maximum_exchanges
            or (value.material.profile == bootstrap.NATIVE_SERVICE_PROFILE)
                != (type(value._service_lifetime) is delivery._ServiceLifetime)):
        raise RuntimeError("workload issuer owner lost its original private lifecycle")


def _require_owner(value):
    _identity(value)
    value.current()
    _identity(value)
    return value


class _IssuerRequest:
    """One accepted v3 exchange; never a replacement ledger or service owner."""

    __slots__ = ("owner", "sequence", "window", "deadline_ns", "_budget", "_seal", "_closed")

    def __init__(self, construction, owner):
        _require_owner(owner)
        if (construction is not _CONSTRUCTION
                or owner.material.profile != bootstrap.NATIVE_SERVICE_PROFILE
                or not owner._service_spent or owner._request is not None
                or owner._exchanges >= owner.material.service_maximum_exchanges):
            raise RuntimeError("workload service cannot open another request")
        # Consume before accepting even the first request byte. An exception
        # exits the service; it never unspends this attempt or opens a retry.
        owner._exchanges += 1
        window = bootstrap.clock._open_on_work(
            deadline_epoch_ns=owner._service_lifetime.interval[1],
            maximum_lifetime_ns=owner.material.request_timeout_ns,
            maximum_clock_skew_ns=0, work=owner.work)
        bound = min(window[4], owner.deadline_ns)
        self.owner, self.sequence = owner, owner._exchanges
        self._budget = bootstrap._Budget(owner.work, window, bound, owner.current)
        self.window, self.deadline_ns = self._budget.window, self._budget.bound
        self._closed = False
        self._seal = (owner, self.sequence, self.window, self.deadline_ns, self._budget)
        owner._request = self
        self.current()

    def current(self):
        _require_request(self, self.owner)
        now = self._budget.current()
        _require_request(self, self.owner)
        return now


def _require_request(value, owner):
    _require_owner(owner)
    if (type(value) is not _IssuerRequest or value.owner is not owner
            or owner._request is not value or value._closed is not False
            or value.sequence != owner._exchanges
            or len(value._seal) != 5 or any(actual is not original for actual, original in zip(
                (value.owner, value.sequence, value.window, value.deadline_ns, value._budget), value._seal))
            or value._budget.work is not owner.work or value._budget.window is not value.window
            or value._budget.bound != value.deadline_ns or value.deadline_ns > owner.deadline_ns):
        raise RuntimeError("workload request lost its original private exchange context")
    return value


def _finish_request(value, owner):
    value.current()
    _require_request(value, owner)
    value._closed = True
    owner._request = None
    _require_owner(owner)


def _key_on_launch(launch, current):
    material, work = launch.material, launch.work
    raw = delivery._read_on_work(delivery.KEY_FD, delivery.MAX_KEY_BYTES, work, current, private=True)
    if len(raw) != material.ca_private_key_byte_count:
        raise RuntimeError("workload issuer key differs from its signed exact byte count")
    work.charge(input_bytes=2 * len(raw))
    current()
    key = serialization.load_pem_private_key(raw, password=None)
    current()
    if not (isinstance(key, ed25519.Ed25519PrivateKey)
            or isinstance(key, ec.EllipticCurvePrivateKey)
            and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1))
            or isinstance(key, rsa.RSAPrivateKey) and 3072 <= key.key_size <= 4096):
        raise RuntimeError("workload issuer private key is outside its direct-issuer profile")
    canonical = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    if canonical != raw:
        raise RuntimeError("workload issuer private key must be exact unencrypted PKCS8 PEM")
    public = key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    work.charge(input_bytes=2 * len(public), hashes=1)
    if ("sha256:" + hashlib.sha256(public).hexdigest() != material.ca_spki_digest
            or public != material.issuer_certificate.spki_der):
        raise RuntimeError("workload issuer private key differs from its independently admitted CA")
    current()
    return key


def _run_on_launch(launch):
    global _state, _owner
    if _state != "new" or _owner is not None:
        raise RuntimeError("workload issuer cannot restart a spent source owner")
    delivery._require_launch(launch)
    _process()
    _state = "starting"
    journal, listener = None, None
    material = launch.material
    listener_pin = (material.listener_device, material.listener_inode,
        material.listener_path_device, material.listener_path_inode)

    def current():
        _process()
        delivery._require_launch(launch)
        if delivery._listener(delivery.LISTENER_FD) != listener_pin:
            raise RuntimeError("workload issuer admitted listener changed")
        delivery._journal_identity(delivery.JOURNAL_FD, material)
        return launch.current()

    try:
        current()
        key = _key_on_launch(launch, current)
        # Recovery retains this base-only guard. It never calls a child journal
        # method while journal I/O holds its own lock.
        journal = journals.WorkloadIdentityIssuerJournal(material=material,
            directory_fd=delivery.JOURNAL_FD, work=launch.work, current=current,
            maximum_original_bytes=2 * 1024 * 1024)
        current()
        listener = socket.socket(fileno=delivery.LISTENER_FD)
        listener.setblocking(False)
        if material.profile == bootstrap.NATIVE_SERVICE_PROFILE:
            delivery._require_launch(launch)
            if type(launch.service_lifetime) is not delivery._ServiceLifetime:
                raise RuntimeError("workload service lacks its original launcher lifetime")
            # Only completed original cold admission/key/journal acquisition
            # can enter the separately signed service lifetime, exactly once.
            launch.service_lifetime.activate()
            delivery._require_launch(launch)
        _owner = _IssuerOwner(_CONSTRUCTION, launch=launch, key=key, journal=journal,
            listener=listener, current=current)
        _state = "ready"
        _require_owner(_owner)
        from serverware import workload_identity_issuer_service as service
        service._serve_on_owner(_owner)
        _require_owner(_owner)
    finally:
        if _owner is not None:
            if _owner._request is not None:
                _owner._request._closed = True
            _owner._active = False
        _state = "closed"
        _owner = None
        try:
            if journal is not None:
                journal.close()
        finally:
            if listener is not None:
                # Root delivery owns descriptor closure and the journal flock.
                if listener.fileno() != delivery.LISTENER_FD:
                    raise RuntimeError("workload issuer listener closure authority is uncertain")
                listener.detach()
