"""Offline development materialization of an already finalized demo policy.

No signing, genesis creation, authority writes or production ceremony occurs.
The actual PostgreSQL genesis read lock remains held through no-replace install,
fsync and readback. Failure is not rollback: a stage or genuinely committed
policy may remain, and the ordinary loader may independently accept installed
bytes. Never automatically retry, delete, restore or invent journal receipts.
Kernel/filesystem stalls still require an external process watchdog.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import re
import threading
import time

from scripts.authority import native_pilot_authority_io as public_io
from catchplate import config, policy_bundle as bundles
from catchplate import control_plane_admin_token_publication as files
from catchplate import control_plane_policy_file_publication as publication
from catchplate.authority_witness_journal import _rename_noreplace
from catchplate.control_plane_policy_file_authority import CurrentPolicyAuthority
from catchplate.control_plane_policy_file_genesis import GenesisPolicyAuthority, read_original
from catchplate.demo_seed_policy import require_demo_semantics
from catchplate.native_pilot_genesis_parent_control_io import owning

MODE = "metadata-bootstrap"
STAGE = ".catchplate-development-policy-genesis.stage"
MAX_NS = 30_000_000_000
_TOKEN, _USED, _LIVE = object(), False, None
_DEVELOPMENT = frozenset({"dev", "development", "local", "test"})
_FORBIDDEN_DSN = ("CATCHPLATE_METADATA_STORE_ADMIN_POSTGRES_DSN",
    "CATCHPLATE_AUDIT_STORE_ADMIN_POSTGRES_DSN", "CATCHPLATE_WEBAUTHN_RECOVERY_WITNESS_ADMIN_POSTGRES_DSN",
    "CATCHPLATE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN", "CATCHPLATE_POLICY_AUTHORITY_EXECUTOR_POSTGRES_DSN_FD")


class DevelopmentGenesisError(ValueError):
    def __init__(self, owner=None):
        super().__init__("development genesis materialization refused; partial files may remain; no automatic retry")
        self.owner = owner


def _require(value):
    if not value:
        raise DevelopmentGenesisError()


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require_development():
    """The fixed offline invocation authorizes a public-file effect only."""
    _require(not config.PRODUCTION_IMAGE
        and os.environ.get("CATCHPLATE_PRODUCTION_IMAGE", "0") == "0"
        and os.environ.get("CATCHPLATE_PROCESS_MODE") == MODE
        and config.RELEASE_CHANNEL.strip().lower() in _DEVELOPMENT
        and os.environ.get("CATCHPLATE_RELEASE_CHANNEL", "dev").strip().lower()
            == config.RELEASE_CHANNEL.strip().lower() == bundles.RELEASE_CHANNEL.strip().lower()
        and not any(name in os.environ for name in _FORBIDDEN_DSN))


def signed_demo(raw):
    """Authenticate actual public trust and exact demo semantics; no DB claim."""
    _require(type(raw) is bytes and 0 < len(raw) <= bundles.MAX_POLICY_BUNDLE_BYTES)
    value = bundles._decode_raw_policy(bundles.POLICY_BUNDLE_PATH, raw)
    trust = bundles._load_policy_signing_trust()  # Never the private-key fallback.
    snapshot = bundles.compile_policy_bundle(value, verify_signature=True,
        validate_schema=True, signing_trust=trust)
    require_demo_semantics(value)
    policy_id, sequence, rollback, policy_hash = bundles._policy_snapshot_authority(snapshot)
    bundles._recheck_policy_signing_trust(trust.identity)
    return trust.identity, dict(policyId=policy_id, sequence=sequence,
        rollbackEpoch=rollback, policyHash=policy_hash)


class GenesisRead(CurrentPolicyAuthority):
    SQL, DSN_PATH, DSN_SHA = GenesisPolicyAuthority.SQL, GenesisPolicyAuthority.DSN_PATH, GenesisPolicyAuthority.DSN_SHA

    def check(self):
        self._check_held_connection()
        current = read_original(self)
        if self.original is None:
            self.original = current
        else:
            _require(current == self.original)
        self._configure()
        self._contract()
        self.publication.check()


class OfflineDevelopmentGenesis:
    def __init__(self, token):
        _require(token is _TOKEN)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline, self.expires = self.mono + MAX_NS, self.epoch + MAX_NS
        self.environment = tuple(sorted((name, value) for name, value in os.environ.items()
            if name.startswith("CATCHPLATE_")))
        self.path = bundles.POLICY_BUNDLE_PATH
        self.pins, self.handles = [], []
        self.parent = self.directory = self.authority = self.input_fd = self.stage_fd = None
        self.raw = self.input_identity = self.trust = self.material_binding = None
        self.installed = self.used = self.failed = self.closed = self.closing = self.uncertain = False

    def _hold(self, fd):
        row = [fd, None]
        self.handles.append(row)
        info = os.fstat(fd)
        row[1] = info.st_dev, info.st_ino
        return fd

    @classmethod
    def open(cls, *, policy_fd, policy_sha256, genesis_preparation_digest, genesis_finalization_digest):
        global _USED, _LIVE
        require_development(); public_io._process()
        _require(cls is OfflineDevelopmentGenesis and not _USED and _LIVE is None)
        _digest(policy_sha256); _digest(genesis_preparation_digest); _digest(genesis_finalization_digest)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner.check()
            expected = public_io._input(policy_fd, bundles.MAX_POLICY_BUNDLE_BYTES)
            with owning():
                owner.input_fd = owner._hold(fcntl.fcntl(policy_fd, fcntl.F_DUPFD_CLOEXEC, 128))
            owner.input_identity = public_io._input(owner.input_fd, bundles.MAX_POLICY_BUNDLE_BYTES)
            _require(owner.input_identity == expected)
            owner.raw = public_io.read_public(owner.input_fd, bundles.MAX_POLICY_BUNDLE_BYTES)
            _require(_sha(owner.raw) == policy_sha256
                and public_io.read_public(policy_fd, bundles.MAX_POLICY_BUNDLE_BYTES) == owner.raw)
            owner.pins.append((None, None, owner.input_fd, owner.raw, files._file_identity(os.fstat(owner.input_fd))))
            owner.trust, bound = signed_demo(owner.raw)
            owner.material_binding = dict(bound, kind="genesis-materialize", expectedFileSha256=None,
                genesisPreparationDigest=genesis_preparation_digest, genesisFinalizationDigest=genesis_finalization_digest)
            with owning():
                owner.path, owner.basename, parent, owner.parent_identity = bundles._open_secure_parent_directory(
                    owner.path, label="development genesis policy", mutation_target=True)
                owner.parent = owner._hold(parent)
            _require(owner.basename.isascii() and owner.basename != STAGE)
            fcntl.flock(owner.parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner._absent(owner.basename); owner._absent(STAGE)
            with owning():
                try:
                    directory, owner.directory_identity, _ = publication._directory(owner.parent, create=False)
                except FileNotFoundError:
                    pass
                else:
                    owner.directory = owner._hold(directory)
            owner.check()
            return owner
        except BaseException as error:
            owner.failed = True
            raise DevelopmentGenesisError(owner) from error

    def _retain_authority(self, reader):
        _require(type(reader) is GenesisRead and self.authority is None)
        self.authority = reader

    def _absent(self, name):
        try:
            os.stat(name, dir_fd=self.parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise DevelopmentGenesisError(self)

    def check(self):
        require_development(); public_io._process()
        _require(type(self) is OfflineDevelopmentGenesis and _LIVE is self
            and (self.pid, self.thread) == (os.getpid(), threading.get_ident())
            and not (self.failed or self.closed or self.closing or self.uncertain)
            and self.environment == tuple(sorted((name, value) for name, value in os.environ.items()
                if name.startswith("CATCHPLATE_"))))
        mono, epoch = time.monotonic_ns(), time.time_ns()
        _require(self.mono <= mono < self.deadline and self.epoch <= epoch < self.expires)
        if self.raw is not None:
            _require(public_io._input(self.input_fd, bundles.MAX_POLICY_BUNDLE_BYTES) == self.input_identity
                and public_io.read_public(self.input_fd, bundles.MAX_POLICY_BUNDLE_BYTES) == self.raw)
        if self.trust is not None:
            bundles._recheck_policy_signing_trust(self.trust)
        if self.parent is not None:
            bundles._recheck_secure_parent_directory(self.path, label="development genesis policy",
                expected=self.parent_identity, mutation_target=True)
            if self.directory is None:
                self._absent(publication.JOURNAL)
            else:
                actual = files._file_identity(os.fstat(self.directory))
                named = files._file_identity(os.stat(publication.JOURNAL, dir_fd=self.parent, follow_symlinks=False))
                _require(actual[:5] == named[:5] == self.directory_identity[:5])
                with os.scandir(self.directory) as entries:
                    _require(next(entries, None) is None)
            if self.installed:
                observed, info = files._read(self.parent, self.basename, bundles.MAX_POLICY_BUNDLE_BYTES)
                _require(observed == self.raw and files._file_identity(info) == self.installed_identity
                    == files._file_identity(os.fstat(self.stage_fd)))
            else:
                self._absent(self.basename)
        closing_mono, closing_epoch = time.monotonic_ns(), time.time_ns()
        _require(mono <= closing_mono < self.deadline and epoch <= closing_epoch < self.expires)
        self.mono, self.epoch = closing_mono, closing_epoch

    def run(self):
        try:
            self.check(); _require(not self.used)
            self.used = True
            # _connect retains this genuine reader before its first acquisition.
            with owning():
                GenesisRead._connect(self)
            self.authority.check(); self._absent(STAGE)
            with owning():
                self.stage_fd = self._hold(os.open(STAGE, os.O_RDWR | os.O_CREAT | os.O_EXCL
                    | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=self.parent))
            os.fchmod(self.stage_fd, 0o600)
            offset = 0
            while offset < len(self.raw):
                self.check()
                count = os.pwrite(self.stage_fd, self.raw[offset:offset + 65536], offset)
                _require(0 < count <= min(65536, len(self.raw) - offset)); offset += count
            os.fsync(self.stage_fd)
            staged, info = files._read(self.parent, STAGE, bundles.MAX_POLICY_BUNDLE_BYTES)
            _require(staged == self.raw and files._file_identity(info) == files._file_identity(os.fstat(self.stage_fd)))
            self.authority.check()
            with owning():
                _rename_noreplace(self.parent, STAGE, self.basename)
                self.installed = True
                self.installed_identity = files._file_identity(os.fstat(self.stage_fd))
            os.fsync(self.parent)
            self.authority.check(); self.check()
            result = {"status": "materialized-finalized-development-demo-policy",
                "policySha256": _sha(self.raw), **{key: self.material_binding[key] for key in
                    ("policyId", "sequence", "rollbackEpoch", "policyHash", "genesisPreparationDigest", "genesisFinalizationDigest")}}
            self.close()
            # Closing is allowed after expiry, but expired cleanup cannot turn
            # an uncertain publication into a successful bounded invocation.
            require_development()
            _require(self.mono <= time.monotonic_ns() < self.deadline
                and self.epoch <= time.time_ns() < self.expires)
            return result
        except BaseException as error:
            self.failed = True
            raise DevelopmentGenesisError(self) from error

    def close(self):
        if self.closed:
            return
        try:
            _require((self.pid, self.thread) == (os.getpid(), threading.get_ident())
                and not self.closing and not self.uncertain)
            self.closing = True
            with owning():
                if self.authority is not None:
                    self.uncertain = True
                    self.authority.close()
                    self.authority = None
                    self.uncertain = False
                while self.handles:
                    row = self.handles[-1]
                    if row[1] is not None:
                        _require((os.fstat(row[0]).st_dev, os.fstat(row[0]).st_ino) == row[1])
                    descriptor, row[0] = row[0], None
                    self.uncertain = True
                    os.close(descriptor)
                    self.handles.pop(); self.uncertain = False
                self.closed = True
        except BaseException as error:
            self.uncertain = True
            raise DevelopmentGenesisError(self) from error
