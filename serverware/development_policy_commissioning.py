"""One live development-demo genesis caller, never an evidence authority.

The genuine runtime client prepares the policy, and this same owner retains
that actual result until finalization.  Independent automation must produce
the real inclusion/evidence and a fresh bound WebAuthn assertion, write the
reserved finalize memfd, and seal it.  Neither signed history nor an input FD
establishes those authorities.  The existing verifier and PostgreSQL owner
perform their normal checks; this module neither connects to SQL nor signs.

An exception after a request is sent is not rollback.  Preserve the actual
results and reconcile externally; there is no retry, reset or file install.
The finalized-policy filesystem materializer is deliberately separate.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import select
import stat
import sys
import threading
import time

MAX_WINDOW_NS = 300_000_000_000
MAX_INPUT = 4 * 1024 * 1024 - 4096  # Leave room for the existing runtime envelope.
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
_TOKEN, _LIVE, _USED = object(), None, False
_DEVELOPMENT = frozenset({"dev", "development", "local", "test"})
_RUNTIME_SOURCES = (("SERVERWARE_POLICY_AUTHORITY_RUNTIME_ROOT_PUBLIC_KEY", 64 * 1024),
    ("SERVERWARE_POLICY_AUTHORITY_RUNTIME_TRUST", 8 * 1024 * 1024))


class CommissioningError(ValueError):
    def __init__(self, owner=None):
        super().__init__("development commissioning refused; authority outcome may require reconciliation; do not retry")
        self.owner = owner


def _require(value):
    if not value:
        raise CommissioningError()


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value)
        value[key] = item
    return value


def _document(raw):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT)
    value = json.loads(raw, object_pairs_hook=_pairs)
    _require(type(value) is dict and _canonical(value) == raw)
    return value


def require_development():
    from serverware import config
    release = os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower()
    _require(not config.PRODUCTION_IMAGE and os.environ.get("SERVERWARE_PRODUCTION_IMAGE", "0") == "0"
        and release in _DEVELOPMENT and release == config.RELEASE_CHANNEL.strip().lower()
        and os.environ.get("SERVERWARE_PROCESS_MODE") == "serverware-control-plane")
    # This is only a genuine runtime client, not an offline SQL/bootstrap owner.
    _require(not any(value.strip() and (name.endswith(("_POSTGRES_DSN", "_POSTGRES_DSN_FD",
        "_POSTGRES_DSN_PATH", "_DATABASE_URL")) or name in {"DATABASE_URL", "PGHOST", "PGPORT",
        "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE"}) for name, value in os.environ.items()))


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source_identity(fd, maximum, *, runtime=False):
    _require(type(fd) is int and 3 <= fd < 2**31)
    before = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
        and not before.st_mode & 0o022 and 0 < before.st_size <= maximum
        and not flags & os.O_PATH and flags & os.O_ACCMODE != os.O_WRONLY)
    if not runtime:
        _require(before.st_gid == 0 and stat.S_IMODE(before.st_mode) == 0o400)
    if before.st_nlink == 0:
        _require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
    else:
        _require(before.st_nlink == 1 and flags & os.O_ACCMODE == os.O_RDONLY)
    return _identity(before)


def _read(fd, maximum, *, runtime=False):
    """No opens/dup: preserve the already admitted inherited descriptor set."""
    before = _source_identity(fd, maximum, runtime=runtime)
    result = bytearray()
    while len(result) < before[6]:
        part = os.pread(fd, min(65536, before[6] - len(result)), len(result))
        _require(bool(part)); result.extend(part)
    _require(not os.pread(fd, 1, before[6]) and _source_identity(fd, maximum, runtime=runtime) == before)
    return bytes(result), before


def _late_descriptor(fd):
    info = os.fstat(fd)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    _require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o400)
        and info.st_nlink == 0 and 0 <= info.st_size <= MAX_INPUT
        and not flags & os.O_PATH and flags & os.O_ACCMODE != os.O_WRONLY
        and fcntl.fcntl(fd, fcntl.F_GET_SEALS) in (0, SEALS))
    return _identity(info)[:6]


def _authorization(value):
    _require(type(value) is dict and set(value) == {"input", "webauthnAuthorization"}
        and type(value["input"]) is dict and type(value["webauthnAuthorization"]) is dict)
    authorization = value["webauthnAuthorization"]
    references = set(authorization) & {"credentialId", "credentialRecordId"}
    _require(len(references) == 1 and set(authorization) == {"challengeId", "assertion"} | references
        and type(authorization["assertion"]) is dict and bool(authorization["assertion"])
        and all(type(authorization[key]) is str and 0 < len(authorization[key]) <= 4096
            for key in references | {"challengeId"}))
    # Syntax only. The existing verifier must authenticate the fresh assertion.
    return value


def prepare_input(policy_raw, request_raw, *, now_unix_ns):
    from serverware.development_policy_genesis import signed_demo
    from serverware import authority_contract, authority_transition_policy as kernel
    trust, bound = signed_demo(policy_raw)
    request = _authorization(_document(request_raw))
    # The kernel consumes internally normalized arguments, not the caller's
    # runtime envelope. Reuse the genuine normalization solely for preflight;
    # preserve the original caller-free request for the actual runtime owner.
    intent = authority_contract.synthesize_business_intent("policy.genesis.prepare", request["input"])
    record, _, _ = kernel._genesis_prepare_arguments({**request["input"], "businessIntent": intent})
    _require(type(now_unix_ns) is int and record["prepared_at_epoch_ns"] <= now_unix_ns < record["expires_at_epoch_ns"]
        and all(record[key] == bound[source] for key, source in (
            ("policy_id", "policyId"), ("policy_sequence", "sequence"),
            ("rollback_epoch", "rollbackEpoch"), ("policy_hash", "policyHash"))))
    return request, record, trust


def finalize_input(raw, prepared):
    """Only the live owner's actual prepare result reaches this data checker."""
    from serverware import authority_contract, authority_transition_policy as kernel
    value = _authorization(_document(raw))
    intent = authority_contract.synthesize_business_intent("policy.genesis.finalize", value["input"])
    preparation, inclusion, _, store = kernel._genesis_finalize_arguments({**value["input"], "businessIntent": intent})
    _require(preparation == prepared["genesis_preparation_digest"]
        and inclusion.get("transition_digest") == prepared["genesis_transition_digest"]
        and inclusion.get("audit_store_identity_digest") == store)
    return value


def _prepared_result(value, record):
    _require(type(value) is dict and value.get("ok") is True and value.get("idempotent") is False
        and all(value.get(key) == item for key, item in record.items())
        and type(value.get("audit_submission")) is dict)
    _digest(value.get("genesis_transition_digest"))
    _require(value["audit_submission"].get("transition_digest") == value["genesis_transition_digest"])
    return value


def _finalized_result(value, prepared, request):
    _require(type(value) is dict and value.get("ok") is True and value.get("idempotent") is False
        and all(value.get(key) == prepared[key] for key in ("genesis_preparation_digest", "policy_id",
            "policy_sequence", "rollback_epoch", "policy_hash", "high_water_digest", "genesis_transition_digest"))
        and value.get("inclusion_receipt_envelope_digest")
            == request["input"]["inclusionReceipt"]["inclusion_receipt_envelope_digest"])
    _digest(value.get("finalization_digest"))
    return value


class DevelopmentPolicyCommissioning:
    """One-shot actual client; takes ownership of the four explicit CLI FDs."""
    def __init__(self, token, descriptors, deadline, expiry):
        _require(token is _TOKEN)
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.environment = tuple(sorted(os.environ.items()))
        self.mono, self.epoch = time.monotonic_ns(), time.time_ns()
        self.deadline, self.expiry = deadline, expiry
        self.handles = [[fd, None] for fd in descriptors]
        self.sources, self.runtime_sources = [], []
        self.client = self.trust = self.prepared = self.finalized = None
        self.late_raw = self.late_identity = self.pipe_identity = None
        self.used = self.failed = self.closed = self.uncertain = False

    @classmethod
    def open(cls, *, policy_fd, policy_sha256, prepare_fd, prepare_sha256, finalize_fd,
             result_fd, deadline_monotonic_ns, expires_at_unix_ns):
        global _USED, _LIVE
        require_development()
        _require(cls is DevelopmentPolicyCommissioning and not _USED and _LIVE is None
            and threading.current_thread() is threading.main_thread()
            and sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1)
        descriptors = (policy_fd, prepare_fd, finalize_fd, result_fd)
        _require(all(type(fd) is int and 3 <= fd < 2**31 for fd in descriptors) and len(set(descriptors)) == 4)
        _digest(policy_sha256); _digest(prepare_sha256)
        _require(type(deadline_monotonic_ns) is int and type(expires_at_unix_ns) is int)
        owner = cls(_TOKEN, descriptors, deadline_monotonic_ns, expires_at_unix_ns)
        _USED, _LIVE = True, owner
        try:
            _require(owner.mono < owner.deadline <= owner.mono + MAX_WINDOW_NS
                and owner.epoch < owner.expiry <= owner.epoch + MAX_WINDOW_NS)
            identities = []
            for row in owner.handles:
                row[1] = _identity(os.fstat(row[0])); identities.append(row[1][:2])
            _require(len(set(identities)) == 4)
            # Snapshot protected trust originals without acquiring any new FD;
            # the actual runtime admission follows before reading task inputs.
            for name, maximum in _RUNTIME_SOURCES:
                text = os.environ.get(name + "_FD", "")
                _require(re.fullmatch(r"[1-9][0-9]{0,9}", text) is not None
                    and not os.environ.get(name + "_PATH"))
                fd = int(text)
                raw, identity = _read(fd, maximum, runtime=True)
                _require(fd not in descriptors and identity[:2] not in identities)
                owner.runtime_sources.append((fd, maximum, raw, identity))
            from serverware.authority_service import AuthorityRuntimeClient
            owner.client = AuthorityRuntimeClient.from_environment()
            _require(type(owner.client) is AuthorityRuntimeClient
                and set(descriptors) <= set(owner.client.inherited_descriptors))
            _require(all(_identity(os.fstat(fd))[:2] not in identities
                for fd in owner.client.inherited_descriptors if fd not in descriptors))
            from serverware import policy_bundle as bundles
            for fd, pin, maximum in ((policy_fd, policy_sha256, bundles.MAX_POLICY_BUNDLE_BYTES),
                    (prepare_fd, prepare_sha256, MAX_INPUT)):
                raw, identity = _read(fd, maximum)
                _require(_sha(raw) == pin and identity[:2] == owner.handles[descriptors.index(fd)][1][:2])
                owner.sources.append((fd, maximum, raw, identity))
            owner.late_fd, owner.pipe_fd = finalize_fd, result_fd
            owner.late_identity = _late_descriptor(finalize_fd)
            _require(os.fstat(finalize_fd).st_size == 0 and fcntl.fcntl(finalize_fd, fcntl.F_GET_SEALS) == 0)
            pipe = os.fstat(result_fd); flags = fcntl.fcntl(result_fd, fcntl.F_GETFL)
            _require(stat.S_ISFIFO(pipe.st_mode) and pipe.st_nlink == 1
                and os.readlink("/proc/self/fd/" + str(result_fd)).startswith("pipe:[")
                and flags & os.O_ACCMODE == os.O_WRONLY and flags & os.O_NONBLOCK)
            owner.pipe_identity = _identity(pipe)[:6]
            owner.request, owner.record, owner.trust = prepare_input(owner.sources[0][2], owner.sources[1][2],
                now_unix_ns=time.time_ns())
            owner.expiry = min(owner.expiry, owner.record["expires_at_epoch_ns"])
            owner.check()
            return owner
        except BaseException as error:
            owner.failed = True
            raise CommissioningError(owner) from error

    def check(self, *, full=True):
        require_development()
        _require(type(self) is DevelopmentPolicyCommissioning and _LIVE is self
            and not (self.failed or self.closed or self.uncertain)
            and (self.pid, self.thread) == (os.getpid(), threading.get_ident())
            and self.environment == tuple(sorted(os.environ.items())))
        mono, epoch = time.monotonic_ns(), time.time_ns()
        _require(self.mono <= mono < self.deadline and self.epoch <= epoch < self.expiry)
        for fd, maximum, raw, identity in self.runtime_sources:
            _require((_read(fd, maximum, runtime=True) == (raw, identity)) if full else
                _source_identity(fd, maximum, runtime=True) == identity)
        for fd, maximum, raw, identity in self.sources:
            _require((_read(fd, maximum) == (raw, identity)) if full else
                _source_identity(fd, maximum) == identity)
        _require(_late_descriptor(self.late_fd) == self.late_identity
            and _identity(os.fstat(self.pipe_fd))[:6] == self.pipe_identity)
        if self.late_raw is not None and full:
            _require(_read(self.late_fd, MAX_INPUT)[0] == self.late_raw)
        from serverware import authority_service, policy_bundle as bundles
        _require(type(self.client) is authority_service.AuthorityRuntimeClient
            and authority_service._open_inherited_descriptors() == set(self.client.inherited_descriptors)
            and (os.geteuid(), os.getegid()) == (self.client.control_plane_uid, self.client.control_plane_gid))
        bundles._recheck_policy_signing_trust(self.trust)
        end_mono, end_epoch = time.monotonic_ns(), time.time_ns()
        _require(mono <= end_mono < self.deadline and epoch <= end_epoch < self.expiry)
        self.mono, self.epoch = end_mono, end_epoch

    def _until(self, *, full=False):
        self.check(full=full)
        return min(self.deadline, self.mono + self.expiry - self.epoch)

    def _write(self, value):
        from serverware import authority_contract
        raw = _canonical(value) + b"\n"
        _require(len(raw) <= authority_contract.MAX_RESULT_BYTES)
        poller = select.poll(); poller.register(self.pipe_fd, select.POLLOUT)
        offset = 0
        while offset < len(raw):
            self.check(full=False)
            if not poller.poll(min(100, max(1, (self._until() - time.monotonic_ns()) // 1_000_000))):
                continue
            try:
                count = os.write(self.pipe_fd, raw[offset:offset + 65536])
            except BlockingIOError:
                continue
            _require(count > 0); offset += count
        self.check()

    def run(self):
        try:
            self.check(); _require(not self.used); self.used = True
            # Preserve the actual result in this same owner, never a supplied
            # preparation DTO. Explicit original deadline requests definite
            # verifier commit and witness receipts in the existing client.
            self.prepared = _prepared_result(self.client.request(operation="policy.genesis.prepare",
                input_value=self.request, deadline_ns=self._until(full=True)), self.record)
            self.check(); self._write(self.prepared)
            while fcntl.fcntl(self.late_fd, fcntl.F_GET_SEALS) != SEALS:
                self.check(full=False)
                select.poll().poll(min(100, max(1, (self._until() - time.monotonic_ns()) // 1_000_000)))
            self.late_raw, _ = _read(self.late_fd, MAX_INPUT)
            final_request = finalize_input(self.late_raw, self.prepared)
            self.check()
            self.finalized = _finalized_result(self.client.request(operation="policy.genesis.finalize",
                input_value=final_request, deadline_ns=self._until(full=True)), self.prepared, final_request)
            self.check(); self._write(self.finalized)
            self.close()
            _require(self.mono <= time.monotonic_ns() < self.deadline
                and self.epoch <= time.time_ns() < self.expiry)
        except BaseException as error:
            self.failed = True
            raise CommissioningError(self) from error

    def close(self):
        if self.closed:
            return
        _require(_LIVE is self and (self.pid, self.thread) == (os.getpid(), threading.get_ident()) and not self.uncertain)
        bad = False
        while self.handles:
            fd, identity = self.handles.pop()
            try:
                # Late memfd bytes/seals may legitimately change. No descriptor
                # number is ever retried after an uncertain close.
                _require(identity is None or _identity(os.fstat(fd))[:2] == identity[:2])
                os.close(fd)
            except BaseException:
                bad = self.uncertain = True
        if bad:
            raise CommissioningError(self)
        self.closed = True
