"""Authenticated inherited seqpacket transport for eight independent approvals.

The channel conveys observations and already provisioned public descriptors;
it never creates a currentness decision, approval, signature or installed file.
The real supervisor's protected intake still checks both originals, signatures,
root:root0400/sealed ownership, exact request association and live owners.

Linux SO_PEERPIDFD and per-message SCM_CREDENTIALS are mandatory. Request and
observation originals use bounded ordered packets, not one oversized seqpacket.
Every failure consumes this channel; no reconnect, resend or new deadline exists.
"""
from __future__ import annotations

import array
import contextlib
import fcntl
import os
import select
import signal
import socket
import stat
import struct
import threading
import time

from serverware import native_pilot_supervisor_current_head_profile as heads
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware.native_pilot_phase_execution import JOBS, MAX_APPROVAL

REQUEST_API = "serverware.nativePilotCurrentHeadApprovalRequest/v1"
CHUNK_API = "serverware.nativePilotCurrentHeadApprovalChunk/v1"
REPLY_API = "serverware.nativePilotCurrentHeadApprovalReply/v1"
RECEIPT_API = "serverware.nativePilotCurrentHeadApprovalReceipt/v1"
MAX_REQUEST = 32 * 1024 * 1024 - 1
MAX_FRAME = 48 * 1024
CHUNK_BYTES = 32 * 1024
MAX_TOTAL = 128 * 1024 * 1024
SO_PEERPIDFD = 77
SCM_PIDFD = 4
_CREDENTIALS = struct.Struct("=iII")
PENDING_FIELDS = ("phase", "job", "sequence", "status", "requestOriginal", "requestSha256",
    "observationOriginal", "observationSha256")
REQUEST_FIELDS = ("apiVersion", "exchangeSequence", "phase", "job", "sequence", "deadlineBoottimeNs", "request", "observation")
CHUNK_FIELDS = ("apiVersion", "requestBindingSha256", "field", "offset", "dataBase64url")
REPLY_FIELDS = ("apiVersion", "requestBindingSha256", "inputSha256", "approvalSha256")
ADOPTED_REQUEST_API = "serverware.nativePilotAdoptedApprovalRequest/v1"
ADOPTED_CHUNK_API = "serverware.nativePilotAdoptedApprovalChunk/v1"
ADOPTED_REPLY_API = "serverware.nativePilotAdoptedApprovalReply/v1"
ADOPTED_RECEIPT_API = "serverware.nativePilotAdoptedApprovalReceipt/v1"
_TOKEN = object()
_CLAIMED = set()
_SEQUENCES = {job.name: sum(len(jobs) for phase, jobs in JOBS.items()
    if list(JOBS).index(phase) < list(JOBS).index("bridge-runtime")) + index + 1
    for index, job in enumerate(JOBS["bridge-runtime"][:len(heads.JOB_NAMES)])}


class ApprovalChannelError(ValueError):
    def __init__(self):
        super().__init__("native pilot approval channel refused; no retry authorized")


def _require(value):
    if not value:
        raise ApprovalChannelError()


def _clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def _identity(fd):
    value = os.fstat(fd)
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


@contextlib.contextmanager
def _owning_descriptors():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _close(fds):
    with _owning_descriptors():
        for fd in set(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _descriptor(fd, maximum):
    _require(type(fd) is int and fd >= 3 and not os.get_inheritable(fd))
    flags, info = fcntl.fcntl(fd, fcntl.F_GETFL), os.fstat(fd)
    _require(not flags & os.O_PATH and flags & os.O_ACCMODE != os.O_WRONLY
        and stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum)
    # This is transport framing, not the protected intake's file admission.
    return info.st_dev, info.st_ino, info.st_size


def _pending(value, index):
    p.fields(value, PENDING_FIELDS)
    _require(index < len(heads.JOB_NAMES) and value["phase"] == "bridge-runtime"
        and value["job"] == heads.JOB_NAMES[index]
        and type(value["sequence"]) is int and value["sequence"] == _SEQUENCES[value["job"]]
        and value["status"] == "awaiting-independent-current-head-approval")
    raws = {}
    for name, maximum in (("request", MAX_REQUEST), ("observation", heads.MAX_OBSERVED)):
        text = value[name + "Original"]
        _require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
        raws[name] = text.encode("ascii")
        _require(p.sha(raws[name]) == p.digest(value[name + "Sha256"]))
    request = p.fields(p.document(raws["request"], MAX_REQUEST), ("apiVersion", "sequence", "conductorSequence",
        "conductorRequestSha256", "phase", "jobIndex", "job", "deadlineBoottimeNs", "conductorRequest", "previousResult"))
    _require(request["apiVersion"] == "serverware.nativePilotAuthorityJobRequest/v1"
        and request["phase"] == value["phase"] and request["job"] == value["job"]
        and type(request["jobIndex"]) is int and request["jobIndex"] == index + 1
        and type(request["sequence"]) is int and request["sequence"] == value["sequence"])
    observation = p.document(raws["observation"], heads.MAX_OBSERVED)
    _require(observation.get("apiVersion") == heads.OBSERVED_API and observation.get("jobName") == value["job"])
    deadline = min(p.ns(request["deadlineBoottimeNs"]),
        p.integer(observation["deadlineBoottimeNanos"], maximum=p.MAX_I64))
    header = {"apiVersion": REQUEST_API, "exchangeSequence": index + 1, "phase": value["phase"],
        "job": value["job"], "sequence": value["sequence"], "deadlineBoottimeNs": str(deadline),
        **{name: {"length": len(raw), "sha256": p.sha(raw)} for name, raw in raws.items()}}
    return header, raws, deadline


def _pending_adopted(value, index):
    from serverware import native_pilot_adopted_phase_profile as adopted
    from serverware.native_pilot_adopted_supervisor_policy import catalogue_original
    p.fields(value, PENDING_FIELDS)
    order = tuple((phase, job.name) for phase, rows in adopted.JOBS.items() for job in rows)
    _require(type(index) is int and 0 <= index < len(order)
        and (value["phase"], value["job"]) == order[index]
        and type(value["sequence"]) is int and value["sequence"] == index + 1
        and value["status"] == "awaiting-independent-job-approval")
    raws = {}
    for name in ("request", "observation"):
        text = value[name + "Original"]
        _require(type(text) is str and text.isascii() and 0 < len(text) <= MAX_REQUEST)
        raws[name] = text.encode("ascii")
        _require(p.sha(raws[name]) == p.digest(value[name + "Sha256"]))
    request = p.fields(p.document(raws["request"], MAX_REQUEST), adopted.REQUEST_FIELDS)
    _require(request["apiVersion"] == adopted.API and request["sequence"] == index + 1
        and (request["phase"], request["job"]) == order[index]
        and request["jobIndex"] == adopted.job_index(value["phase"], value["job"]))
    observation = p.fields(p.document(raws["observation"], MAX_REQUEST), ("apiVersion", "policySha256",
        "catalogueSha256", "intakeConfigurationSha256", "conductorRequestOriginal",
        "measuredConfiguration", "recipeOriginals"))
    _require(observation["apiVersion"] == "serverware.nativePilotAdoptedSupervisorObservation/v1"
        and observation["catalogueSha256"] == p.sha(catalogue_original()))
    for name in ("policySha256", "intakeConfigurationSha256"):
        p.digest(observation[name])
    text = observation["conductorRequestOriginal"]
    _require(type(text) is str and text.isascii() and 0 < len(text) <= MAX_REQUEST)
    conductor_raw = text.encode("ascii")
    conductor = p.fields(p.document(conductor_raw, MAX_REQUEST), ("apiVersion", "sequence", "phase", "payload",
        "deadlineBoottimeNs", "expiresAtUnixNanos"))
    _require(conductor["apiVersion"] == "serverware.nativePilotOperatorRequest/v2"
        and p.sha(conductor_raw) == request["conductorRequestSha256"]
        and conductor["sequence"] == request["conductorSequence"] and conductor["phase"] == request["phase"]
        and conductor["deadlineBoottimeNs"] == request["deadlineBoottimeNs"]
        and conductor["expiresAtUnixNanos"] == request["expiresAtUnixNanos"])
    deadline, expiry = p.ns(request["deadlineBoottimeNs"]), p.ns(request["expiresAtUnixNanos"])
    p.integer(expiry, maximum=p.MAX_I64)
    header = {"apiVersion": ADOPTED_REQUEST_API, "exchangeSequence": index + 1,
        "phase": value["phase"], "job": value["job"], "sequence": value["sequence"],
        "deadlineBoottimeNs": str(deadline), "expiresAtUnixNanos": str(expiry),
        **{name: {"length": len(raw), "sha256": p.sha(raw)} for name, raw in raws.items()}}
    return header, raws, deadline


class ReceivedApproval:
    """Actual descriptors also retained by the channel until terminal cleanup."""
    def __init__(self, token, fds, reply):
        _require(token is _TOKEN)
        self._fds, self._reply, self._pid = tuple(fds), dict(reply), os.getpid()
        self._closed = False

    def resume_kwargs(self):
        _require(not self._closed and os.getpid() == self._pid)
        return {"input_fd": self._fds[0], "input_sha256": self._reply["inputSha256"],
            "approval_fd": self._fds[1], "approval_sha256": self._reply["approvalSha256"]}

    def close(self):
        _require(os.getpid() == self._pid)
        with _owning_descriptors():
            if not self._closed:
                self._closed = True
                _close(self._fds)


class _Connection:
    @classmethod
    def open_adopted(cls, fd, *, peer_pid, peer_uid, peer_gid):
        owner = cls.open(fd, peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid)
        owner._adopted = True
        return owner

    @classmethod
    def open(cls, fd, *, peer_pid, peer_uid, peer_gid):
        _require(cls in (ApprovalChannel, ApprovalPeer) and type(fd) is int and fd >= 3)
        p.integer(peer_pid, minimum=2, maximum=(1 << 31) - 1)
        p.integer(peer_uid, minimum=0, maximum=(1 << 32) - 2)
        p.integer(peer_gid, minimum=0, maximum=(1 << 32) - 2)
        identity = _identity(fd)
        _require(stat.S_ISSOCK(identity[2]))
        claim = os.getpid(), identity
        _require(claim not in _CLAIMED)
        _CLAIMED.add(claim)  # Failure never permits reopening the same inherited endpoint.
        owner = cls()
        owner._socket, owner._peer_fd = None, None
        owner._pid, owner._boot = os.getpid(), originals._boot()
        owner._local_ids = os.getresuid(), os.getresgid()
        owner._peer = peer_pid, peer_uid, peer_gid
        owner._closed = owner._failed = False
        owner._received = []
        owner._active = None
        owner._adopted, owner._epoch_limit = False, None
        owner._wall = time.time_ns()
        owner._index = owner._total = 0
        owner._last = _clock()
        owner._lock = threading.Lock()
        held = None
        try:
            os.set_inheritable(fd, False)
            held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
            owner._socket = socket.socket(fileno=held)
            held = None
            channel = owner._socket
            _require(channel.family == socket.AF_UNIX
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0)
            channel.getpeername()  # Must already be connected; no address discovery/connect.
            _require(_CREDENTIALS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == owner._peer)
            owner._peer_fd = struct.unpack("i", channel.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, 4))[0]
            _require(owner._peer_fd >= 3)
            os.set_inheritable(owner._peer_fd, False)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            owner._socket_identity = _identity(channel.fileno())
            owner._peer_identity = _identity(owner._peer_fd)
            owner.check()
            return owner
        except BaseException:
            if held is not None:
                _close((held,))
            owner.close()
            raise ApprovalChannelError() from None

    def check(self):
        return self._check(peer_live=True)

    def _check(self, *, peer_live):
        try:
            _require(not self._closed and not self._failed and os.getpid() == self._pid
                and originals._boot() == self._boot and (os.getresuid(), os.getresgid()) == self._local_ids)
            channel = self._socket
            _require(_identity(channel.fileno()) == self._socket_identity and not os.get_inheritable(channel.fileno())
                and _identity(self._peer_fd) == self._peer_identity and not os.get_inheritable(self._peer_fd)
                and _CREDENTIALS.unpack(channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)) == self._peer
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
                and (not peer_live or not select.select([self._peer_fd], [], [], 0)[0]))
            now = _clock()
            _require(now >= self._last and (self._active is None or now < self._active))
            if self._adopted:
                epoch = time.time_ns()
                _require(self._wall <= epoch and (self._epoch_limit is None or epoch < self._epoch_limit))
                self._wall = epoch
            self._last = now
            return now
        except BaseException:
            self._failed = True
            raise ApprovalChannelError() from None

    def _wait(self, reading):
        while True:
            now = self.check()
            _require(self._active is not None)
            interval = min(0.05, (self._active - now) / 1_000_000_000)
            ready, writable, _ = select.select([self._socket] if reading else [],
                [] if reading else [self._socket], [], interval)
            self.check()
            if ready or writable:
                return

    def _count(self, size):
        _require(0 < size <= MAX_TOTAL - self._total)
        self._total += size

    def _send(self, value, fds=(), *, receipt=False):
        raw = p.canonical(value)
        _require(0 < len(raw) <= MAX_FRAME and len(raw) <= MAX_TOTAL - self._total)
        ancillary = [] if not fds else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))]
        while True:
            self._wait(False)
            try:
                count = self._socket.sendmsg([raw], ancillary, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
            except (InterruptedError, BlockingIOError):
                continue  # No packet was transferred; never resend positive/ambiguous progress.
            _require(count == len(raw))
            self._count(count)
            # A received receipt permits the independent peer to retire.
            # Never require it to remain alive after this atomic positive send.
            self._check(peer_live=not receipt)
            return

    def _receive(self, rights, *, received=None):
        # A rights-bearing receive uses the caller's existing ownership list.
        # A signal between this return and caller assignment cannot orphan it.
        _require(rights == 0 or received is not None)
        received = [] if received is None else received
        _require(not received)
        transferred = False
        try:
            while True:
                self._wait(True)
                previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
                try:
                    raw, ancillary, flags, _ = self._socket.recvmsg(MAX_FRAME,
                        socket.CMSG_SPACE(12) + socket.CMSG_SPACE(16 * array.array("i").itemsize),
                        socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
                    credentials, invalid = [], False
                    # SIGINT/SIGTERM cannot interrupt the gap between kernel
                    # descriptor installation and ownership by this finally.
                    for level, kind, data in ancillary:
                        if level == socket.SOL_SOCKET and kind in (socket.SCM_RIGHTS, SCM_PIDFD):
                            values = array.array("i")
                            width = values.itemsize
                            values.frombytes(data[:len(data) - len(data) % width])
                            received.extend(values)
                            invalid |= kind != socket.SCM_RIGHTS or len(data) % width != 0
                        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == 12:
                            credentials.append(_CREDENTIALS.unpack(data))
                        else:
                            invalid = True
                    break
                except (InterruptedError, BlockingIOError):
                    continue
                finally:
                    # Restoring may immediately raise the caller's handler;
                    # every delivered FD is already covered by the outer finally.
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            # The kernel closes descriptors omitted by ancillary truncation.
            _require(raw and not invalid and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                and credentials == [self._peer] and len(received) == rights)
            self._count(len(raw))
            value = p.document(raw, MAX_FRAME)
            self.check()
            transferred = True
            return value, received
        finally:
            if not transferred:
                with _owning_descriptors():
                    _close(received)
                    received.clear()

    def close(self):
        _require(os.getpid() == self._pid)
        with _owning_descriptors():
            if self._closed:
                return
            self._closed = True
            for received in self._received:
                received.close()
            if self._socket is not None:
                self._socket.close()
            if self._peer_fd is not None:
                _close((self._peer_fd,))


class ApprovalChannel(_Connection):
    def exchange(self, pending):
        """One pending request consumes one exact two-descriptor response."""
        acquired, fds = self._lock.acquire(blocking=False), []
        result = None
        try:
            _require(acquired and self._active is None)
            self.check()
            header, originals_raw, self._active = (_pending_adopted if self._adopted else _pending)(pending, self._index)
            if self._adopted:
                expiry = p.ns(header["expiresAtUnixNanos"])
                _require(self._epoch_limit is None or self._epoch_limit == expiry)
                self._epoch_limit = expiry
            self.check()
            _require(not select.select([self._socket], [], [], 0)[0])
            binding = p.sha(p.canonical(header))
            self._send(header)
            for name, raw in originals_raw.items():
                for offset in range(0, len(raw), CHUNK_BYTES):
                    self._send({"apiVersion": ADOPTED_CHUNK_API if self._adopted else CHUNK_API, "requestBindingSha256": binding,
                        "field": name, "offset": offset, "dataBase64url": p.encoded(raw[offset:offset + CHUNK_BYTES])})
            reply, _ = self._receive(2, received=fds)
            p.fields(reply, REPLY_FIELDS)
            _require(reply["apiVersion"] == (ADOPTED_REPLY_API if self._adopted else REPLY_API)
                and reply["requestBindingSha256"] == binding)
            p.digest(reply["inputSha256"]); p.digest(reply["approvalSha256"])
            if self._adopted:
                from serverware import native_pilot_adopted_phase_profile as adopted
                maximum = adopted.BY_NAME[pending["job"]][1].maximum
            else:
                maximum = heads.MAX_INPUT
            identities = [_descriptor(fd, bound) for fd, bound in zip(fds, (maximum, MAX_APPROVAL), strict=True)]
            _require(identities[0][:2] != identities[1][:2])
            self.check()
            _require(not select.select([self._socket], [], [], 0)[0])
            with _owning_descriptors():
                accepted = ReceivedApproval(_TOKEN, fds, reply)
                self._received.append(accepted)
                fds.clear()
                result = accepted
            self._send({"apiVersion": ADOPTED_RECEIPT_API if self._adopted else RECEIPT_API, "requestBindingSha256": binding,
                "replySha256": p.sha(p.canonical(reply))}, receipt=True)
            self._index += 1
            self._active = None
            return result
        except BaseException:
            self._failed = True
            if result is not None:
                result.close()
            raise ApprovalChannelError() from None
        finally:
            _close(fds)
            if acquired:
                self._lock.release()


class ApprovalPeer(_Connection):
    """Independent operator adapter; supplied FDs must already be approved."""
    def receive(self, *, deadline_boottime_ns, expires_at_unix_ns=None):
        acquired = self._lock.acquire(blocking=False)
        try:
            if self._adopted:
                from serverware import native_pilot_adopted_phase_profile as adopted
                order = tuple((phase, job.name) for phase, rows in adopted.JOBS.items() for job in rows)
                expiry = p.integer(expires_at_unix_ns, maximum=p.MAX_I64)
                _require(self._epoch_limit is None or expiry == self._epoch_limit)
                self._epoch_limit = expiry
            else:
                _require(expires_at_unix_ns is None)
                order = tuple(("bridge-runtime", name) for name in heads.JOB_NAMES)
            _require(acquired and self._active is None and self._index < len(order))
            self.check()
            self._active = p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
            self.check()
            header, _ = self._receive(0)
            p.fields(header, REQUEST_FIELDS + (("expiresAtUnixNanos",) if self._adopted else ()))
            _require(header["apiVersion"] == (ADOPTED_REQUEST_API if self._adopted else REQUEST_API)
                and type(header["exchangeSequence"]) is int and header["exchangeSequence"] == self._index + 1
                and (header["phase"], header["job"]) == order[self._index]
                and type(header["sequence"]) is int
                and header["sequence"] == (self._index + 1 if self._adopted else _SEQUENCES[header["job"]]))
            if self._adopted:
                expiry = p.ns(header["expiresAtUnixNanos"])
                _require(expiry <= self._epoch_limit and (self._index == 0 or expiry == self._epoch_limit))
                self._epoch_limit = expiry
            selected_deadline = p.ns(header["deadlineBoottimeNs"])
            _require(selected_deadline <= self._active)
            self._active = selected_deadline
            binding, values = p.sha(p.canonical(header)), {}
            for name, maximum in (("request", MAX_REQUEST), ("observation", MAX_REQUEST if self._adopted else heads.MAX_OBSERVED)):
                meta = p.fields(header[name], ("length", "sha256"))
                size = p.integer(meta["length"], maximum=maximum)
                p.digest(meta["sha256"])
                raw = bytearray()
                while len(raw) < size:
                    part, _ = self._receive(0)
                    p.fields(part, CHUNK_FIELDS)
                    _require(part["apiVersion"] == (ADOPTED_CHUNK_API if self._adopted else CHUNK_API)
                        and part["requestBindingSha256"] == binding
                        and part["field"] == name and type(part["offset"]) is int and part["offset"] == len(raw))
                    chunk = p.decoded(part["dataBase64url"], maximum=CHUNK_BYTES)
                    _require(len(chunk) == min(CHUNK_BYTES, size - len(raw)))
                    raw.extend(chunk)
                _require(p.sha(raw) == meta["sha256"])
                values[name] = bytes(raw).decode("ascii")
            pending = {"phase": header["phase"], "job": header["job"], "sequence": header["sequence"],
                "status": "awaiting-independent-job-approval" if self._adopted else "awaiting-independent-current-head-approval",
                "requestOriginal": values["request"],
                "requestSha256": header["request"]["sha256"], "observationOriginal": values["observation"],
                "observationSha256": header["observation"]["sha256"]}
            expected, _, deadline = (_pending_adopted if self._adopted else _pending)(pending, self._index)
            _require(p.canonical(expected) == p.canonical(header) and deadline == self._active)
            self.check()
            self._binding = binding
            self._job = header["job"]
            return pending  # Public observation data; never an approved input template.
        except BaseException:
            self._failed = True
            raise ApprovalChannelError() from None
        finally:
            if acquired:
                self._lock.release()

    def respond(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        acquired = self._lock.acquire(blocking=False)
        try:
            _require(acquired and self._active is not None and hasattr(self, "_binding"))
            self.check()
            if self._adopted:
                from serverware import native_pilot_adopted_phase_profile as adopted
                maximum = adopted.BY_NAME[self._job][1].maximum
            else:
                maximum = heads.MAX_INPUT
            first, second = _descriptor(input_fd, maximum), _descriptor(approval_fd, MAX_APPROVAL)
            _require(first[:2] != second[:2])
            p.digest(input_sha256); p.digest(approval_sha256)
            reply = {"apiVersion": ADOPTED_REPLY_API if self._adopted else REPLY_API, "requestBindingSha256": self._binding,
                "inputSha256": input_sha256, "approvalSha256": approval_sha256}
            self._send(reply, (input_fd, approval_fd))
            receipt, _ = self._receive(0)
            p.fields(receipt, ("apiVersion", "requestBindingSha256", "replySha256"))
            _require(receipt == {"apiVersion": ADOPTED_RECEIPT_API if self._adopted else RECEIPT_API, "requestBindingSha256": self._binding,
                "replySha256": p.sha(p.canonical(reply))})
            self.check()
            del self._binding
            self._index += 1
            self._active = None
        except BaseException:
            self._failed = True
            raise ApprovalChannelError() from None
        finally:
            if acquired:
                self._lock.release()
