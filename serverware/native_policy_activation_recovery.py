"""Read-only extraction of an already retained native publication handoff.

This is an evidence copier, not a signer or an activation authority. The real
protected record-inclusion operation still verifies the receipt and its exact
retained approval/preparation before any state change. Missing or partial files
are unresolved; this module never repairs or repeats a publication.
"""
from __future__ import annotations

import fcntl
import os
import stat
import time

from serverware import authority_policy_canary as p
from serverware import authority_policy_native_activation as profile
from serverware import native_policy_activation_inputs as inputs

SELECTION = "serverware.nativePolicyActivationRecoverySelection/v1"
STATE = "serverware.nativePolicyActivationState/v1"
MAX_STATE = 2 * profile.MAX_ORIGINAL + 16384
FILES = {"activation.lock", "activation-request.json", "activation-receipt.json", "publication.json"}


def selection(raw):
    value = profile.canonical_original(raw.decode("ascii"), 4096)
    p.require(type(value) is dict and set(value) == {"apiVersion", "activationId", "preparedSha256", "initialStateSha256", "journal"}
        and value["apiVersion"] == SELECTION)
    p.identifier(value["activationId"])
    p.digest(value["preparedSha256"]); p.digest(value["initialStateSha256"])
    journal = value["journal"]
    p.require(type(journal) is dict and set(journal) == {"device", "inode", "uid", "gid"})
    for name, limit in (("device", 2**64 - 1), ("inode", 2**64 - 1), ("uid", 2**32 - 2), ("gid", 2**32 - 2)):
        p.require(type(journal[name]) is int and 0 < journal[name] <= limit)
    return value


def _original(raw, maximum):
    return profile.canonical_original(raw.decode("ascii"), maximum)


def _handoff(selected, state_raw, request_raw, receipt_raw):
    state = _original(state_raw, MAX_STATE)
    p.require(type(state) is dict and set(state) == {"apiVersion", "assignmentPayloadSha256", "generationId",
        "generationPublicationEnvelopeSha256", "publication", "previousStateSha256", "preparedOriginal"}
        and state["apiVersion"] == STATE and state["previousStateSha256"] == selected["initialStateSha256"])
    prepared = profile.prepared(profile.canonical_original(state["preparedOriginal"]))
    p.require(prepared["activationId"] == selected["activationId"]
        and p.sha256(state["preparedOriginal"].encode("ascii")) == selected["preparedSha256"])
    for name in ("assignmentPayloadSha256", "generationId", "generationPublicationEnvelopeSha256"):
        p.require(state[name] == prepared[name])
    after = {**prepared["publicationAfter"], "revision": prepared["publicationBefore"]["revision"] + 1}
    p.require(state["publication"] == after)
    native = profile.native_request(_original(request_raw, profile.MAX_NATIVE))
    response = profile.canonical_original(native["prepareResponseOriginal"], profile.MAX_NATIVE)
    p.require(native["requestId"] == prepared["activationId"] and native["replayId"] == prepared["replayId"]
        and response["schema"] == profile.RESPONSE_SCHEMA and response["operation"] == profile.PREFIX + "consume"
        and response["result"]["preparedOriginal"] == state["preparedOriginal"]
        and response["result"]["preparedSha256"] == selected["preparedSha256"])
    receipt = _original(receipt_raw, 32768)
    p.require(type(receipt) is dict and set(receipt) == {"payload", "signature"})
    value = receipt["payload"]
    p.require(type(value) is dict and set(value) == profile.PUBLICATION_FIELDS
        and value["apiVersion"] == profile.PUBLICATION and value["purpose"] == profile.PUBLICATION_PURPOSE
        and value["requestSha256"] == p.sha256(request_raw) and value["preparedSha256"] == selected["preparedSha256"]
        and value["durableStateSha256"] == p.sha256(state_raw) and value["publicationAfter"] == after)
    for name in ("activationId", "replayId", "assignmentPayloadSha256", "generationId", "generationPublicationEnvelopeSha256",
            "publicationBefore", "trustCheckpoint", "expiresAtUnixNanos"):
        p.require(value[name] == prepared[name])
    interval = value["observedAtUnixNanos"]
    p.require(type(interval) is dict and set(interval) == {"earliest", "latest"}
        and prepared["issuedAtUnixNanos"] <= p.epoch(interval["earliest"]) <= p.epoch(interval["latest"]) < prepared["expiresAtUnixNanos"])
    p.digest(value["signingKeyId"]); p.digest(value["signingKeySpkiSha256"])
    p.decoded(receipt["signature"], 64, length=64)
    # No local key or timestamp grants authenticity. Return the exact existing
    # consumer shape and receipt bytes; protected settlement verifies them.
    result = {"nativeRequest": native, "publicationOriginal": receipt_raw.decode("ascii")}
    p.require(len(p.canonical(result)) <= profile.MAX_NATIVE)
    return result


class _JournalRead:
    def __init__(self, selected):
        self.selected, self.fds, self.parents, self.files = selected, [], [], {}
        self.pid, self.deadline = os.getpid(), time.monotonic_ns() + 30_000_000_000
        self.journal = None

    def __enter__(self):
        try:
            expected = self.selected["journal"]
            p.require(os.geteuid() in {0, expected["uid"]} and os.getuid() == os.geteuid())
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            parent = os.open("/", flags); self.fds.append(parent)
            for name in ("var", "lib", "serverware", "native-policy-activation"):
                info = os.fstat(parent)
                p.require(info.st_uid == info.st_gid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & 0o022 == 0)
                child = os.open(name, flags, dir_fd=parent); self.fds.append(child)
                self.parents.append((parent, name, child, inputs._identity(os.fstat(child))))
                parent = child
            info = os.fstat(parent)
            p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
            self.journal = os.open("journal", flags, dir_fd=parent); self.fds.append(self.journal)
            info = os.fstat(self.journal)
            p.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_dev, info.st_ino, info.st_uid, info.st_gid)
                == (expected["device"], expected["inode"], expected["uid"], expected["gid"]))
            self.parents.append((parent, "journal", self.journal, inputs._identity(info)))
            inputs._durable_fs(self.journal)
            lock = self._open("activation.lock", 0, 0o600)
            # A live exclusive publication owner makes this fail immediately.
            # Never stop that owner or infer that a busy journal is complete.
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.check()
            return self
        except BaseException:
            self.close()
            raise

    def _open(self, name, maximum, mode):
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.journal)
        self.fds.append(fd)
        info, expected = os.fstat(fd), self.selected["journal"]
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
            and (info.st_dev, info.st_uid, info.st_gid) == (expected["device"], expected["uid"], expected["gid"])
            and (info.st_size == 0 if maximum == 0 else 0 < info.st_size <= maximum))
        self.files[name] = (fd, inputs._file_identity(info), maximum)
        return fd

    def check(self):
        p.require(os.getpid() == self.pid and time.monotonic_ns() < self.deadline)
        inputs._durable_fs(self.journal)
        for parent, name, fd, identity in self.parents:
            p.require(inputs._identity(os.fstat(fd)) == identity
                and inputs._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)
        # Bound enumeration independently of how many unwanted files exist.
        # A fresh open-file description avoids sharing the retained directory's
        # readdir offset across repeated checks (scandir(fd) duplicates its FD).
        names = set()
        scan = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.journal)
        try:
            p.require(inputs._identity(os.fstat(scan)) == inputs._identity(os.fstat(self.journal)))
            with os.scandir(scan) as entries:
                for entry in entries:
                    p.require(entry.name in FILES and entry.name not in names and len(names) < len(FILES))
                    names.add(entry.name)
        finally:
            os.close(scan)
        p.require(names == FILES)
        for name, (fd, identity, _) in self.files.items():
            p.require(inputs._file_identity(os.fstat(fd)) == identity
                and inputs._file_identity(os.stat(name, dir_fd=self.journal, follow_symlinks=False)) == identity)

    def read(self, name, maximum):
        self.check()
        fd = self._open(name, maximum, 0o400)
        raw = os.pread(fd, maximum + 1, 0)
        p.require(len(raw) == os.fstat(fd).st_size)
        self.check()
        return raw

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def __exit__(self, *_):
        self.close()


def recover(selection_raw):
    selected = selection(selection_raw)
    with _JournalRead(selected) as journal:
        state_raw = journal.read("publication.json", MAX_STATE)
        request_raw = journal.read("activation-request.json", profile.MAX_NATIVE)
        receipt_raw = journal.read("activation-receipt.json", 32768)
        result = _handoff(selected, state_raw, request_raw, receipt_raw)
        journal.check()
        return result
