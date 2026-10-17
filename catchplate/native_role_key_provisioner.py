"""One dedicated boot helper: KMS recipient -> authenticated inventory -> fixed FDs.

No command-line input, path opening, generic decrypt, serving broker, network
socket creation or secret response. This helper runs only from its pinned root.
"""
from __future__ import annotations

import ctypes
import fcntl
import hmac
import os
import secrets
import socket
import stat
import struct
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from catchplate import native_role_key_contract as c
from catchplate.native_kms_cms import unwrap_broker_kek


class Channel:
    def __init__(self):
        c.require(len(sys.argv) == 1 and os.getresuid() == (c.UID,)*3 and os.getresgid() == (c.UID,)*3
                  and os.getgroups() == [])
        libc = ctypes.CDLL(None, use_errno=True)
        c.require(libc.prctl(4, 0, 0, 0, 0) == 0 and libc.prctl(3, 0, 0, 0, 0) == 0
                  and libc.prctl(39, 0, 0, 0, 0) == 1)
        self.socket = socket.socket(fileno=3)
        c.require(self.socket.family == socket.AF_UNIX and self.socket.type == socket.SOCK_STREAM
                  and not self.socket.getsockname() and not self.socket.getpeername())
        self.parent, uid, gid = struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        c.require(uid == gid == 0 and self.parent == os.getppid() and self.parent > 1)
        self.pid = os.getpid()
        self.last = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.deadline = self.last + 10_000_000_000

    def check(self):
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        c.require(os.getpid() == self.pid and os.getppid() == self.parent and self.last <= now < self.deadline)
        self.last = now
        self.socket.settimeout(min(0.25, (self.deadline-now)/1e9))

    def read(self, count):
        result = bytearray()
        while len(result) < count:
            self.check()
            try:
                part = self.socket.recv(min(65536, count-len(result)))
            except socket.timeout:
                continue
            c.require(part); result.extend(part)
        self.check()
        return bytes(result)

    def receive(self):
        count = int.from_bytes(self.read(4), "big")
        c.integer(count, maximum=c.MAX_FRAME)
        return c.document(self.read(count))

    def send(self, value):
        raw = c.canonical(value); c.require(0 < len(raw) <= c.MAX_FRAME)
        remaining = memoryview(len(raw).to_bytes(4, "big") + raw)
        while remaining:
            self.check()
            try:
                written = self.socket.send(remaining[:65536])
            except socket.timeout:
                continue
            c.require(written > 0); remaining = remaining[written:]
        self.check()


def output(value, key, index, *, empty):
    c.closed(value, ("fd", "device", "inode"))
    c.require(value["fd"] == c.FIRST_FD+index)
    c.integer(value["device"], minimum=0); c.integer(value["inode"])
    fd = value["fd"]
    info = os.fstat(fd)
    c.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == (0 if empty else 32)
              and info.st_uid == key["uid"] and info.st_gid == key["gid"] and stat.S_IMODE(info.st_mode) == 0o400
              and (info.st_dev, info.st_ino) == (value["device"], value["inode"])
              and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY)
    return fd


def run():
    channel = Channel()
    start = channel.receive()
    c.closed(start, ("apiVersion", "phase", "deadlineBoottimeNs", "kekSha256", "inventory", "outputs"))
    c.require(start["apiVersion"] == c.CHANNEL and start["phase"] == "initialize")
    inventory = c.inventory(start["inventory"])
    deadline = c.integer(start["deadlineBoottimeNs"])
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    c.require(now < deadline <= now+600_000_000_000 and str(deadline) == inventory["deadlineBoottimeNs"])
    channel.deadline = deadline
    expected_kek = c.sha(start["kekSha256"])
    outputs = start["outputs"]
    c.require(type(outputs) is list and len(outputs) == len(inventory["keys"]))
    for index, (item, key) in enumerate(zip(outputs, inventory["keys"])):
        output(item, key, index, empty=True)
    channel.check()
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    nonce = secrets.token_bytes(32)
    channel.send({"apiVersion":c.CHANNEL,"phase":"recipient","recipientPublicKey":c.encoded(public),
                  "recipientPublicKeySha256":c.digest(public),"nonce":c.encoded(nonce)})
    value = channel.receive()
    c.closed(value, ("apiVersion", "phase", "request", "requestSha256", "ciphertextForRecipient", "ciphertextSha256", "encryptedInventory"))
    request = c.request(value["request"])
    c.require(value["apiVersion"] == c.CHANNEL and value["phase"] == "provision"
              and request["recipientPublicKeySha256"] == c.digest(public) and request["nonce"] == c.encoded(nonce)
              and request["configurationSha256"] == inventory["configurationSha256"]
              and request["deliveryInventorySha256"] == c.digest(c.canonical(inventory))
              and request["bootId"] == inventory["bootId"] and request["deadlineBoottimeNs"] == str(deadline)
              and value["requestSha256"] == c.digest(c.canonical(request)))
    original = c.decoded(value["ciphertextForRecipient"], 65536)
    c.require(c.digest(original) == c.sha(value["ciphertextSha256"]))
    # Reuse only closed CMS/RSA crypto. No broker owner, permission or phase is
    # borrowed; the distinct expected material commitment admits this KEK.
    kek = unwrap_broker_kek(original, private)
    private = None
    c.require(hmac.compare_digest(c.digest(kek), expected_kek))
    iv, ciphertext = c.encrypted(value["encryptedInventory"], inventory)
    raw = AESGCM(kek).decrypt(iv, ciphertext, c.AAD_DOMAIN+c.canonical(inventory))
    kek = None
    plaintext = c.document(raw, c.MAX_CIPHERTEXT)
    c.closed(plaintext, ("apiVersion", "inventorySha256", "seeds"))
    c.require(plaintext["apiVersion"] == c.PLAINTEXT and plaintext["inventorySha256"] == request["deliveryInventorySha256"]
              and type(plaintext["seeds"]) is list and len(plaintext["seeds"]) == len(outputs))
    seeds = []
    # Validate the entire encrypted inventory before the first file write.
    for item, key in zip(plaintext["seeds"], inventory["keys"]):
        seed = c.decoded(item, 32, 32)
        public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        c.require(hmac.compare_digest(c.digest(seed), key["seedSha256"])
                  and hmac.compare_digest(c.digest(public), key["publicKeySha256"]))
        seeds.append(seed)
    channel.check()
    for index, (item, key, seed) in enumerate(zip(outputs, inventory["keys"], seeds)):
        channel.check(); fd = output(item, key, index, empty=True)
        offset = 0
        while offset < 32:
            channel.check(); count = os.pwrite(fd, seed[offset:], offset)
            c.require(count > 0); offset += count
        os.fsync(fd)
        output(item, key, index, empty=False); channel.check()
        os.close(fd)
    # No assertion of Python immutable-byte erasure, readiness or cloud proof.
    seeds = plaintext = raw = None
    channel.send({"apiVersion":c.CHANNEL,"phase":"written","requestSha256":value["requestSha256"],
                  "inventorySha256":request["deliveryInventorySha256"],"files":len(outputs)})


if __name__ == "__main__":
    try:
        run()
    except BaseException:
        os._exit(1)
