"""Fixed one-shot private measured helper. Outputs only role ciphertext.

No file-key output, generic decryption, network connection, argv/environment
authority or claim of Python/OpenSSL allocation erasure. The launcher must pin
this complete interpreter/DSO/helper closure independently.
"""
from __future__ import annotations
import ctypes
import fcntl
import os
import select
import socket
import stat
import struct
import sys
import time

# Establish post-exec nondumpability before importing crypto or reading inputs.
if not sys.flags.isolated or len(sys.argv) != 1:
    os._exit(1)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
    os._exit(1)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from serverware import native_shadow_key_contract as c
from serverware.native_kms_cms import unwrap_broker_kek
p = c.p


class Channel:
    def __init__(self):
        info = os.fstat(4)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 0
                  and stat.S_IMODE(info.st_mode) == 0o600 and 1 <= info.st_size <= 1024
                  and fcntl.fcntl(4, fcntl.F_GET_SEALS) == 15)
        raw = os.pread(4, 1025, 0)
        original = p.document(raw, 1024)
        p.fields(original, ("apiVersion", "uid", "gid", "deadlineBoottimeNs"))
        p.require(original["apiVersion"] == "serverware.nativeShadowKeyHelperBootstrap/v1"
                  and len(raw) == info.st_size and os.getresuid() == (original["uid"],)*3
                  and os.getresgid() == (original["gid"],)*3 and original["uid"] > 0 and original["gid"] > 0
                  and not os.getgroups() and libc.prctl(39, 0, 0, 0, 0) == 1)
        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
        class Caps(ctypes.Structure):
            _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]
        header = Header(0x20080522, 0); caps = (Caps*2)()
        p.require(libc.capget(ctypes.byref(header), caps) == 0
                  and all(not x.effective and not x.permitted and not x.inheritable for x in caps))
        self.uid, self.gid = original["uid"], original["gid"]
        self.deadline = p.ns(original["deadlineBoottimeNs"])
        self.last = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        p.require(self.last < self.deadline)
        # Linux x86_64 fixed measured profile: SIGEV_SIGNAL's union is 8 bytes,
        # followed by signo/notify. Absolute BOOTTIME survives parent loss.
        p.require(ctypes.sizeof(ctypes.c_void_p) == 8 and sys.byteorder == "little" and os.uname().machine == "x86_64")
        event = ctypes.create_string_buffer(64)
        struct.pack_into("=Qii", event, 0, 0, 9, 0)
        self.timer = ctypes.c_void_p()
        p.require(libc.timer_create(time.CLOCK_BOOTTIME, event, ctypes.byref(self.timer)) == 0)
        class Timespec(ctypes.Structure):
            _fields_ = [("seconds", ctypes.c_long), ("nanos", ctypes.c_long)]
        class Schedule(ctypes.Structure):
            _fields_ = [("interval", Timespec), ("value", Timespec)]
        schedule = Schedule(Timespec(0, 0), Timespec(self.deadline//10**9, self.deadline%10**9))
        p.require(libc.timer_settime(self.timer, 1, ctypes.byref(schedule), None) == 0)
        self.socket = socket.socket(fileno=3)
        p.require(self.socket.family == socket.AF_UNIX and self.socket.type == socket.SOCK_STREAM
                  and not self.socket.getsockname() and not self.socket.getpeername())
        self.parent, uid, gid = struct.unpack("3i", self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        p.require(self.parent == os.getppid() and self.parent > 1 and uid == gid == 0)
        self.parent_fd = struct.unpack("i", self.socket.getsockopt(socket.SOL_SOCKET, 77, 4))[0]
        p.require(self.parent_fd >= 0)
        self.pid = os.getpid()
        self.check()

    def check(self):
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        p.require(os.getpid() == self.pid and os.getppid() == self.parent and self.last <= now < self.deadline
                  and not select.select([self.parent_fd], [], [], 0)[0])
        self.last = now
        self.socket.settimeout(min(0.1, (self.deadline-now)/10**9))

    def read(self, count):
        result = bytearray()
        while len(result) < count:
            self.check()
            try:
                part = self.socket.recv(count-len(result))
            except socket.timeout:
                continue
            p.require(part); result.extend(part)
        self.check()
        return bytes(result)

    def receive(self):
        size = int.from_bytes(self.read(4), "big")
        p.integer(size, maximum=c.MAX_FRAME)
        return p.document(self.read(size), c.MAX_FRAME)

    def send(self, value):
        raw = p.canonical(value); p.require(0 < len(raw) <= c.MAX_FRAME)
        remaining = memoryview(len(raw).to_bytes(4, "big")+raw)
        while remaining:
            self.check()
            try:
                count = self.socket.send(remaining)
            except socket.timeout:
                continue
            p.require(count > 0); remaining = remaining[count:]
        self.check()


def run():
    channel = Channel()
    start = channel.receive()
    p.fields(start, ("apiVersion", "phase", "binding", "transport", "roleRecipientPublicKey"))
    p.require(start["apiVersion"] == c.CHANNEL and start["phase"] == "initialize")
    binding, transport = c.binding(start["binding"]), c.transport(start["transport"])
    guest, inventory = binding["guest"], binding["inventory"]
    p.require(guest["uid"] == channel.uid and guest["gid"] == channel.gid
              and p.ns(guest["startupDeadlineBoottimeNs"]) == channel.deadline)
    recipient_raw = p.decoded(start["roleRecipientPublicKey"], size=32)
    p.require(recipient_raw != bytes(32))
    recipient = x25519.X25519PublicKey.from_public_bytes(recipient_raw)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    channel.send({"apiVersion":c.CHANNEL, "phase":"recipient", "recipientPublicKey":p.encoded(public),
                  "recipientPublicKeySha256":p.sha(public)})
    frame = channel.receive()
    p.fields(frame, ("apiVersion", "phase", "request", "requestSha256", "ciphertextForRecipient", "ciphertextSha256", "encryptedInventory"))
    request = c.request(frame["request"])
    p.require(frame["apiVersion"] == c.CHANNEL and frame["phase"] == "provision"
              and request["binding"] == binding and request["transport"] == transport
              and request["roleRecipientPublicKey"] == start["roleRecipientPublicKey"]
              and request["recipientPublicKeySha256"] == p.sha(public)
              and frame["requestSha256"] == p.sha(p.canonical(request)))
    cms = p.decoded(frame["ciphertextForRecipient"], maximum=65536)
    p.require(p.sha(cms) == p.digest(frame["ciphertextSha256"]))
    # Only the existing pinned closed AWS CMS primitive is reused, not a gate
    # or response-v2 role owner/assignment/permission.
    kek = unwrap_broker_kek(cms, private); private = None
    p.require(p.sha(kek) == transport["kekSha256"])
    encrypted = frame["encryptedInventory"]
    p.require(p.sha(p.canonical(encrypted)) == transport["encryptedInventorySha256"])
    iv, ciphertext = c.encrypted(encrypted, inventory)
    raw = AESGCM(kek).decrypt(iv, ciphertext, c.aad(inventory)); kek = None
    payload = c.seeds(p.document(raw, 16368), inventory)
    for item, key in zip(payload["seeds"], inventory["localKeys"]):
        p.fields(item, ("role", "keyId", "seedBase64url"))
        p.require(item["role"] == key["role"] and item["keyId"] == key["keyId"])
        seed = p.decoded(item["seedBase64url"], size=32)
        actual = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(actual) == key["publicKeyBase64url"])
    channel.check()
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = ephemeral.exchange(recipient)
    p.require(shared != bytes(32))
    aad = c.OUTPUT_DOMAIN+p.raw_digest(frame["requestSha256"])
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=c.nonce(binding), info=aad).derive(shared)
    nonce = os.urandom(12)
    output = AESGCM(key).encrypt(nonce, raw, aad)
    channel.send({"apiVersion":"serverware.nativeShadowRoleRecipientCiphertext/v1", "requestSha256":frame["requestSha256"],
                  "recipientPublicKey":start["roleRecipientPublicKey"], "serverEphemeralPublicKey":p.encoded(
                      ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
                  "aeadNonce":p.encoded(nonce), "ciphertext":p.encoded(output)})
    # The entire dedicated process exits, never a persistent key service.


if __name__ == "__main__":
    try:
        run()
    except BaseException:
        os._exit(1)
