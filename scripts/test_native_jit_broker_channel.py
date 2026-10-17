#!/usr/bin/env python3
"""Real FD3 broker process and crypto, with public synthetic provisioning.

Run as UID/GID 65534 under a non-PID1 parent in the cached network-none image.
The unchanged helper checks its own anonymous socket, peer PID and dumpability.
Local RSA/CMS provisions a synthetic KEK; real service-token opening precedes
JIT configuration. The installed facade is intercepted only at its terminal
transport boundary, then actual service extraction constructs the public input.
No KMS, quote, signed cold configuration, native admission, SQL, approval or
authorized review-disclosure claim follows from this component test.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_DATA = tempfile.TemporaryDirectory(prefix="jit-broker-channel-")
os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
os.environ["CATCHPLATE_DATA_DIR"] = _DATA.name


def local_only(event, args):
    if event.startswith("sqlite3."):
        raise AssertionError("broker channel test forbids database access")
    if event == "socket.__new__" and args[1] not in (-1, socket.AF_UNIX):
        raise AssertionError("broker test permits only anonymous Unix sockets")
    if event.startswith("socket.") and event != "socket.__new__":
        raise AssertionError("broker test forbids network/DNS/listener operations")


sys.addaudithook(local_only)
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from scripts import test_authority_jit_private_request as ingress
from catchplate import authority_contract as contract
from catchplate import native_jit_review_material as material
from catchplate import native_service_tokens as service_tokens

SECOND = 1_000_000_000
CHANNEL = "catchplate.nativeJitReviewChannel/v1"
BROKER = "catchplate.nativeSecretBrokerChannel/v1"
KEY = bytes(range(32))  # Public synthetic KEK, never a KMS/native release.
MAX_FRAME = 8 * 1024 * 1024
IO_SECONDS = 5

# No production function, clock, verdict or UID is replaced. runpy executes the
# actual __main__ error boundary; -I ignores ambient Python paths and user-site.
BOOTSTRAP = r'''
import os, runpy, socket, sys
fd, root = int(sys.argv[1]), sys.argv[2]
if fd != 3:
    os.dup2(fd, 3, inheritable=True)
    os.close(fd)
else:
    os.set_inheritable(3, True)
def audit(event, args):
    if event.startswith("sqlite3."):
        raise RuntimeError("database unavailable")
    if event == "socket.__new__" and args[1] not in (-1, socket.AF_UNIX):
        raise RuntimeError("network unavailable")
    if event.startswith("socket.") and event != "socket.__new__":
        raise RuntimeError("network unavailable")
sys.addaudithook(audit)
sys.path.insert(0, root)
sys.argv = [root + "/catchplate/native_secret_broker_helper.py"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def der(tag, value):
    length = len(value)
    encoded = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "big")
    return bytes([tag]) + (bytes([length]) if length < 128 else bytes([128 + len(encoded)]) + encoded) + value


def seq(*values):
    return der(0x30, b"".join(values))


def oid(value):
    return der(6, bytes.fromhex(value))


def cms_for_recipient(public_der):
    """Independent closed DER producer using real OAEP, CBC and PKCS7 crypto."""
    recipient = serialization.load_der_public_key(public_der)
    content_key, iv = os.urandom(32), os.urandom(16)
    encrypted_key = recipient.encrypt(content_key, rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    padder = padding.PKCS7(128).padder()
    padded = padder.update(KEY) + padder.finalize()
    encryptor = Cipher(algorithms.AES(content_key), modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    sha256 = seq(oid("608648016503040201"), der(5, b""))
    oaep = seq(oid("2a864886f70d010107"), seq(der(0xA0, sha256),
        der(0xA1, seq(oid("2a864886f70d010108"), sha256))))
    key_transport = seq(der(2, b"\x02"), der(0x80, b"synthetic-recipient"), oaep, der(4, encrypted_key))
    content = seq(oid("2a864886f70d010701"),
        seq(oid("60864801650304012a"), der(4, iv)), der(0x80, encrypted))
    return seq(oid("2a864886f70d010703"), der(0xA0,
        seq(der(2, b"\x02"), der(0x31, key_transport), content)))


class Peer:
    """One actual child, bounded private frames and exact-PID cleanup only."""
    def __init__(self, test, *, private_floats=True):
        self.test = test
        values = ingress.source_values()
        if private_floats:
            values["canonical_request"]["finite"] = 1.25
            values["redacted_display"]["finite"] = -0.5
        operation, self.envelope = ingress.original.dispatch_input(values)
        test.assertEqual(operation, "jit.request")
        public, explicit, self.documents = ingress.extracted(self.envelope)
        test.assertIsNone(explicit)
        self.request = ingress.typed_request(public)
        self.key_id = "attested-memory-kek:" + sha(KEY)[7:31]
        identity = {name: sha(name.encode()) for name in (
            "holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "releaseRecordSha256",
            "policyHash", "configurationSha256", "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest")}
        identity.update(bootId=b64(b"b" * 32), policyHash=public["policy_hash"])
        identity["holderId"] = sha(b"catchplate/credential-currentness-holder/v1\0"
            + b"b" * 32 + bytes.fromhex(identity["keyId"][7:]))
        self.config = {"apiVersion": "catchplate.nativeJitReviewConfiguration/v1",
            "sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
            "controlPlaneConfigurationDigest": sha(b"synthetic configuration"),
            "deploymentId": "synthetic-offline", "instanceId": "spiffe://synthetic.invalid/native",
            "secretKekId": self.key_id, "identity": identity, "attemptCapacity": 2}

    def __enter__(self):
        self.stdout, self.stderr = tempfile.TemporaryFile(), tempfile.TemporaryFile()
        self.socket, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.process = subprocess.Popen([sys.executable, "-I", "-B", "-c", BOOTSTRAP,
                str(child.fileno()), str(ROOT)], pass_fds=(child.fileno(),), close_fds=True,
                stdin=subprocess.DEVNULL, stdout=self.stdout, stderr=self.stderr,
                env={"LANG": "C.UTF-8", "CATCHPLATE_PROCESS_MODE": "metadata-bootstrap",
                    "CATCHPLATE_RELEASE_CHANNEL": "dev", "CATCHPLATE_DATA_DIR": _DATA.name})
        except BaseException:
            self.socket.close()
            self.stdout.close()
            self.stderr.close()
            raise
        finally:
            child.close()
        return self

    def __exit__(self, kind, _error, _trace):
        self.socket.close()
        try:
            self.process.wait(timeout=IO_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=IO_SECONDS)
            if kind is None:
                self.test.fail("helper failed to exit after its private endpoint closed")
        finally:
            quiet = os.fstat(self.stdout.fileno()).st_size == os.fstat(self.stderr.fileno()).st_size == 0
            self.stdout.close()
            self.stderr.close()
        if kind is None:
            self.test.assertTrue(quiet, "helper emitted unexpected diagnostics (contents withheld)")

    def send(self, value):
        self.send_raw(canonical(value))

    def send_raw(self, raw):
        self.test.assertIs(type(raw), bytes)
        self.test.assertLessEqual(len(raw), MAX_FRAME)
        self.socket.settimeout(IO_SECONDS)
        self.socket.sendall(len(raw).to_bytes(4, "big") + raw)

    def receive(self):
        deadline = time.monotonic() + IO_SECONDS
        def read(length):
            result = bytearray()
            while len(result) < length:
                remaining = deadline - time.monotonic()
                self.test.assertGreater(remaining, 0, "private frame deadline exceeded")
                self.socket.settimeout(remaining)
                part = self.socket.recv(min(65536, length - len(result)))
                self.test.assertTrue(bool(part), "helper closed before a complete expected frame")
                result.extend(part)
            return bytes(result)
        length = int.from_bytes(read(4), "big")
        self.test.assertTrue(0 < length <= MAX_FRAME, "invalid private response frame length")
        raw = read(length)
        value = json.loads(raw)
        self.test.assertTrue(canonical(value) == raw, "response was not canonical JSON")
        for canary in ingress.CANARIES:
            self.test.assertTrue(canary.encode() not in raw, "private canary appeared in response")
        return value

    def closed(self):
        self.socket.settimeout(IO_SECONDS)
        try:
            result = self.socket.recv(1)
        except ConnectionResetError:
            result = b""
        self.test.assertTrue(result == b"", "refusal emitted a response instead of closing custody")
        self.test.assertEqual(self.process.wait(timeout=IO_SECONDS), 1)
        self.test.assertTrue(os.fstat(self.stdout.fileno()).st_size == os.fstat(self.stderr.fileno()).st_size == 0,
            "refusal emitted diagnostics (contents withheld)")

    def provision(self):
        self.deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 12 * SECOND
        self.send({"apiVersion": BROKER, "phase": "initialize", "deadlineBoottimeNs": self.deadline,
            "kekSha256": sha(KEY), "secretKekId": self.key_id})
        recipient = self.receive()
        self.test.assertEqual(set(recipient), {"apiVersion", "phase", "recipientPublicKey", "recipientPublicKeySha256"})
        self.test.assertEqual((recipient["apiVersion"], recipient["phase"]), (BROKER, "recipient"))
        public = unb64(recipient["recipientPublicKey"])
        self.test.assertEqual(sha(public), recipient["recipientPublicKeySha256"])
        ciphertext = cms_for_recipient(public)
        request_digest = sha(b"synthetic KMS request, not AWS admission")
        self.send({"apiVersion": BROKER, "phase": "provision", "requestSha256": request_digest,
            "recipientPublicKeySha256": sha(public), "ciphertextForRecipient": b64(ciphertext),
            "ciphertextSha256": sha(ciphertext)})
        self.test.assertEqual(self.receive(), {"apiVersion": BROKER, "phase": "provisioned", "requestSha256": request_digest})

    def service_request(self):
        binding = {"apiVersion": "catchplate.nativeServiceTokensBinding/v1",
            "instanceId": self.config["instanceId"], "dataPlaneBinaryDigest": self.config["identity"]["expectedBinaryDigest"],
            "policyHash": self.config["identity"]["policyHash"], "atomicReleaseAuthorizationEnabled": False,
            "credentialLeaseUrl": "https://synthetic.invalid/api/data-plane/credential-leases",
            "grantConsumeUrl": "https://synthetic.invalid/api/data-plane/grants/consume",
            "rateLimitConsumeUrl": "https://synthetic.invalid/api/data-plane/rate-limits/consume",
            "releaseAuthorizationBaseUrl": None}
        tokens = {name: "synthetic-only-token-0123456789-" + name for name in
            ("credentialLeaseToken", "grantConsumeToken", "rateLimitConsumeToken", "managementToken")}
        tokens["releaseAuthorizationToken"] = None
        key = x25519.X25519PrivateKey.generate()
        request = {"apiVersion": "catchplate.nativeBrokerOpenServiceTokens/v1", "operationId": "a" * 64,
            "gateRecipientPublicKey": b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
            "gateRecipientNonce": b64(b"n" * 32), "deadlineBoottimeNs": self.deadline,
            "expectedBinding": binding, "envelope": service_tokens.seal(tokens, binding, KEY, sha(KEY))}
        return request, key, tokens

    def open_service(self):
        request, key, tokens = self.service_request()
        self.send(request)
        result = self.receive()
        self.test.assertEqual(set(result), {"apiVersion", "requestSha256", "recipientPublicKey",
            "serverEphemeralPublicKey", "aeadNonce", "ciphertext"})
        self.test.assertEqual(result["apiVersion"], "catchplate.nativeServiceTokensGateCiphertext/v1")
        self.test.assertEqual(result["requestSha256"], sha(canonical(request)))
        self.test.assertEqual(result["recipientPublicKey"], request["gateRecipientPublicKey"])
        aad = b"catchplate/native-service-tokens-gate-ciphertext/v1\0" + bytes.fromhex(result["requestSha256"][7:])
        shared = key.exchange(x25519.X25519PublicKey.from_public_bytes(unb64(result["serverEphemeralPublicKey"])))
        transport_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"n" * 32, info=aad).derive(shared)
        plaintext = AESGCM(transport_key).decrypt(unb64(result["aeadNonce"]), unb64(result["ciphertext"]), aad)
        self.test.assertTrue(plaintext == canonical({"apiVersion": "catchplate.nativeServiceTokens/v1", "tokens": tokens}),
            "actual service-token reply did not decrypt to the original fixture")
        self.test.assertTrue(all(value is None or value.encode() not in canonical(result) for value in tokens.values()),
            "service token escaped outside encrypted transport")

    def configure(self):
        self.send({"apiVersion": CHANNEL, "phase": "configure", "configuration": self.config})
        self.test.assertEqual(self.receive(), {"apiVersion": CHANNEL, "phase": "configured"})

    def ready(self):
        self.provision()
        self.open_service()
        self.configure()

    def command(self):
        now = time.time_ns()
        return {"apiVersion": CHANNEL, "phase": "seal-pair", "runtimeInput": copy.deepcopy(self.envelope),
            "publicRequest": copy.deepcopy(self.request), "issuedAtEpochNs": now,
            "sealExpiresAtEpochNs": now + 4 * SECOND, "documentExpiresAtEpochNs": now + 8 * SECOND,
            "deadlineBoottimeNs": self.deadline, "challenge": b64(b"c" * 32)}


class NativeJitBrokerChannelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux" or os.getuid() != 65534 or os.getgid() != 65534 or os.getpid() <= 1:
            raise RuntimeError("run this component as UID/GID65534 with a non-PID1 parent; no privilege change or skip")

    def test_actual_process_bootstrap_seal_and_private_float_readback(self):
        with Peer(self) as peer:
            peer.ready()
            command = peer.command()
            peer.send(command)
            result = peer.receive()
            self.assertEqual(set(result), {"apiVersion", "phase", "operation", "pair", "statementBindings"})
            self.assertEqual((result["apiVersion"], result["phase"], result["operation"]), (CHANNEL, "prepared", "jit.request"))
            scope = result["pair"]["scope"]
            self.assertTrue(scope["publicRequest"] == peer.request, "public request binding changed")
            self.assertEqual(scope["sourceContractDigest"], contract.OPERATION_MANIFEST_DIGEST)
            self.assertEqual(scope["controlPlaneConfigurationDigest"], peer.config["controlPlaneConfigurationDigest"])
            self.assertEqual(scope["ownerScopeDigest"], sha(canonical(peer.config)))
            self.assertEqual(scope["issuedAtEpochNs"], command["issuedAtEpochNs"])
            self.assertLessEqual(scope["sealExpiresAtEpochNs"], command["sealExpiresAtEpochNs"])
            self.assertLessEqual(scope["documentExpiresAtEpochNs"], command["documentExpiresAtEpochNs"])
            opened = material.open_pair(result["pair"], expected_scope=scope,
                key_id=peer.key_id, kek=AESGCM(KEY), now_epoch_ns=time.time_ns())
            self.assertTrue(opened == peer.documents, "actual pair did not preserve URL/request/display")
            self.assertEqual(opened["canonical_request"]["finite"], 1.25)
            self.assertEqual(opened["redacted_display"]["finite"], -0.5)
            expected = {"sourceContractDigest": contract.OPERATION_MANIFEST_DIGEST,
                "controlPlaneConfigurationDigest": peer.config["controlPlaneConfigurationDigest"],
                "ownerScopeDigest": sha(canonical(peer.config)), "deploymentId": peer.config["deploymentId"],
                "instanceId": peer.config["instanceId"], "requestDigest": peer.request["requestDigest"],
                "operationId": peer.request["operationId"], "publicRequestSha256": sha(canonical(peer.request)),
                "pairSha256": sha(canonical(result["pair"])), "secretKekId": peer.key_id,
                "challenge": command["challenge"], "issuedAtEpochNs": scope["issuedAtEpochNs"],
                "expiresAtEpochNs": scope["sealExpiresAtEpochNs"], "documentExpiresAtEpochNs": scope["documentExpiresAtEpochNs"],
                **peer.config["identity"]}
            self.assertTrue(result["statementBindings"] == expected, "unsigned prepared bindings changed")
            self.assertFalse({"signature", "nativeKeyEvidence", "attestation"}.intersection(result))

    def test_configuration_requires_completed_actual_service_open(self):
        for tamper in (False, True):
            with self.subTest(tampered_service=tamper), Peer(self) as peer:
                peer.provision()
                if tamper:
                    request, _key, _tokens = peer.service_request()
                    blob = bytearray(unb64(request["envelope"]["ciphertext"]))
                    blob[-1] ^= 1
                    request["envelope"]["ciphertext"] = b64(bytes(blob))
                    peer.send(request)
                else:
                    peer.send({"apiVersion": CHANNEL, "phase": "configure", "configuration": peer.config})
                peer.closed()

    def test_wrong_configuration_and_reconfiguration_close_custody(self):
        for change in ("source", "kek", "float", "repeat"):
            with self.subTest(control=change), Peer(self) as peer:
                peer.provision()
                peer.open_service()
                if change == "repeat":
                    peer.configure()
                elif change == "source":
                    peer.config["sourceContractDigest"] = sha(b"wrong source")
                elif change == "kek":
                    peer.config["secretKekId"] = "attested-memory-kek:" + "f" * 24
                else:
                    peer.config["attemptCapacity"] = 1.5
                peer.send({"apiVersion": CHANNEL, "phase": "configure", "configuration": peer.config})
                peer.closed()

    def test_no_open_review_release_or_unknown_purpose_dispatch(self):
        for phase in ("open", "review", "release", "unknown"):
            # Integer-only input reaches phase dispatch, not float rejection.
            with self.subTest(phase=phase), Peer(self, private_floats=False) as peer:
                peer.ready()
                command = peer.command()
                command["phase"] = phase
                peer.send(command)
                peer.closed()

    def test_floats_outside_private_documents_or_before_configuration_refuse(self):
        for change in ("unconfigured", "public", "timestamp", "other-purpose"):
            with self.subTest(control=change), Peer(self) as peer:
                peer.provision()
                peer.open_service()
                if change != "unconfigured":
                    peer.configure()
                command = peer.command()
                if change == "public":
                    command["publicRequest"]["arguments"]["pending_ttl_seconds"] = 300.0
                elif change == "timestamp":
                    command["issuedAtEpochNs"] = float(command["issuedAtEpochNs"])
                elif change == "other-purpose":
                    command["apiVersion"] = "catchplate.nativeOAuthRefreshChannel/v1"
                peer.send(command)
                peer.closed()

    def test_changed_private_original_or_public_request_closes_before_output(self):
        for change in ("private", "public"):
            with self.subTest(control=change), Peer(self) as peer:
                peer.ready()
                command = peer.command()
                if change == "private":
                    command["runtimeInput"]["privateDocuments"]["url"] += "&changed=1"
                else:
                    command["publicRequest"]["requestDigest"] = sha(b"changed request")
                peer.send(command)
                peer.closed()

    def test_actual_configured_frame_codec_rejects_ambiguous_or_nonfinite_json(self):
        for change in ("duplicate", "noncanonical", "nan", "overflow-float"):
            with self.subTest(control=change), Peer(self) as peer:
                peer.ready()
                raw = canonical(peer.command())
                if change == "duplicate":
                    raw = b'{"apiVersion":"duplicate",' + raw[1:]
                elif change == "noncanonical":
                    raw += b"\n"
                else:
                    self.assertTrue(b'"finite":1.25' in raw, "private numeric fixture changed")
                    raw = raw.replace(b'"finite":1.25',
                        b'"finite":NaN' if change == "nan" else b'"finite":1e9999', 1)
                peer.send_raw(raw)
                peer.closed()

    def test_same_public_request_replay_never_returns_second_pair(self):
        with Peer(self) as peer:
            peer.ready()
            command = peer.command()
            peer.send(command)
            self.assertEqual(peer.receive()["phase"], "prepared")
            # New clocks/challenge cannot rearm the already spent public input.
            replay = peer.command()
            replay["challenge"] = b64(b"r" * 32)
            peer.send(replay)
            peer.closed()

    def test_original_wall_and_boottime_deadlines_refuse_without_wait_or_retry(self):
        for change in ("wall", "boot"):
            with self.subTest(control=change), Peer(self) as peer:
                peer.ready()
                command = peer.command()
                if change == "wall":
                    command.update(issuedAtEpochNs=time.time_ns() - 3 * SECOND,
                        sealExpiresAtEpochNs=time.time_ns() - SECOND)
                else:
                    command["deadlineBoottimeNs"] = time.clock_gettime_ns(time.CLOCK_BOOTTIME) - 1
                peer.send(command)
                peer.closed()


if __name__ == "__main__":
    unittest.main(verbosity=2)
