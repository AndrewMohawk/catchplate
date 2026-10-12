"""Purpose-fixed child of the native gate, inside its measured enclave image.

There is no listener, command argument, environment key, plaintext response or
general decrypt operation. The only channel is the parent's inherited anonymous
socket. Any malformed/late/uncertain request destroys this process's custody.
Python/OpenSSL allocations are not claimed to provide complete memory erasure.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import math
import os
import socket
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from serverware.native_kms_cms import unwrap_broker_kek
from serverware import aws_credential_boundary, github_app_boundary, native_service_tokens
from serverware import native_oauth_refresh_owner
from serverware import native_oauth_cleanup_owner
from serverware import native_oauth_pending_retirement_owner
from serverware import native_oauth_capture_retirement_owner
from serverware import native_oauth_exchange_owner
from serverware import native_oauth_setup_owner
from serverware import native_oauth_reconnect_owner
from serverware import native_oauth_succession_owner
from serverware import native_secret_broker_history
from serverware import native_static_credential_owner
from serverware import native_static_credential_rotation_owner
from serverware import native_jit_review_owner

_SCHEMA = "serverware.nativeSecretBrokerChannel/v1"
_WORK = "serverware.nativeBrokerOpenCredential/v1"
_OUTPUT = "serverware.nativeBrokerGateCiphertext/v1"
_DOMAIN = b"serverware/native-broker-gate-ciphertext/v1\0"
_SERVICE_WORK = "serverware.nativeBrokerOpenServiceTokens/v1"
_SERVICE_OUTPUT = "serverware.nativeServiceTokensGateCiphertext/v1"
_SERVICE_DOMAIN = b"serverware/native-service-tokens-gate-ciphertext/v1\0"
_MAX = 8 * 1024 * 1024
_ROW = {"credentialId", "credentialVersion", "secretKekId", "encryptedDek",
    "secretNonce", "secretCiphertext", "secretUpdatedAt"}
_BINDING = {"requestBindingSha256", "policyHash", "dataPlaneBinaryDigest", "principalId",
    "routeId", "credentialId", "credentialVersion", "metadataSha256", "issuedAtEpochMs",
    "expiresAtEpochMs", "requestAuthoritySha256", "releaseAuthorizationSha256"}


def _require(value):
    if not value:
        raise ValueError("native broker owner unavailable")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value):
    _require(type(value) is str and len(value) == 71 and value.startswith("sha256:")
        and all(item in "0123456789abcdef" for item in value[7:]) and value[7:] != "0" * 64)
    return value


def _encoded(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decoded(value, maximum, exact=None):
    _require(type(value) is str and 1 <= len(value) <= (maximum * 4 + 2) // 3
        and all(item in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for item in value))
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    _require(len(raw) <= maximum and _encoded(raw) == value and (exact is None or len(raw) == exact))
    return raw


def _stored(value, maximum, exact=None):
    # Ordinary crypto.py envelopes are unpadded; native writers are padded.
    # Accept only those canonical forms, without rewriting the retained original
    # or changing the private channel's separate unpadded-only codec.
    _require(type(value) is str and 1 <= len(value) <= ((maximum + 2) // 3) * 4)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    canonical = base64.urlsafe_b64encode(raw).decode("ascii")
    _require(value in (canonical, canonical.rstrip("="))
        and 1 <= len(raw) <= maximum and (exact is None or len(raw) == exact))
    return raw


def _integer(value, minimum=1, maximum=2**63 - 1):
    _require(type(value) is int and minimum <= value <= maximum)
    return value


def _text(value, maximum):
    _require(type(value) is str and 1 <= len(value.encode("utf-8")) <= maximum
        and not any(ord(item) < 32 or ord(item) == 127 for item in value))
    return value


def _document(original, *, allow_jit_seal=False):
    _require(type(allow_jit_seal) is bool)
    has_float = False
    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value)
            value[key] = item
        return value
    def invalid(_value):
        raise ValueError("native broker JSON number is invalid")
    def finite(raw):
        nonlocal has_float
        number = float(raw)
        _require(math.isfinite(number))
        has_float = True
        return number
    value = json.loads(original, object_pairs_hook=pairs,
        parse_float=finite if allow_jit_seal else invalid, parse_constant=invalid)
    _require(type(value) is dict)
    jit_seal = (value.get("apiVersion") == native_jit_review_owner.CHANNEL
        and value.get("phase") == "seal-pair")
    _require(not has_float or jit_seal)
    if jit_seal:
        _require(allow_jit_seal and len(original) <= native_jit_review_owner.MAX_COMMAND_BYTES)
        native_jit_review_owner._bounded_json(value, private_floats=True)
    _require(type(value) is dict and _canonical(value) == original)
    return value


def _private_document(original, maximum):
    _require(type(original) is bytes and 1 <= len(original) <= maximum)
    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value)
            value[key] = item
        return value
    def finite(value):
        number = float(value)
        _require(math.isfinite(number))
        return number
    value = json.loads(original.decode("utf-8"), object_pairs_hook=pairs,
        parse_float=finite, parse_constant=lambda _: _require(False))
    _require(type(value) is dict)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        _require(depth <= 32 and count <= 8192)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


def _gate_ciphertext(value, plaintext, output, domain):
    recipient = x25519.X25519PublicKey.from_public_bytes(_decoded(value["gateRecipientPublicKey"], 32, 32))
    nonce = _decoded(value["gateRecipientNonce"], 32, 32)
    ephemeral = x25519.X25519PrivateKey.generate()
    request_digest = _sha(_canonical(value))
    aad = domain + bytes.fromhex(request_digest[7:])
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=aad).derive(ephemeral.exchange(recipient))
    aead_nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(aead_nonce, plaintext, aad)
    return {"apiVersion": output, "requestSha256": request_digest,
        "recipientPublicKey": value["gateRecipientPublicKey"],
        "serverEphemeralPublicKey": _encoded(ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "aeadNonce": _encoded(aead_nonce), "ciphertext": _encoded(ciphertext)}


class _Channel:
    def __init__(self):
        _require(len(sys.argv) == 1 and os.getuid() == 65534 and os.getgid() == 65534)
        # Ordinary exec resets dumpability. Close it again before any private
        # key or KEK is created, rather than relying on the pre-exec setting.
        process = ctypes.CDLL(None, use_errno=True)
        _require(process.prctl(4, 0, 0, 0, 0) == 0 and process.prctl(3, 0, 0, 0, 0) == 0)
        self.socket = socket.socket(fileno=3)
        _require(self.socket.family == socket.AF_UNIX and self.socket.type == socket.SOCK_STREAM
            and not self.socket.getsockname() and not self.socket.getpeername())
        self.parent, _uid, _gid = struct.unpack("3i",
            self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        _require(self.parent > 1 and os.getppid() == self.parent)
        self.deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 10_000_000_000
        self.pid, self.last = os.getpid(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def check(self, deadline=None):
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _require(os.getpid() == self.pid and os.getppid() == self.parent
            and self.last <= now < min(self.deadline, deadline or self.deadline))
        self.last = now
        self.socket.settimeout(min(0.25, (min(self.deadline, deadline or self.deadline) - now) / 1e9))

    def _read(self, length, deadline=None):
        chunks = bytearray()
        while len(chunks) < length:
            self.check(deadline)
            try:
                chunk = self.socket.recv(min(65536, length - len(chunks)))
            except socket.timeout:
                continue
            _require(bool(chunk))
            chunks.extend(chunk)
        self.check(deadline)
        return bytes(chunks)

    def receive(self, deadline=None, *, allow_jit_seal=False):
        length = int.from_bytes(self._read(4, deadline), "big")
        _require(1 <= length <= _MAX)
        return _document(self._read(length, deadline), allow_jit_seal=allow_jit_seal)

    def send(self, value, deadline=None):
        original = _canonical(value)
        _require(1 <= len(original) <= _MAX)
        pending = memoryview(len(original).to_bytes(4, "big") + original)
        while pending:
            self.check(deadline)
            try:
                written = self.socket.send(pending[:65536])
            except socket.timeout:
                continue
            _require(written > 0)
            pending = pending[written:]
        self.check(deadline)


class _Broker:
    def __init__(self, channel, value):
        historical = value.get("apiVersion") == "serverware.nativeSecretBrokerChannel/v2"
        _require(set(value) == {"apiVersion", "phase", "deadlineBoottimeNs", "kekSha256", "secretKekId"}
            | ({"historicalConfigurationSha256"} if historical else set())
            and (historical or value["apiVersion"] == _SCHEMA) and value["phase"] == "initialize")
        self.schema = value["apiVersion"]
        self.historical_configuration_pin = _digest(value["historicalConfigurationSha256"]) if historical else None
        deadline = _integer(value["deadlineBoottimeNs"], maximum=2**64 - 1)
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _require(now < deadline <= now + 86_400_000_000_000)
        channel.deadline = deadline
        self.channel, self.commitment = channel, _digest(value["kekSha256"])
        self.key_id = "attested-memory-kek:" + self.commitment[7:31]
        _require(value["secretKekId"] == self.key_id)
        channel.check()
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        channel.check()
        public = self.rsa.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_digest = _sha(public)
        channel.send({"apiVersion": self.schema, "phase": "recipient",
            "recipientPublicKey": _encoded(public), "recipientPublicKeySha256": self.public_digest})
        self.kek, self.operations = None, set()
        self.service_tokens_opened = False
        self.completed_service_operation_id = None
        self.refresh_owner = None
        self.cleanup_owner = None
        self.pending_retirement_owner = None
        self.capture_retirement_owner = None
        self.exchange_owner = None
        self.setup_owner = None
        self.reconnect_owner = None
        self.succession_owner = None
        self.historical_keys = None
        self.static_credential_owner = None
        self.static_credential_rotation_owner = None
        self.jit_review_owner = None

    def provision(self, value):
        _require(self.kek is None and self.rsa is not None
            and set(value) == {"apiVersion", "phase", "requestSha256", "recipientPublicKeySha256",
                "ciphertextForRecipient", "ciphertextSha256"}
            and value["apiVersion"] == self.schema and value["phase"] == "provision"
            and value["recipientPublicKeySha256"] == self.public_digest)
        request_digest = _digest(value["requestSha256"])
        original = _decoded(value["ciphertextForRecipient"], 65536)
        _require(_sha(original) == _digest(value["ciphertextSha256"]))
        self.channel.check()
        key = unwrap_broker_kek(original, self.rsa)
        self.rsa = None
        _require(hmac.compare_digest(_sha(key), self.commitment))
        self.kek = AESGCM(key)
        self.channel.check()
        self.channel.send({"apiVersion": self.schema, "phase": "provisioned", "requestSha256": request_digest})

    def open_service_tokens(self, value):
        _require(self.kek is not None and self.rsa is None and not self.service_tokens_opened
            and (self.historical_configuration_pin is None or self.historical_keys is not None and self.historical_keys.finished)
            and not self.operations and set(value) == {"apiVersion", "operationId",
                "gateRecipientPublicKey", "gateRecipientNonce", "deadlineBoottimeNs",
                "expectedBinding", "envelope"} and value["apiVersion"] == _SERVICE_WORK)
        self.service_tokens_opened = True
        operation = _text(value["operationId"], 64)
        _require(len(operation) == 64 and all(item in "0123456789abcdef" for item in operation))
        self.operations.add(operation)
        deadline = _integer(value["deadlineBoottimeNs"], maximum=2**64 - 1)
        self.channel.check(deadline)
        plaintext = native_service_tokens.open_for_broker(value["envelope"],
            value["expectedBinding"], self.key_id, self.kek)
        result = _gate_ciphertext(value, plaintext, _SERVICE_OUTPUT, _SERVICE_DOMAIN)
        self.channel.check(deadline)
        self.channel.send(result, deadline)
        self.channel.check(deadline)

        # The attempt fence above remains one-use on every failure. Record
        # completion only after the actual ciphertext send and channel check.
        self.completed_service_operation_id = operation

    def require_owner_configuration(self):
        self.channel.check()
        _require(self.kek is not None and self.rsa is None and self.service_tokens_opened
            and self.completed_service_operation_id is not None
            and self.operations == {self.completed_service_operation_id})
        # Configuration follows the one completed service-token operation;
        # any credential lease or uncertain service delivery still refuses it.

    def open_credential(self, value):
        _require(self.kek is not None and self.rsa is None and set(value) == {
            "apiVersion", "operationId", "gateRecipientPublicKey", "gateRecipientNonce",
            "deadlineBoottimeNs", "leaseBinding", "encryptedCredential", "metadata", "storageMetadata"}
            and value["apiVersion"] == _WORK)
        operation = _text(value["operationId"], 64)
        _require(operation not in self.operations and len(self.operations) < 65536)
        self.operations.add(operation)
        deadline = _integer(value["deadlineBoottimeNs"], maximum=2**64 - 1)
        self.channel.check(deadline)
        binding, row = value["leaseBinding"], value["encryptedCredential"]
        _require(type(binding) is dict and set(binding) == _BINDING and type(row) is dict and set(row) == _ROW)
        for name in {"requestBindingSha256", "policyHash", "dataPlaneBinaryDigest", "metadataSha256"}:
            _digest(binding[name])
        for name in {"requestAuthoritySha256", "releaseAuthorizationSha256"}:
            if binding[name] is not None:
                _digest(binding[name])
        _require(binding["releaseAuthorizationSha256"] is None or binding["requestAuthoritySha256"] is not None)
        _text(binding["principalId"], 1024)
        for name in {"routeId", "credentialId"}:
            _text(binding[name], 256)
        version = _integer(binding["credentialVersion"])
        issued, expires = _integer(binding["issuedAtEpochMs"]), _integer(binding["expiresAtEpochMs"])
        _require(issued < expires and issued <= time.time_ns() // 1_000_000 + 5000
            and time.time_ns() // 1_000_000 < expires and type(value["metadata"]) is dict
            and _sha(_canonical(value["metadata"])) == binding["metadataSha256"]
            and row["credentialId"] == binding["credentialId"] and type(row["credentialVersion"]) is int
            and row["credentialVersion"] == version and row["secretKekId"] == self.key_id)
        _text(row["secretUpdatedAt"], 256)
        _require(type(row["encryptedDek"]) is str and type(row["secretNonce"]) is str
            and type(row["secretCiphertext"]) is str)
        _require(type(value["storageMetadata"]) is str)
        storage = _private_document(value["storageMetadata"].encode("utf-8"), 32 * 1024)
        _require(not aws_credential_boundary.selected(None, storage)
            and not aws_credential_boundary.selected(None, value["metadata"])
            and not github_app_boundary.selected(None, storage)
            and not github_app_boundary.selected(None, value["metadata"]))
        encrypted_dek = row["encryptedDek"].split(":")
        secret_nonce, secret_ciphertext = row["secretNonce"].split(":"), row["secretCiphertext"].split(":")
        _require(len(encrypted_dek) == 3 and len(secret_nonce) == len(secret_ciphertext) == 2
            and encrypted_dek[0] == secret_nonce[0] == secret_ciphertext[0] == "v1")
        credential = row["credentialId"]
        dek = self.kek.decrypt(_stored(encrypted_dek[1], 12, 12), _stored(encrypted_dek[2], 48, 48),
            f"serverware:dek:{credential}:v{version}".encode("utf-8"))
        _require(len(dek) == 32)
        plaintext = AESGCM(dek).decrypt(_stored(secret_nonce[1], 12, 12),
            _stored(secret_ciphertext[1], 1024 * 1024 + 16),
            f"serverware:secret:{credential}:v{version}".encode("utf-8"))
        _require(1 <= len(plaintext) <= 1024 * 1024)
        _require(not github_app_boundary.secret_selected(plaintext))
        if value["metadata"].get("oauth") is True or storage.get("oauth") is True:
            # The CP validates account identity and application ownership on
            # the actual encrypted row. Rejoin its exact private metadata to
            # the actual decrypted token here, never a caller verified flag.
            _require(storage.get("oauth") is True and storage.get("refreshable") is True
                and value["metadata"].get("oauth") is True and len(plaintext) <= 190 * 1024)
            token = _private_document(plaintext, 190 * 1024)
            access = _text(token.get("access_token"), 64 * 1024)
            _text(token.get("refresh_token"), 128 * 1024)
            association = storage.get("oauth_application_owner")
            _require(type(association) is dict and association
                and token.get("oauth_application_owner") == association
                and type(token.get("token_type")) is str and token["token_type"].lower() == "bearer")
            scope = _text(token.get("scope"), 128 * 1025)
            scopes = scope.split(" ")
            _require(1 <= len(scopes) <= 128 and len(set(scopes)) == len(scopes)
                and all(item and len(item.encode("utf-8")) <= 1024
                    and not any(ord(char) < 33 or ord(char) == 127 for char in item) for item in scopes))
            _require(type(storage.get("scopes")) is list and all(type(item) is str for item in storage["scopes"])
                and len(storage["scopes"]) == len(scopes) and set(storage["scopes"]) == set(scopes)
                and value["metadata"].get("scopes") == storage["scopes"])
            access_expiry = _integer(token.get("expires_at_epoch_ms"), maximum=9_223_372_036_854_775)
            _require(type(storage.get("expires_at_epoch_ms")) is int
                and storage["expires_at_epoch_ms"] == access_expiry
                and value["metadata"].get("expires_at_epoch_ms") == access_expiry
                and time.time_ns() // 1_000_000 < access_expiry)
            refresh_expiry = token.get("refresh_token_expires_at_epoch_ms")
            _require(storage.get("refresh_token_expires_at_epoch_ms") == refresh_expiry)
            if refresh_expiry is not None:
                _integer(refresh_expiry, maximum=9_223_372_036_854_775)
                _require(time.time_ns() // 1_000_000 < refresh_expiry)
            plaintext = access.encode("utf-8")
        result = _gate_ciphertext(value, plaintext, _OUTPUT, _DOMAIN)
        self.channel.check(deadline)
        _require(time.time_ns() // 1_000_000 < expires)
        self.channel.send(result, deadline)
        self.channel.check(deadline)


def main():
    channel = _Channel()
    try:
        broker = _Broker(channel, channel.receive())
        broker.provision(channel.receive())
        while True:
            refresh_operation = None if broker.refresh_owner is None else broker.refresh_owner.operation
            exchange_operation = None if broker.exchange_owner is None else broker.exchange_owner.operation
            setup_operation = None if broker.setup_owner is None else broker.setup_owner.operation
            reconnect_operation = None if broker.reconnect_owner is None else broker.reconnect_owner.operation
            succession_operation = None if broker.succession_owner is None else broker.succession_owner.operation
            cleanup_operation = None if broker.cleanup_owner is None else broker.cleanup_owner.operation
            pending_retirement_operation = None if broker.pending_retirement_owner is None else broker.pending_retirement_owner.operation
            capture_retirement_operation = None if broker.capture_retirement_owner is None else broker.capture_retirement_owner.operation
            static_credential_operation = None if broker.static_credential_owner is None else broker.static_credential_owner.operation
            static_rotation_operation = None if broker.static_credential_rotation_owner is None else broker.static_credential_rotation_owner.operation
            jit_review_operation = None if broker.jit_review_owner is None else broker.jit_review_owner.operation
            active = [(purpose, operation) for purpose, operation in (
                (native_oauth_refresh_owner.CHANNEL, refresh_operation),
                (native_oauth_exchange_owner.CHANNEL, exchange_operation),
                (native_oauth_setup_owner.CHANNEL, setup_operation),
                (native_oauth_reconnect_owner.CHANNEL, reconnect_operation),
                (native_oauth_succession_owner.CHANNEL, succession_operation),
                (native_oauth_cleanup_owner.CHANNEL, cleanup_operation),
                (native_oauth_pending_retirement_owner.CHANNEL, pending_retirement_operation),
                (native_oauth_capture_retirement_owner.CHANNEL, capture_retirement_operation),
                (native_static_credential_owner.CHANNEL, static_credential_operation),
                (native_static_credential_rotation_owner.CHANNEL, static_rotation_operation),
                (native_jit_review_owner.CHANNEL, jit_review_operation)) if operation is not None]
            _require(len(active) <= 1)
            active_operation = active[0][1] if active else None
            value = channel.receive(None if active_operation is None else active_operation.deadline,
                allow_jit_seal=broker.jit_review_owner is not None and not active)
            if active:
                _require(value.get("apiVersion") == active[0][0])
            if value.get("apiVersion") == native_jit_review_owner.CHANNEL:
                _require(not active)
                if value.get("phase") == "configure":
                    _require(broker.jit_review_owner is None)
                    broker.jit_review_owner = native_jit_review_owner.Owner(broker, value)
                else:
                    _require(broker.jit_review_owner is not None)
                    broker.jit_review_owner.handle(value)
            elif value.get("apiVersion") == native_static_credential_owner.CHANNEL:
                _require(not active)
                if value.get("phase") == "configure":
                    _require(broker.static_credential_owner is None and broker.static_credential_rotation_owner is None)
                    broker.static_credential_owner = native_static_credential_owner.Owner(broker, value)
                else:
                    _require(broker.static_credential_owner is not None)
                    broker.static_credential_owner.handle(value)
            elif value.get("apiVersion") == native_static_credential_rotation_owner.CHANNEL:
                _require(not active)
                if value.get("phase") == "configure":
                    _require(broker.static_credential_rotation_owner is None and broker.static_credential_owner is None)
                    broker.static_credential_rotation_owner = native_static_credential_rotation_owner.Owner(broker, value)
                else:
                    _require(broker.static_credential_rotation_owner is not None)
                    broker.static_credential_rotation_owner.handle(value)
            elif value.get("apiVersion") == native_secret_broker_history.CHANNEL:
                _require(not active and broker.historical_configuration_pin is not None)
                if value.get("phase") == "initialize":
                    _require(broker.historical_keys is None)
                    broker.historical_keys = native_secret_broker_history.HistoricalKeys(broker, value)
                else:
                    _require(broker.historical_keys is not None)
                    broker.historical_keys.handle(value)
            elif value.get("apiVersion") == _SERVICE_WORK:
                broker.open_service_tokens(value)
            elif value.get("apiVersion") == native_oauth_refresh_owner.CHANNEL:
                _require(exchange_operation is None and setup_operation is None and cleanup_operation is None and pending_retirement_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.refresh_owner is None)
                    broker.refresh_owner = native_oauth_refresh_owner.Owner(broker, value)
                else:
                    _require(broker.refresh_owner is not None)
                    broker.refresh_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_cleanup_owner.CHANNEL:
                _require(refresh_operation is None and exchange_operation is None and setup_operation is None and pending_retirement_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.cleanup_owner is None)
                    broker.cleanup_owner = native_oauth_cleanup_owner.Owner(broker, value)
                else:
                    _require(broker.cleanup_owner is not None and refresh_operation is None)
                    broker.cleanup_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_pending_retirement_owner.CHANNEL:
                _require(refresh_operation is None and exchange_operation is None and setup_operation is None and cleanup_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.pending_retirement_owner is None)
                    broker.pending_retirement_owner = native_oauth_pending_retirement_owner.Owner(broker, value)
                else:
                    _require(broker.pending_retirement_owner is not None)
                    broker.pending_retirement_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_capture_retirement_owner.CHANNEL:
                _require(refresh_operation is None and exchange_operation is None and setup_operation is None
                    and cleanup_operation is None and pending_retirement_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.capture_retirement_owner is None)
                    broker.capture_retirement_owner = native_oauth_capture_retirement_owner.Owner(broker, value)
                else:
                    _require(broker.capture_retirement_owner is not None)
                    broker.capture_retirement_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_exchange_owner.CHANNEL:
                _require(refresh_operation is None and setup_operation is None and cleanup_operation is None and pending_retirement_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.exchange_owner is None and broker.setup_owner is None and broker.reconnect_owner is None and broker.succession_owner is None)
                    broker.exchange_owner = native_oauth_exchange_owner.Owner(broker, value)
                else:
                    _require(broker.exchange_owner is not None)
                    broker.exchange_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_setup_owner.CHANNEL:
                _require(refresh_operation is None and exchange_operation is None and cleanup_operation is None and pending_retirement_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.setup_owner is None and broker.exchange_owner is None and broker.reconnect_owner is None and broker.succession_owner is None)
                    broker.setup_owner = native_oauth_setup_owner.Owner(broker, value)
                else:
                    _require(broker.setup_owner is not None)
                    broker.setup_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_reconnect_owner.CHANNEL:
                _require(refresh_operation is None and exchange_operation is None and setup_operation is None
                    and cleanup_operation is None and pending_retirement_operation is None and capture_retirement_operation is None)
                if value.get("phase") == "configure":
                    _require(broker.reconnect_owner is None and broker.exchange_owner is None and broker.setup_owner is None and broker.succession_owner is None)
                    broker.reconnect_owner = native_oauth_reconnect_owner.Owner(broker, value)
                else:
                    _require(broker.reconnect_owner is not None)
                    broker.reconnect_owner.handle(value)
            elif value.get("apiVersion") == native_oauth_succession_owner.CHANNEL:
                if value.get("phase") == "configure":
                    _require(not active and broker.succession_owner is None and broker.reconnect_owner is None
                        and broker.exchange_owner is None and broker.setup_owner is None)
                    broker.succession_owner = native_oauth_succession_owner.Owner(broker, value)
                else:
                    _require(broker.succession_owner is not None)
                    broker.succession_owner.handle(value)
            else:
                _require(active_operation is None)
                broker.open_credential(value)
    finally:
        channel.socket.close()


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # No decryption detail, plaintext, traceback or recoverable status.
        os._exit(1)
