#!/usr/bin/env python3
"""Fixed ciphertext-only Nitro parent adapter, not enclave admission.

One recipient request causes at most one fixed KMS Decrypt invocation. The
gate authenticates the recovered KEK against its independent full commitment;
neither this process nor its transport response is a success authority.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import stat
import time

from scripts.aws_kms_recipient_release import (
    attested_recipient_public_key, reject_secret_fields, run_aws_kms_decrypt,
)


def require(value):
    if not value:
        raise ValueError("native broker parent request unavailable")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sha(value):
    return type(value) is str and len(value) == 71 and value.startswith("sha256:") \
        and all(char in "0123456789abcdef" for char in value[7:]) and value[7:] != "0" * 64


def text(value, maximum):
    return type(value) is str and 1 <= len(value.encode("utf-8")) <= maximum \
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)


def document(raw, maximum):
    require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
        parse_float=lambda _: require(False), parse_constant=lambda _: require(False))
    require(type(value) is dict and canonical(value) == raw)
    return value


def decoded(value, maximum):
    require(type(value) is str and 1 <= len(value) <= (maximum * 4 + 2) // 3)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(len(raw) <= maximum and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def configuration(path):
    require(type(path) is str and path.startswith("/") and len(path) <= 4096
        and all(part and part not in {".", ".."} for part in path[1:].split("/")))
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = path[1:].split("/")
        for index, part in enumerate(parts):
            next_fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                | (os.O_DIRECTORY if index + 1 < len(parts) else 0), dir_fd=parent)
            os.close(parent)
            parent = next_fd
            info = os.fstat(parent)
            require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 1 <= info.st_size <= 32768)
        raw = os.read(parent, 32769)
        closing = os.fstat(parent)
        require(len(raw) == info.st_size and (closing.st_dev, closing.st_ino, closing.st_size,
            closing.st_mtime_ns, closing.st_ctime_ns, closing.st_mode, closing.st_uid, closing.st_gid)
            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                info.st_mode, info.st_uid, info.st_gid))
        config = document(raw, 32768)
    finally:
        os.close(parent)
    require(set(config) == {"apiVersion", "enclaveCid", "port", "kmsKeyId", "ciphertextBlob",
        "encryptionContext", "region"} and config["apiVersion"] == "serverware.nativeBrokerKmsParent/v1")
    require(type(config["enclaveCid"]) is int and 3 < config["enclaveCid"] < 2**32 - 1
        and type(config["port"]) is int and 1023 < config["port"] < 2**32 - 1
        and text(config["kmsKeyId"], 2048)
        and type(config["encryptionContext"]) is dict and len(config["encryptionContext"]) <= 32
        and len(canonical(config["encryptionContext"])) <= 8192
        and all(text(key, 1024) and text(value, 1024)
            for key, value in config["encryptionContext"].items())
        and (config["region"] is None or type(config["region"]) is str and 1 <= len(config["region"]) <= 128))
    blob = decoded(config["ciphertextBlob"], 6144)
    return config, blob


def read_exact(channel, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        channel.settimeout(remaining)
        part = channel.recv(min(65536, count - len(result)))
        require(part)
        result.extend(part)
    return bytes(result)


def serve_one(channel, config, blob):
    # Parent and enclave boottime origins differ. This independent parent cap
    # cannot replace or renew the enclave's original retained deadline.
    deadline = time.monotonic() + 30
    length = int.from_bytes(read_exact(channel, 4, deadline), "big")
    require(1 <= length <= 32768)
    envelope = document(read_exact(channel, length, deadline), 32768)
    require(set(envelope) == {"request", "requestSha256", "attestationDocument"})
    request = envelope["request"]
    require(type(request) is dict and set(request) == {"apiVersion", "material", "configurationSha256",
        "kmsKeyId", "ciphertextBlobSha256", "encryptionContext", "recipientPublicKeySha256", "nonce", "deadlineBoottimeNs"}
        and request["apiVersion"] == "serverware.nativeBrokerKmsRecipientRequest/v1" and request["material"] == "broker-kek"
        and request["kmsKeyId"] == config["kmsKeyId"] and request["ciphertextBlobSha256"] == digest(blob)
        and request["encryptionContext"] == config["encryptionContext"]
        and sha(request["configurationSha256"]) and sha(request["recipientPublicKeySha256"])
        and type(request["deadlineBoottimeNs"]) is int and 1 <= request["deadlineBoottimeNs"] <= 2**64 - 1
        and envelope["requestSha256"] == digest(canonical(request)))
    quote = decoded(envelope["attestationDocument"], 16384)
    _public, public_digest, bits = attested_recipient_public_key(quote)
    require(bits == 2048 and public_digest == request["recipientPublicKeySha256"]
        and len(decoded(request["nonce"], 32)) == 32)
    remaining = deadline - time.monotonic()
    require(remaining > 0)
    result = run_aws_kms_decrypt(aws_binary="/usr/local/bin/aws", key_id=config["kmsKeyId"],
        ciphertext=blob, attestation_document=quote, encryption_context=config["encryptionContext"],
        region=config["region"], timeout=remaining)
    reject_secret_fields(result)
    text = result.get("CiphertextForRecipient")
    require(type(text) is str and 1 <= len(text) <= 87384)
    ciphertext = base64.b64decode(text, validate=True)
    require(1 <= len(ciphertext) <= 65536)
    response = canonical({"apiVersion": "serverware.nativeBrokerKmsRecipientCiphertext/v1",
        "requestSha256": envelope["requestSha256"], "ciphertextForRecipient":
            base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii"),
        "ciphertextSha256": digest(ciphertext)})
    remaining = deadline - time.monotonic()
    require(remaining > 0)
    channel.settimeout(remaining)
    channel.sendall(len(response).to_bytes(4, "big") + response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    config, blob = configuration(parser.parse_args().configuration)
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, config["port"]))
        listener.listen(16)
        while True:
            channel, peer = listener.accept()
            with channel:
                try:
                    require(peer[0] == config["enclaveCid"])
                    serve_one(channel, config, blob)
                except (Exception, SystemExit):
                    # No retry, error-as-authority reply, token log or plaintext.
                    pass


if __name__ == "__main__":
    main()
