#!/usr/bin/env python3
"""One-shot ciphertext-only AWS KMS Recipient adapter for shadow local keys.

No quote verification claim is made by local COSE correlation. AWS KMS must
independently admit the measured EIF/PCRs and fixed key/context. The actual role
also checks the independently pinned full KEK and encrypted inventory.
"""
from __future__ import annotations
import argparse
import base64
import os
import socket
import stat
import time
import cbor2
from scripts.aws_kms_recipient_release import attested_recipient_public_key, reject_secret_fields, run_aws_kms_decrypt
from serverware import native_shadow_key_contract as c
p = c.p


def configuration(path):
    p.require(type(path) is str and path.startswith("/") and path.isascii() and len(path) <= 4096
              and all(part and part not in {".", ".."} for part in path[1:].split("/")))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = path[1:].split("/")
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                            | (os.O_DIRECTORY if index+1 < len(parts) else 0), dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            p.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o400
                  and 1 <= info.st_size <= 32768)
        raw = os.pread(fd, 32769, 0); closing = os.fstat(fd)
        stamp = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mode, x.st_nlink, x.st_uid, x.st_gid, x.st_mtime_ns, x.st_ctime_ns)
        p.require(stamp(info) == stamp(closing) and len(raw) == info.st_size)
        value = p.document(raw, 32768)
    finally:
        os.close(fd)
    p.fields(value, ("apiVersion", "enclaveCid", "transport", "bindingSha256", "ciphertextBlob", "region"))
    p.require(value["apiVersion"] == "serverware.nativeShadowKeyKmsParent/v1")
    p.integer(value["enclaveCid"], 4, (1 << 32)-2)
    c.transport(value["transport"]); p.digest(value["bindingSha256"])
    blob = p.decoded(value["ciphertextBlob"], maximum=6144)
    p.require(p.sha(blob) == value["transport"]["ciphertextBlobSha256"])
    if value["region"] is not None:
        p.require(type(value["region"]) is str and 1 <= len(value["region"]) <= 128
                  and all(char.isascii() and (char.isalnum() or char == "-") for char in value["region"]))
    return value, blob


def read(channel, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline-time.monotonic(); p.require(remaining > 0)
        channel.settimeout(remaining)
        part = channel.recv(count-len(result)); p.require(part); result.extend(part)
    return bytes(result)


def serve(channel, config, blob):
    # A different kernel cannot interpret the guest's BOOTTIME origin. This is
    # a separate cap on this untrusted transport, never renewed role authority.
    deadline = time.monotonic()+30
    size = int.from_bytes(read(channel, 4, deadline), "big"); p.integer(size, maximum=32768)
    envelope = p.document(read(channel, size, deadline), 32768)
    p.fields(envelope, ("request", "requestSha256", "attestationDocument"))
    request = c.request(envelope["request"])
    expected = p.sha(p.canonical(request))
    p.require(envelope["requestSha256"] == expected and request["transport"] == config["transport"]
              and p.sha(p.canonical(request["binding"])) == config["bindingSha256"])
    quote = p.decoded(envelope["attestationDocument"], maximum=16384)
    _public, digest, bits = attested_recipient_public_key(quote)
    p.require(bits == 2048 and digest == request["recipientPublicKeySha256"])
    cose = cbor2.loads(quote)
    if isinstance(cose, cbor2.CBORTag):
        p.require(cose.tag == 18); cose = cose.value
    p.require(type(cose) is list and len(cose) == 4 and type(cose[2]) is bytes)
    document = cbor2.loads(cose[2])
    p.require(type(document) is dict and document.get("nonce") == p.decoded(request["nonce"], size=32)
              and document.get("user_data") == c.QUOTE_DOMAIN+p.raw_digest(expected))
    remaining = deadline-time.monotonic(); p.require(remaining > 0)
    transport = config["transport"]
    result = run_aws_kms_decrypt(aws_binary="/usr/local/bin/aws", key_id=transport["kmsKeyId"], ciphertext=blob,
        attestation_document=quote, encryption_context=transport["encryptionContext"], region=config["region"], timeout=remaining)
    reject_secret_fields(result)
    encoded = result.get("CiphertextForRecipient")
    p.require(type(encoded) is str and 1 <= len(encoded) <= 87384)
    ciphertext = base64.b64decode(encoded, validate=True)
    p.require(1 <= len(ciphertext) <= 65536)
    raw = p.canonical({"apiVersion":c.RESPONSE, "requestSha256":expected,
                       "ciphertextForRecipient":p.encoded(ciphertext), "ciphertextSha256":p.sha(ciphertext)})
    remaining = deadline-time.monotonic(); p.require(remaining > 0)
    channel.settimeout(remaining); channel.sendall(len(raw).to_bytes(4, "big")+raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    config, blob = configuration(parser.parse_args().configuration)
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, config["transport"]["kmsParentPort"]))
        listener.listen(1)
        channel, peer = listener.accept()
        with channel:
            p.require(peer[0] == config["enclaveCid"])
            serve(channel, config, blob)


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        os._exit(1)
