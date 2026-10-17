#!/usr/bin/env python3
"""One-shot ciphertext-only parent transport for the boot role-key purpose.

Local COSE decoding below checks correlation, not authenticity. KMS verifies
the genuine Recipient attestation under independently provisioned policy; the
enclave separately checks the admitted KEK and encrypted inventory originals.
No plaintext, arbitrary KMS operation, retry, or serving-broker profile.
"""
from __future__ import annotations

import argparse
import base64
import os
import socket
import stat
import time

import cbor2

from scripts.aws_kms_recipient_release import (
    attested_recipient_public_key, reject_secret_fields, run_aws_kms_decrypt,
)
from catchplate import native_role_key_contract as contract


def configuration(path):
    contract.path(path)
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = path[1:].split("/")
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                | (os.O_DIRECTORY if index + 1 < len(parts) else 0), dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            contract.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
        contract.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 1 <= info.st_size <= 32768)
        raw = os.read(parent, 32769)
        closing = os.fstat(parent)
        fields = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        contract.require(len(raw) == info.st_size and fields(info) == fields(closing))
        value = contract.document(raw, 32768)
    finally:
        os.close(parent)
    contract.closed(value, {"apiVersion", "enclaveCid", "port", "kmsKeyId", "ciphertextBlob",
        "encryptionContext", "region", "configurationSha256", "deliveryInventorySha256",
        "provisionerConfigurationSha256", "helperImageSha256"})
    contract.require(value["apiVersion"] == "catchplate.nativeRoleKeyKmsParent/v1")
    contract.integer(value["enclaveCid"], 4, 2**32 - 2)
    contract.integer(value["port"], 1024, 2**32 - 2)
    contract.text(value["kmsKeyId"], 2048)
    for field in ("configurationSha256", "deliveryInventorySha256", "provisionerConfigurationSha256", "helperImageSha256"):
        contract.sha(value[field])
    context = value["encryptionContext"]
    contract.require(type(context) is dict and 1 <= len(context) <= 32
        and len(contract.canonical(context)) <= 8192 and context.get("catchplatePurpose") == "guest-role-keys/v1")
    for key, item in context.items():
        contract.text(key, 1024)
        contract.text(item, 1024)
    if value["region"] is not None:
        contract.text(value["region"], 128)
    blob = contract.decoded(value["ciphertextBlob"], 6144)
    contract.require(blob)
    return value, blob


def read_exact(channel, count, deadline):
    result = bytearray()
    while len(result) < count:
        remaining = deadline - time.monotonic()
        contract.require(remaining > 0)
        channel.settimeout(remaining)
        part = channel.recv(min(65536, count - len(result)))
        contract.require(part)
        result.extend(part)
    return bytes(result)


def serve_one(channel, config, blob):
    # This parent-side cap never replaces the enclave's original BOOTTIME
    # deadline. Different kernels do not share a BOOTTIME origin.
    deadline = time.monotonic() + 30
    length = int.from_bytes(read_exact(channel, 4, deadline), "big")
    contract.require(1 <= length <= 32768)
    envelope = contract.document(read_exact(channel, length, deadline), 32768)
    contract.closed(envelope, {"request", "requestSha256", "attestationDocument"})
    request = contract.request(envelope["request"])
    request_digest = contract.digest(contract.canonical(request))
    contract.require(envelope["requestSha256"] == request_digest
        and request["kmsKeyId"] == config["kmsKeyId"]
        and request["ciphertextBlobSha256"] == contract.digest(blob)
        and request["encryptionContext"] == config["encryptionContext"])
    for field in ("configurationSha256", "deliveryInventorySha256", "provisionerConfigurationSha256", "helperImageSha256"):
        contract.require(request[field] == config[field])
    quote = contract.decoded(envelope["attestationDocument"], 16384)
    _public, public_digest, bits = attested_recipient_public_key(quote)
    contract.require(bits == 2048 and public_digest == request["recipientPublicKeySha256"])
    cose = cbor2.loads(quote)
    if isinstance(cose, cbor2.CBORTag):
        contract.require(cose.tag == 18)
        cose = cose.value
    contract.require(type(cose) is list and len(cose) == 4 and type(cose[2]) is bytes)
    document = cbor2.loads(cose[2])
    contract.require(type(document) is dict
        and document.get("nonce") == contract.decoded(request["nonce"], 32, 32)
        and document.get("user_data") == contract.QUOTE_DOMAIN + bytes.fromhex(request_digest[7:]))
    remaining = deadline - time.monotonic()
    contract.require(remaining > 0)
    result = run_aws_kms_decrypt(aws_binary="/usr/local/bin/aws", key_id=config["kmsKeyId"],
        ciphertext=blob, attestation_document=quote, encryption_context=config["encryptionContext"],
        region=config["region"], timeout=remaining)
    reject_secret_fields(result)
    encoded = result.get("CiphertextForRecipient")
    contract.require(type(encoded) is str and 1 <= len(encoded) <= 87384)
    ciphertext = base64.b64decode(encoded, validate=True)
    contract.require(1 <= len(ciphertext) <= 65536)
    response = contract.canonical({"apiVersion": contract.RESPONSE, "requestSha256": request_digest,
        "ciphertextForRecipient": contract.encoded(ciphertext), "ciphertextSha256": contract.digest(ciphertext)})
    remaining = deadline - time.monotonic()
    contract.require(remaining > 0)
    channel.settimeout(remaining)
    channel.sendall(len(response).to_bytes(4, "big") + response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    config, blob = configuration(parser.parse_args().configuration)
    # One process accepts one peer/request. A caller cannot reconnect to this
    # process after an unknown outcome. Restart is explicit operator action,
    # not permission for the enclave to reuse its consumed output slots.
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, config["port"]))
        listener.listen(1)
        channel, peer = listener.accept()
        with channel:
            contract.require(peer[0] == config["enclaveCid"])
            serve_one(channel, config, blob)


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        # Fixed error status only. No provider output, key bytes, traceback or
        # success-like response escapes the ciphertext-only protocol.
        os._exit(1)
