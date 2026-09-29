#!/usr/bin/env python3
"""Explicit finite broker/v2 ciphertext adapter; not token-use authority.

The protected cold original pins every KMS key, blob, context and full native
configuration. A recipient request consumes its inventory slot before the
single KMS call. Restart is an operator action, never a retry or admission
signal to the enclave. No plaintext or arbitrary decrypt endpoint exists.
"""
import argparse
import base64
import hashlib
import socket
import time
import cbor2
from scripts import native_broker_kms_parent as old
from scripts.aws_kms_recipient_release import attested_recipient_public_key, reject_secret_fields, run_aws_kms_decrypt
from serverware import native_secret_broker_history as history

CONFIGURATION = "serverware.nativeHistoricalBrokerKmsParent/v1"
BINDING = b"serverware/enclave-runtime-key-binding/v1\0"
PRIMARY_REQUEST = "serverware.nativeBrokerKmsRecipientRequest/v1"
PRIMARY_RESPONSE = "serverware.nativeBrokerKmsRecipientCiphertext/v1"
RESPONSE = "serverware.nativeHistoricalBrokerKmsRecipientCiphertext/v1"
PRIMARY_FIELDS = frozenset({"apiVersion", "material", "configurationSha256", "kmsKeyId", "ciphertextBlobSha256",
    "encryptionContext", "recipientPublicKeySha256", "nonce", "deadlineBoottimeNs"})


class Inventory:
    def __init__(self, path):
        self.original = old.protected_original(path, 512 * 1024)
        value = old.document(self.original, 512 * 1024)
        old.require(set(value) == {"apiVersion", "nativeConfigurationOriginal", "enclaveCid", "region", "keys"}
            and value["apiVersion"] == CONFIGURATION and type(value["enclaveCid"]) is int
            and 3 < value["enclaveCid"] < 2**32 - 1
            and (value["region"] is None or old.text(value["region"], 128)))
        self.native_original = old.decoded(value["nativeConfigurationOriginal"], history.MAX_CONFIGURATION)
        self.native = history.configuration(self.native_original)
        self.configuration_sha256 = old.digest(self.native_original)
        self.cid, self.region, self.port = value["enclaveCid"], value["region"], self.native["kmsParentPort"]
        expected = [{name: self.native[name] for name in history.KEY_FIELDS}] + self.native["historicalKeys"]
        keys = value["keys"]
        old.require(type(keys) is list and len(keys) == len(expected) <= 17)
        self.blobs, self.assignments = {}, {item["kekSha256"]: item for item in expected}
        commitments = []
        for key in keys:
            old.require(type(key) is dict and set(key) == {"kekSha256", "ciphertextBlob"}
                and key["kekSha256"] in self.assignments and key["kekSha256"] not in self.blobs)
            blob = old.decoded(key["ciphertextBlob"], 6144)
            old.require(old.digest(blob) == self.assignments[key["kekSha256"]]["ciphertextBlobSha256"])
            self.blobs[key["kekSha256"]] = blob; commitments.append(key["kekSha256"])
        old.require(commitments == sorted(self.assignments))
        self.used, self.deadline, self.next_historical = set(), None, 0

    def select(self, request):
        old.require(type(request) is dict)
        primary = request.get("apiVersion") == PRIMARY_REQUEST
        if primary:
            old.require(set(request) == PRIMARY_FIELDS and request["material"] == "broker-kek" and not self.used)
            assignment = self.assignments[self.native["kekSha256"]]
            compared = ("kmsKeyId", "ciphertextBlobSha256", "encryptionContext")
        else:
            old.require(set(request) == history.REQUEST_FIELDS and request["apiVersion"] == history.REQUEST
                and request["material"] == "historical-broker-kek" and self.native["kekSha256"] in self.used
                and self.next_historical < len(self.native["historicalKeys"]))
            assignment = self.native["historicalKeys"][self.next_historical]
            compared = history.KEY_FIELDS
        old.require(all(request[name] == assignment[name] for name in compared)
            and request["configurationSha256"] == self.configuration_sha256
            and old.sha(request["recipientPublicKeySha256"])
            and type(request["deadlineBoottimeNs"]) is int and 0 < request["deadlineBoottimeNs"] < 2**64
            and (self.deadline is None or self.deadline == request["deadlineBoottimeNs"])
            and assignment["kekSha256"] not in self.used)
        return assignment, primary

    def consume(self, assignment, request, primary):
        # Burn before the potentially uncertain external call. A failed slot
        # cannot be replaced with another recipient or a fresh time window.
        self.used.add(assignment["kekSha256"])
        self.deadline = request["deadlineBoottimeNs"]
        if not primary:
            self.next_historical += 1


def quote_binding(raw, request, primary):
    public, public_sha, bits = attested_recipient_public_key(raw)
    old.require(bits == 2048 and public_sha == request["recipientPublicKeySha256"])
    cose = cbor2.loads(raw)
    if isinstance(cose, cbor2.CBORTag):
        old.require(cose.tag == 18); cose = cose.value
    old.require(type(cose) is list and len(cose) == 4 and type(cose[2]) is bytes)
    document = cbor2.loads(cose[2])
    old.require(type(document) is dict and document.get("public_key") == public
        and document.get("nonce") == old.decoded(request["nonce"], 32))
    nonce, binding = document["nonce"], document.get("user_data")
    old.require(len(nonce) == 32 and any(nonce) and type(binding) is bytes
        and len(binding) == len(BINDING) + 1 + 7 * 32 and binding.startswith(BINDING)
        and binding[len(BINDING)] == (6 if primary else 7)
        and binding[-64:-32] == hashlib.sha256(public).digest()
        and binding[-32:] == hashlib.sha256(old.canonical(request)).digest())
    # These are correspondence checks, not a host-produced attestation verdict.
    # KMS independently authenticates the NSM document and recipient conditions.


def serve_one(channel, inventory):
    deadline = time.monotonic() + 30  # Independent parent transport cap only.
    size = int.from_bytes(old.read_exact(channel, 4, deadline), "big")
    old.require(0 < size <= 32768)
    envelope = old.document(old.read_exact(channel, size, deadline), 32768)
    old.require(set(envelope) == {"request", "requestSha256", "attestationDocument"})
    request = envelope["request"]
    assignment, primary = inventory.select(request)
    old.require(envelope["requestSha256"] == old.digest(old.canonical(request)))
    quote = old.decoded(envelope["attestationDocument"], 16384)
    quote_binding(quote, request, primary)
    remaining = deadline - time.monotonic(); old.require(remaining > 0)
    inventory.consume(assignment, request, primary)
    result = run_aws_kms_decrypt(aws_binary="/usr/local/bin/aws", key_id=assignment["kmsKeyId"],
        ciphertext=inventory.blobs[assignment["kekSha256"]], attestation_document=quote,
        encryption_context=assignment["encryptionContext"], region=inventory.region, timeout=remaining)
    reject_secret_fields(result)
    encoded = result.get("CiphertextForRecipient")
    old.require(type(encoded) is str and 0 < len(encoded) <= 87384)
    ciphertext = base64.b64decode(encoded, validate=True)
    old.require(0 < len(ciphertext) <= 65536)
    response = old.canonical({"apiVersion": PRIMARY_RESPONSE if primary else RESPONSE,
        "requestSha256": envelope["requestSha256"], "ciphertextForRecipient":
            base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii"), "ciphertextSha256": old.digest(ciphertext)})
    remaining = deadline - time.monotonic(); old.require(remaining > 0)
    channel.settimeout(remaining); channel.sendall(len(response).to_bytes(4, "big") + response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    inventory = Inventory(parser.parse_args().configuration)
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, inventory.port)); listener.listen(16)
        while True:
            channel, peer = listener.accept()
            with channel:
                try:
                    old.require(peer[0] == inventory.cid)
                    serve_one(channel, inventory)
                except (Exception, SystemExit):
                    pass  # No retry, plaintext, or success-shaped failure response.


if __name__ == "__main__":
    main()
