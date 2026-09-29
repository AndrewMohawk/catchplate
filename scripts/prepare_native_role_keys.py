#!/usr/bin/env python3
"""Encrypt an independently assigned exact boot role-key inventory offline.

This is a material producer, not an enrollment signer or KMS provisioner. The
public inventory must already identify the genuine boot and signed delivery
originals. It emits only ciphertext, never a seed, KEK or signing capability.
"""
from __future__ import annotations

import argparse
import os
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from serverware import native_role_key_contract as contract


def protected_original(path, maximum, *, private):
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
        contract.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 1 <= info.st_size <= maximum
            and (not private or stat.S_IMODE(info.st_mode) == 0o400))
        raw = os.read(parent, maximum + 1)
        closing = os.fstat(parent)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mode,
            item.st_uid, item.st_gid, item.st_nlink, item.st_mtime_ns, item.st_ctime_ns)
        contract.require(len(raw) == info.st_size and identity(info) == identity(closing))
        return raw
    finally:
        os.close(parent)


def publish(path, raw):
    contract.path(path)
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = None
    try:
        parts = path[1:].split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            contract.require(info.st_uid == info.st_gid == 0 and info.st_mode & 0o022 == 0)
        descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400, dir_fd=parent)
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            contract.require(written > 0)
            offset += written
        os.fsync(descriptor)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
    # No failure path removes or repairs a partially published original.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--assignment", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    contract.require(os.geteuid() == os.getegid() == 0)
    inventory_raw = protected_original(args.inventory, contract.MAX_FRAME, private=False)
    inventory = contract.inventory(contract.document(inventory_raw))
    assignment = contract.document(protected_original(args.assignment, 32768, private=True), 32768)
    contract.closed(assignment, {"apiVersion", "inventorySha256", "kekPath", "seedPaths"})
    contract.require(assignment["apiVersion"] == "serverware.nativeGuestRoleKeyOfflineAssignment/v1"
        and assignment["inventorySha256"] == contract.digest(inventory_raw)
        and type(assignment["seedPaths"]) is list
        and len(assignment["seedPaths"]) == len(inventory["keys"])
        and len(set(assignment["seedPaths"])) == len(assignment["seedPaths"]))
    kek = protected_original(assignment["kekPath"], 32, private=True)
    contract.require(len(kek) == 32 and assignment["kekPath"] not in assignment["seedPaths"])
    seeds = []
    for path, key in zip(assignment["seedPaths"], inventory["keys"]):
        seed = protected_original(path, 32, private=True)
        contract.require(len(seed) == 32 and contract.digest(seed) == key["seedSha256"])
        public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        contract.require(contract.digest(public) == key["publicKeySha256"])
        seeds.append(contract.encoded(seed))
    plaintext = contract.canonical({"apiVersion": contract.PLAINTEXT,
        "inventorySha256": contract.digest(inventory_raw), "seeds": seeds})
    nonce = os.urandom(12)
    ciphertext = AESGCM(kek).encrypt(nonce, plaintext, contract.AAD_DOMAIN + inventory_raw)
    contract.require(len(ciphertext) <= contract.MAX_CIPHERTEXT)
    result = contract.canonical({"apiVersion": contract.CIPHERTEXT,
        "inventorySha256": contract.digest(inventory_raw), "nonce": contract.encoded(nonce),
        "ciphertext": contract.encoded(ciphertext)})
    contract.require(len(result) <= 32768)
    publish(args.output, result)
    # Python immutable objects are not claimed to be securely erased.


if __name__ == "__main__":
    try:
        main()
    except (Exception, SystemExit):
        os._exit(1)
