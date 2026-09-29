#!/usr/bin/env python3
"""Offline, one-shot encryption of independently provisioned shadow seeds.

FD3 public inventory, FD4 exact private bundle, FD5 actual KEK: separate sealed
root:root0600 zero-link memfds. No seed file, key generation, argv/key-return
API, KMS contact or authority signature. Stdout contains ciphertext only.
"""
from __future__ import annotations
import ctypes
import fcntl
import os
import stat
import sys
if not sys.flags.isolated or len(sys.argv) != 1:
    os._exit(1)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
    os._exit(1)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from serverware import native_shadow_key_contract as c
p = c.p


def original(fd, maximum):
    info = os.fstat(fd)
    p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 0
              and stat.S_IMODE(info.st_mode) == 0o600 and 1 <= info.st_size <= maximum
              and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == 15)
    raw = os.pread(fd, maximum+1, 0)
    p.require(len(raw) == info.st_size)
    return info, raw


def run():
    inventory_info, raw = original(3, 16384)
    inventory = c.inventory(p.document(raw, 16384))
    seeds_info, seeds_raw = original(4, 16368)
    kek_info, kek = original(5, 32)
    p.require(len(kek) == 32 and len({(v.st_dev, v.st_ino) for v in (inventory_info, seeds_info, kek_info)}) == 3)
    value = p.document(seeds_raw, 16368)
    p.fields(value, ("apiVersion", "inventorySha256", "seeds"))
    p.require(value["apiVersion"] == "serverware.nativeShadowLocalKeySeeds/v1"
              and value["inventorySha256"] == p.sha(raw) and type(value["seeds"]) is list
              and len(value["seeds"]) == len(inventory["localKeys"]))
    for item, expected in zip(value["seeds"], inventory["localKeys"]):
        p.fields(item, ("role", "keyId", "seedBase64url"))
        p.require(item["role"] == expected["role"] and item["keyId"] == expected["keyId"])
        key = Ed25519PrivateKey.from_private_bytes(p.decoded(item["seedBase64url"], size=32))
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(public) == expected["publicKeyBase64url"])
    nonce = os.urandom(12)
    ciphertext = AESGCM(kek).encrypt(nonce, seeds_raw, c.AAD_DOMAIN+raw)
    output = p.canonical({"apiVersion":"serverware.nativeShadowEncryptedLocalKeys/v1", "inventorySha256":p.sha(raw),
                          "nonce":p.encoded(nonce), "ciphertext":p.encoded(ciphertext)})
    # Actual process exit, not an assertion that Python/OpenSSL copies erased.
    sys.stdout.buffer.write(output); sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        run()
    except BaseException:
        os._exit(1)
