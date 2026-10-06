#!/usr/bin/env python3
"""Offline outer-image cold inputs, never C9 delivery, keys or late transport.

The existing six-file claimant SquashFS is unchanged. The receiver supervisor
still requires actual inherited pipes/journal and independently signed late
originals in the service enclave; an image cannot provision those resources.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

INPUTS = Path("/activation-receiver-inputs")
OUTPUT = Path("/activation-receiver-root")
RECEIVER = "/etc/serverware/native-shadow-activation-receiver.json"
DELIVERY = "/etc/serverware/native-activation-delivery.json"
SUPERVISOR = "/opt/serverware/serverware-native-shadow-guest-supervisor"
MANIFEST = "/usr/share/serverware/native-activation-receiver.json"
FIELDS = {"apiVersion", "sourceManifestSha256", "receiverConfigurationSha256", "deliveryConfigurationSha256"}
FILES = {"inputs.json": 16384, "receiver.json": 32768, "delivery-configuration.json": 65536}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def require(condition, message="activation receiver public image input refused"):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and DIGEST.fullmatch(value) is not None and value != "sha256:" + "0" * 64)
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def document(raw, fields, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
    require(type(value) is dict and set(value) == set(fields) and canonical(value) == raw)
    return value


def validate(manifest_raw, receiver_raw, delivery_raw, *, expected_sha256, source_sha256):
    """Pure source/format joins; not independent approval or C9 admission."""
    require(sha(manifest_raw) == digest(expected_sha256))
    manifest = document(manifest_raw, FIELDS, FILES["inputs.json"])
    require(manifest["apiVersion"] == "serverware.nativeActivationReceiverImageInputs/v1"
            and manifest["sourceManifestSha256"] == digest(source_sha256))
    require(sha(receiver_raw) == digest(manifest["receiverConfigurationSha256"])
            and sha(delivery_raw) == digest(manifest["deliveryConfigurationSha256"]))
    receiver = document(receiver_raw, {"apiVersion", "deliveryConfiguration"}, FILES["receiver.json"])
    require(receiver["apiVersion"] == "serverware.nativeShadowActivationReceiverConfiguration/v1"
            and receiver["deliveryConfiguration"] == {"path": DELIVERY, "sha256": sha(delivery_raw)})
    delivery = document(delivery_raw, {"apiVersion", "authority", "serviceRole", "uid", "gid"}, FILES["delivery-configuration.json"])
    require(delivery["apiVersion"] == "serverware.policyCustodyGuestConfiguration/v1"
            and delivery["serviceRole"] == "production-bridge")
    for field in ("uid", "gid"):
        value = delivery[field]
        require(type(value) is int and 0 < value < 2**32 - 1 and value not in (64988, 64989, 64990, 65534))
    authority = delivery["authority"]
    require(type(authority) is dict and set(authority) == {"publicKeyBase64url", "keyId"})
    encoded = authority["publicKeyBase64url"]
    require(type(encoded) is str and re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is not None)
    key = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
    require(len(key) == 32 and any(key) and base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii") == encoded
            and sha(key) == digest(authority["keyId"]))
    return {
        "apiVersion": "serverware.nativeActivationReceiverImage/v1",
        "artifactOnly": True, "releaseAuthority": False, "liveReady": False, "lateInputsInstalled": False,
        "sourceManifestSha256": source_sha256, "inputManifestSha256": expected_sha256,
        "command": [SUPERVISOR, "--activation-receiver"], "environment": {},
        "exactInheritedFdSet": [0, 1, 2, 6],
        "inheritedFds": {"0": {"kind": "fifo", "access": "read-only", "purpose": "completion"},
                         "1": {"kind": "fifo", "access": "write-only", "purpose": "observation"}, "2": "stderr",
                         "6": {"kind": "existing-activation-journal-directory", "mode": "0700",
                               "uid": delivery["uid"], "gid": delivery["gid"]}},
        "files": {RECEIVER: {"sha256": sha(receiver_raw), "bytes": len(receiver_raw), "mode": "0400"},
                  DELIVERY: {"sha256": sha(delivery_raw), "bytes": len(delivery_raw), "mode": "0400"}},
        "requiredExternalResources": ["actual service-enclave kernel and NSM",
            "same-process observation and independently signed late C9/service/key/closure originals",
            "privileged installation of those originals without replacing held receiver inputs",
            "actual already-open retained journal and stdin/stdout descriptors, not Docker-created placeholders",
            "separately configured untrusted parent relay; no cross-kernel descriptor transfer"],
    }


def read_original(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        raw = os.pread(fd, maximum + 1, 0)
        after = os.fstat(fd)
        attributes = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == before.st_size and all(getattr(before, name) == getattr(after, name) for name in attributes)
                and os.pread(fd, maximum + 1, 0) == raw)
        return raw
    finally:
        os.close(fd)


def main():
    require(len(sys.argv) == 1 and os.geteuid() == 0)
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,9}", epoch) is not None and int(epoch) <= 2**32 - 1)
    require(set(path.name for path in INPUTS.iterdir()) == set(FILES))
    raw = {name: read_original(INPUTS / name, limit) for name, limit in FILES.items()}
    source = sha(read_original(Path("/source-contract/source-manifest.json"), 4 * 1024 * 1024))
    result = validate(raw["inputs.json"], raw["receiver.json"], raw["delivery-configuration.json"],
                      expected_sha256=os.environ.get("ACTIVATION_RECEIVER_INPUTS_SHA256"), source_sha256=source)
    OUTPUT.mkdir(mode=0o755)
    for name, data, mode in ((RECEIVER, raw["receiver.json"], 0o400),
                             (DELIVERY, raw["delivery-configuration.json"], 0o400),
                             (MANIFEST, canonical(result), 0o444)):
        path = OUTPUT / name[1:]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.utime(path, (int(epoch), int(epoch)))
    for directory, _, _ in os.walk(OUTPUT, topdown=False, followlinks=False):
        os.chmod(directory, 0o755)
        os.utime(directory, (int(epoch), int(epoch)))


if __name__ == "__main__":
    main()
