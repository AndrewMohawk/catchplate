"""Issue a real snapshot receipt for an already frozen, content-addressed tree.

This issuer does not construct/freeze the tree or assert import closure, rootfs
pivot, provenance, hardware custody or installation. Its independently approved
inputs and purpose-specific key are delivered by a trusted local supervisor.
Only the exact measured snapshot receipt is signed. No trust ledger is advanced.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import time

from cryptography.hazmat.primitives import serialization

from scripts.authority import native_pilot_authority_io as io
from scripts.authority.generate_artifact_bundle import _verification_key
from serverware import authority_artifact_spec as spec
from serverware import authority_local_artifact_measure as measure
from serverware.authority_local_limits import LOCAL_SETUP_MAX_NS

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalSnapshotApproval/v1"
SIGNATURE_DOMAIN = "serverware.authorityStableSnapshotReceiptSignature/v1"
MAX_OPERATION_NS = LOCAL_SETUP_MAX_NS
MAX_VALIDITY_NS = 86_400_000_000_000


def _require(value):
    if not value:
        raise ValueError("local snapshot issuance refused")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _document(raw):
    def pairs(rows):
        result = {}
        for name, value in rows:
            _require(name not in result)
            result[name] = value
        return result
    _require(type(raw) is bytes and 0 < len(raw) <= io.MAX_PUBLIC)
    value = json.loads(raw, object_pairs_hook=pairs)
    _require(type(value) is dict and spec.canonical_json_bytes(value) == raw)
    return value


def _integer(value, minimum=0):
    _require(type(value) is int and minimum <= value < 2**63)
    return value


def approval(raw):
    value = _document(raw)
    _require(set(value) == {"schema", "trustSha256", "signerKeyId", "sourceRoot",
        "treeDigest", "files", "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs",
        "issuedAtUnixNanos", "expiresAtUnixNanos", "receiptValidUntil"}
        and value["schema"] == APPROVAL_SCHEMA)
    for field in ("trustSha256", "treeDigest", "bootIdDigest"):
        spec._require_digest(value[field], name=field)
    spec._require_identifier(value["signerKeyId"], name="snapshot key")
    root = value["sourceRoot"]
    _require(type(root) is dict and set(root) == {"runtimePath", "device", "inode"})
    path = spec._require_runtime_path(root["runtimePath"], name="snapshot root")
    _require(path != "/" and PurePosixPath(path).name == "sha256-" + value["treeDigest"][7:])
    _integer(root["device"]); _integer(root["inode"], 1)
    for field in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        _integer(value[field], 1)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        _require(0 < value[end] - value[start] <= MAX_OPERATION_NS)
    until = spec._require_timestamp(value["receiptValidUntil"], name="snapshot expiry")
    until_ns = int(until.timestamp()) * 1_000_000_000
    _require(value["expiresAtUnixNanos"] < until_ns
             <= value["issuedAtUnixNanos"] + MAX_VALIDITY_NS)
    files = value["files"]
    _require(type(files) is list and 0 < len(files) <= spec.MAX_BUNDLE_FILES)
    paths = []
    for item in files:
        _require(type(item) is dict and set(item) == measure.FIELDS)
        paths.append(spec._require_relative_path(item["path"], name="snapshot file"))
        _require(item["kind"] in spec.FILE_KINDS)
        _require(type(item["mode"]) is int and 0 <= item["mode"] <= 0o7777
                 and not item["mode"] & 0o7022
                 and type(item["uid"]) is int and item["uid"] == 0
                 and type(item["gid"]) is int and item["gid"] == 0)
    _require(paths == sorted(set(paths)))
    return value


def _boot():
    with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
        raw = stream.read(128).strip()
    _require(len(raw) == 36)
    return spec.domain_digest("serverware.policyAuthorityBootIdentity/v1", raw)


class LocalSnapshotIssuer:
    """Retain original input custody through measurement, signing and output."""

    def __init__(self, *, approval_fd, approval_sha256, trust_fd, trust_sha256,
                 source_root_fd, signing_key_fd):
        io._process()
        descriptors = (approval_fd, trust_fd, source_root_fd, signing_key_fd)
        _require(all(type(fd) is int and fd >= 3 for fd in descriptors)
                 and len(set(descriptors)) == len(descriptors))
        for value in (approval_sha256, trust_sha256):
            spec._require_digest(value, name="approved original")
        self.approval_fd, self.trust_fd = approval_fd, trust_fd
        self.source_root_fd, self.signing_key_fd = source_root_fd, signing_key_fd
        self.identities = {fd: io._identity(os.fstat(fd)) for fd in descriptors}
        _require(len({stamp[:2] for stamp in self.identities.values()}) == len(descriptors))
        self.approval_raw = io.read_public(approval_fd, io.MAX_PUBLIC)
        self.trust_raw = io.read_public(trust_fd, io.MAX_PUBLIC)
        _require(_sha(self.approval_raw) == approval_sha256 and _sha(self.trust_raw) == trust_sha256)
        self.selected = approval(self.approval_raw)
        _require(self.selected["trustSha256"] == trust_sha256)
        self.trust = spec.validate_trust_state(_document(self.trust_raw))
        self.previous_boot_ns = self.selected["issuedAtBoottimeNs"]
        self.previous_unix_ns = self.selected["issuedAtUnixNanos"]
        self.measured_root = None
        self.used = False
        self.check()

    def check(self):
        for fd, original in self.identities.items():
            _require(io._identity(os.fstat(fd)) == original)
        _require(io._input(self.approval_fd, io.MAX_PUBLIC) == self.identities[self.approval_fd]
                 and io._input(self.trust_fd, io.MAX_PUBLIC) == self.identities[self.trust_fd]
                 and _boot() == self.selected["bootIdDigest"])
        if self.measured_root is not None:
            _require(measure.root_identity(self.source_root_fd,
                self.selected["sourceRoot"]["runtimePath"]) == self.measured_root)
        boot_ns, unix_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        _require(self.previous_boot_ns <= boot_ns < self.selected["deadlineBoottimeNs"]
                 and self.previous_unix_ns <= unix_ns < self.selected["expiresAtUnixNanos"])
        self.previous_boot_ns, self.previous_unix_ns = boot_ns, unix_ns

    def check_originals(self):
        self.check()
        _require(io.read_public(self.approval_fd, io.MAX_PUBLIC) == self.approval_raw
                 and io.read_public(self.trust_fd, io.MAX_PUBLIC) == self.trust_raw)
        self.check()

    def issue(self):
        _require(not self.used)
        self.used = True  # A failed invocation never retries signing.
        self.check()
        observed = measure.measure_tree(self.source_root_fd, self.selected["files"],
            runtime_path=self.selected["sourceRoot"]["runtimePath"], check=self.check)
        _require(observed["treeDigest"] == self.selected["treeDigest"]
            and all(observed["rootIdentity"][name] == value
                    for name, value in self.selected["sourceRoot"].items())
            and observed["totalBytes"] > 0)
        self.measured_root = dict(observed["rootIdentity"])
        self.check()
        created_at = datetime.fromtimestamp(self.previous_unix_ns // 1_000_000_000,
                                            timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        key = _verification_key(self.trust, key_id=self.selected["signerKeyId"],
            purpose="stable-snapshot-verifier", validation_time=created_at)
        _require(self.selected["receiptValidUntil"] <= key.not_after)
        payload = dict(schema="serverware.authorityStableSnapshotReceiptPayload/v1",
            rootIdentity=observed["rootIdentity"], snapshotKind="content-addressed-cas",
            readOnly=True, treeAlgorithm="canonical-path-tree-sha256-v1",
            treeDigest=observed["treeDigest"], treeEntryCount=len(observed["files"]),
            totalBytes=observed["totalBytes"], enumeratedTreeDigest=observed["enumeratedTreeDigest"],
            createdAt=created_at, expiresAt=self.selected["receiptValidUntil"])
        payload["receiptId"] = spec.domain_digest("serverware.authorityStableSnapshotReceiptId/v1",
                                                 spec.canonical_json_bytes(payload))
        self.check_originals()
        private_key = io.signing_key(self.signing_key_fd)
        try:
            _require(private_key.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw) == key.public_key)
            self.check()
            message = spec.domain_digest(SIGNATURE_DOMAIN, spec.canonical_json_bytes(payload)).encode("ascii")
            signature = private_key.sign(message)
        finally:
            del private_key
        self.check_originals()
        receipt = dict(schema=spec.SNAPSHOT_RECEIPT_SCHEMA, payload=payload,
            signerKeyId=key.key_id, algorithm="Ed25519",
            signatureBase64Url=spec.strict_base64url_encode(signature))
        spec.validate_snapshot_receipt(receipt)
        spec.verify_ed25519_signature(key.public_key, receipt["signatureBase64Url"], message, name="local snapshot")
        _require(spec.snapshot_receipt_digest(receipt) not in self.trust["acceptedEvidenceDigests"])
        self.check()
        # This is one snapshot original, not a package, closure or installation receipt.
        return spec.canonical_json_bytes(receipt)

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self.selected["deadlineBoottimeNs"], check=self.check)
        self.check()
