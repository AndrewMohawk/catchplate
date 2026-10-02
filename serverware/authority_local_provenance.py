"""Sign an observed local source/report/OCI association, not build execution.

The fixed predicate authenticates retained clean-source build-report bytes,
their exact Git object/archive inputs and the measured OCI objects they name.
It does not establish who executed a build, reproducibility, SLSA, independent
custody or release approval. Dirty-tree reports and raw rootfs TAR exports are
not eligible. The detached reference uses the existing package signature
contract; nothing containing the final artifact-tree digest is put in that tree.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
import tarfile
import time

from cryptography.hazmat.primitives import serialization

from scripts.authority import native_pilot_authority_io as io
from scripts.authority.generate_artifact_bundle import _verification_key
from serverware import authority_artifact_spec as spec
from serverware import authority_local_artifact_measure as measure
from serverware.authority_contract import SOURCE_REVISION
from serverware.authority_local_snapshot import _boot

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalProvenanceApproval/v1"
PURPOSE = "observe-exact-clean-source-report-and-oci-objects"
PREDICATE = "serverware.authorityTrustedHostLocalMeasuredArtifacts/v1"
BUILDER = "serverware-trusted-host-local-observer"
MAX_OPERATION_NS = 300_000_000_000
MAX_DOCUMENT = 16 * 1024 * 1024
OBJECT_NAMES = frozenset({"report", "sourceManifest", "sourceArchive", "gitCommit",
                          "ociManifest", "ociConfig", "layers"})
SERVICES = {"serverware-control": "Dockerfile.production",
            "serverware-decision-gate": "data-plane/decision-gate-rs/Dockerfile.production"}
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYERS = frozenset({"application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"})


def _require(value):
    if not value:
        raise ValueError("local provenance association refused")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def document(raw, *, canonical=False):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT)
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError("nonintegral provenance number refused")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                       parse_float=invalid, parse_constant=invalid)
    _require(type(value) is dict)
    if canonical:
        _require(spec.canonical_json_bytes(value) == raw)
    return value


def _integer(value, minimum=0):
    _require(type(value) is int and minimum <= value < 2**63)
    return value


def _git_id(value):
    _require(type(value) is str and re.fullmatch("[0-9a-f]{40}", value) is not None)
    return value


def approval(raw):
    value = document(raw, canonical=True)
    _require(set(value) == {"schema", "purpose", "trustSha256", "signerKeyId", "sourceRoot",
        "treeDigest", "files", "objects", "imageService", "bootIdDigest",
        "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
        and value["schema"] == APPROVAL_SCHEMA and value["purpose"] == PURPOSE
        and value["imageService"] in SERVICES)
    for name in ("trustSha256", "treeDigest", "bootIdDigest"):
        spec._require_digest(value[name], name=name)
    spec._require_identifier(value["signerKeyId"], name="provenance signer")
    root = value["sourceRoot"]
    _require(type(root) is dict and set(root) == {"runtimePath", "device", "inode"})
    _require(spec._require_runtime_path(root["runtimePath"], name="source root") != "/")
    _integer(root["device"]); _integer(root["inode"], 1)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"),
                       ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        _integer(value[start], 1); _integer(value[end], 1)
        _require(0 < value[end] - value[start] <= MAX_OPERATION_NS)
    files = value["files"]
    _require(type(files) is list and 0 < len(files) <= spec.MAX_BUNDLE_FILES)
    paths = []
    for item in files:
        _require(type(item) is dict and set(item) == measure.FIELDS)
        spec._validate_file_entry(dict(item, size=0, sha256="sha256:" + "0" * 64))
        _require(type(item["uid"]) is int and item["uid"] == 0
                 and type(item["gid"]) is int and item["gid"] == 0)
        paths.append(item["path"])
    _require(paths == sorted(set(paths)))
    objects = value["objects"]
    _require(type(objects) is dict and set(objects) == OBJECT_NAMES
             and type(objects["layers"]) is list
             and 0 < len(objects["layers"]) <= spec.MAX_LAYER_DIGESTS)
    selected = [objects[name] for name in sorted(OBJECT_NAMES - {"layers"})] + objects["layers"]
    for path in selected:
        spec._require_relative_path(path, name="selected original")
        _require(path in paths)
    _require(len(set(selected)) == len(selected)
             and next(item for item in files if item["path"] == objects["report"])["kind"] == "provenance")
    return value


def _git_tree(rows):
    """Reconstruct the exact Git tree object from authenticated blob identities."""
    root = {}
    for row in rows:
        current = root
        for part in row["path"].split("/")[:-1]:
            current = current.setdefault(part, {})
            _require(type(current) is dict)
        leaf = row["path"].rsplit("/", 1)[-1]
        _require(leaf not in current)
        current[leaf] = (row["mode"], row["gitBlob"])
    def digest(tree):
        raw = bytearray()
        for name, value in sorted(tree.items(), key=lambda item: (item[0] + ("/" if type(item[1]) is dict else "")).encode("ascii")):
            mode, object_id = ("40000", digest(value)) if type(value) is dict else value
            raw.extend(mode.encode("ascii") + b" " + name.encode("ascii") + b"\0" + bytes.fromhex(object_id))
        return hashlib.sha1(b"tree " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    return digest(root)


def source_manifest(raw, commit_raw):
    value = document(raw)
    _require(raw == spec.canonical_json_bytes(value) + b"\n"
        and set(value) == {"apiVersion", "identityMode", "productionReleaseEligible", "repository",
            "commit", "commitTimestamp", "gitTree", "sourceTreeDigest", "sourceTreeManifest",
            "archive", "verification", "reconstruction"}
        and value["apiVersion"] == "serverware.sourceArchive/v1"
        and value["identityMode"] == "production-commit" and value["productionReleaseEligible"] is True
        and value["repository"] == "https://github.com/example/private-deployment")
    commit = _git_id(value["commit"]); tree = _git_id(value["gitTree"])
    _require(type(commit_raw) is bytes and 0 < len(commit_raw) <= 1024 * 1024)
    framed = b"commit " + str(len(commit_raw)).encode("ascii") + b"\0" + commit_raw
    _require(hashlib.sha1(framed).hexdigest() == commit)
    header, separator, _message = commit_raw.partition(b"\n\n")
    _require(separator and header.splitlines()[0] == b"tree " + tree.encode("ascii"))
    committers = [line for line in header.splitlines() if line.startswith(b"committer ")]
    _require(len(committers) == 1 and len(committers[0].rsplit(b" ", 2)) == 3)
    timestamp = committers[0].rsplit(b" ", 2)[1].decode("ascii")
    _require(timestamp.isdigit() and str(int(timestamp)) == timestamp
             and value["commitTimestamp"] == timestamp)
    manifest = value["sourceTreeManifest"]
    _require(type(manifest) is dict and set(manifest) == {"version", "identityMode", "productionReleaseEligible",
        "commit", "commitTimestamp", "gitTree", "files"} and manifest["version"] == "serverware.sourceTree/v3"
        and manifest["productionReleaseEligible"] is True
        and all(manifest[name] == value[name] for name in ("identityMode", "productionReleaseEligible", "commit", "commitTimestamp", "gitTree"))
        and value["sourceTreeDigest"] == sha(spec.canonical_json_bytes(manifest)))
    rows = manifest["files"]
    _require(type(rows) is list and 0 < len(rows) <= spec.MAX_BUNDLE_FILES)
    paths = []
    total = 0
    for row in rows:
        _require(type(row) is dict and set(row) == {"path", "type", "mode", "gitBlob", "bytes", "sha256"}
                 and row["type"] == "file" and row["mode"] in {"100644", "100755"})
        path = spec._require_relative_path(row["path"], name="source archive member")
        _require(re.fullmatch(r"[A-Za-z0-9._@+/-]+", path) is not None and len(path.split("/")) <= 64)
        _git_id(row["gitBlob"]); spec._require_digest(row["sha256"], name="source member hash")
        total += _integer(row["bytes"])
        _require(row["bytes"] <= spec.MAX_FILE_BYTES and total <= spec.MAX_TOTAL_BUNDLE_BYTES)
        paths.append(path)
    _require(len(paths) == len(set(paths)) and _git_tree(rows) == tree)
    archive = value["archive"]
    _require(type(archive) is dict and set(archive) == {"format", "name", "bytes", "sha256"}
        and archive["format"] == "tar-ustar-deterministic-v1"
        and archive["name"] == "source-" + value["sourceTreeDigest"][7:] + ".tar")
    _integer(archive["bytes"], 1024); spec._require_digest(archive["sha256"], name="source archive")
    _require(value["reconstruction"] == dict(requiresExactCommit=True, trackedFilesOnly=True,
        mtime=0, uid=0, gid=0, entryOrder="sourceTreeManifest.files order"))
    verification = value["verification"]
    _require(type(verification) is dict and set(verification) == {"fileList", "fileHashes", "fileModes"})
    rendered = {
        "fileList": (".files", "".join(row["path"] + "\n" for row in rows)),
        "fileHashes": (".files.sha256", "".join(row["sha256"][7:] + "  " + row["path"] + "\n" for row in rows)),
        "fileModes": (".files.mode", "".join(("755" if row["mode"] == "100755" else "644") + "  " + row["path"] + "\n" for row in rows)),
    }
    for name, (suffix, text) in rendered.items():
        encoded = text.encode("ascii")
        _require(verification[name] == dict(name="source-" + value["sourceTreeDigest"][7:] + suffix,
                                           bytes=len(encoded), sha256=sha(encoded)))
    # SHA-256 of the literal Git object frame, not of a supplied revision string.
    return value, sha(framed)


def verify_archive(fd, source, *, check):
    """Authenticate bounded USTAR members without extraction or PAX expansion."""
    offset = 0
    for row in source["sourceTreeManifest"]["files"]:
        check()
        header = tarfile.TarInfo(row["path"])
        header.mode = 0o755 if row["mode"] == "100755" else 0o644
        header.size = row["bytes"]
        expected = header.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")
        _require(len(expected) == 512 and os.pread(fd, 512, offset) == expected)
        offset += 512
        digest = hashlib.sha256()
        blob = hashlib.sha1(b"blob " + str(row["bytes"]).encode("ascii") + b"\0")
        remaining = row["bytes"]
        while remaining:
            check()
            raw = os.pread(fd, min(1024 * 1024, remaining), offset)
            _require(bool(raw)); digest.update(raw); blob.update(raw)
            offset += len(raw); remaining -= len(raw)
        _require("sha256:" + digest.hexdigest() == row["sha256"] and blob.hexdigest() == row["gitBlob"])
        padding = -row["bytes"] % 512
        _require(os.pread(fd, padding, offset) == b"\0" * padding)
        offset += padding
    # Python's existing writer emits two EOF blocks then pads to RECORDSIZE.
    tail = ((offset + 1024 + 10239) // 10240) * 10240 - offset
    _require(source["archive"]["bytes"] == offset + tail
             and os.pread(fd, tail + 1, offset) == b"\0" * tail)
    check()


def measured_originals(selected, measured, originals):
    """Join literal selected originals to the independently measured tree."""
    objects = selected["objects"]
    _require(set(originals) == OBJECT_NAMES - {"sourceArchive", "layers"})
    rows = {row["path"]: row for row in measured["files"]}
    _require(measured["treeDigest"] == selected["treeDigest"])
    for name, raw in originals.items():
        row = rows[objects[name]]
        _require(row["size"] == len(raw) and row["sha256"] == sha(raw))
    source, commit_digest = source_manifest(originals["sourceManifest"], originals["gitCommit"])
    archive_row = rows[objects["sourceArchive"]]
    _require((archive_row["size"], archive_row["sha256"]) == (source["archive"]["bytes"], source["archive"]["sha256"]))
    return rows, source, commit_digest, archive_row


def oci_objects(objects, rows, originals):
    """Verify selected OCI object hashes, not execution or source derivation."""
    manifest, config = document(originals["ociManifest"]), document(originals["ociConfig"])
    _require(type(manifest.get("schemaVersion")) is int and manifest["schemaVersion"] == 2
        and manifest.get("mediaType") == OCI_MANIFEST
        and type(manifest.get("config")) is dict and type(manifest["config"].get("size")) is int
        and manifest.get("config") == dict(mediaType=OCI_CONFIG, digest=sha(originals["ociConfig"]), size=len(originals["ociConfig"])))
    layers = manifest.get("layers")
    _require(type(layers) is list and len(layers) == len(objects["layers"]))
    for descriptor, path in zip(layers, objects["layers"]):
        row = rows[path]
        _require(type(descriptor) is dict and set(descriptor) == {"mediaType", "digest", "size"}
            and descriptor["mediaType"] in OCI_LAYERS
            and type(descriptor["size"]) is int
            and (descriptor["digest"], descriptor["size"]) == (row["sha256"], row["size"]))
    _require(config.get("os") == "linux" and config.get("architecture") == "amd64"
        and config.get("variant") is None and type(config.get("rootfs")) is dict
        and config["rootfs"].get("type") == "layers"
        and type(config["rootfs"].get("diff_ids")) is list
        and len(config["rootfs"]["diff_ids"]) == len(layers))
    for digest in config["rootfs"]["diff_ids"]:
        spec._require_digest(digest, name="OCI diff ID")
    return config


def association(selected, measured, originals):
    """Pure measured-byte joins; runtime separately verifies the archive stream."""
    objects = selected["objects"]
    rows, source, commit_digest, archive_row = measured_originals(selected, measured, originals)
    report = document(originals["report"])
    _require(set(report) == {"apiVersion", "kind", "ok", "identity_mode", "production_release_eligible",
        "generated_at_unix", "metadata", "images", "no_shell", "publish_requirement"}
        and report["apiVersion"] == "serverware.productionImagesBuild/v2" and report["kind"] == "ProductionImagesBuild"
        and report["ok"] is True and report["identity_mode"] == "production-commit"
        and report["production_release_eligible"] is True)
    _require(0 < _integer(report["generated_at_unix"], 1) <= selected["issuedAtUnixNanos"] // 1_000_000_000)
    metadata = report["metadata"]
    _require(type(metadata) is dict and metadata["revision"] == source["commit"]
        and metadata["source"] == source["repository"] and metadata["source_date_epoch"] == source["commitTimestamp"]
        and metadata["source_tree_digest"] == source["sourceTreeDigest"]
        and metadata["source_archive_digest"] == archive_row["sha256"]
        and metadata["source_manifest_digest"] == sha(originals["sourceManifest"])
        and metadata["source_identity_mode"] == "production-commit" and metadata["production_release_eligible"] is True)
    embedded = metadata["source_contract"]
    _require(type(embedded) is dict and all(embedded.get(name) == item for name, item in source.items())
        and embedded["digest"] == source["sourceTreeDigest"]
        and embedded["manifest"] == dict(name="source-" + source["sourceTreeDigest"][7:] + ".manifest.json",
            sha256=sha(originals["sourceManifest"]), bytes=len(originals["sourceManifest"])))
    images = report["images"]
    _require(type(images) is list and 0 < len(images) <= len(SERVICES)
        and all(type(row) is dict and row.get("service") in SERVICES for row in images)
        and len({row["service"] for row in images}) == len(images))
    matches = [row for row in images if row["service"] == selected["imageService"]]
    _require(len(matches) == 1 and matches[0]["dockerfile"] == SERVICES[selected["imageService"]]
        and matches[0]["image_id"] == sha(originals["ociConfig"]))
    config = oci_objects(objects, rows, originals)
    labels = config.get("config", {}).get("Labels", {})
    expected_labels = {"org.opencontainers.image.revision": source["commit"],
        "dev.serverware.source_tree_digest": source["sourceTreeDigest"],
        "dev.serverware.source_archive_digest": archive_row["sha256"],
        "dev.serverware.source_manifest_digest": sha(originals["sourceManifest"]),
        "dev.serverware.source_identity_mode": "production-commit",
        "dev.serverware.production_release_eligible": "true"}
    _require(type(labels) is dict and all(labels.get(name) == value for name, value in expected_labels.items()))
    payload = dict(path=objects["report"], sha256=sha(originals["report"]), predicateType=PREDICATE,
        mediaType="application/json", builderId=BUILDER, sourceRevision=SOURCE_REVISION,
        sourceCommitDigest=commit_digest, sourceTreeDigest=measured["treeDigest"],
        ociRootDigest=sha(originals["ociManifest"]))
    payload["statementDigest"] = spec.domain_digest(spec.PROVENANCE_PAYLOAD_DIGEST_DOMAIN, spec.canonical_json_bytes(payload))
    return payload, source


def _open_file(root_fd, path):
    current = os.dup(root_fd)
    try:
        for part in path.split("/")[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
            os.close(current); current = next_fd
        return os.open(path.rsplit("/", 1)[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
    finally:
        os.close(current)


class LocalProvenanceIssuer:
    """Borrow retained approved descriptors; no signing retry or state mutation."""

    validate_approval = staticmethod(approval)
    associate = staticmethod(association)

    def __init__(self, *, approval_fd, approval_sha256, trust_fd, trust_sha256,
                 source_root_fd, signing_key_fd):
        io._process()
        fds = (approval_fd, trust_fd, source_root_fd, signing_key_fd)
        _require(all(type(fd) is int and fd >= 3 for fd in fds) and len(set(fds)) == len(fds))
        self.approval_fd, self.trust_fd = approval_fd, trust_fd
        self.source_root_fd, self.signing_key_fd = source_root_fd, signing_key_fd
        self.identities = {fd: io._identity(os.fstat(fd)) for fd in fds}
        _require(len({identity[:2] for identity in self.identities.values()}) == len(fds))
        self.approval_raw = io.read_public(approval_fd, MAX_DOCUMENT)
        self.trust_raw = io.read_public(trust_fd, MAX_DOCUMENT)
        _require(sha(self.approval_raw) == approval_sha256 and sha(self.trust_raw) == trust_sha256)
        self.selected = self.validate_approval(self.approval_raw)
        _require(self.selected["trustSha256"] == trust_sha256)
        self.trust = spec.validate_trust_state(document(self.trust_raw, canonical=True))
        self.previous_boot_ns = self.selected["issuedAtBoottimeNs"]
        self.previous_unix_ns = self.selected["issuedAtUnixNanos"]
        self.measured_root, self.used = None, False
        self.check()

    def check(self):
        io._process()
        for fd, identity in self.identities.items():
            _require(io._identity(os.fstat(fd)) == identity)
        _require(io._input(self.approval_fd, MAX_DOCUMENT) == self.identities[self.approval_fd]
            and io._input(self.trust_fd, MAX_DOCUMENT) == self.identities[self.trust_fd]
            and _boot() == self.selected["bootIdDigest"])
        if self.measured_root is not None:
            _require(measure.root_identity(self.source_root_fd, self.selected["sourceRoot"]["runtimePath"]) == self.measured_root)
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        _require(self.previous_boot_ns <= boot < self.selected["deadlineBoottimeNs"]
            and self.previous_unix_ns <= unix < self.selected["expiresAtUnixNanos"])
        self.previous_boot_ns, self.previous_unix_ns = boot, unix

    def check_originals(self):
        self.check()
        _require(io.read_public(self.approval_fd, MAX_DOCUMENT) == self.approval_raw
                 and io.read_public(self.trust_fd, MAX_DOCUMENT) == self.trust_raw)
        self.check()

    def _read(self, row):
        fd = _open_file(self.source_root_fd, row["path"])
        try:
            before = io._identity(os.fstat(fd))
            _require(stat.S_ISREG(before[2]) and 0 < row["size"] <= MAX_DOCUMENT and before[6] == row["size"])
            raw = bytearray()
            while len(raw) < row["size"]:
                self.check()
                part = os.pread(fd, min(65536, row["size"] - len(raw)), len(raw))
                _require(bool(part)); raw.extend(part)
            _require(io._identity(os.fstat(fd)) == before and not os.pread(fd, 1, len(raw)) and sha(raw) == row["sha256"])
            return bytes(raw)
        finally:
            os.close(fd)

    def issue(self):
        _require(not self.used)
        self.used = True
        self.check()
        measured = measure.measure_tree(self.source_root_fd, self.selected["files"],
            runtime_path=self.selected["sourceRoot"]["runtimePath"], check=self.check)
        _require(measured["treeDigest"] == self.selected["treeDigest"]
            and all(measured["rootIdentity"][name] == value for name, value in self.selected["sourceRoot"].items()))
        self.measured_root = dict(measured["rootIdentity"])
        rows = {row["path"]: row for row in measured["files"]}
        originals = {name: self._read(rows[self.selected["objects"][name]])
                     for name in OBJECT_NAMES - {"sourceArchive", "layers"}}
        payload, source = self.associate(self.selected, measured, originals)
        fd = _open_file(self.source_root_fd, self.selected["objects"]["sourceArchive"])
        try:
            before = io._identity(os.fstat(fd))
            _require(stat.S_ISREG(before[2]) and before[6] == source["archive"]["bytes"])
            verify_archive(fd, source, check=self.check)
            _require(io._identity(os.fstat(fd)) == before)
        finally:
            os.close(fd)
        self.check_originals()
        instant = datetime.fromtimestamp(self.previous_unix_ns // 1_000_000_000,
                                         timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        key = _verification_key(self.trust, key_id=self.selected["signerKeyId"], purpose="provenance", validation_time=instant)
        expiry = spec._require_timestamp(key.not_after, name="provenance key expiry")
        _require(self.selected["expiresAtUnixNanos"] <= int(expiry.timestamp()) * 1_000_000_000)
        private = io.signing_key(self.signing_key_fd)
        try:
            _require(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == key.public_key)
            self.check()
            message = spec._signature_message(spec.PROVENANCE_SIGNATURE_DOMAIN, payload)
            signature = private.sign(message)
        finally:
            del private
        self.check_originals()
        reference = dict(payload, signerKeyId=key.key_id, algorithm="Ed25519",
                         signatureBase64Url=spec.strict_base64url_encode(signature))
        spec.verify_ed25519_signature(key.public_key, reference["signatureBase64Url"], message, name="local measured provenance")
        return spec.canonical_json_bytes(reference)

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self.selected["deadlineBoottimeNs"], check=self.check)
        self.check()
