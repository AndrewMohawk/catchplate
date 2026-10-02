"""Issue a local measured-roster receipt from an actual frozen snapshot.

This does not prove exhaustive imports, dynamic native loading, rootfs isolation,
future mappings, build execution or hardware custody. The native complete-closure
contract remains separate. Supplied public approval selects every roster entry;
the issuer measures its bytes and ordinary ELF metadata without executing it.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
import stat
import struct
import time

from cryptography.hazmat.primitives import serialization
from scripts.authority import native_pilot_authority_io as io
from scripts.authority.generate_artifact_bundle import _verification_key
from serverware import authority_artifact_spec as spec
from serverware import authority_local_artifact_measure as measure
from serverware.authority_local_artifact_witness import document, sha
from serverware.authority_local_snapshot import _boot

APPROVAL_SCHEMA = "serverware.authorityTrustedHostLocalMeasuredRosterApproval/v1"
MAX_OPERATION_NS = 300_000_000_000


def _require(value):
    if not value:
        raise ValueError("local measured roster refused")


def approval(raw):
    value = document(raw)
    _require(set(value) == {"schema", "trustSha256", "snapshotSha256", "signerKeyId", "sourceRoot",
        "files", "pythonImportClosure", "nativeClosure", "stageZero", "receiptValidUntil",
        "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"}
        and value["schema"] == APPROVAL_SCHEMA)
    for name in ("trustSha256", "snapshotSha256", "bootIdDigest"):
        spec._require_digest(value[name], name=name)
    spec._require_identifier(value["signerKeyId"], name="roster signer")
    root = value["sourceRoot"]
    _require(type(root) is dict and set(root) == {"runtimePath", "device", "inode"})
    _require(spec._require_runtime_path(root["runtimePath"], name="source root") != "/")
    for name, minimum in (("device", 0), ("inode", 1)):
        _require(type(root[name]) is int and minimum <= root[name] < 2**64)
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        _require(type(value[name]) is int and 0 < value[name] < 2**63)
    for start, end in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        _require(0 < value[end] - value[start] <= MAX_OPERATION_NS)
    expiry = spec._require_timestamp(value["receiptValidUntil"], name="local roster expiry")
    _require(value["expiresAtUnixNanos"] < int(expiry.timestamp()) * 10**9)
    rows = value["files"]
    _require(type(rows) is list and 0 < len(rows) <= spec.MAX_BUNDLE_FILES)
    paths = []
    for row in rows:
        _require(type(row) is dict and set(row) == measure.FIELDS)
        spec._validate_file_entry(dict(row, size=0, sha256="sha256:" + "0" * 64))
        _require(row["uid"] == row["gid"] == 0)
        paths.append(row["path"])
    _require(paths == sorted(set(paths)))
    # Validate independent roster declarations without constructing a receipt.
    imports = spec._require_list(value["pythonImportClosure"], name="Python roster", maximum=spec.MAX_IMPORTS)
    for row in imports:
        spec._validate_python_import(row)
    spec._require_sorted_unique(imports, name="Python roster", key=lambda row: (row["module"], row["path"]))
    native = spec._require_mapping(value["nativeClosure"], name="native roster", keys={"executables", "objects"})
    for name, validate in (("executables", spec._validate_native_executable), ("objects", spec._validate_native_object)):
        rows = spec._require_list(native[name], name=name, maximum=spec.MAX_NATIVE_OBJECTS)
        for row in rows:
            validate(row)
        spec._require_sorted_unique(rows, name=name, key=lambda row: row["runtimePath"])
    _require(spec.validate_stage_zero_reference(value["stageZero"], native_executables=native["executables"],
                                              trust_mode="trusted-host-local"))
    return value


def elf_metadata(fd, *, check):
    """Bounded x86_64 ELF headers/dynamic names, not loader-resolution proof."""
    check()
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and 64 <= before.st_size <= spec.MAX_FILE_BYTES)
    def read(offset, size):
        check()
        _require(0 <= offset <= before.st_size and 0 <= size <= 1024 * 1024 and offset + size <= before.st_size)
        raw = os.pread(fd, size, offset)
        _require(len(raw) == size)
        return raw
    header = read(0, 64)
    _require(header[:7] == b"\x7fELF\x02\x01\x01")
    kind, machine, version, _entry, phoff, _shoff, _flags, ehsize, phsize, phnum, *_ = struct.unpack("<HHIQQQIHHHHHH", header[16:])
    _require(kind in {2, 3} and machine == 62 and version == 1 and ehsize == 64 and phsize == 56 and 1 <= phnum <= 4096)
    segments, dynamics, interps = [], [], []
    for index in range(phnum):
        tag, _flags, offset, virtual, _physical, size, memsize, _align = struct.unpack("<IIQQQQQQ", read(phoff+index*56, 56))
        _require(offset + size <= before.st_size)
        if tag == 1:
            _require(size <= memsize); segments.append((virtual, offset, size))
        elif tag == 2:
            dynamics.append((offset, size))
        elif tag == 3:
            _require(1 < size <= 4096)
            raw = read(offset, size)
            _require(raw.endswith(b"\0") and b"\0" not in raw[:-1])
            interps.append(spec._require_runtime_path(raw[:-1].decode("ascii"), name="observed PT_INTERP"))
    _require(len(dynamics) <= 1 and len(interps) <= 1)
    names, soname, string_addr, string_size = [], None, None, None
    if dynamics:
        offset, size = dynamics[0]
        _require(size % 16 == 0 and 0 < size <= 1024 * 1024)
        stopped = False
        for index in range(size // 16):
            tag, value = struct.unpack("<qQ", read(offset+index*16, 16))
            if tag == 0:
                stopped = True; break
            if tag == 1:
                names.append(value); _require(len(names) <= 4096)
            elif tag == 5:
                _require(string_addr is None); string_addr = value
            elif tag == 10:
                _require(string_size is None); string_size = value
            elif tag == 14:
                _require(soname is None); soname = value
        _require(stopped)
        _require(string_addr is not None and string_size is not None and 0 < string_size <= 1024 * 1024)
        matches = [(offset+string_addr-virtual) for virtual, offset, size in segments
                   if virtual <= string_addr and string_addr + string_size <= virtual + size]
        _require(len(matches) == 1)
        strings = read(matches[0], string_size)
        def name(offset):
            _require(offset < len(strings))
            end = strings.find(b"\0", offset)
            _require(offset < end <= offset + 512)
            return strings[offset:end].decode("ascii")
        names = [name(offset) for offset in names]
        soname = None if soname is None else name(soname)
    _require(io._identity(os.fstat(fd)) == io._identity(before))
    check()
    return dict(elfClass="ELF64", machine=machine, ptInterp=interps[0] if interps else None,
                needed=names, soname=soname)


def _open(root, path):
    current = os.dup(root)
    try:
        for part in path.split("/")[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
            os.close(current); current = child
        return os.open(path.rsplit("/", 1)[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
    finally:
        os.close(current)


def verify_roster(selected, measured, root_fd, *, check):
    """Join independently selected roster to actual measured file/ELF originals."""
    files = {row["path"]: row for row in measured["files"]}
    native = selected["nativeClosure"]
    all_native = native["executables"] + native["objects"]
    runtime = {row["runtimePath"]: row for row in all_native}
    _require(len(runtime) == len(all_native))
    for row in selected["pythonImportClosure"]:
        actual = files.get(row["path"])
        _require(actual is not None and actual["sha256"] == row["sha256"] and actual["kind"] in
                 {"authority-source", "authority-bytecode", "python-extension"})
    for reference in (selected["stageZero"], selected["stageZero"]["interpreter"]):
        actual = files.get(reference["path"])
        _require(actual is not None and (actual["sha256"], actual["size"]) == (reference["sha256"], reference["size"]))
    observed, sonames = {}, {}
    for row in all_native:
        actual = files.get(row["path"])
        _require(actual is not None and actual["sha256"] == row["sha256"] and actual["kind"] in
                 {"elf-executable", "elf-shared-object", "native-stage-zero", "python-extension"})
        fd = _open(root_fd, row["path"])
        try:
            measure._frozen(fd)
            value = elf_metadata(fd, check=check)
            # Re-measure the opened inode, not merely a previous pathname lookup.
            digest = hashlib.sha256()
            offset = 0
            while offset < actual["size"]:
                check()
                chunk = os.pread(fd, min(1024*1024, actual["size"]-offset), offset)
                _require(bool(chunk)); digest.update(chunk); offset += len(chunk)
            _require(not os.pread(fd, 1, offset) and "sha256:" + digest.hexdigest() == actual["sha256"])
        finally:
            os.close(fd)
        _require(value["elfClass"] == row["elfClass"] and value["machine"] == row["machine"])
        if row in native["executables"]:
            _require(value["ptInterp"] == row["ptInterp"])
        else:
            _require(value["soname"] == row["soname"])
        if value["soname"] is not None:
            _require(value["soname"] not in sonames)
            sonames[value["soname"]] = row["runtimePath"]
        observed[row["runtimePath"]] = value
    for path, value in observed.items():
        resolved = [name if name.startswith("/") else sonames.get(name) for name in value["needed"]]
        _require(all(name in runtime for name in resolved) and sorted(set(resolved)) == runtime[path]["needed"])
        if value["ptInterp"] is not None:
            _require(value["ptInterp"] in runtime)
    check()


class LocalClosureIssuer:
    """Borrow exact protected inputs through one measurement/sign/output."""
    def __init__(self, *, approval_fd, approval_sha256, trust_fd, trust_sha256,
                 snapshot_fd, snapshot_sha256, source_root_fd, signing_key_fd):
        io._process()
        fds = (approval_fd, trust_fd, snapshot_fd, source_root_fd, signing_key_fd)
        _require(all(type(fd) is int and fd >= 3 for fd in fds) and len(set(fds)) == len(fds))
        self.root_fd, self.key_fd = source_root_fd, signing_key_fd
        self.identities = {fd: io._identity(os.fstat(fd)) for fd in fds}
        _require(len({value[:2] for value in self.identities.values()}) == len(fds))
        self.originals = {fd: io.read_public(fd, io.MAX_PUBLIC) for fd in (approval_fd, trust_fd, snapshot_fd)}
        for fd, pin in ((approval_fd, approval_sha256), (trust_fd, trust_sha256), (snapshot_fd, snapshot_sha256)):
            spec._require_digest(pin, name="public original pin")
            _require(sha(self.originals[fd]) == pin)
        self.selected = approval(self.originals[approval_fd])
        _require(self.selected["trustSha256"] == trust_sha256 and self.selected["snapshotSha256"] == snapshot_sha256)
        self.trust = spec.validate_trust_state(document(self.originals[trust_fd]))
        self.snapshot = document(self.originals[snapshot_fd]); spec.validate_snapshot_receipt(self.snapshot)
        self.previous_boot, self.previous_unix = self.selected["issuedAtBoottimeNs"], self.selected["issuedAtUnixNanos"]
        self.measured_root, self.used = None, False
        self.check()

    def check(self):
        io._process()
        for fd, original in self.identities.items():
            _require(io._identity(os.fstat(fd)) == original)
        for fd, raw in self.originals.items():
            _require(io._input(fd, io.MAX_PUBLIC) == self.identities[fd])
        _require(_boot() == self.selected["bootIdDigest"])
        if self.measured_root is not None:
            _require(measure.root_identity(self.root_fd, self.selected["sourceRoot"]["runtimePath"]) == self.measured_root)
        boot, unix = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        _require(self.previous_boot <= boot < self.selected["deadlineBoottimeNs"]
            and self.previous_unix <= unix < self.selected["expiresAtUnixNanos"])
        self.previous_boot, self.previous_unix = boot, unix

    def issue(self):
        _require(not self.used); self.used = True
        self.check()
        instant = datetime.fromtimestamp(self.previous_unix // 10**9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        snapshot, selected = self.snapshot, self.selected
        source = snapshot["payload"]
        key = _verification_key(self.trust, key_id=snapshot["signerKeyId"], purpose="stable-snapshot-verifier", validation_time=instant)
        spec.verify_ed25519_signature(key.public_key, snapshot["signatureBase64Url"],
            spec._signature_message("serverware.authorityStableSnapshotReceiptSignature/v1", source), name="snapshot")
        snapshot_digest = spec.snapshot_receipt_digest(snapshot)
        _require(snapshot_digest not in self.trust["acceptedEvidenceDigests"]
            and source["createdAt"] <= instant < source["expiresAt"]
            and selected["receiptValidUntil"] <= min(source["expiresAt"], key.not_after))
        measured = measure.measure_tree(self.root_fd, selected["files"],
            runtime_path=selected["sourceRoot"]["runtimePath"], check=self.check)
        _require(measured["rootIdentity"] == source["rootIdentity"]
            and all(measured["rootIdentity"][name] == value for name, value in selected["sourceRoot"].items())
            and measured["treeDigest"] == source["treeDigest"] and measured["enumeratedTreeDigest"] == source["enumeratedTreeDigest"]
            and len(measured["files"]) == source["treeEntryCount"] and measured["totalBytes"] == source["totalBytes"])
        self.measured_root = dict(measured["rootIdentity"])
        verify_roster(selected, measured, self.root_fd, check=self.check)
        self.check()
        instant = datetime.fromtimestamp(self.previous_unix // 10**9, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        key = _verification_key(self.trust, key_id=selected["signerKeyId"], purpose="closure-verifier", validation_time=instant)
        _require(instant < selected["receiptValidUntil"] <= key.not_after)
        payload = dict(schema="serverware.authorityTrustedHostLocalMeasuredRosterPayload/v1",
            snapshotReceiptDigest=snapshot_digest, treeDigest=measured["treeDigest"], treeEntryCount=len(measured["files"]),
            totalBytes=measured["totalBytes"], pythonImportClosure=selected["pythonImportClosure"],
            nativeClosure=selected["nativeClosure"], stageZero=selected["stageZero"], assurance=dict(spec.LOCAL_CLOSURE_CLAIMS),
            createdAt=instant, expiresAt=selected["receiptValidUntil"])
        payload["receiptId"] = spec.domain_digest("serverware.authorityTrustedHostLocalMeasuredRosterId/v1", spec.canonical_json_bytes(payload))
        for fd, raw in self.originals.items():
            _require(io.read_public(fd, io.MAX_PUBLIC) == raw)
        self.check()
        private = io.signing_key(self.key_fd)
        try:
            _require(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == key.public_key)
            message = spec._signature_message(spec.LOCAL_CLOSURE_SIGNATURE_DOMAIN, payload)
            signature = private.sign(message)
        finally:
            del private
        receipt = dict(schema=spec.LOCAL_CLOSURE_RECEIPT_SCHEMA, payload=payload, signerKeyId=key.key_id,
            algorithm="Ed25519", signatureBase64Url=spec.strict_base64url_encode(signature))
        spec.validate_local_closure_receipt(receipt)
        spec.verify_ed25519_signature(key.public_key, receipt["signatureBase64Url"], message, name="local measured roster")
        self.check()
        return spec.canonical_json_bytes(receipt)

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self.selected["deadlineBoottimeNs"], check=self.check)
        self.check()
