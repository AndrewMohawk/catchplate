"""Bounded image-manifest and streamed content verification, without authority.

This is a deliberately closed OCI image v1 / Docker schema-2 subset, not a
general registry or runnable-image validator. Configuration blobs are opaque:
their exact size/hash is checked, not rootfs semantics. Layers are never
decompressed or extracted. Original UTF-8 manifest bytes are retained unchanged.

Readers are supplied by the caller and consumed from their current positions;
this module never opens, seeks, closes or retains them. Callers own blocking,
cancellation, deadlines and custody. Verification observes bytes once, not their
future immutability, durable staging, approval, credentials or publication.
No parser result or serialized commitment is proof that a stream was verified.

Format references: https://github.com/opencontainers/image-spec/tree/v1.1.1
https://distribution.github.io/distribution/spec/manifest-v2-2/
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import BinaryIO


MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_BLOB_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_LAYERS = 128
READ_CHUNK_BYTES = 1024 * 1024
MAX_READ_CALLS_PER_BLOB = 8192  # Includes the final one-byte EOF check.
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 20000
SCHEMA = "catchplate.ecrVerifiedImage/v1"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYERS = frozenset(("application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.oci.image.layer.v1.tar+zstd"))
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYERS = frozenset(("application/vnd.docker.image.rootfs.diff.tar.gzip",))
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"(?:0|[1-9][0-9]{0,9})\Z")
_SEAL = object()


class ImageArtifactError(ValueError):
    def __init__(self) -> None:
        super().__init__("ECR image artifact unavailable")


def _require(condition):
    if not condition:
        raise ImageArtifactError()


@dataclass(frozen=True, slots=True)
class Descriptor:
    media_type: str
    digest: str
    size: int


@dataclass(frozen=True, slots=True)
class Blob:
    digest: str
    size: int


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ManifestDescription:
    """Validated declarations only: none of the referenced bytes were read."""
    manifest_bytes: bytes
    manifest: Descriptor
    config: Descriptor
    layers: tuple[Descriptor, ...]
    blobs: tuple[Blob, ...]
    total_blob_bytes: int

    def __init__(self, *args, **kwargs):
        raise ImageArtifactError()

    def __repr__(self):
        return "ManifestDescription(<unverified content declarations>)"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class VerifiedImage:
    """Immutable point-in-time content observation; not an authority token."""
    manifest_bytes: bytes
    manifest: Descriptor
    config: Descriptor
    layers: tuple[Descriptor, ...]
    blobs: tuple[Blob, ...]
    total_blob_bytes: int
    commitment_sha256: str
    _seal: object

    def __init__(self, *args, **kwargs):
        raise ImageArtifactError()

    def __repr__(self):
        return "VerifiedImage(<content observation only>)"

    def commitment(self):
        """A fresh public value; mutating it cannot mutate this observation."""
        try:
            _require(type(self) is VerifiedImage and self._seal is _SEAL)
            return _commitment(self)
        except Exception:
            raise ImageArtifactError() from None


def _descriptor_value(item):
    return {"media_type": item.media_type, "digest": item.digest, "size": item.size}


def _commitment(image):
    return {"schema": SCHEMA, "manifest": _descriptor_value(image.manifest),
        "config": _descriptor_value(image.config),
        "layers": [_descriptor_value(layer) for layer in image.layers],
        "blobs": [{"digest": blob.digest, "size": blob.size} for blob in image.blobs],
        "total_blob_bytes": image.total_blob_bytes}


def _sha256(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _reject(_value):
    raise ImageArtifactError()


def _integer(value):
    _require(_INTEGER.fullmatch(value) is not None)
    return int(value)


def _unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        _require(name not in result)
        result[name] = value
    return result


def _document(raw):
    _require(type(raw) is bytes and 1 <= len(raw) <= MAX_MANIFEST_BYTES)
    text = raw.decode("utf-8", errors="strict")
    # Bound nesting and container work BEFORE the JSON decoder allocates its
    # graph. String escapes are only skipped here; the strict decoder owns them.
    depth = punctuation = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            punctuation += 1
            _require(depth <= MAX_JSON_DEPTH)
        elif character in "]}":
            depth -= 1
            _require(depth >= 0)
        elif character in ",:":
            punctuation += 1
        _require(punctuation <= MAX_JSON_NODES)
    _require(not quoted and depth == 0)
    return json.loads(text, object_pairs_hook=_unique_pairs, parse_int=_integer,
        parse_float=_reject, parse_constant=_reject)


def _annotations(value):
    _require(type(value) is dict and len(value) <= 32)
    for key, item in value.items():
        _require(type(key) is str and 1 <= len(key) <= 256
            and all("!" <= character <= "~" for character in key))
        _require(type(item) is str and "\0" not in item and len(item.encode("utf-8")) <= 4096)


def _descriptor(value, media_types, maximum, *, oci):
    required = {"mediaType", "digest", "size"}
    _require(type(value) is dict and required <= set(value)
        and set(value) <= required | ({"annotations"} if oci else set()))
    _require(type(value["mediaType"]) is str and value["mediaType"] in media_types
        and type(value["digest"]) is str and _DIGEST.fullmatch(value["digest"]) is not None
        and type(value["size"]) is int and 1 <= value["size"] <= maximum)
    if "annotations" in value:
        _annotations(value["annotations"])
    return Descriptor(value["mediaType"], value["digest"], value["size"])


def parse_manifest(manifest_bytes: bytes) -> ManifestDescription:
    """Parse a bounded roster for opening streams; this does not verify blobs."""
    try:
        value = _document(manifest_bytes)
        required = {"schemaVersion", "mediaType", "config", "layers"}
        _require(type(value) is dict and required <= set(value))
        media = value["mediaType"]
        _require(type(media) is str and media in (OCI_MANIFEST, DOCKER_MANIFEST))
        oci = media == OCI_MANIFEST
        _require(set(value) <= required | ({"annotations"} if oci else set())
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 2
            and type(value["layers"]) is list and len(value["layers"]) <= MAX_LAYERS)
        if "annotations" in value:
            _annotations(value["annotations"])
        config = _descriptor(value["config"], {OCI_CONFIG if oci else DOCKER_CONFIG}, MAX_CONFIG_BYTES, oci=oci)
        layers = tuple(_descriptor(layer, OCI_LAYERS if oci else DOCKER_LAYERS, MAX_BLOB_BYTES, oci=oci)
            for layer in value["layers"])
        unique = {}
        for item, declaration in zip((config, *layers), (value["config"], *value["layers"])):
            if item.digest in unique:
                # Same bytes may occur repeatedly in layer order, but all
                # semantic descriptor fields, including annotations, must agree.
                _require(unique[item.digest][1] == declaration)
            else:
                unique[item.digest] = (item, declaration)
        blobs = tuple(Blob(digest, unique[digest][0].size) for digest in sorted(unique))
        total = sum(blob.size for blob in blobs)
        _require(1 <= total <= MAX_TOTAL_BYTES)
        result = object.__new__(ManifestDescription)
        for key, item in {"manifest_bytes": manifest_bytes,
                "manifest": Descriptor(media, _sha256(manifest_bytes), len(manifest_bytes)),
                "config": config, "layers": layers, "blobs": blobs, "total_blob_bytes": total}.items():
            object.__setattr__(result, key, item)
        return result
    except Exception:
        raise ImageArtifactError() from None


def _verify_blob(blob, read):
    hasher = hashlib.sha256()
    remaining, calls = blob.size, 0
    while remaining:
        _require(calls < MAX_READ_CALLS_PER_BLOB)
        amount = min(READ_CHUNK_BYTES, remaining)
        chunk = read(amount)
        calls += 1
        _require(type(chunk) is bytes and 0 < len(chunk) <= amount)
        hasher.update(chunk)
        remaining -= len(chunk)
    _require(calls < MAX_READ_CALLS_PER_BLOB)
    trailing = read(1)
    _require(type(trailing) is bytes and trailing == b"")
    _require("sha256:" + hasher.hexdigest() == blob.digest)


def verify_image(manifest_bytes: bytes, blobs: dict[str, BinaryIO]) -> VerifiedImage:
    """Consume all unique streams, accepting bounded short reads and exact EOF.

    All declarations and the entire supplied roster are checked before any
    stream is read. Extremely fragmented readers exceeding the fixed call
    budget refuse; blocking time remains the trusted caller's responsibility.
    Ordinary failures have a fixed safe message. BaseException cancellation
    propagates, and no partial VerifiedImage is ever returned.
    """
    try:
        description = parse_manifest(manifest_bytes)
        _require(type(blobs) is dict and len(blobs) == len(description.blobs))
        supplied = tuple(blobs.items())
        _require(all(type(key) is str and _DIGEST.fullmatch(key) is not None for key, _ in supplied))
        readers = {key: getattr(reader, "read") for key, reader in supplied}
        _require(set(readers) == {blob.digest for blob in description.blobs}
            and all(callable(read) for read in readers.values()))
        for blob in description.blobs:
            _verify_blob(blob, readers[blob.digest])
        public = _commitment(description)
        canonical = json.dumps(public, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        result = object.__new__(VerifiedImage)
        for key in ("manifest_bytes", "manifest", "config", "layers", "blobs", "total_blob_bytes"):
            object.__setattr__(result, key, getattr(description, key))
        object.__setattr__(result, "commitment_sha256", _sha256(canonical))
        object.__setattr__(result, "_seal", _SEAL)
        return result
    except Exception:
        raise ImageArtifactError() from None
