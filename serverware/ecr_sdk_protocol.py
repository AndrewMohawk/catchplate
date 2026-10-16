"""Pure, closed JSON codec for a bounded five-action ECR publication profile.

This is not an HTTP client, authorization, artifact verification, upload state,
response authentication, or dispatch authority. The caller must bind the real
HTTP method, endpoint/region, target header, framing, authenticated connection,
and outstanding attempt. A body digest does not commit to a region or attempt:
Response.request retains the exact in-process Request object for that join.
Constructor seals are internal provenance, not isolation from Python code.

This supported profile is deliberately stricter than the AWS model: explicit
account/repository, SHA-256 only, indispensable success acknowledgment fields,
no batch failures, and parts/provider partSize at most 10 MiB. Redundant response
scope, manifest and manifest-media echoes are optional but must match when
present. That is not a claim about AWS's universal maximum or acceptance of
short final parts. The API reference and service-quota page disagree about the
maximum part size. No response or exception here authorizes retries,
reconciliation, approval, or publication.

Manifest strings retain their original UTF-8 bytes and are otherwise opaque;
the separate artifact verifier owns OCI/Docker structure and blob verification.
Only its two single-image manifest media types are supported. Successful raw
API bodies are parsed, not SDK dictionaries containing ResponseMetadata.

References: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html
https://raw.githubusercontent.com/boto/botocore/1.34.46/botocore/data/ecr/2015-09-21/service-2.json
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re


MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
MAX_PART_BYTES = 10 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 8
MAX_JSON_PUNCTUATION = 4096
MAX_INTEGER = (1 << 63) - 1
ACTIONS = frozenset({"BatchCheckLayerAvailability", "InitiateLayerUpload",
    "UploadLayerPart", "CompleteLayerUpload", "PutImage"})
_MANIFEST_MEDIA = frozenset({"application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json"})
_REGISTRY = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[1-9][0-9]?\Z")
_REPOSITORY = re.compile(r"(?:[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*/)*[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UPLOAD_ID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_TAG = re.compile(r"[!-~]{1,300}\Z")
_MEDIA = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_INTEGER = re.compile(r"(?:0|[1-9][0-9]{0,18})\Z")
_SEAL = object()


class ProtocolError(ValueError):
    def __init__(self) -> None:
        super().__init__("ECR SDK protocol unavailable")


def _require(condition):
    if not condition:
        raise ProtocolError()


def _scope_fields(scope):
    _require(type(scope.registry_id) is str and _REGISTRY.fullmatch(scope.registry_id) is not None)
    _require(type(scope.region) is str and 1 <= len(scope.region) <= 63
        and _REGION.fullmatch(scope.region) is not None and not scope.region.startswith("cn-"))
    _require(type(scope.repository_name) is str and 2 <= len(scope.repository_name) <= 256
        and _REPOSITORY.fullmatch(scope.repository_name) is not None)


@dataclass(frozen=True, slots=True)
class Scope:
    registry_id: str
    region: str
    repository_name: str

    def __post_init__(self):
        try:
            _scope_fields(self)
        except Exception:
            raise ProtocolError() from None


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class Request:
    action: str
    scope: Scope
    body: bytes
    body_sha256: str
    layer_digests: tuple[str, ...]
    upload_id: str | None
    part_first_byte: int | None
    part_last_byte: int | None
    part_bytes: bytes | None
    image_manifest: bytes | None
    image_manifest_media_type: str | None
    image_tag: str | None
    image_digest: str | None
    _seal: object

    def __init__(self, *args, **kwargs):
        raise ProtocolError()

    def __repr__(self):
        return "Request(<ECR protocol observation only>)"


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class Response:
    request: Request
    request_sha256: str
    action: str
    available_digests: tuple[str, ...]
    unavailable_digests: tuple[str, ...]
    layer_sizes: tuple[tuple[str, int], ...]
    layer_media_types: tuple[tuple[str, str], ...]
    upload_id: str | None
    part_size: int | None
    last_byte_received: int | None
    layer_digest: str | None
    image_digest: str | None
    image_tag: str | None
    image_manifest_media_type: str | None
    _seal: object

    def __init__(self, *args, **kwargs):
        raise ProtocolError()

    def __repr__(self):
        return "Response(<ECR protocol observation only>)"


def require_request(value) -> None:
    """Require an internally constructed Request, not authorization or currentness."""
    try:
        _require(type(value) is Request and value._seal is _SEAL)
    except Exception:
        raise ProtocolError() from None


def require_response(value) -> None:
    """Require constructor provenance and request joins, not authentic provider IO."""
    try:
        _require(type(value) is Response and value._seal is _SEAL)
        require_request(value.request)
        _require(value.action == value.request.action
            and value.request_sha256 == value.request.body_sha256)
    except Exception:
        raise ProtocolError() from None


def _sha256(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _reject(_value):
    raise ProtocolError()


def _integer(raw):
    _require(_INTEGER.fullmatch(raw) is not None)
    value = int(raw)
    _require(value <= MAX_INTEGER)
    return value


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _document(body, limit):
    _require(type(body) is bytes and 1 <= len(body) <= limit)
    text = body.decode("utf-8", errors="strict")
    # Bound container work before json.loads allocates its object graph. The
    # decoder, not this scanner, validates escapes and JSON grammar.
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
        _require(punctuation <= MAX_JSON_PUNCTUATION)
    _require(not quoted and depth == 0)
    return json.loads(text, object_pairs_hook=_unique_pairs, parse_int=_integer,
        parse_float=_reject, parse_constant=_reject)


def _keys(value, required, optional=frozenset()):
    _require(type(value) is dict and required <= value.keys()
        and value.keys() <= required | optional)


def _scope_echo(value, scope):
    _require(value["registryId"] == scope.registry_id
        and value["repositoryName"] == scope.repository_name)


def _response_scope_echo(value, scope):
    # AWS models these echoes as optional. The retained request already binds
    # the scope; a present response echo must never contradict that binding.
    for name, expected in (("registryId", scope.registry_id),
                           ("repositoryName", scope.repository_name)):
        if name in value:
            _require(value[name] == expected)


def _digest(value):
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None)
    return value


def _digests(value, *, maximum):
    _require(type(value) is list and 1 <= len(value) <= maximum)
    result = tuple(_digest(item) for item in value)
    _require(len(set(result)) == len(result))
    return result


def _upload_id(value):
    _require(type(value) is str and _UPLOAD_ID.fullmatch(value) is not None)
    return value


def _number(value, *, minimum=0, maximum=MAX_INTEGER):
    _require(type(value) is int and minimum <= value <= maximum)
    return value


def _tag(value):
    _require(type(value) is str and _TAG.fullmatch(value) is not None)
    return value


def _manifest(value):
    _require(type(value) is str and 1 <= len(value) <= MAX_MANIFEST_BYTES)
    raw = value.encode("utf-8", errors="strict")
    _require(1 <= len(raw) <= MAX_MANIFEST_BYTES)
    return raw


def _manifest_media(value):
    _require(type(value) is str and value in _MANIFEST_MEDIA)
    return value


def _part(value):
    _require(type(value) is str and 1 <= len(value) <= 4 * ((MAX_PART_BYTES + 2) // 3))
    encoded = value.encode("ascii", errors="strict")
    raw = base64.b64decode(encoded, validate=True)
    _require(1 <= len(raw) <= MAX_PART_BYTES and base64.b64encode(raw) == encoded)
    return raw


def _request(scope, action, body, values):
    result = object.__new__(Request)
    fields = {"action": action, "scope": scope, "body": body, "body_sha256": _sha256(body),
        "layer_digests": (), "upload_id": None, "part_first_byte": None,
        "part_last_byte": None, "part_bytes": None, "image_manifest": None,
        "image_manifest_media_type": None, "image_tag": None, "image_digest": None,
        "_seal": _SEAL, **values}
    for key, value in fields.items():
        object.__setattr__(result, key, value)
    return result


def parse_request(*, scope: Scope, action: str, body: bytes) -> Request:
    """Validate one raw SDK action body without granting or dispatching it."""
    try:
        _require(type(scope) is Scope and type(action) is str and action in ACTIONS)
        _scope_fields(scope)
        value = _document(body, MAX_REQUEST_BYTES)
        common = {"registryId", "repositoryName"}
        if action == "BatchCheckLayerAvailability":
            _keys(value, common | {"layerDigests"})
            fields = {"layer_digests": _digests(value["layerDigests"], maximum=100)}
        elif action == "InitiateLayerUpload":
            _keys(value, common)
            fields = {}
        elif action == "UploadLayerPart":
            _keys(value, common | {"uploadId", "partFirstByte", "partLastByte", "layerPartBlob"})
            first, last = _number(value["partFirstByte"]), _number(value["partLastByte"])
            part = _part(value["layerPartBlob"])
            _require(last >= first and last - first + 1 == len(part))
            fields = {"upload_id": _upload_id(value["uploadId"]), "part_first_byte": first,
                "part_last_byte": last, "part_bytes": part}
        elif action == "CompleteLayerUpload":
            _keys(value, common | {"uploadId", "layerDigests"})
            fields = {"upload_id": _upload_id(value["uploadId"]),
                "layer_digests": _digests(value["layerDigests"], maximum=1)}
        else:
            _keys(value, common | {"imageManifest", "imageTag"},
                {"imageManifestMediaType", "imageDigest"})
            manifest = _manifest(value["imageManifest"])
            fields = {"image_manifest": manifest, "image_tag": _tag(value["imageTag"])}
            if "imageManifestMediaType" in value:
                fields["image_manifest_media_type"] = _manifest_media(value["imageManifestMediaType"])
            if "imageDigest" in value:
                digest = _digest(value["imageDigest"])
                _require(digest == _sha256(manifest))
                fields["image_digest"] = digest
        _scope_echo(value, scope)
        return _request(scope, action, body, fields)
    except Exception:
        raise ProtocolError() from None


def _batch_response(request, value):
    _keys(value, {"layers"}, {"failures"})
    if "failures" in value:
        _require(type(value["failures"]) is list and not value["failures"])
    layers = value["layers"]
    _require(type(layers) is list and len(layers) == len(request.layer_digests))
    states, sizes, media_types = {}, {}, {}
    for layer in layers:
        _keys(layer, {"layerDigest", "layerAvailability"}, {"layerSize", "mediaType"})
        digest = _digest(layer["layerDigest"])
        _require(digest in request.layer_digests and digest not in states)
        state = layer["layerAvailability"]
        _require(type(state) is str and state in {"AVAILABLE", "UNAVAILABLE"})
        states[digest] = state
        if "layerSize" in layer:
            sizes[digest] = _number(layer["layerSize"])
        if "mediaType" in layer:
            media = layer["mediaType"]
            _require(type(media) is str and 1 <= len(media) <= 256
                and _MEDIA.fullmatch(media) is not None)
            media_types[digest] = media
    # Stable request order, independent of provider response ordering.
    return {"available_digests": tuple(d for d in request.layer_digests if states[d] == "AVAILABLE"),
        "unavailable_digests": tuple(d for d in request.layer_digests if states[d] == "UNAVAILABLE"),
        "layer_sizes": tuple((d, sizes[d]) for d in request.layer_digests if d in sizes),
        "layer_media_types": tuple((d, media_types[d]) for d in request.layer_digests if d in media_types)}


def _put_response(request, value):
    _keys(value, {"image"})
    image = value["image"]
    _keys(image, {"imageId"},
        {"registryId", "repositoryName", "imageManifest", "imageManifestMediaType"})
    _response_scope_echo(image, request.scope)
    if "imageManifest" in image:
        _require(_manifest(image["imageManifest"]) == request.image_manifest)
    identity = image["imageId"]
    _keys(identity, {"imageDigest", "imageTag"})
    digest, tag = _digest(identity["imageDigest"]), _tag(identity["imageTag"])
    _require(digest == _sha256(request.image_manifest) and tag == request.image_tag)
    media = None
    if "imageManifestMediaType" in image:
        media = _manifest_media(image["imageManifestMediaType"])
        _require(request.image_manifest_media_type is None or media == request.image_manifest_media_type)
    return {"image_digest": digest, "image_tag": tag, "image_manifest_media_type": media}


def parse_response(request: Request, *, status: int, body: bytes) -> Response:
    """Parse a strict success ACK; all errors remain errors, never retry advice."""
    try:
        require_request(request)
        _require(type(status) is int and status == 200)
        value = _document(body, MAX_RESPONSE_BYTES)
        if request.action == "BatchCheckLayerAvailability":
            fields = _batch_response(request, value)
        elif request.action == "InitiateLayerUpload":
            # The actual API does not echo account/repository on this action.
            _keys(value, {"uploadId", "partSize"})
            fields = {"upload_id": _upload_id(value["uploadId"]),
                "part_size": _number(value["partSize"], minimum=1, maximum=MAX_PART_BYTES)}
        elif request.action == "UploadLayerPart":
            _keys(value, {"uploadId", "lastByteReceived"}, {"registryId", "repositoryName"})
            _response_scope_echo(value, request.scope)
            upload, last = _upload_id(value["uploadId"]), _number(value["lastByteReceived"])
            _require(upload == request.upload_id and last == request.part_last_byte)
            fields = {"upload_id": upload, "last_byte_received": last}
        elif request.action == "CompleteLayerUpload":
            _keys(value, {"uploadId", "layerDigest"}, {"registryId", "repositoryName"})
            _response_scope_echo(value, request.scope)
            upload, digest = _upload_id(value["uploadId"]), _digest(value["layerDigest"])
            _require(upload == request.upload_id and digest == request.layer_digests[0])
            fields = {"upload_id": upload, "layer_digest": digest}
        else:
            _require(request.action == "PutImage")
            fields = _put_response(request, value)
        result = object.__new__(Response)
        for key, item in {"request": request, "request_sha256": request.body_sha256,
                "action": request.action, "available_digests": (), "unavailable_digests": (),
                "layer_sizes": (), "layer_media_types": (), "upload_id": None, "part_size": None,
                "last_byte_received": None, "layer_digest": None, "image_digest": None,
                "image_tag": None, "image_manifest_media_type": None, "_seal": _SEAL, **fields}.items():
            object.__setattr__(result, key, item)
        return result
    except Exception:
        raise ProtocolError() from None
