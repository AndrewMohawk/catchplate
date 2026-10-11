"""Pure, bounded proposals for one exact-image ECR SDK publication.

Nothing here authorizes, approves, signs, persists or sends a request. Scope and
clocks are caller-supplied observations, not authenticated by this module.
VerifiedImage is a prior content observation, not immutable custody: membership
checks are CONDITIONAL on read_blob returning the unchanged verified content
from trusted ownership. Mutable stage paths do not satisfy that contract.

The caller must authenticate scope, preserve custody/current policy/generation
and original deadlines, durably CAS each pending reservation before any effect,
and correlate real responses. Reapplying identical old pure inputs produces the
same proposal; object identity checks are not a durable anti-replay mechanism or
isolation from adversarial Python. A lost/invalid write response must be passed
to fail(), never used to reopen its upload slot. No automatic retry or resume is
provided. Callback I/O/cancellation and final dispatch checks belong to callers.

This supported flow has one active upload and one pending request. Batch checks
occur between uploads; arbitrary blob order is allowed. Initiate names no blob,
so every part narrows the SAME candidate set until Complete selects one complete
verified blob. Config is included; repeated layers are uploaded only once while
their original manifest order/bytes are preserved. Conservative work limits can
refuse highly overlapping blob prefixes; they never expand to fit an input.
Counters bound successful proposals along one retained state chain, not repeated
rejected calls or replayed pure inputs. The caller must separately bound those
attempts and their CPU/I/O cost before using this reducer in an effectful owner.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import re

from serverware import ecr_image_artifact as image_artifact
from serverware import ecr_sdk_protocol as protocol

MAX_CALLS = 4096
MAX_COMPARISON_BYTES = 1024 * 1024 * 1024
MAX_COMPARISON_CALLS = 4096
READ_CHUNK_BYTES = 1024 * 1024
_MAX_INTEGER = 9_007_199_254_740_991
_MAX_UNIX = 253402300799
_MAX_MONOTONIC = (1 << 63) - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SEAL = object()


class PlanError(ValueError):
    def __init__(self):
        super().__init__("ECR publication proposal unavailable")


def _require(condition):
    if not condition:
        raise PlanError()


def _text(value, maximum):
    return type(value) is str and 1 <= len(value) <= maximum and all("!" <= char <= "~" for char in value)


def _time_fields(value):
    _require(type(value.unix_seconds) is int and 0 <= value.unix_seconds <= _MAX_UNIX
        and type(value.monotonic_ns) is int and 0 <= value.monotonic_ns <= _MAX_MONOTONIC)


@dataclass(frozen=True, slots=True)
class Clock:
    unix_seconds: int
    monotonic_ns: int

    def __post_init__(self):
        _time_fields(self)


@dataclass(frozen=True, slots=True)
class Deadline:
    unix_seconds: int
    monotonic_ns: int

    def __post_init__(self):
        _time_fields(self)


@dataclass(frozen=True, slots=True, repr=False)
class PublicationScope:
    protocol_scope: protocol.Scope
    publication_id: str
    principal_id: str
    route_id: str
    credential_id: str
    credential_generation: int
    policy_hash: str
    image_tag: str

    def __post_init__(self):
        try:
            _require(type(self.protocol_scope) is protocol.Scope)
            protocol.Scope(self.protocol_scope.registry_id, self.protocol_scope.region,
                self.protocol_scope.repository_name)
            _require(all(_text(value, 256) for value in (self.publication_id,
                self.principal_id, self.route_id, self.credential_id)))
            _require(type(self.credential_generation) is int
                and 1 <= self.credential_generation <= _MAX_INTEGER)
            _require(type(self.policy_hash) is str and _DIGEST.fullmatch(self.policy_hash)
                and _text(self.image_tag, 300))
        except Exception:
            raise PlanError() from None

    def __repr__(self):
        return "PublicationScope(<caller-supplied, not authority>)"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class Upload:
    upload_id: str
    candidate_digests: tuple[str, ...]
    acknowledged_offset: int  # Next byte; zero until the first acknowledged part.
    part_size: int
    parts: int

    def __init__(self, *args, **kwargs):
        raise PlanError()


@dataclass(frozen=True, slots=True, repr=False, init=False)
class RequestPlan:
    request: protocol.Request
    request_sha256: str
    base_revision: int
    action: str
    _next_upload: Upload | None
    _completion_digest: str | None
    _seal: object

    def __init__(self, *args, **kwargs):
        raise PlanError()

    def __repr__(self):
        return "RequestPlan(<non-authoritative proposal>)"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class Snapshot:
    scope: PublicationScope
    deadline: Deadline
    clock: Clock
    revision: int
    status: str
    ready_digests: tuple[str, ...]
    seen_upload_ids: tuple[str, ...]
    upload: Upload | None
    calls: int
    part_bytes: int
    comparison_bytes: int
    comparison_calls: int
    artifact_sha256: str
    manifest_digest: str
    _image: image_artifact.VerifiedImage
    _plan: RequestPlan | None
    _seal: object

    def __init__(self, *args, **kwargs):
        raise PlanError()

    def __repr__(self):
        return "Snapshot(<non-authoritative proposal>)"


def _new(kind, **values):
    result = object.__new__(kind)
    for key, value in values.items():
        object.__setattr__(result, key, value)
    return result


def _change(snapshot, **changes):
    return _new(Snapshot, **{**{field.name: getattr(snapshot, field.name)
        for field in fields(Snapshot)}, **changes})


def _snapshot(value):
    _require(type(value) is Snapshot and value._seal is _SEAL)


def _clock(snapshot, clock, *, live=True):
    _require(type(clock) is Clock)
    _time_fields(clock)
    if live:
        _require(clock.unix_seconds >= snapshot.clock.unix_seconds
            and clock.monotonic_ns >= snapshot.clock.monotonic_ns
            and clock.unix_seconds < snapshot.deadline.unix_seconds
            and clock.monotonic_ns < snapshot.deadline.monotonic_ns)


def create(image: image_artifact.VerifiedImage, scope: PublicationScope, *, clock: Clock,
        deadline: Deadline) -> Snapshot:
    """Bind a prior verified observation to caller-selected finite scope/time."""
    try:
        _require(type(image) is image_artifact.VerifiedImage and type(scope) is PublicationScope
            and type(clock) is Clock and type(deadline) is Deadline)
        scope.__post_init__()
        _time_fields(clock)
        _time_fields(deadline)
        _require(clock.unix_seconds < deadline.unix_seconds and clock.monotonic_ns < deadline.monotonic_ns)
        commitment = image.commitment()  # Checks the verifier's constructor seal.
        digest = "sha256:" + hashlib.sha256(json.dumps(commitment, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        _require(digest == image.commitment_sha256)
        parsed = image_artifact.parse_manifest(image.manifest_bytes)
        _require(all(getattr(parsed, key) == getattr(image, key)
            for key in ("manifest", "config", "layers", "blobs", "total_blob_bytes")))
        return _new(Snapshot, scope=scope, deadline=deadline, clock=clock, revision=0,
            status="fresh", ready_digests=(), seen_upload_ids=(), upload=None, calls=0, part_bytes=0,
            comparison_bytes=0, comparison_calls=0, artifact_sha256=digest,
            manifest_digest=image.manifest.digest, _image=image, _plan=None, _seal=_SEAL)
    except Exception:
        raise PlanError() from None


def _part(snapshot, request, read_blob):
    upload = snapshot.upload
    _require(upload is not None and callable(read_blob) and request.upload_id == upload.upload_id
        and request.part_first_byte == upload.acknowledged_offset)
    raw = request.part_bytes
    _require(type(raw) is bytes and 1 <= len(raw) <= upload.part_size
        and request.part_last_byte == request.part_first_byte + len(raw) - 1
        and snapshot.part_bytes + len(raw) <= snapshot._image.total_blob_bytes)
    sizes = {blob.digest: blob.size for blob in snapshot._image.blobs}
    end = request.part_last_byte + 1
    comparison_bytes, comparison_calls = snapshot.comparison_bytes, snapshot.comparison_calls
    candidates = []
    for digest in upload.candidate_digests:
        if end > sizes[digest] or len(raw) < upload.part_size and end != sizes[digest]:
            continue
        matches = True
        for offset in range(0, len(raw), READ_CHUNK_BYTES):
            amount = min(READ_CHUNK_BYTES, len(raw) - offset)
            _require(comparison_bytes + amount <= MAX_COMPARISON_BYTES
                and comparison_calls < MAX_COMPARISON_CALLS)
            comparison_bytes += amount
            comparison_calls += 1
            observed = read_blob(digest, request.part_first_byte + offset, amount)
            _require(type(observed) is bytes and len(observed) == amount)
            if observed != raw[offset:offset + amount]:
                matches = False
                break
        if matches:
            candidates.append(digest)
    _require(bool(candidates))
    proposed = _new(Upload, upload_id=upload.upload_id, candidate_digests=tuple(candidates),
        acknowledged_offset=end, part_size=upload.part_size, parts=upload.parts + 1)
    return proposed, comparison_bytes, comparison_calls


def begin(snapshot: Snapshot, request: protocol.Request, *, clock: Clock, read_blob=None):
    """Propose a charged pending reservation; this is NOT a dispatch permit.

    read_blob(digest, offset, length) must return unchanged verified bytes, with
    each length <= READ_CHUNK_BYTES. It is called only for UploadLayerPart.
    No clock is sampled after callbacks: the caller must recheck its original
    deadline/currentness before actual dispatch. Ordinary errors are redacted;
    BaseException cancellation propagates without changing the input snapshot.
    """
    try:
        _snapshot(snapshot)
        _clock(snapshot, clock)
        _require(snapshot.status in {"fresh", "active"} and snapshot._plan is None
            and snapshot.calls < MAX_CALLS)
        protocol.require_request(request)
        _require(request.scope == snapshot.scope.protocol_scope)
        roster = {blob.digest for blob in snapshot._image.blobs}
        ready = set(snapshot.ready_digests)
        action, proposed, complete = request.action, None, None
        comparison_bytes, comparison_calls = snapshot.comparison_bytes, snapshot.comparison_calls
        part_bytes = snapshot.part_bytes
        if action == "BatchCheckLayerAvailability":
            _require(snapshot.upload is None and set(request.layer_digests) <= roster)
        elif action == "InitiateLayerUpload":
            _require(snapshot.upload is None and bool(roster - ready))
        elif action == "UploadLayerPart":
            proposed, comparison_bytes, comparison_calls = _part(snapshot, request, read_blob)
            part_bytes += len(request.part_bytes)
        elif action == "CompleteLayerUpload":
            upload = snapshot.upload
            _require(upload is not None and request.upload_id == upload.upload_id
                and len(request.layer_digests) == 1 and upload.parts > 0)
            complete = request.layer_digests[0]
            sizes = {blob.digest: blob.size for blob in snapshot._image.blobs}
            _require(complete in upload.candidate_digests and complete not in ready
                and upload.acknowledged_offset == sizes[complete])
        elif action == "PutImage":
            _require(snapshot.upload is None and ready == roster
                and request.image_manifest == snapshot._image.manifest_bytes
                and request.image_tag == snapshot.scope.image_tag
                and request.image_digest in (None, snapshot.manifest_digest)
                and request.image_manifest_media_type in (None, snapshot._image.manifest.media_type))
        else:
            raise PlanError()
        plan = _new(RequestPlan, request=request, request_sha256=request.body_sha256,
            base_revision=snapshot.revision, action=action, _next_upload=proposed,
            _completion_digest=complete, _seal=_SEAL)
        return _change(snapshot, status="pending", revision=snapshot.revision + 1,
            clock=clock, calls=snapshot.calls + 1, part_bytes=part_bytes,
            comparison_bytes=comparison_bytes, comparison_calls=comparison_calls, _plan=plan), plan
    except Exception:
        raise PlanError() from None


def _pending(snapshot, plan):
    _snapshot(snapshot)
    _require(type(plan) is RequestPlan and plan._seal is _SEAL and snapshot.status == "pending"
        and snapshot._plan is plan and snapshot.revision == plan.base_revision + 1)
    protocol.require_request(plan.request)
    _require(plan.action == plan.request.action and plan.request_sha256 == plan.request.body_sha256
        and plan.request.scope == snapshot.scope.protocol_scope)


def apply_response(snapshot: Snapshot, plan: RequestPlan, response: protocol.Response, *, clock: Clock) -> Snapshot:
    """Propose the ACK transition only for this exact current pending request.

    This is deterministic. A caller's durable compare-and-swap, not this pure
    function, must prevent replaying an old pending snapshot. If parsing or this
    operation refuses a response after a send, terminalize with fail().
    """
    try:
        _pending(snapshot, plan)
        _clock(snapshot, clock)
        protocol.require_response(response)
        _require(response.request is plan.request and response.action == plan.action
            and response.request_sha256 == plan.request_sha256)
        ready, upload, status = set(snapshot.ready_digests), snapshot.upload, "active"
        seen_upload_ids = snapshot.seen_upload_ids
        if plan.action == "BatchCheckLayerAvailability":
            sizes = {blob.digest: blob.size for blob in snapshot._image.blobs}
            media = {item.digest: item.media_type
                for item in (snapshot._image.config, *snapshot._image.layers)}
            _require(all(sizes[digest] == size for digest, size in response.layer_sizes))
            _require(all(media[digest] == value for digest, value in response.layer_media_types))
            _require(not ready.intersection(response.unavailable_digests))
            ready.update(response.available_digests)
        elif plan.action == "InitiateLayerUpload":
            _require(response.upload_id not in seen_upload_ids
                and len(seen_upload_ids) < len(snapshot._image.blobs))
            seen_upload_ids = tuple(sorted((*seen_upload_ids, response.upload_id)))
            candidates = tuple(blob.digest for blob in snapshot._image.blobs if blob.digest not in ready)
            upload = _new(Upload, upload_id=response.upload_id, candidate_digests=candidates,
                acknowledged_offset=0, part_size=response.part_size, parts=0)
        elif plan.action == "UploadLayerPart":
            _require(response.last_byte_received == plan.request.part_last_byte)
            upload = plan._next_upload
        elif plan.action == "CompleteLayerUpload":
            _require(response.layer_digest == plan._completion_digest)
            ready.add(plan._completion_digest)
            upload = None
        elif plan.action == "PutImage":
            _require(response.image_digest == snapshot.manifest_digest
                and response.image_tag == snapshot.scope.image_tag
                and response.image_manifest_media_type in (None, snapshot._image.manifest.media_type))
            status = "published"
        else:
            raise PlanError()
        return _change(snapshot, status=status, clock=clock, revision=snapshot.revision + 1,
            ready_digests=tuple(sorted(ready)), seen_upload_ids=seen_upload_ids, upload=upload, _plan=None)
    except Exception:
        raise PlanError() from None


def fail(snapshot: Snapshot, plan: RequestPlan, *, clock: Clock) -> Snapshot:
    """Fail-stop a pending request, retaining all charged budgets and deadlines.

    Expiry does not prevent recording uncertainty. A well-formed backwards clock
    is not adopted: the last retained observation stays. This never authorizes
    another operation. A write's outcome is uncertain regardless of the caller's
    exception text; a read failure is terminal failed. No raw errors are taken.
    """
    try:
        _pending(snapshot, plan)
        _clock(snapshot, clock, live=False)
        retained = clock if (clock.unix_seconds >= snapshot.clock.unix_seconds
            and clock.monotonic_ns >= snapshot.clock.monotonic_ns) else snapshot.clock
        return _change(snapshot, status="failed" if plan.action == "BatchCheckLayerAvailability" else "uncertain",
            clock=retained, revision=snapshot.revision + 1, _plan=None)
    except Exception:
        raise PlanError() from None
