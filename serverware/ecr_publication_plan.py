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
Checkpoints are bounded data from a trusted durable owner, not authenticated
history or dispatch authority. Restoring one never consumes it or proves that
its claimed ACKs occurred. The owner must bind the latest committed checkpoint,
original scope/deadline and same monotonic-clock domain, and retain custody.

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
CHECKPOINT_SCHEMA = "serverware.ecrPublicationCheckpoint/v1"
MAX_CHECKPOINT_BYTES = 64 * 1024
_MAX_INTEGER = 9_007_199_254_740_991
_MAX_UNIX = 253402300799
_MAX_MONOTONIC = (1 << 63) - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UPLOAD_ID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_CHECKPOINT_FIELDS = frozenset({"schema", "scope", "deadline", "clock", "revision", "status",
    "ready_digests", "seen_upload_ids", "upload", "calls", "part_bytes", "comparison_bytes",
    "comparison_calls", "artifact_sha256", "manifest_digest"})
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


def _checkpoint_integer(value, maximum, *, minimum=0):
    _require(type(value) is int and minimum <= value <= maximum)
    return value


def _checkpoint_keys(value, expected):
    _require(type(value) is dict and set(value) == expected)
    return value


def _checkpoint_strings(value, pattern, maximum):
    _require(type(value) is list and len(value) <= maximum
        and all(type(item) is str and pattern.fullmatch(item) for item in value)
        and value == sorted(set(value)))
    return tuple(value)


def _checkpoint_document(raw):
    _require(type(raw) is bytes and 1 <= len(raw) <= MAX_CHECKPOINT_BYTES)
    text = raw.decode("utf-8", errors="strict")
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
            _require(depth <= 4)
        elif character in "]}":
            depth -= 1
            _require(depth >= 0)
        elif character in ",:":
            punctuation += 1
        _require(punctuation <= 2048)
    _require(not quoted and depth == 0)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result)
            result[key] = value
        return result

    def integer(value):
        _require(len(value) <= 19)
        return int(value)

    def refuse(_value):
        raise PlanError()

    return json.loads(text, object_pairs_hook=unique, parse_int=integer,
        parse_float=refuse, parse_constant=refuse)


def _restore_checkpoint(image, scope, value, *, clock, deadline):
    _checkpoint_keys(value, _CHECKPOINT_FIELDS)
    _require(value["schema"] == CHECKPOINT_SCHEMA and type(value["status"]) is str
        and value["status"] in {"fresh", "active", "published"})
    times = {"unix_seconds", "monotonic_ns"}
    retained_clock = Clock(**_checkpoint_keys(value["clock"], times))
    retained_deadline = Deadline(**_checkpoint_keys(value["deadline"], times))
    _require(type(deadline) is Deadline and deadline == retained_deadline)
    scope_value = _checkpoint_keys(value["scope"], {field.name for field in fields(PublicationScope)})
    protocol_value = _checkpoint_keys(scope_value["protocol_scope"],
        {"registry_id", "region", "repository_name"})
    retained_scope = PublicationScope(**{**scope_value, "protocol_scope": protocol.Scope(**protocol_value)})
    _require(type(scope) is PublicationScope and scope == retained_scope)
    # Rejoin a real, freshly supplied verifier result, not serialized descriptors.
    base = create(image, scope, clock=retained_clock, deadline=deadline)
    _clock(base, clock)
    _require(value["artifact_sha256"] == base.artifact_sha256
        and value["manifest_digest"] == base.manifest_digest)
    sizes = {blob.digest: blob.size for blob in image.blobs}
    ready = _checkpoint_strings(value["ready_digests"], _DIGEST, len(sizes))
    seen = _checkpoint_strings(value["seen_upload_ids"], _UPLOAD_ID, len(sizes))
    _require(set(ready) <= sizes.keys())
    calls = _checkpoint_integer(value["calls"], MAX_CALLS)
    revision = _checkpoint_integer(value["revision"], 2 * MAX_CALLS)
    part_bytes = _checkpoint_integer(value["part_bytes"], image.total_blob_bytes)
    comparison_bytes = _checkpoint_integer(value["comparison_bytes"], MAX_COMPARISON_BYTES)
    comparison_calls = _checkpoint_integer(value["comparison_calls"], MAX_COMPARISON_CALLS)
    _require(revision == 2 * calls
        and part_bytes <= comparison_bytes <= part_bytes * len(sizes)
        and comparison_calls <= comparison_bytes <= comparison_calls * READ_CHUNK_BYTES)
    upload, offset, parts = None, 0, 0
    if value["upload"] is not None:
        raw = _checkpoint_keys(value["upload"], {field.name for field in fields(Upload)})
        _require(type(raw["upload_id"]) is str and raw["upload_id"] in seen)
        candidates = _checkpoint_strings(raw["candidate_digests"], _DIGEST, len(sizes))
        _require(bool(candidates) and set(candidates) <= sizes.keys() - set(ready))
        offset = _checkpoint_integer(raw["acknowledged_offset"], image_artifact.MAX_BLOB_BYTES)
        parts = _checkpoint_integer(raw["parts"], MAX_CALLS)
        part_size = _checkpoint_integer(raw["part_size"], protocol.MAX_PART_BYTES, minimum=1)
        if parts == 0:
            _require(offset == 0 and set(candidates) == sizes.keys() - set(ready))
        else:
            _require((parts - 1) * part_size < offset <= parts * part_size
                and all(offset <= sizes[key] for key in candidates)
                and (offset % part_size == 0 or all(offset == sizes[key] for key in candidates)))
        upload = _new(Upload, **{**raw, "candidate_digests": candidates})
    completed = len(seen) - int(upload is not None)
    _require(0 <= completed <= len(ready) and part_bytes >= offset)
    # Completed uploads are distinct ready blobs; availability checks may also
    # populate ready. Their exact provenance is the durable owner's ACK history,
    # not reconstructed by this bounded structural validator.
    ready_sizes = sorted(sizes[key] for key in ready)
    lower = sum(ready_sizes[:completed])
    upper = sum(ready_sizes[len(ready_sizes) - completed:]) if completed else 0
    _require(lower <= part_bytes - offset <= upper)
    # Every surviving candidate matched every acknowledged byte of this upload.
    # Account for its exact per-part read chunks, not just one plausible blob.
    current_reads = 0
    if upload is not None and parts:
        full_reads = (upload.part_size + READ_CHUNK_BYTES - 1) // READ_CHUNK_BYTES
        last_size = offset - (parts - 1) * upload.part_size
        current_reads = len(upload.candidate_digests) * ((parts - 1) * full_reads
            + (last_size + READ_CHUNK_BYTES - 1) // READ_CHUNK_BYTES)
        _require(comparison_bytes >= part_bytes + (len(upload.candidate_digests) - 1) * offset)
    completed_reads = max(completed, (part_bytes - offset + READ_CHUNK_BYTES - 1) // READ_CHUNK_BYTES)
    _require(comparison_calls >= current_reads + completed_reads)
    minimum_parts = max(completed + parts, (part_bytes + protocol.MAX_PART_BYTES - 1) // protocol.MAX_PART_BYTES)
    available = len(ready) - completed
    minimum_batches = max(int(not seen and calls > 0), (available + 99) // 100)
    minimum_calls = len(seen) + completed + minimum_parts + minimum_batches + int(value["status"] == "published")
    _require(minimum_calls <= calls and minimum_parts <= comparison_calls)
    if value["status"] == "fresh":
        _require(calls == 0 and not ready and not seen and upload is None)
    else:
        _require(calls > 0)
        if value["status"] == "published":
            _require(upload is None and set(ready) == sizes.keys())
    return _change(base, clock=clock, revision=revision, status=value["status"],
        ready_digests=ready, seen_upload_ids=seen, upload=upload, calls=calls,
        part_bytes=part_bytes, comparison_bytes=comparison_bytes, comparison_calls=comparison_calls)


def export_checkpoint(snapshot: Snapshot) -> bytes:
    """Encode a quiescent fresh/ACKed/published state, never a pending permit.

    Canonical JSON contains no request body, secret, handle or constructor seal.
    Only a trusted durable owner may retain/adopt it as current. A checkpoint
    digest would detect changed bytes, not authenticate the claimed history.
    """
    try:
        _snapshot(snapshot)
        _require(snapshot._plan is None)
        scope = {field.name: getattr(snapshot.scope, field.name) for field in fields(PublicationScope)}
        scope["protocol_scope"] = {field.name: getattr(snapshot.scope.protocol_scope, field.name)
            for field in fields(protocol.Scope)}
        value = {key: getattr(snapshot, key) for key in _CHECKPOINT_FIELDS
            - {"schema", "scope", "deadline", "clock", "upload", "ready_digests", "seen_upload_ids"}}
        value.update(schema=CHECKPOINT_SCHEMA, scope=scope,
            deadline={field.name: getattr(snapshot.deadline, field.name) for field in fields(Deadline)},
            clock={field.name: getattr(snapshot.clock, field.name) for field in fields(Clock)},
            ready_digests=list(snapshot.ready_digests), seen_upload_ids=list(snapshot.seen_upload_ids),
            upload=None if snapshot.upload is None else {field.name:
                list(snapshot.upload.candidate_digests) if field.name == "candidate_digests" else getattr(snapshot.upload, field.name)
                for field in fields(Upload)})
        _restore_checkpoint(snapshot._image, snapshot.scope, value, clock=snapshot.clock, deadline=snapshot.deadline)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        _require(len(raw) <= MAX_CHECKPOINT_BYTES)
        return raw
    except Exception:
        raise PlanError() from None


def restore_checkpoint(image: image_artifact.VerifiedImage, scope: PublicationScope, checkpoint: bytes,
        *, clock: Clock, deadline: Deadline) -> Snapshot:
    """Restore bounded data against original owner-selected scope and deadline.

    Pending/failed/uncertain states cannot restore. The observation clock may
    advance but never regress or reach either original deadline; published
    remains terminal. The owner must enforce same boot/clock domain, current
    durable CAS, authenticated history and immutable content custody separately.
    This function performs no blob reads, history replay, authorization or send.
    """
    try:
        return _restore_checkpoint(image, scope, _checkpoint_document(checkpoint), clock=clock, deadline=deadline)
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
