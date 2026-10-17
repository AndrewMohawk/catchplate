"""Bounded literal read-original framing, not a signed or executable plan.

One small manifest describes source-ordered byte leaves. Data frames are at
most 128 KiB; a decoder joins only an individual bounded original, never a
96 MiB JSON/base64 packet. Digests detect changed framing, not authenticity.
Actual native/current-root/row replay remains mandatory after decoding.

Each fixed original gets one standard child allowance under an unchanged
caller ledger/window, with an aggregate ceiling. No generic limit is raised,
and no token, selected-row projection, SQL or successful authority is accepted.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
import threading
import time

from catchplate import authority_native_jit_review_current_read as reads
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


SCHEMA = "catchplate.nativeJitReviewReadPlanStream/v1"
FRAME_BYTES = 128 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MAX_ORIGINAL_BYTES = reads.MAX_ORIGINAL_BYTES
MAX_ORIGINALS = 5 + 13 + reads.chunks.MAX_TOTAL_DATA_CHUNKS + 13
MAX_FRAMES = (MAX_ORIGINAL_BYTES + FRAME_BYTES - 1) // FRAME_BYTES + MAX_ORIGINALS
_ROOTS = (
    ("completeRootVectorOriginal", reads.vector.MAX_BYTES),
    ("headQueryOriginal", reads.head.MAX_QUERY_BYTES),
    ("headObservationOriginal", reads.head.MAX_BYTES),
    ("finalHeadQueryOriginal", reads.head.MAX_QUERY_BYTES),
    ("finalHeadObservationOriginal", reads.head.MAX_BYTES),
)
_SCALARS = frozenset({"schema", "operation", "requestDigest", "databaseNowEpochNs", "trustPublicationId"})
_FIELDS = frozenset({"schema", "read", "rowChunkCounts", "originals"})


class NativeJitReviewPlanStreamError(ValueError):
    def __init__(self):
        super().__init__("Native review original stream is unavailable")


def _require(value):
    if not value:
        raise NativeJitReviewPlanStreamError()


def _scope(operation, request_digest):
    _require(type(operation) is str and operation in reads.contract.OPERATIONS)
    reads.contract.grammar.digest(request_digest)


def _schedule(counts, operation):
    _require(type(counts) is list and len(counts) == (13 if operation == reads.contract.RECEIPT else 9)
        and all(type(value) is int and 1 <= value <= 98 for value in counts)
        and sum(counts) <= reads.chunks.MAX_TOTAL_DATA_CHUNKS + 13)
    return tuple(maximum for _name, maximum in _ROOTS) + tuple(
        maximum for count in counts
        for maximum in (*([2 * reads.chunks.CHUNK_BYTES + 2048] * count), reads.MAX_PROOF_BYTES))


class _StreamWork:
    """A single source-counted pass; failed or completed stages cannot reopen."""

    def __init__(self, parent, window, deadline, count):
        _require(type(parent) is _ValidationWork and type(count) is int and 5 < count <= MAX_ORIGINALS
            and type(deadline) is int and deadline > 0)
        self.parent, self.window = parent, reads.head.clock._validate(window)
        self.deadline = min(deadline, self.window[4])
        self.count, self.index, self.total = count, 0, 0
        self.identity = os.getpid(), threading.get_ident()
        self.parent_pin = reads._pin(parent)
        self.last_epoch, self.last_monotonic = self.window[0], self.window[2]
        self.stages, self.failed, self.active = [], False, None

    def check(self):
        _require(not self.failed and self.identity == (os.getpid(), threading.get_ident())
            and reads._pin(self.parent) == self.parent_pin
            and self.parent.limits is self.parent_pin[0]
            and self.total <= 4 * MAX_ORIGINAL_BYTES)
        _require(all(reads._pin(work) == pin and work.limits is pin[0] for work, pin in self.stages))

    def current(self, work):
        self.check()
        now = reads.head.clock._check_on_work(self.window, work=work)
        mono = time.monotonic_ns()
        _require(now >= self.last_epoch and mono >= self.last_monotonic and mono < self.deadline)
        self.last_epoch, self.last_monotonic = now, mono

    @contextmanager
    def stage(self, index):
        try:
            self.check()
            _require(self.active is None and type(index) is int and index == self.index < self.count)
            child = _ValidationWork(QueryReadValidationLimits())
            self.active = child
            self.current(child)
            yield child
            self.current(child)
            self.total += child.input_bytes
            self.stages.append((child, reads._pin(child)))
            self.index += 1
            self.active = None
            self.check()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.active = None

    def finish(self):
        self.check()
        _require(self.index == self.count and self.active is None)


def _manifest(raw, operation, request_digest, work):
    _require(type(raw) is bytes and 2 <= len(raw) <= MAX_MANIFEST_BYTES and raw.isascii())
    work.charge(input_bytes=3 * len(raw))
    value = reads.contract.grammar.document(raw.decode("ascii"), MAX_MANIFEST_BYTES)
    _require(type(value) is dict and set(value) == _FIELDS and value["schema"] == SCHEMA)
    scalar = value["read"]
    _require(type(scalar) is dict and set(scalar) == _SCALARS
        and scalar["schema"] == reads.SCHEMA and scalar["operation"] == operation
        and scalar["requestDigest"] == request_digest
        and type(scalar["databaseNowEpochNs"]) is int and 0 < scalar["databaseNowEpochNs"] < 2**63
        and type(scalar["trustPublicationId"]) is str and 0 < len(scalar["trustPublicationId"]) <= 1024)
    maxima = _schedule(value["rowChunkCounts"], operation)
    descriptors = value["originals"]
    _require(type(descriptors) is list and len(descriptors) == len(maxima))
    total = frames = 0
    for item, maximum in zip(descriptors, maxima, strict=True):
        _require(type(item) is dict and set(item) == {"byteCount", "sha256"}
            and type(item["byteCount"]) is int and 2 <= item["byteCount"] <= maximum)
        reads.contract.grammar.digest(item["sha256"])
        total += item["byteCount"]
        frames += (item["byteCount"] + FRAME_BYTES - 1) // FRAME_BYTES
    _require(total <= MAX_ORIGINAL_BYTES and frames <= MAX_FRAMES)
    work.prepare_copy(value)
    return value, frames


def encode_on_work(originals, *, operation, request_digest, live_window, deadline_ns, work):
    """Encode only opaque read originals; no proof or authority is asserted."""
    _scope(operation, request_digest)
    owned = reads._snapshot_originals(originals, operation, work)
    _require(owned["schema"] == reads.SCHEMA and owned["operation"] == operation
        and owned["requestDigest"] == request_digest)
    counts = [len(row["chunks"]) for row in owned["rows"]]
    maxima = _schedule(counts, operation)
    leaves = tuple(owned[name] for name, _maximum in _ROOTS) + tuple(
        raw for row in owned["rows"] for raw in (*row["chunks"], row["proof"]))
    _require(len(leaves) == len(maxima) and sum(map(len, leaves)) <= MAX_ORIGINAL_BYTES)
    budget = _StreamWork(work, live_window, deadline_ns, len(leaves))
    descriptors, frames = [], []
    for index, (raw, maximum) in enumerate(zip(leaves, maxima, strict=True)):
        with budget.stage(index) as child:
            _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
            child.charge(hashes=1, input_bytes=2 * len(raw))
            descriptors.append({"byteCount": len(raw), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()})
            frames.extend(raw[offset:offset + FRAME_BYTES] for offset in range(0, len(raw), FRAME_BYTES))
    budget.finish()
    manifest = {"schema": SCHEMA, "read": {name: owned[name] for name in sorted(_SCALARS)},
        "rowChunkCounts": counts, "originals": descriptors}
    work.prepare_encoding(manifest)
    raw = reads.core.canonical_bytes(manifest)
    _manifest(raw, operation, request_digest, work)
    _require(len(frames) <= MAX_FRAMES)
    return raw, tuple(frames)


def decode_on_work(manifest_original, frames, *, operation, request_digest, live_window, deadline_ns, work):
    """Reconstruct source-ordered literals; callers must genuinely replay them."""
    _scope(operation, request_digest)
    manifest, expected_frames = _manifest(manifest_original, operation, request_digest, work)
    _require(type(frames) is tuple and len(frames) == expected_frames
        and all(type(raw) is bytes and 1 <= len(raw) <= FRAME_BYTES for raw in frames))
    # Hold the complete immutable frame inventory before clock/hash callbacks.
    work.charge(input_bytes=64 * len(frames), json_nodes=len(frames))
    budget = _StreamWork(work, live_window, deadline_ns, len(manifest["originals"]))
    leaves, offset = [], 0
    for index, descriptor in enumerate(manifest["originals"]):
        with budget.stage(index) as child:
            size = descriptor["byteCount"]
            count = (size + FRAME_BYTES - 1) // FRAME_BYTES
            selected = frames[offset:offset + count]
            _require(all(len(raw) == min(FRAME_BYTES, size - ordinal * FRAME_BYTES)
                for ordinal, raw in enumerate(selected)))
            child.charge(hashes=1, input_bytes=2 * size)
            raw = b"".join(selected)
            _require("sha256:" + hashlib.sha256(raw).hexdigest() == descriptor["sha256"])
            leaves.append(raw)
            offset += count
    budget.finish()
    _require(offset == len(frames))
    result = dict(manifest["read"])
    result.update((name, raw) for (name, _maximum), raw in zip(_ROOTS, leaves[:5], strict=True))
    rows, offset = [], 5
    for count in manifest["rowChunkCounts"]:
        rows.append({"chunks": tuple(leaves[offset:offset + count]), "proof": leaves[offset + count]})
        offset += count + 1
    result["rows"] = tuple(rows)
    return reads._snapshot_originals(result, operation, work)
