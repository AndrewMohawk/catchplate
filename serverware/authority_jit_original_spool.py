"""Private, bounded handoff of immutable originals from one native JIT pass.

Capture hashes bytes on their actual child allowance. Seal joins their held
identities to the literal returned context/manifest without rehashing the whole
spool on the suspended native parent's allowance. Read hashes on its supplied
allowance. No allowance, SQL pass, deadline or durable custody is created here.
The producer must seal only after acquire_pass returns through normal native
closure, persist these bytes, and independently read back and replay them.
This object is not proof against arbitrary Python-private-memory modification.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
import threading
import time

from serverware import authority_jit_compound as compound
from serverware import authority_jit_compound_plan as plan


_CONTEXT_FIELDS = frozenset({"schema", "sourceRevision", "operation",
    "operationManifestDigest", "queryManifestDigest", "authorizationManifestDigest",
    "handlerContractDigest", "requestDigest", "operationId", "assertionPolicy",
    "databaseCutoffUs", "originalDeadlineNs", "businessBeforeRoots",
    "authorizationBeforeRoots", "countedBeforeHeads", "schedule"})
_CAPS = {"primary-chunk": compound.frames.MAX_CHUNK_BYTES,
    "primary-proof": compound.frames.MAX_PROOF_BYTES,
    "index-frontier": compound.frames.MAX_INDEX_BYTES}


class JitOriginalSpoolError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalSpoolError("JIT original spool lost its fixed order, bytes or live owner")


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class _JitOriginalSpool:
    """Same-process/thread, one-shot capture and seal; raw reads are not verdicts."""

    def __init__(self, *, original_deadline_ns, work):
        _require(type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63)
        compound.source.batch._SharedLedger(work)
        work.charge(input_bytes=4096, json_nodes=128)
        self._deadline = original_deadline_ns
        self._process = os.getpid(), threading.get_ident()
        self._identity = self._deadline, self._process
        self._last_clock = 0
        self._failed = self._busy = self._sealed = False
        self._entries, self._lookup = [], {}
        self._bytes = self._slot = self._chunk = self._data_chunks = self._index = 0
        self._absent = self._receipt = False
        self._local()

    def _local(self):
        _require(type(self) is _JitOriginalSpool and not self._failed
            and self._identity == (self._deadline, self._process)
            and self._process == (os.getpid(), threading.get_ident()))
        now = time.monotonic_ns()
        _require(type(now) is int and self._last_clock <= now < self._deadline)
        self._last_clock = now

    @contextmanager
    def _call(self, work):
        try:
            self._local()
            _require(not self._busy)
            self._busy = True
            compound.source.batch._SharedLedger(work)
            # Fixed owner and at-most-67-entry metadata only; raw walks below
            # debit the caller's current child before touching its body.
            work.charge(input_bytes=8192, json_nodes=256)
            yield
            self._local()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def _key(self, kind, ordinal):
        _require(type(kind) is str and kind in _CAPS
            and type(ordinal) is int and ordinal >= 0)

    def _advance(self, kind, ordinal, raw):
        if self._slot < 7:
            if kind == "primary-chunk":
                _require(not self._absent and self._chunk < compound.rows.chunks.MAX_ROW_DATA_CHUNKS
                    and ordinal == self._slot * compound.rows.chunks.MAX_ROW_DATA_CHUNKS + self._chunk)
                if raw == b"[]":
                    _require(self._chunk == 0)
                    self._absent = True
                else:
                    _require(self._data_chunks < compound.rows.chunks.MAX_TOTAL_DATA_CHUNKS)
                    self._data_chunks += 1
                self._chunk += 1
            else:
                _require(kind == "primary-proof" and ordinal == self._slot and self._chunk > 0)
                self._slot += 1
                self._chunk, self._absent = 0, False
        elif not self._receipt:
            _require(kind == "primary-proof" and ordinal == 7)
            self._receipt = True
        else:
            _require(kind == "index-frontier" and ordinal == self._index and self._index < 12)
            self._index += 1

    def retain(self, kind, ordinal, raw, work):
        with self._call(work):
            _require(not self._sealed)
            self._key(kind, ordinal)
            _require(type(raw) is bytes and 2 <= len(raw) <= _CAPS[kind]
                and len(self._entries) < compound.MAX_ORIGINALS
                and len(raw) <= compound.MAX_ORIGINAL_BYTES - self._bytes
                and (kind, ordinal) not in self._lookup)
            self._advance(kind, ordinal, raw)
            digest = _digest(raw, work)
            entry = kind, ordinal, raw, digest
            self._entries.append(entry)
            self._lookup[kind, ordinal] = entry
            self._bytes += len(raw)

    def seal(self, *, context_bytes, manifest_bytes, work):
        with self._call(work):
            _require(not self._sealed and self._slot == 7 and self._receipt and self._index == 12)
            context = plan._decode(context_bytes, plan.MAX_CONTEXT_BYTES, work)
            manifest = plan._decode(manifest_bytes, plan.MAX_MANIFEST_BYTES, work)
            plan._object(context, _CONTEXT_FIELDS)
            plan._object(manifest, plan.MANIFEST_FIELDS)
            _require(context["schema"] == compound.CONTEXT_SCHEMA
                and type(context["originalDeadlineNs"]) is int
                and context["originalDeadlineNs"] == self._deadline
                and manifest["schema"] == compound.MANIFEST_SCHEMA
                and type(manifest["originalCount"]) is int
                and type(manifest["originalBytes"]) is int
                and manifest["originalCount"] == len(self._entries)
                and manifest["originalBytes"] == self._bytes)
            # Match the genuine context builder's reservation before its
            # source-fixed manifest helpers allocate their documents.
            work.charge(input_bytes=1024 * 1024, json_nodes=32768)
            bindings, _spec = compound.original._source_bindings(work)
            for name, value in bindings.items():
                if name != "schema":
                    plan._same(context[name], value, work)
            work.charge(input_bytes=65536, json_nodes=2048)
            plan._same(context["schedule"], compound.schedule_binding(), work)
            context_digest = compound._framed(compound.CONTEXT_DOMAIN, context_bytes, work=work)
            chain = compound._framed(compound.SEED_DOMAIN, context_digest.encode("ascii"), work=work)
            descriptors = []
            for kind, ordinal, raw, digest in self._entries:
                # Exact immutable bytes were hashed before capture. Rebuild
                # descriptors from held identities, never caller metadata.
                work.charge(input_bytes=1024, json_nodes=32)
                descriptor = {"kind": kind, "ordinal": ordinal, "byteLength": len(raw), "digest": digest}
                descriptors.append(descriptor)
                chain = compound._framed(compound.STEP_DOMAIN, chain.encode("ascii"),
                    work.wire(descriptor), work=work)
            plan._same(manifest["originals"], descriptors, work)
            plan._same(manifest["contextDigest"], context_digest, work)
            plan._same(manifest["originalChainDigest"], chain, work)
            self._sealed = True

    def keys(self, *, work):
        with self._call(work):
            _require(self._sealed)
            return tuple((kind, ordinal) for kind, ordinal, _raw, _digest in self._entries)

    def read(self, kind, ordinal, work):
        with self._call(work):
            _require(self._sealed)
            self._key(kind, ordinal)
            _require((kind, ordinal) in self._lookup)
            _kind, _ordinal, raw, digest = self._lookup[kind, ordinal]
            _require(_digest(raw, work) == digest)
            return raw
