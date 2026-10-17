"""One bounded candidate-window page on the source owner's held snapshot.

The original compound owner derives interval, offset and exact page schedule.
SQL supplies raw observations only. Empty/short pages do not establish complete
population, rank, primary membership, currentness or mutation authority.
"""
from __future__ import annotations

from catchplate import authority_challenge_id as ids
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_query_reads as reads
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import I64_MAX, CountedNode, IndexLeaf, KeyInterval
from catchplate.authority_index_heads import CapturedIndexHead, CHALLENGE_OPERATIONS
from catchplate.authority_query_read_work import _ValidationWork

SCHEMA = "catchplate.policyAuthorityChallengeCandidatePage/v1"
READ_PROFILE = "catchplate.policyAuthorityChallengeCandidatePageRead/v1"
PAGE_ROWS = 256
MAX_ORDINAL = 24
MAX_BASE_OFFSET = 1000000
MAX_RAW_BYTES = 4 * 1024 * 1024
PHASE_INDEX = {
    "expire": "webauthn_challenge_unused_global",
    "old": "webauthn_challenge_terminal_unreferenced_global",
    "overflow": "webauthn_challenge_terminal_unreferenced_global",
    "scope": "webauthn_challenge_scope_unused",
}


def _require(condition, message):
    if not condition:
        raise reader.IndexReadError(message)


def _context(phase, head, interval, base_offset, ordinal, trace, work):
    _require(type(phase) is str and phase in PHASE_INDEX
        and type(getattr(trace, "operation", None)) is str and trace.operation in CHALLENGE_OPERATIONS,
        "candidate page operation/phase is not source admitted")
    _require(type(base_offset) is int and 0 <= base_offset <= (MAX_BASE_OFFSET if phase == "overflow" else 0)
        and type(ordinal) is int and 0 <= ordinal <= MAX_ORDINAL,
        "candidate page offset/ordinal exceeds the fixed source window")
    _require(type(head) is CapturedIndexHead and type(head.index_root) is CountedNode
        and type(interval) is KeyInterval, "candidate page requires exact original head/interval types")
    values = reads._CopyBudget(work).copy((head.index_id, head.table, head.counted_profile,
        head.projection_digest, head.projection_manifest_digest, head.index_revision,
        head.index_root.digest, head.index_root.count, interval.lower, interval.upper))
    owned = CapturedIndexHead(*values[:6], CountedNode(*values[6:8]))
    interval = KeyInterval(*values[8:])
    index_id = PHASE_INDEX[phase]
    reader._profile_work(index_id, work)
    profile = projection.profile_for(index_id)
    work.prepare_encoding([projection._definition(name).document() for name in projection.INDEX_IDS])
    work.charge(hashes=1)
    _require(owned.index_id == index_id and owned.table == "webauthn_challenges"
        and owned.counted_profile == projection.COUNTED_PROFILE
        and owned.projection_digest == profile.projection_digest
        and owned.projection_manifest_digest == projection.projection_manifest_digest()
        and type(owned.index_revision) is int and 0 <= owned.index_revision <= I64_MAX
        and not (owned.index_revision == 0 and owned.index_root.count != 0),
        "candidate page head differs from its source projection")
    return profile, owned, interval


def acquire_candidate_page(cursor, *, phase, head: CapturedIndexHead, interval: KeyInterval,
                           base_offset: int, ordinal: int, trace, work, acquisition) -> bytes:
    """Return exact raw bytes; never create a connection, clock or verdict."""
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise reader.IndexReadError("candidate page needs the original work/acquisition pair")
    with acquisition.read_phase(cursor, trace, work):
        profile, owned, interval = _context(phase, head, interval, base_offset, ordinal, trace, work)
        offset = base_offset + PAGE_ROWS * ordinal
        descending = phase == "overflow"
        marker = dict(profile=READ_PROFILE, phase=phase, indexId=profile.index_id,
            projectionDigest=profile.projection_digest, indexRevision=owned.index_revision,
            rootDigest=owned.index_root.digest, rootCount=owned.index_root.count,
            lower=interval.lower, upper=interval.upper, baseOffset=base_offset,
            ordinal=ordinal, descending=descending, offset=offset, limit=PAGE_ROWS)
        upper_sql = "" if interval.upper is None else ' AND leaf.index_key COLLATE "C" < %s'
        parameters = (profile.index_id, interval.lower)
        if interval.upper is not None:
            parameters += (interval.upper,)
        direction = "DESC" if descending else "ASC"
        leaves, previous, seen = [], None, set()
        with acquisition.scope(cursor, trace, work):
            rows = acquisition.read(reader.LEAF_TABLE, marker,
                f'SELECT {reader._LEAF_SELECT} FROM "catchplate_metadata"."{reader.LEAF_TABLE}" AS leaf '
                'WHERE leaf.index_id COLLATE "C" = %s AND leaf.index_key COLLATE "C" >= %s'
                f'{upper_sql} ORDER BY leaf.index_key COLLATE "C" {direction} LIMIT %s OFFSET %s',
                (*parameters, PAGE_ROWS, offset), PAGE_ROWS)
            for raw in rows:
                row = reader._record(raw, reader._LEAF_FIELDS, work)
                reader._context(row, profile.index_id, profile.projection_digest, owned.index_revision, work)
                leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
                identity = reader._text(row["primary_id"], 71, minimum=36, work=work)
                ids.require_generated(identity)
                _require(leaf.key >= interval.lower and (interval.upper is None or leaf.key < interval.upper)
                    and (previous is None or (leaf.key < previous if descending else leaf.key > previous))
                    and leaf.primary_key_digest not in seen,
                    "candidate page changed its exact interval/order/unique primary key")
                acquisition.charge("leaf", row, reader._LEAF_FIELDS)
                work.prepare_utf8(profile.table)
                work.prepare_encoding({"id": identity})
                work.charge(hashes=1, input_bytes=16)
                digest = core.framed_digest("catchplate.policyAuthorityBusinessKey/v1",
                    profile.table.encode("ascii"), core.canonical_bytes({"id": identity}))
                _require(digest == leaf.primary_key_digest and leaf.key[-80:] == ids.order_suffix(identity),
                    "candidate page ID differs from its real BusinessKey/source order suffix")
                leaves.append(dict(key=leaf.key, primaryKeyDigest=leaf.primary_key_digest,
                    primaryRowDigest=leaf.primary_row_digest, primaryId=identity))
                previous = leaf.key
                seen.add(digest)
        raw = dict(schema=SCHEMA, phase=phase, indexId=profile.index_id,
            projectionDigest=profile.projection_digest, indexRevision=owned.index_revision,
            rootDigest=owned.index_root.digest, rootCount=owned.index_root.count,
            lower=interval.lower, upper=interval.upper, baseOffset=base_offset, ordinal=ordinal, leaves=leaves)
        size, _ = work.prepare_encoding(raw)
        _require(size <= MAX_RAW_BYTES, "candidate raw page exceeds the unchanged 4 MiB bound")
        encoded = core.canonical_bytes(raw)
        _require(len(encoded) == size, "candidate page changed during canonical encoding")
        return encoded
