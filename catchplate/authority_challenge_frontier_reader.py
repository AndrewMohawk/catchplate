"""Bounded raw immediate-child reads for the nine challenge write profiles.

Geometry is captured once from the caller's genuinely derived OLD/NEW targets.
It is not a root admission or proof result. The caller retains the original
transaction, cursor, deadline and phase schedule; independent mutation replay
must still reconstruct every root from the complete raw page series.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import I64_MAX, KEY_NIBBLES, CountedNode, OpaqueSubtree
from catchplate.authority_index_heads import CapturedIndexHead, CHALLENGE_OPERATIONS
from catchplate.authority_query_read_work import _ValidationWork


SCHEMA = "catchplate.policyAuthorityChallengeWriteFrontierPage/v1"
READ_PROFILE = "catchplate.policyAuthorityChallengeWriteFrontierRead/v1"
PARENTS_PER_PAGE = 16
MAX_TARGETS = 512
MAX_PARENTS = 1 + KEY_NIBBLES * MAX_TARGETS
MAX_CHILDREN = 16 * PARENTS_PER_PAGE
MAX_RAW_BYTES = 4 * 1024 * 1024
INDEX_IDS = (
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_challenge_created_global", "webauthn_challenge_created_user",
    "webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
    "webauthn_challenge_terminal_unreferenced_global",
    "webauthn_challenge_scope_unused", "webauthn_challenge_value",
)
_HEX = frozenset("0123456789abcdef")
_SEAL = object()


def _require(condition, message):
    if not condition:
        raise reader.IndexReadError(message)


def _targets(target_keys):
    _require(type(target_keys) is tuple and len(target_keys) <= MAX_TARGETS,
             "challenge frontier targets exceed their exact source shape")
    previous = None
    for key in target_keys:
        _require(type(key) is str and len(key) == KEY_NIBBLES
                 and all(character in _HEX for character in key)
                 and (previous is None or previous < key),
                 "challenge frontier targets are not sorted unique counted keys")
        previous = key


def _parents(target_keys, work=None):
    opened = {""}
    if work is not None:
        work.charge(input_bytes=2, json_nodes=1)
    for key in target_keys:
        for depth in range(1, KEY_NIBBLES):
            # Charge each actually created ASCII scalar before its slice,
            # including duplicates later discarded by the bounded set.
            if work is not None:
                work.charge(input_bytes=depth + 2, json_nodes=1)
            opened.add(key[:depth])
    _require(len(opened) <= MAX_PARENTS, "challenge frontier geometry exceeds its source bound")
    if work is not None:
        # Sorting/tuple ownership visits the existing bounded scalar graph;
        # these are canonical work units, not interpreter allocation metrics.
        work.charge(input_bytes=2 + max(0, len(opened) - 1)
                    + sum(len(prefix) + 2 for prefix in opened), json_nodes=1 + len(opened))
    return tuple(sorted(opened))


def frontier_parents(target_keys, *, work=None):
    """Pure deterministic geometry, never caller-selected parent slices."""
    _require(work is None or type(work) is _ValidationWork,
             "challenge frontier geometry work has an unexpected exact type")
    _targets(target_keys)
    return _parents(target_keys, work)


@dataclass(frozen=True, slots=True, init=False)
class _FrontierGeometry:
    _head: tuple
    _targets: tuple
    _parents: tuple
    _originals: tuple
    _seal: object

    def _require_originals(self):
        _require(self._seal is _SEAL and type(self._originals) is tuple
                 and len(self._originals) == 3
                 and all(current is original for current, original in zip(
                     (self._head, self._targets, self._parents), self._originals)),
                 "challenge frontier geometry is not its captured original")


def capture_frontier_geometry(*, head, target_keys, work):
    """Capture the source geometry once, on the caller's existing work meter."""
    _require(type(work) is _ValidationWork and type(head) is CapturedIndexHead
             and type(head.index_root) is CountedNode,
             "challenge frontier requires exact original head/work types")
    _targets(target_keys)
    work.prepare_scan(target_keys)
    _require(type(head.index_id) is str and head.index_id in INDEX_IDS
             and set(projection.index_ids_for_table("webauthn_challenges")) == set(INDEX_IDS),
             "challenge frontier profile is outside the fixed source inventory")
    reader._profile_work(head.index_id, work)
    profile = projection.profile_for(head.index_id)
    work.prepare_encoding([projection._definition(name).document() for name in projection.INDEX_IDS])
    work.charge(hashes=1)
    _require(type(head.table) is str and head.table == "webauthn_challenges"
             and type(head.counted_profile) is str and head.counted_profile == projection.COUNTED_PROFILE
             and type(head.projection_digest) is str and head.projection_digest == profile.projection_digest
             and type(head.projection_manifest_digest) is str
             and head.projection_manifest_digest == projection.projection_manifest_digest()
             and type(head.index_revision) is int and 0 <= head.index_revision <= I64_MAX,
             "challenge frontier head differs from its source profile")
    root = CountedNode(head.index_root.digest, head.index_root.count)
    _require(head.index_revision != 0 or root.count == 0,
             "challenge frontier zero revision has a nonempty root")
    fields = (head.index_id, head.projection_digest, head.index_revision, root.digest, root.count)
    work.prepare_copy(fields)
    parents = _parents(target_keys, work)
    geometry = object.__new__(_FrontierGeometry)
    for name, value in (("_head", fields), ("_targets", target_keys), ("_parents", parents),
                        ("_originals", (fields, target_keys, parents)), ("_seal", _SEAL)):
        object.__setattr__(geometry, name, value)
    return geometry


def acquire_frontier_page(cursor, *, geometry, ordinal, trace, work, acquisition):
    """Read one internally selected page; do not fold, admit or renew anything."""
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise reader.IndexReadError("challenge frontier requires the original work/acquisition pair")
    with acquisition.read_phase(cursor, trace, work):
        _require(type(geometry) is _FrontierGeometry,
                 "challenge frontier requires source-captured geometry")
        geometry._require_originals()
        _require(type(getattr(trace, "operation", None)) is str and trace.operation in CHALLENGE_OPERATIONS,
                 "challenge frontier operation is not source admitted")
        work.prepare_scan(geometry._targets)
        fields, all_parents = geometry._head, geometry._parents
        index_id, projection_digest, revision, root_digest, root_count = fields
        _require(type(ordinal) is int and 0 <= ordinal < (len(all_parents) + 15) // PARENTS_PER_PAGE,
                 "challenge frontier page ordinal is outside its exact geometry")
        parents = all_parents[ordinal * PARENTS_PER_PAGE:(ordinal + 1) * PARENTS_PER_PAGE]
        work.prepare_copy(parents)
        marker = dict(profile=READ_PROFILE, indexId=index_id, projectionDigest=projection_digest,
            indexRevision=revision, rootDigest=root_digest, rootCount=root_count,
            ordinal=ordinal, parentCount=len(all_parents), parents=list(parents), limit=MAX_CHILDREN)
        work.prepare_copy(marker)
        ranges = tuple(value for parent in parents for value in (len(parent) + 1, parent + "0", parent + "f"))
        values = ", ".join("(%s::pg_catalog.int4,%s::pg_catalog.text,%s::pg_catalog.text)" for _ in parents)
        sql = (f'SELECT {reader._NODE_SELECT} FROM "catchplate_metadata"."{reader.NODE_TABLE}" AS node '
            f'JOIN (VALUES {values}) AS requested(depth, lower_prefix, upper_prefix) '
            'ON node.depth = requested.depth AND node.path_prefix COLLATE "C" >= requested.lower_prefix COLLATE "C" '
            'AND node.path_prefix COLLATE "C" <= requested.upper_prefix COLLATE "C" '
            'WHERE node.index_id COLLATE "C" = %s ORDER BY node.path_prefix COLLATE "C" LIMIT %s')
        children, previous = [], None
        with acquisition.scope(cursor, trace, work):
            work.prepare_utf8(sql)
            rows = acquisition.read(reader.NODE_TABLE, marker, sql,
                                    (*ranges, index_id, MAX_CHILDREN + 1), MAX_CHILDREN)
            geometry._require_originals()
            for raw in rows:
                row = reader._record(raw, reader._NODE_FIELDS, work)
                reader._context(row, index_id, projection_digest, revision, work)
                depth = reader._integer(row["depth"], 1, KEY_NIBBLES)
                prefix = reader._text(row["path_prefix"], KEY_NIBBLES, work=work)
                _require(len(prefix) == depth and prefix[:-1] in parents
                         and (previous is None or previous < prefix),
                         "challenge frontier child is unexpected, duplicated or unordered")
                node = OpaqueSubtree(prefix, row["node_digest"], row["subtree_count"])
                acquisition.charge("node", row, reader._NODE_FIELDS)
                children.append(dict(prefix=node.prefix, digest=node.digest, count=node.count))
                previous = prefix
        raw = dict(schema=SCHEMA, indexId=index_id, projectionDigest=projection_digest,
            indexRevision=revision, rootDigest=root_digest, rootCount=root_count,
            ordinal=ordinal, parentCount=len(all_parents), parents=list(parents), children=children)
        size, _ = work.prepare_encoding(raw)
        _require(size <= MAX_RAW_BYTES, "challenge frontier page exceeds its unchanged raw byte bound")
        encoded = core.canonical_bytes(raw)
        _require(len(encoded) == size, "challenge frontier page changed during encoding")
        geometry._require_originals()
        return encoded
