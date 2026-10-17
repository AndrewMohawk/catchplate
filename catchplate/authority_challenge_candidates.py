"""Bounded candidate-window merge over the actual earlier phase changes.

The private parent supplies only its genuine completed engine layers and IDs.
Raw SQL observations are not membership, rank, completeness or authority. The
returned IDs remain candidates: the parent must verify their raw primary
proofs and close the complete current range/rank before accepting a phase.
No roots are folded here, and no SQL, connection or clock is created.
"""
from __future__ import annotations

from contextlib import contextmanager

from catchplate import authority_challenge_candidate_reader as source
from catchplate import authority_challenge_id as ids
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate import authority_query_reads as reads
from catchplate import authority_revocation_wire as wire
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import I64_MAX, CountedNode, IndexLeaf, KeyInterval
from catchplate.authority_index_heads import CapturedIndexHead
from catchplate.authority_index_mutation import IndexLeafChange
from catchplate.authority_query_read_work import _ValidationWork


MAX_PRIOR_MUTATIONS = 6 * 256
MAX_LAYERS = 6
_LEAF_FIELDS = frozenset({"key", "primaryKeyDigest", "primaryRowDigest", "primaryId"})
_TABLE = "webauthn_challenges"


class ChallengeCandidateError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeCandidateError("challenge candidate window differs from its source geometry")


def _leaf_wire(leaf):
    if leaf is None:
        return None
    _require(type(leaf) is IndexLeaf)
    return [leaf.key, leaf.primary_key_digest, leaf.primary_row_digest]


def _primary_digest(identity, work):
    ids.require_generated(identity)
    work.prepare_utf8(_TABLE)
    encoded = work.wire({"id": identity})
    domain = "catchplate.policyAuthorityBusinessKey/v1"
    work.charge(hashes=1, input_bytes=len(domain) + 1 + 16 + len(_TABLE) + len(encoded))
    return core.framed_digest(domain, _TABLE.encode("ascii"), encoded)


def _sort_work(count, work):
    # Match the source owner's bounded key-sort accounting before sorting:
    # each fixed-width comparison visits at most two 160-nibble keys.
    comparisons = count * max(1, count.bit_length())
    work.charge(input_bytes=320 * comparisons, json_nodes=comparisons)


class _CandidateWindow:
    """Source-owned candidate observations; errors permanently retire it."""

    def __init__(self, *, phase, head, interval, expected_rows, retained_limit,
                 prior_mutations, change_layers, changed_ids, work):
        _require(type(work) is _ValidationWork and type(phase) is str and phase in source.PHASE_INDEX
            and type(expected_rows) is int and 1 <= expected_rows <= (255 if phase == "scope" else 256)
            and type(retained_limit) is int and 0 <= retained_limit <= source.MAX_BASE_OFFSET
            and type(prior_mutations) is int and 0 <= prior_mutations <= MAX_PRIOR_MUTATIONS
            and type(head) is CapturedIndexHead and type(head.index_root) is CountedNode
            and type(interval) is KeyInterval and type(change_layers) is tuple and len(change_layers) <= MAX_LAYERS
            and type(changed_ids) is tuple and len(changed_ids) <= prior_mutations)
        _require(all(type(layer) is tuple and len(layer) <= 512 for layer in change_layers)
                 and sum(len(layer) for layer in change_layers) <= 2 * prior_mutations)
        change_count = sum(len(layer) for layer in change_layers)
        values = reads._CopyBudget(work).copy((head.index_id, head.table, head.counted_profile,
            head.projection_digest, head.projection_manifest_digest, head.index_revision,
            head.index_root.digest, head.index_root.count, interval.lower, interval.upper))
        owned_head = CapturedIndexHead(*values[:6], CountedNode(*values[6:8]))
        self._interval = KeyInterval(*values[8:])
        index_id = source.PHASE_INDEX[phase]
        reader._profile_work(index_id, work)
        profile = projection.profile_for(index_id)
        work.prepare_encoding([projection._definition(name).document() for name in projection.INDEX_IDS])
        work.charge(hashes=1)
        _require(owned_head.index_id == index_id and owned_head.table == _TABLE
            and owned_head.counted_profile == projection.COUNTED_PROFILE
            and owned_head.projection_digest == profile.projection_digest
            and owned_head.projection_manifest_digest == projection.projection_manifest_digest()
            and type(owned_head.index_revision) is int and 0 <= owned_head.index_revision <= I64_MAX
            and not (owned_head.index_revision == 0 and owned_head.index_root.count != 0))
        # Each source change is at most one 160-nibble key and two fixed
        # leaf triples (312 canonical bytes each). Reserve its actual typed
        # copy, wire container and bounded scans before constructing them.
        work.charge(input_bytes=2048 * change_count + 2 * len(change_layers) + 2,
                    json_nodes=32 * change_count + len(change_layers) + 1)
        work.charge(input_bytes=320 * change_count, json_nodes=change_count)
        layers = []
        for layer in change_layers:
            owned_layer, previous = [], None
            for change in layer:
                _require(type(change) is IndexLeafChange)
                item = IndexLeafChange(change.key, change.before, change.after)
                _require(previous is None or previous < item.key)
                owned_layer.append([item.key, _leaf_wire(item.before), _leaf_wire(item.after)])
                previous = item.key
            layers.append(owned_layer)
        work.charge(input_bytes=2 + max(0, len(changed_ids) - 1), json_nodes=1)
        copied_ids = []
        for pair in changed_ids:
            _require(type(pair) is tuple and len(pair) == 2 and all(type(value) is str for value in pair)
                     and len(pair[0]) == 71 and len(pair[1]) in (36, 71))
            work.prepare_copy(pair)
            copied_ids.append(list(pair))
        owned = maintenance._owned({"layers": layers, "ids": copied_ids}, work)
        self._changed_ids = {}
        seen_ids = set()
        for digest, identity in owned["ids"]:
            _require(digest == _primary_digest(identity, work)
                     and digest not in self._changed_ids and identity not in seen_ids)
            self._changed_ids[digest] = identity
            seen_ids.add(identity)
        # The captured graph is charged separately above. These are the new
        # immutable leaf objects, net map and eventual tuple snapshot.
        work.charge(input_bytes=2048 * change_count, json_nodes=32 * change_count)
        net = {}
        for layer in owned["layers"]:
            for key, before, after in layer:
                before = None if before is None else IndexLeaf(*before)
                after = None if after is None else IndexLeaf(*after)
                for leaf in (before, after):
                    if leaf is not None:
                        identity = self._changed_ids.get(leaf.primary_key_digest)
                        _require(identity is not None and leaf.key[-80:] == ids.order_suffix(identity))
                if key in net:
                    original, previous = net[key]
                    work.prepare_comparison(_leaf_wire(previous), _leaf_wire(before))
                    _require(previous == before)
                    net[key] = original, after
                else:
                    net[key] = before, after
        _sort_work(len(net), work)
        self._net = tuple((key, *net[key]) for key in sorted(net))
        self._phase, self._expected, self._retained = phase, expected_rows, retained_limit
        self._pages = (expected_rows + 4 * prior_mutations + source.PAGE_ROWS - 1) // source.PAGE_ROWS
        _require(1 <= self._pages <= source.MAX_ORDINAL + 1)
        self._offset = max(0, retained_limit - 2 * prior_mutations) if phase == "overflow" else 0
        self._anchors = dict(schema=source.SCHEMA, phase=phase, indexId=index_id,
            projectionDigest=owned_head.projection_digest, indexRevision=owned_head.index_revision,
            rootDigest=owned_head.index_root.digest, rootCount=owned_head.index_root.count,
            lower=self._interval.lower, upper=self._interval.upper, baseOffset=self._offset)
        self._anchor_bytes = work.wire(self._anchors)
        self._originals = (self._phase, self._expected, self._retained, self._pages, self._offset,
                           self._interval, self._net, self._changed_ids, self._anchors, self._anchor_bytes)
        self._base, self._base_ids = [], set()
        self._received = 0
        self._exhausted = self._busy = self._failed = self._closed = False

    @property
    def page_count(self):
        return self._pages

    @property
    def base_offset(self):
        return self._offset

    @property
    def received_pages(self):
        return self._received

    @contextmanager
    def _using(self, work):
        try:
            _require(type(work) is _ValidationWork and not self._busy and not self._failed and not self._closed)
            current = (self._phase, self._expected, self._retained, self._pages, self._offset,
                       self._interval, self._net, self._changed_ids, self._anchors, self._anchor_bytes)
            _require(type(self._originals) is tuple and len(self._originals) == len(current)
                and all(value is original for value, original in zip(current, self._originals)))
            actual = work.wire(self._anchors)
            work.charge(input_bytes=len(actual) + len(self._anchor_bytes))
            _require(actual == self._anchor_bytes)
            self._busy = True
            yield
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def _inside(self, key):
        return self._interval.lower <= key and (self._interval.upper is None or key < self._interval.upper)

    def consume(self, *, body_bytes, work):
        with self._using(work):
            _require(self._received < self._pages)
            raw = wire._decode_object(body_bytes, work=work, maximum_bytes=source.MAX_RAW_BYTES)
            canonical = work.wire(raw)
            work.charge(input_bytes=len(canonical) + len(body_bytes))
            _require(canonical == body_bytes and set(raw) == set(self._anchors) | {"ordinal", "leaves"})
            anchors = {name: raw[name] for name in self._anchors}
            actual = work.wire(anchors)
            work.charge(input_bytes=len(actual) + len(self._anchor_bytes))
            _require(actual == self._anchor_bytes and type(raw["ordinal"]) is int
                and raw["ordinal"] == self._received and type(raw["leaves"]) is list
                and len(raw["leaves"]) <= source.PAGE_ROWS
                and (not self._exhausted or not raw["leaves"]))
            for item in raw["leaves"]:
                _require(type(item) is dict and set(item) == _LEAF_FIELDS)
                leaf = IndexLeaf(item["key"], item["primaryKeyDigest"], item["primaryRowDigest"])
                identity = item["primaryId"]
                _require(leaf.primary_key_digest == _primary_digest(identity, work)
                    and leaf.key[-80:] == ids.order_suffix(identity) and self._inside(leaf.key)
                    and leaf.primary_key_digest not in self._base_ids)
                if self._base:
                    previous = self._base[-1][0].key
                    _require(leaf.key < previous if self._phase == "overflow" else leaf.key > previous)
                self._base.append((leaf, identity))
                self._base_ids.add(leaf.primary_key_digest)
            self._exhausted = self._exhausted or len(raw["leaves"]) < source.PAGE_ROWS
            self._received += 1

    def finish(self, *, work):
        with self._using(work):
            _require(self._received == self._pages)
            # Precharge the actual fixed-width retained graphs before their
            # map copies/scans and prefix/identity bookkeeping. These units
            # conservatively cover containers as well as all leaf scalars.
            work.charge(input_bytes=2048 * len(self._net) + 1024 * len(self._base),
                        json_nodes=32 * len(self._net) + 16 * len(self._base))
            net = {key: (before, after) for key, before, after in self._net}
            merged = {}
            for leaf, identity in self._base:
                if leaf.key in net:
                    before, _after = net[leaf.key]
                    work.prepare_comparison(_leaf_wire(leaf), _leaf_wire(before))
                    _require(leaf == before)
                else:
                    merged[leaf.key] = leaf, identity
            for key, _before, after in self._net:
                if after is not None and self._inside(key):
                    _require(key not in merged)
                    merged[key] = after, self._changed_ids[after.primary_key_digest]
            # Every net BEFORE in the implicit prefix leaves it, including a
            # same-key update whose AFTER is explicitly reinserted locally.
            # At most 2M changed keys can precede the raw window; its 2M margin
            # therefore keeps every implicit row before the requested rank.
            # E+4M captured rows cover those skips and all possible removals.
            implicit = 0
            if self._offset:
                _require(bool(self._base))
                first = self._base[0][0].key
                removed = sum(before is not None and self._inside(key) and key > first
                              for key, before, _after in self._net)
                _require(removed <= self._offset)
                implicit = self._offset - removed
            skip = self._retained - implicit if self._phase == "overflow" else 0
            _require(skip >= 0)
            # A leaf/ID tuple is at most 390 canonical bytes. Reserve the
            # ordered snapshot before producing it, then every sort compare.
            work.charge(input_bytes=512 * len(merged), json_nodes=8 * len(merged))
            _sort_work(len(merged), work)
            ordered = sorted(merged.values(), key=lambda item: item[0].key, reverse=self._phase == "overflow")
            _require(len({leaf.primary_key_digest for leaf, _identity in ordered}) == len(ordered)
                     and len({identity for _leaf, identity in ordered}) == len(ordered))
            selected = ordered[skip:skip + self._expected]
            _require(len(selected) == self._expected)
            result = tuple(identity for _leaf, identity in selected)
            self._closed = True
            return result
