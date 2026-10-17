"""Relative scope replacement inventory with one-row raw membership stages.

No complete-row batch survives a consume call. The enclosing source owner
provides the original transaction/root/deadline and fixed stage meters; this
component creates none. Genuine count, every primary membership, and complete
whole-scope range reconstruction remain mandatory before a summary is emitted.
The summary is never accepted in place of proof inputs or as write authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from catchplate import authority_challenge_counts as counts
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_challenge_retention as retention
from catchplate import authority_challenge_scope as scope
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_contract as contract
from catchplate import authority_index_range as ranges
from catchplate import authority_index_reader as reader
from catchplate import authority_radix_mutation as primary
from catchplate.authority_index_contract import KEY_NIBBLES
from catchplate.authority_query_read_work import _ValidationWork


class ChallengeScopeStreamError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ScopeSummary:
    count: int
    terminal_slots: int
    overflow: bool


def _require(condition):
    if not condition:
        raise ChallengeScopeStreamError("challenge scope stream differs from its original source inventory")


class _StreamingScope:
    """Private computation invoked by the real parent, not an evidence DTO."""

    def __init__(self, *, challenge_type, user_id, scope_key, replace_scope,
                 primary_root, index_head, count_evidence, work):
        _require(type(work) is _ValidationWork and type(replace_scope) is bool
                 and type(primary_root) is primary.PrimaryRoot)
        raw = maintenance._owned({"challengeType": challenge_type, "userId": user_id,
            "scopeKey": scope_key, "replaceScope": replace_scope,
            "primary": primary_root.json_projection(), "head": maintenance.head_wire(index_head),
            "count": count_evidence}, work)
        self._request = {name: raw[name] for name in ("challengeType", "userId", "scopeKey", "replaceScope")}
        self._request_bytes = work.wire(self._request)
        self._disabled = not replace_scope or raw["scopeKey"] is None
        self._root = self._head = self._profile = self._interval = None
        self._count = self._expected = 0
        self._overflow = False
        if self._disabled:
            _require(raw["count"] is None)
        else:
            work.charge(hashes=contract.TREE_DEPTH + 1)
            self._root = maintenance._root(raw["primary"])
            self._profile, self._interval = counts.scope_interval(challenge_type=raw["challengeType"],
                user_id=raw["userId"], scope_key=raw["scopeKey"], work=work)
            self._head = maintenance._head(raw["head"], self._profile, self._root, work)
            self._count = counts._verify_interval_evidence(raw["count"], role=counts.SCOPE_ROLE,
                expected_head=self._head, profile=self._profile, interval=self._interval, work=work)
            self._overflow = self._count > scope.MAX_REPLACEMENTS
            self._expected = 0 if self._overflow else self._count
        self._originals = (self._request, self._request_bytes, self._root, self._head,
            self._profile, self._interval, self._disabled, self._count, self._expected, self._overflow)
        self._leaves = []
        self._last_id = None
        self._slots = 0
        self._busy = self._failed = self._closed = False

    @property
    def expected_rows(self):
        """Authenticated schedule observation; not permission to skip proofs."""
        return self._expected

    @contextmanager
    def _using(self, work):
        try:
            _require(type(work) is _ValidationWork and not self._busy and not self._failed and not self._closed)
            held = (self._request, self._request_bytes, self._root, self._head,
                self._profile, self._interval, self._disabled, self._count, self._expected, self._overflow)
            _require(type(self._originals) is tuple and len(self._originals) == len(held)
                     and all(current is original for current, original in zip(held, self._originals)))
            actual = work.wire(self._request)
            work.charge(input_bytes=len(actual) + len(self._request_bytes))
            _require(actual == self._request_bytes)
            self._busy = True
            yield
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def consume(self, *, selected_row, before_proof, work):
        """Verify one raw row against the held unchanged root, then release it."""
        with self._using(work):
            _require(not self._disabled and not self._overflow and len(self._leaves) < self._expected
                     and type(selected_row) is dict and type(before_proof) is dict)
            observed = primary.evaluate_primary_radix_memberships(
                table_contracts=(primary.PrimaryTableContract(retention.CHALLENGE_TABLE,
                    ("id",), False, "business"),),
                business_before_roots=(self._root,), authorization_before_roots=(),
                selected_rows=(selected_row,), before_proofs=(before_proof,),
                limits=batch._primary_limits(contract.operation_spec(maintenance.OPERATION), 1,
                    batch._SharedLedger(work)))
            metrics = observed.result.metrics
            work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
            _require(observed.result.business_after_roots == (self._root,)
                     and not observed.result.authorization_after_roots)
            selected, proof = observed.selected_rows[0], observed.before_proofs[0]
            _require(selected["present"] is True)
            size, _ = work.measure(selected["row"])
            _require(size <= reader.MAX_PRIMARY_ROW_BYTES)
            leaf = maintenance._project(self._profile, selected, proof, work)
            identity = selected["row"]["id"]
            _require(self._interval.lower <= leaf.key
                     and (self._interval.upper is None or leaf.key < self._interval.upper)
                     and all(previous.primary_key_digest != leaf.primary_key_digest for previous in self._leaves)
                     and (not self._leaves or self._leaves[-1].key < leaf.key)
                     and (self._last_id is None or self._last_id < identity))
            self._leaves.append(leaf)
            self._last_id = identity
            self._slots += int(selected["row"]["retention_reference_mask"] == 0)

    def finish(self, *, range_evidence, work):
        """Close whole-scope membership; overflow never admits a truncated set."""
        with self._using(work):
            _require(len(self._leaves) == self._expected)
            if self._disabled or self._overflow:
                _require(range_evidence is None)
            else:
                raw = maintenance._owned(range_evidence, work)
                opened = 1 + KEY_NIBBLES * scope.MAX_REPLACEMENTS + 2 * KEY_NIBBLES
                complete = ranges._reconstruct_complete_index_range(
                    profile=self._profile, expected_root=self._head.index_root,
                    interval=self._interval, frontier=maintenance._frontier(raw),
                    limits=ranges.IndexRangeLimits(
                        max_entries=reader.MAX_OUTSIDE_PREFIXES + scope.MAX_REPLACEMENTS,
                        max_leaves=scope.MAX_REPLACEMENTS, max_opened_nodes=opened,
                        max_hashes=16 * opened + scope.MAX_REPLACEMENTS), work=work)
                work.prepare_comparison(
                    [[leaf.key, leaf.primary_key_digest, leaf.primary_row_digest] for leaf in complete.leaves],
                    [[leaf.key, leaf.primary_key_digest, leaf.primary_row_digest] for leaf in self._leaves])
                _require(complete.leaves == tuple(self._leaves))
            result = _ScopeSummary(self._count, self._slots, self._overflow)
            self._closed = True
            return result
