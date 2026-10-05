"""One source-fixed256-row phase with bounded per-row genuine proof work.

The phase is still one logical pruning batch, not256 database commits. Each
row stage verifies its raw phase-before proof, rebases only with this owner's
actual earlier folds, and invokes the real one-row OLD/NEW engine. Full rows
are released after that call; only candidate leaves, leaf changes and genuine
node maps survive. Complete range/rank closure and all nine real index folds
are mandatory before the phase can finish. SQL/parent/currentness admission
and the original absolute deadline remain the enclosing owner's obligations.

No public API accepts a successful row computation or supplied node overlay.
The independent executor follows the same raw path inside its single outer
transaction and must roll back all tentative changes if this owner fails.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_phase_plan as phase_plan
from serverware import authority_challenge_retention as retention
from serverware import authority_challenge_row_transition as row_transition
from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_contract as contract
from serverware import authority_index_heads as heads
from serverware import authority_index_mutation as counted
from serverware import authority_index_projection as projection
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import _ValidationWork


_TABLE = retention.CHALLENGE_TABLE
_PROOF_DOMAIN = "serverware.policyAuthorityRadixMultiproof/v3"


class ChallengeStreamError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _CompletedPhase:
    """Only an invocation's relative output, never a verifier input."""

    context: dict
    available: int
    row_count: int
    primary_before: primary.PrimaryRoot
    primary_after: primary.PrimaryRoot
    before_heads: tuple
    after_heads: tuple
    primary_layers: tuple
    counted_nodes: dict
    counted_changes: dict


class _StreamingPhase:
    """Private actual-row owner; an error retires the entire phase."""

    def __init__(self, *, context, primary_root, index_heads, count_evidence, work):
        if type(work) is not _ValidationWork or type(index_heads) is not tuple:
            raise ChallengeStreamError("challenge phase requires original work/head types")
        owned = maintenance._owned({"context": context, "root": primary_root,
            "heads": [maintenance.head_wire(head) for head in index_heads],
            "count": count_evidence}, work)
        phase_plan._context(owned["context"])
        self._context = owned["context"]
        self._context_bytes = work.wire(self._context)
        work.charge(hashes=contract.TREE_DEPTH + 1)
        self._before = self._root = maintenance._root(owned["root"])
        self._identities = heads.required_index_ids(maintenance.OPERATION, include_write_heads=True)
        if tuple(item.get("indexId") for item in owned["heads"]) != self._identities:
            raise ChallengeStreamError("challenge phase omitted a fixed source head")
        before = []
        for value in owned["heads"]:
            work.charge(hashes=projection.PROFILE_HASH_WORK)
            before.append(maintenance._head(value, projection.profile_for(value["indexId"]),
                self._before, work))
        self._heads = tuple(before)
        role = maintenance.phase_role(self._context["phase"])
        self._profile, self._whole = counts.source_interval(role, user_id="",
            cutoff_us=self._context["cutoffUs"], rate_window_us=1,
            retention_us=self._context["retentionUs"], work=work)
        self._read_head = next(head for head in self._heads if head.index_id == self._profile.index_id)
        self._available = counts._verify_interval_evidence(owned["count"], role=role,
            expected_head=self._read_head, profile=self._profile, interval=self._whole, work=work)
        self._expected = min(maintenance.BATCH_SIZE,
            max(0, self._available - self._context["retainedLimit"])
            if self._context["phase"] == "overflow" else self._available)
        work.charge(hashes=(contract.TREE_DEPTH + 1) * (contract.TREE_DEPTH + 2) // 2)
        self._empty = tuple(radix.empty_digest(depth) for depth in range(contract.TREE_DEPTH + 1))
        self._keys, self._leaves, self._primary_layers = set(), [], []
        self._changes = {identity: {} for identity in self._identities}
        self._deltas = dict.fromkeys(self._identities, 0)
        self._after_heads, self._counted_nodes = [], {}
        self._reads_closed = False
        self._busy = self._failed = self._closed = False

    @property
    def expected_rows(self):
        """Ordinary count observation for the enclosing fixed stage schedule."""
        return self._expected

    @contextmanager
    def _using(self, work):
        try:
            if type(work) is not _ValidationWork or self._busy or self._failed or self._closed:
                raise ChallengeStreamError("challenge phase is closed or reentered")
            actual = work.wire(self._context)
            work.charge(input_bytes=len(actual) + len(self._context_bytes))
            if actual != self._context_bytes:
                raise ChallengeStreamError("challenge phase original context changed")
            self._busy = True
            yield
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def _node(self, depth, prefix, original):
        for layer in reversed(self._primary_layers):
            address = (_TABLE, depth, prefix)
            if address in layer:
                return layer[address]
            for ancestor in range(depth):
                address = (_TABLE, ancestor, prefix[:ancestor])
                if address in layer and layer[address] == self._empty[ancestor]:
                    return self._empty[depth]
        return original

    def consume(self, *, selected_row, before_proof, work):
        """Compute one actual mutation; no aggregate row graph is retained.

        The returned raw mutation is only suitable for the independently
        admitted executor's tentative outer transaction. Its existence cannot
        authorize a commit, skip complete-selection closure, or spend a new
        clock. Production and replay both invoke this exact method themselves.
        """
        with self._using(work):
            if self._reads_closed or len(self._keys) >= self._expected:
                raise ChallengeStreamError("challenge row is repeated or exceeds its authenticated count")
            # Check the full raw original against this phase's BEFORE root.
            # The subsequent fold against the intermediate root is separate:
            # only actual earlier one-row maps may rebase these proof vectors.
            observed = primary.evaluate_primary_radix_memberships(
                table_contracts=(primary.PrimaryTableContract(_TABLE, ("id",), False, "business"),),
                business_before_roots=(self._before,), authorization_before_roots=(),
                selected_rows=(selected_row,), before_proofs=(before_proof,),
                limits=batch._primary_limits(contract.operation_spec(maintenance.OPERATION), 1,
                    batch._SharedLedger(work)))
            metrics = observed.result.metrics
            work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
            if observed.result.business_after_roots != (self._before,) or observed.result.authorization_after_roots:
                raise ChallengeStreamError("challenge row membership changed the phase-before root")
            selected, proof = observed.selected_rows[0], observed.before_proofs[0]
            key = selected["keyDigest"]
            if key in self._keys or selected["present"] is not True:
                raise ChallengeStreamError("challenge row is absent or duplicates a phase primary key")
            proof["rootRevision"], proof["rootDigest"] = self._root.root_revision, self._root.root_digest
            for level in proof["siblings"]:
                depth, prefix = level["depth"] + 1, level["pathPrefix"]
                for nibble, digest in enumerate(level["childDigests"]):
                    level["childDigests"][nibble] = self._node(depth, prefix + format(nibble, "x"), digest)
            del proof["proofDigest"]
            encoded = work.wire(proof)
            work.charge(hashes=1, input_bytes=len(_PROOF_DOMAIN) + 9 + len(encoded))
            proof["proofDigest"] = core.framed_digest(_PROOF_DOMAIN, encoded)
            computed = row_transition.evaluate_row(phase=self._context["phase"],
                cutoff_us=self._context["cutoffUs"], retention_us=self._context["retentionUs"],
                primary_root=self._root, selected_row=selected, before_proof=proof, work=work)
            if (computed.primary_before != self._root
                    or tuple(entry.index_id for entry in computed.index_changes) != self._identities):
                raise ChallengeStreamError("challenge row engine changed the actual source/root inventory")
            leaf = computed.candidate_leaf
            if self._leaves:
                descending = self._context["phase"] == "overflow"
                if (leaf.key >= self._leaves[-1].key if descending else leaf.key <= self._leaves[-1].key):
                    raise ChallengeStreamError("challenge rows do not follow the actual timestamp/ID order")
            for entry in computed.index_changes:
                changes = self._changes[entry.index_id]
                for change in entry.changes:
                    if change.key in changes:
                        raise ChallengeStreamError("challenge rows collide on a source-projected key")
                    changes[change.key] = change
                self._deltas[entry.index_id] += entry.revision_delta
            self._keys.add(key)
            self._leaves.append(leaf)
            self._primary_layers.append(computed.primary_nodes)
            self._root = computed.primary_after
            return computed.mutation

    def close_reads(self, *, range_evidence, rank_evidence, work):
        with self._using(work):
            if self._reads_closed or len(self._keys) != self._expected:
                raise ChallengeStreamError("challenge phase has not consumed its exact authenticated batch")
            if self._expected == 0:
                # The count frontier already proves no expired/old member or
                # no overflow beyond retainedLimit. There are no selected
                # rows to cover. Do not acquire a redundant empty-range proof
                # or accept arbitrary evidence in an unscheduled stage.
                if range_evidence is not None or rank_evidence is not None:
                    raise ChallengeStreamError("empty challenge phase carries unscheduled range or rank evidence")
                self._reads_closed = True
                return
            raw = maintenance._owned({"range": range_evidence, "rank": rank_evidence}, work)
            maintenance._close_selection(phase=self._context["phase"],
                retained_limit=self._context["retainedLimit"], available=self._available,
                profile=self._profile, whole=self._whole, head=self._read_head,
                projected=tuple(sorted(self._leaves, key=lambda leaf: leaf.key)),
                range_evidence=raw["range"], rank_evidence=raw["rank"], work=work)
            self._reads_closed = True

    def _next_index(self, index_id):
        if (not self._reads_closed or type(index_id) is not str
                or len(self._after_heads) >= len(self._identities)
                or self._identities[len(self._after_heads)] != index_id):
            raise ChallengeStreamError("challenge index is not the exact next closed-row stage")

    def _write_changes(self, *, index_id, work):
        """Private raw leaf images derived here, never supplied by a caller."""
        with self._using(work):
            self._next_index(index_id)
            return tuple(self._changes[index_id][key] for key in sorted(self._changes[index_id]))

    def fold_index(self, *, index_id, frontier, work):
        with self._using(work):
            self._next_index(index_id)
            head = self._heads[len(self._after_heads)]
            changes = tuple(self._changes[index_id][key] for key in sorted(self._changes[index_id]))
            if not self._expected:
                if frontier is not None:
                    raise ChallengeStreamError("empty challenge phase carries unexpected write proof input")
                self._after_heads.append(head)
                self._counted_nodes[index_id] = {}
                return
            work.charge(hashes=projection.PROFILE_HASH_WORK)
            profile = projection.profile_for(index_id)
            limits = read_write._write_limits(contract.operation_spec(maintenance.OPERATION),
                batch._SharedLedger(work)).index
            actual = counted._evaluate_index_mutations_overlay(profile=profile,
                before_root=head.index_root, changes=changes, frontier=frontier, limits=limits)
            work.charge(hashes=actual.result.metrics.hashes, input_bytes=actual.result.metrics.input_bytes)
            revision = head.index_revision + self._deltas[index_id]
            if revision >= 2**63 or actual.result.after_root.count > self._root.leaf_count:
                raise ChallengeStreamError("challenge computed head exceeds its primary/revision bound")
            self._after_heads.append(heads.CapturedIndexHead(head.index_id, head.table,
                head.counted_profile, head.projection_digest, head.projection_manifest_digest,
                revision, actual.result.after_root))
            self._counted_nodes[index_id] = actual.nodes

    def finish(self, *, work):
        with self._using(work):
            if (not self._reads_closed or len(self._keys) != self._expected
                    or tuple(head.index_id for head in self._after_heads) != self._identities):
                raise ChallengeStreamError("challenge phase lacks complete rows/range/nine-index closure")
            completed = _CompletedPhase(maintenance._owned(self._context, work), self._available,
                self._expected, self._before, self._root, self._heads, tuple(self._after_heads),
                tuple(self._primary_layers), self._counted_nodes, self._changes)
            # Transfer the private actual maps to the surrounding chain. A
            # later borrower close cannot erase that chain's node provenance.
            self._primary_layers, self._counted_nodes, self._changes = [], {}, {}
            self._closed = True
            return completed

    def close(self):
        self._closed = True
        self._primary_layers.clear()
        self._changes.clear()
        self._counted_nodes.clear()
