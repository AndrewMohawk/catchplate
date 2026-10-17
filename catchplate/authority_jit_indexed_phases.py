"""Private fixed JIT primary/count folds on original compound child work.

All three deltas enter as raw row/proof/mutation originals. Only the genuine
primary engine's same-call owned values feed hashing and projection. All twelve
raw counted frontiers are required, including empty/nonmember profiles. This
component admits no currentness, operation semantics, five read-only membership
verdicts or caller-supplied prepared/geometry result. Those parent obligations
remain independent and mandatory. No SQL, clock or allowance is created here.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
import os
import threading

from catchplate import authority_complete_query_batch as batch
from catchplate import authority_complete_read_write as read_write
from catchplate import authority_contract as contract
from catchplate import authority_index_heads as heads
from catchplate import authority_index_projection as projection
from catchplate import authority_indexed_mutation as indexed
from catchplate import authority_jit_assertion_receipt as receipt
from catchplate import authority_primary_contract as primary_contract
from catchplate.authority_index_contract import CountedNode, empty_node, validate_counted_node
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationMetrics


OPERATION = receipt.OPERATION
PRIMARY_TABLES = (receipt.RECEIPT_TABLE, "webauthn_challenges", "webauthn_credentials")
PRIMARY_KINDS = ("INSERT", "UPDATE", "UPDATE")
STAGE_COUNT = 30
MAX_MUTATION_BYTES = 3 * contract.MAX_REQUEST_BYTES + 2 * 1024 * 1024 + 131072


class JitIndexedPhaseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _IndexObservation:
    """Detached source outputs for acquisition, never an accepted input token."""

    index_id: str
    index_revision: int
    before_root: CountedNode
    changes: tuple
    target_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class JitIndexedObservation:
    result: indexed.IndexedMutationResult
    stage_work: tuple[QueryReadValidationMetrics, ...]
    total_work: QueryReadValidationMetrics


def _require(value):
    if not value:
        raise JitIndexedPhaseError("JIT indexed phase differs from its fixed originals or source order")


def _values(work):
    batch._SharedLedger(work)
    return work.hash_work, work.input_bytes, work.json_nodes


def _limits(work):
    return work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes


def _engine(work):
    return indexed._Budget(read_write._write_limits(contract.operation_spec(OPERATION),
        batch._SharedLedger(work)), work=work)


def _head_values(head):
    return head.index_id, head.index_revision, head.index_root.digest, head.index_root.count


def _pins(*values):
    # Type tags prevent bool/int equality from preserving an altered scalar.
    _require(all(type(value) in (str, int, bool) or value is None for value in values))
    return tuple((type(value), value) for value in values)


def _prepared_pins(prepared):
    """Small engine metadata only; privately owned full rows never escape."""
    _require(type(prepared) is indexed._PreparedPrimaryChanges and prepared.verified is None
        and type(prepared.by_table) is dict and len(prepared.by_table) == 2
        and tuple(prepared.by_table) == PRIMARY_TABLES[1:])
    changes = []
    for table, entries in prepared.by_table.items():
        _require(type(entries) is list and len(entries) == 1)
        mutation = entries[0]
        _require(type(mutation) is dict and set(mutation) == indexed.primary._MUTATION_FIELDS
            and type(mutation["key"]) is dict and set(mutation["key"]) == {"id"}
            and type(mutation["expectedRow"]) is dict and type(mutation["row"]) is dict)
        changes.append((id(entries), id(mutation), id(mutation["key"]),
            id(mutation["expectedRow"]), id(mutation["row"]),
            _pins(table, mutation["table"], mutation["operation"], mutation["templateId"],
                mutation["keyDigest"], mutation["key"]["id"],
                mutation["expectedRow"]["id"], mutation["row"]["id"])))
    counts = []
    for mapping, size in ((prepared.primary_before_counts, 2), (prepared.primary_after_counts, 4)):
        _require(type(mapping) is dict and len(mapping) == size)
        counts.append((id(mapping), tuple(_pins(key, value) for key, value in mapping.items())))
    digests = []
    for mapping, size in ((prepared.old_digests, 3), (prepared.new_digests, 2)):
        _require(type(mapping) is dict and len(mapping) == size
            and all(type(key) is tuple and len(key) == 2 for key in mapping))
        digests.append((id(mapping), tuple(_pins(*key, value) for key, value in mapping.items())))
    return (id(prepared), id(prepared.by_table), tuple(changes), tuple(counts), tuple(digests),
        _pins(prepared.new_row_hashes))


def _pending_pins(pending):
    item, profile, changes, delta, allowance = pending
    _require(type(item) is indexed.IndexedMutationInput and type(profile) is indexed.counted.IndexProfile
        and type(item.index_root) is CountedNode and item.frontier == ()
        and type(changes) is tuple and len(changes) <= 2)
    images = []
    for change in changes:
        _require(type(change) is indexed.counted.IndexLeafChange)
        leaves = []
        for leaf in (change.before, change.after):
            _require(leaf is None or type(leaf) is indexed.counted.IndexLeaf)
            leaves.append(None if leaf is None else (id(leaf),
                _pins(leaf.key, leaf.primary_key_digest, leaf.primary_row_digest)))
        images.append((id(change), _pins(change.key), tuple(leaves)))
    return (id(item), id(item.index_root), id(profile), id(changes),
        _pins(*_head_values(item), profile.index_id, profile.table, profile.projection_digest,
            delta, allowance), tuple(images))


def _primary_hidden_work(selected, proof, mutation, sizes, work):
    """Reserve hidden unchanged primary SQL-JSON/copy/hash-material walks.

    The engine's own metric additionally charges its complete canonical input
    and snapshot nodes. ASCII measurements conservatively bound SQL UTF-8.
    Fixed v3 64x16 sibling framing, keys and root metadata use the final reserve.
    This is not a blanket 4 MiB writable-row fit claim: prior spending and the
    unchanged per-stage limits still refuse. Large read-only trust rows are
    handled by the parent's separate actual membership stage, not here.
    """
    proof_size, proof_nodes = work.measure(proof)
    size = sizes[0][0] + sizes[1][0] + proof_size
    nodes = sizes[0][1] + sizes[1][1] + proof_nodes
    work.charge(input_bytes=2 * size, json_nodes=nodes)
    # Actual tree_json_bytes owns a graph and serializes it. Present OLD is
    # hashed for membership and encoded again for full-row CAS; NEW is hashed.
    for row, copies in ((selected.get("row"), 5), (mutation["expectedRow"], 2),
                        (mutation["row"], 3)):
        if row is not None:
            row_size, row_nodes = work.measure(row)
            work.charge(input_bytes=copies * row_size, json_nodes=2 * row_nodes)
    work.charge(input_bytes=2 * 1024 * 1024, json_nodes=32768)


class _JitIndexedPhases:
    def __init__(self, *, business_before_roots, authorization_before_roots, counted_before_heads, work):
        self._process = os.getpid(), threading.get_ident()
        self._busy = self._failed = self._closed = False
        self._phase = 0
        self._meters, self._work_metrics, self._acquisition_meters = [], [], []
        self._acquired = set()
        self._verified, self._before_heads, self._after_heads, self._index_metrics = [], [], [], []
        self._business = self._authorization = self._heads = self._contracts = self._ids = None
        self._prepared = self._after_roots = self._pending = None
        self._prepared_original = self._pending_original = None
        self._selected_bytes = self._mutation_bytes = self._engine_bytes = 0
        self._context_hashes = self._projection_hashes = 0
        with self._stage(0, work):
            _require(type(business_before_roots) is tuple and len(business_before_roots) == 4
                and type(authorization_before_roots) is tuple and len(authorization_before_roots) == 4
                and type(counted_before_heads) is tuple and len(counted_before_heads) == 12)
            self._contracts = primary_contract.primary_table_contracts(OPERATION)
            _require(len(self._contracts) == 8
                and sum(item.root_class == "business" for item in self._contracts) == 4
                and sum(item.root_class == "authorization" for item in self._contracts) == 4
                and all(not item.write_access or item.root_class == "business" for item in self._contracts)
                and tuple(item.table for item in self._contracts if item.write_access)
                    == PRIMARY_TABLES)
            # Exact constructors recheck scalar types, genesis/empty roots and
            # source complete ordering; no boolean/integer alias is accepted.
            work.charge(hashes=contract.TREE_DEPTH + 2)
            inventories = []
            for root_class, originals in (("business", business_before_roots),
                    ("authorization", authorization_before_roots)):
                copied = []
                for root in originals:
                    _require(type(root) is indexed.primary.PrimaryRoot)
                    work.prepare_copy((root.table, root.root_revision, root.root_digest, root.leaf_count))
                    copied.append(indexed.primary._root_snapshot(root))
                owned = tuple(copied)
                _require(tuple(root.table for root in owned)
                    == tuple(item.table for item in self._contracts if item.root_class == root_class))
                inventories.append(owned)
            self._business, self._authorization = inventories
            self._ids = heads._jit_receipt_ids()
            _require(len(self._ids) == 12)
            copied, by_table = [], {root.table: root for root in self._business}
            for head, identity in zip(counted_before_heads, self._ids, strict=True):
                _require(type(head) is read_write.CompleteReadWriteHead
                    and type(head.index_id) is str and head.index_id == identity
                    and type(head.index_revision) is int and 0 <= head.index_revision < 2**63)
                root = validate_counted_node(head.index_root)
                work.prepare_copy(_head_values(head))
                definition = projection._definition(identity)
                work.prepare_encoding(definition.document(), ensure_ascii=False)
                work.charge(hashes=projection.PROFILE_HASH_WORK + 1)
                profile = projection.profile_for(identity)
                empty = empty_node(profile, "")
                _require((root.count == 0) == (root.digest == empty.digest)
                    and (head.index_revision != 0 or root.count == 0)
                    and root.count <= by_table[profile.table].leaf_count)
                copied.append(read_write.CompleteReadWriteHead(identity, head.index_revision, root))
            self._heads = tuple(copied)
            work.charge(input_bytes=16384, json_nodes=512)
            self._anchor_scalars = self._anchor_pins()
        self._anchors = self._business, self._authorization, self._heads, self._contracts, self._ids

    def _anchor_pins(self):
        return (tuple((id(root), _pins(root.table, root.root_revision, root.root_digest, root.leaf_count))
                for root in self._business),
            tuple((id(root), _pins(root.table, root.root_revision, root.root_digest, root.leaf_count))
                for root in self._authorization),
            tuple((id(head), id(head.index_root), _pins(*_head_values(head))) for head in self._heads),
            tuple((id(value), id(value.key_columns), _pins(value.table, *value.key_columns,
                value.write_access, value.root_class)) for value in self._contracts), self._ids)

    def _local(self):
        _require(type(self) is _JitIndexedPhases and not self._failed and not self._closed
            and self._process == (os.getpid(), threading.get_ident()))
        if self._phase:
            _require(all(current is original for current, original in zip(
                (self._business, self._authorization, self._heads, self._contracts, self._ids),
                self._anchors, strict=True)) and self._anchor_pins() == self._anchor_scalars)
        if self._prepared is not None:
            _require(_prepared_pins(self._prepared) == self._prepared_original)
        if self._pending is not None:
            _require(_pending_pins(self._pending) == self._pending_original)
        for record in self._meters:
            work, limits, scalar_limits, previous = record
            _require(type(work) is _ValidationWork and work.limits is limits and _limits(work) == scalar_limits)
            actual = _values(work)
            _require(all(now >= before for now, before in zip(actual, previous, strict=True)))
            record[3] = actual

    def _acquisition_idle(self):
        for record in self._acquisition_meters:
            work, limits, scalar_limits, previous = record
            _require(type(work) is _ValidationWork and work.limits is limits and _limits(work) == scalar_limits)
            actual = _values(work)
            _require(all(now >= before for now, before in zip(actual, previous, strict=True)))
            record[3] = actual

    @contextmanager
    def _stage(self, ordinal, work):
        try:
            self._local()
            self._acquisition_idle()
            _require(not self._busy and self._phase == ordinal and type(work) is _ValidationWork
                and all(work is not item[0] for item in (*self._meters, *self._acquisition_meters)))
            start = _values(work)
            self._meters.append([work, work.limits, _limits(work), start])
            self._busy = True
            yield
            self._local()
            self._acquisition_idle()
            end = _values(work)
            self._work_metrics.append(QueryReadValidationMetrics(*(
                after - before for after, before in zip(end, start, strict=True))))
            self._phase += 1
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def verify_primary(self, *, selected_row, before_proof, mutation, work):
        ordinal = len(self._verified)
        with self._stage(1 + ordinal, work):
            _require(ordinal < 3 and type(selected_row) is dict and type(before_proof) is dict
                and type(mutation) is dict and set(mutation) == indexed.primary._MUTATION_FIELDS)
            table, kind = PRIMARY_TABLES[ordinal], PRIMARY_KINDS[ordinal]
            _require(selected_row.get("table") == before_proof.get("table") == mutation["table"] == table
                and mutation["operation"] == kind and selected_row.get("contractSelector") is None)
            template = contract.mutation_template(OPERATION, mutation["templateId"])
            _require(template["table"] == table and template["mutation"] == kind
                and template["predicate"] == "exact-primary-key-and-full-row-cas-v1"
                and template["cardinality"] == 1)
            size, selected_nodes = work.measure(selected_row)
            self._selected_bytes += size
            _require(self._selected_bytes <= contract.MAX_REQUEST_BYTES)
            selected_size = size
            size, mutation_nodes = work.measure(mutation)
            self._mutation_bytes += size
            _require(self._mutation_bytes <= MAX_MUTATION_BYTES)
            root = next(item for item in self._business if item.table == table)
            source_contract = next(item for item in self._contracts if item.table == table)
            _primary_hidden_work(selected_row, before_proof, mutation,
                ((selected_size, selected_nodes), (size, mutation_nodes)), work)
            budget = _engine(work)
            verified = indexed._verify_primary(table_contracts=(source_contract,),
                business_before_roots=(root,), authorization_before_roots=(),
                selected_rows=(selected_row,), before_proofs=(before_proof,),
                mutations=(mutation,), budget=budget)
            _require(len(verified.selected_rows) == len(verified.before_proofs) == len(verified.mutations) == 1
                and len(verified.result.business_after_roots) == 1
                and not verified.result.authorization_after_roots
                and verified.result.metrics.selected_rows == verified.result.metrics.mutations == 1
                and verified.result.business_after_roots[0].table == table)
            self._verified.append(verified)
            self._engine_bytes += budget.input_bytes

    def prepare_primary(self, work):
        with self._stage(4, work):
            _require(len(self._verified) == 3)
            after = {value.result.business_after_roots[0].table: value.result.business_after_roots[0]
                     for value in self._verified}
            self._after_roots = tuple(after.get(root.table, root) for root in self._business)
            mutations = tuple(value.mutations[0] for value in self._verified)
            proofs = tuple(value.before_proofs[0] for value in self._verified)
            # The historical engine meters hash counts but not these actual
            # NEW-row serialization/hash-material bytes. Charge them before
            # calling its single genuine preparation; never per profile.
            for mutation in mutations:
                if projection.index_ids_for_table(mutation["table"]):
                    size, _ = work.prepare_encoding(mutation["row"], ensure_ascii=False)
                    work.charge(input_bytes=size + 256)
            work.charge(input_bytes=16384, json_nodes=512)
            budget = _engine(work)
            self._prepared = indexed._prepare_owned_primary_changes(mutations=mutations,
                before_proofs=proofs, business_after_roots=self._after_roots,
                index_ids=self._ids, budget=budget)
            _require(self._prepared.new_row_hashes == 2)
            self._prepared_original = _prepared_pins(self._prepared)
            self._engine_bytes += budget.input_bytes

    def prepare_index(self, work):
        ordinal = len(self._after_heads)
        with self._stage(5 + 2 * ordinal, work):
            _require(ordinal < 12 and self._prepared is not None and self._pending is None)
            head = self._heads[ordinal]
            item = indexed.IndexedMutationInput(head.index_id, head.index_revision, head.index_root, ())
            definition = projection._definition(head.index_id)
            work.prepare_encoding(definition.document(), ensure_ascii=False)
            # Only this profile's actual referenced scalar fields are copied
            # by projection. Full-row scans conservatively cover those walks.
            for mutation in self._prepared.by_table[definition.table]:
                for name in ("expectedRow", "row"):
                    if mutation[name] is not None:
                        work.prepare_scan(mutation[name])
            budget = _engine(work)
            profile, changes, delta, allowance = indexed._prepare_index_changes(item, self._prepared, budget)
            _require(len(changes) <= 2 and delta in (0, 1))
            self._pending = item, profile, changes, delta, allowance
            self._pending_original = _pending_pins(self._pending)
            self._context_hashes += projection.PROFILE_HASH_WORK
            self._projection_hashes += allowance
            self._engine_bytes += budget.input_bytes
            # Never expose the held engine objects across an acquisition call.
            work.charge(input_bytes=8192, json_nodes=128)
            detached = tuple(indexed.counted._change(change) for change in changes)
            result = _IndexObservation(head.index_id, head.index_revision,
                validate_counted_node(head.index_root), detached, tuple(change.key for change in detached))
        return result

    @contextmanager
    def _acquisition_binding(self, *, work):
        """Borrow sole-engine originals for one source-owned physical stage.

        This is not one of the thirty pure stages and grants no fold result.
        The actual reader owns its existing collector/reservation guard; it
        must restore the original limits before leaving. No rows are copied
        or given to a callback. The prepared graph is borrowed only by the
        private source reader, which consumes its bounded OLD ID metadata.
        """
        try:
            self._local()
            self._acquisition_idle()
            ordinal = len(self._after_heads)
            _require(not self._busy and self._phase == 6 + 2 * ordinal and ordinal < 12
                and self._pending is not None and self._prepared is not None
                and ordinal not in self._acquired and type(work) is _ValidationWork
                and all(work is not item[0] for item in (*self._meters, *self._acquisition_meters)))
            self._acquisition_meters.append([work, work.limits, _limits(work), _values(work)])
            work.charge(input_bytes=32768, json_nodes=1024)
            original = self._phase, self._pending, self._prepared
            self._busy = True
            self._acquired.add(ordinal)
            yield (*self._pending, self._prepared)
            _require(self._phase == original[0] and self._pending is original[1]
                and self._prepared is original[2])
            self._local()
            self._acquisition_idle()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def fold_index(self, index_input, *, work):
        ordinal = len(self._after_heads)
        with self._stage(6 + 2 * ordinal, work):
            _require(ordinal < 12 and self._pending is not None
                and type(index_input) is indexed.IndexedMutationInput)
            original, profile, changes, delta, _allowance = self._pending
            budget = _engine(work)
            captured, reservations = indexed._inputs_snapshot((index_input,), budget)
            item = captured[0]
            _require(_head_values(item) == _head_values(original))
            actual = indexed._evaluate_one_index(item, self._prepared, profile, changes,
                budget, reservations[item.index_id])
            _require(actual.before_root == original.index_root)
            self._before_heads.append(indexed.IndexedMutationHead(item.index_id,
                item.index_revision, actual.before_root))
            self._after_heads.append(indexed.IndexedMutationHead(item.index_id,
                item.index_revision + delta, actual.after_root))
            self._index_metrics.append((item.index_id, actual.metrics))
            self._engine_bytes += budget.input_bytes
            self._pending = None
            self._pending_original = None

    def finish(self, work):
        with self._stage(29, work):
            _require(len(self._verified) == 3 and len(self._after_heads) == 12 and self._pending is None
                and tuple(item.index_id for item in self._before_heads) == self._ids)
            work.charge(input_bytes=32768, json_nodes=1024)
            names = tuple(field.name for field in fields(indexed.primary.PrimaryRadixMetrics))
            metrics = indexed.primary.PrimaryRadixMetrics(**{name: sum(
                getattr(value.result.metrics, name) for value in self._verified) for name in names})
            primary = indexed.primary.PrimaryRadixBatchResult(self._after_roots, self._authorization, metrics)
            result = indexed.IndexedMutationResult(primary, tuple(self._before_heads), tuple(self._after_heads),
                indexed.IndexedMutationMetrics(metrics, tuple(self._index_metrics), self._context_hashes,
                    self._projection_hashes, self._prepared.new_row_hashes, self._engine_bytes))
        self._closed = True
        _require(len(self._work_metrics) == STAGE_COUNT)
        phases = tuple(self._work_metrics)
        total = QueryReadValidationMetrics(*(sum(getattr(value, name) for value in phases)
            for name in ("hash_work", "input_bytes", "json_nodes")))
        return JitIndexedObservation(result, phases, total)
