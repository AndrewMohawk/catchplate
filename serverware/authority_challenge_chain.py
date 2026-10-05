"""Private conditional-evidence production for one maintenance root chain.

The SQL planner holds the original read-only snapshot. Later phases therefore
cannot read their future roots from SQL. This owner replays the preceding raw
phase through the genuine primary/counted engines and retains only those
engines' computed nodes. It constructs conditional raw proofs, which the next
phase and the independent executor must verify again. No computed overlay,
after-root, mutation list or successful proof object is accepted as an input.

This is not the surrounding SQL transaction, signed parent, transport custody
or admission owner. In particular, a completed relative chain cannot authorize
commit. The actual caller must preserve one transaction and commit verified
maintenance before reporting its separately computed admission refusal.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib

from serverware import authority_challenge_compound as compound
from serverware import authority_challenge_candidates as candidates
from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_frontier_reader as frontier_reader
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_retention as retention
from serverware import authority_challenge_scope as scope
from serverware import authority_challenge_scope_stream as scope_stream
from serverware import authority_challenge_stream_phase as stream
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract as contract
from serverware import authority_index_count_reader as count_reader
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_index_mutation as counted_mutation
from serverware import authority_index_range as ranges
from serverware import authority_index_reader as reader
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
from serverware import authority_revocation_wire as wire
from serverware import authority_transition_core as core
from serverware.authority_index_contract import KEY_NIBBLES, IndexLeaf, KeyInterval, OpaqueSubtree
from serverware.authority_index_frontier import outside_prefixes
from serverware.authority_query_read_work import _ValidationWork


SCHEMA = "serverware.policyAuthorityChallengeMaintenanceChain/v1"
_PROOF_DOMAIN = "serverware.policyAuthorityRadixMultiproof/v3"
_PENDING_ROLES = ("expired_remaining", "old_remaining", "admission_terminal_count")
_TABLE = retention.CHALLENGE_TABLE


class ChallengeChainError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MaintenanceDecision:
    """Relative computation only, never a commit or admission capability."""

    replacement_overflow: bool
    pruning_pending: bool
    retained_limit: int
    primary_after: primary.PrimaryRoot
    counted_after: tuple[heads.CapturedIndexHead, ...]


@dataclass(slots=True)
class _WritePages:
    """Only a private phase's source-derived geometry and actual raw nodes."""

    index_id: str
    parents: tuple[str, ...]
    opened: frozenset[str]
    targets: frozenset[str]
    frontier: list
    ordinal: int = 0


@dataclass(frozen=True, slots=True)
class _ChainOverlay:
    primary_layers: tuple
    counted_nodes: dict
    counted_changes: dict


@dataclass(frozen=True, slots=True)
class _ScheduleState:
    """Bounded observations for the source scheduler, never authority."""

    phase_ordinal: int
    phase_name: str
    count_roles: tuple[str, ...]
    row_count: int | None
    rows_consumed: int
    reads_closed: bool
    index_position: int
    page_count: int | None
    pages_consumed: int
    candidate_page_count: int | None
    range_required: bool


class MaintenanceChain:
    """Source order and actual relative roots, with no external callbacks.

    Public observations are detached from private computed nodes. A failed
    phase permanently retires this owner; it cannot skip or resume a phase.
    Each work argument is the enclosing compound's exact source stage meter.
    This worker never constructs a replacement work allowance.
    """

    def __init__(self, *, request_digest, cutoff_us, retention_us,
                 maximum_retained, challenge_type, user_id, scope_key,
                 replace_scope, primary_root, index_heads, work):
        if type(work) is not _ValidationWork or type(replace_scope) is not bool:
            raise ChallengeChainError("maintenance chain lacks original work/request types")
        if type(index_heads) is not tuple:
            raise ChallengeChainError("maintenance chain head inventory is not exact")
        context = maintenance._owned({"requestDigest": request_digest,
            "cutoffUs": cutoff_us, "retentionUs": retention_us,
            "maximumRetained": maximum_retained, "challengeType": challenge_type,
            "userId": user_id, "scopeKey": scope_key, "replaceScope": replace_scope,
            "primary": primary_root,
            "heads": [maintenance.head_wire(head) for head in index_heads]}, work)
        core.require_digest(context["requestDigest"], "maintenance request")
        maintenance._integer(context["cutoffUs"])
        maintenance._integer(context["retentionUs"], 1)
        maintenance._integer(context["maximumRetained"], 1, 1_000_000)
        retention._text(context["challengeType"], "challenge type")
        retention._text(context["userId"], "challenge user")
        if context["scopeKey"] is not None:
            retention._text(context["scopeKey"], "challenge scope")
        work.charge(hashes=contract.TREE_DEPTH + 1)
        root = maintenance._root(context["primary"])
        identities = heads.required_index_ids(maintenance.OPERATION, include_write_heads=True)
        if tuple(item["indexId"] for item in context["heads"]) != identities:
            raise ChallengeChainError("maintenance chain omitted a source-fixed head")
        captured = []
        for item in context["heads"]:
            work.charge(hashes=projection.PROFILE_HASH_WORK)
            captured.append(maintenance._head(item,
                projection.profile_for(item["indexId"]), root, work))
        self._context, self._context_bytes = context, work.wire(context)
        self._original_root = self._root = root
        self._original_heads = self._heads = tuple(captured)
        # empty_digest(depth) independently constructs its cold suffix ladder.
        # Reserve the sum, not just 65 hashes or an assumed warm-cache hit.
        work.charge(hashes=(contract.TREE_DEPTH + 1) * (contract.TREE_DEPTH + 2) // 2)
        self._empty = tuple(radix.empty_digest(depth) for depth in range(contract.TREE_DEPTH + 1))
        self._position = 0
        self._busy = self._failed = self._closed = False
        self._replacement_slots = 0
        self._replacement_overflow = False
        self._overlays = []
        self._changed_rows = {}
        self._changed_ids = {}
        self._pending_primary = None
        self._rebased_primary = None
        self._primary_captured = False
        self._candidate_projection = None
        self._candidate_window = None
        self._candidate_ids = None
        self._stream_phase = None
        self._scope_stream = None
        self._phase_row_changes = {}
        self._phase_row_ids = {}
        self._prior_mutations = 0
        self._write_pages = None

    @contextmanager
    def _using(self, work):
        try:
            if (type(work) is not _ValidationWork or self._busy or self._closed
                    or self._failed or self._position >= len(compound.PHASES)):
                raise ChallengeChainError("maintenance chain is closed or reentered")
            current = work.wire(self._context)
            work.charge(input_bytes=len(current) + len(self._context_bytes))
            if current != self._context_bytes:
                raise ChallengeChainError("maintenance chain original context changed")
            self._busy = True
            yield
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def _retained_limit(self):
        return max(0, self._context["maximumRetained"] - 1
            - (self._replacement_slots if self._position > 3 else 0))

    def _phase_context(self):
        name = compound.PHASES[self._position]
        if name in ("scope", "admission"):
            raise ChallengeChainError("maintenance position is not a pruning phase")
        return {"requestDigest": self._context["requestDigest"],
            "cycle": int(name.startswith("post-")), "phase": name.split("-", 1)[1],
            "cutoffUs": self._context["cutoffUs"], "retentionUs": self._context["retentionUs"],
            "retainedLimit": self._retained_limit()}

    def phase_inputs(self, *, work):
        """Fresh public comparison inputs, never private node-map references."""
        with self._using(work):
            return maintenance._owned({"context": self._phase_context(),
                "primary": self._root.json_projection(),
                "heads": [maintenance.head_wire(head) for head in self._heads]}, work)

    def schedule_state(self):
        """Derive the physical inventory only from this actual chain's state.

        Candidate-window overfetch is bounded by the exact number of genuine
        earlier row mutations: each contributes at most one old and one new
        leaf. Final complete range/rank proofs, not this acquisition allowance,
        determine which candidates are admissible. No caller registers counts
        or asks for extra row/index/page stages.
        """
        if self._failed or self._busy:
            raise ChallengeChainError("maintenance schedule cannot observe a failed or active chain")
        position = self._position
        if position == len(compound.PHASES):
            return _ScheduleState(position, "complete", (), 0, 0, True, 0, 0, 0, 0, False)
        phase = compound.PHASES[position]
        roles, count, consumed, read_closed, index = (), None, 0, False, 0
        range_required = phase != "admission"
        if phase == "admission":
            roles, count = _PENDING_ROLES, 0
        elif phase == "scope":
            enabled = self._context["replaceScope"] and self._context["scopeKey"] is not None
            roles = (counts.SCOPE_ROLE,) if enabled else ()
            range_required = enabled
            if self._scope_stream is not None:
                scope_owner = self._scope_stream
                count, consumed = scope_owner.expected_rows, len(scope_owner._leaves)
                range_required = not scope_owner._disabled and not scope_owner._overflow
                read_closed = scope_owner._closed
        else:
            roles = (maintenance.phase_role(phase.split("-", 1)[1]),)
            if self._stream_phase is not None:
                owner = self._stream_phase
                count, consumed = owner.expected_rows, len(owner._keys)
                read_closed, index = owner._reads_closed, len(owner._after_heads)
                range_required = count != 0
        candidate_pages = (None if count is None else 0 if count == 0 else
            (count + 4 * self._prior_mutations + maintenance.BATCH_SIZE - 1) // maintenance.BATCH_SIZE)
        if candidate_pages is not None and candidate_pages > 25:
            raise ChallengeChainError("maintenance candidate window exceeded its six-phase source bound")
        pages = self._write_pages
        return _ScheduleState(position, phase, roles, count, consumed, read_closed, index,
            self._page_count(pages.parents) if pages is not None else 0 if count == 0 else None,
            pages.ordinal if pages is not None else 0, candidate_pages, range_required)

    def _next(self):
        if (self._pending_primary is not None or self._rebased_primary is not None
                or self._write_pages is not None):
            raise ChallengeChainError("maintenance phase left unreconstructed primary originals")
        self._position += 1
        self._primary_captured = False
        self._candidate_projection = None
        self._candidate_window = None
        self._candidate_ids = None
        self._phase_row_changes = {}
        self._phase_row_ids = {}

    def begin_phase(self, *, count_evidence, work):
        """Authenticate the original phase count before any row allowance."""
        with self._using(work):
            if self._stream_phase is not None or self._pending_primary is not None:
                raise ChallengeChainError("maintenance phase preparation is repeated or incomplete")
            self._stream_phase = stream._StreamingPhase(context=self._phase_context(),
                primary_root=self._root.json_projection(), index_heads=self._heads,
                count_evidence=count_evidence, work=work)
            self._candidate_projection = (self._stream_phase._profile,
                self._stream_phase._whole, ())
            self._open_candidates(self._stream_phase.expected_rows, work)
            return self._stream_phase._expected

    def _open_candidates(self, expected, work):
        if self._candidate_window is not None or self._candidate_ids is not None:
            raise ChallengeChainError("maintenance candidate window is repeated")
        if expected == 0:
            self._candidate_ids = ()
            return
        profile, interval, _leaves = self._candidate_projection
        original_head = next(head for head in self._original_heads if head.index_id == profile.index_id)
        # The immutable changes are actual outputs of completed folds. Charge
        # these bounded tuple snapshots before constructing them; no arbitrary
        # overlay or successful-proof DTO can enter this path.
        change_count = sum(len(layer.counted_changes[profile.index_id]) for layer in self._overlays)
        work.charge(input_bytes=1024 * change_count, json_nodes=16 * change_count + len(self._overlays) + 1)
        comparisons = sum(len(layer.counted_changes[profile.index_id])
            * max(1, len(layer.counted_changes[profile.index_id]).bit_length())
            for layer in self._overlays)
        work.charge(input_bytes=2 * KEY_NIBBLES * comparisons, json_nodes=comparisons)
        layers = tuple(tuple(layer.counted_changes[profile.index_id][key]
            for key in sorted(layer.counted_changes[profile.index_id])) for layer in self._overlays)
        work.prepare_copy(self._changed_ids)
        changed_ids = tuple(self._changed_ids.items())
        phase = compound.PHASES[self._position].split("-", 1)[-1]
        self._candidate_window = candidates._CandidateWindow(phase=phase, head=original_head,
            interval=interval, expected_rows=expected, retained_limit=self._retained_limit(),
            prior_mutations=self._prior_mutations, change_layers=layers,
            changed_ids=changed_ids, work=work)

    def candidate_input(self, *, ordinal, work):
        """The actual source window selects the physical SQL page, not callers."""
        with self._using(work):
            window = self._candidate_window
            if (window is None or type(ordinal) is not int
                    or ordinal != window.received_pages or ordinal >= window.page_count):
                raise ChallengeChainError("maintenance candidate page is not the exact next source window")
            profile, interval, _leaves = self._candidate_projection
            head = next(head for head in self._original_heads if head.index_id == profile.index_id)
            return head, interval, window.base_offset

    def accept_candidate_page(self, *, body_bytes, work):
        with self._using(work):
            window = self._candidate_window
            if window is None or self._candidate_ids is not None:
                raise ChallengeChainError("maintenance candidate originals are absent or repeated")
            window.consume(body_bytes=body_bytes, work=work)
            if window.received_pages == window.page_count:
                self._candidate_ids = window.finish(work=work)
                self._candidate_window = None

    def candidate_id(self, *, ordinal, work):
        with self._using(work):
            if (self._candidate_ids is None or type(ordinal) is not int
                    or not 0 <= ordinal < len(self._candidate_ids)):
                raise ChallengeChainError("maintenance primary read lacks its actual candidate window")
            owner = self._scope_stream if compound.PHASES[self._position] == "scope" else self._stream_phase
            consumed = len(owner._leaves) if owner is not None else -1
            if ordinal != consumed:
                raise ChallengeChainError("maintenance primary read skipped its actual candidate ordinal")
            work.prepare_copy(self._candidate_ids[ordinal])
            return self._candidate_ids[ordinal]

    def consume_row(self, *, work):
        """One raw row, actual primary mutation and fixed source projections."""
        with self._using(work):
            if (self._stream_phase is None or self._pending_primary is not None
                    or self._rebased_primary is None or not self._primary_captured):
                raise ChallengeChainError("maintenance row lacks its original proof capture")
            selected, proofs = self._rebased_primary
            self._rebased_primary = None
            mutation = self._stream_phase.consume(selected_row=selected[0],
                before_proof=proofs[0], work=work)
            # All maintenance UPDATEs change used_at only. Retain that actual
            # scalar delta, not up to256 copies of1MiB payloads. A later phase
            # reopens/proves the full original and applies this exact delta.
            self._phase_row_changes[mutation["keyDigest"]] = (
                None if mutation["row"] is None else mutation["row"]["used_at"])
            self._phase_row_ids[mutation["keyDigest"]] = mutation["key"]["id"]
            self._primary_captured = False
            return mutation

    def close_phase_reads(self, *, range_evidence, rank_evidence, work):
        with self._using(work):
            if (self._stream_phase is None or self._pending_primary is not None
                    or self._rebased_primary is not None
                    or self._primary_captured):
                raise ChallengeChainError("maintenance row acquisition has not closed")
            self._stream_phase.close_reads(range_evidence=range_evidence,
                rank_evidence=rank_evidence, work=work)

    def advance(self, *, index_id, work):
        """Fixed write-proof stage; never accept a supplied read result/map."""
        with self._using(work):
            prepared = self._stream_phase
            if prepared is None:
                raise ChallengeChainError("maintenance write replay lacks its own original read preparation")
            # No caller callback occurs between private preparation and this
            # check. The actual compound/transaction owner binds their lifetime.
            if (prepared._before != self._root or prepared._heads != self._heads
                    or prepared._context != self._phase_context()):
                raise ChallengeChainError("maintenance write replay changed its prior root or position")
            frontier = None
            if prepared._expected:
                pages = self._write_pages
                if (pages is None or pages.index_id != index_id
                        or pages.ordinal != self._page_count(pages.parents)):
                    raise ChallengeChainError("maintenance write frontier pages are incomplete")
                # Every opaque record is an untouched immediate sibling from
                # exact retained raw pages plus actual preceding engine nodes.
                # Every leaf is the genuine current primary OLD projection.
                # The unchanged index engine owns and verifies the whole root.
                frontier = tuple(sorted(pages.frontier,
                    key=lambda item: item.key if type(item) is IndexLeaf else item.prefix))
            prepared.fold_index(index_id=index_id, frontier=frontier, work=work)
            self._write_pages = None
            if len(prepared._after_heads) != len(prepared._identities):
                return None
            computed = prepared.finish(work=work)
            self._stream_phase = None
            if computed.row_count:
                if len(self._overlays) >= 6:
                    raise ChallengeChainError("maintenance exceeded its six source write phases")
                # The maps are private outputs of this invocation's real fold,
                # never maps provided by the plan or a caller. Preserve their
                # chronological separation: an empty ancestor in a later phase
                # must hide older descendants, even after later reinsertion.
                self._overlays.append(_ChainOverlay(computed.primary_layers,
                    computed.counted_nodes, computed.counted_changes))
                self._changed_rows.update(self._phase_row_changes)
                self._changed_ids.update(self._phase_row_ids)
                self._prior_mutations += computed.row_count
            self._root, self._heads = computed.primary_after, computed.after_heads
            self._next()
            return computed

    @staticmethod
    def _page_count(parents):
        return (len(parents) + frontier_reader.PARENTS_PER_PAGE - 1) // frontier_reader.PARENTS_PER_PAGE

    def begin_write_index(self, *, index_id, work):
        """Select the sole next profile's physical page geometry once.

        The SQL collector receives immutable targets, not authority to choose
        parents. It captures its own source geometry independently. The chain
        never accepts a caller's geometry object, frontier, or fold verdict.
        """
        with self._using(work):
            prepared = self._stream_phase
            if (prepared is None or self._write_pages is not None or not prepared._expected):
                raise ChallengeChainError("maintenance write-page geometry is not the next source index")
            changes = prepared._write_changes(index_id=index_id, work=work)
            keys = tuple(change.key for change in changes)
            # The same source helper charges every actual prefix allocation
            # and bounded sort before construction. This happens once, never
            # one full reconstruction/sort per physical page.
            work.prepare_scan(keys)
            parents = frontier_reader.frontier_parents(keys, work=work)
            self._write_pages = _WritePages(index_id, parents, frozenset(parents),
                frozenset(keys), [change.before for change in changes if change.before is not None])
            return {"indexId": index_id, "targetKeys": keys,
                "pageCount": self._page_count(parents),
                "head": next(head for head in self._original_heads if head.index_id == index_id)}

    def accept_write_page(self, *, body_bytes, work):
        """Rebase one exact original page; no page is a successful proof DTO.

        The enclosing compound binds and retains these original bytes. A new
        independent chain consumes the same bytes and replays every preceding
        mutation before this node construction. Only the final genuine root
        fold establishes whether the entire raw page set is valid evidence.
        """
        with self._using(work):
            pages = self._write_pages
            if pages is None or pages.ordinal >= self._page_count(pages.parents):
                raise ChallengeChainError("maintenance write page is absent or repeated")
            value = wire._decode_object(body_bytes, work=work,
                maximum_bytes=reader.MAX_TRANSPORT_BYTES)
            encoded = work.wire(value)
            work.charge(input_bytes=len(encoded) + len(body_bytes))
            if encoded != body_bytes:
                raise ChallengeChainError("maintenance write page is not the original canonical byte form")
            if type(value) is not dict or set(value) != {
                "schema", "indexId", "projectionDigest", "indexRevision", "rootDigest", "rootCount",
                "ordinal", "parentCount", "parents", "children",
            }:
                raise ChallengeChainError("maintenance write page is not source closed")
            head = next(head for head in self._original_heads if head.index_id == pages.index_id)
            expected = {"schema": frontier_reader.SCHEMA, "indexId": head.index_id,
                "projectionDigest": head.projection_digest, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "rootCount": head.index_root.count,
                "ordinal": pages.ordinal, "parentCount": len(pages.parents),
                "parents": list(pages.parents[pages.ordinal * frontier_reader.PARENTS_PER_PAGE:
                    (pages.ordinal + 1) * frontier_reader.PARENTS_PER_PAGE])}
            # Canonical bytes preserve exact scalar types (True is not1).
            if work.wire({name: value[name] for name in expected}) != work.wire(expected):
                raise ChallengeChainError("maintenance write page changed its original anchor or ordinal")
            records = value["children"]
            if type(records) is not list or len(records) > 16 * len(expected["parents"]):
                raise ChallengeChainError("maintenance write page exceeds its immediate-child bound")
            source, previous = {}, None
            parent_set = set(expected["parents"])
            for record in records:
                if type(record) is not dict or set(record) != {"prefix", "digest", "count"}:
                    raise ChallengeChainError("maintenance write child is not a raw counted node")
                node = OpaqueSubtree(record["prefix"], record["digest"], record["count"])
                if node.prefix[:-1] not in parent_set or previous is not None and node.prefix <= previous:
                    raise ChallengeChainError("maintenance write children are duplicated, reordered or unrequested")
                source[node.prefix] = node
                previous = node.prefix
            for parent in expected["parents"]:
                for digit in "0123456789abcdef":
                    prefix = parent + digit
                    if prefix in pages.opened or prefix in pages.targets:
                        continue
                    node = self._counted_node(pages.index_id, prefix, source.get(prefix))
                    if node is not None:
                        if len(pages.frontier) >= counted_mutation.MAX_FRONTIER_ENTRIES:
                            raise ChallengeChainError("maintenance write frontier exceeds its unchanged generic cap")
                        pages.frontier.append(OpaqueSubtree(prefix, node.digest, node.count))
            pages.ordinal += 1
            work.charge(hashes=1, input_bytes=len(body_bytes))
            return {"byteCount": len(body_bytes), "digest": "sha256:" + hashlib.sha256(body_bytes).hexdigest()}

    def begin_scope(self, *, count_evidence, work):
        with self._using(work):
            if compound.PHASES[self._position] != "scope" or self._scope_stream is not None:
                raise ChallengeChainError("scope observation is out of maintenance order")
            head = next(head for head in self._heads
                if head.index_id == "webauthn_challenge_scope_unused")
            context = self._context
            self._scope_stream = scope_stream._StreamingScope(challenge_type=context["challengeType"],
                user_id=context["userId"], scope_key=context["scopeKey"],
                replace_scope=context["replaceScope"], primary_root=self._root,
                index_head=head, count_evidence=count_evidence, work=work)
            if not self._scope_stream._disabled and not self._scope_stream._overflow:
                self._candidate_projection = (self._scope_stream._profile,
                    self._scope_stream._interval, ())
            self._open_candidates(self._scope_stream.expected_rows, work)
            return self._scope_stream.expected_rows

    def consume_scope_row(self, *, work):
        with self._using(work):
            if (compound.PHASES[self._position] != "scope" or self._scope_stream is None
                    or self._pending_primary is not None or self._rebased_primary is None
                    or not self._primary_captured):
                raise ChallengeChainError("scope row lacks its actual original proof capture")
            selected, proofs = self._rebased_primary
            self._rebased_primary = None
            self._scope_stream.consume(selected_row=selected[0], before_proof=proofs[0], work=work)
            self._primary_captured = False

    def finish_scope(self, *, range_evidence, work):
        with self._using(work):
            if (compound.PHASES[self._position] != "scope" or self._scope_stream is None
                    or self._pending_primary is not None or self._rebased_primary is not None
                    or self._primary_captured):
                raise ChallengeChainError("scope phase has not closed its original row inventory")
            observed = self._scope_stream.finish(range_evidence=range_evidence, work=work)
            self._replacement_slots = observed.terminal_slots
            self._replacement_overflow = observed.overflow
            self._scope_stream = None
            self._next()
            return observed

    def finish(self, *, pending_evidence, work):
        """Check exact pending predicates; actual caller owns commit/refusal."""
        with self._using(work):
            if compound.PHASES[self._position] != "admission":
                raise ChallengeChainError("maintenance admission is out of order")
            raw = maintenance._owned(pending_evidence, work)
            if type(raw) is not dict or set(raw) != set(_PENDING_ROLES):
                raise ChallengeChainError("maintenance pending evidence is not exact")
            observed = {}
            for role in _PENDING_ROLES:
                profile, interval = self._interval(role, work)
                head = next(head for head in self._heads if head.index_id == profile.index_id)
                observed[role] = counts._verify_interval_evidence(raw[role], role=role,
                    expected_head=head, profile=profile, interval=interval, work=work)
            retained_limit = self._retained_limit()
            pending = (observed["expired_remaining"] != 0 or observed["old_remaining"] != 0
                or observed["admission_terminal_count"] > retained_limit)
            self._next()
            self._closed = True
            return MaintenanceDecision(self._replacement_overflow, pending, retained_limit,
                self._root, self._heads)

    def capture_primary(self, *, selected_rows, before_proofs, work):
        """Acquisition stage: verify one actual base-snapshot original.

        The subsequent construction stage consumes these private engine-owned
        graphs, not a caller-provided successful-membership result. Its output
        still needs full current-root replay in ``advance``/``observe_scope``.
        """
        with self._using(work):
            if (self._primary_captured or self._pending_primary is not None
                    or self._rebased_primary is not None
                    or compound.PHASES[self._position] == "admission"):
                raise ChallengeChainError("maintenance primary capture is repeated or out of order")
            pruning = compound.PHASES[self._position] != "scope"
            if ((self._stream_phase is None if pruning else self._scope_stream is None)
                    or type(selected_rows) is not tuple
                    or len(selected_rows) != 1 or type(before_proofs) is not tuple or len(before_proofs) != 1):
                raise ChallengeChainError("maintenance captures exactly one raw source row per stage")
            ledger = batch._SharedLedger(work)
            actual = primary.evaluate_primary_radix_memberships(
                table_contracts=(primary.PrimaryTableContract(_TABLE, ("id",), False, "business"),),
                business_before_roots=(self._original_root,), authorization_before_roots=(),
                selected_rows=selected_rows, before_proofs=before_proofs,
                limits=batch._primary_limits(contract.operation_spec(maintenance.OPERATION), 1, ledger))
            metrics = actual.result.metrics
            work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes,
                json_nodes=metrics.json_nodes)
            if actual.result.business_after_roots != (self._original_root,):
                raise ChallengeChainError("maintenance base membership changed its original root")
            owner = self._stream_phase if pruning else self._scope_stream
            ordinal = len(owner._leaves)
            if self._candidate_ids is None or ordinal >= len(self._candidate_ids):
                raise ChallengeChainError("maintenance primary proof differs from its actual window selection")
            expected_key = {"id": self._candidate_ids[ordinal]}
            work.prepare_comparison(actual.selected_rows[0]["key"], expected_key)
            if actual.selected_rows[0]["key"] != expected_key:
                raise ChallengeChainError("maintenance primary proof differs from its actual window selection")
            self._pending_primary = (actual.selected_rows, actual.before_proofs)
            self._primary_captured = True

    def _primary_node(self, depth, prefix, original):
        identity = (_TABLE, depth, prefix)
        for overlay in reversed(self._overlays):
            for layer in reversed(overlay.primary_layers):
                if identity in layer:
                    return layer[identity]
                # Preserve the actual row/phase chronology: a newer empty
                # ancestor must hide older descendant hashes, not resurrect
                # an obsolete node through a flattened-dictionary lookup.
                for ancestor in range(depth):
                    key = (_TABLE, ancestor, prefix[:ancestor])
                    if key in layer and layer[key] == self._empty[ancestor]:
                        return self._empty[depth]
        return original

    def rebase_primary(self, *, work):
        """Construction stage: emit raw proofs for the computed prior root."""
        with self._using(work):
            if self._pending_primary is None:
                raise ChallengeChainError("maintenance has no original primary proofs to reconstruct")
            selected, proofs = self._pending_primary
            self._pending_primary = None
            by_key = {item["keyDigest"]: item for item in selected}
            for proof in proofs:
                item = by_key[proof["keyDigest"]]
                work.prepare_encoding(item["key"], ensure_ascii=False, shallow_copies=2)
                work.charge(hashes=1)
                path = radix.authenticated_key_digest(_TABLE, item["key"])[7:]
                if item["keyDigest"] in self._changed_rows:
                    used_at = self._changed_rows[item["keyDigest"]]
                    row = None
                    if used_at is not None:
                        row = maintenance._owned(item["row"], work)
                        if type(row) is not dict:
                            raise ChallengeChainError("maintenance scalar rebase lacks its proved original row")
                        row["used_at"] = used_at
                    item["row"], item["present"] = row, row is not None
                    proof["present"] = item["present"]
                    proof["rowDigest"] = (retention._reference_digest(_TABLE, row, work)
                        if row is not None else None)
                    # The genuine preceding engine computed this exact leaf;
                    # do not reproduce its hash implementation or accept a
                    # caller-proposed leaf digest.
                    proof["leafDigest"] = self._primary_node(contract.TREE_DEPTH,
                        path, proof["leafDigest"])
                proof["rootRevision"], proof["rootDigest"] = self._root.root_revision, self._root.root_digest
                for level in proof["siblings"]:
                    depth, prefix = level["depth"] + 1, level["pathPrefix"]
                    # Reuse the engine-owned vector; do not allocate another
                    # unmetered full 256x64x16 copy before encoding admission.
                    for nibble, original in enumerate(level["childDigests"]):
                        level["childDigests"][nibble] = self._primary_node(
                            depth, prefix + format(nibble, "x"), original)
                del proof["proofDigest"]
                encoded = work.wire(proof)
                work.charge(hashes=1, input_bytes=len(_PROOF_DOMAIN) + 9 + len(encoded))
                proof["proofDigest"] = core.framed_digest(_PROOF_DOMAIN, encoded)
            role = (counts.SCOPE_ROLE if compound.PHASES[self._position] == "scope"
                else maintenance.phase_role(self._phase_context()["phase"]))
            profile, interval = self._interval(role, work)
            by_proof = {item["keyDigest"]: item for item in proofs}
            leaves = [maintenance._project(profile, item, by_proof[item["keyDigest"]], work)
                for item in selected]
            if self._candidate_projection is not None:
                previous_profile, previous_interval, previous_leaves = self._candidate_projection
                if previous_profile != profile or previous_interval != interval:
                    raise ChallengeChainError("maintenance row pages changed the source candidate predicate")
                leaves.extend(previous_leaves)
            leaves.sort(key=lambda leaf: leaf.key)
            if len(leaves) > maintenance.BATCH_SIZE or len({leaf.key for leaf in leaves}) != len(leaves):
                raise ChallengeChainError("maintenance row pages exceed or repeat the original candidate inventory")
            self._candidate_projection = profile, interval, tuple(leaves)
            # Keep the actual rebased originals private until the next fixed
            # proof stage consumes them. Returning their mutable dictionaries
            # would let a callback substitute a different raw-page transcript.
            self._rebased_primary = (selected, proofs)

    def _interval(self, role, work):
        if type(role) is not str:
            raise ChallengeChainError("maintenance count role is not exact text")
        position = compound.PHASES[self._position]
        if position == "scope":
            if role != counts.SCOPE_ROLE or not self._context["replaceScope"]:
                raise ChallengeChainError("scope count role is not selected")
            return counts.scope_interval(challenge_type=self._context["challengeType"],
                user_id=self._context["userId"], scope_key=self._context["scopeKey"], work=work)
        allowed = (_PENDING_ROLES if position == "admission"
            else (maintenance.phase_role(self._phase_context()["phase"]),))
        if role not in allowed:
            raise ChallengeChainError("maintenance count role is out of phase")
        return counts.source_interval(role, user_id=self._context["userId"],
            cutoff_us=self._context["cutoffUs"], rate_window_us=1,
            retention_us=self._context["retentionUs"], work=work)

    def count_input(self, *, role, work):
        """Only this original source phase selects the SQL count interval."""
        with self._using(work):
            profile, interval = self._interval(role, work)
            head = next(head for head in self._original_heads if head.index_id == profile.index_id)
            return profile, head, interval

    def _range_coordinates(self):
        if self._candidate_projection is None:
            raise ChallengeChainError("maintenance range lacks actual candidate projections")
        profile, whole, leaves = self._candidate_projection
        position = compound.PHASES[self._position]
        if position == "scope":
            interval = whole
        elif not leaves:
            raise ChallengeChainError("empty pruning has no scheduled range acquisition")
        else:
            interval = KeyInterval(leaves[0].key if self._phase_context()["phase"] == "overflow"
                else whole.lower, maintenance._next_key(leaves[-1].key))
        if (interval.lower < whole.lower or whole.upper is not None
                and (interval.upper is None or interval.upper > whole.upper)):
            raise ChallengeChainError("maintenance candidates escaped the source range")
        return profile, whole, leaves, interval

    def range_input(self, *, work):
        """Derive the outside-node read only from the genuinely joined rows."""
        with self._using(work):
            profile, _whole, _leaves, interval = self._range_coordinates()
            head = next(head for head in self._original_heads if head.index_id == profile.index_id)
            return profile, head, interval

    def rank_input(self, *, work):
        """The overflow rank boundary is the actual selected final key."""
        with self._using(work):
            if self._phase_context()["phase"] != "overflow":
                raise ChallengeChainError("maintenance rank read is outside the overflow phase")
            profile, whole, leaves, _interval = self._range_coordinates()
            end = maintenance._next_key(leaves[-1].key)
            if end is None:
                raise ChallengeChainError("maintenance rank escaped its fixed source partition")
            head = next(head for head in self._original_heads if head.index_id == profile.index_id)
            return profile, head, KeyInterval(end, whole.upper)

    def _counted_node(self, index_id, prefix, original):
        for overlay in reversed(self._overlays):
            nodes = overlay.counted_nodes[index_id]
            if prefix in nodes:
                return nodes[prefix]
            for depth in range(len(prefix)):
                ancestor = prefix[:depth]
                if ancestor in nodes and nodes[ancestor] is None:
                    return None
        return original

    def rebase_count(self, *, role, original_evidence, work):
        """Reconstruct fixed count evidence, including previously empty slots.

        Iterating only SQL's positive nodes would lose newly populated prefixes.
        The whole deterministic interval cover is used, with genuine computed
        tombstones taking precedence over older snapshot nodes.
        """
        with self._using(work):
            profile, interval = self._interval(role, work)
            return self._rebase_count(role, original_evidence, profile, interval, work)

    def _rebase_count(self, role, original_evidence, profile, interval, work):
        original = next(head for head in self._original_heads if head.index_id == profile.index_id)
        current = next(head for head in self._heads if head.index_id == profile.index_id)
        raw = maintenance._owned(original_evidence, work)
        counts._verify_interval_evidence(raw, role=role, expected_head=original,
            profile=profile, interval=interval, work=work)
        source = {item["prefix"]: OpaqueSubtree(item["prefix"], item["digest"], item["count"])
            for item in raw["frontier"]}
        prefixes = count_reader.count_prefixes(interval)
        if not set(source) <= set(prefixes):
            raise ChallengeChainError("maintenance count did not use the actual fixed SQL cover")
        frontier = []
        for prefix in prefixes:
            node = self._counted_node(profile.index_id, prefix, source.get(prefix))
            if node is not None:
                frontier.append({"prefix": prefix, "digest": node.digest, "count": node.count})
        raw.update(indexRevision=current.index_revision, rootDigest=current.index_root.digest,
            rootCount=current.index_root.count, frontier=frontier)
        counts._verify_interval_evidence(raw, role=role, expected_head=current,
            profile=profile, interval=interval, work=work)
        return raw

    def rebase_rank(self, *, original_evidence, work):
        """The descending skip interval is derived from actual candidate keys."""
        with self._using(work):
            if (self._phase_context()["phase"] != "overflow"
                    or self._candidate_projection is None):
                raise ChallengeChainError("maintenance rank is not an actual overflow phase")
            profile, whole, leaves = self._candidate_projection
            if not leaves:
                raise ChallengeChainError("empty maintenance cannot carry an overflow rank")
            end = maintenance._next_key(leaves[-1].key)
            if end is None:
                raise ChallengeChainError("maintenance rank escaped its fixed source partition")
            return self._rebase_count("overflow_skip_count", original_evidence, profile,
                KeyInterval(end, whole.upper), work)

    def rebase_range(self, *, original_outside_nodes, work):
        """Complete current range from source-derived candidates and raw nodes.

        The SQL collector must read the fixed outside-prefix cover. Its nodes
        are not accepted as true merely because SQL returned them: after the
        preceding real overlays are applied, the entire frontier reconstructs
        the independently computed current head here and again in phase replay.
        """
        with self._using(work):
            profile, _whole, leaves, interval = self._range_coordinates()
            raw = maintenance._owned(original_outside_nodes, work)
            if type(raw) is not list or len(raw) > reader.MAX_OUTSIDE_PREFIXES:
                raise ChallengeChainError("maintenance outside range nodes exceed the source bound")
            prefixes = outside_prefixes(interval)
            allowed, source = set(prefixes), {}
            for item in raw:
                if type(item) is not dict or set(item) != {"prefix", "digest", "count"}:
                    raise ChallengeChainError("maintenance outside node is not a closed original")
                node = OpaqueSubtree(item["prefix"], item["digest"], item["count"])
                if node.prefix not in allowed or node.prefix in source:
                    raise ChallengeChainError("maintenance outside node is duplicated or unrequested")
                source[node.prefix] = node
            frontier = list(leaves)
            for prefix in prefixes:
                node = self._counted_node(profile.index_id, prefix, source.get(prefix))
                if node is not None:
                    frontier.append(OpaqueSubtree(prefix, node.digest, node.count))
            current = next(head for head in self._heads if head.index_id == profile.index_id)
            opened = 1 + KEY_NIBBLES * maintenance.BATCH_SIZE + 2 * KEY_NIBBLES
            observed = ranges._reconstruct_complete_index_range(profile=profile,
                expected_root=current.index_root, interval=interval, frontier=tuple(frontier),
                limits=ranges.IndexRangeLimits(max_entries=reader.MAX_OUTSIDE_PREFIXES + maintenance.BATCH_SIZE,
                    max_leaves=maintenance.BATCH_SIZE, max_opened_nodes=opened,
                    max_hashes=16 * opened + maintenance.BATCH_SIZE), work=work)
            work.prepare_comparison(
                [[leaf.key, leaf.primary_key_digest, leaf.primary_row_digest] for leaf in observed.leaves],
                [[leaf.key, leaf.primary_key_digest, leaf.primary_row_digest] for leaf in leaves])
            if observed.leaves != leaves:
                raise ChallengeChainError("maintenance range changed its genuine candidate set")
            return maintenance._owned({"schema": maintenance.RANGE_SCHEMA, "frontier": [
                {"kind": "leaf", "key": leaf.key, "primaryKeyDigest": leaf.primary_key_digest,
                 "primaryRowDigest": leaf.primary_row_digest} for leaf in leaves] + [
                {"kind": "opaque", "prefix": node.prefix, "digest": node.digest, "count": node.count}
                for node in frontier[len(leaves):]]}, work)

    def close(self):
        """Retire private conditional state; never close external resources."""
        self._closed = True
        self._pending_primary = None
        self._rebased_primary = None
        self._candidate_projection = None
        self._candidate_window = None
        self._candidate_ids = None
        if self._stream_phase is not None:
            self._stream_phase.close()
        self._stream_phase = None
        self._scope_stream = None
        self._phase_row_changes.clear()
        self._phase_row_ids.clear()
        self._write_pages = None
        self._overlays.clear()
        self._changed_rows.clear()
        self._changed_ids.clear()
