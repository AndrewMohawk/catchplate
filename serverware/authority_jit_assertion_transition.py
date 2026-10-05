"""Private, fixed-stage JIT semantics on the compound owner's original work.

This is not proof/currentness admission or a compound allowance allocator. The
caller authenticates the eight originals and supplies nine distinct original
child meters under its one original clock and aggregate ledger. The separate
first-seven receipt owner uses only the first three supplied stages, returning
the real ES256 digest that selects the eighth lookup, then closes. No absent
receipt is invented; the full transition independently recomputes after that
lookup's genuine proof. No meter or clock is created here. A receipt or
mutation DTO is never an input: the actual ES256 receipt, three mutations and
inline reference commitment are recomputed.

Only the existing semantic bodies are used. Their public paths still execute
in the original order on the original single ledger. Splitting their actual
ownership/normalization walks here avoids spending all copies on one child.
Byte accounting is canonical work, not interpreter/cryptographic CPU or RSS.
Generic hash/node/depth refusal ceilings are unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import threading

from serverware import authority_challenge_retention as retention
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract as contract
from serverware import authority_jit_assertion_receipt as source
from serverware import authority_query_reads as reads
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import _ValidationWork


STAGES = ("capture", "actor-policy", "receipt", "base-mutations", "normalize-selected",
          "normalize-mutations", "validate-inventory", "expand-inline", "finish")
RECEIPT_STAGES = STAGES[:3]
MAX_SELECTED_BYTES = contract.MAX_REQUEST_BYTES  # No framework row in JIT.
MAX_ASSERTION_BYTES = 1024 * 1024
# An assertion is embedded as JSON *text* in the receipt, so quoting may double
# it. Remaining inherited challenge/credential scalars are charged within S.
MAX_RECEIPT_BYTES = MAX_SELECTED_BYTES + 2 * MAX_ASSERTION_BYTES + 65536
MAX_BASE_MUTATION_BYTES = 3 * MAX_SELECTED_BYTES + 2 * MAX_ASSERTION_BYTES + 131072
# Conservative canonical-byte envelopes for the fixed source request/query
# shapes (S <= 4 MiB selected, Q <= 4 MiB arguments, A <= 1 MiB assertion):
# capture <= 5Q + 7S + 4 MiB; actor <= 13S + 2 MiB;
# receipt <= 10S + 13A + 4 MiB; base <= 6S + 2R + M + 16 KiB;
# selected normalization = 4S; mutation normalization = 4M;
# inventory <= 6S + 2M; inline <= 4S + 3R + 16 KiB;
# result <= 2M + 68 KiB. R/M are bounded above before their later walks.
# These are not replacement limits or blanket acceptance promises: original
# per-child H/B/N limits, parser depth and previously spent work still refuse.


class JitAssertionTransitionError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitAssertionTransitionError("JIT staged transition custody or source order changed")


def _values(work):
    batch._SharedLedger(work)
    return work.hash_work, work.input_bytes, work.json_nodes


def _limit_values(work):
    return work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes


def _own(value, work):
    # Exact same actual canonical ownership as the retention inventory. Passing
    # a tuple directly avoids an unnecessary list(...) full-graph copy charge.
    return retention._copy(value, work)


def _legacy_json_work(raw, work):
    """Reserve hidden legacy parser walks; this scanner never admits JSON.

    Counting tokens without allocating a parsed graph lets the unchanged real
    parser remain responsible for grammar, canonical form and policy meaning.
    In particular, this accounting scanner does not impose a new number grammar.
    Six node walks/eight byte walks conservatively include the quota helpers'
    parse, dict copy, repeated encoding/decoding, comparison and digest input.
    """
    _require(type(raw) is str and raw.isascii())
    work.prepare_utf8(raw)
    work.charge(input_bytes=len(raw))
    position = nodes = depth = 0
    while position < len(raw):
        token = raw[position]
        if token in " \t\r\n,:}]":
            if token in "}]":
                depth -= 1
            position += 1
            continue
        nodes += 1
        if token in "[{":
            depth += 1
            _require(depth <= 128)
            position += 1
        elif token == '"':
            position += 1
            while position < len(raw):
                character = raw[position]
                position += 1
                if character == "\\":
                    position += 1
                elif character == '"':
                    break
        else:
            while position < len(raw) and raw[position] not in " \t\r\n,:]}{[":
                position += 1
        _require(6 * nodes <= work.limits.max_json_nodes - work.json_nodes)
    work.charge(input_bytes=8 * len(raw) + 256, json_nodes=6 * nodes + 256)


class _JitAssertionSemantics:
    """Shared first-three-stage bodies, selected only by two exact source types."""

    def __init__(self, context, *, assertion_policy, work):
        self._process = os.getpid(), threading.get_ident()
        self._phase = 0
        self._busy = self._failed = self._closed = False
        self._meters = []
        self._context = self._policy = self._inputs = self._receipt = self._mutations = None
        self._selected = self._entries = self._originals = None
        self._held = self._state()
        with self._stage(0, work):
            receipt_only = type(self) is _JitAssertionReceipt
            row_count = 7 if receipt_only else 8
            _require(type(context) is core.KernelContext and type(context.operation) is str
                and context.operation == source.OPERATION and type(context.request_digest) is str
                and type(context.arguments) is dict and type(context.selected_rows) is tuple
                and len(context.selected_rows) == row_count and type(context.query_reads) is tuple
                and len(context.query_reads) in ((7,) if receipt_only else (0, 8))
                and type(context.database_now) is datetime and context.database_now.tzinfo is not None
                and context.database_now.utcoffset() == timezone.utc.utcoffset(context.database_now)
                and context.verified_webauthn_evidence is None
                and context.rbac_primary_inputs is None
                and context.retirement_succession_primary_roots is None
                and context.canary_delivery_admission is None
                and context.genesis_root_digest is None and context.genesis_policy is None)
            core.require_digest(context.request_digest, "JIT request")
            # Each captured graph is bounded before ownership; these walks are
            # additional real work, never an uncharged stored byte-size claim.
            size, _ = work.measure(context.arguments)
            _require(size <= contract.MAX_REQUEST_BYTES)
            arguments = _own(context.arguments, work)
            source._arguments(arguments)
            size, _ = work.measure(context.selected_rows)
            _require(size <= MAX_SELECTED_BYTES)
            selected = _own(context.selected_rows, work)
            _require(all(type(item) is dict and set(item) == reads._SELECTED_FIELDS
                and item["contractSelector"] is None for item in selected))
            tables = tuple(item["table"] for item in selected)
            work.charge(input_bytes=131072, json_nodes=4096)
            queries = source.queries(arguments)
            expected = tuple(sorted((*[query.table for query in queries],
                *(() if receipt_only else (source.RECEIPT_TABLE,)))))
            _require(tables == expected and len(set(tables)) == row_count)
            # The actual query observations are retained, not turned into proof.
            records = tuple(reads._copy_read(item, work) for item in context.query_reads)
            work.prepare_copy(selected)
            selected = tuple(selected)
            if receipt_only:
                # The first stage cannot borrow a fabricated eighth absence or
                # omit bookkeeping. Replay all seven actual query/key/presence
                # joins; their independent primary proofs remain caller-owned.
                reads._validate_query_reads(source.OPERATION, queries=queries,
                    query_reads=records, selected_rows=selected, work=work)
            self._context = core.KernelContext(source.OPERATION, arguments, selected,
                context.database_now, context.request_digest, query_reads=records)
            size, _ = work.measure(assertion_policy)
            _require(size <= 16384)
            self._policy = _own(assertion_policy, work)
            _require(type(self._policy) is dict and set(self._policy)
                == {"rp_id", "origin", "maximum_assertion_age_seconds"})

    def _state(self):
        return (self._context, self._policy, self._inputs, self._receipt, self._mutations,
                self._selected, self._entries, self._originals)

    def _local(self):
        _require(type(self) in (_JitAssertionReceipt, _JitAssertionTransition)
            and not self._failed and not self._closed
            and self._process == (os.getpid(), threading.get_ident())
            and all(current is held for current, held in zip(self._state(), self._held, strict=True)))
        for record in self._meters:
            work, limits, maximums, prior = record
            _require(type(work) is _ValidationWork and work.limits is limits
                and _limit_values(work) == maximums)
            current = _values(work)
            _require(all(value >= before for value, before in zip(current, prior, strict=True)))
            record[3] = current

    @contextmanager
    def _stage(self, ordinal, work):
        try:
            self._local()
            maximum = len(RECEIPT_STAGES) if type(self) is _JitAssertionReceipt else len(STAGES)
            _require(type(ordinal) is int and 0 <= ordinal < maximum
                and not self._busy and self._phase == ordinal and type(work) is _ValidationWork
                and all(work is not record[0] for record in self._meters))
            values = _values(work)
            self._meters.append([work, work.limits, _limit_values(work), values])
            self._busy = True
            yield
            _require(not self._failed and self._process == (os.getpid(), threading.get_ident()))
            # Updates are produced by this one source stage, never a callback.
            self._held = self._state()
            self._local()
            self._phase += 1
            if type(self) is _JitAssertionReceipt and self._phase == len(RECEIPT_STAGES):
                # Closing here also covers direct calls to the shared receipt
                # body; an unbound transition method cannot reopen this owner.
                self._closed = True
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def actor_policy(self, work):
        with self._stage(1, work):
            context = self._context
            # receipt_from_context uses the legacy quota row copies and actor
            # parser without a work parameter. Reserve those hidden operations
            # before invoking that unchanged semantic body.
            for table in ("approval_requests", "webauthn_challenges", "webauthn_credentials",
                          "policy_high_water"):
                selected = next(item for item in context.selected_rows if item["table"] == table)
                if selected["present"]:
                    work.prepare_copy(selected["row"])
            approval = next(item["row"] for item in context.selected_rows
                            if item["table"] == "approval_requests")
            preview = None
            if type(approval) is dict and type(approval.get("approver_policy_json")) is str:
                raw = approval["approver_policy_json"]
                _require(len(raw) <= 65536)
                _legacy_json_work(raw, work)
                work.charge(hashes=1)
                # This extra bounded parse is covered above and selects only
                # hidden-work reservations. It is never the admitted policy:
                # receipt_from_context reparses and validates the actual original.
                preview = json.loads(raw)
            binding = next(item for item in context.selected_rows if item["table"] == "rbac_role_bindings")
            if (type(preview) is dict and type(preview.get("requiredRoles")) is list
                    and preview["requiredRoles"] and binding["present"]):
                work.prepare_copy(binding["row"])
                if type(binding["row"].get("roles_json")) is str:
                    _legacy_json_work(binding["row"]["roles_json"], work)
            if (type(preview) is dict and type(preview.get("credentialPolicy")) is dict
                    and preview["credentialPolicy"].get("requireAttestationTrusted") is True):
                head = next(item for item in context.selected_rows
                            if item["table"] == "webauthn_trust_publication_high_water")
                if head["present"]:
                    work.prepare_copy(head["row"])
            work.charge(input_bytes=131072, json_nodes=2048)
            self._inputs = source._receipt_inputs_from_context(context,
                assertion_policy=self._policy, work=work)

    def receipt(self, work):
        with self._stage(2, work):
            inputs = self._inputs
            # The original helper accounts semantic scans, encoding and hashes.
            # Reserve its additional shallow assertion copy and explicit ASCII
            # decode/encode copies here, on this genuine ES256 child only.
            work.prepare_copy(inputs["assertion"])
            assertion_size, _ = work.measure(inputs["assertion"])
            _require(assertion_size <= MAX_ASSERTION_BYTES)
            work.charge(input_bytes=3 * assertion_size + 262144, json_nodes=131072)
            # Charge the actual kwargs shallow copy conservatively by its
            # complete JSON value graphs. The held exact UTC datetime is the
            # sole non-JSON scalar and is neither copied nor serialized here.
            sizes = {}
            for name, value in inputs.items():
                if name != "verified_at":
                    size, nodes = work.measure(value)
                    work.charge(input_bytes=size, json_nodes=nodes)
                    sizes[name] = size
            # Explicit ASCII decode/encode pairs for the expected challenge
            # payload and credential binding are bounded by these full rows;
            # source-fixed field-name/policy overhead is covered above.
            work.charge(input_bytes=2 * (sizes["challenge"] + sizes["credential"]))
            work.charge(input_bytes=8192, json_nodes=64)
            self._receipt = source.derive_receipt(**inputs, work=work)
            size, _ = work.measure(self._receipt)
            _require(size <= MAX_RECEIPT_BYTES)
            digest = self._receipt["assertion_receipt_digest"]
        return digest


class _JitAssertionReceipt(_JitAssertionSemantics):
    """Seven originals, three real stages, one digest; no mutation API."""


class _JitAssertionTransition(_JitAssertionSemantics):
    """Eight originals and all nine stages; recomputes the actual receipt."""

    def base_mutations(self, work):
        with self._stage(3, work):
            context, row = self._context, self._receipt
            challenge = context.exact(retention.CHALLENGE_TABLE, {"id": row["challenge_id"]})
            credential = context.exact("webauthn_credentials", {"id": row["credential_record_id"]})
            absent = context.exact(source.RECEIPT_TABLE,
                {"assertion_receipt_digest": row["assertion_receipt_digest"]})
            for selected in (challenge, credential):
                # Actual row update construction, then core.mutation's OLD and
                # NEW dict copies. No successful mutation is supplied here.
                for _ in range(3):
                    work.prepare_copy(selected["row"])
                work.prepare_copy(selected["key"])
            work.prepare_copy(row)
            work.prepare_copy(absent["key"])
            work.charge(input_bytes=8192, json_nodes=256)
            self._mutations = source._base_mutations(context, row)
            size, _ = work.measure(self._mutations)
            _require(len(self._mutations) == 3 and size <= MAX_BASE_MUTATION_BYTES)

    def normalize_selected(self, work):
        with self._stage(4, work):
            self._selected = _own(self._context.selected_rows, work)

    def normalize_mutations(self, work):
        with self._stage(5, work):
            self._entries = _own(self._mutations, work)

    def validate_inventory(self, work):
        with self._stage(6, work):
            # The unchanged loop scans wrappers and compares the real OLD
            # challenge row. Credential mutations are explicitly outside the
            # retention family; their semantics came from _base_mutations.
            work.prepare_scan(self._selected)
            work.prepare_scan(self._entries)
            for entry in self._entries:
                if entry["table"] in (retention.CHALLENGE_TABLE, *retention.REFERENCE_TABLES):
                    original = next(item for item in self._selected
                        if item["table"] == entry["table"])
                    work.prepare_comparison(entry["expectedRow"], original["row"])
            self._originals, actual = retention._validate_inventory(source.OPERATION,
                self._selected, self._entries)
            _require(actual is self._entries)

    def expand_inline(self, work):
        with self._stage(7, work):
            # The actual loop copies the OLD challenge and composes its NEW
            # full row. Its genuine reference hashing charges its own work.
            entry = next(item for item in self._entries if item["table"] == retention.CHALLENGE_TABLE)
            work.prepare_copy(entry["expectedRow"])
            work.prepare_copy(entry["row"])
            work.charge(input_bytes=16384, json_nodes=512)
            self._mutations = retention._expand_inventory(source.OPERATION,
                self._originals, self._entries, work=work)
            _require(type(self._mutations) is tuple and len(self._mutations) == 3)

    def finish(self, work):
        with self._stage(8, work):
            # The original result helper retains its original mutation-copy
            # debit. Reserve the additional small result construction/encoding.
            work.charge(input_bytes=65536, json_nodes=256)
            result = source._transition_result(self._receipt, self._mutations, work=work)
        self._closed = True
        return result
