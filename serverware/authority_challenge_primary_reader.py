"""One real challenge row and metered radix originals on the held snapshot.

The source compound owner selects the candidate ID and retains the original
cursor, root, deadline and phase ledger. Missing rows/leaves are broken joins,
not absence evidence. Returned bytes contain raw originals, never authority or
a successful-proof DTO; the transition owner independently replays them.
"""
from __future__ import annotations

import json

from serverware import authority_challenge_id as ids
from serverware import authority_challenge_retention as retention
from serverware import authority_index_reader as reader
from serverware import authority_query_reads as reads
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware.authority_index_heads import CHALLENGE_OPERATIONS
from serverware.authority_query_read_work import _ValidationWork

SCHEMA = "serverware.policyAuthorityChallengePrimaryOriginal/v1"
PRIMARY_READ_PROFILE = "serverware.policyAuthorityChallengePrimaryRead/v1"
TABLE = "webauthn_challenges"
MAX_RAW_BYTES = 4 * 1024 * 1024
PHASE_INDEX = {
    "expire": "webauthn_challenge_unused_global",
    "old": "webauthn_challenge_terminal_unreferenced_global",
    "overflow": "webauthn_challenge_terminal_unreferenced_global",
    "scope": "webauthn_challenge_scope_unused",
}
_NULLABLE = frozenset({"scope_key", "approval_request_id", "used_at", *retention.DERIVED_FIELDS[:-1]})
_HEX = frozenset("0123456789abcdef")


def _require(condition, message):
    if not condition:
        raise reader.IndexReadError(message)


def _digest(value):
    return (type(value) is str and len(value) == 71 and value.startswith("sha256:")
            and all(character in _HEX for character in value[7:]))


def _row(cursor, *, phase, identity, trace, work, acquisition):
    key = {"id": identity}
    work.prepare_utf8(TABLE)
    work.prepare_encoding(key)
    work.charge(hashes=1, input_bytes=16)
    digest = core.framed_digest("serverware.policyAuthorityBusinessKey/v1",
        TABLE.encode("ascii"), core.canonical_bytes(key))
    marker = dict(profile=PRIMARY_READ_PROFILE, phase=phase, indexId=PHASE_INDEX[phase],
        primaryId=identity, primaryKeyDigest=digest, limit=2)
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read(TABLE, marker,
            "SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::pg_catalog.text) "
            f"<= {reader.MAX_PRIMARY_ROW_BYTES} THEN pg_catalog.to_jsonb(target) ELSE NULL END AS row_value "
            "FROM serverware_metadata.webauthn_challenges AS target WHERE target.id = %s LIMIT %s",
            (identity, 2), 1)
        _require(len(rows) == 1 and type(rows[0]) is dict and set(rows[0]) == {"row_value"},
                 "challenge candidate lacks one closed actual business row")
        row = rows[0]["row_value"]
        _require(type(row) is dict and set(row) == retention.ROW_FIELDS,
                 "challenge original is not the full source row")
        for name, value in row.items():
            _require((value is None and name in _NULLABLE)
                or (name == "retention_reference_mask" and type(value) is int and 0 <= value <= 7)
                or (name != "retention_reference_mask" and type(value) is str
                    and len(value) <= reader.MAX_PRIMARY_ROW_BYTES),
                "challenge original column is not its bounded source scalar")
        _require(row["id"] == identity, "challenge original changed its source candidate ID")
        retention._validate_inline(row)
        size, _ = work.prepare_encoding(row)
        _require(size <= reader.MAX_PRIMARY_ROW_BYTES, "challenge canonical original exceeds 1 MiB")
        encoded = core.canonical_bytes(row)
        _require(len(encoded) == size, "challenge original changed during encoding")
        acquisition.charge_primary_row(encoded)
        owned = reads._CopyBudget(work).copy(row)
        return dict(table=TABLE, key=key, keyDigest=digest, present=True,
                    row=owned, contractSelector=None)


def _tree_wire(value, work):
    work.prepare_encoding(value, ensure_ascii=False)
    return radix.tree_json_bytes(value)


def _tree_hash(domain, frames, work):
    work.charge(hashes=1, input_bytes=len(domain) + 8 + sum(8 + len(frame) for frame in frames))
    return radix._tree_digest(domain, *frames)


def _before_proof(cursor, *, selected, root, trace, work, acquisition):
    """The actual fixed radix SQL/hash recipe on the original physical ledger.

    No generic store helper or callback escapes accounting. Sixteen children
    per level use flattened exact parameters, fitting the unchanged ledger.
    Empty digests are computed in one genuine bottom-up ladder, not inferred.
    """
    key_bytes = _tree_wire(selected["key"], work)
    tree_key = _tree_hash("serverware.policyAuthorityAuthenticatedKey/v1", (TABLE.encode(), key_bytes), work)
    row_digest = _tree_hash("serverware.policyAuthorityAuthenticatedRow/v1",
                            (TABLE.encode(), _tree_wire(selected["row"], work)), work)
    leaf_digest = _tree_hash("serverware.policyAuthorityAuthenticatedLeaf/v1",
        (TABLE.encode(), tree_key.encode(), key_bytes, row_digest.encode()), work)
    path = tree_key[7:]
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read("policy_authority_authenticated_leaves", {"tableName": TABLE, "keyDigest": tree_key},
            "SELECT CASE WHEN pg_catalog.octet_length(key_json) BETWEEN 1 AND 32768 THEN key_json ELSE NULL END AS key_json, "
            "CASE WHEN pg_catalog.octet_length(row_digest) = 71 THEN row_digest ELSE NULL END AS row_digest, "
            "CASE WHEN pg_catalog.octet_length(leaf_digest) = 71 THEN leaf_digest ELSE NULL END AS leaf_digest, root_revision "
            "FROM serverware_metadata.policy_authority_authenticated_leaves "
            "WHERE table_name = %s AND key_digest = %s LIMIT %s", (TABLE, tree_key, 2), 1)
        _require(len(rows) == 1 and type(rows[0]) is dict
                 and set(rows[0]) == {"key_json", "row_digest", "leaf_digest", "root_revision"},
                 "challenge primary leaf is not one genuine closed original")
        stored = rows[0]
        _require(type(stored["key_json"]) is str and 0 < len(stored["key_json"]) <= 32768
            and _digest(stored["row_digest"]) and _digest(stored["leaf_digest"])
            and type(stored["root_revision"]) is int and 0 < stored["root_revision"] <= root.root_revision,
            "challenge primary leaf fields exceed their source bounds")
        work.prepare_encoding(stored)
        acquisition.charge_primary_row(core.canonical_bytes(stored))
        work.prepare_utf8(stored["key_json"])
        parsed = json.loads(stored["key_json"])
        work.prepare_comparison(parsed, selected["key"])
        _require(parsed == selected["key"] and stored["row_digest"] == row_digest
                 and stored["leaf_digest"] == leaf_digest, "challenge row differs from its stored authenticated leaf")
        empty = {64: _tree_hash("serverware.policyAuthorityAuthenticatedEmptyLeaf/v1", (b"64",), work)}
        for depth in range(63, -1, -1):
            empty[depth] = _tree_hash("serverware.policyAuthorityAuthenticatedNode/v1",
                (str(depth).encode(), _tree_wire([empty[depth + 1]] * 16, work)), work)
        siblings = []
        for depth in range(64):
            prefix = path[:depth]
            paths = tuple(prefix + format(n, "x") for n in range(16))
            placeholders = ", ".join("%s" for _ in paths)
            rows = acquisition.read("policy_authority_authenticated_tree_nodes",
                {"tableName": TABLE, "depth": depth + 1, "pathPrefix": prefix},
                "SELECT CASE WHEN pg_catalog.octet_length(path_prefix) BETWEEN 1 AND 64 THEN path_prefix ELSE NULL END AS path_prefix, "
                "CASE WHEN pg_catalog.octet_length(node_digest) = 71 THEN node_digest ELSE NULL END AS node_digest, root_revision "
                "FROM serverware_metadata.policy_authority_authenticated_tree_nodes "
                f"WHERE table_name = %s AND depth = %s AND path_prefix IN ({placeholders}) LIMIT %s",
                (TABLE, depth + 1, *paths, 17), 16)
            by_path = {}
            for raw in rows:
                row = reader._record(raw, ("path_prefix", "node_digest", "root_revision"), work)
                _require(type(row["path_prefix"]) is str and row["path_prefix"] in paths
                    and row["path_prefix"] not in by_path and _digest(row["node_digest"])
                    and type(row["root_revision"]) is int and 0 < row["root_revision"] <= root.root_revision,
                    "challenge primary node identity/revision changed")
                acquisition.charge("primary-node", row, ("path_prefix", "node_digest", "root_revision"))
                by_path[row["path_prefix"]] = row["node_digest"]
            siblings.append({"depth": depth, "pathPrefix": prefix, "selectedNibble": path[depth],
                             "childDigests": [by_path.get(p, empty[depth + 1]) for p in paths]})
        proof = {"schema": "serverware.policyAuthorityRadixMultiproof/v3", "table": TABLE,
            "key": selected["key"].copy(), "keyDigest": selected["keyDigest"], "present": True,
            "rowDigest": row_digest, "leafDigest": leaf_digest, "rootRevision": root.root_revision,
            "rootDigest": root.root_digest, "siblings": siblings}
        work.prepare_encoding(proof)
        work.charge(hashes=1)
        proof["proofDigest"] = core.framed_digest("serverware.policyAuthorityRadixMultiproof/v3", core.canonical_bytes(proof))
        return proof


def acquire_primary_original(cursor, *, phase, primary_id, primary_root: primary.PrimaryRoot,
                             trace, work, acquisition) -> bytes:
    """Capture exactly one present candidate with the original phase budgets."""
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise reader.IndexReadError("challenge primary capture requires its original work/acquisition pair")
    with acquisition.read_phase(cursor, trace, work):
        _require(type(phase) is str and phase in PHASE_INDEX
            and type(getattr(trace, "operation", None)) is str and trace.operation in CHALLENGE_OPERATIONS,
            "challenge primary capture has no source phase/operation")
        identity = ids.require_generated(primary_id)
        work.prepare_copy(identity)
        _require(type(primary_root) is primary.PrimaryRoot,
                 "challenge primary capture requires its genuine root descriptor type")
        values = reads._CopyBudget(work).copy((primary_root.table, primary_root.root_revision,
            primary_root.root_digest, primary_root.leaf_count))
        work.charge(hashes=66)
        root = primary.PrimaryRoot(*values)
        _require(root.table == TABLE, "challenge primary capture cannot select another table")
        selected = _row(cursor, phase=phase, identity=identity, trace=trace, work=work, acquisition=acquisition)
        proof = _before_proof(cursor, selected=selected, root=root, trace=trace, work=work, acquisition=acquisition)
        limits = primary.PrimaryRadixLimits(1, 1, 64, 1024,
            min(136, work.limits.max_hashes - work.hash_work),
            work.limits.max_input_bytes - work.input_bytes, 128,
            work.limits.max_json_nodes - work.json_nodes)
        observed = primary.evaluate_primary_radix_memberships(
            table_contracts=(primary.PrimaryTableContract(TABLE, ("id",), False, "business"),),
            business_before_roots=(root,), authorization_before_roots=(),
            selected_rows=(selected,), before_proofs=(proof,), limits=limits)
        metrics = observed.result.metrics
        work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
        _require(observed.result.business_after_roots == (root,)
            and not observed.result.authorization_after_roots,
            "challenge primary capture changed its original roots")
        raw = dict(schema=SCHEMA, selectedRows=list(observed.selected_rows),
                   beforeProofs=list(observed.before_proofs))
        size, _ = work.prepare_encoding(raw)
        _require(size <= MAX_RAW_BYTES, "challenge primary raw original exceeds 4 MiB")
        encoded = core.canonical_bytes(raw)
        _require(len(encoded) == size, "challenge primary original changed during encoding")
        return encoded
