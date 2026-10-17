"""Held-cursor, metered raw evidence for source-owned recovery history phases.

One compound owner admits the original root/head/user/count and orders phases.
These functions create no connection, clock, transaction, allowance or authority.
Each existing phase ledger is consumed once; the owner separately accounts the
whole chain. SQL candidates never replace complete range or primary proofs.
"""
from __future__ import annotations

import json
from typing import Any

from catchplate import authority_index_count_reader as counter
from catchplate import authority_index_projection as projection
from catchplate import authority_index_range as ranges
from catchplate import authority_index_reader as reader
from catchplate import authority_query_reads as reads
from catchplate import authority_radix_mutation as primary
from catchplate import authority_radix_proof as radix
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexLeaf, KeyInterval, OpaqueSubtree,
)
from catchplate.authority_index_heads import CapturedIndexHead
from catchplate.authority_query_read_work import _ValidationWork


COUNT_SCHEMA = "catchplate.policyAuthorityRecoveryHistoryCount/v1"
PAGE_SCHEMA = "catchplate.policyAuthorityRecoveryHistoryPage/v1"
CANDIDATE_READ_PROFILE = "catchplate.policyAuthorityRecoveryHistoryCandidateRead/v1"
PRIMARY_READ_PROFILE = "catchplate.policyAuthorityRecoveryHistoryPrimaryRead/v1"
OPERATIONS = tuple("webauthn.recovery." + phase for phase in ("create", "candidate", "finalize"))
INDEX_ID = "webauthn_credential_user_history"
TABLE = "webauthn_credentials"
PAGE_ROWS = 1
MAX_HISTORY_ROWS = 10000
MAX_RAW_BYTES = 4 * 1024 * 1024
_HEX = frozenset("0123456789abcdef")
_INTEGER_COLUMNS = frozenset({"sign_count", "attestation_trusted", "attestation_trust_bundle_sequence"})
_NULLABLE_COLUMNS = frozenset({
    "aaguid", "attestation_fmt", "attestation_leaf_sha256", "attestation_root_sha256",
    "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence", "attestation_verified_at",
    "dev_private_key_pem", "last_used_at", "revoked_at", "revoked_by", "revocation_reason", "revocation_source",
})
_ROW_COLUMNS = frozenset({
    "id", "credential_id", "user_id", "label", "public_key_cose", "sign_count", "aaguid",
    "authenticator_class", "attestation_fmt", "attestation_trusted", "attestation_trust_path",
    "attestation_leaf_sha256", "attestation_root_sha256", "attestation_trust_bundle_digest",
    "attestation_trust_bundle_sequence", "attestation_verified_at", "transports", "dev_private_key_pem",
    "created_at", "updated_at", "last_used_at", "revoked_at", "revoked_by", "revocation_reason", "revocation_source",
})


def _require(value: bool, message: str) -> None:
    if not value:
        raise reader.IndexReadError(message)


def _key(value: Any) -> bool:
    return type(value) is str and len(value) == KEY_NIBBLES and all(c in _HEX for c in value)


def _digest(value: Any) -> bool:
    return type(value) is str and len(value) == 71 and value.startswith("sha256:") and all(c in _HEX for c in value[7:])


def _context(operation, user_id, head, trace, work):
    _require(type(operation) is str and operation in OPERATIONS
             and type(getattr(trace, "operation", None)) is str and trace.operation == operation,
             "history operation is not the original source phase")
    _require(type(head) is CapturedIndexHead and type(head.index_root) is CountedNode,
             "history counted head type changed")
    values = reads._CopyBudget(work).copy((head.index_id, head.table, head.counted_profile,
        head.projection_digest, head.projection_manifest_digest, head.index_revision,
        head.index_root.digest, head.index_root.count))
    owned = CapturedIndexHead(*values[:6], CountedNode(*values[6:]))
    user_id = reader._text(user_id, projection.MAX_TEXT_BYTES, work=work)
    reader._profile_work(INDEX_ID, work)
    profile = projection.profile_for(INDEX_ID)
    selector = {"user_id": user_id}
    reader._interval_work(profile, profile, selector, work)
    whole = projection.query_interval(INDEX_ID, selector)
    work.prepare_encoding([projection._definition(name).document() for name in projection.INDEX_IDS])
    work.charge(hashes=1)
    _require(owned.index_id == INDEX_ID and owned.table == TABLE
        and owned.counted_profile == projection.COUNTED_PROFILE
        and owned.projection_digest == profile.projection_digest
        and owned.projection_manifest_digest == projection.projection_manifest_digest()
        and type(owned.index_revision) is int and 0 <= owned.index_revision <= I64_MAX
        and not (owned.index_revision == 0 and owned.index_root.count != 0),
        "history head differs from its source profile")
    return profile, whole, owned, user_id


def _frontier_wire(frontier):
    result = []
    for item in frontier:
        if type(item) is OpaqueSubtree:
            result.append({"kind": "opaque", "prefix": item.prefix, "digest": item.digest, "count": item.count})
        elif type(item) is IndexLeaf:
            result.append({"kind": "leaf", "key": item.key, "primaryKeyDigest": item.primary_key_digest,
                           "primaryRowDigest": item.primary_row_digest})
        else:
            raise reader.IndexReadError("history frontier contains an unknown record")
    return result


def _finish(raw, work) -> bytes:
    size, _ = work.prepare_encoding(raw)
    _require(size <= MAX_RAW_BYTES, "history raw phase exceeds its unchanged 4 MiB bound")
    encoded = core.canonical_bytes(raw)
    _require(len(encoded) == size, "history raw phase changed during encoding")
    return encoded


def _phase_pair(work, acquisition):
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise reader.IndexReadError("history requires the original phase work/acquisition pair")


def acquire_history_count(cursor: Any, *, operation: str, user_id: str, head: CapturedIndexHead,
                          trace: Any, work: _ValidationWork,
                          acquisition: reader._ReadAcquisitionBudget) -> bytes:
    """Return exact canonical count bytes; no SQL COUNT or caller limit."""
    _phase_pair(work, acquisition)
    with acquisition.read_phase(cursor, trace, work):
        profile, whole, owned, _ = _context(operation, user_id, head, trace, work)
        observed = counter.acquire_count_frontier(cursor, profile=profile,
            index_revision=owned.index_revision, expected_root=owned.index_root,
            interval=whole, trace=trace, work=work, acquisition=acquisition)
        return _finish({"schema": COUNT_SCHEMA, "frontier": _frontier_wire(observed.frontier)}, work)


def _candidate(cursor, *, ordinal, lower, whole, profile, head, trace, work, acquisition):
    upper_sql = "" if whole.upper is None else ' AND leaf.index_key COLLATE "C" < %s'
    parameters = (INDEX_ID, lower) if whole.upper is None else (INDEX_ID, lower, whole.upper)
    marker = {"profile": CANDIDATE_READ_PROFILE, "ordinal": ordinal, "indexId": INDEX_ID,
        "projectionDigest": profile.projection_digest, "indexRevision": head.index_revision,
        "rootDigest": head.index_root.digest, "rootCount": head.index_root.count,
        "lower": lower, "upper": whole.upper, "limit": PAGE_ROWS}
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read(reader.LEAF_TABLE, marker,
            f'SELECT {reader._LEAF_SELECT} FROM "catchplate_metadata"."{reader.LEAF_TABLE}" AS leaf '
            'WHERE leaf.index_id COLLATE "C" = %s AND leaf.index_key COLLATE "C" >= %s'
            f'{upper_sql} ORDER BY leaf.index_key COLLATE "C" ASC LIMIT %s', (*parameters, PAGE_ROWS), PAGE_ROWS)
        _require(len(rows) == 1, "history page lacks its one actual candidate")
        row = reader._record(rows[0], reader._LEAF_FIELDS, work)
        reader._context(row, INDEX_ID, profile.projection_digest, head.index_revision, work)
        leaf = IndexLeaf(row["index_key"], row["primary_key_digest"], row["primary_row_digest"])
        identity = reader._text(row["primary_id"], projection.MAX_TEXT_BYTES, minimum=0, work=work)
        _require(leaf.key >= lower and (whole.upper is None or leaf.key < whole.upper),
                 "history candidate is outside the original source interval")
        acquisition.charge("leaf", row, reader._LEAF_FIELDS)
        work.prepare_utf8(TABLE)
        work.prepare_encoding({"id": identity})
        work.charge(hashes=1, input_bytes=16)
        digest = core.framed_digest("catchplate.policyAuthorityBusinessKey/v1", TABLE.encode(),
                                   core.canonical_bytes({"id": identity}))
        _require(digest == leaf.primary_key_digest and leaf.key[-64:] == digest[7:],
                 "history candidate lost its exact BusinessKey join")
        return leaf, identity


def _primary_row(cursor, *, ordinal, identity, leaf, user_id, trace, work, acquisition):
    marker = {"profile": PRIMARY_READ_PROFILE, "ordinal": ordinal, "indexId": INDEX_ID,
              "primaryId": identity, "primaryKeyDigest": leaf.primary_key_digest, "limit": 2}
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read(TABLE, marker,
            "SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::pg_catalog.text) "
            f"<= {reader.MAX_PRIMARY_ROW_BYTES} THEN pg_catalog.to_jsonb(target) ELSE NULL END AS row_value "
            "FROM catchplate_metadata.webauthn_credentials AS target WHERE target.id = %s LIMIT %s",
            (identity, 2), 1)
        _require(len(rows) == 1 and type(rows[0]) is dict and set(rows[0]) == {"row_value"},
                 "history primary response is not one closed source row")
        row = rows[0]["row_value"]
        _require(type(row) is dict and set(row) == _ROW_COLUMNS, "history requires the full scalar source credential row")
        for name, value in row.items():
            _require((value is None and name in _NULLABLE_COLUMNS)
                or (type(value) is int and name in _INTEGER_COLUMNS and -(2**63) <= value <= I64_MAX)
                or (type(value) is str and name not in _INTEGER_COLUMNS and len(value) <= reader.MAX_PRIMARY_ROW_BYTES),
                "history credential column differs from its exact source scalar type")
        _require(row["id"] == identity and row["user_id"] == user_id, "history primary row changed its original user/key")
        size, _ = work.prepare_encoding(row)
        _require(size <= reader.MAX_PRIMARY_ROW_BYTES, "history canonical ASCII row exceeds 1 MiB")
        wire = core.canonical_bytes(row)
        _require(len(wire) == size, "history primary row changed during encoding")
        acquisition.charge_primary_row(wire)
        row = reads._CopyBudget(work).copy(row)
        return {"table": TABLE, "key": {"id": identity}, "keyDigest": leaf.primary_key_digest,
                "present": True, "row": row, "contractSelector": None}


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
    tree_key = _tree_hash("catchplate.policyAuthorityAuthenticatedKey/v1", (TABLE.encode(), key_bytes), work)
    row_digest = _tree_hash("catchplate.policyAuthorityAuthenticatedRow/v1",
                            (TABLE.encode(), _tree_wire(selected["row"], work)), work)
    leaf_digest = _tree_hash("catchplate.policyAuthorityAuthenticatedLeaf/v1",
        (TABLE.encode(), tree_key.encode(), key_bytes, row_digest.encode()), work)
    path = tree_key[7:]
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read("policy_authority_authenticated_leaves", {"tableName": TABLE, "keyDigest": tree_key},
            "SELECT CASE WHEN pg_catalog.octet_length(key_json) BETWEEN 1 AND 32768 THEN key_json ELSE NULL END AS key_json, "
            "CASE WHEN pg_catalog.octet_length(row_digest) = 71 THEN row_digest ELSE NULL END AS row_digest, "
            "CASE WHEN pg_catalog.octet_length(leaf_digest) = 71 THEN leaf_digest ELSE NULL END AS leaf_digest, root_revision "
            "FROM catchplate_metadata.policy_authority_authenticated_leaves "
            "WHERE table_name = %s AND key_digest = %s LIMIT %s", (TABLE, tree_key, 2), 1)
        _require(len(rows) == 1 and type(rows[0]) is dict
                 and set(rows[0]) == {"key_json", "row_digest", "leaf_digest", "root_revision"},
                 "history primary leaf is not one genuine closed original")
        stored = rows[0]
        _require(type(stored["key_json"]) is str and 0 < len(stored["key_json"]) <= 32768
            and _digest(stored["row_digest"]) and _digest(stored["leaf_digest"])
            and type(stored["root_revision"]) is int and 0 < stored["root_revision"] <= root.root_revision,
            "history primary leaf fields exceed their source bounds")
        work.prepare_encoding(stored)
        acquisition.charge_primary_row(core.canonical_bytes(stored))
        work.prepare_utf8(stored["key_json"])
        parsed = json.loads(stored["key_json"])
        work.prepare_comparison(parsed, selected["key"])
        _require(parsed == selected["key"] and stored["row_digest"] == row_digest
                 and stored["leaf_digest"] == leaf_digest, "history row differs from its stored authenticated leaf")
        empty = {64: _tree_hash("catchplate.policyAuthorityAuthenticatedEmptyLeaf/v1", (b"64",), work)}
        for depth in range(63, -1, -1):
            empty[depth] = _tree_hash("catchplate.policyAuthorityAuthenticatedNode/v1",
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
                "FROM catchplate_metadata.policy_authority_authenticated_tree_nodes "
                f"WHERE table_name = %s AND depth = %s AND path_prefix IN ({placeholders}) LIMIT %s",
                (TABLE, depth + 1, *paths, 17), 16)
            by_path = {}
            for raw in rows:
                row = reader._record(raw, ("path_prefix", "node_digest", "root_revision"), work)
                _require(type(row["path_prefix"]) is str and row["path_prefix"] in paths
                    and row["path_prefix"] not in by_path and _digest(row["node_digest"])
                    and type(row["root_revision"]) is int and 0 < row["root_revision"] <= root.root_revision,
                    "history primary node identity/revision changed")
                acquisition.charge("primary-node", row, ("path_prefix", "node_digest", "root_revision"))
                by_path[row["path_prefix"]] = row["node_digest"]
            siblings.append({"depth": depth, "pathPrefix": prefix, "selectedNibble": path[depth],
                             "childDigests": [by_path.get(p, empty[depth + 1]) for p in paths]})
        proof = {"schema": "catchplate.policyAuthorityRadixMultiproof/v3", "table": TABLE,
            "key": selected["key"].copy(), "keyDigest": selected["keyDigest"], "present": True,
            "rowDigest": row_digest, "leafDigest": leaf_digest, "rootRevision": root.root_revision,
            "rootDigest": root.root_digest, "siblings": siblings}
        work.prepare_encoding(proof)
        work.charge(hashes=1)
        proof["proofDigest"] = core.framed_digest("catchplate.policyAuthorityRadixMultiproof/v3", core.canonical_bytes(proof))
        return proof


def acquire_history_page(cursor: Any, *, operation: str, user_id: str, head: CapturedIndexHead,
                         primary_root: primary.PrimaryRoot, ordinal: int, authenticated_count: int,
                         lower: str, trace: Any, work: _ValidationWork,
                         acquisition: reader._ReadAcquisitionBudget) -> bytes:
    """Return one exact canonical page; parent owns count/lower/phase admission.

    Neither a supplied count nor a prior returned object is an authority. The
    compound verifier independently checks the count, ordinal, interval chain,
    original roots, full proofs and exact final remainder before any effect.
    """
    _phase_pair(work, acquisition)
    with acquisition.read_phase(cursor, trace, work):
        profile, whole, owned, user_id = _context(operation, user_id, head, trace, work)
        _require(type(ordinal) is int and type(authenticated_count) is int
                 and 1 <= authenticated_count <= MAX_HISTORY_ROWS and 0 <= ordinal < authenticated_count,
                 "history page ordinal/count is outside the fixed source family")
        _require(_key(lower) and lower >= whole.lower and (whole.upper is None or lower < whole.upper)
                 and (ordinal != 0 or lower == whole.lower), "history page lower is outside its source interval")
        _require(type(primary_root) is primary.PrimaryRoot, "history primary root type changed")
        root_values = reads._CopyBudget(work).copy((primary_root.table, primary_root.root_revision,
                                                   primary_root.root_digest, primary_root.leaf_count))
        work.charge(hashes=66)
        root = primary.PrimaryRoot(*root_values)
        _require(root.table == TABLE and root.leaf_count >= owned.index_root.count,
                 "history counted population exceeds its original primary descriptor")
        leaf, identity = _candidate(cursor, ordinal=ordinal, lower=lower, whole=whole, profile=profile,
            head=owned, trace=trace, work=work, acquisition=acquisition)
        following = int(leaf.key, 16) + 1
        next_key = None if following == 1 << (4 * KEY_NIBBLES) else format(following, "0160x")
        upper = whole.upper if ordinal == authenticated_count - 1 else next_key
        _require(upper is None or upper > leaf.key, "history page interval cannot progress")
        interval = KeyInterval(lower, upper)
        observed = counter.acquire_count_frontier(cursor, profile=profile, index_revision=owned.index_revision,
            expected_root=owned.index_root, interval=interval, trace=trace, work=work, acquisition=acquisition)
        _require(observed.count == 1, "history page skips or adds authenticated members")
        outside = set(reader.outside_prefixes(interval))
        frontier = tuple(sorted((leaf, *(entry for entry in observed.frontier if entry.prefix in outside)),
            key=lambda item: item.key if type(item) is IndexLeaf else item.prefix))
        ranges._reconstruct_complete_index_range(profile=profile, expected_root=owned.index_root,
            interval=interval, frontier=frontier, limits=ranges.IndexRangeLimits(max_leaves=1,
                max_opened_nodes=481, max_hashes=16 * 481 + 1), work=work)
        selected = _primary_row(cursor, ordinal=ordinal, identity=identity, leaf=leaf, user_id=user_id,
                                trace=trace, work=work, acquisition=acquisition)
        proof = _before_proof(cursor, selected=selected, root=root, trace=trace, work=work, acquisition=acquisition)
        # Reconstruct the actual primary before proof. Historical primary
        # metrics retain their documented snapshot/hash scope, not driver cost.
        limits = primary.PrimaryRadixLimits(1, 1, 64, 1024,
            min(136, work.limits.max_hashes - work.hash_work),
            work.limits.max_input_bytes - work.input_bytes, 128,
            work.limits.max_json_nodes - work.json_nodes)
        memberships = primary.evaluate_primary_radix_memberships(table_contracts=(primary.PrimaryTableContract(
            TABLE, ("id",), False, "business"),), business_before_roots=(root,), authorization_before_roots=(),
            selected_rows=(selected,), before_proofs=(proof,), limits=limits)
        metrics = memberships.result.metrics
        work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
        work.prepare_encoding(projection._definition(INDEX_ID).document(), ensure_ascii=False)
        work.prepare_encoding({"user_id": user_id}, ensure_ascii=False)
        work.charge(hashes=projection.ROW_HASH_WORK)
        derived = projection.project_row(INDEX_ID, memberships.selected_rows[0]["row"],
            primary_key_digest=selected["keyDigest"], primary_row_digest=proof["rowDigest"])
        _require(derived == leaf and memberships.result.business_after_roots == (root,),
                 "history counted leaf does not join its genuine full primary original")
        return _finish({"schema": PAGE_SCHEMA, "ordinal": ordinal, "lower": lower, "upper": upper,
            "selectedRows": list(memberships.selected_rows), "beforeProofs": list(memberships.before_proofs),
            "frontier": _frontier_wire(frontier)}, work)
