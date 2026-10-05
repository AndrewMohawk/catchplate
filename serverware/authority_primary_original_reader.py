"""Exact present/absent primary originals on an existing physical read budget.

Only the private JIT and recovery-invalidation producers use this fixed PK
reader. Their source kernels derive the query; their native owners admit the
database, current roots, transaction and deadline. The caller already owns
read_phase. Each of the row, leaf and 64 child-vector SELECTs uses a child scope
on that same collector, including actual parameter and returned-row charges.
No connection, allowance, unmetered radix SQL, signing or authority DTO exists.

The unchanged 1 MiB row and 4 MiB aggregate physical ceilings are independent:
several individually allowed large rows may exhaust one original collector.
This module does not claim worst-case whole-operation capacity or reset it.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_index_reader as reader
from serverware import authority_primary_contract as contracts
from serverware import authority_query_reads as reads
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import _ValidationWork


OPERATIONS = frozenset({"jit.assertion.issue", "webauthn.recovery.invalidate"})
SQL_READS_PER_ORIGINAL = 66
_HEX = frozenset("0123456789abcdef")
_LEAF_FIELDS = ("key_json", "row_digest", "leaf_digest", "root_revision")
_NODE_FIELDS = ("path_prefix", "node_digest", "root_revision")


def _require(value):
    if not value:
        raise reader.IndexReadError("exact primary original differs from its source/read binding")


def _digest(value):
    return (type(value) is str and len(value) == 71 and value.startswith("sha256:")
        and all(character in _HEX for character in value[7:]))


def _tree_wire(value, work):
    work.prepare_encoding(value, ensure_ascii=False)
    return radix.tree_json_bytes(value)


def _tree_hash(domain, frames, work):
    work.charge(hashes=1, input_bytes=len(domain) + 8 + sum(8 + len(frame) for frame in frames))
    return radix._tree_digest(domain, *frames)


def _inputs(operation, query, manifest, root, work):
    _require(type(operation) is str and operation in OPERATIONS and type(query) is core.BoundedQuery
        and type(manifest) is tuple and len(manifest) <= authority.MAX_QUERY_PROOFS
        and type(root) is primary.PrimaryRoot)
    query = reads._snapshot_queries(operation, (query,), work=work)[0]
    _require(type(query.absent_key) is dict and query.maximum_rows == 1
        and query.proof_primitive == "primary-key-row" and query.exact_page is False
        and query.page_size is None and query.continuation_token_digest is None
        and query.secondary_index_name is None and type(query.require_absence) is bool)
    table = query.table
    columns = contracts.PRIMARY_KEY_COLUMNS[table]
    selected_manifest = tuple(item for item in manifest if type(item) is dict and item.get("table") == table)
    _require(len(selected_manifest) == 1 and tuple(selected_manifest[0].get("keyColumns", ())) == columns
        and set(query.absent_key) == set(columns)
        and len(query.predicates) == len(columns) == len(query.order_by)
        and tuple(item.column for item in query.predicates) == tuple(sorted(columns))
        and tuple(item.column for item in query.order_by) == tuple(sorted(columns)))
    for predicate, ordering in zip(query.predicates, query.order_by):
        _require(type(predicate) is core.QueryPredicate and predicate.operator == "eq"
            and type(ordering) is core.QueryOrder and ordering.descending is False)
        value = query.absent_key[predicate.column]
        _require(type(value) is str and 1 <= len(value) <= 4096 and "\x00" not in value)
        work.prepare_comparison(predicate.value, value)
        _require(type(predicate.value) is str and predicate.value == value)
    values = reads._CopyBudget(work).copy((root.table, root.root_revision, root.root_digest, root.leaf_count))
    work.charge(hashes=66)
    root = primary.PrimaryRoot(*values)
    _require(root.table == table)
    matches = tuple(item for item in contracts.primary_table_contracts(operation) if item.table == table)
    _require(len(matches) == 1 and matches[0].key_columns == columns)
    return query, root, matches[0]


def _row(cursor, *, query, trace, work, acquisition):
    table, key = query.table, query.absent_key
    work.prepare_utf8(table)
    work.prepare_encoding(key)
    domain = "serverware.policyAuthorityBusinessKey/v1"
    work.charge(hashes=1, input_bytes=len(domain) + 17)
    key_digest = core.framed_digest(domain, table.encode("ascii"), core.canonical_bytes(key))
    # Names come only from the exact source PK inventory, never raw SQL input.
    columns = tuple(item.column for item in query.predicates)
    work.prepare_copy(columns)
    clauses = " AND ".join(f"target.{column} IS NOT DISTINCT FROM %s" for column in columns)
    parameters = tuple(key[column] for column in columns) + (2,)
    sql = ("SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::pg_catalog.text) "
        f"<= {reader.MAX_PRIMARY_ROW_BYTES} THEN pg_catalog.to_jsonb(target) ELSE NULL END AS row_value "
        f"FROM serverware_metadata.{table} AS target WHERE {clauses} LIMIT %s")
    work.prepare_scan(sql)
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read(table, key, sql, parameters, 1)
        _require(not query.require_absence or not rows)
        if rows:
            _require(type(rows[0]) is dict and set(rows[0]) == {"row_value"}
                and type(rows[0]["row_value"]) is dict)
            row = rows[0]["row_value"]
            size, _ = work.prepare_encoding(row)
            _require(size <= reader.MAX_PRIMARY_ROW_BYTES)
            encoded = core.canonical_bytes(row)
            _require(len(encoded) == size)
            acquisition.charge_primary_row(encoded)
            row = reads._CopyBudget(work).copy(row)
            for column in columns:
                work.prepare_comparison(row.get(column), key[column])
                _require(type(row.get(column)) is str and row[column] == key[column])
        else:
            # Absence has no returned SQL row, but its retained scalar is still
            # actual framed evidence, not a zero-cost successful observation.
            acquisition.charge_primary_row(b"null")
            row = None
    work.prepare_copy(key)
    work.charge(json_nodes=13)
    return {"table": table, "key": dict(key), "keyDigest": key_digest,
        "present": row is not None, "row": row, "contractSelector": None}


def _before_proof(cursor, *, selected, root, trace, work, acquisition):
    table, key = selected["table"], selected["key"]
    table_bytes = table.encode("ascii")
    key_bytes = _tree_wire(key, work)
    tree_key = _tree_hash("serverware.policyAuthorityAuthenticatedKey/v1", (table_bytes, key_bytes), work)
    # No parser for stored key text: exact real tree-wire equality is stricter
    # than generic JSON equality and preserves bool/integer distinctions.
    work.charge(input_bytes=len(key_bytes))
    key_text = key_bytes.decode("utf-8")
    path = tree_key[7:]
    empty = {64: _tree_hash("serverware.policyAuthorityAuthenticatedEmptyLeaf/v1", (b"64",), work)}
    for depth in range(63, -1, -1):
        work.charge(json_nodes=17)
        empty[depth] = _tree_hash("serverware.policyAuthorityAuthenticatedNode/v1",
            (str(depth).encode("ascii"), _tree_wire([empty[depth + 1]] * 16, work)), work)
    row_digest = (_tree_hash("serverware.policyAuthorityAuthenticatedRow/v1",
        (table_bytes, _tree_wire(selected["row"], work)), work) if selected["present"] else None)
    leaf_digest = (_tree_hash("serverware.policyAuthorityAuthenticatedLeaf/v1",
        (table_bytes, tree_key.encode("ascii"), key_bytes, row_digest.encode("ascii")), work)
        if selected["present"] else empty[64])
    with acquisition.scope(cursor, trace, work):
        rows = acquisition.read("policy_authority_authenticated_leaves", {"tableName": table, "keyDigest": tree_key},
            "SELECT CASE WHEN pg_catalog.octet_length(key_json) BETWEEN 1 AND 32768 THEN key_json ELSE NULL END AS key_json, "
            "CASE WHEN pg_catalog.octet_length(row_digest) = 71 THEN row_digest ELSE NULL END AS row_digest, "
            "CASE WHEN pg_catalog.octet_length(leaf_digest) = 71 THEN leaf_digest ELSE NULL END AS leaf_digest, root_revision "
            "FROM serverware_metadata.policy_authority_authenticated_leaves "
            "WHERE table_name = %s AND key_digest = %s LIMIT %s", (table, tree_key, 2), 1)
        _require(len(rows) == int(selected["present"]))
        if rows:
            stored = rows[0]
            _require(type(stored) is dict and set(stored) == set(_LEAF_FIELDS)
                and type(stored["key_json"]) is str and 0 < len(stored["key_json"]) <= 32768
                and _digest(stored["row_digest"]) and _digest(stored["leaf_digest"])
                and type(stored["root_revision"]) is int and 0 < stored["root_revision"] <= root.root_revision)
            # A bounded key JSON record can exceed the counted reader's 4096
            # byte scalar slot. Charge its actual canonical whole-row frame,
            # like business rows, without splitting or renewing an allowance.
            encoded = work.wire(stored)
            acquisition.charge_primary_row(encoded)
            work.prepare_comparison(stored["key_json"], key_text)
            _require(stored["key_json"] == key_text and stored["row_digest"] == row_digest
                and stored["leaf_digest"] == leaf_digest)
        else:
            acquisition.charge_primary_row(b"null")
        siblings = []
        for depth in range(64):
            prefix = path[:depth]
            work.charge(input_bytes=16 * (depth + 1), json_nodes=17)
            paths = tuple(prefix + format(n, "x") for n in range(16))
            placeholders = ", ".join("%s" for _ in paths)
            rows = acquisition.read("policy_authority_authenticated_tree_nodes",
                {"tableName": table, "depth": depth + 1, "pathPrefix": prefix},
                "SELECT CASE WHEN pg_catalog.octet_length(path_prefix) BETWEEN 1 AND 64 THEN path_prefix ELSE NULL END AS path_prefix, "
                "CASE WHEN pg_catalog.octet_length(node_digest) = 71 THEN node_digest ELSE NULL END AS node_digest, root_revision "
                "FROM serverware_metadata.policy_authority_authenticated_tree_nodes "
                f"WHERE table_name = %s AND depth = %s AND path_prefix IN ({placeholders}) LIMIT %s",
                (table, depth + 1, *paths, 17), 16)
            by_path = {}
            for raw in rows:
                node = reader._record(raw, _NODE_FIELDS, work)
                _require(type(node["path_prefix"]) is str and node["path_prefix"] in paths
                    and node["path_prefix"] not in by_path and _digest(node["node_digest"])
                    and type(node["root_revision"]) is int and 0 < node["root_revision"] <= root.root_revision)
                acquisition.charge("primary-node", node, _NODE_FIELDS)
                by_path[node["path_prefix"]] = node["node_digest"]
            work.charge(json_nodes=26, input_bytes=16 * 71 + depth)
            siblings.append({"depth": depth, "pathPrefix": prefix, "selectedNibble": path[depth],
                "childDigests": [by_path.get(p, empty[depth + 1]) for p in paths]})
    work.prepare_copy(key)
    work.charge(json_nodes=25)
    proof = {"schema": "serverware.policyAuthorityRadixMultiproof/v3", "table": table,
        "key": dict(key), "keyDigest": selected["keyDigest"], "present": selected["present"],
        "rowDigest": row_digest, "leafDigest": leaf_digest, "rootRevision": root.root_revision,
        "rootDigest": root.root_digest, "siblings": siblings}
    work.prepare_encoding(proof)
    domain = "serverware.policyAuthorityRadixMultiproof/v3"
    work.charge(hashes=1, input_bytes=len(domain) + 9)
    proof["proofDigest"] = core.framed_digest(domain, core.canonical_bytes(proof))
    return proof


def acquire_exact_primary(cursor, *, operation, query, manifest,
        primary_root: primary.PrimaryRoot, trace, work, acquisition):
    """Return owned raw (selected, proof), after actual membership replay."""
    if type(work) is not _ValidationWork or type(acquisition) is not reader._ReadAcquisitionBudget:
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise reader.IndexReadError("exact primary reader requires the original work/physical collector")
    try:
        acquisition.require_idle(cursor, trace, work)
        _require(acquisition._read_phase_active is True and getattr(trace, "operation", None) == operation)
        query, root, contract = _inputs(operation, query, manifest, primary_root, work)
        started = acquisition.sql_reads
        selected = _row(cursor, query=query, trace=trace, work=work, acquisition=acquisition)
        proof = _before_proof(cursor, selected=selected, root=root, trace=trace, work=work, acquisition=acquisition)
        business = (root,) if contract.root_class == "business" else ()
        authorization = (root,) if contract.root_class == "authorization" else ()
        limits = primary.PrimaryRadixLimits(1, 1, 64, 1024,
            min(136, work.limits.max_hashes - work.hash_work),
            work.limits.max_input_bytes - work.input_bytes, 128,
            work.limits.max_json_nodes - work.json_nodes)
        observed = primary.evaluate_primary_radix_memberships(table_contracts=(contract,),
            business_before_roots=business, authorization_before_roots=authorization,
            selected_rows=(selected,), before_proofs=(proof,), limits=limits)
        metrics = observed.result.metrics
        work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
        _require(observed.result.business_after_roots == business
            and observed.result.authorization_after_roots == authorization and metrics.mutations == 0
            and metrics.recomputed_ancestors == 0 and acquisition.sql_reads - started == SQL_READS_PER_ORIGINAL)
        acquisition.require_idle(cursor, trace, work)
        return observed.selected_rows[0], observed.before_proofs[0]
    except BaseException:
        acquisition.failed = True
        raise
