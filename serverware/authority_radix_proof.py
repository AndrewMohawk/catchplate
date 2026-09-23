"""Existing primary-key radix proofs, independent of transition registration.

Business addresses use BusinessKey/v1; persisted tree paths and leaf hashes use
AuthenticatedKey/v1. SQL tree hashes length-prefix the domain; business address
and proof-envelope hashes retain their separate domain-plus-NUL wire framing.
These proofs establish individual row inclusion/absence
relative to a supplied root, not predicate completeness or root freshness.
"""
from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from typing import Any, Mapping

from serverware import authority_contract
from serverware.authority_transition_core import canonical_bytes, framed_digest, require_digest


class RadixProofError(ValueError):
    pass


BATCH_TRACE_PROFILE = "serverware.policyAuthorityRadixReadBatch/v1"
MAX_BATCH_PARENTS = 16
MAX_BATCH_CHILDREN = MAX_BATCH_PARENTS * authority_contract.TREE_RADIX
_TABLE_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")


def validate_batch_trace_key(key: Any) -> tuple[tuple[str, int, str], ...]:
    """Validate the closed physical-read profile, not execution or authority.

    Parent depth is the child-node SQL depth, so its prefix has depth-1
    nibbles. A physical read may span both tables and depths. These identities
    are always business charged; they never replace the reserved counter's
    separately traced singleton proof.
    """
    if (type(key) is not dict or set(key) != {"profile", "parents"}
            or type(key["profile"]) is not str or key["profile"] != BATCH_TRACE_PROFILE
            or type(key["parents"]) is not list
            or not 1 <= len(key["parents"]) <= MAX_BATCH_PARENTS):
        raise RadixProofError("authenticated batch trace is not closed")
    parents: list[tuple[str, int, str]] = []
    for parent in key["parents"]:
        if type(parent) is not dict or set(parent) != {"tableName", "depth", "pathPrefix"}:
            raise RadixProofError("authenticated batch parent is not closed")
        table, depth, prefix = parent["tableName"], parent["depth"], parent["pathPrefix"]
        if (type(table) is not str or _TABLE_IDENTIFIER.fullmatch(table) is None
                or type(depth) is not int or not 1 <= depth <= authority_contract.TREE_DEPTH
                or type(prefix) is not str or len(prefix) != depth - 1
                or any(character not in "0123456789abcdef" for character in prefix)):
            raise RadixProofError("authenticated batch parent identity is invalid")
        parents.append((table, depth, prefix))
    if parents != sorted(set(parents)):
        raise RadixProofError("authenticated batch parents are not sorted and unique")
    return tuple(parents)


def tree_json_bytes(value: Any) -> bytes:
    """SQL UTF-8 JSON for lossless scalars; never approximate numeric scale.

JSONB float/numeric decoding can discard PostgreSQL's decimal representation.
Those values require a separate end-to-end canonicalization contract, not an
inferred row digest. Business/proof transport canonicalization is unchanged.
"""
    def normalize(item: Any) -> Any:
        if item is None or type(item) in (str, bool, int):
            return item
        if isinstance(item, Mapping):
            if any(type(key) is not str for key in item):
                raise RadixProofError("authenticated JSON object keys must be strings")
            return {key: normalize(child) for key, child in item.items()}
        if isinstance(item, list):
            return [normalize(child) for child in item]
        raise RadixProofError("authenticated JSON requires lossless scalar types; numeric scale is unsupported")

    try:
        return json.dumps(normalize(value), ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, RadixProofError):
            raise
        raise RadixProofError("authenticated JSON cannot be represented losslessly") from exc


def _tree_digest(domain: str, *frames: bytes) -> str:
    """Match PostgreSQL serverware_policy_authority_framed_digest exactly."""
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(len(encoded_domain).to_bytes(8, "big"))
    digest.update(encoded_domain)
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def authenticated_key_digest(table: str, key: Mapping[str, Any]) -> str:
    return _tree_digest(
        "serverware.policyAuthorityAuthenticatedKey/v1",
        table.encode("utf-8"), tree_json_bytes(dict(key)),
    )


@lru_cache(maxsize=65, typed=True)
def empty_digest(depth: int) -> str:
    if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= authority_contract.TREE_DEPTH:
        raise RadixProofError("authenticated empty depth is invalid")
    digest = _tree_digest(
        "serverware.policyAuthorityAuthenticatedEmptyLeaf/v1",
        str(authority_contract.TREE_DEPTH).encode("ascii"),
    )
    for current in range(authority_contract.TREE_DEPTH - 1, depth - 1, -1):
        digest = _tree_digest(
            "serverware.policyAuthorityAuthenticatedNode/v1",
            str(current).encode("ascii"), tree_json_bytes([digest] * authority_contract.TREE_RADIX),
        )
    return digest


def _database_text(value: Any, *, maximum_bytes: int, label: str) -> str:
    """Reject SQL projection sentinels and malformed driver values explicitly."""
    if type(value) is not str or not 0 < len(value) <= maximum_bytes:
        raise RadixProofError(f"{label} is not bounded database text")
    try:
        if len(value.encode("utf-8")) > maximum_bytes:
            raise RadixProofError(f"{label} is not bounded database text")
    except UnicodeError as exc:
        raise RadixProofError(f"{label} is not bounded database text") from exc
    return value


def _database_digest(value: Any, label: str) -> str:
    digest = _database_text(value, maximum_bytes=71, label=label)
    if len(digest) != 71 or not digest.startswith("sha256:") or any(
        character not in "0123456789abcdef" for character in digest[7:]
    ):
        raise RadixProofError(f"{label} is not a canonical database digest")
    return digest


def _read_selected_leaf(
    cursor: Any, *, selected: dict[str, Any], root_by_table: Mapping[str, Any],
    trace: Any, quoted_namespace: str,
) -> tuple[dict[str, Any], str, Mapping[str, Any]]:
    """Shared singleton leaf validation; no node queries or proof authority."""
    table = str(selected["table"])
    root = root_by_table.get(table)
    if root is None:
        raise RadixProofError("selected row has no authenticated relation root")
    if (
        type(root.get("rootRevision")) is not int or root["rootRevision"] < 0
        or type(selected.get("present")) is not bool
        or (selected["present"] and not isinstance(selected.get("row"), Mapping))
        or (not selected["present"] and selected.get("row") is not None)
    ):
        raise RadixProofError("selected row or authenticated root revision is not closed")
    require_digest(root.get("rootDigest"), "authenticated relation root")
    key_digest = str(selected["keyDigest"])
    require_digest(key_digest, "selected row key digest")
    if key_digest != framed_digest(
        "serverware.policyAuthorityBusinessKey/v1", table.encode("utf-8"), canonical_bytes(selected["key"]),
    ):
        raise RadixProofError("selected business key digest changed")
    tree_key_digest = authenticated_key_digest(table, selected["key"])
    path = tree_key_digest[7:]
    trace.read("policy_authority_authenticated_leaves", {"tableName": table, "keyDigest": tree_key_digest})
    leaf = cursor.execute(
        "SELECT CASE WHEN pg_catalog.octet_length(key_json) BETWEEN 1 AND "
        f"{authority_contract.MAX_RESULT_BYTES} THEN key_json ELSE NULL END AS key_json, "
        "CASE WHEN pg_catalog.octet_length(row_digest) = 71 "
        "THEN row_digest ELSE NULL END AS row_digest, "
        "CASE WHEN pg_catalog.octet_length(leaf_digest) = 71 "
        "THEN leaf_digest ELSE NULL END AS leaf_digest, root_revision "
        f"FROM {quoted_namespace}.policy_authority_authenticated_leaves "
        "WHERE table_name = %s AND key_digest = %s", (table, tree_key_digest),
    ).fetchone()
    if leaf is not None:
        if not isinstance(leaf, Mapping):
            raise RadixProofError("authenticated leaf is not a database record")
        stored_key_json = _database_text(
            leaf.get("key_json"), maximum_bytes=authority_contract.MAX_RESULT_BYTES,
            label="authenticated leaf key JSON",
        )
        stored_row_digest = _database_digest(leaf.get("row_digest"), "authenticated leaf row digest")
        stored_leaf_digest = _database_digest(leaf.get("leaf_digest"), "authenticated leaf digest")
        try:
            stored_key = json.loads(stored_key_json)
        except (ValueError, RecursionError) as exc:
            raise RadixProofError("authenticated leaf key JSON is malformed") from exc
    row_digest = (
        _tree_digest("serverware.policyAuthorityAuthenticatedRow/v1", table.encode("utf-8"), tree_json_bytes(selected["row"]))
        if selected["present"] else None
    )
    leaf_digest = (
        _tree_digest(
            "serverware.policyAuthorityAuthenticatedLeaf/v1", table.encode("utf-8"),
            tree_key_digest.encode("ascii"), tree_json_bytes(selected["key"]), str(row_digest).encode("ascii"),
        )
        if selected["present"] else empty_digest(authority_contract.TREE_DEPTH)
    )
    if selected["present"]:
        if (
            leaf is None or stored_key != selected["key"]
            or stored_row_digest != row_digest or stored_leaf_digest != leaf_digest
            or type(leaf.get("root_revision")) is not int
            or not 0 < leaf["root_revision"] <= root["rootRevision"]
        ):
            raise RadixProofError("selected row differs from its authenticated leaf")
    elif leaf is not None:
        raise RadixProofError("selected nonmembership has an authenticated leaf")
    proof = {
        "schema": "serverware.policyAuthorityRadixMultiproof/v3",
        "table": table, "key": selected["key"], "keyDigest": key_digest,
        "present": selected["present"], "rowDigest": row_digest, "leafDigest": leaf_digest,
        "rootRevision": root["rootRevision"], "rootDigest": root["rootDigest"], "siblings": [],
    }
    return proof, path, root


def derive_multiproofs(
    cursor: Any,
    *,
    selected_rows: tuple[dict[str, Any], ...],
    roots: tuple[dict[str, Any], ...],
    trace: Any,
    namespace: str = "serverware_metadata",
) -> tuple[dict[str, Any], ...]:
    """Read bounded persisted proof records from one validated SQL namespace.

    CASE projections preserve a malformed row as a rejection sentinel instead
    of filtering it into apparent nonmembership. The SQL projections bound text
    before driver transport; the Python checks also reject malformed responders.
    Root authenticity/currentness and transaction isolation remain caller duties.
    """
    if type(namespace) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", namespace) is None:
        raise RadixProofError("authenticated proof namespace is not a lowercase ASCII identifier")
    quoted_namespace = f'"{namespace}"'
    root_by_table = {entry["table"]: entry for entry in roots}
    proofs: list[dict[str, Any]] = []
    for selected in selected_rows:
        proof, path, root = _read_selected_leaf(
            cursor, selected=selected, root_by_table=root_by_table,
            trace=trace, quoted_namespace=quoted_namespace,
        )
        table, siblings = proof["table"], proof["siblings"]
        for depth in range(authority_contract.TREE_DEPTH):
            prefix = path[:depth]
            trace.read("policy_authority_authenticated_tree_nodes", {
                "tableName": table, "depth": depth + 1, "pathPrefix": prefix,
            })
            expected_paths = [prefix + format(index, "x") for index in range(authority_contract.TREE_RADIX)]
            rows = cursor.execute(
                "SELECT CASE WHEN pg_catalog.octet_length(path_prefix) BETWEEN 1 AND 64 "
                "THEN path_prefix ELSE NULL END AS path_prefix, "
                "CASE WHEN pg_catalog.octet_length(node_digest) = 71 "
                "THEN node_digest ELSE NULL END AS node_digest, root_revision "
                f"FROM {quoted_namespace}.policy_authority_authenticated_tree_nodes "
                "WHERE table_name = %s AND depth = %s "
                "AND path_prefix = ANY(%s) LIMIT %s",
                (table, depth + 1, expected_paths, authority_contract.TREE_RADIX + 1),
            ).fetchmany(authority_contract.TREE_RADIX + 1)
            if len(rows) > authority_contract.TREE_RADIX:
                raise RadixProofError("authenticated child set exceeded its fixed radix")
            by_path: dict[str, str] = {}
            for row in rows:
                if not isinstance(row, Mapping):
                    raise RadixProofError("authenticated child is not a database record")
                child_path = _database_text(
                    row.get("path_prefix"), maximum_bytes=64, label="authenticated child path",
                )
                if (
                    child_path not in expected_paths or child_path in by_path
                    or type(row.get("root_revision")) is not int
                    or not 0 < row["root_revision"] <= root["rootRevision"]
                ):
                    raise RadixProofError("authenticated child identity or revision changed")
                by_path[child_path] = _database_digest(row.get("node_digest"), "authenticated child digest")
            child_digests = [
                by_path.get(prefix + format(index, "x"), empty_digest(depth + 1))
                for index in range(authority_contract.TREE_RADIX)
            ]
            siblings.append({"depth": depth, "pathPrefix": prefix, "selectedNibble": path[depth], "childDigests": child_digests})
        proof["proofDigest"] = framed_digest("serverware.policyAuthorityRadixMultiproof/v3", canonical_bytes(proof))
        proofs.append(proof)
    return tuple(sorted(proofs, key=lambda entry: (entry["table"], entry["keyDigest"])))


def derive_multiproofs_batched(
    cursor: Any,
    *,
    selected_rows: tuple[dict[str, Any], ...],
    roots: tuple[dict[str, Any], ...],
    trace: Any,
    namespace: str = "serverware_metadata",
) -> tuple[dict[str, Any], ...]:
    """Share before-tree reads without changing any v3 proof or stored hash.

    Every selected leaf still has one physical singleton read. The operation's
    distinct (table, child-depth, parent-prefix) vectors are sorted and fetched
    in groups of at most 16, including across tables/depths. There are at most
    N + ceil(64*N/16) = 5*N SQL reads, each traced exactly once. Missing children
    retain the existing empty hashes; malformed returned rows are never hidden.

    Callers keep the global audit counter in the existing singleton path: its
    reserved contiguous trace block is not a batch allowance. This per-call
    cache cannot cross transactions or before-root inventories. Output still
    has all 64*16 slots per row; downstream proof/hash/byte budgets, root
    authority, transaction isolation and predicate completeness are unchanged.
    """
    if type(namespace) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", namespace) is None:
        raise RadixProofError("authenticated proof namespace is not a lowercase ASCII identifier")
    if (type(selected_rows) is not tuple
            or len(selected_rows) > authority_contract.MAX_QUERY_PROOFS
            or type(roots) is not tuple or len(roots) > authority_contract.MAX_QUERY_PROOFS):
        raise RadixProofError("authenticated batch inventory exceeds its bound")
    root_by_table: dict[str, dict[str, Any]] = {}
    for root in roots:
        if (type(root) is not dict or type(root.get("table")) is not str
                or _TABLE_IDENTIFIER.fullmatch(root["table"]) is None
                or root["table"] in root_by_table
                or type(root.get("rootRevision")) is not int
                or not 0 <= root["rootRevision"] <= 2**63 - 1):
            raise RadixProofError("authenticated batch root inventory is not closed")
        _database_digest(root.get("rootDigest"), "authenticated relation root")
        root_by_table[root["table"]] = root
    addresses: set[tuple[str, str]] = set()
    for selected in selected_rows:
        if (type(selected) is not dict or type(selected.get("table")) is not str
                or _TABLE_IDENTIFIER.fullmatch(selected["table"]) is None
                or not isinstance(selected.get("key"), Mapping)):
            raise RadixProofError("authenticated batch selected identity is not closed")
        key_digest = _database_digest(selected.get("keyDigest"), "selected row key digest")
        address = (selected["table"], key_digest)
        if address in addresses:
            raise RadixProofError("authenticated batch selected address is duplicated")
        addresses.add(address)

    quoted_namespace = f'"{namespace}"'
    pending: list[tuple[dict[str, Any], str]] = []
    parent_set: set[tuple[str, int, str]] = set()
    tree_addresses: set[tuple[str, str]] = set()
    for selected in selected_rows:
        proof, path, _root = _read_selected_leaf(
            cursor, selected=selected, root_by_table=root_by_table,
            trace=trace, quoted_namespace=quoted_namespace,
        )
        table = proof["table"]
        if (table, path) in tree_addresses:
            raise RadixProofError("authenticated batch tree address is duplicated")
        tree_addresses.add((table, path))
        pending.append((proof, path))
        parent_set.update((table, depth + 1, path[:depth])
                          for depth in range(authority_contract.TREE_DEPTH))

    parents = sorted(parent_set)
    vectors: dict[tuple[str, int, str], tuple[str, ...]] = {}
    for offset in range(0, len(parents), MAX_BATCH_PARENTS):
        batch = parents[offset:offset + MAX_BATCH_PARENTS]
        trace_key = {
            "profile": BATCH_TRACE_PROFILE,
            "parents": [{"tableName": table, "depth": depth, "pathPrefix": prefix}
                        for table, depth, prefix in batch],
        }
        validate_batch_trace_key(trace_key)
        children = tuple(
            (table, depth, prefix + format(index, "x"))
            for table, depth, prefix in batch
            for index in range(authority_contract.TREE_RADIX)
        )
        requested = set(children)
        if len(requested) != len(children) or len(children) > MAX_BATCH_CHILDREN:
            raise RadixProofError("authenticated batch child inventory is not closed")
        limit = len(children) + 1
        parameters = tuple(value for child in children for value in child) + (limit,)
        # Only the fixed placeholder count varies. Identifiers are source fixed
        # except the independently validated/quoted SQL namespace above.
        values_sql = ", ".join("(%s::text,%s::integer,%s::text)" for _ in children)
        trace.read("policy_authority_authenticated_tree_nodes", trace_key)
        rows = cursor.execute(
            "SELECT CASE WHEN pg_catalog.octet_length(node.table_name) BETWEEN 1 AND 128 "
            "THEN node.table_name ELSE NULL END AS table_name, node.depth AS depth, "
            "CASE WHEN pg_catalog.octet_length(node.path_prefix) BETWEEN 1 AND 64 "
            "THEN node.path_prefix ELSE NULL END AS path_prefix, "
            "CASE WHEN pg_catalog.octet_length(node.node_digest) = 71 "
            "THEN node.node_digest ELSE NULL END AS node_digest, node.root_revision AS root_revision "
            f"FROM {quoted_namespace}.policy_authority_authenticated_tree_nodes AS node "
            f"JOIN (VALUES {values_sql}) AS requested(table_name, depth, path_prefix) "
            "ON node.table_name = requested.table_name AND node.depth = requested.depth "
            "AND node.path_prefix = requested.path_prefix LIMIT %s",
            parameters,
        ).fetchmany(limit)
        if type(rows) is not list or len(rows) > len(children):
            raise RadixProofError("authenticated batch child set exceeded its bound")
        by_child: dict[tuple[str, int, str], str] = {}
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {
                "table_name", "depth", "path_prefix", "node_digest", "root_revision",
            }:
                raise RadixProofError("authenticated batch child is not a closed database record")
            table = _database_text(row["table_name"], maximum_bytes=128,
                                   label="authenticated batch child table")
            path = _database_text(row["path_prefix"], maximum_bytes=64,
                                  label="authenticated batch child path")
            depth = row["depth"]
            if type(depth) is not int:
                raise RadixProofError("authenticated batch child depth is not exact")
            identity = (table, depth, path)
            if (identity not in requested or identity in by_child
                    or type(row["root_revision"]) is not int
                    or not 0 < row["root_revision"] <= root_by_table[table]["rootRevision"]):
                raise RadixProofError("authenticated batch child identity or revision changed")
            by_child[identity] = _database_digest(row["node_digest"], "authenticated batch child digest")
        for table, depth, prefix in batch:
            vectors[(table, depth, prefix)] = tuple(
                by_child.get((table, depth, prefix + format(index, "x")), empty_digest(depth))
                for index in range(authority_contract.TREE_RADIX)
            )

    proofs: list[dict[str, Any]] = []
    for proof, path in pending:
        proof["siblings"] = [
            {"depth": depth, "pathPrefix": path[:depth], "selectedNibble": path[depth],
             "childDigests": list(vectors[(proof["table"], depth + 1, path[:depth])])}
            for depth in range(authority_contract.TREE_DEPTH)
        ]
        proof["proofDigest"] = framed_digest("serverware.policyAuthorityRadixMultiproof/v3", canonical_bytes(proof))
        proofs.append(proof)
    return tuple(sorted(proofs, key=lambda entry: (entry["table"], entry["keyDigest"])))


def reconstruct_multiproof_root(proof: Mapping[str, Any], *, selected: Mapping[str, Any]) -> str:
    """Reconstruct a row root; the planner separately checks proofDigest/signature."""
    required = {
        "schema", "table", "key", "keyDigest", "present", "rowDigest", "leafDigest",
        "rootRevision", "rootDigest", "siblings", "proofDigest",
    }
    table = proof.get("table")
    key = proof.get("key")
    key_digest = proof.get("keyDigest")
    siblings = proof.get("siblings")
    if (
        set(proof) != required or proof.get("schema") != "serverware.policyAuthorityRadixMultiproof/v3"
        or table != selected.get("table") or key != selected.get("key")
        or key_digest != selected.get("keyDigest") or proof.get("present") != selected.get("present")
        or type(proof.get("present")) is not bool or type(selected.get("present")) is not bool
        or type(proof.get("rootRevision")) is not int or proof["rootRevision"] < 0
        or (selected["present"] and not isinstance(selected.get("row"), Mapping))
        or (not selected["present"] and selected.get("row") is not None)
        or not isinstance(table, str) or not isinstance(key, Mapping)
        or not isinstance(siblings, list) or len(siblings) != authority_contract.TREE_DEPTH
    ):
        raise RadixProofError("writer multiproof envelope is not closed")
    require_digest(key_digest, "writer multiproof key digest")
    if key_digest != framed_digest(
        "serverware.policyAuthorityBusinessKey/v1", table.encode("utf-8"), canonical_bytes(dict(key)),
    ):
        raise RadixProofError("writer multiproof business key digest changed")
    tree_key_digest = authenticated_key_digest(table, key)
    path = tree_key_digest[7:]
    expected_row_digest = (
        _tree_digest("serverware.policyAuthorityAuthenticatedRow/v1", table.encode("utf-8"), tree_json_bytes(selected["row"]))
        if selected["present"] else None
    )
    expected_leaf_digest = (
        _tree_digest(
            "serverware.policyAuthorityAuthenticatedLeaf/v1", table.encode("utf-8"),
            tree_key_digest.encode("ascii"), tree_json_bytes(dict(key)), str(expected_row_digest).encode("ascii"),
        )
        if selected["present"] else empty_digest(authority_contract.TREE_DEPTH)
    )
    if proof.get("rowDigest") != expected_row_digest or proof.get("leafDigest") != expected_leaf_digest:
        raise RadixProofError("writer multiproof leaf binding changed")
    parent = expected_leaf_digest
    for depth in range(authority_contract.TREE_DEPTH - 1, -1, -1):
        level = siblings[depth]
        child_digests = level.get("childDigests") if isinstance(level, Mapping) else None
        selected_nibble = path[depth]
        selected_index = int(selected_nibble, 16)
        if (
            not isinstance(level, Mapping) or set(level) != {"depth", "pathPrefix", "selectedNibble", "childDigests"}
            or type(level.get("depth")) is not int
            or level.get("depth") != depth or level.get("pathPrefix") != path[:depth]
            or level.get("selectedNibble") != selected_nibble or not isinstance(child_digests, list)
            or len(child_digests) != authority_contract.TREE_RADIX
            or any(not isinstance(digest, str) or require_digest(digest, "writer multiproof child digest") != digest for digest in child_digests)
            or child_digests[selected_index] != parent
        ):
            raise RadixProofError("writer multiproof path reconstruction changed")
        parent = _tree_digest(
            "serverware.policyAuthorityAuthenticatedNode/v1", str(depth).encode("ascii"), tree_json_bytes(child_digests),
        )
    if parent != proof.get("rootDigest"):
        raise RadixProofError("writer multiproof root reconstruction failed")
    return parent
