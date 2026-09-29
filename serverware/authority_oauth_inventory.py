"""Bounded full-population root reconstruction, not a SQL-count assertion.

The actual planner calls this after primary membership admission and before its
OAuth kernel, against those same before-roots. Currentness and writer fencing
remain the surrounding measured transaction's responsibility.
"""
import time

from serverware import authority_radix_proof as radix
from serverware import authority_oauth_activation as profile

MAX_ROWS = 64
TABLES = ("credentials", "pending_oauth_credentials", "setup_sessions")


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns):
    # No new allowance and no arbitrary success/effect callback.
    profile.require(type(deadline_ns) is int)
    def check():
        profile.require(time.monotonic_ns() < deadline_ns, "OAuth inventory original deadline expired")
    work.prepare_copy(before_roots)
    roots = {entry["table"]: entry for entry in before_roots}
    for table in TABLES:
        check()
        work.prepare_scan(selected_rows)
        rows = [entry for entry in selected_rows if entry["table"] == table and entry["present"]]
        profile.require(table in roots and len(rows) <= MAX_ROWS, "OAuth complete inventory exceeds its 64-row table bound")
        nodes = {}
        # Each cold empty_digest(depth) separately computes its suffix ladder.
        # Reserve the complete triangular work, regardless of cache state.
        work.charge(hashes=65 * 66 // 2)
        for entry in rows:
            check()
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["row"], ensure_ascii=False)
            work.charge(hashes=3)
            key_digest = radix.authenticated_key_digest(table, entry["key"])
            path = key_digest[7:]
            profile.require(path not in nodes, "OAuth complete inventory contains a duplicate radix path")
            row_digest = radix._tree_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                table.encode("ascii"), radix.tree_json_bytes(entry["row"]))
            nodes[path] = radix._tree_digest("serverware.policyAuthorityAuthenticatedLeaf/v1",
                table.encode("ascii"), key_digest.encode("ascii"), radix.tree_json_bytes(entry["key"]), row_digest.encode("ascii"))
        for depth in range(63, -1, -1):
            check()
            parents = {}
            for path, value in nodes.items():
                parent = path[:-1]
                if parent not in parents:
                    parents[parent] = [radix.empty_digest(depth + 1)] * 16
                parents[parent][int(path[-1], 16)] = value
            nodes = {}
            for parent, children in parents.items():
                work.prepare_encoding(children, ensure_ascii=False)
                work.charge(hashes=1)
                nodes[parent] = radix._tree_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                    str(depth).encode("ascii"), radix.tree_json_bytes(children))
        reconstructed = nodes.get("", radix.empty_digest(0))
        profile.require(reconstructed == roots[table]["rootDigest"],
            "OAuth population is incomplete relative to the actual authenticated before-root")
    check()
