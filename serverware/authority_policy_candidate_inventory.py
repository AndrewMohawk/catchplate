"""Candidate intake's fixed complete populations, checked against before-roots.

These capacity limits are not a production scale or lifecycle claim. Overflow
refuses without truncation, pruning, key retirement or replay-history repair.
"""
import time
from serverware import authority_radix_proof as radix
from serverware import authority_policy_candidate as profile

MAX_ROWS = 32
TABLES = ("policy_authority_trusted_key_revocations", "policy_runtime_role_key_revocations",
    "policy_authority_evidence_verifications", "policy_authority_trusted_keys",
    "policy_shadow_generation_publications", profile.TABLE)


def tables_for(operation):
    profile.require(operation in profile.OPERATIONS)
    return TABLES


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns, operation):
    profile.require(type(deadline_ns) is int)
    work.prepare_copy(before_roots)
    roots = {entry["table"]: entry for entry in before_roots}
    for table in tables_for(operation):
        profile.require(time.monotonic_ns() < deadline_ns)
        work.prepare_scan(selected_rows)
        rows = [entry for entry in selected_rows if entry["table"] == table and entry["present"]]
        profile.require(table in roots and len(rows) <= MAX_ROWS, "candidate complete population exceeds32")
        nodes = {}
        work.charge(hashes=65 * 66 // 2)
        for entry in rows:
            profile.require(time.monotonic_ns() < deadline_ns)
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["row"], ensure_ascii=False)
            work.charge(hashes=3)
            key_digest = radix.authenticated_key_digest(table, entry["key"])
            path = key_digest[7:]
            profile.require(path not in nodes, "candidate inventory repeats a primary path")
            row_digest = radix._tree_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                table.encode("ascii"), radix.tree_json_bytes(entry["row"]))
            nodes[path] = radix._tree_digest("serverware.policyAuthorityAuthenticatedLeaf/v1",
                table.encode("ascii"), key_digest.encode("ascii"), radix.tree_json_bytes(entry["key"]), row_digest.encode("ascii"))
        for depth in range(63, -1, -1):
            profile.require(time.monotonic_ns() < deadline_ns)
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
        profile.require(nodes.get("", radix.empty_digest(0)) == roots[table]["rootDigest"],
            "candidate population is incomplete against its authenticated current before-root")
    profile.require(time.monotonic_ns() < deadline_ns)
