"""Bounded full-population root reconstruction, not a SQL-count assertion.

The actual planner calls this after primary membership admission and before its
OAuth kernel, against those same before-roots. Currentness and writer fencing
remain the surrounding measured transaction's responsibility.
"""
import time

from serverware import authority_radix_proof as radix
from serverware import authority_oauth_activation as profile

MAX_ROWS = 64
TABLES = ("credentials", "pending_oauth_credentials", "setup_sessions", "oauth_family_retirements")


def maximum_rows(table):
    # Four complete populations plus exact assertion/current rows must fit the
    # unchanged global 256-proof ceiling. No larger population is truncated.
    return 32 if table == "oauth_family_retirements" else MAX_ROWS


def tables_for(operation):
    if operation in {"oauth.measured-refresh-cleanup.inspect", "oauth.measured-refresh-cleanup.claim", "oauth.measured-refresh-cleanup.contact",
            "oauth.measured-refresh-cleanup.finish", "oauth.measured-refresh-cleanup.recover"}:
        return ("credentials",)
    if operation in {"oauth.pending.activate", "oauth.pending.stage", "oauth.measured-exchange.stage"}:
        return TABLES
    if operation in {"oauth.exchange.prepare", "oauth.measured-exchange.prepare"}:
        return ("oauth_exchange_reservations", "oauth_revocation_work", "pending_oauth_credentials")
    if operation == "oauth.refresh.claim":
        return ("oauth_refresh_reservations", "oauth_revocation_work", "oauth_family_retirements")
    if operation == "oauth.measured-refresh.claim":
        return ("oauth_refresh_reservations", "oauth_measured_refresh_custody", "oauth_revocation_work", "oauth_family_retirements")
    if operation in {"oauth.measured-refresh.inspect", "oauth.measured-refresh.capture", "oauth.measured-refresh.commit", "oauth.measured-refresh.recover"}:
        return ("oauth_family_retirements",)
    if operation in {"oauth.refresh.retain", "oauth.refresh.commit"}:
        return ("oauth_family_retirements",)
    if operation == "credential.currentness.challenge":
        return ("credential_currentness_challenges",)
    if operation in {"credential.currentness.register", "credential.currentness.quiesce", "credential.currentness.admit"}:
        return ("credential_currentness_holders",)
    if operation in {"oauth.refresh-cleanup.claim", "oauth.refresh-cleanup.contact", "oauth.refresh-cleanup.finish"}:
        return ("credentials",)
    raise ValueError("operation has no complete OAuth population contract")


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns, operation="oauth.pending.activate"):
    # No new allowance and no arbitrary success/effect callback.
    profile.require(type(deadline_ns) is int)
    def check():
        profile.require(time.monotonic_ns() < deadline_ns, "OAuth inventory original deadline expired")
    work.prepare_copy(before_roots)
    roots = {entry["table"]: entry for entry in before_roots}
    for table in tables_for(operation):
        check()
        work.prepare_scan(selected_rows)
        rows = [entry for entry in selected_rows if entry["table"] == table and entry["present"]]
        profile.require(table in roots and len(rows) <= maximum_rows(table), "OAuth complete inventory exceeds its source-fixed table bound")
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
