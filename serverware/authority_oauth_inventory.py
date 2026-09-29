"""Bounded full-population root reconstruction, not a SQL-count assertion.

The actual planner calls this after primary membership admission and before its
OAuth kernel, against those same before-roots. Currentness and writer fencing
remain the surrounding measured transaction's responsibility.
"""
import time

from serverware import authority_radix_proof as radix
from serverware import authority_oauth_activation as profile
from serverware import authority_oauth_family_query_group as family_group

MAX_ROWS = 64
TABLES = ("credentials", "pending_oauth_credentials", "setup_sessions") + family_group.TABLES


def maximum_rows(table):
    # The fixed two-family-table group plus ordinary complete populations and
    # exact rows must fit the unchanged 256-proof ceiling. Never truncate.
    return 32 if table in family_group.TABLES else MAX_ROWS


def tables_for(operation):
    if operation in {"oauth.measured-capture-retirement.inspect", "oauth.measured-capture-retirement.claim"}:
        return ("credentials", "pending_oauth_credentials", "oauth_exchange_reservations", "oauth_refresh_reservations")
    if operation == "oauth.setup.create":
        return ("setup_sessions",)
    if operation in {"oauth.measured-pending-retirement.inspect", "oauth.measured-pending-retirement.claim",
            "oauth.measured-pending-retirement.contact", "oauth.measured-pending-retirement.finish", "oauth.measured-pending-retirement.recover"}:
        return ("credentials", "pending_oauth_credentials") + family_group.TABLES
    if operation in {"oauth.measured-refresh-cleanup.inspect", "oauth.measured-refresh-cleanup.claim", "oauth.measured-refresh-cleanup.contact",
            "oauth.measured-refresh-cleanup.finish", "oauth.measured-refresh-cleanup.recover"}:
        return ("credentials",) + family_group.TABLES
    if operation in {"oauth.pending.activate", "oauth.pending.stage", "oauth.measured-exchange.stage", "oauth.measured-setup.stage", "oauth.setup.activate"}:
        return TABLES
    if operation in {"oauth.exchange.prepare", "oauth.measured-exchange.prepare", "oauth.measured-setup.prepare"}:
        return ("oauth_exchange_reservations", "oauth_revocation_work", "pending_oauth_credentials")
    if operation == "oauth.refresh.claim":
        return ("oauth_refresh_reservations", "oauth_revocation_work") + family_group.TABLES
    if operation == "oauth.measured-refresh.claim":
        return ("oauth_refresh_reservations", "oauth_measured_refresh_custody", "oauth_revocation_work") + family_group.TABLES
    if operation in {"oauth.measured-refresh.inspect", "oauth.measured-refresh.capture", "oauth.measured-refresh.commit", "oauth.measured-refresh.recover"}:
        return family_group.TABLES
    if operation in {"oauth.refresh.retain", "oauth.refresh.commit"}:
        return family_group.TABLES
    if operation == "credential.currentness.challenge":
        return ("credential_currentness_challenges",)
    if operation in {"credential.currentness.register", "credential.currentness.quiesce", "credential.currentness.admit"}:
        return ("credential_currentness_holders",)
    if operation in {"oauth.refresh-cleanup.claim", "oauth.refresh-cleanup.contact", "oauth.refresh-cleanup.finish"}:
        return ("credentials",) + family_group.TABLES
    raise ValueError("operation has no complete OAuth population contract")


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns, operation="oauth.pending.activate"):
    # No new allowance and no arbitrary success/effect callback.
    profile.require(type(deadline_ns) is int)
    def check():
        profile.require(time.monotonic_ns() < deadline_ns, "OAuth inventory original deadline expired")
    work.prepare_copy(before_roots)
    roots = {entry["table"]: entry for entry in before_roots}
    if operation in family_group.OPERATIONS:
        work.prepare_scan(selected_rows)
        profile.require(sum(entry["table"] in family_group.TABLES and entry["present"] for entry in selected_rows) <= family_group.MAX_ROWS,
            "combined OAuth family retirement inventory exceeds32")
    for table in tables_for(operation):
        check()
        work.prepare_scan(selected_rows)
        rows = [entry for entry in selected_rows if entry["table"] == table and entry["present"]]
        maximum = 32 if operation in {"oauth.measured-capture-retirement.inspect", "oauth.measured-capture-retirement.claim"} else maximum_rows(table)
        profile.require(table in roots and len(rows) <= maximum, "OAuth complete inventory exceeds its source-fixed table bound")
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
