"""Fixed complete canary populations, never caller-selected SQL or authority."""
import time

from serverware import authority_policy_canary as profile
from serverware import authority_contract as contract
from serverware import authority_radix_proof as radix

# Audit outbox and transition history are addressed by exact derived primary
# keys, not copied as a complete unbounded audit-history population.
TABLES = contract.POLICY_CANARY_INTAKE_TABLES
HEAD_TABLES = contract._CANARY_INTAKE_HEADS
AUDIT_TABLES = ("metadata_audit_outbox", "policy_authority_transition_audits")


def key(table, row):
    from serverware import authority_primary_contract as primary
    profile.require(table in TABLES or table in AUDIT_TABLES)
    return {field: row[field] for field in primary.PRIMARY_KEY_COLUMNS[table]}


def snapshot(value, events):
    profile.require(type(value) is dict and set(value) == set(TABLES)
        and type(events) is list and 1 <= len(events) <= profile.LIMITS["events"])
    count = 0
    for table in TABLES:
        rows = value[table]
        profile.require(type(rows) is list and len(rows) <= profile.MAX_ROWS)
        identities = []
        for row in rows:
            profile.require(type(row) is dict and bool(row) and all(type(name) is str for name in row)
                and all(item is None or type(item) in {str, int, bool} for item in row.values()))
            identities.append(profile.canonical(key(table, row)))
        profile.require(identities == sorted(set(identities)), "canary snapshot repeats or reorders a primary key")
        count += len(rows) + 1
    profile.require(count <= profile.LIMITS["queryRows"], "complete canary populations exceed the finite query budget")
    return value


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns, operation):
    profile.require(operation == profile.OP_INTAKE and type(deadline_ns) is int)
    work.prepare_copy(before_roots)
    roots = {entry["table"]: entry for entry in before_roots}
    for table in TABLES:
        profile.require(time.monotonic_ns() < deadline_ns)
        work.prepare_scan(selected_rows)
        rows = [entry for entry in selected_rows if entry["table"] == table and entry["present"]]
        profile.require(table in roots and len(rows) <= profile.MAX_ROWS)
        nodes = {}
        work.charge(hashes=65 * 66 // 2)
        for entry in rows:
            profile.require(time.monotonic_ns() < deadline_ns)
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["row"], ensure_ascii=False)
            work.charge(hashes=3)
            key_digest = radix.authenticated_key_digest(table, entry["key"])
            path = key_digest[7:]
            profile.require(path not in nodes)
            row_digest = radix._tree_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                table.encode("ascii"), radix.tree_json_bytes(entry["row"]))
            nodes[path] = radix._tree_digest("serverware.policyAuthorityAuthenticatedLeaf/v1", table.encode("ascii"),
                key_digest.encode("ascii"), radix.tree_json_bytes(entry["key"]), row_digest.encode("ascii"))
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
                work.prepare_encoding(children, ensure_ascii=False); work.charge(hashes=1)
                nodes[parent] = radix._tree_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                    str(depth).encode("ascii"), radix.tree_json_bytes(children))
        profile.require(nodes.get("", radix.empty_digest(0)) == roots[table]["rootDigest"],
            "canary population is incomplete against its actual transaction before-root")
    profile.require(time.monotonic_ns() < deadline_ns)
