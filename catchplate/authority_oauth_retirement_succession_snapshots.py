"""Fixed complete parts, retained by protected writes, never cached authority.

Each part is tied to the independently signed grant and its original admission
expiry. FENCE re-admits every current source before-root in the same transaction
and reconstructs every retained population on that transaction's work meter.
There is no refresh, overwrite, arbitrary table, union-root or partial fence.
"""
import time
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as records
from catchplate import authority_radix_proof as radix
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared

FIELDS = frozenset({"id", "authorization_id", "authorization_sha256", "part", "root_original_json",
    "rows_original_json", "acquisition_request_digest", "created_at", "expires_at"})
MAX_PART_BYTES = 1024 * 1024
MAX_GRAPH_BYTES = 4 * 1024 * 1024
ROOT_OPERATIONS = frozenset(p.SNAPSHOT_OPERATIONS) | {p.OP_FENCE}


def original(value):
    raw = records.original(value, FIELDS, maximum=MAX_PART_BYTES)
    p.require(value["part"] in p.SNAPSHOT_PARTS
        and value["id"] == p.snapshot_id(value["authorization_id"], value["part"]))
    p.digest(value["authorization_sha256"]); p.digest(value["acquisition_request_digest"])
    root = records.stored(value["root_original_json"], 8192)
    p.require(set(root) == {"table", "rootRevision", "rootDigest", "leafCount"}
        and root["table"] == p.SNAPSHOT_PARTS[value["part"]]
        and type(root["rootRevision"]) is int and 0 <= root["rootRevision"] <= 2**63 - 1
        and type(root["leafCount"]) is int and 0 <= root["leafCount"] <= p.snapshot_limit(value["part"]))
    p.digest(root["rootDigest"])
    rows = records.array(value["rows_original_json"], MAX_PART_BYTES)
    p.require(len(rows) == root["leafCount"] and all(type(row) is dict and type(row.get("id")) is str for row in rows)
        and [row["id"] for row in rows] == sorted({row["id"] for row in rows}))
    return raw


def queries(operation, authorization_id):
    p.require(operation in p.SNAPSHOT_OPERATIONS or operation in {p.OP_AUTHORIZE_DECIDE, p.OP_FENCE})
    parts = (p.SNAPSHOT_OPERATIONS[operation],) if operation in p.SNAPSHOT_OPERATIONS else tuple(sorted(p.SNAPSHOT_PARTS))
    result = [shared._query(operation=operation, name="succession_snapshot_" + part.replace("-", "_"),
        table=p.SNAPSHOT_TABLE, key={"id": p.snapshot_id(authorization_id, part)},
        require_absence=operation in p.SNAPSHOT_OPERATIONS) for part in parts]
    if operation in p.SNAPSHOT_OPERATIONS:
        table = p.SNAPSHOT_PARTS[parts[0]]
        bound = p.snapshot_limit(parts[0]) + 1
        result.append(core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", table), table=table,
            predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=bound,
            proof_primitive="bounded-limit-plus-one", work_units=bound))
    return tuple(result)


def _root(roots, table):
    p.require(type(roots) is tuple, "actual planner before-roots were not retained")
    values = [root for root in roots if root["table"] == table]
    p.require(len(values) == 1, "actual authenticated source root is missing or duplicated")
    return values[0]


def create(context, values, journal):
    p.require(context.operation in p.SNAPSHOT_OPERATIONS and journal["status"] == "requested")
    grant = p.grant_document(p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES))["payload"]
    now = shared._database_epoch_ns(context.database_now)
    p.require(values["request"]["authorizationRowSha256"] == p.sha256(records.journal_original(journal))
        and grant["issuedAtEpochNs"] <= now < grant["admissionExpiresAtEpochNs"])
    part = p.SNAPSHOT_OPERATIONS[context.operation]; table = p.SNAPSHOT_PARTS[part]
    root = _root(context.retirement_succession_primary_roots, table)
    wanted = next(item["root"] for item in grant["inventoryRoots"] if item["part"] == part)
    p.require(root == wanted, "snapshot root differs from the original independently signed grant")
    selected = context.exact(p.SNAPSHOT_TABLE, {"id": p.snapshot_id(grant["authorizationId"], part)})
    p.require(not selected["present"], "snapshot acquisition is consumed; lookup does not authorize replacement")
    rows = sorted((shared._row(item, "actual complete snapshot row") for item in context.present_rows(table)), key=lambda row: row["id"])
    p.require(len(rows) == root["leafCount"] <= p.snapshot_limit(part))
    # The actual planner already reconstructed this one complete population;
    # no SQL count or caller root reaches this protected write as proof.
    row = {"id": p.snapshot_id(grant["authorizationId"], part), "authorization_id": grant["authorizationId"],
        "authorization_sha256": journal["authorization_sha256"], "part": part,
        "root_original_json": p.canonical(root).decode("ascii"), "rows_original_json": p.canonical(rows).decode("ascii"),
        "acquisition_request_digest": context.request_digest, "created_at": context.database_now.isoformat(),
        "expires_at": journal["admission_expires_at"]}
    original(row)
    return row, core.mutation(operation=context.operation, selected=selected, row=row)


def _reconstruct(table, rows, root, work, deadline_ns):
    def check():
        p.require(time.monotonic_ns() < deadline_ns, "original succession acquisition deadline expired")
    nodes = {}; work.charge(hashes=65 * 66 // 2)
    for row in rows:
        check(); key = {"id": row["id"]}
        work.prepare_encoding(key, ensure_ascii=False); work.prepare_encoding(key, ensure_ascii=False)
        work.prepare_encoding(row, ensure_ascii=False); work.charge(hashes=3)
        key_digest = radix.authenticated_key_digest(table, key); path = key_digest[7:]
        p.require(path not in nodes)
        row_digest = radix._tree_digest("catchplate.policyAuthorityAuthenticatedRow/v1", table.encode("ascii"), radix.tree_json_bytes(row))
        nodes[path] = radix._tree_digest("catchplate.policyAuthorityAuthenticatedLeaf/v1", table.encode("ascii"),
            key_digest.encode("ascii"), radix.tree_json_bytes(key), row_digest.encode("ascii"))
    for depth in range(63, -1, -1):
        check(); parents = {}
        for path, value in nodes.items():
            parent = path[:-1]
            if parent not in parents:
                parents[parent] = [radix.empty_digest(depth + 1)] * 16
            parents[parent][int(path[-1], 16)] = value
        nodes = {}
        for parent, children in parents.items():
            work.prepare_encoding(children, ensure_ascii=False); work.charge(hashes=1)
            nodes[parent] = radix._tree_digest("catchplate.policyAuthorityAuthenticatedNode/v1",
                str(depth).encode("ascii"), radix.tree_json_bytes(children))
    p.require(nodes.get("", radix.empty_digest(0)) == root["rootDigest"], "retained part is not complete at the current root")


def validate_fence_inputs(*, selected_rows, before_roots, work, deadline_ns):
    """Called by the actual planner after primary proof verification only."""
    work.prepare_scan(selected_rows); work.prepare_copy(before_roots)
    snapshots = [shared._row(item, "authenticated protected snapshot") for item in selected_rows
        if item["table"] == p.SNAPSHOT_TABLE and item["present"]]
    p.require(len(snapshots) == len(p.SNAPSHOT_PARTS) and {item["part"] for item in snapshots} == set(p.SNAPSHOT_PARTS))
    total = 0
    for row in snapshots:
        work.prepare_encoding(row); original(row)
        total += len(row["rows_original_json"].encode("ascii")); p.require(total <= MAX_GRAPH_BYTES)
        root = records.stored(row["root_original_json"], 8192)
        p.require(root == _root(before_roots, root["table"]), "source changed after acquisition; no rebase or split fence")
        rows = records.array(row["rows_original_json"], MAX_PART_BYTES)
        _reconstruct(root["table"], rows, root, work, deadline_ns)


class RetainedGraph:
    """Owned data graph from exact protected snapshots, not a permission type."""
    def __init__(self, context, grant, journal):
        p.require(context.operation == p.OP_FENCE)
        self._tables = {}; self.originals = []; total = 0
        now = shared._database_epoch_ns(context.database_now)
        p.require(now < grant["admissionExpiresAtEpochNs"])
        for item in grant["inventoryRoots"]:
            part, root = item["part"], item["root"]
            row = shared._row(context.exact(p.SNAPSHOT_TABLE, {"id": p.snapshot_id(grant["authorizationId"], part)}), "actual retained part")
            original(row)
            p.require(row["authorization_id"] == grant["authorizationId"] and row["authorization_sha256"] == journal["authorization_sha256"]
                and row["part"] == part and row["expires_at"] == journal["admission_expires_at"]
                and row["root_original_json"] == p.canonical(root).decode("ascii")
                and _root(context.retirement_succession_primary_roots, root["table"]) == root)
            total += len(row["rows_original_json"].encode("ascii")); p.require(total <= MAX_GRAPH_BYTES)
            self._tables[root["table"]] = records.array(row["rows_original_json"], MAX_PART_BYTES)
            self.originals.append(original(row).decode("ascii"))

    def rows(self, table):
        p.require(table in self._tables)
        return self._tables[table]

    def row(self, table, identifier, *, optional=False):
        found = [row for row in self.rows(table) if row["id"] == identifier]
        p.require(len(found) <= 1 and (optional or len(found) == 1), "actual retained source association is missing")
        return found[0] if found else None
