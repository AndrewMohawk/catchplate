"""One fixed two-root admission group; never generic query-budget subtraction.

Both independent SQL reads keep limit33, work33 and their own complete-root
proof. The declared shared population allowance is34 (32 rows plus the two
sentinels); actual combined observations above32 refuse before any dependent
source-row proof. No union substitutes for either authenticated root.
"""
TABLES = ("oauth_family_retirements", "oauth_pending_family_retirements")
MAX_ROWS = 32
DECLARED_ROWS = 34
OPERATIONS = frozenset({
    "oauth.pending.activate", "oauth.pending.stage", "oauth.measured-exchange.stage",
    "oauth.measured-setup.stage", "oauth.setup.activate",
    "oauth.refresh.claim", "oauth.refresh.retain", "oauth.refresh.commit",
    "oauth.measured-refresh.inspect", "oauth.measured-refresh.claim", "oauth.measured-refresh.capture",
    "oauth.measured-refresh.commit", "oauth.measured-refresh.recover",
    "oauth.refresh-cleanup.claim", "oauth.refresh-cleanup.contact", "oauth.refresh-cleanup.finish",
    "oauth.measured-refresh-cleanup.inspect", "oauth.measured-refresh-cleanup.claim", "oauth.measured-refresh-cleanup.contact",
    "oauth.measured-refresh-cleanup.finish", "oauth.measured-refresh-cleanup.recover",
    "oauth.measured-pending-retirement.inspect", "oauth.measured-pending-retirement.claim",
    "oauth.measured-pending-retirement.contact", "oauth.measured-pending-retirement.finish", "oauth.measured-pending-retirement.recover",
})


def queries(operation):
    from serverware import authority_transition_core as core
    if operation not in OPERATIONS:
        raise core.TransitionKernelError("operation has no fixed family inventory admission group")
    return tuple(core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", table),
        table=table, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=33,
        proof_primitive="bounded-limit-plus-one", work_units=33) for table in TABLES)


def _members(operation, declarations):
    from serverware import authority_transition_core as core
    expected = queries(operation)
    members = tuple(query for query in declarations if query.query_id in {item.query_id for item in expected})
    if (len(members) != 2 or any(type(query) is not core.BoundedQuery for query in members)
            or any(sum(query == item for query in members) != 1 for item in expected)):
        raise core.TransitionKernelError("family admission group is missing or has a forged member")
    return expected


def ordered(operation, declarations):
    """Fixed kernel producers place the two independent reads before references."""
    if operation not in OPERATIONS:
        return declarations
    expected = _members(operation, declarations)
    names = {item.query_id for item in expected}
    return expected + tuple(query for query in declarations if query.query_id not in names)


def declared_rows(operation, declarations):
    if operation not in OPERATIONS:
        return sum(query.maximum_rows for query in declarations)
    from serverware import authority_transition_core as core
    expected = _members(operation, declarations)
    if declarations[:2] != expected:
        raise core.TransitionKernelError("family reads must precede every dependent proof acquisition")
    return DECLARED_ROWS + sum(query.maximum_rows for query in declarations[2:])


class Acquisition:
    """Internal bookkeeping for the actual SQL loop; not an authority carrier."""
    def __init__(self, operation, declarations):
        self.expected = queries(operation) if operation in OPERATIONS else ()
        if self.expected:
            declared_rows(operation, declarations)
        self.counts = []

    def before(self, query):
        from serverware import authority_transition_core as core
        if self.expected and len(self.counts) < 2 and query != self.expected[len(self.counts)]:
            raise core.TransitionKernelError("family observations are incomplete before another acquisition")

    def record(self, query, count):
        from serverware import authority_transition_core as core
        if not self.expected or len(self.counts) == 2:
            return
        if query != self.expected[len(self.counts)] or type(count) is not int or not 0 <= count <= MAX_ROWS:
            raise core.TransitionKernelError("family inventory sentinel or mismatching acquisition")
        self.counts.append(count)
        if sum(self.counts) > MAX_ROWS:
            raise core.TransitionKernelError("combined OAuth family retirement capacity exceeded")

    def finish(self):
        from serverware import authority_transition_core as core
        if self.expected and len(self.counts) != 2:
            raise core.TransitionKernelError("family inventory omitted an independently read root")


def validate_observations(operation, declarations, records):
    if operation not in OPERATIONS:
        return
    from serverware import authority_transition_core as core
    observed = Acquisition(operation, declarations)
    if len(records) != len(declarations):
        raise core.TransitionKernelError("family observation inventory differs from source declarations")
    for query, record in zip(declarations, records):
        observed.before(query)
        if record.query_id != query.query_id:
            raise core.TransitionKernelError("family query observation has another source identity")
        observed.record(query, record.returned_row_count)
    observed.finish()
