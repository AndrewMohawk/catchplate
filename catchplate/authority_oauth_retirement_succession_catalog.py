"""Dependency-free, closed source inventory; never a runtime permission.

The operation contract and actual producers share this finite acquisition map.
No incoming operation may name a different snapshot table or broaden a write.
"""
from types import MappingProxyType

SNAPSHOT_PARTS = MappingProxyType({
    "credentials": "credentials", "pending": "pending_oauth_credentials", "setup": "setup_sessions",
    "exchanges": "oauth_exchange_reservations", "refreshes": "oauth_refresh_reservations", "work": "oauth_revocation_work",
    "initial-custody": "oauth_measured_exchange_custody", "setup-custody": "oauth_measured_setup_custody",
    "reconnect-custody": "oauth_measured_reconnect_custody", "succession-custody": "oauth_measured_succession_custody",
    "refresh-custody": "oauth_measured_refresh_custody",
    "exchange-cleanup": "oauth_revocation_reservations", "exchange-attempts": "oauth_revocation_attempts",
    "refresh-cleanup": "oauth_refresh_cleanup_reservations", "refresh-attempts": "oauth_refresh_cleanup_attempts",
    "refresh-cleanup-custody": "oauth_measured_refresh_cleanup_custody",
    "pending-cleanup": "oauth_pending_retirement_reservations", "pending-attempts": "oauth_pending_retirement_attempts",
    "pending-cleanup-custody": "oauth_measured_pending_retirement_custody",
    "capture-cleanup": "oauth_capture_retirement_reservations", "capture-attempts": "oauth_capture_retirement_attempts",
    "capture-cleanup-custody": "oauth_measured_capture_retirement_custody",
    "family-fences": "oauth_family_retirements", "pending-fences": "oauth_pending_family_retirements",
    "provider-fences": "oauth_provider_retirements", "reconnect-authorizations": "oauth_reconnect_authorizations",
    "succession-materials": "oauth_retirement_succession_materials", "succession-attempts": "oauth_retirement_succession_attempts",
})
SNAPSHOT_OPERATIONS = MappingProxyType({"oauth.succession.snapshot." + part: part for part in SNAPSHOT_PARTS})
HUMAN_OPERATIONS = frozenset("oauth.succession." + phase for phase in
    ("authorize", "decide", "fence", "activation-request", "activation-decide", "activate"))
NATIVE_OPERATIONS = frozenset("oauth.measured-succession." + phase for phase in
    ("inspect", "material-claim", "contact", "finish", "recover", "prepare", "claim", "capture", "stage", "cancel"))
OPERATIONS = HUMAN_OPERATIONS | NATIVE_OPERATIONS | frozenset(SNAPSHOT_OPERATIONS)
ASSERTION_OPERATIONS = HUMAN_OPERATIONS - {"oauth.succession.fence"}
NEW_TABLES = ("oauth_retirement_scope_heads", "oauth_retirement_scopes", "oauth_retirement_successions",
    "oauth_measured_succession_custody", "oauth_retirement_succession_materials", "oauth_retirement_succession_attempts",
    "oauth_retirement_successor_generations", "oauth_retirement_succession_snapshots")
GUARDED_OPERATIONS = frozenset({"oauth.exchange.prepare", "oauth.exchange.claim", "oauth.pending.stage", "oauth.pending.activate",
    "oauth.setup.create", "oauth.setup.activate", "oauth.measured-exchange.prepare", "oauth.measured-exchange.claim", "oauth.measured-exchange.stage",
    "oauth.measured-setup.prepare", "oauth.measured-setup.claim", "oauth.measured-setup.stage",
    "oauth.reconnect.authorize", "oauth.reconnect.fence", "oauth.reconnect.activate", "oauth.measured-reconnect.prepare",
    "oauth.measured-reconnect.claim", "oauth.measured-reconnect.stage", "oauth.revocation.claim", "oauth.revocation.contact",
    "oauth.refresh-cleanup.claim", "oauth.refresh-cleanup.contact", "oauth.measured-refresh-cleanup.claim", "oauth.measured-refresh-cleanup.contact",
    "oauth.measured-pending-retirement.claim", "oauth.measured-pending-retirement.contact",
    "oauth.measured-capture-retirement.claim", "oauth.measured-capture-retirement.contact"})
CONTINUATION_OPERATIONS = frozenset({"oauth.refresh.claim", "oauth.refresh.retain", "oauth.refresh.commit",
    "oauth.measured-refresh.inspect", "oauth.measured-refresh.claim", "oauth.measured-refresh.capture",
    "oauth.measured-refresh.commit", "oauth.measured-refresh.recover"})
COMMIT_OPERATIONS = frozenset({"oauth.refresh.commit", "oauth.measured-refresh.commit"})
PREDECESSOR_TABLES = ("oauth_family_retirements", "oauth_refresh_cleanup_reservations", "oauth_pending_family_retirements",
    "oauth_pending_retirement_reservations", "oauth_provider_retirements", "oauth_capture_retirement_reservations",
    "oauth_reconnect_authorizations", "oauth_retirement_scopes", "oauth_retirement_successions")


def consumer_reads(operation):
    if operation in CONTINUATION_OPERATIONS:
        return ("oauth_retirement_scope_heads", "oauth_retirement_successor_generations")
    return ("oauth_retirement_scope_heads",) if operation in GUARDED_OPERATIONS else ()


def consumer_writes(operation):
    return ("oauth_retirement_successor_generations",) if operation in COMMIT_OPERATIONS else ()


def read_tables(operation):
    if operation not in OPERATIONS:
        raise ValueError("not a source-owned succession operation")
    tables = {"oauth_retirement_successions", "oauth_retirement_scope_heads", "rbac_role_bindings"}
    if operation in SNAPSHOT_OPERATIONS:
        return tuple(sorted(tables | {"oauth_retirement_succession_snapshots", SNAPSHOT_PARTS[SNAPSHOT_OPERATIONS[operation]]}))
    tables.update({"credentials", "credential_generations"})
    if operation in {"oauth.succession.authorize", "oauth.succession.decide", "oauth.succession.fence"}:
        tables.update(PREDECESSOR_TABLES)
    if operation in {"oauth.succession.decide", "oauth.succession.fence"}:
        tables.add("oauth_retirement_succession_snapshots")
    if operation == "oauth.succession.fence":
        # All 28 current roots are retained from this actual atomic transaction,
        # not copied from the earlier acquisition slots.
        tables.update(SNAPSHOT_PARTS.values())
        tables.update({"webauthn_credentials", "webauthn_trust_publications", "webauthn_trust_publication_high_water"})
    if operation not in {"oauth.succession.authorize", "oauth.succession.decide"}:
        tables.update({"credential_currentness_roots", "credential_currentness_barriers", "oauth_retirement_scopes"})
    if operation in NATIVE_OPERATIONS or operation in {"oauth.succession.activation-request", "oauth.succession.activation-decide", "oauth.succession.activate"}:
        tables.update({"oauth_retirement_succession_materials", "oauth_retirement_succession_attempts", "oauth_measured_succession_custody",
            "oauth_exchange_reservations", "oauth_retirement_successor_generations"})
    if operation in HUMAN_OPERATIONS:
        tables.add("control_plane_approvals")
    return tuple(sorted(tables))


def write_tables(operation):
    if operation not in OPERATIONS:
        raise ValueError("not a source-owned succession operation")
    tables = {"metadata_audit_outbox"}
    if operation in SNAPSHOT_OPERATIONS:
        tables.add("oauth_retirement_succession_snapshots")
    if operation in {"oauth.succession.authorize", "oauth.succession.decide", "oauth.succession.fence", "oauth.succession.activate"}:
        tables.add("oauth_retirement_successions")
    if operation in HUMAN_OPERATIONS:
        tables.add("control_plane_approvals")
    if operation == "oauth.succession.fence":
        tables.update({"credentials", "credential_currentness_roots", "credential_currentness_barriers", "oauth_retirement_scope_heads", "oauth_retirement_scopes"})
    if operation == "oauth.measured-succession.material-claim":
        tables.add("oauth_retirement_succession_materials")
    if operation in {"oauth.measured-succession.contact", "oauth.measured-succession.finish"}:
        tables.add("oauth_retirement_succession_attempts")
    if operation in {"oauth.measured-succession." + phase for phase in ("prepare", "claim", "capture", "stage", "cancel")}:
        tables.update({"oauth_measured_succession_custody", "oauth_exchange_reservations"})
    if operation == "oauth.succession.activate":
        tables.update({"credentials", "credential_generations", "credential_currentness_roots", "oauth_measured_succession_custody",
            "oauth_retirement_successor_generations"})
    return tuple(sorted(tables))


def mutation_kinds(operation):
    append_only = {"oauth_retirement_scopes", "oauth_retirement_succession_snapshots", "oauth_retirement_succession_materials",
        "oauth_retirement_successor_generations", "metadata_audit_outbox"}
    return {table: ("INSERT",) if table in append_only else ("INSERT", "UPDATE") for table in write_tables(operation)}
