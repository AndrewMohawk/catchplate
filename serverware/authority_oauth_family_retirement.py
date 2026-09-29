"""Permanent local provider-account fence; never proof of external ownership."""
import uuid

from serverware import authority_oauth_refresh_cleanup as profile
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_oauth_family_query_group as group

TABLE = "oauth_family_retirements"
FIELDS = frozenset({"id", "provider_id", "provider_subject", "authorization_sha256", "work_id", "credential_id", "credential_version", "created_at"})


def family_id(provider, subject):
    profile.require(provider in {"google", "x"}); profile.text(subject, 512)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "serverware.oauthFamilyRetirement/v1:" + profile.canonical([provider, subject]).decode("ascii")))


def query(operation, provider, subject):
    return shared._query(operation=operation, name="oauth_family_retirement", table=TABLE, key={"id": family_id(provider, subject)})


def population_query(operation):
    """Absence is admitted only with the planner's complete-root inventory proof."""
    from serverware import authority_oauth_inventory as inventory
    return core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", TABLE),
        table=TABLE, predicates=(), order_by=(core.QueryOrder("id"),),
        maximum_rows=inventory.maximum_rows(TABLE) + 1, proof_primitive="bounded-limit-plus-one",
        work_units=inventory.maximum_rows(TABLE) + 1)


def population_queries(operation):
    return group.queries(operation)


def order_populations(operation, queries):
    return group.ordered(operation, queries)


def pending_query(operation, provider, subject):
    return shared._query(operation=operation, name="oauth_pending_family_retirement", table=group.TABLES[1],
        key={"id": family_id(provider, subject)})


def require_open_from_population(context, provider, subject):
    """Caller must acquire this complete population in its same proved transaction."""
    key = family_id(provider, subject)
    for selected in context.present_rows(TABLE):
        row = shared._row(selected, "complete OAuth family retirement inventory")
        profile.require(set(row) == FIELDS and row["id"] == family_id(row["provider_id"], row["provider_subject"]))
        profile.require(row["id"] != key, "OAuth family retirement blocks activation, refresh and reuse")
    from serverware import authority_oauth_measured_pending_retirement as pending
    for selected in context.present_rows(pending.FAMILY_TABLE):
        row = shared._row(selected, "complete pending family retirement inventory")
        profile.require(set(row) == pending.FAMILY_FIELDS and row["id"] == family_id(row["provider_id"], row["provider_subject"]))
        profile.require(row["id"] != key, "pending family retirement blocks activation, refresh and reuse")


def require_single_lineage(context, grant, current):
    scope = grant["familyScope"]
    for selected in context.present_rows("credentials"):
        row = shared._row(selected, "complete local credential family inventory")
        if row["kind"] != "oauth2":
            continue
        metadata = shared._canonical_stored_mapping(row["metadata"], "local OAuth family metadata")
        # Same provider account is conservative across all locally represented
        # OAuth clients. Independent grant covers external project/family risk.
        if metadata.get("provider_id") == grant["providerId"] and metadata.get("provider_subject") == scope["providerSubject"]:
            profile.require(row["id"] == current["id"], "family retirement requires one exact complete local lineage")


def claim(context, grant, authorization_sha256):
    require_open_from_population(context, grant["providerId"], grant["familyScope"]["providerSubject"])
    profile.require(sum(len(context.present_rows(table)) for table in group.TABLES) < group.MAX_ROWS,
        "combined family retirement capacity is full; no archival or overwrite permission")
    key = {"id": family_id(grant["providerId"], grant["familyScope"]["providerSubject"])}
    selected = context.exact(TABLE, key)
    profile.require(not selected["present"], "family retirement identity already consumed")
    row = {**key, "provider_id": grant["providerId"], "provider_subject": grant["familyScope"]["providerSubject"],
        "authorization_sha256": authorization_sha256, "work_id": grant["workId"], "credential_id": grant["credentialId"],
        "credential_version": grant["credentialVersion"], "created_at": context.database_now.isoformat()}
    return core.mutation(operation=context.operation, selected=selected, row=row)


def require_claim(context, grant, authorization_sha256):
    key = {"id": family_id(grant["providerId"], grant["familyScope"]["providerSubject"])}
    row = shared._row(context.exact(TABLE, key), "retained family retirement")
    profile.require(set(row) == FIELDS and row["id"] == key["id"] and row["provider_id"] == grant["providerId"]
        and row["provider_subject"] == grant["familyScope"]["providerSubject"] and row["authorization_sha256"] == authorization_sha256
        and row["work_id"] == grant["workId"] and row["credential_id"] == grant["credentialId"] and row["credential_version"] == grant["credentialVersion"])


def require_open(context, provider, subject):
    """Actual effect callers must select query() in their same transaction."""
    profile.require(not context.exact(TABLE, {"id": family_id(provider, subject)})["present"],
        "OAuth family retirement blocks activation, refresh and reuse")
    profile.require(not context.exact(group.TABLES[1], {"id": family_id(provider, subject)})["present"],
        "pending family retirement blocks activation, refresh and reuse")
