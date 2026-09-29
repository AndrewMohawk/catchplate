"""Authenticated successor association, never an old-fence bypass flag."""
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_oauth_retirement_succession_records as records
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_provider_retirement as provider_retirement
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_credential_currentness as root_profile
from serverware import authority_oauth_retirement_succession_catalog as catalog

CONTINUATION_OPERATIONS = catalog.CONTINUATION_OPERATIONS
COMMIT_OPERATIONS = catalog.COMMIT_OPERATIONS
# Existing purposes may retain a response after fencing, but cannot acquire a
# new token contact, stage a competing token, or reset a previous generation.
GUARDED_OPERATIONS = catalog.GUARDED_OPERATIONS


def query(operation, provider_id):
    p.require(operation in GUARDED_OPERATIONS | CONTINUATION_OPERATIONS)
    return records.head_query(operation, provider_id)


def association_queries(operation, credential_id, version):
    p.require(operation in CONTINUATION_OPERATIONS)
    result = [shared._query(operation=operation, name="current_retirement_successor", table=p.ASSOCIATION_TABLE,
        key={"id": p.association_id(credential_id, version)})]
    if operation in COMMIT_OPERATIONS:
        p.require(version < 2**63 - 1)
        result.append(shared._query(operation=operation, name="next_retirement_successor", table=p.ASSOCIATION_TABLE,
            key={"id": p.association_id(credential_id, version + 1)}, require_absence=True))
    return tuple(result)


def inspection_queries(operation, credential_id):
    """Select positive owners by the actual already-selected credential version.

    No derived UUID is accepted from an inspection caller. A successor path
    requires both positive authenticated rows and recomputes their exact IDs;
    a zero-result range never supplies absence or successor permission.
    """
    p.require(operation == "oauth.measured-refresh.inspect")
    version = core.SelectedRowFieldReference("credentials", {"id": credential_id}, "credential_version")
    return tuple(core.BoundedQuery(query_id=core.query_program_id(operation, name, table), table=table,
        predicates=(core.QueryPredicate("credential_id", "eq", credential_id), core.QueryPredicate("credential_version", "eq", version)),
        order_by=(core.QueryOrder("id"),), maximum_rows=2, proof_primitive="bounded-limit-plus-one", work_units=2)
        for name, table in (("inspection_successor", p.ASSOCIATION_TABLE), ("inspection_currentness", root_profile.ROOT_TABLE)))


def require_unassigned(context, provider_id):
    p.require(context.operation in GUARDED_OPERATIONS)
    selected = context.exact(p.HEAD_TABLE, {"id": p.head_id(provider_id)})
    p.require(not selected["present"], "an actual retired-scope head requires its independently authorized successor purpose")


def require_observation(context, enrollment_original):
    """Completed/history read only; never a refresh recovery-processing claim."""
    p.require(context.operation in {"oauth.measured-refresh.inspect", "oauth.measured-refresh.recover"})
    raw = p.activation.enrollment_bytes(enrollment_original)
    provider = enrollment.enrollment_document(raw)["payload"]["providerId"]
    selected = context.exact(p.HEAD_TABLE, {"id": p.head_id(provider)})
    if not selected["present"]:
        provider_retirement.require_open(context, provider)
    else:
        head = shared._row(selected, "actual retained scope for observation only")
        records.head_original(head); p.require(head["provider_id"] == provider)


def require_current(context, credential, enrollment_original):
    p.require(context.operation in CONTINUATION_OPERATIONS)
    refresh.credential_original(credential)
    metadata = shared._canonical_stored_mapping(credential["metadata"], "actual successor metadata")
    provider = metadata.get("provider_id"); p.require(provider in {"google", "x"})
    raw = p.activation.enrollment_bytes(enrollment_original)
    p.require(metadata.get("provider_identity_verified") is True and metadata.get("oauth_application_owner") == enrollment.association(raw))
    head_selected = context.exact(p.HEAD_TABLE, {"id": p.head_id(provider)})
    if not head_selected["present"]:
        if context.operation not in {"oauth.refresh.retain", "oauth.measured-refresh.capture"}:
            provider_retirement.require_open(context, provider)
        family.require_open_from_population(context, provider, metadata["provider_subject"])
        return None
    head = shared._row(head_selected, "actual monotonic retirement head"); records.head_original(head)
    if head["scope_kind"] == "family" and head["provider_subject"] != metadata["provider_subject"]:
        if context.operation not in {"oauth.refresh.retain", "oauth.measured-refresh.capture"}:
            provider_retirement.require_open(context, provider)
        family.require_open_from_population(context, provider, metadata["provider_subject"])
        return None
    if context.operation == "oauth.measured-refresh.inspect":
        p.require(len(context.present_rows(p.ASSOCIATION_TABLE)) == len(context.present_rows(root_profile.ROOT_TABLE)) == 1)
    selected = context.exact(p.ASSOCIATION_TABLE, {"id": p.association_id(credential["id"], credential["credential_version"])})
    association = shared._row(selected, "actual protected successor generation"); records.association_original(association)
    _, root = currentness.require_root(context, credential["id"], credential["credential_version"])
    p.require(credential["lifecycle_status"] == "active" and credential["revocation_requested_at"] is None and credential["revocation_error"] is None
        and association["credential_id"] == credential["id"] and association["credential_version"] == credential["credential_version"]
        and association["scope_id"] == head["scope_id"] and association["scope_sha256"] == head["scope_sha256"]
        and association["provider_id"] == provider and association["provider_subject"] == metadata["provider_subject"]
        and association["credential_sha256"] == p.sha256(refresh.credential_original(credential))
        and association["enrollment_sha256"] == p.sha256(raw)
        and association["root_origin_request_digest"] == root["origin_request_digest"]
        and root["credential_id"] == credential["id"] and root["credential_version"] == credential["credential_version"])
    return association


def propagate(context, previous, replacement, enrollment_original):
    """Only the actual refresh COMMIT appends this alongside its genuine root."""
    p.require(context.operation in COMMIT_OPERATIONS)
    association = require_current(context, previous, enrollment_original)
    selected = context.exact(p.ASSOCIATION_TABLE, {"id": p.association_id(previous["id"], previous["credential_version"] + 1)})
    p.require(not selected["present"])
    if association is None:
        return ()
    p.require(replacement["id"] == previous["id"] and replacement["credential_version"] == previous["credential_version"] + 1)
    row = {**association, "id": p.association_id(replacement["id"], replacement["credential_version"]),
        "credential_version": replacement["credential_version"], "credential_sha256": p.sha256(refresh.credential_original(replacement)),
        "root_origin_request_digest": context.request_digest, "previous_association_sha256": p.sha256(records.association_original(association)),
        "created_at": context.database_now.isoformat()}
    records.association_original(row)
    return (core.mutation(operation=context.operation, selected=selected, row=row),)
