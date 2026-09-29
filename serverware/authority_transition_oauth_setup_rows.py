"""Fixed Setup row/event CAS producers shared by the two actual OAuth owners.

No callbacks, database writes or supplied success flags. Every input is rejoined
to the genuine kernel context and every mutation retains its actual prestate.
"""
from datetime import datetime, timedelta, timezone
from serverware import authority_oauth_setup as profile
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared


def _original(text):
    profile.require(type(text) is str)
    raw = text.encode("ascii")
    row = profile.document(raw, profile.MAX_ROW_BYTES)
    profile.require(profile.row_original(row) == raw)
    return row


def event_queries(operation, session_id, next_revision):
    profile.require(type(next_revision) is int and 0 <= next_revision <= 3)
    item_id = profile.event_id(session_id, next_revision + 1)
    return (shared._query(operation=operation, name="setup_event", table="setup_session_events", key={"id": item_id}, require_absence=True),
        shared._query(operation=operation, name="setup_audit_link", table=profile.AUDIT_LINK_TABLE, key={"id": item_id}, require_absence=True))


def current(context, binding, *, phase, actor):
    bound = profile.binding(binding)
    selected = context.exact("setup_sessions", {"id": bound["sessionId"]})
    row = shared._row(selected, "exact Setup session")
    profile.require(profile.row_binding(row) == bound and row["status"] == "active" and row["phase"] == phase
        and row["owner_id"] == actor and row["current_assignee_id"] in {None, actor}
        and shared._database_epoch_ns(context.database_now) < bound["expiresAtEpochNs"], "Setup owner, revision, phase or original expiry changed")
    return selected, row


def created(context, values):
    request = values["request"]; bound = request["setupBinding"]
    selected, row = current(context, bound, phase="created", actor=values["actor_id"])
    profile.require(row["revision"] == 0 and all(row[name] is None for name in (
        "credential_id", "credential_version", "oauth_provider", "oauth_state_digest", "oauth_pending_credential_id",
        "policy_hash", "assignment_digest", "enrollment_session_id", "terminal_at")))
    event = shared._row(context.exact("setup_session_events", {"id": profile.event_id(row["id"], 1)}), "genuine controlled Setup creation event")
    link = shared._row(context.exact(profile.AUDIT_LINK_TABLE, {"id": event["id"]}), "controlled Setup creation audit association")
    document = profile.document(event["event_json"].encode("ascii"), profile.MAX_EVENT_BYTES)
    profile.require(set(event) == profile.EVENT_FIELDS and event["session_id"] == row["id"] and event["sequence"] == 1
        and event["transition"] == "create" and event["actor_id"] == values["actor_id"]
        and document["details"]["setupPostSha256"] == bound["rowSha256"]
        and document["details"]["providerId"] == request["providerId"]
        and document["details"]["enrollmentSha256"] == request["enrollmentSha256"]
        and document["details"]["authorityOperation"] == profile.OP_CREATE
        and event["payload_digest"] == profile.sha256(profile.canonical(document))
        and set(link) == profile.AUDIT_LINK_FIELDS and link["event_id"] == link["id"] == event["id"]
        and link["session_id"] == row["id"] and link["request_digest"] == document["details"]["authorityRequestDigest"]
        and link["outbox_id"] == shared._audit_identity(profile.OP_CREATE, link["request_digest"]))
    return selected, row


def held(context, values, custody, *, staged=False):
    initial = _original(custody["setup_initial_json"])
    expected = _original(custody["setup_final_json"] if staged else custody["setup_started_json"])
    profile.require(profile.row_binding(initial) == values["request"]["setupBinding"]
        and initial["revision"] == 0 and initial["owner_id"] == values["actor_id"]
        and expected["id"] == initial["id"] and expected["expires_at"] == initial["expires_at"]
        and expected["owner_id"] == initial["owner_id"] and expected["current_assignee_id"] == initial["current_assignee_id"])
    selected, actual = current(context, profile.row_binding(expected), phase="oauth_verified" if staged else "oauth_started", actor=values["actor_id"])
    profile.require(actual == expected and actual["revision"] == (2 if staged else 1)
        and actual["oauth_state_digest"] is not None and actual["credential_id"] is None
        and actual["credential_version"] is None
        and actual["oauth_pending_credential_id"] == (values["resource_id"] if staged else None))
    return selected, actual


def next_row(context, before, *, transition, provider=None, state_digest=None, pending_id=None, credential_id=None):
    stamp = context.database_now.astimezone(timezone.utc).isoformat()
    profile.require(before["status"] == "active" and before["terminal_at"] is None
        and shared._database_epoch_ns(context.database_now) < profile.epoch(before["expires_at"]))
    if transition == "bind_oauth_flow":
        profile.require(before["revision"] == 0 and before["phase"] == "created"
            and before["oauth_provider"] is None and before["oauth_state_digest"] is None
            and provider in {"google", "x"})
        profile.digest(state_digest)
        changes = {"oauth_provider": provider, "oauth_state_digest": state_digest}
        phase = "oauth_started"
    elif transition == "bind_pending_credential":
        profile.require(before["revision"] == 1 and before["phase"] == "oauth_started" and before["oauth_pending_credential_id"] is None)
        profile.identifier(pending_id)
        changes = {"oauth_pending_credential_id": pending_id}
        phase = "oauth_verified"
    elif transition == "bind_credential":
        profile.require(before["revision"] == 2 and before["phase"] == "oauth_verified"
            and before["oauth_pending_credential_id"] == credential_id
            and before["credential_id"] is None and before["credential_version"] is None)
        profile.identifier(credential_id)
        changes = {"credential_id": credential_id, "credential_version": 1}
        phase = "credential_activated"
    else:
        profile.require(transition == "cancel" and before["revision"] == 1 and before["phase"] == "oauth_started")
        changes = {"status": "cancelled", "terminal_at": stamp}
        phase = "cancelled"
    after = {**before, **changes, "phase": phase, "revision": before["revision"] + 1, "updated_at": stamp}
    profile.row_original(after)
    return after, changes


def new_row(context, values):
    request = values["request"]
    profile.create_request(request)
    actor = values["actor_id"]
    stamp = context.database_now.astimezone(timezone.utc).isoformat()
    expires = (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=request["expiresAtEpochNs"] // 1000)).isoformat()
    row = {name: None for name in profile.ROW_FIELDS}
    row.update(id=request["sessionId"], owner_id=actor, current_assignee_id=actor, status="active", phase="created", revision=0,
        template_id=request["templateId"], principal_id=request["principalId"], route_id=request["routeId"],
        created_at=stamp, updated_at=stamp, expires_at=expires)
    profile.row_original(row)
    return row


def mutations(context, before, after, *, transition, actor, updates, audit_digest, provider, enrollment_sha256):
    profile.row_original(after); profile.digest(audit_digest)
    sequence = after["revision"] + 1
    profile.require(1 <= sequence <= 4 and (before is None and after["revision"] == 0 or before is not None and after["revision"] == before["revision"] + 1))
    item_id = profile.event_id(after["id"], sequence)
    event_selected = context.exact("setup_session_events", {"id": item_id})
    link_selected = context.exact(profile.AUDIT_LINK_TABLE, {"id": item_id})
    profile.require(not event_selected["present"] and not link_selected["present"])
    selected = context.exact("setup_sessions", {"id": after["id"]})
    profile.require(not selected["present"] if before is None else shared._row(selected, "actual Setup prestate") == before)
    details = {"authorityOperation": context.operation, "authorityRequestDigest": context.request_digest,
        "setupPostSha256": profile.sha256(profile.row_original(after)), "providerId": provider, "enrollmentSha256": enrollment_sha256}
    document = {"version": "serverware.setupTransition/v1", "setup_session_id": after["id"], "transition": transition,
        "from_phase": None if before is None else before["phase"], "to_phase": after["phase"], "binding_updates": updates,
        "evidence_digests": [], "details": details}
    raw = profile.canonical(document)
    profile.require(len(raw) <= profile.MAX_EVENT_BYTES)
    event = {"id": item_id, "session_id": after["id"], "sequence": sequence, "transition": transition,
        "actor_id": actor, "payload_digest": profile.sha256(raw), "event_json": raw.decode("ascii"), "created_at": after["updated_at"],
        "audit_status": "controlled_pending", "audit_claim_id": None, "audit_claimed_at": None, "audit_attempts": 0,
        "audited_at": None, "audit_event_hash": None, "audit_last_error": None}
    link = {"id": item_id, "session_id": after["id"], "event_id": item_id,
        "outbox_id": shared._audit_identity(context.operation, context.request_digest), "outbox_event_digest": audit_digest,
        "request_digest": context.request_digest, "created_at": after["updated_at"]}
    return (core.mutation(operation=context.operation, selected=selected, row=after),
        core.mutation(operation=context.operation, selected=event_selected, row=event),
        core.mutation(operation=context.operation, selected=link_selected, row=link))
