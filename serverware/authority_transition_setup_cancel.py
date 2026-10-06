"""Purpose-fixed tracking cancellation and factual audit settlement.

The selected bounded profile requires the actual complete event-table root.
No credential, provider, policy, enrollment or retained binding is revoked.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import time
from types import MappingProxyType

from serverware import authority_setup_cancel as profile
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware
from serverware.authority_query_read_work import _ValidationWork


def _maximum(value):
    profile.require(type(value) is int and 1 <= value <= profile.MAX_EVENTS,
        "Setup cancellation lacks its independently admitted event ceiling")
    return value


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns, maximum_events):
    """Reconstruct the exact current primary root, not a SQL count assertion."""
    maximum = _maximum(maximum_events)
    profile.require(type(deadline_ns) is int)

    def check():
        profile.require(time.monotonic_ns() < deadline_ns,
            "Setup event population exceeded its original deadline")

    check()
    work.prepare_copy(before_roots)
    roots = [entry for entry in before_roots if entry["table"] == "setup_session_events"]
    work.prepare_scan(selected_rows)
    rows = [entry for entry in selected_rows
        if entry["table"] == "setup_session_events" and entry["present"]]
    profile.require(len(roots) == 1 and len(rows) <= maximum,
        "Setup event population exceeds its selected complete-table capacity")
    nodes = {}
    work.charge(hashes=65 * 66 // 2)
    for entry in rows:
        check()
        work.prepare_encoding(entry["key"], ensure_ascii=False)
        work.prepare_encoding(entry["key"], ensure_ascii=False)
        work.prepare_encoding(entry["row"], ensure_ascii=False)
        work.charge(hashes=3)
        key_digest = radix.authenticated_key_digest("setup_session_events", entry["key"])
        path = key_digest[7:]
        profile.require(path not in nodes, "Setup event population duplicates a primary leaf")
        row_digest = radix._tree_digest("serverware.policyAuthorityAuthenticatedRow/v1",
            b"setup_session_events", radix.tree_json_bytes(entry["row"]))
        nodes[path] = radix._tree_digest("serverware.policyAuthorityAuthenticatedLeaf/v1",
            b"setup_session_events", key_digest.encode("ascii"),
            radix.tree_json_bytes(entry["key"]), row_digest.encode("ascii"))
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
    profile.require(nodes.get("", radix.empty_digest(0)) == roots[0]["rootDigest"],
        "Setup event population is incomplete against the actual before-root")
    check()


def _event_id(request_digest):
    return core.deterministic_uuid(operation=profile.OPERATION,
        request_digest=request_digest, purpose="setup-cancel-event")


def _authorize(context, actor, session):
    binding = shared._row(context.exact("rbac_role_bindings", {"subject_id": actor}),
        "current Setup cancellation RBAC")
    raw = binding.get("roles_json")
    profile.require(type(raw) is str)
    roles = json.loads(raw)
    profile.require(profile.canonical(roles).decode("ascii") == raw)
    if type(roles) is dict:
        roles = roles.get("roles")
    profile.require(binding.get("status") == "active" and type(roles) is list
        and all(type(role) is str for role in roles)
        and bool(set(roles).intersection(profile.MUTATION_ROLES)),
        "Current Setup mutation role is required")
    profile.require(actor in {session["owner_id"], session["current_assignee_id"]} or "admin" in roles,
        "Setup tracking is assigned to another operator")


@dataclass(frozen=True, slots=True)
class CancelKernel:
    operation: str = profile.OPERATION
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_setup_session_cancel"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("Setup cancellation requires actual current hardware evidence")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        before = profile.row(values["request"]["sessionOriginal"])
        item_id = _event_id(request_digest)
        queries = [shared._query(operation=self.operation, name="setup", table="setup_sessions", key={"id": before["id"]}),
            shared._role_query(self.operation, "actor_role", values["actor_id"]),
            core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", "setup_session_events"),
                table="setup_session_events", predicates=(), order_by=(core.QueryOrder("id"),),
                maximum_rows=profile.MAX_EVENTS + 1, proof_primitive="bounded-limit-plus-one", work_units=profile.MAX_EVENTS + 1),
            shared._query(operation=self.operation, name="cancel_event", table="setup_session_events", key={"id": item_id}, require_absence=True),
            shared._query(operation=self.operation, name="cancel_audit_link", table=profile.AUDIT_LINK_TABLE, key={"id": item_id}, require_absence=True)]
        for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"),
                ("assertion_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        request, actor = values["request"], values["actor_id"]
        before = profile.row(request["sessionOriginal"])
        selected = context.exact("setup_sessions", {"id": before["id"]})
        actual = shared._row(selected, "actual Setup cancellation prestate")
        now = shared._database_epoch_ns(context.database_now)
        profile.require(profile.row_original(actual) == profile.row_original(before)
            and before["status"] == "active" and before["terminal_at"] is None
            and request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"]
            and now < profile.epoch(before["expires_at"])
            and 0 <= before["revision"] < 9_223_372_036_854_775_807,
            "Setup original revision, status or lifetime changed")
        _authorize(context, actor, before)
        evidence = context.verified_webauthn_evidence
        profile.require(evidence is not None)
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}),
            "actual Setup cancellation hardware")
        policy = values["credential_policy"]
        hardware._hardware(credential, policy)
        profile.require(evidence["rpId"] == policy["rpId"] and evidence["origin"] in policy["origins"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= policy["maxAssertionAgeSeconds"] * 1_000_000_000)
        authn = tuple(assertion._assertion_mutations(context, {"actor_id": actor}))
        # The planner independently reconstructed this WHOLE table's before-root.
        population = context.present_rows("setup_session_events")
        profile.require(len(population) < _maximum(context.setup_cancel_maximum_events),
            "Setup cancellation event capacity is exhausted")
        sequences = set()
        for item in population:
            event = shared._row(item, "complete Setup event population")
            if event["session_id"] == before["id"]:
                sequence = core.require_integer(event["sequence"], "Setup event sequence",
                    minimum=1, maximum=9_223_372_036_854_775_806)
                profile.require(sequence not in sequences, "Setup event sequence is duplicated")
                sequences.add(sequence)
        next_sequence = max(sequences, default=0) + 1
        stamp = context.database_now.astimezone(timezone.utc).isoformat()
        after = {**before, "status": "cancelled", "phase": "cancelled", "revision": before["revision"] + 1,
            "updated_at": stamp, "terminal_at": stamp}
        original = profile.row_original(after)
        before_digest, after_digest = profile.sha256(profile.row_original(before)), profile.sha256(original)
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=actor,
            event={"schema": "serverware.setupTrackingCancellationAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "sessionId": before["id"],
                "setupPreSha256": before_digest, "setupPostSha256": after_digest, "reason": request["reason"]})
        profile.require(not replay)
        item_id = _event_id(context.request_digest)
        event_selected = context.exact("setup_session_events", {"id": item_id})
        link_selected = context.exact(profile.AUDIT_LINK_TABLE, {"id": item_id})
        profile.require(not event_selected["present"] and not link_selected["present"])
        document = {"version": "serverware.setupTransition/v1", "setup_session_id": before["id"], "transition": "cancel",
            "from_phase": before["phase"], "to_phase": "cancelled", "binding_updates": {}, "evidence_digests": [],
            "details": {"authorityOperation": self.operation, "authorityRequestDigest": context.request_digest,
                "setupPreSha256": before_digest, "setupPostSha256": after_digest, "reason": request["reason"]}}
        raw = profile.canonical(document)
        profile.require(len(raw) <= profile.MAX_EVENT_BYTES)
        event = {"id": item_id, "session_id": before["id"], "sequence": next_sequence, "transition": "cancel", "actor_id": actor,
            "payload_digest": profile.sha256(raw), "event_json": raw.decode("ascii"), "created_at": stamp,
            "audit_status": "controlled_pending", "audit_claim_id": None, "audit_claimed_at": None, "audit_attempts": 0,
            "audited_at": None, "audit_event_hash": None, "audit_last_error": None}
        link = {"id": item_id, "session_id": before["id"], "event_id": item_id,
            "outbox_id": shared._audit_identity(self.operation, context.request_digest), "outbox_event_digest": audit_digest,
            "request_digest": context.request_digest, "created_at": stamp}
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=selected, row=after),
            core.mutation(operation=self.operation, selected=event_selected, row=event),
            core.mutation(operation=self.operation, selected=link_selected, row=link)) + authn + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "setupOriginal": original.decode("ascii"),
                "setupEventId": item_id, "auditState": "controlled_pending"}, work_units=1024)


@dataclass(frozen=True, slots=True)
class AuditSettleKernel:
    operation: str = profile.OP_SETTLE
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_setup_session_audit_settle"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        key = {"id": values["event_id"]}
        return (shared._query(operation=self.operation, name="setup_event", table="setup_session_events", key=key),
            shared._query(operation=self.operation, name="setup_audit_link", table=profile.AUDIT_LINK_TABLE, key=key),
            shared._query(operation=self.operation, name="actual_completed_outbox", table="metadata_audit_outbox",
                key={"id": core.SelectedRowFieldReference(profile.AUDIT_LINK_TABLE, key, "outbox_id")}),
            shared._audit_query(self.operation, request_digest))

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        key = {"id": values["event_id"]}
        selected = context.exact("setup_session_events", key)
        event = shared._row(selected, "exact controlled cancellation event")
        link = shared._row(context.exact(profile.AUDIT_LINK_TABLE, key), "exact cancellation audit link")
        profile.require(set(event) == profile.EVENT_FIELDS and set(link) == profile.AUDIT_LINK_FIELDS
            and event["id"] == link["id"] == link["event_id"] == _event_id(link["request_digest"])
            and event["session_id"] == link["session_id"] and event["transition"] == "cancel"
            and event["audit_status"] == "controlled_pending" and event["audit_attempts"] == 0
            and all(event[name] is None for name in ("audit_claim_id", "audit_claimed_at", "audited_at", "audit_event_hash", "audit_last_error")))
        document = shared._canonical_stored_mapping(event["event_json"], "original cancellation event")
        details = document["details"]
        profile.require(event["payload_digest"] == profile.sha256(profile.canonical(document))
            and document["setup_session_id"] == event["session_id"] and document["transition"] == "cancel"
            and document["to_phase"] == "cancelled" and document["binding_updates"] == {} and document["evidence_digests"] == []
            and details["authorityOperation"] == profile.OPERATION
            and details["authorityRequestDigest"] == link["request_digest"]
            and link["outbox_id"] == shared._audit_identity(profile.OPERATION, link["request_digest"]))
        outbox = shared._row(context.exact("metadata_audit_outbox", {"id": link["outbox_id"]}), "genuinely completed cancellation audit")
        profile.require(outbox["status"] == "audited" and outbox["event_type"] == profile.OPERATION
            and outbox["actor_type"] == "admin" and outbox["actor_id"] == event["actor_id"]
            and outbox["event_digest"] == link["outbox_event_digest"]
            and outbox["audited_at"] is not None and outbox["audit_event_hash"] is not None
            and outbox["claim_id"] is None and outbox["claimed_at"] is None
            and profile.epoch(outbox["audited_at"]) <= shared._database_epoch_ns(context.database_now))
        profile.digest(outbox["audit_event_hash"])
        actual = shared._canonical_stored_mapping(outbox["event_json"], "completed cancellation audit original")
        profile.require(actual == {"schema": "serverware.setupTrackingCancellationAudit/v1", "operation": profile.OPERATION,
            "requestDigest": link["request_digest"], "sessionId": event["session_id"],
            "setupPreSha256": details["setupPreSha256"], "setupPostSha256": details["setupPostSha256"], "reason": details["reason"]}
            and outbox["event_digest"] == core.framed_digest("serverware.metadataAuditOutboxEvent/v1", outbox["event_json"].encode("ascii")))
        after = {**event, "audit_status": "audited", "audited_at": outbox["audited_at"], "audit_event_hash": outbox["audit_event_hash"]}
        audit, digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="control_plane", actor_id=None,
            event={"schema": "serverware.setupTrackingCancellationAuditSettlement/v1", "requestDigest": context.request_digest,
                "eventId": event["id"], "outboxId": outbox["id"], "auditEventHash": outbox["audit_event_hash"]})
        profile.require(not replay)
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=selected, row=after),) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest, "auditEventDigest": digest,
                "idempotentReplay": False, "eventId": event["id"], "auditState": "audited", "auditEventHash": outbox["audit_event_hash"]}, work_units=256)


def verify_cancel_plan(*, payload, arguments, verified_webauthn_evidence,
        maximum_events, deadline_ns, now_epoch_ns, work):
    """Check one authenticated planner proposal before capability issuance.

    The caller first authenticates the original plan and primary-root proof,
    and supplies its own admitted policy ceiling, assertion original and live
    deadline. The signed UPDATE timestamp is a proposed cutoff, NOT a new or
    independent database-clock observation. Replaying at that retained value
    checks exact source effects; it does not mint time or execution authority.
    """
    from serverware import authority_audit_capacity as capacity
    from serverware import authority_challenge_retention as retention
    from serverware.authority_query_reads import _CopyBudget

    profile.require(type(work) is _ValidationWork and type(payload) is dict
        and type(arguments) is dict and type(verified_webauthn_evidence) is dict)
    maximum = _maximum(maximum_events)
    core.require_integer(deadline_ns, "original cancellation deadline", minimum=1, maximum=2**63 - 1)
    core.require_integer(now_epoch_ns, "current verifier time", minimum=1, maximum=2**63 - 1)
    expires = None

    def check():
        current = time.time_ns()
        profile.require(time.monotonic_ns() < deadline_ns and now_epoch_ns <= current
            and (expires is None or current < expires), "Cancellation plan crossed its original live bound")

    def equal(left, right):
        work.prepare_encoding(left)
        work.prepare_encoding(right)
        profile.require(profile.canonical(left) == profile.canonical(right),
            "Cancellation plan differs from its actual originals or source effects")

    check()
    owned = _CopyBudget(work).copy({"payload": payload, "arguments": arguments,
        "evidence": verified_webauthn_evidence})
    plan, evidence = owned["payload"], owned["evidence"]
    values = profile.arguments(profile.OPERATION, owned["arguments"],
        typed="businessIntent" in owned["arguments"])
    typed, measured, projection = plan["typedRequest"], plan["measuredPlan"], plan["authorizationProjection"]
    profile.require(typed["operation"] == measured["operation"] == profile.OPERATION)
    equal(profile.arguments(profile.OPERATION, typed["arguments"], typed=True), values)
    equal(plan["webauthnEvidence"], evidence)
    request_digest = profile.request_digest(profile.OPERATION, values)
    profile.require(typed["requestDigest"] == measured["requestDigest"] == evidence["requestDigest"] == request_digest
        and measured["deadlineMonotonicNs"] == deadline_ns)
    expires = measured["deadlineEpochNs"]
    core.require_integer(expires, "signed plan expiry", minimum=1, maximum=2**63 - 1)
    selected, mutations = plan["selectedBusinessRows"], plan["mutationPlan"]
    before = profile.row(values["request"]["sessionOriginal"])
    work.prepare_scan(mutations)
    updates = [item for item in mutations if item["table"] == "setup_sessions"]
    profile.require(len(updates) == 1 and updates[0]["key"] == {"id": before["id"]}
        and updates[0]["operation"] == "UPDATE" and type(updates[0]["row"]) is dict)
    proposed = updates[0]["row"]
    profile.row_original(proposed)
    stamp = proposed["updated_at"]
    cutoff = profile.epoch(stamp)
    profile.require(proposed["terminal_at"] == stamp
        and values["request"]["issuedAtEpochNs"] <= projection["createdAtEpochNs"] <= cutoff <= now_epoch_ns
        and evidence["verifiedAtEpochNs"] <= cutoff
        and now_epoch_ns < evidence["expiresAtEpochNs"] <= expires
        and projection["expiresAtEpochNs"] == expires <= values["request"]["expiresAtEpochNs"])
    check()
    roots = plan["rootTransition"]
    require_complete_populations(selected_rows=selected,
        before_roots=tuple(roots["businessBeforeRoots"]) + tuple(roots["authorizationBeforeRoots"]),
        work=work, deadline_ns=deadline_ns, maximum_events=maximum)
    check()
    # Same source kernel, held originals and cumulative meter; no SQL or new
    # clock is substituted for the signed proposal's literal timestamp.
    context = core.KernelContext(profile.OPERATION, typed["arguments"], tuple(selected),
        datetime.fromisoformat(stamp), request_digest, verified_webauthn_evidence=evidence,
        setup_cancel_maximum_events=maximum)
    kernel = CancelKernel()
    transition = kernel.transition(context)
    expanded = retention.expand_mutations(context, transition.mutations, work=work)
    expected = capacity._finalize_capacity(context, expanded, work=work)
    expected = sorted(expected, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    equal(mutations, expected)
    equal(plan["expectedResult"], transition.result)
    queries = capacity.add_capacity_query(profile.OPERATION, kernel.queries_with_evidence(
        arguments=typed["arguments"], database_now=context.database_now,
        request_digest=request_digest, evidence=evidence))
    profile.require(measured["workUnits"] == capacity.transition_work_units(
        operation=profile.OPERATION, query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=transition.work_units, mutations=tuple(expected)))
    check()


KERNELS = MappingProxyType({profile.OPERATION: CancelKernel(), profile.OP_SETTLE: AuditSettleKernel()})
