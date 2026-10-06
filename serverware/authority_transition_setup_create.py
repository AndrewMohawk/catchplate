"""Bounded protected Setup creation and factual creation-audit settlement.

Current session/event populations come from complete authenticated roots, not
SQL counts. No retained row is pruned or adopted. Requested route labels are
tracking annotations, not route/publication/currentness authority; all other
credential, provider, policy, enrollment and evidence bindings start empty.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import time
from types import MappingProxyType

from serverware import authority_setup_create as profile
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware
from serverware.authority_query_read_work import _ValidationWork


def _policy(value):
    # This checks the retained policy shape; admission is the caller's actual
    # signed configuration, never a policy supplied in the HTTP arguments.
    profile.require(type(value) is dict and set(value) == profile.POLICY_FIELDS
        and value["schema"] == profile.SCHEMA,
        "Setup creation lacks its independently admitted policy")
    profile.digest(value["controlPlaneConfigurationDigest"])
    profile.policy(value["credentialPolicy"])
    for name, lower, upper in (("maximumSessions", 1, profile.MAX_SESSIONS),
            ("maximumEvents", 1, profile.MAX_EVENTS), ("operationMaxSeconds", 1, 30),
            ("maximumSessionTtlSeconds", profile.MIN_SESSION_TTL_SECONDS, profile.MAX_SESSION_TTL_SECONDS)):
        profile.require(type(value[name]) is int and lower <= value[name] <= upper)
    profile.require(type(value["maximumActiveSessions"]) is int
        and 1 <= value["maximumActiveSessions"] <= value["maximumSessions"]
        and type(value["maximumArgumentBytes"]) is int
        and value["maximumArgumentBytes"] == profile.MAX_ARGUMENT_BYTES)
    return value


def require_complete_populations(*, selected_rows, before_roots, work, deadline_ns, creation_policy):
    """Reconstruct both fixed whole-table roots under the original work/window."""
    selected_policy = _policy(creation_policy)
    profile.require(type(work) is _ValidationWork and type(deadline_ns) is int)

    def check():
        profile.require(time.monotonic_ns() < deadline_ns, "Setup creation population deadline expired")

    check()
    work.prepare_copy(before_roots)
    for table, field in (("setup_sessions", "maximumSessions"), ("setup_session_events", "maximumEvents")):
        work.prepare_scan(before_roots)
        roots = [entry for entry in before_roots if entry["table"] == table]
        work.prepare_scan(selected_rows)
        rows = [entry for entry in selected_rows if entry["table"] == table and entry["present"]]
        profile.require(len(roots) == 1 and len(rows) <= selected_policy[field],
            "Setup creation population exceeds its selected complete-table capacity")
        nodes = {}
        work.charge(hashes=65 * 66 // 2)
        for entry in rows:
            check()
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["key"], ensure_ascii=False)
            work.prepare_encoding(entry["row"], ensure_ascii=False)
            work.charge(hashes=3)
            key_digest = radix.authenticated_key_digest(table, entry["key"])
            path = key_digest[7:]
            profile.require(path not in nodes, "Setup creation population duplicates a primary leaf")
            row_digest = radix._tree_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                table.encode("ascii"), radix.tree_json_bytes(entry["row"]))
            nodes[path] = radix._tree_digest("serverware.policyAuthorityAuthenticatedLeaf/v1",
                table.encode("ascii"), key_digest.encode("ascii"),
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
            "Setup creation population is incomplete against the actual before-root")
    check()


def _event_id(request_digest):
    return core.deterministic_uuid(operation=profile.OPERATION,
        request_digest=request_digest, purpose="setup-create-event")


def _authorize(context, actor):
    binding = shared._row(context.exact("rbac_role_bindings", {"subject_id": actor}), "current Setup creator RBAC")
    raw = binding.get("roles_json")
    profile.require(type(raw) is str)
    roles = json.loads(raw)
    profile.require(profile.canonical(roles).decode("ascii") == raw)
    if type(roles) is dict:
        roles = roles.get("roles")
    profile.require(binding.get("status") == "active" and type(roles) is list
        and all(type(role) is str for role in roles)
        and bool(set(roles).intersection(profile.MUTATION_ROLES)), "Current Setup creation role is required")


@dataclass(frozen=True, slots=True)
class CreateKernel:
    operation: str = profile.OPERATION
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_setup_session_create"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("Setup creation requires actual current hardware evidence")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        session_id, item_id = values["request"]["sessionId"], _event_id(request_digest)
        queries = [shared._query(operation=self.operation, name="setup", table="setup_sessions",
            key={"id": session_id}, require_absence=True), shared._role_query(self.operation, "actor_role", values["actor_id"])]
        for table, maximum in (("setup_sessions", profile.MAX_SESSIONS), ("setup_session_events", profile.MAX_EVENTS)):
            queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table),
                table=table, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=maximum + 1,
                proof_primitive="bounded-limit-plus-one", page_size=maximum, work_units=maximum + 1))
        queries.extend((shared._query(operation=self.operation, name="create_event", table="setup_session_events",
            key={"id": item_id}, require_absence=True), shared._query(operation=self.operation,
            name="create_audit_link", table=profile.AUDIT_LINK_TABLE, key={"id": item_id}, require_absence=True)))
        for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"),
                ("assertion_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        selected_policy = _policy(context.setup_create_policy)
        request, actor = values["request"], values["actor_id"]
        now = shared._database_epoch_ns(context.database_now)
        profile.require(values["control_plane_configuration_digest"] == selected_policy["controlPlaneConfigurationDigest"]
            and values["credential_policy"] == selected_policy["credentialPolicy"]
            and request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"]
            <= request["issuedAtEpochNs"] + selected_policy["operationMaxSeconds"] * 1_000_000_000
            and request["ttlSeconds"] <= selected_policy["maximumSessionTtlSeconds"],
            "Setup creation original purpose, policy or lifetime changed")
        session_id = request["sessionId"]
        selected = context.exact("setup_sessions", {"id": session_id})
        profile.require(selected["present"] is False and selected["row"] is None, "Setup creation identity already exists")
        _authorize(context, actor)
        sessions, events = context.present_rows("setup_sessions"), context.present_rows("setup_session_events")
        profile.require(len(sessions) < selected_policy["maximumSessions"]
            and len(events) < selected_policy["maximumEvents"], "Setup creation retained capacity is exhausted")
        active = 0
        for item in sessions:
            old = shared._row(item, "complete retained Setup population")
            profile.row_original(old)
            # Expiry alone does not reclaim a protected capacity slot. A real
            # terminal transition must first change the retained status.
            if old["status"] == "active":
                active += 1
        profile.require(active < selected_policy["maximumActiveSessions"], "Setup creation active capacity is exhausted")
        profile.require(all(shared._row(item, "complete retained Setup event population")["session_id"] != session_id
            for item in events), "Setup creation cannot adopt retained or orphaned history")
        evidence = context.verified_webauthn_evidence
        profile.require(evidence is not None)
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}),
            "actual Setup creator hardware")
        policy = values["credential_policy"]
        hardware._hardware(credential, policy)
        profile.require(evidence["rpId"] == policy["rpId"] and evidence["origin"] in policy["origins"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= policy["maxAssertionAgeSeconds"] * 1_000_000_000)
        authn = tuple(assertion._assertion_mutations(context, {"actor_id": actor}))
        instant = context.database_now.astimezone(timezone.utc)
        stamp, expiry = instant.isoformat(), (instant + timedelta(seconds=request["ttlSeconds"])).isoformat()
        profile.require(profile.epoch(expiry) <= 2**63 - 1)
        after = {name: None for name in profile.ROW_FIELDS}
        after.update({"id": session_id, "owner_id": actor, "current_assignee_id": actor,
            "status": "active", "phase": "created", "revision": 0, "template_id": request["templateId"],
            "principal_id": request["principalId"], "route_id": request["routeId"],
            "route_policy_digest": request["routePolicyDigest"], "created_at": stamp, "updated_at": stamp, "expires_at": expiry})
        original = profile.row_original(after)
        after_digest = profile.sha256(original)
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=actor,
            event={"schema": "serverware.setupTrackingCreationAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "sessionId": session_id, "setupPostSha256": after_digest, "request": request})
        profile.require(not replay)
        item_id = _event_id(context.request_digest)
        event_selected = context.exact("setup_session_events", {"id": item_id})
        link_selected = context.exact(profile.AUDIT_LINK_TABLE, {"id": item_id})
        profile.require(not event_selected["present"] and not link_selected["present"])
        document = {"version": "serverware.setupTransition/v1", "setup_session_id": session_id, "transition": "create",
            "from_phase": None, "to_phase": "created", "binding_updates": {}, "evidence_digests": [],
            "details": {"authorityOperation": self.operation, "authorityRequestDigest": context.request_digest,
                "setupPostSha256": after_digest, "request": request}}
        raw = profile.canonical(document)
        profile.require(len(raw) <= profile.MAX_EVENT_BYTES)
        event = {"id": item_id, "session_id": session_id, "sequence": 1, "transition": "create", "actor_id": actor,
            "payload_digest": profile.sha256(raw), "event_json": raw.decode("ascii"), "created_at": stamp,
            "audit_status": "controlled_pending", "audit_claim_id": None, "audit_claimed_at": None, "audit_attempts": 0,
            "audited_at": None, "audit_event_hash": None, "audit_last_error": None}
        link = {"id": item_id, "session_id": session_id, "event_id": item_id,
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
        return "serverware_policy_authority_setup_session_create_audit_settle"

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
        _policy(context.setup_create_policy)
        values = profile.arguments(self.operation, context.arguments, typed=True)
        key = {"id": values["event_id"]}
        selected = context.exact("setup_session_events", key)
        event = shared._row(selected, "exact controlled creation event")
        link = shared._row(context.exact(profile.AUDIT_LINK_TABLE, key), "exact creation audit link")
        profile.require(set(event) == profile.EVENT_FIELDS and set(link) == profile.AUDIT_LINK_FIELDS
            and event["id"] == link["id"] == link["event_id"] == _event_id(link["request_digest"])
            and event["session_id"] == link["session_id"] and event["transition"] == "create" and event["sequence"] == 1
            and event["audit_status"] == "controlled_pending" and event["audit_attempts"] == 0
            and event["created_at"] == link["created_at"]
            and all(event[name] is None for name in ("audit_claim_id", "audit_claimed_at", "audited_at", "audit_event_hash", "audit_last_error")))
        document = shared._canonical_stored_mapping(event["event_json"], "original creation event")
        details = document["details"]
        profile.require(event["payload_digest"] == profile.sha256(profile.canonical(document))
            and document["version"] == "serverware.setupTransition/v1"
            and document["setup_session_id"] == event["session_id"] and document["transition"] == "create"
            and document["from_phase"] is None and document["to_phase"] == "created"
            and document["binding_updates"] == {} and document["evidence_digests"] == []
            and details["authorityOperation"] == profile.OPERATION
            and details["authorityRequestDigest"] == link["request_digest"]
            and details["request"]["sessionId"] == event["session_id"]
            and link["outbox_id"] == shared._audit_identity(profile.OPERATION, link["request_digest"]))
        profile.digest(details["setupPostSha256"])
        outbox = shared._row(context.exact("metadata_audit_outbox", {"id": link["outbox_id"]}), "genuinely completed creation audit")
        profile.require(outbox["status"] == "audited" and outbox["event_type"] == profile.OPERATION
            and outbox["actor_type"] == "admin" and outbox["actor_id"] == event["actor_id"]
            and outbox["event_digest"] == link["outbox_event_digest"] and outbox["created_at"] == event["created_at"]
            and outbox["audited_at"] is not None and outbox["audit_event_hash"] is not None
            and outbox["claim_id"] is None and outbox["claimed_at"] is None
            and profile.epoch(outbox["audited_at"]) <= shared._database_epoch_ns(context.database_now))
        profile.digest(outbox["audit_event_hash"])
        actual = shared._canonical_stored_mapping(outbox["event_json"], "completed creation audit original")
        profile.require(actual == {"schema": "serverware.setupTrackingCreationAudit/v1", "operation": profile.OPERATION,
            "requestDigest": link["request_digest"], "sessionId": event["session_id"],
            "setupPostSha256": details["setupPostSha256"], "request": details["request"]}
            and outbox["event_digest"] == core.framed_digest("serverware.metadataAuditOutboxEvent/v1", outbox["event_json"].encode("ascii")))
        after = {**event, "audit_status": "audited", "audited_at": outbox["audited_at"], "audit_event_hash": outbox["audit_event_hash"]}
        audit, digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="control_plane", actor_id=None,
            event={"schema": "serverware.setupTrackingCreationAuditSettlement/v1", "requestDigest": context.request_digest,
                "eventId": event["id"], "outboxId": outbox["id"], "auditEventHash": outbox["audit_event_hash"]})
        profile.require(not replay)
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=selected, row=after),) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest, "auditEventDigest": digest,
                "idempotentReplay": False, "eventId": event["id"], "auditState": "audited", "auditEventHash": outbox["audit_event_hash"]}, work_units=256)


def verify_create_plan(*, payload, arguments, verified_webauthn_evidence,
        creation_policy, deadline_ns, now_epoch_ns, work):
    """Replay an authenticated proposal, not an independent DB observation.

    The caller first verifies original planner signature/root proof and binds
    this plan to its request. Policy, assertion evidence and original deadline
    are independently retained by that caller, not learned from the plan.
    The signed INSERT timestamp is only the proposal's literal replay cutoff.
    """
    from serverware import authority_audit_capacity as capacity
    from serverware import authority_challenge_retention as retention
    from serverware.authority_query_reads import _CopyBudget

    profile.require(type(work) is _ValidationWork and type(payload) is dict
        and type(arguments) is dict and type(verified_webauthn_evidence) is dict)
    core.require_integer(deadline_ns, "original creation deadline", minimum=1, maximum=2**63 - 1)
    core.require_integer(now_epoch_ns, "current verifier time", minimum=1, maximum=2**63 - 1)
    expires = None

    def check():
        current = time.time_ns()
        profile.require(time.monotonic_ns() < deadline_ns and now_epoch_ns <= current
            and (expires is None or current < expires), "Creation plan crossed its original live bound")

    def equal(left, right):
        work.prepare_encoding(left)
        work.prepare_encoding(right)
        profile.require(profile.canonical(left) == profile.canonical(right),
            "Creation plan differs from its actual originals or source effects")

    check()
    owned = _CopyBudget(work).copy({"payload": payload, "arguments": arguments,
        "evidence": verified_webauthn_evidence, "policy": creation_policy})
    plan, evidence, selected_policy = owned["payload"], owned["evidence"], _policy(owned["policy"])
    values = profile.arguments(profile.OPERATION, owned["arguments"], typed="businessIntent" in owned["arguments"])
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
    work.prepare_scan(mutations)
    inserts = [item for item in mutations if item["table"] == "setup_sessions"]
    profile.require(len(inserts) == 1 and inserts[0]["key"] == {"id": values["request"]["sessionId"]}
        and inserts[0]["operation"] == "INSERT" and inserts[0]["expectedRow"] is None and type(inserts[0]["row"]) is dict)
    proposed = inserts[0]["row"]
    profile.row_original(proposed)
    stamp = proposed["created_at"]
    cutoff = profile.epoch(stamp)
    profile.require(proposed["updated_at"] == stamp
        and values["request"]["issuedAtEpochNs"] <= projection["createdAtEpochNs"] <= cutoff <= now_epoch_ns
        and evidence["verifiedAtEpochNs"] <= cutoff
        and now_epoch_ns < evidence["expiresAtEpochNs"] <= expires
        and projection["expiresAtEpochNs"] == expires <= values["request"]["expiresAtEpochNs"])
    check()
    roots = plan["rootTransition"]
    require_complete_populations(selected_rows=selected,
        before_roots=tuple(roots["businessBeforeRoots"]) + tuple(roots["authorizationBeforeRoots"]),
        work=work, deadline_ns=deadline_ns, creation_policy=selected_policy)
    check()
    context = core.KernelContext(profile.OPERATION, typed["arguments"], tuple(selected),
        datetime.fromisoformat(stamp), request_digest, verified_webauthn_evidence=evidence,
        setup_create_policy=selected_policy)
    kernel = CreateKernel()
    transition = kernel.transition(context)
    expanded = retention.expand_mutations(context, transition.mutations, work=work)
    expected = capacity._finalize_capacity(context, expanded, work=work)
    expected = sorted(expected, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    equal(mutations, expected)
    equal(plan["expectedResult"], transition.result)
    queries = capacity.add_capacity_query(profile.OPERATION, kernel.queries_with_evidence(
        arguments=typed["arguments"], database_now=context.database_now, request_digest=request_digest, evidence=evidence))
    profile.require(measured["workUnits"] == capacity.transition_work_units(
        operation=profile.OPERATION, query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=transition.work_units, mutations=tuple(expected)))
    check()


KERNELS = MappingProxyType({profile.OPERATION: CreateKernel(), profile.OP_SETTLE: AuditSettleKernel()})
