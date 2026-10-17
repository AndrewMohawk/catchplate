"""Atomic reviewed candidate association after proved controlled Setup binding.

No legacy Setup row/event is changed. This successor neither activates policy
nor produces filesystem, enrollment, canary readiness or proxy-ready evidence.
"""
from dataclasses import dataclass
from datetime import timezone
import time
from types import MappingProxyType

from catchplate import authority_setup_policy as profile
from catchplate import authority_policy_candidate as candidate
from catchplate import authority_policy_candidate_inventory as inventory
from catchplate import authority_transition_policy_candidate_context as originals
from catchplate import authority_transition_policy_candidate_publication as publication
from catchplate import authority_transition_policy_candidate_trust as trust
from catchplate import authority_transition_oauth_setup_rows as setup_rows
from catchplate import authority_transition_credential_currentness as currentness
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_webauthn as assertion
from catchplate import authority_transition_oauth_activation as hardware
from catchplate import authority_setup_bind_credential as binding
from catchplate import authority_static_credential_create as static_creation
from catchplate import authority_static_credential_provenance as static_provenance


def _inputs(arguments):
    values = profile.arguments(profile.OP_BIND, arguments, typed=True)
    claim = profile.claim_original(values["request"]["generationClaimOriginal"])
    bound = candidate.context(profile.setup.document(claim["context_json"].encode("ascii"), 8192))
    management = candidate.management_original(claim["management_request_json"])
    return values, claim, bound, management


def require_complete_populations(**kwargs):
    # Exactly the same six immutable-generation/trust histories are needed.
    # Reuse their original root reconstruction, not a second completeness rule.
    inventory.require_complete_populations(operation=candidate.OP_PUBLISH, **kwargs)


def _activated_session(context, values):
    setup = profile.setup
    _, session = setup_rows.current(context, values["request"]["setupBinding"],
        phase="credential_activated", actor=values["actor_id"])
    profile.require(session["revision"] == 3 and session["terminal_at"] is None
        and session["credential_id"] == session["oauth_pending_credential_id"] == values["request"]["credentialId"]
        and session["credential_version"] == values["request"]["credentialVersion"] == 1
        and all(session[name] is None for name in ("policy_hash", "assignment_digest", "canary_id", "enrollment_session_id")))
    key = {"id": setup.event_id(session["id"], 4)}
    event = shared._row(context.exact("setup_session_events", key), "controlled Setup activation event")
    link = shared._row(context.exact(setup.AUDIT_LINK_TABLE, key), "controlled Setup activation audit link")
    document = setup.document(event["event_json"].encode("ascii"), setup.MAX_EVENT_BYTES)
    profile.require(set(event) == setup.EVENT_FIELDS and set(link) == setup.AUDIT_LINK_FIELDS
        and event["id"] == link["id"] == link["event_id"] == key["id"]
        and event["session_id"] == link["session_id"] == session["id"] and event["sequence"] == 4
        and event["transition"] == "bind_credential" and event["actor_id"] == values["actor_id"]
        and event["payload_digest"] == profile.sha256(profile.canonical(document))
        and document["details"]["authorityOperation"] == setup.OP_ACTIVATE
        and document["details"]["authorityRequestDigest"] == link["request_digest"]
        and document["details"]["setupPostSha256"] == profile.sha256(setup.row_original(session))
        and document["details"]["providerId"] == session["oauth_provider"]
        and link["outbox_id"] == shared._audit_identity(setup.OP_ACTIVATE, link["request_digest"]))
    outbox = shared._row(context.exact("metadata_audit_outbox", {"id": link["outbox_id"]}), "completed Setup activation audit")
    profile.require(outbox["status"] == "audited" and outbox["event_digest"] == link["outbox_event_digest"]
        and outbox["audited_at"] is not None and outbox["audit_event_hash"] is not None
        and outbox["claim_id"] is None and outbox["claimed_at"] is None
        and setup.epoch(outbox["audited_at"]) <= shared._database_epoch_ns(context.database_now))
    profile.digest(outbox["audit_event_hash"])
    actual = shared._canonical_stored_mapping(outbox["event_json"], "actual completed Setup activation audit")
    profile.require(actual["requestDigest"] == link["request_digest"]
        and actual["setupPostSha256"] == document["details"]["setupPostSha256"])
    return session


def _static_bound_session(context, values):
    request, setup = values["request"], profile.setup
    _, session = setup_rows.current(context, request["setupBinding"],
        phase="credential_activated", actor=values["actor_id"])
    profile.require_static_session(session, rotated=set(request) == profile.ROTATED_STATIC_REQUEST_FIELDS)
    profile.require(session["credential_id"] == request["credentialId"]
        and session["credential_version"] == request["credentialVersion"])
    key = {"id": request["credentialBindingEventId"]}
    event = shared._row(context.exact("setup_session_events", key), "actual controlled static binding event")
    link = shared._row(context.exact(binding.AUDIT_LINK_TABLE, key), "actual static binding audit link")
    profile.digest(link["request_digest"])
    profile.require(set(event) == binding.EVENT_FIELDS and set(link) == binding.AUDIT_LINK_FIELDS
        and event["id"] == link["id"] == link["event_id"] == key["id"]
        == core.deterministic_uuid(operation=binding.OPERATION, request_digest=link["request_digest"],
            purpose="setup-bind-credential-event")
        and event["session_id"] == link["session_id"] == session["id"]
        and event["transition"] == "bind_credential"
        and event["created_at"] == link["created_at"] == session["updated_at"]
        and setup.epoch(event["created_at"]) <= shared._database_epoch_ns(context.database_now))
    core.require_integer(event["sequence"], "actual binding sequence", minimum=1, maximum=2**63 - 1)
    setup.text(event["actor_id"], 512)
    profile.require(event["actor_id"].startswith("oidc:"))
    document = shared._canonical_stored_mapping(event["event_json"], "original static binding event")
    details, updates = document["details"], document["binding_updates"]
    profile.require(set(document) == {"version", "setup_session_id", "transition", "from_phase", "to_phase",
            "binding_updates", "evidence_digests", "details"}
        and document["version"] == "catchplate.setupTransition/v1"
        and set(details) == {"authorityOperation", "authorityRequestDigest", "setupPreSha256", "setupPostSha256",
            "credentialOriginalSha256", "currentnessRootSha256", "credential_lifecycle_status"}
        and updates == {"credential_id": session["credential_id"], "credential_version": session["credential_version"]}
        and type(updates["credential_version"]) is int
        and event["payload_digest"] == profile.sha256(profile.canonical(document))
        and document["setup_session_id"] == session["id"] and document["transition"] == "bind_credential"
        and document["from_phase"] == "created" and document["to_phase"] == "credential_activated"
        and document["evidence_digests"] == [] and details["credential_lifecycle_status"] == "active"
        and details["authorityOperation"] == binding.OPERATION
        and details["authorityRequestDigest"] == link["request_digest"]
        and details["setupPostSha256"] == profile.sha256(setup.row_original(session))
        and link["outbox_id"] == shared._audit_identity(binding.OPERATION, link["request_digest"]))
    for field in ("setupPreSha256", "setupPostSha256", "credentialOriginalSha256", "currentnessRootSha256"):
        profile.digest(details[field])
    outbox = shared._row(context.exact("metadata_audit_outbox", {"id": link["outbox_id"]}), "completed static binding audit")
    profile.require(outbox["id"] == link["outbox_id"] and outbox["status"] == "audited"
        and outbox["event_type"] == binding.OPERATION and outbox["actor_type"] == "admin"
        and outbox["actor_id"] == event["actor_id"] and outbox["event_digest"] == link["outbox_event_digest"]
        and outbox["audited_at"] is not None and outbox["audit_event_hash"] is not None
        and outbox["claim_id"] is None and outbox["claimed_at"] is None
        and setup.epoch(event["created_at"]) <= setup.epoch(outbox["audited_at"])
        <= shared._database_epoch_ns(context.database_now))
    profile.digest(outbox["audit_event_hash"])
    actual = shared._canonical_stored_mapping(outbox["event_json"], "completed static binding audit original")
    expected = {"schema": "catchplate.setupCredentialBindingAudit/v1", "operation": binding.OPERATION,
        "requestDigest": link["request_digest"], "sessionId": session["id"],
        "setupPreSha256": details["setupPreSha256"], "setupPostSha256": details["setupPostSha256"],
        "credentialId": session["credential_id"], "credentialVersion": session["credential_version"],
        "credentialOriginalSha256": details["credentialOriginalSha256"], "currentnessRootSha256": details["currentnessRootSha256"]}
    profile.require(profile.canonical(actual) == profile.canonical(expected)
        and outbox["event_digest"] == core.framed_digest("catchplate.metadataAuditOutboxEvent/v1", outbox["event_json"].encode("ascii")))
    # Completion is the genuine outbox fact. The separate factual settlement
    # may still be pending; neither state authorizes retry of the original bind.
    profile.require(event["audit_status"] in {"controlled_pending", "audited"}
        and type(event["audit_attempts"]) is int and event["audit_attempts"] == 0
        and all(event[name] is None for name in ("audit_claim_id", "audit_claimed_at", "audit_last_error")))
    profile.require((event["audited_at"] is None and event["audit_event_hash"] is None)
        if event["audit_status"] == "controlled_pending" else
        (event["audited_at"] == outbox["audited_at"] and event["audit_event_hash"] == outbox["audit_event_hash"]))
    credential = shared._row(context.exact("credentials", {"id": session["credential_id"]}), "current bound static credential")
    public = {name: credential[name] for name in binding.CREDENTIAL_FIELDS}
    public["metadata"] = shared._canonical_stored_mapping(credential["metadata"], "current static credential metadata")
    profile.require(credential["kind"] in static_creation.KINDS and public["metadata"].get("oauth") is not True
        and profile.sha256(binding.credential_original(public)) == details["credentialOriginalSha256"])
    return session


@dataclass(frozen=True, slots=True)
class BindCandidateKernel:
    operation: str = profile.OP_BIND
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "catchplate_policy_authority_setup_policy_bind_candidate"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("Setup policy association needs original owner hardware evidence")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values, claim, bound, management = _inputs(arguments)
        request = values["request"]
        sid, cid = request["setupBinding"]["sessionId"], request["credentialId"]
        event_key = {"id": request["credentialBindingEventId"] if profile.is_static_request(request)
            else profile.setup.event_id(sid, 4)}
        queries = list(originals.queries(self.operation, bound, management))
        from catchplate import authority_primary_contract as primary
        queries.extend(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table),
            table=table, predicates=(), order_by=tuple(core.QueryOrder(field) for field in primary.PRIMARY_KEY_COLUMNS[table]),
            maximum_rows=inventory.MAX_ROWS + 1, proof_primitive="bounded-limit-plus-one", work_units=inventory.MAX_ROWS + 1, page_size=inventory.MAX_ROWS)
            for table in inventory.TABLES)
        queries.extend((originals.exact(self.operation, "setup", "setup_sessions", {"id": sid}),
            originals.exact(self.operation, "setup_activation", "setup_session_events", event_key),
            originals.exact(self.operation, "setup_audit_link", profile.setup.AUDIT_LINK_TABLE, event_key),
            originals.exact(self.operation, "setup_audit_completion", "metadata_audit_outbox", {
                "id": core.SelectedRowFieldReference(profile.setup.AUDIT_LINK_TABLE, event_key, "outbox_id")}),
            originals.exact(self.operation, "continuation", profile.TABLE, {"session_id": sid}, absence=True),
            originals.exact(self.operation, "credential", "credentials", {"id": cid}),
            originals.exact(self.operation, "credential_generation", "credential_generations", {"credential_id": cid}),
            currentness.root_query(self.operation, cid, request["credentialVersion"]),
            shared._role_query(self.operation, "owner", values["actor_id"]), shared._audit_query(self.operation, request_digest)))
        if set(request) == profile.ROTATED_STATIC_REQUEST_FIELDS:
            queries.append(originals.exact(self.operation, "rotation_provenance_audit", "metadata_audit_outbox",
                {"id": static_provenance.generation_outbox_id(request["credentialProvenanceOriginal"])}))
        for name, table, field in (("hardware", "webauthn_credentials", "credentialRecordId"),
                ("challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(originals.exact(self.operation, name, table, {"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        return tuple(queries)

    def transition(self, context):
        from catchplate import db
        values, claim, bound, management = _inputs(context.arguments)
        request, actor = values["request"], values["actor_id"]
        now = shared._database_epoch_ns(context.database_now)
        profile.require(request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
        shared._require_role(context, subject_id=actor, required_role="credential_owner")
        evidence = context.verified_webauthn_evidence
        profile.require(evidence is not None)
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "actual Setup owner hardware")
        hardware._hardware(credential, values["credential_policy"])
        profile.require(evidence["rpId"] == values["credential_policy"]["rpId"]
            and evidence["origin"] in values["credential_policy"]["origins"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= values["credential_policy"]["maxAssertionAgeSeconds"] * 1_000_000_000)
        static_binding = profile.is_static_request(request)
        session = _static_bound_session(context, values) if static_binding else _activated_session(context, values)
        selected = context.exact(profile.TABLE, {"session_id": session["id"]})
        profile.require(not selected["present"], "Setup already has a candidate successor; inspect, never overwrite")
        credential = shared._row(context.exact("credentials", {"id": session["credential_id"]}), "actual active Setup credential")
        generation = shared._row(context.exact("credential_generations", {"credential_id": session["credential_id"]}), "actual credential version")
        _, root = currentness.require_root(context, session["credential_id"], session["credential_version"])
        profile.require(credential["lifecycle_status"] == "active" and credential["credential_version"] == session["credential_version"]
            == generation["last_version"] and root["status"] == "open")
        if static_binding:
            profile.require(root["barrier_id"] is None)
        if set(request) == profile.ROTATED_STATIC_REQUEST_FIELDS:
            outbox = shared._row(context.exact("metadata_audit_outbox", {
                "id": static_provenance.generation_outbox_id(request["credentialProvenanceOriginal"])}),
                "actual completed static rotation audit")
            profile.verify_rotated_rows(request["credentialProvenanceOriginal"], selection=context.setup_rotated_static_policy,
                credential=credential, generation=generation, root=root, outbox=outbox,
                configuration_digest=values["control_plane_configuration_digest"], now_epoch_ns=now)
        actual_claim = shared._row(context.exact(candidate.TABLE, {"request_id": claim["request_id"]}), "actual completed generation claim")
        profile.require(actual_claim == claim and claim["configuration_digest"] == values["control_plane_configuration_digest"])
        actual = originals.original_context(context, bound, management)
        profile.require(actual["head"]["assignment_envelope_digest"] == bound["assignmentEnvelopeDigest"])
        published = shared._row(context.exact("policy_shadow_generation_publications", {
            "generation_publication_envelope_digest": claim["publication_envelope_digest"]}), "actual native generation publication")
        profile.require(published["request_id"] == claim["request_id"]
            and published["management_request_json"] == claim["management_request_json"]
            and published["management_actor_id"] == claim["actor_id"]
            and published["request_payload_digest"] == claim["payload_digest"]
            and published["candidate_id"] == bound["candidateId"] and published["canary_id"] == bound["canaryId"]
            and published["assignment_envelope_digest"] == bound["assignmentEnvelopeDigest"]
            and published["load_receipt_envelope_digest"] == bound["loadReceiptEnvelopeDigest"]
            and published["candidate_policy_hash"] == actual["artifact"]["policy_hash"]
            and published["candidate_policy_bundle_digest"] == actual["candidate_bundle_digest"])
        projection = db._policy_shadow_generation_evidence(published)
        for source, receipt_field in zip(publication.evidence_inputs(published, projection), (
                "rust_attestation_verification_receipt_digest", "verification_receipt_digest"), strict=True):
            trust.historical(context, receipt_digest=published[receipt_field], **source)
        assignment, assignment_digest = profile.reviewed_assignment(session, management)
        profile.require(assignment["policyHash"] == actual["artifact"]["policy_hash"]
            and request["routePolicyDigest"] == assignment["routePolicyDigest"] and request["assignmentDigest"] == assignment_digest)
        row = {"session_id": session["id"], "revision": 0, "phase": "candidate_bound", "owner_id": actor,
            "setup_original": profile.setup.row_original(session).decode("ascii"), "setup_sha256": request["setupBinding"]["rowSha256"],
            "credential_id": session["credential_id"], "credential_version": session["credential_version"],
            "generation_request_id": claim["request_id"], "generation_claim_sha256": profile.sha256(request["generationClaimOriginal"].encode("ascii")),
            "generation_publication_digest": claim["publication_envelope_digest"], "candidate_id": bound["candidateId"],
            "canary_id": bound["canaryId"], "artifact_envelope_digest": bound["artifactEnvelopeDigest"],
            "assignment_envelope_digest": bound["assignmentEnvelopeDigest"], "policy_hash": assignment["policyHash"],
            "route_policy_digest": assignment["routePolicyDigest"], "assignment_digest": assignment_digest,
            "request_original": profile.canonical(values).decode("ascii"), "request_digest": context.request_digest,
            "configuration_digest": values["control_plane_configuration_digest"],
            "created_at": context.database_now.astimezone(timezone.utc).isoformat(), "expires_at": session["expires_at"]}
        raw = profile.row_original(row)
        audit, audit_digest, replayed = shared._audit_mutations(context, event_type=self.operation, actor_type="admin", actor_id=actor,
            event={"schema": "catchplate.setupPolicyCandidateAudit/v1", "requestDigest": context.request_digest,
                "sessionId": session["id"], "continuationSha256": profile.sha256(raw), "setupSha256": row["setup_sha256"],
                "generationPublicationSha256": row["generation_publication_digest"], "assignmentSha256": assignment_digest})
        profile.require(not replayed)
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=selected, row=row),)
            + tuple(assertion._assertion_mutations(context, {"actor_id": actor})) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "continuationOriginal": raw.decode("ascii")}, work_units=4096)


def verify_rotated_plan(*, payload, arguments, verified_webauthn_evidence,
        selected_policy, deadline_ns, now_epoch_ns, work):
    """Independent exact source replay after authenticated plan/root admission."""
    from datetime import datetime
    from catchplate import authority_audit_capacity as capacity
    from catchplate import authority_challenge_retention as retention
    from catchplate.authority_query_read_work import _ValidationWork
    from catchplate.authority_transition_static_credential_rotation_approval import _original_copy

    profile.require(type(work) is _ValidationWork and type(payload) is dict and type(arguments) is dict
        and type(verified_webauthn_evidence) is dict and type(selected_policy) is dict)
    core.require_integer(deadline_ns, "original Setup deadline", minimum=1, maximum=2**63 - 1)
    core.require_integer(now_epoch_ns, "current Setup verifier time", minimum=1, maximum=2**63 - 1)
    expires = None

    def check():
        current = time.time_ns()
        profile.require(time.monotonic_ns() < deadline_ns and now_epoch_ns <= current
            and (expires is None or current < expires))

    def equal(left, right):
        profile.require(profile.canonical(_original_copy(left, work)) == profile.canonical(_original_copy(right, work)),
            "Rotated Setup plan differs from its original source effects")

    check()
    owned = _original_copy({"payload": payload, "arguments": arguments,
        "evidence": verified_webauthn_evidence, "policy": selected_policy}, work)
    plan, evidence = owned["payload"], owned["evidence"]
    values = profile.arguments(profile.OP_BIND, owned["arguments"], typed="businessIntent" in owned["arguments"])
    profile.rotated_provenance(values["request"])
    typed, measured, projection = plan["typedRequest"], plan["measuredPlan"], plan["authorizationProjection"]
    profile.require(typed["operation"] == measured["operation"] == profile.OP_BIND)
    equal(profile.arguments(profile.OP_BIND, typed["arguments"], typed=True), values)
    equal(plan["webauthnEvidence"], evidence)
    request_digest = profile.request_digest(profile.OP_BIND, values)
    profile.require(typed["requestDigest"] == measured["requestDigest"] == evidence["requestDigest"] == request_digest
        and measured["deadlineMonotonicNs"] == deadline_ns)
    expires = measured["deadlineEpochNs"]
    core.require_integer(expires, "signed Setup expiry", minimum=1, maximum=2**63 - 1)
    selected, mutations = plan["selectedBusinessRows"], plan["mutationPlan"]
    work.prepare_scan(mutations)
    challenges = [item for item in mutations if item["table"] == "webauthn_challenges"
        and item["key"] == {"id": evidence["challengeId"]}]
    profile.require(len(challenges) == 1 and challenges[0]["operation"] == "UPDATE" and type(challenges[0]["row"]) is dict)
    stamp = challenges[0]["row"]["used_at"]
    cutoff = profile.setup.epoch(stamp)
    profile.require(values["request"]["issuedAtEpochNs"] <= projection["createdAtEpochNs"] <= cutoff <= now_epoch_ns
        and evidence["verifiedAtEpochNs"] <= cutoff and now_epoch_ns < expires
        and projection["expiresAtEpochNs"] == expires <= values["request"]["expiresAtEpochNs"]
        and expires <= evidence["expiresAtEpochNs"])
    roots = plan["rootTransition"]
    require_complete_populations(selected_rows=selected,
        before_roots=tuple(roots["businessBeforeRoots"]) + tuple(roots["authorizationBeforeRoots"]),
        work=work, deadline_ns=deadline_ns)
    context = core.KernelContext(profile.OP_BIND, typed["arguments"], tuple(selected), datetime.fromisoformat(stamp),
        request_digest, verified_webauthn_evidence=evidence, setup_rotated_static_policy=owned["policy"])
    kernel = BindCandidateKernel()
    transition = kernel.transition(context)
    check()
    expanded = retention.expand_mutations(context, transition.mutations, work=work)
    expected = capacity._finalize_capacity(context, expanded, work=work)
    expected = sorted(expected, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
    equal(mutations, expected); equal(plan["expectedResult"], transition.result)
    queries = capacity.add_capacity_query(profile.OP_BIND, kernel.queries_with_evidence(arguments=typed["arguments"],
        database_now=context.database_now, request_digest=request_digest, evidence=evidence))
    profile.require(measured["workUnits"] == capacity.transition_work_units(operation=profile.OP_BIND,
        query_work_units=sum(query.work_units for query in queries), kernel_work_units=transition.work_units,
        mutations=tuple(expected)))
    check()


KERNELS = MappingProxyType({profile.OP_BIND: BindCandidateKernel()})
