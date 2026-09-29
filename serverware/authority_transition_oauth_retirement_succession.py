"""Protected append-only scope succession; provider I/O stays measured-native."""
from dataclasses import dataclass
from types import MappingProxyType
from serverware import authority_oauth_retirement_succession as p
from serverware import authority_oauth_retirement_succession_records as rows
from serverware import authority_oauth_retirement_succession_queries as queries
from serverware import authority_oauth_retirement_succession_snapshots as snapshots
from serverware import authority_oauth_retirement_succession_lineages as lineages
from serverware import authority_oauth_retirement_succession_inventory as inventory
from serverware import authority_oauth_retirement_succession_materials as materials
from serverware import authority_oauth_retirement_succession_contacts as contacts
from serverware import authority_oauth_retirement_succession_approvals as approvals
from serverware import authority_oauth_retirement_succession_retire as retire
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_exchange as exchange
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_measured_pending_retirement as pending
from serverware import authority_oauth_provider_retirement as provider
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_oauth_activation as approval_public


def _head(context, grant, *, current_scope=False):
    selected = context.exact(p.HEAD_TABLE, {"id": p.head_id(grant["providerId"])})
    if not selected["present"]:
        p.require(not current_scope and grant["previousHeadSha256"] is None)
        return selected, None
    head = shared._row(selected, "actual monotonic provider succession head"); rows.head_original(head)
    p.require(head["provider_id"] == grant["providerId"])
    if current_scope:
        p.require(head["scope_id"] == grant["authorizationId"] and head["scope_kind"] == grant["scope"]["kind"]
            and head["provider_subject"] == grant["scope"]["providerSubject"])
    else:
        p.require(p.sha256(rows.head_original(head)) == grant["previousHeadSha256"]
            and any(pin["kind"] == "succession" and pin["id"] == head["scope_id"] for pin in grant["predecessors"])
            and (grant["scope"]["kind"] == "provider" or head["scope_kind"] == "family" and head["provider_subject"] == grant["providerSubject"]),
            "head change requires an independently authorized complete widening scope")
    return selected, head


def _snapshot_bindings(context, grant, journal):
    result = []
    for item in grant["inventoryRoots"]:
        selected = context.exact(p.SNAPSHOT_TABLE, {"id": p.snapshot_id(grant["authorizationId"], item["part"])})
        row = shared._row(selected, "actual one-use complete acquisition")
        raw = snapshots.original(row)
        p.require(row["authorization_id"] == grant["authorizationId"] and row["authorization_sha256"] == journal["authorization_sha256"]
            and row["root_original_json"] == p.canonical(item["root"]).decode("ascii")
            and row["expires_at"] == journal["admission_expires_at"])
        result.append({"snapshotId": row["id"], "snapshotSha256": p.sha256(raw)})
    return result


def _predecessor_coverage(graph, grant):
    expected = {(pin["kind"], pin["id"]) for pin in grant["predecessors"]}
    p.require(len(graph.rows(family.TABLE)) + len(graph.rows(pending.FAMILY_TABLE)) <= 32,
        "the two actual family populations retain their shared capacity; no split-root omission")
    for kind, table in (("refresh-family", family.TABLE), ("pending-family", pending.FAMILY_TABLE)):
        for marker in graph.rows(table):
            if marker["provider_id"] == grant["providerId"] and (grant["scope"]["kind"] == "provider" or marker["provider_subject"] == grant["providerSubject"]):
                p.require((kind, marker["id"]) in expected, "actual predecessor family fence was omitted")
    for marker in graph.rows(provider.TABLE):
        if marker["provider_id"] == grant["providerId"]:
            p.require(grant["scope"]["kind"] == "provider" and ("provider-capture", marker["id"]) in expected)
    for journal in graph.rows(rows.reconnect.JOURNAL_TABLE):
        rows.reconnect.journal_original(journal)
        previous = rows.reconnect.grant_document(journal["authorization_original"].encode("ascii"))["payload"]
        if journal["status"] == "fenced" and previous["providerId"] == grant["providerId"] and (grant["scope"]["kind"] == "provider" or previous["providerSubject"] == grant["providerSubject"]):
            p.require(("reconnect-fence", journal["id"]) in expected, "actual fenced reconnect history was omitted")


@dataclass(frozen=True, slots=True)
class SuccessionKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        return queries.build(self.operation, arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        return queries.build(self.operation, arguments, request_digest, evidence)

    def transition(self, context):
        values = p.arguments(self.operation, context.arguments, typed=True); grant = lineages.grant(values)
        now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
        p.require(grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        shared._require_role(context, subject_id=values["actor_id"], required_role="credential_owner")
        effects, scope, head, custody, exchanged, candidate, association = [], None, None, None, None, None, None
        claims, attempts = [], []
        observation = {"status": None, "approval": None, "snapshotOriginal": None, "materialOriginal": None,
            "contactDisposition": None, "closureSha256": None}
        if self.operation == p.OP_AUTHORIZE:
            selected = context.exact(p.JOURNAL_TABLE, {"id": grant["authorizationId"]})
            p.require(not selected["present"] and len(context.present_rows(p.JOURNAL_TABLE)) < p.MAX_HISTORY
                and now < grant["admissionExpiresAtEpochNs"])
            _, head = _head(context, grant)
            members = lineages.members(context, grant); rows.predecessors(context, grant["predecessors"])
            target = next(row for row, _ in members if row["id"] == grant["credentialId"])
            lineages.exact_application(values, grant, target)
            approval, evidence, mutations = approvals.transition(context, values, grant)
            effects.extend(mutations)
            journal = {"id": grant["authorizationId"], "provider_id": grant["providerId"],
                "authorization_original": p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES).decode("ascii"),
                "authorization_sha256": values["request"]["authorizationSha256"],
                "enrollment_original": p.activation.enrollment_bytes(values["enrollment_original"]).decode("ascii"), "actor_id": values["actor_id"],
                "credential_policy_json": p.canonical(values["credential_policy"]).decode("ascii"),
                "authorize_arguments_json": p.canonical(values).decode("ascii"), "authorize_request_digest": context.request_digest,
                "approval_id": approval["id"], "requester_credential_id": evidence["credentialRecordId"],
                "requester_evidence_expires_at": lineages.iso(evidence["expiresAtEpochNs"]),
                "fence_arguments_json": None, "fence_request_digest": None, "scope_original_json": None,
                "status": "requested", "created_at": stamp, "admission_expires_at": lineages.iso(grant["admissionExpiresAtEpochNs"]),
                "expires_at": lineages.iso(grant["expiresAtEpochNs"]), "updated_at": stamp}
            rows.journal_original(journal)
            effects.append(core.mutation(operation=self.operation, selected=selected, row=journal))
            observation["approval"] = approval_public._public(approval)
        elif self.operation in p.SNAPSHOT_OPERATIONS:
            _, journal, _ = lineages.journal(context, values, statuses={"requested"})
            _, head = _head(context, grant)
            snapshot, mutation = snapshots.create(context, values, journal)
            effects.append(mutation); observation["snapshotOriginal"] = snapshots.original(snapshot).decode("ascii")
        elif self.operation == p.OP_AUTHORIZE_DECIDE:
            selected, journal, _ = lineages.journal(context, values, statuses={"requested"})
            p.require(values["approval_id"] == journal["approval_id"]
                and values["request"]["authorizationRowSha256"] == p.sha256(rows.journal_original(journal))
                and now < grant["admissionExpiresAtEpochNs"])
            _, head = _head(context, grant); lineages.members(context, grant); rows.predecessors(context, grant["predecessors"])
            _snapshot_bindings(context, grant, journal)
            approval, _, mutations = approvals.transition(context, values, grant)
            effects.extend(mutations)
            journal = {**journal, "status": "approved", "updated_at": stamp}
            effects.append(core.mutation(operation=self.operation, selected=selected, row=journal))
            observation["approval"] = approval_public._public(approval)
        elif self.operation == p.OP_FENCE:
            selected, journal, _ = lineages.journal(context, values, statuses={"approved"})
            request = values["request"]
            p.require(request["authorizationRowSha256"] == p.sha256(rows.journal_original(journal))
                and grant["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"] <= grant["admissionExpiresAtEpochNs"])
            head_selected, previous = _head(context, grant)
            graph = snapshots.RetainedGraph(context, grant, journal)
            _predecessor_coverage(graph, grant)
            predecessor = rows.predecessors(context, grant["predecessors"])
            analysis = inventory.collect(graph, grant)
            material_originals = materials.collect(graph, grant, analysis, values["enrollment_original"])
            prior_contacts = contacts.catalogue(graph, grant)
            members = lineages.members(context, grant)
            p.require([refresh.credential_original(row).decode("ascii") for row, _ in members] == analysis["affectedCredentials"])
            approval, _, mutations = approvals.transition(context, values, grant, journal=journal)
            effects.extend(mutations)
            drains, mutations = lineages.fence(context, graph, grant, members, predecessor, request["currentnessBarriers"])
            effects.extend(mutations)
            sequence = 1 if previous is None else previous["sequence"] + 1
            p.require(sequence <= 2**63 - 1)
            scope = {"id": grant["authorizationId"], "provider_id": grant["providerId"], "sequence": sequence,
                "authorization_sha256": journal["authorization_sha256"], "previous_head_json": None if previous is None else rows.head_original(previous).decode("ascii"),
                "predecessors_json": p.canonical(predecessor).decode("ascii"),
                "affected_originals_json": p.canonical([{"credentialOriginal": refresh.credential_original(row).decode("ascii"),
                    "generationOriginal": refresh.generation_original(head).decode("ascii")} for row, head in members]).decode("ascii"),
                "inventory_original_json": p.canonical({"snapshotBindings": _snapshot_bindings(context, grant, journal),
                    "materialOriginals": material_originals, "priorContacts": prior_contacts, "analysisSha256": p.sha256(p.canonical(analysis))}).decode("ascii"),
                "currentness_barriers_json": p.canonical(drains).decode("ascii"), "fence_request_digest": context.request_digest,
                "created_at": stamp, "expires_at": journal["expires_at"]}
            raw_scope = rows.scope_original(scope)
            head = {"id": p.head_id(grant["providerId"]), "provider_id": grant["providerId"], "scope_kind": grant["scope"]["kind"],
                "provider_subject": grant["scope"]["providerSubject"], "sequence": sequence, "scope_id": scope["id"], "scope_sha256": p.sha256(raw_scope),
                "created_at": stamp if previous is None else previous["created_at"], "updated_at": stamp}
            rows.head_original(head)
            journal = {**journal, "status": "fenced", "fence_arguments_json": p.canonical(values).decode("ascii"),
                "fence_request_digest": context.request_digest, "scope_original_json": raw_scope.decode("ascii"), "updated_at": stamp}
            effects.extend((core.mutation(operation=self.operation, selected=selected, row=journal),
                core.mutation(operation=self.operation, selected=context.exact(p.SCOPE_TABLE, {"id": scope["id"]}), row=scope),
                core.mutation(operation=self.operation, selected=head_selected, row=head)))
            observation["approval"] = approval_public._public(approval)
        else:
            journal_selected, journal, _ = lineages.journal(context, values, statuses={"fenced", "committed"})
            _, head = _head(context, grant, current_scope=True)
            scope = shared._row(context.exact(p.SCOPE_TABLE, {"id": grant["authorizationId"]}), "actual immutable admitted scope")
            raw_scope = rows.scope_original(scope)
            p.require(journal["scope_original_json"] == raw_scope.decode("ascii") and head["scope_sha256"] == p.sha256(raw_scope)
                and scope["authorization_sha256"] == journal["authorization_sha256"] and scope["fence_request_digest"] == journal["fence_request_digest"])
            custody_selected = context.exact(p.TABLE, {"id": grant["authorizationId"]})
            if custody_selected["present"]:
                custody = shared._row(custody_selected, "actual fresh-token custody"); rows.custody_original(custody)
                exchanged = shared._row(context.exact(exchange.TABLE, {"id": grant["authorizationId"]}), "actual fresh-token exchange"); exchange.row_original(exchanged)
            committed = None if custody is None or custody["status"] != "committed" else rows.stored(custody["committed_credential_json"], 512 * 1024)
            members = lineages.retained(context, scope, grant, committed=committed)
            target = next(row for row, _ in members if row["id"] == grant["credentialId"])
            if self.operation in p.NATIVE_OPERATIONS:
                p.require(values["request"]["scopeRowSha256"] == p.sha256(raw_scope))
            if self.operation in p.MATERIAL_OPERATIONS | {p.OP_RECOVER}:
                mutations, claims, attempts, extra = retire.transition(context, values, grant, scope)
                effects.extend(mutations); observation.update(extra)
                if self.operation == p.OP_RECOVER and committed is not None:
                    association = shared._row(context.exact(p.ASSOCIATION_TABLE,
                        {"id": p.association_id(grant["credentialId"], grant["credentialVersion"] + 1)}),
                        "actual historical committed successor association")
                    rows.association_original(association)
                    p.require(association["scope_id"] == scope["id"] and association["scope_sha256"] == p.sha256(raw_scope)
                        and association["credential_id"] == committed["id"] == grant["credentialId"]
                        and association["credential_version"] == committed["credential_version"] == grant["credentialVersion"] + 1
                        and association["credential_sha256"] == p.sha256(refresh.credential_original(committed))
                        and association["root_origin_request_digest"] == custody["commit_request_digest"])
                    # Historical observation only. This does not admit the
                    # current root, rejoin a holder or supply fresh send rights.
            else:
                lineages.exact_application(values, grant, target)
                claims, attempts = retire.observed(context, grant)
                _, material_originals = retire.material_list(scope)
                closure = contacts.complete(attempts, material_originals, grant["authorizationId"])
                observation["closureSha256"] = closure
                from serverware import authority_oauth_retirement_succession_fresh as fresh
                exchanged, custody, candidate, association, mutations, extra = fresh.transition(
                    context, values, grant, scope, journal, target, exchanged, custody, closure)
                effects.extend(mutations); observation.update(extra)
                if association is not None and journal["status"] != "committed":
                    journal = {**journal, "status": "committed", "updated_at": stamp}
                    effects.append(core.mutation(operation=self.operation, selected=journal_selected, row=journal))
        rows.journal_original(journal)
        observation["status"] = journal["status"] if custody is None else custody["status"]
        p.require(set(observation) == rows.OBSERVATION_FIELDS)
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="retired_scope_succession", actor_id=values["actor_id"], event={"schema": "serverware.oauthRetiredScopeSuccessionAudit/v1",
                "operation": self.operation, "requestDigest": context.request_digest, "authorizationSha256": journal["authorization_sha256"],
                "journalSha256": p.sha256(rows.journal_original(journal)), "status": observation["status"],
                "contactDisposition": observation["contactDisposition"]})
        p.require(not replay)
        result = {"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
            "auditEventDigest": audit_digest, "idempotentReplay": False, "observation": observation, "originals": {
                "journalOriginal": rows.journal_original(journal).decode("ascii"), "scopeOriginal": None if scope is None else rows.scope_original(scope).decode("ascii"),
                "headOriginal": None if head is None else rows.head_original(head).decode("ascii"),
                "materialOriginals": [rows.material_original(row).decode("ascii") for row in claims],
                "attemptOriginals": [rows.attempt_original(row).decode("ascii") for row in attempts],
                "exchangeOriginal": None if exchanged is None else exchange.row_original(exchanged).decode("ascii"),
                "custodyOriginal": None if custody is None else rows.custody_original(custody).decode("ascii"),
                "candidateOriginal": None if custody is None else custody["candidate_original_json"],
                "associationOriginal": None if association is None else rows.association_original(association).decode("ascii")}}
        p.require(set(result) == rows.RESULT_FIELDS and set(result["originals"]) == rows.ORIGINALS_FIELDS
            and len(p.canonical(result)) <= p.MAX_KERNEL_RESULT)
        return core.KernelTransition(mutations=tuple(effects) + audit, result=result, work_units=8192)


KERNELS = MappingProxyType({operation: SuccessionKernel(operation) for operation in p.OPERATIONS})
