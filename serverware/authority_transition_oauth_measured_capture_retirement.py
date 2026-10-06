"""Actual retained pre-subject captures -> explicit complete-provider retirement.

The same protected transaction consumes every real holder barrier, installs a
permanent provider fence and burns the retained work. No subject is guessed and
no old consent window is renewed. Provider contact is a later one-use phase.
"""
from dataclasses import dataclass
from serverware import authority_oauth_retirement_succession_current as succession
from types import MappingProxyType

from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_oauth_measured_capture_retirement as p
from serverware import authority_oauth_exchange as exchange
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_activation as activation
from serverware import authority_oauth_revocation as retained
from serverware import authority_oauth_measured_exchange as unbound
from serverware import authority_oauth_measured_setup as setup
from serverware import authority_oauth_setup as setup_rows
from serverware import authority_oauth_provider_retirement as provider
from serverware import authority_credential_currentness as roots
from serverware import authority_transition_credential_currentness as currentness
from serverware.authority_transition_oauth_exchange import _iso

POPULATIONS = ("credentials", "pending_oauth_credentials", exchange.TABLE, refresh.TABLE)


def _stored(raw, maximum=p.MAX_ROW_BYTES):
    p.require(type(raw) is str and raw.isascii())
    return p.document(raw.encode("ascii"), maximum)


def _grant(values):
    return p.grant_document(p.unb64(values["authorization_original"], p.MAX_GRANT_BYTES))["payload"]


def _contract(grant):
    return setup if grant["workSource"] == setup.WORK_SOURCE else unbound


def _originals(context, values, grant):
    contract = _contract(grant)
    row = shared._row(context.exact(exchange.TABLE, {"id": grant["exchangeId"]}), "retained captured exchange")
    custody = shared._row(context.exact(contract.TABLE, {"id": grant["exchangeId"]}), "actual issuance custody")
    row_raw, custody_raw = exchange.row_original(row), contract.row_original(custody)
    p.require(p.sha256(row_raw) == grant["exchangeRowSha256"] and p.sha256(custody_raw) == grant["custodyRowSha256"]
        and row["id"] == custody["id"] == grant["exchangeId"] and row["provider_id"] == grant["providerId"]
        and row["status"] == "retained" and custody["status"] == "captured"
        and custody["pending_original_json"] is None and custody["stage_arguments_json"] is None
        and custody["cancel_arguments_json"] is None and row["enrollment_original"] == values["enrollment_original"])
    consent = contract.request_binding(contract.OP_PREPARE, _stored(row["consent_json"]))
    preparation = contract.arguments(contract.OP_PREPARE, _stored(custody["preparation_arguments_json"]))
    claim = contract.arguments(contract.OP_CLAIM, _stored(custody["claim_arguments_json"]))
    capture = contract.arguments(contract.OP_CAPTURE, _stored(custody["capture_arguments_json"]))
    request = capture["request"]
    p.require(p.sha256(custody["capture_arguments_json"].encode("ascii")) == grant["captureArgumentsSha256"]
        and preparation["request"] == consent and all(item["resource_id"] == row["id"]
            and item["enrollment_original"] == values["enrollment_original"]
            and item["actor_id"] == row["requester_id"] for item in (preparation, claim, capture))
        and consent["enrollmentSha256"] == grant["enrollmentSha256"] and consent["providerId"] == grant["providerId"]
        and request["rawResponseSha256"] == row["raw_response_sha256"] == grant["rawResponseSha256"]
        and p.canonical(request["rawResponseEnvelope"]).decode("ascii") == row["raw_response_envelope_json"]
        and p.sha256(p.canonical(request["rawResponseEnvelope"])) == grant["rawResponseEnvelopeSha256"]
        and request["issuedMaterialEnvelope"] is not None
        and request["issuedMaterialSha256"] == row["token_secret_sha256"] == grant["tokenSecretSha256"]
        and p.canonical(request["issuedMaterialEnvelope"]).decode("ascii") == row["token_envelope_json"]
        and p.sha256(p.canonical(request["issuedMaterialEnvelope"])) == grant["tokenEnvelopeSha256"]
        and request["receivedAtEpochNs"] == custody["received_at_epoch_ns"]
        and custody["owner_nonce_sha256"] == p.sha256(p.unb64(request["ownerNonce"], 32, 32)))
    for item in (claim, capture):
        p.require(item["request"]["exchangeId"] == row["id"] and item["assignment_original"] == claim["assignment_original"])
    for name in ("holderId", "bootId", "keyId", "instanceId", "enrollmentSha256"):
        p.require(claim["native_evidence"]["statement"][name] == capture["native_evidence"]["statement"][name])
    # Keep a literal Setup original; old expiry does not authorize cleanup and
    # a new cleanup grant does not make an expired Setup active again.
    setup_original = None
    if contract is setup:
        p.require(custody["setup_final_json"] is None)
        bound = consent["setupBinding"]
        p.require(bound["sessionId"] == grant["setupSessionId"])
        selected = context.exact("setup_sessions", {"id": bound["sessionId"]})
        actual = shared._row(selected, "original unfinished Setup")
        setup_original = setup_rows.row_original(actual).decode("ascii")
        p.require(setup_original == custody["setup_started_json"] and actual["phase"] == "oauth_started"
            and actual["status"] == "active" and actual["revision"] == 1
            and p.sha256(custody["setup_initial_json"].encode("ascii")) == grant["setupInitialSha256"]
            and p.sha256(custody["setup_started_json"].encode("ascii")) == grant["setupStartedSha256"]
            and p.sha256(setup_original.encode("ascii")) == grant["setupCurrentSha256"]
            and all(item["request"]["setupBinding"] == bound for item in (preparation, claim, capture)))
    p.require(not context.exact("pending_oauth_credentials", {"id": row["id"]})["present"]
        and not context.exact("credentials", {"id": row["id"]})["present"])
    return row, custody, request, setup_original


def _population(context, grant):
    """Real complete roots, never provider-filtered rows presented as absence."""
    found = []
    for selected in context.present_rows("credentials"):
        row = shared._row(selected, "complete provider credential population")
        refresh.credential_original(row)
        if row["kind"] != "oauth2":
            continue
        metadata = shared._canonical_stored_mapping(row["metadata"], "OAuth provider classification")
        p.require(metadata.get("provider_id") in {"google", "x"}, "unclassified OAuth credential blocks retirement")
        if metadata["provider_id"] == grant["providerId"]:
            found.append(row)
    found.sort(key=lambda row: row["id"])
    p.require([row["id"] for row in found] == [item["credentialId"] for item in grant["affectedLineages"]]
        and len(found) <= p.MAX_AFFECTED_LINEAGES, "grant must name every actual local provider lineage")
    for selected in context.present_rows("pending_oauth_credentials"):
        row = shared._row(selected, "complete pending population")
        activation.pending_original(row)
        if row["kind"] == "oauth2":
            metadata = shared._canonical_stored_mapping(row["metadata"], "pending provider classification")
            p.require(metadata.get("provider_id") in {"google", "x"}, "unclassified pending original blocks retirement")
    for selected in context.present_rows(exchange.TABLE):
        row = shared._row(selected, "complete issuance population")
        exchange.row_original(row)
        if row["provider_id"] == grant["providerId"] and row["id"] != grant["exchangeId"]:
            # Prepared cannot POST after the same-transaction fence is installed;
            # retained/staged have captured their response. Claimed is unknown,
            # regardless of elapsed time, cancellation intention or row age.
            p.require(row["status"] in {"prepared", "retained", "staged"},
                "another unresolved provider exchange prevents retirement")
    for selected in context.present_rows(refresh.TABLE):
        row = shared._row(selected, "complete refresh population")
        refresh.row_original(row)
        if row["provider_id"] == grant["providerId"]:
            p.require(row["status"] in {"retained", "committed"},
                "another unresolved provider refresh prevents retirement")
    return found


def _affected(context, grant, *, journal=None):
    prior = None
    if journal is not None:
        prior = p.document(b'{"items":' + journal["original_affected_json"].encode("ascii") + b'}', p.MAX_ROW_BYTES)["items"]
        p.require(type(prior) is list and len(prior) == len(grant["affectedLineages"]))
    originals = []
    for index, pin in enumerate(grant["affectedLineages"]):
        root_id = roots.root_id(pin["credentialId"], pin["credentialVersion"])
        p.require(sum(shared._row(item, "affected currentness barrier")["root_id"] == root_id
            for item in context.present_rows(roots.BARRIER_TABLE)) <= 1,
            "Affected lineage has more than one currentness barrier")
        row = shared._row(context.exact("credentials", {"id": pin["credentialId"]}), "actual affected provider credential")
        head = shared._row(context.exact("credential_generations", {"credential_id": pin["credentialId"]}), "actual provider generation")
        head_raw = refresh.generation_original(head)
        if prior is None:
            p.require(row["lifecycle_status"] == "active" and row["revocation_requested_at"] is None and row["revocation_error"] is None)
            before = row
            _, root = currentness.require_root(context, row["id"], pin["credentialVersion"])
            p.require(root["status"] in {"open", "admitted"})
        else:
            p.require(type(prior[index]) is dict and set(prior[index]) == {"credentialOriginal", "generationOriginal"})
            before = _stored(prior[index]["credentialOriginal"])
            p.require(prior[index]["generationOriginal"] == head_raw.decode("ascii")
                and row == {**before, "lifecycle_status": "revocation_pending", "revocation_requested_at": journal["created_at"],
                    "updated_at": journal["created_at"]})
        raw = refresh.credential_original(before)
        metadata = shared._canonical_stored_mapping(before["metadata"], "affected provider original")
        p.require(before["kind"] == "oauth2" and metadata.get("provider_id") == grant["providerId"]
            and before["credential_version"] == head["last_version"] == pin["credentialVersion"]
            and p.sha256(raw) == pin["credentialRowSha256"] and p.sha256(head_raw) == pin["generationRowSha256"])
        originals.append({"credentialOriginal": raw.decode("ascii"), "generationOriginal": head_raw.decode("ascii")})
    return originals


def _status(attempts, purposes):
    states = [row["status"] for row in attempts]
    if "unknown" in states:
        return "unknown"
    if len(states) < len(purposes) or "contact-claimed" in states:
        return "claimed"
    return "observed-rejected" if "rejected" in states else "observed-accepted"


def _work(before, journal, attempts):
    return {**before, "status": "capture_retirement_" + journal["status"].replace("-", "_"),
        "attempts": len(attempts), "updated_at": journal["updated_at"]}


@dataclass(frozen=True)
class CaptureRetirementKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = p.arguments(self.operation, dict(arguments), typed=True); grant = _grant(values)
        contract = _contract(grant)
        queries = [provider.query(self.operation, grant["providerId"])]
        if self.operation in succession.GUARDED_OPERATIONS:
            queries.append(succession.query(self.operation, grant["providerId"]))
        if self.operation in {p.OP_INSPECT, p.OP_CLAIM}:
            for table in POPULATIONS:
                queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table),
                    table=table, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=p.MAX_POPULATION + 1,
                    proof_primitive="bounded-limit-plus-one", work_units=p.MAX_POPULATION + 1, page_size=p.MAX_POPULATION))
        for name, table, key in (("exchange", exchange.TABLE, {"id": grant["exchangeId"]}),
                ("issuance_custody", contract.TABLE, {"id": grant["exchangeId"]}),
                ("work", "oauth_revocation_work", {"id": grant["exchangeId"]}),
                ("pending", "pending_oauth_credentials", {"id": grant["exchangeId"]}),
                ("target_credential", "credentials", {"id": grant["exchangeId"]}),
                ("journal", p.JOURNAL_TABLE, {"id": grant["exchangeId"]}),
                ("custody", p.TABLE, {"id": grant["exchangeId"]})):
            queries.append(shared._query(operation=self.operation, name=name, table=table, key=key))
        if contract is setup:
            queries.append(shared._query(operation=self.operation, name="setup_capture_owner", table="setup_sessions",
                key={"id": grant["setupSessionId"]}))
        for pin in grant["affectedLineages"]:
            suffix = pin["credentialId"].replace("-", "")
            for name, table, key in (("credential_", "credentials", {"id": pin["credentialId"]}),
                    ("generation_", "credential_generations", {"credential_id": pin["credentialId"]}),
                    ("root_", roots.ROOT_TABLE, {"id": roots.root_id(pin["credentialId"], pin["credentialVersion"])})):
                queries.append(shared._query(operation=self.operation, name=name + suffix, table=table, key=key))
            queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "barrier_" + suffix, roots.BARRIER_TABLE),
                table=roots.BARRIER_TABLE, predicates=(core.QueryPredicate("root_id", "eq", roots.root_id(pin["credentialId"], pin["credentialVersion"])),),
                order_by=(core.QueryOrder("id"),), maximum_rows=2, proof_primitive="bounded-limit-plus-one", work_units=2, page_size=1))
        for purpose in grant["tokenPurposes"]:
            queries.append(shared._query(operation=self.operation, name="attempt_" + purpose, table=p.ATTEMPT_TABLE,
                key={"id": p.attempt_id(grant["exchangeId"], purpose)}))
        queries.append(shared._audit_query(self.operation, request_digest))
        return tuple(queries)

    def transition(self, context):
        values = p.arguments(self.operation, dict(context.arguments), typed=True); grant = _grant(values)
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, grant["providerId"])
        request = values["request"]; statement = values["evidence"]["statement"]
        now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
        p.require(statement["issuedAtEpochNs"] <= now < statement["expiresAtEpochNs"])
        if self.operation != p.OP_RECOVER:
            p.require(grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        row, original_custody, capture, setup_original = _originals(context, values, grant)
        if self.operation == p.OP_CLAIM:
            p.require(capture["rawResponseEnvelope"]["secret_kek_id"] == values["assignment_original"]["secretKekId"]
                and capture["issuedMaterialEnvelope"]["secret_kek_id"] == values["assignment_original"]["secretKekId"])
        selected = context.exact("oauth_revocation_work", {"id": grant["exchangeId"]})
        work = shared._row(selected, "captured issued work")
        journal_selected = context.exact(p.JOURNAL_TABLE, {"id": grant["exchangeId"]})
        custody_selected = context.exact(p.TABLE, {"id": grant["exchangeId"]})
        selections = {purpose: context.exact(p.ATTEMPT_TABLE, {"id": p.attempt_id(grant["exchangeId"], purpose)})
            for purpose in grant["tokenPurposes"]}
        attempts = [shared._row(item, "exact claimed revocation attempt") for item in selections.values() if item["present"]]
        authorization_sha = p.sha256(p.unb64(values["authorization_original"], p.MAX_GRANT_BYTES))
        fence_selected = context.exact(provider.TABLE, {"id": provider.provider_id(grant["providerId"])})
        journal, custody, mutations, attempt = None, None, [], None
        if not journal_selected["present"]:
            p.require(not custody_selected["present"] and not attempts)
            provider.require_open(context, grant["providerId"])
            before = work
            if self.operation in {p.OP_INSPECT, p.OP_CLAIM}:
                _population(context, grant)
            affected = _affected(context, grant)
        else:
            p.require(self.operation not in {p.OP_INSPECT, p.OP_CLAIM})
            journal = shared._row(journal_selected, "consumed capture retirement")
            custody = shared._row(custody_selected, "retirement originals")
            p.journal_original(journal); p.row_original(custody)
            p.require(journal["id"] == custody["id"] == grant["exchangeId"]
                and journal["authorization_original"] == values["authorization_original"]
                and journal["authorization_sha256"] == custody["authorization_sha256"] == authorization_sha
                and journal["work_source"] == grant["workSource"])
            before = _stored(journal["original_work_json"])
            p.require(work == _work(before, journal, attempts))
            affected = _affected(context, grant, journal=journal)
            fence = shared._row(fence_selected, "permanent complete-provider fence")
            p.require(set(fence) == provider.FIELDS and fence["provider_id"] == grant["providerId"]
                and fence["deployment_id"] == grant["deploymentId"] and fence["authorization_sha256"] == authorization_sha
                and fence["exchange_id"] == grant["exchangeId"] and fence["source_profile"] == grant["workSource"]
                and fence["claim_request_digest"] == journal["claim_request_digest"])
            claimed = p.arguments(p.OP_CLAIM, _stored(custody["claim_original_json"]))
            p.require(claimed["authorization_original"] == values["authorization_original"]
                and claimed["request"]["ownerNonceSha256"] == journal["owner_nonce_sha256"]
                and p.canonical(claimed["request"]["currentnessBarriers"]).decode("ascii") == journal["currentness_barriers_json"])
            for item in claimed["request"]["currentnessBarriers"]:
                currentness.require_consumed_capture_retirement_barrier(context, item["credentialId"], item["credentialVersion"],
                    item["barrierSha256"], claim_request_digest=journal["claim_request_digest"])
            contacts, finishes = _stored(custody["contact_originals_json"]), _stored(custody["finish_originals_json"])
            p.require(set(contacts) == {item["token_purpose"] for item in attempts}
                and set(finishes) == {item["token_purpose"] for item in attempts if item["status"] != "contact-claimed"})
            for item in attempts:
                p.attempt_original(item); purpose = item["token_purpose"]
                contact = p.arguments(p.OP_CONTACT, contacts[purpose])
                p.require(item["exchange_id"] == grant["exchangeId"] and item["id"] == p.attempt_id(grant["exchangeId"], purpose)
                    and contact["request"]["contactRequestSha256"] == item["contact_request_sha256"])
                if purpose in finishes:
                    finished = p.arguments(p.OP_FINISH, finishes[purpose])
                    raw = p.unb64(finished["request"]["transportOriginal"], p.MAX_TRANSPORT_BYTES)
                    p.require(item["transport_original"] == raw.decode("ascii") and item["transport_sha256"] == p.sha256(raw)
                        and item["status"] == p.transport(raw, item["contact_request_sha256"]))
            p.require(journal["status"] == _status(attempts, grant["tokenPurposes"]))
        retained.work_original(before)
        p.require(p.sha256(retained.work_original(before)) == grant["workRowSha256"]
            and before["id"] == row["id"] and before["provider_id"] == grant["providerId"]
            and before["source"] == grant["workSource"] and before["actor_id"] == row["requester_id"]
            and before["status"] == "held" and before["attempts"] == 0
            and all(before[name] is None for name in ("last_error", "lease_owner", "lease_until"))
            and all(before[name] == capture["issuedMaterialEnvelope"][name] for name in exchange.ENVELOPE_FIELDS))
        if self.operation in {p.OP_INSPECT, p.OP_RECOVER}:
            p.require(request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
            status = ("ready" if self.operation == p.OP_INSPECT else "no-local-claim") if journal is None else (
                "outcome-unknown" if journal["status"] == "claimed" else journal["status"])
            result = {"status": status, "exchangeOriginal": exchange.row_original(row).decode("ascii"),
                "issuanceCustodyOriginal": _contract(grant).row_original(original_custody).decode("ascii"),
                "workOriginal": retained.work_original(before).decode("ascii"),
                "captureArgumentsOriginal": original_custody["capture_arguments_json"],
                "enrollmentOriginal": p.unb64(values["enrollment_original"], 32768).decode("ascii"),
                "setupOriginal": setup_original, "affectedLineages": affected,
                "journalOriginal": None if journal is None else p.journal_original(journal).decode("ascii"),
                "custodyOriginal": None if custody is None else p.row_original(custody).decode("ascii"),
                "attemptOriginals": [p.attempt_original(item).decode("ascii") for item in attempts]}
            p.require(set(result) == p.OBSERVATION_FIELDS)
            return self._result(context, grant, values, (), result, status)
        if self.operation == p.OP_CLAIM:
            p.require(journal is None)
            for item in request["currentnessBarriers"]:
                mutations.extend(currentness.consume_barrier(context, item["credentialId"], item["credentialVersion"], item["barrierSha256"]))
                selected_credential = context.exact("credentials", {"id": item["credentialId"]})
                credential = shared._row(selected_credential, "drained provider credential")
                mutations.append(core.mutation(operation=self.operation, selected=selected_credential, row={**credential,
                    "lifecycle_status": "revocation_pending", "revocation_requested_at": stamp, "updated_at": stamp}))
            journal = {"id": grant["exchangeId"], "work_source": grant["workSource"],
                "authorization_original": values["authorization_original"], "authorization_sha256": authorization_sha,
                "original_work_json": retained.work_original(before).decode("ascii"), "original_affected_json": p.canonical(affected).decode("ascii"),
                "currentness_barriers_json": p.canonical(request["currentnessBarriers"]).decode("ascii"),
                "claim_request_digest": context.request_digest, "owner_nonce_sha256": request["ownerNonceSha256"],
                "status": "claimed", "created_at": stamp, "expires_at": _iso(grant["expiresAtEpochNs"]), "updated_at": stamp}
            custody = {"id": grant["exchangeId"], "authorization_sha256": authorization_sha,
                "claim_original_json": p.canonical(values).decode("ascii"), "contact_originals_json": "{}", "finish_originals_json": "{}",
                "created_at": stamp, "updated_at": stamp}
            mutations.append(core.mutation(operation=self.operation, selected=fence_selected, row={"id": provider.provider_id(grant["providerId"]),
                "provider_id": grant["providerId"], "deployment_id": grant["deploymentId"], "authorization_sha256": authorization_sha,
                "source_profile": grant["workSource"], "exchange_id": grant["exchangeId"], "claim_request_digest": context.request_digest, "created_at": stamp}))
        else:
            p.require(journal is not None and journal["status"] == "claimed" and p.sha256(p.journal_original(journal)) == request["journalRowSha256"]
                and journal["owner_nonce_sha256"] == p.sha256(p.unb64(request["ownerNonce"], 32, 32)))
            claimed = p.arguments(p.OP_CLAIM, _stored(custody["claim_original_json"]))
            p.require(claimed["assignment_original"] == values["assignment_original"]
                and all(claimed["evidence"]["statement"][name] == statement[name] for name in ("holderId", "bootId", "keyId", "instanceId")))
            purpose = request["tokenPurpose"]; attempt_selected = selections[purpose]
            if self.operation == p.OP_CONTACT:
                index = grant["tokenPurposes"].index(purpose)
                p.require(not attempt_selected["present"] and len(attempts) == index and all(item["status"] in {"accepted", "rejected"} for item in attempts))
                attempt = {"id": p.attempt_id(grant["exchangeId"], purpose), "exchange_id": grant["exchangeId"], "token_purpose": purpose,
                    "contact_request_sha256": request["contactRequestSha256"], "status": "contact-claimed", "transport_original": None,
                    "transport_sha256": None, "created_at": stamp, "updated_at": stamp}
                attempts.append(attempt)
            else:
                attempt = shared._row(attempt_selected, "irreversible provider contact")
                p.require(p.sha256(p.attempt_original(attempt)) == request["attemptRowSha256"] and attempt["status"] == "contact-claimed"
                    and attempt["transport_original"] is None)
                raw = p.unb64(request["transportOriginal"], p.MAX_TRANSPORT_BYTES)
                status = p.transport(raw, attempt["contact_request_sha256"]); transport = p.document(raw, p.MAX_TRANSPORT_BYTES)
                p.require(shared._database_epoch_ns(exchange.timestamp(attempt["created_at"])) <= transport["receivedAtEpochNs"] <= now
                    and transport["receivedAtEpochNs"] < grant["expiresAtEpochNs"]
                    and transport["rawResponseEnvelope"]["secret_kek_id"] == values["assignment_original"]["secretKekId"])
                attempt = {**attempt, "status": status, "transport_original": raw.decode("ascii"), "transport_sha256": p.sha256(raw), "updated_at": stamp}
                attempts = [attempt if item["token_purpose"] == purpose else item for item in attempts]
            mutations.append(core.mutation(operation=self.operation, selected=attempt_selected, row=attempt))
            field = "contact_originals_json" if self.operation == p.OP_CONTACT else "finish_originals_json"
            originals = _stored(custody[field]); p.require(purpose not in originals and len(originals) < 2)
            originals[purpose] = values
            custody = {**custody, field: p.canonical(originals).decode("ascii"), "updated_at": stamp}
            journal = {**journal, "status": _status(attempts, grant["tokenPurposes"]), "updated_at": stamp}
        work = _work(before, journal, attempts); retained.work_original(work)
        mutations.extend((core.mutation(operation=self.operation, selected=selected, row=work),
            core.mutation(operation=self.operation, selected=journal_selected, row=journal),
            core.mutation(operation=self.operation, selected=custody_selected, row=custody)))
        result = {"journalOriginal": p.journal_original(journal).decode("ascii"),
            "attemptOriginal": None if attempt is None else p.attempt_original(attempt).decode("ascii"),
            "custodyOriginal": p.row_original(custody).decode("ascii")}
        return self._result(context, grant, values, tuple(mutations), result, journal["status"])

    def _result(self, context, grant, values, mutations, payload, status):
        p.require(len(p.canonical(payload)) <= 3 * 1024 * 1024)
        audit, digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="provider_capture_retirement_authority",
            actor_id=grant["authorizationId"], event={"schema": "serverware.oauthCaptureRetirementAudit/v1", "operation": self.operation,
                "exchangeId": grant["exchangeId"], "workSource": grant["workSource"], "providerId": grant["providerId"],
                "requestDigest": context.request_digest, "authorizationSha256": p.sha256(p.unb64(values["authorization_original"], p.MAX_GRANT_BYTES)),
                "observation": status, "scope": "complete-local-provider", "providerRevocationProven": False})
        p.require(not replay)
        return core.KernelTransition(mutations=mutations + audit, work_units=4096, result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": digest, "idempotentReplay": False, "payload": payload})


KERNELS = MappingProxyType({operation: CaptureRetirementKernel(operation) for operation in p.OPERATIONS})
