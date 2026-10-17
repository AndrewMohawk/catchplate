"""Actual protected pending-family claim, contact reservation and observation.

Only this kernel constructs the staged-original binder from authenticated rows.
There is no provider call here; a contact reservation is irreversible even when
the helper/transport subsequently disappears. Recovery cannot create a contact.
"""
from dataclasses import dataclass
from catchplate import authority_oauth_retirement_succession_current as succession
from types import MappingProxyType

from catchplate import authority_oauth_measured_pending_retirement as profile
from catchplate import authority_oauth_measured_pending_originals as binder
from catchplate import authority_oauth_activation as activation
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_oauth_measured_exchange as measured_exchange
from catchplate import authority_oauth_inventory as inventory
from catchplate import authority_oauth_family_retirement as family
from catchplate import authority_oauth_family_query_group as family_group
from catchplate import authority_credential_currentness as roots
from catchplate import authority_transition_credential_currentness as currentness
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate.authority_transition_oauth_exchange import _iso


def _values(operation, arguments):
    return profile.arguments(operation, arguments, typed=True)


def _grant(values):
    return profile.grant_document(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))["payload"]


def _stored(value, maximum):
    profile.require(type(value) is str and value.isascii())
    return profile.document(value.encode("ascii"), maximum)


def check_acquired_credentials(operation, arguments, query, rows):
    """Early refusal on actual SQL rows, not a substitute for primary proofs."""
    if operation not in profile.OPERATIONS or query.table != "credentials":
        return
    expected = core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", "credentials"),
        table="credentials", predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=65,
        proof_primitive="bounded-limit-plus-one", work_units=65, page_size=64)
    profile.require(query == expected)
    grant = _grant(_values(operation, arguments))
    affected = []
    profile.require(len(rows) <= inventory.MAX_ROWS)
    for selected in rows:
        row = selected["row_value"]
        if row["kind"] != "oauth2":
            continue
        metadata = shared._canonical_stored_mapping(row["metadata"], "acquired OAuth metadata")
        if metadata.get("provider_id") == grant["providerId"] and metadata.get("provider_subject") == grant["familyScope"]["providerSubject"]:
            affected.append(row["id"])
    profile.require(len(affected) <= profile.MAX_AFFECTED_LINEAGES
        and sorted(affected) == [item["credentialId"] for item in grant["affectedLineages"]],
        "actual bounded acquisition does not match the complete affected lineage grant")


def _originals(context, values, grant):
    history = shared._row(context.exact(exchange.TABLE, {"id": grant["exchangeId"]}), "actual staged exchange")
    custody = shared._row(context.exact(measured_exchange.TABLE, {"id": grant["exchangeId"]}), "actual staged issuance custody")
    originals = binder.read_staged_pending(history, custody, values["enrollment_original"])
    profile.require(history["id"] == grant["pendingId"]
        and profile.sha256(originals.exchange_original) == grant["exchangeRowSha256"]
        and profile.sha256(originals.custody_original) == grant["custodyRowSha256"]
        and profile.sha256(originals.initial_pending_original) == grant["initialPendingRowSha256"]
        and profile.sha256(originals.stage_arguments_original) == grant["stageArgumentsSha256"]
        and profile.sha256(originals.normalized_envelope_original) == grant["tokenEnvelopeSha256"]
        and originals.normalized_token_sha256 == grant["tokenSecretSha256"]
        and originals.provider_id == grant["providerId"]
        and originals.provider_subject == grant["familyScope"]["providerSubject"]
        and originals.provider_account == grant["familyScope"]["providerAccount"])
    pending_selected = context.exact("pending_oauth_credentials", {"id": grant["pendingId"]})
    pending = shared._row(pending_selected, "actual staged pending target")
    activation.pending_original(pending)
    return originals, pending_selected, pending


def _family_rows(context, grant):
    """Both complete populations have already reconstructed their own roots."""
    found = []
    for selected in context.present_rows("credentials"):
        row = shared._row(selected, "complete affected credential inventory")
        profile.refresh.credential_original(row)
        if row["kind"] != "oauth2":
            continue
        metadata = shared._canonical_stored_mapping(row["metadata"], "affected credential metadata")
        if metadata.get("provider_id") != grant["providerId"]:
            continue
        profile.require(metadata.get("provider_identity_verified") is True
            and type(metadata.get("provider_subject")) is str and metadata["provider_subject"],
            "unclassified local provider credential cannot prove family coverage")
        if metadata["provider_subject"] == grant["familyScope"]["providerSubject"]:
            profile.require(metadata.get("provider_account") == grant["familyScope"]["providerAccount"])
            found.append(row)
    found.sort(key=lambda row: row["id"])
    profile.require(len(found) <= profile.MAX_AFFECTED_LINEAGES
        and [row["id"] for row in found] == [item["credentialId"] for item in grant["affectedLineages"]],
        "grant must cover the entire bounded local family, never a selected subset")
    for selected in context.present_rows("pending_oauth_credentials"):
        pending = shared._row(selected, "complete local pending inventory")
        activation.pending_original(pending)
        if pending["kind"] == "oauth2":
            metadata = shared._canonical_stored_mapping(pending["metadata"], "local pending metadata")
            if metadata.get("provider_id") == grant["providerId"]:
                profile.require(metadata.get("provider_identity_verified") is True
                    and type(metadata.get("provider_subject")) is str and metadata["provider_subject"],
                    "unclassified local pending issuance prevents family retirement")
    return found


def _affected(context, grant, *, journal=None):
    current_rows = _family_rows(context, grant)
    retained = None if journal is None else profile.array_document(journal["original_affected_json"].encode("ascii"), 2 * 1024 * 1024)
    if retained is not None:
        profile.require(len(retained) == len(current_rows))
    originals = []
    for index, (row, pin) in enumerate(zip(current_rows, grant["affectedLineages"])):
        root_id = roots.root_id(pin["credentialId"], pin["credentialVersion"])
        profile.require(sum(shared._row(item, "affected currentness barrier")["root_id"] == root_id
            for item in context.present_rows(roots.BARRIER_TABLE)) <= 1,
            "Affected lineage has more than one currentness barrier")
        head = shared._row(context.exact("credential_generations", {"credential_id": row["id"]}), "actual affected generation")
        generation_raw = profile.refresh.generation_original(head)
        profile.require(row["credential_version"] == head["last_version"] == pin["credentialVersion"]
            and profile.sha256(generation_raw) == pin["generationRowSha256"])
        if journal is None:
            original_row = row
            profile.require(row["lifecycle_status"] == "active" and row["revocation_requested_at"] is None
                and row["revocation_error"] is None)
            _, root = currentness.require_root(context, row["id"], pin["credentialVersion"])
            profile.require(root["status"] in {"open", "admitted"})
        else:
            item = retained[index]
            profile.require(type(item) is dict and set(item) == profile.AFFECTED_ORIGINAL_FIELDS)
            original_row = _stored(item["credentialOriginal"], 512 * 1024)
            profile.require(item["generationOriginal"] == generation_raw.decode("ascii")
                and row == {**original_row, "lifecycle_status": "revocation_pending",
                    "revocation_requested_at": journal["created_at"], "updated_at": journal["created_at"]})
        raw = profile.refresh.credential_original(original_row)
        profile.require(profile.sha256(raw) == pin["credentialRowSha256"] and original_row["id"] == pin["credentialId"])
        originals.append({"credentialOriginal": raw.decode("ascii"), "generationOriginal": generation_raw.decode("ascii")})
    return originals


def _claimed_pending(before, journal, attempts):
    return {**before, "status": "family_retired", "revocation_status": "pending_retirement_" + journal["status"].replace("-", "_"),
        "revocation_attempts": len(attempts), "revocation_next_attempt_at": None,
        "revocation_error": None, "revocation_lease_owner": None, "revocation_lease_until": None,
        "updated_at": journal["updated_at"]}


def _claim_association(context, values, grant, originals, pending, attempts):
    journal = shared._row(context.exact(profile.JOURNAL_TABLE, {"id": grant["pendingId"]}), "retained pending retirement claim")
    custody = shared._row(context.exact(profile.TABLE, {"id": grant["pendingId"]}), "retained pending retirement originals")
    profile.journal_original(journal); profile.row_original(custody)
    authorization_sha = profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))
    profile.require(journal["id"] == custody["id"] == grant["pendingId"]
        and journal["authorization_original"] == values["authorization_original"]
        and journal["authorization_sha256"] == custody["authorization_sha256"] == authorization_sha
        and journal["expires_at"] == _iso(grant["expiresAtEpochNs"]))
    before = _stored(journal["original_pending_json"], activation.MAX_PENDING_BYTES)
    before_raw = binder.current_pending_before_claim(originals, before,
        database_now=exchange.timestamp(journal["created_at"]), reason=grant["reason"])
    profile.require(profile.sha256(before_raw) == grant["currentPendingRowSha256"]
        and pending == _claimed_pending(before, journal, attempts))
    affected = _affected(context, grant, journal=journal)
    barriers = profile.barriers(profile.array_document(journal["currentness_barriers_json"].encode("ascii"), 16384), grant["affectedLineages"])
    for item in barriers:
        currentness.require_consumed_pending_retirement_barrier(context, item["credentialId"], item["credentialVersion"],
            item["barrierSha256"], claim_request_digest=journal["claim_request_digest"])
    fence = shared._row(context.exact(profile.FAMILY_TABLE,
        {"id": family.family_id(grant["providerId"], grant["familyScope"]["providerSubject"])}), "actual pending family fence")
    profile.require(set(fence) == profile.FAMILY_FIELDS and fence == {
        "id": family.family_id(grant["providerId"], grant["familyScope"]["providerSubject"]),
        "provider_id": grant["providerId"], "provider_subject": grant["familyScope"]["providerSubject"],
        "authorization_sha256": authorization_sha, "pending_id": grant["pendingId"],
        "claim_request_digest": journal["claim_request_digest"], "created_at": journal["created_at"]})
    claim = profile.arguments(profile.OP_CLAIM, _stored(custody["claim_original_json"], profile.MAX_ARGUMENT_BYTES))
    profile.require(claim["authorization_original"] == values["authorization_original"]
        and claim["request"]["ownerNonceSha256"] == journal["owner_nonce_sha256"]
        and claim["request"]["currentnessBarriers"] == barriers)
    contacts = _stored(custody["contact_originals_json"], 2 * profile.MAX_ARGUMENT_BYTES)
    finishes = _stored(custody["finish_originals_json"], 2 * profile.MAX_ARGUMENT_BYTES)
    purposes = [row["token_purpose"] for row in attempts]
    profile.require(purposes == grant["tokenPurposes"][:len(purposes)] and set(contacts) == set(purposes)
        and set(finishes) <= set(contacts))
    states = []
    for attempt in attempts:
        profile.attempt_original(attempt)
        purpose = attempt["token_purpose"]
        contact = profile.arguments(profile.OP_CONTACT, contacts[purpose])
        profile.require(attempt["id"] == profile.attempt_id(grant["pendingId"], purpose)
            and attempt["pending_id"] == grant["pendingId"] and contact["authorization_original"] == values["authorization_original"]
            and contact["request"]["tokenPurpose"] == purpose
            and contact["request"]["contactRequestSha256"] == attempt["contact_request_sha256"])
        if purpose in finishes:
            finish = profile.arguments(profile.OP_FINISH, finishes[purpose])
            raw = profile.unb64(finish["request"]["transportOriginal"], profile.MAX_TRANSPORT_BYTES)
            profile.require(finish["authorization_original"] == values["authorization_original"]
                and finish["request"]["tokenPurpose"] == purpose and attempt["transport_original"] == raw.decode("ascii")
                and attempt["transport_sha256"] == profile.sha256(raw)
                and attempt["status"] == profile.transport(raw, attempt["contact_request_sha256"]))
        else:
            profile.require(attempt["status"] == "contact-claimed" and attempt["transport_original"] is None
                and attempt["transport_sha256"] is None)
        states.append(attempt["status"])
    profile.require(journal["status"] == _status(states, grant["tokenPurposes"]))
    return journal, custody, before, affected


def _status(states, purposes):
    if "unknown" in states:
        return "unknown"
    if len(states) == len(purposes) and all(state in {"accepted", "rejected"} for state in states):
        return "observed-rejected" if "rejected" in states else "observed-accepted"
    return "claimed"


@dataclass(frozen=True, slots=True)
class PendingRetirementKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "catchplate_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = _values(self.operation, arguments); grant = _grant(values)
        # Effective maximum: family34 + credentials65 + pending65 + lineage72
        # + exact history/journal/custody/pending/fences7 + attempts2 + audit1
        # =246, plus the separately source-owned audit-capacity read if selected.
        queries = list(family.population_queries(self.operation))
        if self.operation in succession.GUARDED_OPERATIONS:
            queries.append(succession.query(self.operation, grant["providerId"]))
        for table in ("credentials", "pending_oauth_credentials"):
            queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table),
                table=table, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=65,
                proof_primitive="bounded-limit-plus-one", work_units=65, page_size=64))
        for name, table, key, absent in (
                ("exchange", exchange.TABLE, {"id": grant["exchangeId"]}, False),
                ("measured_exchange", measured_exchange.TABLE, {"id": grant["exchangeId"]}, False),
                ("pending", "pending_oauth_credentials", {"id": grant["pendingId"]}, False),
                ("journal", profile.JOURNAL_TABLE, {"id": grant["pendingId"]}, self.operation == profile.OP_CLAIM),
                ("custody", profile.TABLE, {"id": grant["pendingId"]}, self.operation == profile.OP_CLAIM)):
            queries.append(shared._query(operation=self.operation, name=name, table=table, key=key, require_absence=absent))
        queries.extend((family.query(self.operation, grant["providerId"], grant["familyScope"]["providerSubject"]),
            family.pending_query(self.operation, grant["providerId"], grant["familyScope"]["providerSubject"])))
        for item in grant["affectedLineages"]:
            suffix = item["credentialId"].replace("-", "")
            key = {"id": roots.root_id(item["credentialId"], item["credentialVersion"])}
            queries.extend((shared._query(operation=self.operation, name="generation_" + suffix,
                table="credential_generations", key={"credential_id": item["credentialId"]}),
                shared._query(operation=self.operation, name="root_" + suffix, table=roots.ROOT_TABLE, key=key),
                core.BoundedQuery(query_id=core.query_program_id(self.operation, "barrier_" + suffix, roots.BARRIER_TABLE),
                    table=roots.BARRIER_TABLE, predicates=(core.QueryPredicate("root_id", "eq", key["id"]),),
                    order_by=(core.QueryOrder("id"),), maximum_rows=2, proof_primitive="bounded-limit-plus-one", work_units=2, page_size=1)))
        for purpose in grant["tokenPurposes"]:
            queries.append(shared._query(operation=self.operation, name="attempt_" + purpose, table=profile.ATTEMPT_TABLE,
                key={"id": profile.attempt_id(grant["pendingId"], purpose)}, require_absence=self.operation == profile.OP_CLAIM))
        queries.append(shared._audit_query(self.operation, request_digest))
        return family.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        values = _values(self.operation, context.arguments); grant = _grant(values); request = values["request"]
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, grant["providerId"])
        now = shared._database_epoch_ns(context.database_now); stamp = context.database_now.isoformat()
        statement = values["evidence"]["statement"]
        profile.require(statement["issuedAtEpochNs"] <= now < statement["expiresAtEpochNs"])
        if self.operation != profile.OP_RECOVER:
            profile.require(grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        originals, pending_selected, pending = _originals(context, values, grant)
        journal_selected = context.exact(profile.JOURNAL_TABLE, {"id": grant["pendingId"]})
        custody_selected = context.exact(profile.TABLE, {"id": grant["pendingId"]})
        selections = {purpose: context.exact(profile.ATTEMPT_TABLE, {"id": profile.attempt_id(grant["pendingId"], purpose)})
            for purpose in grant["tokenPurposes"]}
        attempts = [shared._row(selected, "actual pending contact") for selected in selections.values() if selected["present"]]
        mutations, attempt = [], None
        if not journal_selected["present"]:
            profile.require(not custody_selected["present"] and not attempts)
            before = pending
            raw = binder.current_pending_before_claim(originals, before, database_now=context.database_now, reason=grant["reason"])
            profile.require(profile.sha256(raw) == grant["currentPendingRowSha256"])
            affected = _affected(context, grant)
            family.require_open_from_population(context, grant["providerId"], grant["familyScope"]["providerSubject"])
            journal, custody = None, None
        else:
            profile.require(self.operation != profile.OP_INSPECT and self.operation != profile.OP_CLAIM)
            journal, custody, before, affected = _claim_association(context, values, grant, originals, pending, attempts)
        if self.operation in {profile.OP_INSPECT, profile.OP_RECOVER}:
            profile.require(request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
            status = ("ready" if self.operation == profile.OP_INSPECT else "no-local-claim") if journal is None else (
                "outcome-unknown" if journal["status"] == "claimed" else journal["status"])
            payload = {"status": status, "exchangeOriginal": originals.exchange_original.decode("ascii"),
                "measuredExchangeOriginal": originals.custody_original.decode("ascii"),
                "initialPendingOriginal": originals.initial_pending_original.decode("ascii"),
                "currentPendingOriginal": activation.pending_original(pending).decode("ascii"),
                "enrollmentOriginal": originals.enrollment_original.decode("ascii"),
                "stageArgumentsOriginal": originals.stage_arguments_original.decode("ascii"),
                "normalizedEnvelopeOriginal": originals.normalized_envelope_original.decode("ascii"),
                "normalizedTokenSha256": originals.normalized_token_sha256, "affectedLineages": affected,
                "journalOriginal": None if journal is None else profile.journal_original(journal).decode("ascii"),
                "custodyOriginal": None if custody is None else profile.row_original(custody).decode("ascii"),
                "attemptOriginals": [profile.attempt_original(row).decode("ascii") for row in attempts]}
            profile.require(set(payload) == profile.OBSERVATION_FIELDS)
            return self._result(context, values, grant, (), payload, status)
        if self.operation == profile.OP_CLAIM:
            profile.require(journal is None and sum(len(context.present_rows(table)) for table in family_group.TABLES) < family_group.MAX_ROWS)
            for item in request["currentnessBarriers"]:
                mutations.extend(currentness.consume_barrier(context, item["credentialId"], item["credentialVersion"], item["barrierSha256"]))
                selected = context.exact("credentials", {"id": item["credentialId"]})
                row = shared._row(selected, "actual claimed credential")
                mutations.append(core.mutation(operation=self.operation, selected=selected, row={**row,
                    "lifecycle_status": "revocation_pending", "revocation_requested_at": stamp, "updated_at": stamp}))
            authorization_sha = profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))
            journal = {"id": grant["pendingId"], "authorization_original": values["authorization_original"],
                "authorization_sha256": authorization_sha, "original_pending_json": activation.pending_original(before).decode("ascii"),
                "original_affected_json": profile.canonical(affected).decode("ascii"),
                "currentness_barriers_json": profile.canonical(request["currentnessBarriers"]).decode("ascii"),
                "claim_request_digest": context.request_digest, "owner_nonce_sha256": request["ownerNonceSha256"],
                "status": "claimed", "created_at": stamp, "expires_at": _iso(grant["expiresAtEpochNs"]), "updated_at": stamp}
            fence_selected = context.exact(profile.FAMILY_TABLE, {"id": family.family_id(grant["providerId"], grant["familyScope"]["providerSubject"])})
            profile.require(not fence_selected["present"])
            mutations.append(core.mutation(operation=self.operation, selected=fence_selected, row={
                "id": fence_selected["key"]["id"], "provider_id": grant["providerId"], "provider_subject": grant["familyScope"]["providerSubject"],
                "authorization_sha256": authorization_sha, "pending_id": grant["pendingId"], "claim_request_digest": context.request_digest,
                "created_at": stamp}))
            custody = {"id": grant["pendingId"], "authorization_sha256": authorization_sha,
                "claim_original_json": profile.canonical(values).decode("ascii"), "contact_originals_json": "{}",
                "finish_originals_json": "{}", "created_at": stamp, "updated_at": stamp}
        else:
            profile.require(journal is not None and journal["status"] == "claimed"
                and profile.sha256(profile.journal_original(journal)) == request["journalRowSha256"]
                and journal["owner_nonce_sha256"] == profile.sha256(profile.unb64(request["ownerNonce"], 32)))
            claim = profile.arguments(profile.OP_CLAIM, _stored(custody["claim_original_json"], profile.MAX_ARGUMENT_BYTES))
            profile.require(claim["assignment_original"] == values["assignment_original"]
                and all(claim["evidence"]["statement"][name] == statement[name] for name in ("holderId", "bootId", "keyId", "instanceId")))
            purpose = request["tokenPurpose"]; selected = selections[purpose]
            if self.operation == profile.OP_CONTACT:
                index = grant["tokenPurposes"].index(purpose)
                profile.require(not selected["present"] and len(attempts) == index
                    and all(row["status"] in {"accepted", "rejected"} for row in attempts))
                attempt = {"id": profile.attempt_id(grant["pendingId"], purpose), "pending_id": grant["pendingId"],
                    "token_purpose": purpose, "contact_request_sha256": request["contactRequestSha256"], "status": "contact-claimed",
                    "transport_original": None, "transport_sha256": None, "created_at": stamp, "updated_at": stamp}
                attempts.append(attempt)
            else:
                attempt = shared._row(selected, "claimed pending contact")
                profile.require(profile.sha256(profile.attempt_original(attempt)) == request["attemptRowSha256"]
                    and attempt["status"] == "contact-claimed" and attempt["transport_original"] is None)
                raw = profile.unb64(request["transportOriginal"], profile.MAX_TRANSPORT_BYTES)
                status = profile.transport(raw, attempt["contact_request_sha256"])
                transport = profile.document(raw, profile.MAX_TRANSPORT_BYTES)
                profile.require(shared._database_epoch_ns(exchange.timestamp(attempt["created_at"])) <= transport["receivedAtEpochNs"] <= now
                    and transport["receivedAtEpochNs"] < grant["expiresAtEpochNs"]
                    and transport["rawResponseEnvelope"]["secret_kek_id"] == values["assignment_original"]["secretKekId"])
                attempt = {**attempt, "status": status, "transport_original": raw.decode("ascii"),
                    "transport_sha256": profile.sha256(raw), "updated_at": stamp}
                attempts = [attempt if row["token_purpose"] == purpose else row for row in attempts]
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=attempt))
            journal = {**journal, "status": _status([row["status"] for row in attempts], grant["tokenPurposes"]), "updated_at": stamp}
            field = "contact_originals_json" if self.operation == profile.OP_CONTACT else "finish_originals_json"
            held = _stored(custody[field], 2 * profile.MAX_ARGUMENT_BYTES)
            profile.require(purpose not in held and len(held) < 2)
            held[purpose] = values
            custody = {**custody, field: profile.canonical(held).decode("ascii"), "updated_at": stamp}
        pending = _claimed_pending(before, journal, attempts)
        activation.pending_original(pending); profile.journal_original(journal); profile.row_original(custody)
        if attempt is not None:
            profile.attempt_original(attempt)
        mutations.extend((core.mutation(operation=self.operation, selected=pending_selected, row=pending),
            core.mutation(operation=self.operation, selected=journal_selected, row=journal),
            core.mutation(operation=self.operation, selected=custody_selected, row=custody)))
        payload = {"journalOriginal": profile.journal_original(journal).decode("ascii"),
            "attemptOriginal": None if attempt is None else profile.attempt_original(attempt).decode("ascii"),
            "custodyOriginal": profile.row_original(custody).decode("ascii")}
        return self._result(context, values, grant, tuple(mutations), payload, journal["status"])

    def _result(self, context, values, grant, mutations, payload, status):
        # Leave room for the independently signed configuration and receipts in
        # the existing 6MiB authenticated response; never truncate originals.
        profile.require(len(profile.canonical(payload)) <= 3 * 1024 * 1024)
        audit, digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="pending_family_retirement_authority",
            actor_id=grant["authorizationId"], event={"schema": "catchplate.oauthMeasuredPendingRetirementAudit/v1",
                "operation": self.operation, "pendingId": grant["pendingId"], "requestDigest": context.request_digest,
                "authorizationSha256": profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES)), "observation": status})
        profile.require(not replay)
        return core.KernelTransition(mutations=mutations + audit, work_units=4096,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": digest, "idempotentReplay": False, "payload": payload})


KERNELS = MappingProxyType({operation: PendingRetirementKernel(operation) for operation in profile.OPERATIONS})
