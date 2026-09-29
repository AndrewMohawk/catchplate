"""Measured family retirement with exact encrypted transport custody."""
from dataclasses import dataclass
from types import MappingProxyType

from serverware import authority_oauth_measured_cleanup as profile
from serverware import authority_oauth_inventory as inventory
from serverware import authority_oauth_measured_refresh as measured
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_credential_currentness as roots
from serverware import authority_oauth_family_retirement as family
from serverware.authority_transition_oauth_exchange import _iso


def _values(operation, arguments):
    try:
        return profile.arguments(operation, arguments, typed=True)
    except (ValueError, TypeError, KeyError) as exc:
        raise core.TransitionKernelError("refresh cleanup originals are not exact") from exc


def _grant(values):
    return profile.grant_document(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))["payload"]


def _journal_public(row):
    return {"workId": row["id"], "status": row["status"], "rowSha256": profile.sha256(profile.journal_original(row)),
        "authorizationSha256": row["authorization_sha256"], "expiresAt": row["expires_at"]}


def _attempt_public(row):
    return None if row is None else {"id": row["id"], "tokenPurpose": row["token_purpose"], "status": row["status"],
        "rowSha256": profile.sha256(profile.attempt_original(row)), "transportSha256": row["transport_sha256"]}


def _originals(context, values, grant):
    refresh = profile.refresh
    row = shared._row(context.exact(refresh.TABLE, {"id": grant["refreshId"]}), "refresh history")
    profile.require(refresh.row_digest(row) == grant["refreshRowSha256"] and row["credential_id"] == grant["credentialId"]
        and row["credential_version"] == grant["refreshVersion"] and row["provider_id"] == grant["providerId"]
        and row["id"] == refresh.refresh_id(grant["credentialId"], grant["refreshVersion"])
        and row["enrollment_original"] == values["enrollment_original"] and row["raw_response_envelope_json"] is not None)
    original = refresh.enrollment_bytes(row["enrollment_original"])
    historical = enrollment.enrollment_document(original)["payload"]
    created = shared._database_epoch_ns(refresh.timestamp(row["created_at"]))
    profile.require(historical["issuedAtEpochNs"] <= created < historical["expiresAtEpochNs"])
    issued = grant["workSource"] == profile.ISSUED_SOURCE
    purpose = "issued" if issued else "superseded"
    profile.require(row["status"] == ("retained" if issued else "committed")
        and row[purpose + "_work_id"] == grant["workId"] == refresh.artifact_id(row["id"], purpose)
        and row[purpose + "_material_sha256"] == grant["tokenSecretSha256"])
    work_selected = context.exact("oauth_revocation_work", {"id": grant["workId"]})
    work = shared._row(work_selected, "retained refresh work")
    profile.work_original(work)
    token = {name: work[name] for name in refresh.ENVELOPE_FIELDS}
    refresh.envelope(token, 1)
    profile.require(work["source"] == grant["workSource"] and work["provider_id"] == grant["providerId"]
        and work["actor_id"] == "oauth-refresh" and work["created_at"] == row["created_at"]
        and all(work[name] is None for name in ("last_error", "lease_owner", "lease_until"))
        and profile.sha256(profile.canonical(token)) == grant["tokenEnvelopeSha256"])
    if issued:
        profile.require(row["issued_material_envelope_json"] == profile.canonical(token).decode("ascii"))
    credential_selected = context.exact("credentials", {"id": grant["credentialId"]})
    credential = shared._row(credential_selected, "affected current credential")
    generation = shared._row(context.exact("credential_generations", {"credential_id": grant["credentialId"]}), "affected generation")
    refresh.credential_original(credential); refresh.generation_original(generation)
    profile.require(credential["kind"] == "oauth2" and credential["credential_version"] == grant["credentialVersion"]
        and generation["last_version"] == grant["credentialVersion"]
        and profile.sha256(refresh.generation_original(generation)) == grant["generationRowSha256"])
    metadata = shared._canonical_stored_mapping(credential["metadata"], "affected OAuth metadata")
    profile.require(metadata.get("provider_identity_verified") is True and metadata.get("provider_id") == grant["providerId"]
        and metadata.get("provider_subject") == grant["familyScope"]["providerSubject"]
        and metadata.get("provider_account") == grant["familyScope"]["providerAccount"]
        and profile.canonical(metadata.get("oauth_application_owner")) == profile.canonical(enrollment.association(original)))
    # Complete primary-root reconstruction runs before this kernel. A count or
    # unproven missing row cannot establish this bounded local exclusivity.
    family.require_single_lineage(context, grant, credential)
    currentness.require_consumed_refresh_barrier(context, grant["credentialId"], grant["refreshVersion"],
        grant["historicalBarrierSha256"], claim_request_digest=row["claim_request_digest"])
    custody = shared._row(context.exact(measured.TABLE, {"id": grant["refreshId"]}), "measured issuance custody")
    measured.row_original(custody)
    profile.require(profile.sha256(measured.row_original(custody)) == grant["custodyRowSha256"]
        and custody["id"] == row["id"] and custody["credential_id"] == row["credential_id"]
        and custody["credential_version"] == row["credential_version"]
        and custody["enrollment_original"] == row["enrollment_original"]
        and custody["status"] == ("captured" if issued else "committed")
        and custody["capture_request_json"] is not None and (issued or custody["commit_request_json"] is not None))
    return row, work_selected, work, credential_selected, credential, generation


@dataclass(frozen=True, slots=True)
class MeasuredCleanupKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = _values(self.operation, arguments); grant = _grant(values)
        queries = [shared._query(operation=self.operation, name=name, table=table, key=key, require_absence=absent)
            for name, table, key, absent in (
                ("refresh", profile.refresh.TABLE, {"id": grant["refreshId"]}, False),
                ("measured_history", measured.TABLE, {"id": grant["refreshId"]}, False),
                ("measured_cleanup", profile.TABLE, {"id": grant["workId"]}, self.operation == profile.OP_CLAIM),
                ("work", "oauth_revocation_work", {"id": grant["workId"]}, False),
                ("generation", "credential_generations", {"credential_id": grant["credentialId"]}, False),
                ("journal", profile.JOURNAL_TABLE, {"id": grant["workId"]}, self.operation == profile.OP_CLAIM))]
        queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", "credentials"),
            table="credentials", predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.MAX_ROWS + 1,
            proof_primitive="bounded-limit-plus-one", work_units=inventory.MAX_ROWS + 1))
        queries.extend(currentness.effect_queries(self.operation, grant["credentialId"], grant["credentialVersion"]))
        if grant["credentialVersion"] != grant["refreshVersion"]:
            key = {"id": roots.root_id(grant["credentialId"], grant["refreshVersion"])}
            queries.extend((shared._query(operation=self.operation, name="historical_root", table=roots.ROOT_TABLE, key=key),
                shared._query(operation=self.operation, name="historical_barrier", table=roots.BARRIER_TABLE,
                    key={"id": core.SelectedRowFieldReference(roots.ROOT_TABLE, key, "barrier_id")})))
        queries.append(family.query(self.operation, grant["providerId"], grant["familyScope"]["providerSubject"]))
        queries.extend(family.population_queries(self.operation))
        queries.append(family.pending_query(self.operation, grant["providerId"], grant["familyScope"]["providerSubject"]))
        for purpose in grant["tokenPurposes"]:
            queries.append(shared._query(operation=self.operation, name="attempt_" + purpose, table=profile.ATTEMPT_TABLE,
                key={"id": profile.attempt_id(grant["workId"], purpose)}, require_absence=self.operation == profile.OP_CLAIM))
        queries.append(shared._audit_query(self.operation, request_digest))
        return family.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        values = _values(self.operation, context.arguments); grant = _grant(values); request = values["request"]
        now = shared._database_epoch_ns(context.database_now); stamp = context.database_now.isoformat()
        statement = values["evidence"]["statement"]
        profile.require(statement["issuedAtEpochNs"] <= now < statement["expiresAtEpochNs"])
        if self.operation != profile.OP_RECOVER:
            profile.require(grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        history, work_selected, work, credential_selected, credential, generation = _originals(context, values, grant)
        if self.operation in {profile.OP_INSPECT, profile.OP_RECOVER}:
            return self._observe(context, values, grant, history, work, credential, generation)
        journal_selected = context.exact(profile.JOURNAL_TABLE, {"id": grant["workId"]})
        attempts = {purpose: context.exact(profile.ATTEMPT_TABLE, {"id": profile.attempt_id(grant["workId"], purpose)}) for purpose in grant["tokenPurposes"]}
        mutations, attempt = [], None
        if self.operation == profile.OP_CLAIM:
            profile.require(not journal_selected["present"] and not any(item["present"] for item in attempts.values())
                and work["status"] == "held" and work["attempts"] == 0
                and profile.sha256(profile.work_original(work)) == grant["workRowSha256"]
                and profile.sha256(profile.refresh.credential_original(credential)) == grant["credentialRowSha256"]
                and credential["lifecycle_status"] == "active" and credential["revocation_requested_at"] is None and credential["revocation_error"] is None)
            if grant["credentialVersion"] == grant["refreshVersion"]:
                profile.require(request["currentnessBarrierSha256"] == grant["historicalBarrierSha256"])
            else:
                mutations.extend(currentness.consume_barrier(context, grant["credentialId"], grant["credentialVersion"], request["currentnessBarrierSha256"]))
            journal = {"id": work["id"], "authorization_original": values["authorization_original"],
                "authorization_sha256": profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES)),
                "refresh_row_sha256": grant["refreshRowSha256"], "original_work_json": profile.work_original(work).decode("ascii"),
                "original_credential_json": profile.refresh.credential_original(credential).decode("ascii"),
                "original_generation_json": profile.refresh.generation_original(generation).decode("ascii"),
                "currentness_barrier_sha256": request["currentnessBarrierSha256"], "claim_request_digest": context.request_digest,
                "owner_nonce_sha256": request["ownerNonceSha256"], "status": "claimed", "created_at": stamp,
                "expires_at": _iso(grant["expiresAtEpochNs"]), "updated_at": stamp}
            mutations.append(family.claim(context, grant, journal["authorization_sha256"]))
            credential = {**credential, "lifecycle_status": "revocation_pending", "revocation_requested_at": stamp, "updated_at": stamp}
            mutations.append(core.mutation(operation=self.operation, selected=credential_selected, row=credential))
            work = {**work, "status": "refresh_cleanup_reserved", "updated_at": stamp}
        else:
            journal = shared._row(journal_selected, "family retirement journal")
            profile.require(profile.sha256(profile.journal_original(journal)) == request["journalRowSha256"]
                and journal["authorization_original"] == values["authorization_original"]
                and journal["authorization_sha256"] == profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))
                and journal["refresh_row_sha256"] == grant["refreshRowSha256"] and journal["status"] == "claimed"
                and journal["owner_nonce_sha256"] == profile.sha256(profile.unb64(request["ownerNonce"], 32))
                and journal["expires_at"] == _iso(grant["expiresAtEpochNs"]))
            original_work = profile.document(journal["original_work_json"].encode("ascii"), 512 * 1024)
            original_credential = profile.document(journal["original_credential_json"].encode("ascii"), 512 * 1024)
            profile.require(profile.sha256(profile.work_original(original_work)) == grant["workRowSha256"]
                and profile.sha256(profile.refresh.credential_original(original_credential)) == grant["credentialRowSha256"]
                and journal["original_generation_json"] == profile.refresh.generation_original(generation).decode("ascii")
                and credential == {**original_credential, "lifecycle_status": "revocation_pending", "revocation_requested_at": journal["created_at"], "updated_at": journal["created_at"]}
                and work["status"] == "refresh_cleanup_reserved"
                and all(work[name] == original_work[name] for name in profile.WORK_FIELDS - {"status", "attempts", "updated_at"}))
            family.require_claim(context, grant, journal["authorization_sha256"])
            if grant["credentialVersion"] != grant["refreshVersion"]:
                currentness.require_consumed_refresh_barrier(context, grant["credentialId"], grant["credentialVersion"],
                    journal["currentness_barrier_sha256"], claim_request_digest=journal["claim_request_digest"])
            purpose = request["tokenPurpose"]; selected = attempts[purpose]
            used = [shared._row(item, "retirement attempt") for item in attempts.values() if item["present"]]
            profile.require(work["attempts"] == len(used))
            if self.operation == profile.OP_CONTACT:
                index = grant["tokenPurposes"].index(purpose)
                profile.require(not selected["present"] and not any(attempts[name]["present"] for name in grant["tokenPurposes"][index + 1:])
                    and all(attempts[name]["present"] and shared._row(attempts[name], "prior contact")["status"] in {"accepted", "rejected"} for name in grant["tokenPurposes"][:index])
                    and all(item["status"] in {"accepted", "rejected"} for item in used))
                attempt = {"id": profile.attempt_id(work["id"], purpose), "work_id": work["id"], "token_purpose": purpose,
                    "contact_request_sha256": request["contactRequestSha256"], "status": "contact-claimed", "transport_original": None,
                    "transport_sha256": None, "created_at": stamp, "updated_at": stamp}
                work = {**work, "attempts": work["attempts"] + 1, "updated_at": stamp}
            else:
                attempt = shared._row(selected, "retirement contact")
                profile.require(profile.sha256(profile.attempt_original(attempt)) == request["attemptRowSha256"]
                    and attempt["work_id"] == work["id"] and attempt["token_purpose"] == purpose
                    and attempt["status"] == "contact-claimed" and attempt["transport_original"] is None and attempt["transport_sha256"] is None)
                raw = profile.unb64(request["transportOriginal"], profile.MAX_TRANSPORT_BYTES)
                outcome = profile.transport(raw, attempt["contact_request_sha256"])
                transport = profile.document(raw, profile.MAX_TRANSPORT_BYTES)
                profile.require(statement["issuedAtEpochNs"] <= transport["receivedAtEpochNs"] <= now
                    and transport["rawResponseEnvelope"]["secret_kek_id"] == values["assignment_original"]["secretKekId"])
                attempt = {**attempt, "status": outcome, "transport_original": raw.decode("ascii"), "transport_sha256": profile.sha256(raw), "updated_at": stamp}
                states = [outcome if name == purpose else shared._row(item, "prior contact")["status"] if item["present"] else None for name, item in attempts.items()]
                if "unknown" in states:
                    journal = {**journal, "status": "unknown"}
                elif all(state in {"accepted", "rejected"} for state in states):
                    journal = {**journal, "status": "observed-rejected" if "rejected" in states else "observed-accepted"}
                if journal["status"] != "claimed":
                    work = {**work, "status": "refresh_cleanup_" + journal["status"].replace("-", "_"), "updated_at": stamp}
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=attempt))
            journal = {**journal, "updated_at": stamp}
        retained_selected = context.exact(profile.TABLE, {"id": grant["workId"]})
        raw_arguments = profile.canonical(values).decode("ascii")
        if self.operation == profile.OP_CLAIM:
            profile.require(not retained_selected["present"])
            retained = {"id": grant["workId"], "authorization_sha256": journal["authorization_sha256"],
                "claim_original_json": raw_arguments, "contact_originals_json": "{}", "finish_originals_json": "{}",
                "created_at": stamp, "updated_at": stamp}
        else:
            retained = shared._row(retained_selected, "measured cleanup provenance")
            profile.row_original(retained)
            claim = profile.document(retained["claim_original_json"].encode("ascii"), profile.MAX_ARGUMENT_BYTES)
            profile.require(retained["id"] == grant["workId"] and retained["authorization_sha256"] == journal["authorization_sha256"]
                and claim["authorization_original"] == values["authorization_original"]
                and claim["assignment_original"] == values["assignment_original"]
                and all(claim["evidence"]["statement"][name] == values["evidence"]["statement"][name]
                    for name in ("holderId", "bootId", "keyId", "instanceId")))
            field = "contact_originals_json" if self.operation == profile.OP_CONTACT else "finish_originals_json"
            originals = profile.document(retained[field].encode("ascii"), 2 * profile.MAX_ARGUMENT_BYTES)
            profile.require(request["tokenPurpose"] not in originals and len(originals) < 2)
            originals[request["tokenPurpose"]] = values
            retained = {**retained, field: profile.canonical(originals).decode("ascii"), "updated_at": stamp}
        profile.row_original(retained)
        mutations.append(core.mutation(operation=self.operation, selected=retained_selected, row=retained))
        profile.journal_original(journal)
        if attempt is not None: profile.attempt_original(attempt)
        mutations.extend((core.mutation(operation=self.operation, selected=journal_selected, row=journal), core.mutation(operation=self.operation, selected=work_selected, row=work)))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="family_retirement_authority",
            actor_id=grant["authorizationId"], event={"schema": "serverware.oauthMeasuredRefreshCleanupAudit/v1", "operation": self.operation,
                "workId": work["id"], "requestDigest": context.request_digest, "authorizationSha256": journal["authorization_sha256"],
                "journal": _journal_public(journal), "attempt": _attempt_public(attempt)})
        profile.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations) + audit, work_units=1024,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "payload": {
                    "journalOriginal": profile.journal_original(journal).decode("ascii"),
                    "attemptOriginal": None if attempt is None else profile.attempt_original(attempt).decode("ascii"),
                    "custodyOriginal": profile.row_original(retained).decode("ascii")}})


    def _observe(self, context, values, grant, history, work, credential, generation):
        request = values["request"]; now = shared._database_epoch_ns(context.database_now)
        profile.require(request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
        journal_selected = context.exact(profile.JOURNAL_TABLE, {"id": grant["workId"]})
        custody_selected = context.exact(profile.TABLE, {"id": grant["workId"]})
        attempts = []
        for purpose in grant["tokenPurposes"]:
            selected = context.exact(profile.ATTEMPT_TABLE, {"id": profile.attempt_id(grant["workId"], purpose)})
            if selected["present"]:
                attempt = shared._row(selected, "observed measured cleanup attempt")
                profile.attempt_original(attempt); attempts.append(attempt)
        journal, custody = None, None
        if not journal_selected["present"]:
            profile.require(not custody_selected["present"] and not attempts and work["status"] == "held" and work["attempts"] == 0
                and profile.sha256(profile.work_original(work)) == grant["workRowSha256"]
                and profile.sha256(profile.refresh.credential_original(credential)) == grant["credentialRowSha256"]
                and credential["lifecycle_status"] == "active")
            status = "ready" if self.operation == profile.OP_INSPECT else "no-local-claim"
        else:
            profile.require(self.operation == profile.OP_RECOVER and custody_selected["present"])
            journal = shared._row(journal_selected, "observed family retirement journal")
            custody = shared._row(custody_selected, "observed measured cleanup provenance")
            profile.journal_original(journal); profile.row_original(custody)
            profile.require(journal["authorization_original"] == values["authorization_original"]
                and custody["authorization_sha256"] == journal["authorization_sha256"]
                == profile.sha256(profile.unb64(values["authorization_original"], profile.MAX_GRANT_BYTES))
                and journal["original_generation_json"] == profile.refresh.generation_original(generation).decode("ascii")
                and work["attempts"] == len(attempts) and credential["lifecycle_status"] == "revocation_pending")
            original = profile.document(journal["original_credential_json"].encode("ascii"), 512 * 1024)
            profile.require(credential == {**original, "lifecycle_status": "revocation_pending",
                "revocation_requested_at": journal["created_at"], "updated_at": journal["created_at"]})
            family.require_claim(context, grant, journal["authorization_sha256"])
            claim = profile.document(custody["claim_original_json"].encode("ascii"), profile.MAX_ARGUMENT_BYTES)
            profile.arguments(profile.OP_CLAIM, claim)
            profile.require(claim["authorization_original"] == values["authorization_original"]
                and claim["request"]["ownerNonceSha256"] == journal["owner_nonce_sha256"]
                and claim["request"]["currentnessBarrierSha256"] == journal["currentness_barrier_sha256"])
            contacts = profile.document(custody["contact_originals_json"].encode("ascii"), 2 * profile.MAX_ARGUMENT_BYTES)
            finishes = profile.document(custody["finish_originals_json"].encode("ascii"), 2 * profile.MAX_ARGUMENT_BYTES)
            purposes = [item["token_purpose"] for item in attempts]
            profile.require(purposes == grant["tokenPurposes"][:len(purposes)] and set(contacts) == set(purposes)
                and set(finishes) <= set(contacts))
            states = []
            for attempt in attempts:
                purpose = attempt["token_purpose"]
                contact = profile.arguments(profile.OP_CONTACT, contacts[purpose])
                profile.require(attempt["id"] == profile.attempt_id(grant["workId"], purpose) and attempt["work_id"] == grant["workId"]
                    and contact["authorization_original"] == values["authorization_original"]
                    and contact["request"]["tokenPurpose"] == purpose
                    and contact["request"]["contactRequestSha256"] == attempt["contact_request_sha256"])
                if purpose in finishes:
                    finish = profile.arguments(profile.OP_FINISH, finishes[purpose])
                    raw = profile.unb64(finish["request"]["transportOriginal"], profile.MAX_TRANSPORT_BYTES)
                    profile.require(finish["authorization_original"] == values["authorization_original"]
                        and finish["request"]["tokenPurpose"] == purpose and attempt["transport_original"].encode("ascii") == raw
                        and attempt["transport_sha256"] == profile.sha256(raw)
                        and attempt["status"] == profile.transport(raw, attempt["contact_request_sha256"]))
                else:
                    profile.require(attempt["status"] == "contact-claimed" and attempt["transport_original"] is None
                        and attempt["transport_sha256"] is None)
                states.append(attempt["status"])
            expected = ("unknown" if "unknown" in states else
                "observed-rejected" if len(states) == len(grant["tokenPurposes"]) and all(item in {"accepted", "rejected"} for item in states) and "rejected" in states else
                "observed-accepted" if len(states) == len(grant["tokenPurposes"]) and all(item == "accepted" for item in states) else "claimed")
            profile.require(journal["status"] == expected
                and work["status"] == ("refresh_cleanup_reserved" if expected == "claimed" else "refresh_cleanup_" + expected.replace("-", "_")))
            status = "outcome-unknown" if journal["status"] == "claimed" else journal["status"]
        actual_history = shared._row(context.exact(measured.TABLE, {"id": grant["refreshId"]}), "actual measured history")
        payload = {"status": status, "refreshOriginal": profile.refresh.row_original(history).decode("ascii"),
            "measuredRefreshOriginal": measured.row_original(actual_history).decode("ascii"),
            "workOriginal": profile.work_original(work).decode("ascii"),
            "credentialOriginal": profile.refresh.credential_original(credential).decode("ascii"),
            "generationOriginal": profile.refresh.generation_original(generation).decode("ascii"),
            "journalOriginal": None if journal is None else profile.journal_original(journal).decode("ascii"),
            "custodyOriginal": None if custody is None else profile.row_original(custody).decode("ascii"),
            "attemptOriginals": [profile.attempt_original(item).decode("ascii") for item in attempts]}
        audit, digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="measured_policy",
            actor_id=values["evidence"]["statement"]["holderId"], event={"schema": "serverware.oauthMeasuredRefreshCleanupAudit/v1",
                "operation": self.operation, "workId": grant["workId"], "requestDigest": context.request_digest, "observation": status})
        profile.require(not replay)
        return core.KernelTransition(mutations=audit, work_units=1024, result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": digest, "idempotentReplay": False, "payload": payload})


KERNELS = MappingProxyType({operation: MeasuredCleanupKernel(operation) for operation in profile.OPERATIONS})
