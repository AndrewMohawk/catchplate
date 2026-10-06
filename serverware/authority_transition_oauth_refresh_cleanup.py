"""One irreversible family retirement, competing with refresh and activation."""
from dataclasses import dataclass
from serverware import authority_oauth_retirement_succession_current as succession
from types import MappingProxyType

from serverware import authority_oauth_refresh_cleanup as profile
from serverware import authority_oauth_inventory as inventory
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
    issued = grant["workSource"] == refresh.ISSUED_SOURCE
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
    return row, work_selected, work, credential_selected, credential, generation


@dataclass(frozen=True, slots=True)
class OAuthRefreshCleanupKernel:
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
                ("work", "oauth_revocation_work", {"id": grant["workId"]}, False),
                ("generation", "credential_generations", {"credential_id": grant["credentialId"]}, False),
                ("journal", profile.JOURNAL_TABLE, {"id": grant["workId"]}, self.operation == profile.OP_CLAIM))]
        if self.operation in succession.GUARDED_OPERATIONS:
            queries.append(succession.query(self.operation, grant["providerId"]))
        queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", "credentials"),
            table="credentials", predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.MAX_ROWS + 1,
            proof_primitive="bounded-limit-plus-one", work_units=inventory.MAX_ROWS + 1, page_size=inventory.MAX_ROWS))
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
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, grant["providerId"])
        now = shared._database_epoch_ns(context.database_now); stamp = context.database_now.isoformat()
        profile.require(grant["issuedAtEpochNs"] <= now < grant["expiresAtEpochNs"])
        history, work_selected, work, credential_selected, credential, generation = _originals(context, values, grant)
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
        profile.journal_original(journal)
        if attempt is not None: profile.attempt_original(attempt)
        mutations.extend((core.mutation(operation=self.operation, selected=journal_selected, row=journal), core.mutation(operation=self.operation, selected=work_selected, row=work)))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation, actor_type="family_retirement_authority",
            actor_id=grant["authorizationId"], event={"schema": "serverware.oauthRefreshCleanupAudit/v1", "operation": self.operation,
                "workId": work["id"], "requestDigest": context.request_digest, "authorizationSha256": journal["authorization_sha256"],
                "journal": _journal_public(journal), "attempt": _attempt_public(attempt)})
        profile.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations) + audit, work_units=1024,
            result={"ok": True, "journal": _journal_public(journal), "attempt": _attempt_public(attempt), "operation": self.operation,
                "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False})


KERNELS = MappingProxyType({operation: OAuthRefreshCleanupKernel(operation) for operation in profile.OPERATIONS})
