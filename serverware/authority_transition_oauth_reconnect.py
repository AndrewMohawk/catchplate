"""Protected family reconnect, with exact originals and no provider I/O."""
from dataclasses import dataclass
from datetime import timedelta
from types import MappingProxyType
from serverware import authority_oauth_reconnect as profile
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_exchange as exchange
from serverware import authority_oauth_inventory as inventory
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_provider_retirement as provider_retirement
from serverware import authority_oauth_retirement_succession_current as succession
from serverware import authority_credential_currentness as current
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as approvals
from serverware import authority_transition_oauth_reconnect_rows as rows


def _population(operation, table):
    return core.BoundedQuery(query_id=core.query_program_id(operation, "complete_population", table), table=table,
        predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.maximum_rows(table) + 1,
        proof_primitive="bounded-limit-plus-one", work_units=inventory.maximum_rows(table) + 1, page_size=inventory.maximum_rows(table))


def _approval_id(operation, values, request_digest):
    return values["approval_id"] or core.deterministic_uuid(operation=operation, request_digest=request_digest, purpose="oauth-reconnect-approval")


def _hardware(context, values):
    actor, policy = values["actor_id"], values["credential_policy"]
    evidence = context.verified_webauthn_evidence
    profile.require(evidence is not None)
    credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "actual requester hardware")
    approvals._hardware(credential, policy)
    profile.require(credential["user_id"] == actor and evidence["rpId"] == policy["rpId"] and evidence["origin"] in policy["origins"]
        and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= policy["maxAssertionAgeSeconds"] * 1_000_000_000)
    return evidence, list(assertion._assertion_mutations(context, {"actor_id": actor}))


def _same_native(current_proof, original_proof):
    for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "instanceId", "policyHash",
            "dataPlaneBinarySha256", "enrollmentSha256", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256", "ingressLeafSpkiSha256"):
        profile.require(current_proof[name] == original_proof[name], "native reconnect owner changed")


def _candidate(values, expected, target, now):
    request = values["request"]
    before = rows.metadata(target); metadata, review = request["metadata"], request["review"]
    variable = {"scopes", "expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms", "token_type", "refreshable", "provider_identity_verified"}
    profile.require({key: item for key, item in metadata.items() if key not in variable} ==
        {key: item for key, item in before.items() if key not in variable}
        and metadata.get("provider_id") == expected["providerId"] and metadata.get("provider_subject") == expected["providerSubject"]
        and metadata.get("provider_account") == expected["providerAccount"] and metadata.get("scopes") == expected["scopes"]
        and metadata.get("provider_identity_verified") is True and metadata.get("refreshable") is True and metadata.get("token_type") == "Bearer"
        and type(metadata.get("expires_at_epoch_ms")) is int and metadata["expires_at_epoch_ms"] * 1_000_000 > now)
    if "refresh_token_expires_at_epoch_ms" in metadata:
        profile.require(type(metadata["refresh_token_expires_at_epoch_ms"]) is int and metadata["refresh_token_expires_at_epoch_ms"] * 1_000_000 > now)
    expected_review = {"credential_type": "oauth2", "provider": expected["providerId"], "provider_subject": expected["providerSubject"],
        "provider_account": expected["providerAccount"], "scopes": expected["scopes"], "credential_name": target["name"],
        "metadata_keys": sorted(metadata), "expires_at_epoch_ms": metadata["expires_at_epoch_ms"],
        "oauth_application_owner": metadata["oauth_application_owner"], "reconnect_credential_id": expected["credentialId"],
        "reconnect_credential_version": expected["credentialVersion"]}
    if expected["providerId"] == "x":
        expected_review["x_app_id"] = expected["clientId"]
    profile.require(review == expected_review)
    authorization_sha = profile.sha256(profile.decoded(values["authorization_original"], profile.MAX_GRANT_BYTES))
    wanted = profile.sha256(profile.canonical({"action": profile.ACTION, "authorizationSha256": authorization_sha,
        "review": review, "encrypted_token_source_sha256": request["tokenSecretSha256"]}))
    profile.require(request["payloadDigest"] == wanted)
    value = {"apiVersion": "serverware.oauthReconnectCandidate/v1", "authorizationSha256": authorization_sha,
        "credentialId": expected["credentialId"], "previousVersion": expected["credentialVersion"], "exchangeId": expected["authorizationId"],
        "tokenSecretSha256": request["tokenSecretSha256"], "tokenEnvelope": request["tokenEnvelope"], "metadata": metadata,
        "review": review, "payloadDigest": wanted, "createdAtEpochNs": now, "expiresAtEpochNs": expected["pendingExpiresAtEpochNs"]}
    profile.candidate_original(value, expected)
    return value


@dataclass(frozen=True, slots=True)
class ReconnectKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        profile.require(self.operation not in profile.ASSERTION_OPERATIONS, "actual hardware evidence is required")
        return self._queries(arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        profile.require(self.operation in profile.ASSERTION_OPERATIONS)
        return self._queries(arguments, request_digest, evidence)

    def _queries(self, arguments, request_digest, evidence):
        values = profile.arguments(self.operation, arguments, typed=True); expected = rows.grant(values)
        identifier = expected["authorizationId"]
        result = [shared._query(operation=self.operation, name="reconnect_authorization", table=profile.JOURNAL_TABLE,
            key={"id": identifier}, require_absence=self.operation == profile.OP_AUTHORIZE),
            shared._role_query(self.operation, "actor_role", values["actor_id"]),
            provider_retirement.query(self.operation, expected["providerId"])]
        if self.operation in succession.GUARDED_OPERATIONS:
            result.append(succession.query(self.operation, expected["providerId"]))
        if self.operation == profile.OP_AUTHORIZE:
            result.append(_population(self.operation, profile.JOURNAL_TABLE))
        if self.operation == profile.OP_FENCE:
            result.extend(_population(self.operation, table) for table in inventory.TABLES)
        else:
            result.extend((family.query(self.operation, expected["providerId"], expected["providerSubject"]),
                family.pending_query(self.operation, expected["providerId"], expected["providerSubject"])))
        for index, pin in enumerate(expected["affectedLineages"]):
            if self.operation != profile.OP_FENCE:
                result.append(shared._query(operation=self.operation, name="reconnect_credential_" + str(index),
                    table="credentials", key={"id": pin["credentialId"]}))
            result.append(shared._query(operation=self.operation, name="reconnect_generation_" + str(index),
                table="credential_generations", key={"credential_id": pin["credentialId"]}))
            if self.operation != profile.OP_AUTHORIZE:
                root_key = {"id": current.root_id(pin["credentialId"], pin["credentialVersion"])}
                result.extend((currentness.root_query(self.operation, pin["credentialId"], pin["credentialVersion"],
                    name="reconnect_root_" + str(index)), shared._query(operation=self.operation,
                    name="reconnect_barrier_" + str(index), table=current.BARRIER_TABLE,
                    key={"id": core.SelectedRowFieldReference(current.ROOT_TABLE, root_key, "barrier_id")})))
        if self.operation not in {profile.OP_AUTHORIZE, profile.OP_FENCE}:
            result.extend((shared._query(operation=self.operation, name="reconnect_custody", table=profile.TABLE,
                key={"id": identifier}, require_absence=self.operation == profile.OP_PREPARE),
                shared._query(operation=self.operation, name="reconnect_exchange", table=exchange.TABLE,
                    key={"id": identifier}, require_absence=self.operation == profile.OP_PREPARE)))
        if self.operation == profile.OP_PREPARE:
            result.append(_population(self.operation, exchange.TABLE))
        if evidence is not None:
            for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"),
                    ("assertion_challenge", "webauthn_challenges", "challengeId")):
                core.require_text(evidence.get(field), field, maximum_bytes=1024)
                result.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
            result.extend(assertion._trust_queries(self.operation, work=None))
        if self.operation in {profile.OP_REQUEST, profile.OP_DECIDE, profile.OP_ACTIVATE}:
            item = _approval_id(self.operation, values, request_digest)
            result.append(shared._query(operation=self.operation, name="approval", table="control_plane_approvals", key={"id": item}))
            if self.operation == profile.OP_REQUEST:
                result.append(shared._aggregate_query(self.operation, "approval_capacity", "control-plane-approvals", "global"))
            else:
                result.append(shared._role_query(self.operation, "other_role", core.SelectedRowFieldReference("control_plane_approvals",
                    {"id": item}, "requester_id" if self.operation == profile.OP_DECIDE else "approved_by")))
        if self.operation == profile.OP_ACTIVATE:
            result.extend((currentness.root_query(self.operation, expected["credentialId"], expected["credentialVersion"] + 1,
                absent=True, name="next_currentness_root"),
                shared._query(operation=self.operation, name="approver_credential", table="webauthn_credentials", key={"id":
                    core.SelectedRowFieldReference("control_plane_approvals", {"id": values["approval_id"]}, "approver_webauthn_credential_id")})))
        result.append(shared._audit_query(self.operation, request_digest))
        return family.order_populations(self.operation, tuple(result))

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True); expected = rows.grant(values)
        now = shared._database_epoch_ns(context.database_now); stamp = context.database_now.isoformat()
        profile.require(expected["issuedAtEpochNs"] <= now < expected["expiresAtEpochNs"])
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, expected["providerId"])
        provider_retirement.require_open(context, expected["providerId"])
        shared._require_role(context, subject_id=values["actor_id"], required_role="credential_owner")
        mutations, custody, exchanged, candidate, extra = [], None, None, None, {}
        if self.operation == profile.OP_AUTHORIZE:
            _, mutations = _hardware(context, values)
            selected = context.exact(profile.JOURNAL_TABLE, {"id": expected["authorizationId"]})
            profile.require(not selected["present"] and len(context.present_rows(profile.JOURNAL_TABLE)) < profile.MAX_HISTORY_ROWS
                and now < expected["contactExpiresAtEpochNs"])
            members = rows.before_members(context, expected)
            target = next(row for row, _ in members if row["id"] == expected["credentialId"])
            rows.exact_application(values, expected, target)
            family.require_open(context, expected["providerId"], expected["providerSubject"])
            journal = {"id": expected["authorizationId"], "authorization_original": profile.decoded(values["authorization_original"], profile.MAX_GRANT_BYTES).decode("ascii"),
                "authorization_sha256": values["request"]["authorizationSha256"],
                "enrollment_original": profile.activation.enrollment_bytes(values["enrollment_original"]).decode("ascii"), "actor_id": values["actor_id"],
                "credential_policy_json": profile.canonical(values["credential_policy"]).decode("ascii"),
                "original_affected_json": profile.canonical([{"credentialOriginal": refresh.credential_original(row).decode("ascii"),
                    "generationOriginal": refresh.generation_original(head).decode("ascii")} for row, head in members]).decode("ascii"),
                "authorize_arguments_json": profile.canonical(values).decode("ascii"), "authorize_request_digest": context.request_digest,
                "currentness_barriers_json": None, "fence_arguments_json": None, "fence_request_digest": None, "status": "authorized",
                "created_at": stamp, "admission_expires_at": rows.iso(min(now + 30_000_000_000, expected["contactExpiresAtEpochNs"])),
                "expires_at": rows.iso(expected["expiresAtEpochNs"]), "updated_at": stamp}
            profile.journal_original(journal)
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=journal))
        elif self.operation == profile.OP_FENCE:
            selected, journal, _ = rows.journal(context, values, fenced=False)
            request = values["request"]
            profile.require(request["authorizationRowSha256"] == profile.sha256(profile.journal_original(journal))
                and request["issuedAtEpochNs"] == rows.epoch(journal["created_at"])
                and request["expiresAtEpochNs"] == rows.epoch(journal["admission_expires_at"])
                and request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"] <= expected["contactExpiresAtEpochNs"])
            rows.complete_family(context, expected)
            members = rows.before_members(context, expected)
            profile.require(members == rows.affected(journal, expected))
            for (before, _), barrier in zip(members, request["currentnessBarriers"]):
                mutations.extend(currentness.consume_barrier(context, before["id"], before["credential_version"], barrier["barrierSha256"]))
                mutations.append(core.mutation(operation=self.operation, selected=context.exact("credentials", {"id": before["id"]}),
                    row={**before, "lifecycle_status": "reconnect_pending" if before["id"] == expected["credentialId"] else "reconnect_fenced", "updated_at": stamp}))
            journal = {**journal, "status": "fenced", "currentness_barriers_json": profile.canonical(request["currentnessBarriers"]).decode("ascii"),
                "fence_arguments_json": profile.canonical(values).decode("ascii"), "fence_request_digest": context.request_digest, "updated_at": stamp}
            profile.journal_original(journal)
            mutations.append(core.mutation(operation=self.operation, selected=selected, row=journal))
        else:
            _, journal, _ = rows.journal(context, values)
            selected = context.exact(profile.TABLE, {"id": expected["authorizationId"]})
            exchange_selected = context.exact(exchange.TABLE, {"id": expected["authorizationId"]})
            if selected["present"]:
                custody = shared._row(selected, "actual reconnect custody"); profile.row_original(custody)
                exchanged = shared._row(exchange_selected, "actual reconnect exchange"); exchange.row_original(exchanged)
            committed = rows.stored(custody["committed_credential_json"], 512 * 1024) if custody is not None and custody["status"] == "committed" else None
            originals = rows.fenced_members(context, journal, expected, committed=committed)
            target = next(row for row, _ in originals if row["id"] == expected["credentialId"])
            rows.exact_application(values, expected, target)
            if self.operation in profile.NATIVE_OPERATIONS:
                profile.require(values["request"]["fencedRowSha256"] == profile.sha256(profile.journal_original(journal)))
                exchanged, custody, candidate, effects = self._native(context, values, expected, journal, target, exchanged, custody)
                mutations.extend(effects)
            else:
                profile.require(custody is not None and custody["status"] == "staged" and now < expected["pendingExpiresAtEpochNs"])
                candidate = rows.stored(custody["candidate_original_json"], profile.MAX_CANDIDATE_BYTES)
                profile.require(profile.candidate_original(candidate, expected).decode("ascii") == custody["candidate_original_json"]
                    and values["request"]["candidateSha256"] == profile.sha256(profile.candidate_original(candidate, expected)))
                effects, approval, credential = self._approval(context, values, expected, journal, custody, candidate, target)
                mutations.extend(effects); extra["approval"] = approvals._public(approval)
                if credential is not None:
                    custody = {**custody, "status": "committed", "commit_request_digest": context.request_digest,
                        "committed_credential_json": refresh.credential_original(credential).decode("ascii"),
                        "predecessor_original_json": refresh.credential_original(target).decode("ascii"), "updated_at": stamp}
                    profile.row_original(custody)
                    mutations.append(core.mutation(operation=self.operation, selected=selected, row=custody))
                    extra["credential"] = {key: (candidate["metadata"] if key == "metadata" else value) for key, value in credential.items()
                        if key not in {"encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext"}}
        audit, audit_digest, replay = shared._audit_mutations(context, event_type="credential.oauth.reconnect." + self.operation.rsplit(".", 1)[1],
            actor_type="credential_owner" if self.operation in profile.ASSERTION_OPERATIONS else "measured_oauth_reconnect", actor_id=values["actor_id"],
            event={"schema": "serverware.oauthReconnectAudit/v1", "operation": self.operation, "requestDigest": context.request_digest,
                "authorizationSha256": journal["authorization_sha256"], "credentialId": expected["credentialId"],
                "previousVersion": expected["credentialVersion"], "journalSha256": profile.sha256(profile.journal_original(journal)),
                "status": journal["status"] if custody is None else custody["status"]})
        profile.require(not replay)
        result = {"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
            "auditEventDigest": audit_digest, "idempotentReplay": False, "originals": {
                "journalOriginal": profile.journal_original(journal).decode("ascii"),
                "exchangeOriginal": None if exchanged is None else exchange.row_original(exchanged).decode("ascii"),
                "custodyOriginal": None if custody is None else profile.row_original(custody).decode("ascii"),
                "candidateOriginal": None if custody is None else custody["candidate_original_json"]}, **extra}
        return core.KernelTransition(mutations=tuple(mutations) + audit, result=result, work_units=4096)

    def _native(self, context, values, expected, journal, target, exchanged, custody):
        request = values["request"]; now = shared._database_epoch_ns(context.database_now); stamp = context.database_now.isoformat()
        effects, candidate = [], None
        selected = context.exact(profile.TABLE, {"id": expected["authorizationId"]})
        exchange_selected = context.exact(exchange.TABLE, {"id": expected["authorizationId"]})
        if self.operation == profile.OP_PREPARE:
            profile.require(custody is None and not selected["present"] and not exchange_selected["present"]
                and len(context.present_rows(exchange.TABLE)) < inventory.MAX_ROWS
                and rows.epoch(journal["updated_at"]) <= request["issuedAtEpochNs"] <= now < expected["contactExpiresAtEpochNs"]
                and request["metadata"] == rows.metadata(target) and request["credentialName"] == target["name"])
            profile.require(all(rows.stored(shared._row(item, "prior exchange")["consent_json"])["stateSha256"] != request["stateSha256"]
                for item in context.present_rows(exchange.TABLE)))
            exchanged = {"id": expected["authorizationId"], "provider_id": expected["providerId"], "requester_id": expected["requesterId"],
                "enrollment_original": values["enrollment_original"], "credential_policy_json": journal["credential_policy_json"],
                "consent_json": profile.canonical(request).decode("ascii"), "status": "prepared", **{name: None for name in exchange.NULLABLE},
                "created_at": stamp, "updated_at": stamp}
            custody = {name: None for name in profile.ROW_FIELDS}
            custody.update(id=expected["authorizationId"], prepare_request_digest=context.request_digest,
                preparation_arguments_json=profile.canonical(values).decode("ascii"), status="prepared", created_at=stamp, updated_at=stamp)
        else:
            profile.require(custody is not None)
            preparation = profile.arguments(profile.OP_PREPARE, rows.stored(custody["preparation_arguments_json"], profile.MAX_ARGUMENT_BYTES))
            profile.require(preparation["authorization_original"] == values["authorization_original"]
                and preparation["request"] == rows.stored(exchanged["consent_json"])
                and preparation["credential_policy"] == values["credential_policy"]
                and exchanged["enrollment_original"] == values["enrollment_original"])
            if self.operation == profile.OP_RECOVER:
                profile.require(request["custodyRowSha256"] == profile.sha256(profile.row_original(custody))
                    and custody["capture_arguments_json"] is not None
                    and request["captureInputSha256"] == profile.sha256(custody["capture_arguments_json"].encode("ascii")))
                if custody["status"] in {"staged", "committed"}:
                    return exchanged, custody, rows.stored(custody["candidate_original_json"], profile.MAX_CANDIDATE_BYTES), ()
                profile.require(custody["status"] == "captured" and exchanged["status"] == "retained"
                    and exchanged["token_envelope_json"] is not None and custody["recovery_request_digest"] is None
                    and request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"] <= expected["pendingExpiresAtEpochNs"])
                custody = {**custody, "recovery_request_digest": context.request_digest, "recovery_expires_at_epoch_ns": request["expiresAtEpochNs"],
                    "recovery_arguments_json": profile.canonical(values).decode("ascii"), "recovery_owner_nonce_sha256": request["ownerNonceSha256"], "updated_at": stamp}
            else:
                profile.require(request["exchangeRowSha256"] == exchange.row_digest(exchanged))
                recovering = self.operation == profile.OP_STAGE and request["recoveryRequestDigest"] is not None
                if recovering:
                    recovery = profile.arguments(profile.OP_RECOVER, rows.stored(custody["recovery_arguments_json"], profile.MAX_ARGUMENT_BYTES))
                    _same_native(values["native_evidence"]["statement"], recovery["native_evidence"]["statement"])
                    profile.require(request["recoveryRequestDigest"] == custody["recovery_request_digest"]
                        and now < custody["recovery_expires_at_epoch_ns"] and values["assignment_original"] == recovery["assignment_original"]
                        and profile.sha256(profile.decoded(request["ownerNonce"], 32, 32)) == custody["recovery_owner_nonce_sha256"])
                else:
                    _same_native(values["native_evidence"]["statement"], preparation["native_evidence"]["statement"])
                    profile.require(values["assignment_original"] == preparation["assignment_original"] and custody["recovery_request_digest"] is None
                        and now < expected["contactExpiresAtEpochNs" if self.operation in {profile.OP_CLAIM, profile.OP_CANCEL} else "retentionExpiresAtEpochNs"])
                    if self.operation in {profile.OP_CAPTURE, profile.OP_STAGE}:
                        profile.require(profile.sha256(profile.decoded(request["ownerNonce"], 32, 32)) == custody["owner_nonce_sha256"])
                if self.operation == profile.OP_CLAIM:
                    profile.require(custody["status"] == exchanged["status"] == "prepared" and all(exchanged[name] is None for name in exchange.NULLABLE))
                    exchanged = {**exchanged, "status": "claimed", "claim_request_digest": context.request_digest,
                        "code_sha256": request["codeSha256"], "contact_request_sha256": request["contactRequestSha256"], "updated_at": stamp}
                    custody = {**custody, "status": "claimed", "claim_arguments_json": profile.canonical(values).decode("ascii"),
                        "owner_nonce_sha256": request["ownerNonceSha256"], "updated_at": stamp}
                elif self.operation == profile.OP_CANCEL:
                    profile.require(custody["status"] == exchanged["status"] == "prepared" and all(exchanged[name] is None for name in exchange.NULLABLE))
                    custody = {**custody, "status": "cancelled", "cancel_arguments_json": profile.canonical(values).decode("ascii"), "updated_at": stamp}
                elif self.operation == profile.OP_CAPTURE:
                    profile.require(custody["status"] == exchanged["status"] == "claimed" and custody["capture_arguments_json"] is None
                        and preparation["request"]["issuedAtEpochNs"] <= request["receivedAtEpochNs"] <= now)
                    exchanged = {**exchanged, "status": "retained", "raw_response_sha256": request["rawResponseSha256"],
                        "raw_response_envelope_json": profile.canonical(request["rawResponseEnvelope"]).decode("ascii"),
                        "token_secret_sha256": request["issuedMaterialSha256"], "token_envelope_json": None if request["issuedMaterialEnvelope"] is None else profile.canonical(request["issuedMaterialEnvelope"]).decode("ascii"),
                        "updated_at": stamp}
                    custody = {**custody, "status": "captured", "capture_arguments_json": profile.canonical(values).decode("ascii"),
                        "received_at_epoch_ns": request["receivedAtEpochNs"], "updated_at": stamp}
                else:
                    profile.require(self.operation == profile.OP_STAGE and custody["status"] == "captured" and exchanged["status"] == "retained"
                        and exchanged["token_envelope_json"] is not None and exchanged["raw_response_envelope_json"] is not None
                        and now < expected["pendingExpiresAtEpochNs"])
                    candidate = _candidate(values, expected, target, now)
                    exchanged = {**exchanged, "status": "staged", "updated_at": stamp}
                    custody = {**custody, "status": "staged", "stage_arguments_json": profile.canonical(values).decode("ascii"),
                        "candidate_original_json": profile.candidate_original(candidate, expected).decode("ascii"), "updated_at": stamp}
        exchange.row_original(exchanged); profile.row_original(custody)
        effects.extend((core.mutation(operation=self.operation, selected=exchange_selected, row=exchanged),
            core.mutation(operation=self.operation, selected=selected, row=custody)))
        return exchanged, custody, candidate, effects

    def _approval(self, context, values, expected, journal, custody, candidate, target):
        evidence, effects = _hardware(context, values); actor, now = values["actor_id"], context.database_now
        item = _approval_id(self.operation, values, context.request_digest)
        selected = context.exact("control_plane_approvals", {"id": item}); credential = None
        if self.operation == profile.OP_REQUEST:
            profile.require(not selected["present"] and actor == expected["requesterId"])
            expires = min(now + timedelta(seconds=300), exchange.timestamp(rows.iso(expected["pendingExpiresAtEpochNs"])))
            profile.require(expires > now)
            provenance = {"schema": profile.PROVENANCE_SCHEMA, "requestDigest": context.request_digest,
                "requestEvidenceDigest": evidence["verifiedAssertionReceiptDigest"], "credentialPolicy": values["credential_policy"],
                "decisionDigest": None, "decisionEvidenceDigest": None, "consumptionDigest": None, "consumptionEvidenceDigest": None}
            row = {"id": item, "action": profile.ACTION, "resource_id": expected["authorizationId"], "payload_digest": values["payload_digest"],
                "requester_id": actor, "request_json": profile.canonical(values["request"]).decode("ascii"), "status": "pending", "requested_at": now.isoformat(),
                "expires_at": expires.isoformat(), "approved_by": None, "approved_at": None, "consumed_by": None, "consumed_at": None,
                "decision_note": None, "approver_webauthn_credential_id": None, "approval_authn": profile.canonical(provenance).decode("ascii")}
            effects.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global", live_delta=1,
                active_delta=1, next_sequence_delta=1, minimum_expiry_epoch_ns=shared._database_epoch_ns(expires)))
        else:
            row = shared._row(selected, "actual reconnect approval"); provenance = rows.stored(row["approval_authn"], 16384)
            profile.require(set(provenance) == approvals._PROVENANCE and provenance["schema"] == profile.PROVENANCE_SCHEMA
                and provenance["credentialPolicy"] == values["credential_policy"] and row["action"] == profile.ACTION
                and row["resource_id"] == expected["authorizationId"] and row["payload_digest"] == values["payload_digest"]
                and row["request_json"] == profile.canonical(values["request"]).decode("ascii") and row["requester_id"] == expected["requesterId"]
                and exchange.timestamp(row["expires_at"]) > now and row["decision_note"] is None)
            for name in ("requestDigest", "requestEvidenceDigest"):
                profile.digest(provenance[name])
            if self.operation == profile.OP_DECIDE:
                shared._require_role(context, subject_id=row["requester_id"], required_role="credential_owner")
                profile.require(row["status"] == "pending" and actor != row["requester_id"] and row["approved_by"] is None
                    and all(provenance[name] is None for name in ("decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest")))
                provenance.update(decisionDigest=context.request_digest, decisionEvidenceDigest=evidence["verifiedAssertionReceiptDigest"])
                row = {**row, "status": "approved", "approved_by": actor, "approved_at": now.isoformat(), "approver_webauthn_credential_id": evidence["credentialRecordId"]}
            else:
                profile.require(row["status"] == "approved" and row["requester_id"] == actor and row["approved_by"] not in {None, actor}
                    and row["consumed_by"] is None and row["consumed_at"] is None
                    and provenance["consumptionDigest"] is None and provenance["consumptionEvidenceDigest"] is None)
                for name in ("decisionDigest", "decisionEvidenceDigest"):
                    profile.digest(provenance[name])
                shared._require_role(context, subject_id=row["approved_by"], required_role="credential_owner")
                approver = shared._row(context.exact("webauthn_credentials", {"id": row["approver_webauthn_credential_id"]}), "actual approver hardware")
                approvals._hardware(approver, values["credential_policy"])
                publications = context.present_rows("webauthn_trust_publications"); profile.require(len(publications) == 1)
                publication = shared._row(publications[0], "current physical trust")
                import json
                withdrawn = json.loads(publication["withdrawn_credential_ids_json"])
                profile.require(approver["user_id"] == row["approved_by"] and approver.get("attestation_trust_bundle_digest") == publication["bundle_digest"]
                    and approver.get("attestation_trust_bundle_sequence") == publication["sequence"] and type(withdrawn) is list
                    and approver["id"] not in withdrawn and approver["credential_id"] not in withdrawn)
                target_selected = context.exact("credentials", {"id": expected["credentialId"]})
                head_selected = context.exact("credential_generations", {"credential_id": expected["credentialId"]})
                head = shared._row(head_selected, "actual predecessor head")
                next_selected = context.exact(current.ROOT_TABLE, {"id": current.root_id(target["id"], target["credential_version"] + 1)})
                profile.require(not next_selected["present"])
                credential = {**target, **candidate["tokenEnvelope"], "metadata": profile.canonical(candidate["metadata"]).decode("ascii"),
                    "lifecycle_status": "active", "revocation_error": None, "revocation_requested_at": None, "updated_at": now.isoformat()}
                refresh.credential_original(credential)
                barriers = profile.lineages_codec.array_document(journal["currentness_barriers_json"].encode("ascii"), 16384)
                predecessor = next(value["barrierSha256"] for value in barriers if value["credentialId"] == target["id"])
                effects.extend((core.mutation(operation=self.operation, selected=target_selected, row=credential),
                    core.mutation(operation=self.operation, selected=head_selected, row={**head, "last_version": head["last_version"] + 1, "updated_at": now.isoformat()}),
                    core.mutation(operation=self.operation, selected=next_selected,
                        row=current.new_root(target["id"], target["credential_version"] + 1, context.request_digest, now.isoformat(), predecessor))))
                provenance.update(consumptionDigest=context.request_digest, consumptionEvidenceDigest=evidence["verifiedAssertionReceiptDigest"])
                row = {**row, "status": "consumed", "consumed_by": actor, "consumed_at": now.isoformat()}
            row["approval_authn"] = profile.canonical(provenance).decode("ascii")
        effects.append(core.mutation(operation=self.operation, selected=selected, row=row))
        return effects, row, credential


KERNELS = MappingProxyType({operation: ReconnectKernel(operation) for operation in profile.OPERATIONS})
