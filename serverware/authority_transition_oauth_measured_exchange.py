"""Measured initial issuance: definite consent, contact, capture and staging.

Provider I/O and plaintext are deliberately absent. Each machine phase arrives
with independently verified, purpose-bound native evidence. The prepare phase
also consumes genuine current requester WebAuthn evidence. A retained capture
is not a second contact permit, and neither absence nor expiry resolves contact.
"""
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType

from serverware import authority_oauth_measured_exchange as profile
from serverware import authority_oauth_measured_setup as setup_profile
from serverware import authority_oauth_setup as setup
from serverware import authority_transition_oauth_setup_rows as setup_rows
from serverware import authority_oauth_exchange as exchange
from serverware import authority_oauth_activation as activation
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_inventory as inventory
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_provider_retirement as provider_retirement
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_exchange as old
from serverware import authority_transition_oauth_activation as activate


def _original(value, label):
    return shared._canonical_stored_mapping(value, label)


def _public(row, custody, *, contract=profile):
    consent = _original(row["consent_json"], "native consent")
    return {"id": row["id"], "status": custody["status"], "exchangeRowSha256": exchange.row_digest(row),
        "custodyRowSha256": contract.sha256(contract.row_original(custody)),
        **{name: consent[name] for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")}}


def _same_owner(left, right):
    names = ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "deploymentId", "instanceId",
        "providerId", "enrollmentSha256", "policyHash", "dataPlaneBinarySha256", "callbackOrigin", "portalOrigin",
        "ingressLeafCertificateSha256", "ingressLeafSpkiSha256")
    profile.require(all(left[name] == right[name] for name in names), "native issuance owner changed")


@dataclass(frozen=True, slots=True)
class MeasuredExchangeKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def profile(self):
        # A source-owned closed operation selects the implementation contract.
        # The separate verifier policy/signature admission is still mandatory.
        profile.require(self.operation in profile.OPERATIONS | setup_profile.OPERATIONS)
        return setup_profile if self.operation in setup_profile.OPERATIONS else profile

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        profile = self.profile
        profile.require(self.operation != profile.OP_PREPARE, "consent requires actual requester assertion")
        return self._queries(arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        profile = self.profile
        profile.require(self.operation == profile.OP_PREPARE)
        return self._queries(arguments, request_digest, evidence)

    def _queries(self, arguments, request_digest, evidence):
        profile = self.profile
        values = profile.arguments(self.operation, arguments, typed=True)
        item_id = values["resource_id"]
        provider = enrollment.enrollment_document(activation.enrollment_bytes(values["enrollment_original"]))["payload"]["providerId"]
        queries = [shared._query(operation=self.operation, name=name, table=table, key={"id": item_id},
            require_absence=self.operation == profile.OP_PREPARE) for name, table in
            (("exchange", exchange.TABLE), ("custody", profile.TABLE), ("work", "oauth_revocation_work"))]
        queries.append(provider_retirement.query(self.operation, provider))
        if self.operation == profile.OP_PREPARE:
            queries.append(shared._role_query(self.operation, "actor_role", values["actor_id"]))
            for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"),
                    ("assertion_challenge", "webauthn_challenges", "challengeId")):
                core.require_text(evidence.get(field), field, maximum_bytes=1024)
                queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
            queries.extend(assertion._trust_queries(self.operation, work=None))
        if self.operation in {profile.OP_PREPARE, profile.OP_STAGE}:
            for table in inventory.tables_for(self.operation):
                queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table),
                    table=table, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.maximum_rows(table) + 1,
                    proof_primitive="bounded-limit-plus-one", work_units=inventory.maximum_rows(table) + 1))
        if self.operation in {profile.OP_STAGE, profile.OP_RECOVER}:
            queries.append(shared._query(operation=self.operation, name="pending", table="pending_oauth_credentials", key={"id": item_id}))
        if self.operation == profile.OP_STAGE:
            queries.extend((shared._query(operation=self.operation, name="credential", table="credentials", key={"id": item_id}, require_absence=True),
                shared._query(operation=self.operation, name="generation", table="credential_generations", key={"credential_id": item_id}, require_absence=True)))
        if profile is setup_profile:
            session_id = values["request"]["setupBinding"]["sessionId"]
            queries.append(shared._query(operation=self.operation, name="setup", table="setup_sessions", key={"id": session_id}))
            if self.operation == profile.OP_PREPARE:
                queries.append(shared._query(operation=self.operation, name="setup_creation_event", table="setup_session_events",
                    key={"id": setup.event_id(session_id, 1)}))
                queries.append(shared._query(operation=self.operation, name="setup_creation_link", table=setup.AUDIT_LINK_TABLE,
                    key={"id": setup.event_id(session_id, 1)}))
            if self.operation in {profile.OP_PREPARE, profile.OP_STAGE, profile.OP_CANCEL}:
                queries.extend(setup_rows.event_queries(self.operation, session_id, 1 if self.operation == profile.OP_PREPARE else 2))
        queries.append(shared._audit_query(self.operation, request_digest))
        return family.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        profile = self.profile
        values = profile.arguments(self.operation, context.arguments, typed=True)
        request, actor = values["request"], values["actor_id"]
        now = context.database_now.astimezone(timezone.utc)
        stamp, now_ns = now.isoformat(), shared._database_epoch_ns(now)
        raw = activation.enrollment_bytes(values["enrollment_original"])
        payload = enrollment.enrollment_document(raw)["payload"]
        if self.operation not in {profile.OP_CAPTURE, profile.OP_CANCEL}:
            provider_retirement.require_open(context, payload["providerId"])
        association = enrollment.association(raw)
        statement = values["native_evidence"]["statement"]
        profile.require(statement["issuedAtEpochNs"] <= now_ns < statement["expiresAtEpochNs"])
        historical = self.operation == profile.OP_RECOVER or self.operation == profile.OP_STAGE and request["recoveryRequestDigest"] is not None
        if not historical:
            profile.require(payload["issuedAtEpochNs"] <= now_ns < payload["expiresAtEpochNs"])
        selected = context.exact(exchange.TABLE, {"id": values["resource_id"]})
        custody_selected = context.exact(profile.TABLE, {"id": values["resource_id"]})
        work_selected = context.exact("oauth_revocation_work", {"id": values["resource_id"]})
        mutations, pending, observed = [], None, False
        setup_before = setup_after = setup_transition = setup_updates = None
        if self.operation == profile.OP_PREPARE:
            if profile is setup_profile:
                _, setup_before = setup_rows.created(context, values)
                setup_after, setup_updates = setup_rows.next_row(context, setup_before, transition="bind_oauth_flow",
                    provider=request["providerId"], state_digest=request["stateSha256"])
                setup_transition = "bind_oauth_flow"
            row, custody, work, assertion_effects = self._prepare(context, values, payload, association, selected, custody_selected, work_selected)
            if profile is setup_profile:
                custody.update(setup_initial_json=setup.row_original(setup_before).decode("ascii"),
                    setup_started_json=setup.row_original(setup_after).decode("ascii"), setup_final_json=None)
            mutations.extend(assertion_effects)
        else:
            row = shared._row(selected, "native exchange")
            custody = shared._row(custody_selected, "native exchange custody")
            exchange.row_original(row); profile.row_original(custody)
            preparation = profile.arguments(profile.OP_PREPARE, _original(custody["preparation_arguments_json"], "native preparation"))
            consent = profile.request_binding(profile.OP_PREPARE, _original(row["consent_json"], "native consent"))
            profile.require(row["id"] == custody["id"] == request["exchangeId"]
                and row["requester_id"] == actor == preparation["actor_id"]
                and row["enrollment_original"] == values["enrollment_original"] == preparation["enrollment_original"]
                and row["credential_policy_json"] == profile.canonical(values["credential_policy"]).decode("ascii")
                and preparation["request"] == consent and consent["limits"] == request["limits"]
                and consent["metadata"].get("oauth_application_owner") == association
                and all(statement[name] == consent[name] for name in ("providerId", "portalOrigin", "callbackOrigin")))
            if profile is setup_profile:
                profile.require(request["setupBinding"] == consent["setupBinding"])
                _, setup_before = setup_rows.held(context, values, custody, staged=custody["status"] == "staged")
                setup_after = setup_before
            if self.operation == profile.OP_RECOVER and custody["status"] == "staged":
                profile.require(row["status"] == "staged" and not work_selected["present"]
                    and request["custodyRowSha256"] == profile.sha256(profile.row_original(custody))
                    and request["captureInputSha256"] == profile.sha256(custody["capture_arguments_json"].encode("ascii"))
                    and request["issuedAtEpochNs"] <= now_ns < request["expiresAtEpochNs"])
                pending = shared._row(context.exact("pending_oauth_credentials", {"id": row["id"]}), "exact completed pending")
                profile.require(activation.pending_original(pending).decode("ascii") == custody["pending_original_json"],
                    "completed pending changed; no absence or later outcome inference")
                observed = True
                work = None
            else:
                work = self._work(row, custody, consent, work_selected)
                if self.operation == profile.OP_RECOVER:
                    profile.require(custody["status"] == "captured" and row["status"] == "retained"
                        and custody["recovery_request_digest"] is None and row["token_envelope_json"] is not None
                        and request["custodyRowSha256"] == profile.sha256(profile.row_original(custody))
                        and request["captureInputSha256"] == profile.sha256(custody["capture_arguments_json"].encode("ascii"))
                        and request["issuedAtEpochNs"] <= now_ns < request["expiresAtEpochNs"] < consent["pendingExpiresAtEpochNs"])
                    custody = {**custody, "recovery_request_digest": context.request_digest,
                        "recovery_expires_at_epoch_ns": request["expiresAtEpochNs"],
                        "recovery_owner_nonce_sha256": request["ownerNonceSha256"],
                        "recovery_arguments_json": profile.canonical(values).decode("ascii"), "updated_at": stamp}
                else:
                    profile.require(request["exchangeRowSha256"] == exchange.row_digest(row))
                    if historical:
                        recovery = profile.arguments(profile.OP_RECOVER, _original(custody["recovery_arguments_json"], "processing grant"))
                        _same_owner(statement, recovery["native_evidence"]["statement"])
                        profile.require(request["recoveryRequestDigest"] == custody["recovery_request_digest"]
                            and now_ns < custody["recovery_expires_at_epoch_ns"]
                            and custody["recovery_owner_nonce_sha256"] == profile.sha256(profile.decoded(request["ownerNonce"], 32, 32))
                            and values["assignment_original"] == recovery["assignment_original"])
                    else:
                        _same_owner(statement, preparation["native_evidence"]["statement"])
                        profile.require(custody["recovery_request_digest"] is None)
                        deadline = consent["contactExpiresAtEpochNs"] if self.operation in {profile.OP_CLAIM, profile.OP_CANCEL} else consent["retentionExpiresAtEpochNs"]
                        profile.require(consent["issuedAtEpochNs"] <= now_ns < deadline)
                        if self.operation in {profile.OP_CAPTURE, profile.OP_STAGE}:
                            claim = profile.arguments(profile.OP_CLAIM, _original(custody["claim_arguments_json"], "native contact claim"))
                            profile.require(custody["owner_nonce_sha256"] == profile.sha256(profile.decoded(request["ownerNonce"], 32, 32))
                                and values["assignment_original"] == claim["assignment_original"])
                    if self.operation == profile.OP_CLAIM:
                        profile.require(custody["status"] == row["status"] == "prepared"
                            and all(row[name] is None for name in exchange.NULLABLE))
                        row = {**row, "status": "claimed", "claim_request_digest": context.request_digest,
                            "code_sha256": request["codeSha256"], "contact_request_sha256": request["contactRequestSha256"], "updated_at": stamp}
                        custody = {**custody, "status": "claimed", "claim_arguments_json": profile.canonical(values).decode("ascii"),
                            "owner_nonce_sha256": request["ownerNonceSha256"], "updated_at": stamp}
                        work = {**work, "status": "exchange_in_flight", "next_attempt_at": old._iso(consent["retentionExpiresAtEpochNs"]), "updated_at": stamp}
                    elif self.operation == profile.OP_CANCEL:
                        profile.require(custody["status"] == row["status"] == "prepared"
                            and all(row[name] is None for name in exchange.NULLABLE))
                        custody = {**custody, "status": "cancelled", "cancel_arguments_json": profile.canonical(values).decode("ascii"), "updated_at": stamp}
                        work = {**work, "status": "cancelled_before_contact", "updated_at": stamp}
                        if profile is setup_profile:
                            setup_after, setup_updates = setup_rows.next_row(context, setup_before, transition="cancel")
                            setup_transition = "cancel"
                            custody["setup_final_json"] = setup.row_original(setup_after).decode("ascii")
                    elif self.operation == profile.OP_CAPTURE:
                        profile.require(custody["status"] == row["status"] == "claimed" and custody["capture_arguments_json"] is None
                            and consent["issuedAtEpochNs"] <= request["receivedAtEpochNs"] <= now_ns)
                        token = request["issuedMaterialEnvelope"]
                        row = {**row, "status": "retained", "raw_response_sha256": request["rawResponseSha256"],
                            "raw_response_envelope_json": profile.canonical(request["rawResponseEnvelope"]).decode("ascii"),
                            "token_secret_sha256": request["issuedMaterialSha256"],
                            "token_envelope_json": None if token is None else profile.canonical(token).decode("ascii"), "updated_at": stamp}
                        custody = {**custody, "status": "captured", "capture_arguments_json": profile.canonical(values).decode("ascii"),
                            "received_at_epoch_ns": request["receivedAtEpochNs"], "updated_at": stamp}
                        work = {**work, **({} if token is None else token), "status": "issued_unavailable" if token is None else "held", "updated_at": stamp}
                    else:
                        profile.require(self.operation == profile.OP_STAGE and custody["status"] == "captured"
                            and row["status"] == "retained" and row["token_envelope_json"] is not None
                            and row["raw_response_envelope_json"] is not None and now_ns < consent["pendingExpiresAtEpochNs"])
                        pending, effects = self._stage(context, values, row, consent, payload, association)
                        mutations.extend(effects)
                        row = {**row, "status": "staged", "updated_at": stamp}
                        custody = {**custody, "status": "staged", "stage_arguments_json": profile.canonical(values).decode("ascii"),
                            "pending_original_json": activation.pending_original(pending).decode("ascii"), "updated_at": stamp}
                        if profile is setup_profile:
                            setup_after, setup_updates = setup_rows.next_row(context, setup_before,
                                transition="bind_pending_credential", pending_id=row["id"])
                            setup_transition = "bind_pending_credential"
                            custody["setup_final_json"] = setup.row_original(setup_after).decode("ascii")
                        mutations.append(core.delete_mutation(operation=self.operation, selected=work_selected))
        if not observed:
            exchange.row_original(row); profile.row_original(custody)
            mutations.append(core.mutation(operation=self.operation, selected=custody_selected, row=custody))
            if self.operation != profile.OP_RECOVER:
                mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
                if self.operation != profile.OP_STAGE:
                    mutations.append(core.mutation(operation=self.operation, selected=work_selected, row=work))
        audit, audit_digest, replay = shared._audit_mutations(context,
            event_type=("credential.oauth.measured-setup." if profile is setup_profile else "credential.oauth.measured-exchange.") + self.operation.rsplit(".", 1)[1],
            actor_type="admin" if self.operation == profile.OP_PREPARE else "measured_oauth_exchange", actor_id=actor,
            event={"schema": "serverware.nativeOAuthSetupExchangeAudit/v1" if profile is setup_profile else "serverware.nativeOAuthExchangeAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "exchangeId": row["id"], "custodyRowSha256": profile.sha256(profile.row_original(custody)),
                "enrollmentSha256": association["enrollmentSha256"], "status": custody["status"], "observedComplete": observed,
                **({"setupPostSha256": setup.sha256(setup.row_original(setup_after))} if profile is setup_profile else {})})
        profile.require(not replay, "audit original already consumed")
        if setup_transition is not None:
            mutations.extend(setup_rows.mutations(context, setup_before, setup_after, transition=setup_transition,
                actor=actor, updates=setup_updates, audit_digest=audit_digest, provider=payload["providerId"],
                enrollment_sha256=association["enrollmentSha256"]))
        result = {"ok": True, "exchange": _public(row, custody, contract=profile), "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False,
            "originals": {"exchangeOriginal": exchange.row_original(row).decode("ascii"),
                "custodyOriginal": profile.row_original(custody).decode("ascii"),
                **({"setupOriginal": setup.row_original(setup_after).decode("ascii")} if profile is setup_profile else {})}}
        if pending is not None:
            result["pending"] = old._pending_public(pending)
        return core.KernelTransition(mutations=tuple(mutations) + audit, result=result, work_units=2048)

    def _prepare(self, context, values, payload, association, selected, custody_selected, work_selected):
        profile = self.profile
        request, actor = values["request"], values["actor_id"]
        now_ns = shared._database_epoch_ns(context.database_now)
        stamp = context.database_now.isoformat()
        profile.require(not selected["present"] and not custody_selected["present"] and not work_selected["present"])
        shared._require_role(context, subject_id=actor, required_role="credential_owner")
        profile.require(request["providerId"] == payload["providerId"] and request["redirectUri"] == payload["redirectUri"]
            and request["metadata"].get("oauth_application_owner") == association
            and payload["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now_ns < request["contactExpiresAtEpochNs"]
            and now_ns - request["issuedAtEpochNs"] <= 30_000_000_000 and request["pendingExpiresAtEpochNs"] <= payload["expiresAtEpochNs"])
        profile.require(not set(request["metadata"]) & {"setup_session_id", "setupSessionId", "reconnect", "reconnect_credential_id", "reconnect_credential_version"},
            "setup and reconnect require their own complete atomic measured successors")
        exchanges = context.present_rows(exchange.TABLE)
        work = context.present_rows("oauth_revocation_work")
        active = backlog = 0
        for selected_pending in context.present_rows("pending_oauth_credentials"):
            pending = shared._row(selected_pending, "pending population")
            live = pending["status"] == "pending" and exchange.timestamp(pending["expires_at"]) > context.database_now
            active += live
            backlog += pending["status"] in {"cancelled", "expired", "rejected"} or pending["status"] == "pending" and not live
        # All retained work counts conservatively, across old and new profiles.
        # A cancelled or uncertain original is never an available capacity slot.
        profile.require(len(exchanges) < inventory.MAX_ROWS and len(work) < request["limits"]["revocationCapacity"]
            and active + len(work) < request["limits"]["pendingCapacity"] and backlog < request["limits"]["revocationCapacity"])
        profile.require(all(_original(shared._row(item, "prior exchange")["consent_json"], "prior consent")["stateSha256"] != request["stateSha256"] for item in exchanges))
        evidence = context.verified_webauthn_evidence
        profile.require(evidence is not None)
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "requester authenticator")
        activate._hardware(credential, values["credential_policy"])
        profile.require(evidence["rpId"] == values["credential_policy"]["rpId"]
            and evidence["origin"] in values["credential_policy"]["origins"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= values["credential_policy"]["maxAssertionAgeSeconds"] * 1_000_000_000)
        row = {"id": values["resource_id"], "provider_id": payload["providerId"], "requester_id": actor,
            "enrollment_original": values["enrollment_original"], "credential_policy_json": profile.canonical(values["credential_policy"]).decode("ascii"),
            "consent_json": profile.canonical(request).decode("ascii"), "status": "prepared",
            **{name: None for name in exchange.NULLABLE}, "created_at": stamp, "updated_at": stamp}
        custody = {name: None for name in profile.ROW_FIELDS}
        custody.update(id=row["id"], prepare_request_digest=context.request_digest,
            preparation_arguments_json=profile.canonical(values).decode("ascii"), status="prepared", created_at=stamp, updated_at=stamp)
        retained = {"id": row["id"], "provider_id": row["provider_id"], "actor_id": actor, "source": profile.WORK_SOURCE,
            **request["reservedEnvelope"], "status": "reserved", "attempts": 0, "last_error": None,
            "next_attempt_at": old._iso(request["contactExpiresAtEpochNs"]), "lease_owner": None, "lease_until": None,
            "created_at": stamp, "updated_at": stamp}
        return row, custody, retained, assertion._assertion_mutations(context, {"actor_id": actor})

    def _work(self, row, custody, consent, selected):
        profile = self.profile
        work = shared._row(selected, "measured issued work")
        token = consent["reservedEnvelope"] if row["token_envelope_json"] is None else _original(row["token_envelope_json"], "issued envelope")
        status = {"prepared": "reserved", "claimed": "exchange_in_flight", "captured": "held" if row["token_envelope_json"] is not None else "issued_unavailable"}
        deadline = consent["contactExpiresAtEpochNs"] if custody["status"] == "prepared" else consent["retentionExpiresAtEpochNs"]
        profile.require(set(work) == old._WORK_FIELDS and work["id"] == row["id"] and work["provider_id"] == row["provider_id"]
            and work["actor_id"] == row["requester_id"] and work["source"] == profile.WORK_SOURCE
            and type(work["attempts"]) is int and work["attempts"] == 0 and work["created_at"] == row["created_at"]
            and all(work[name] is None for name in ("last_error", "lease_owner", "lease_until"))
            and all(type(work[name]) is type(token[name]) and work[name] == token[name] for name in exchange.ENVELOPE_FIELDS)
            and work["status"] == status.get(custody["status"]) and work["next_attempt_at"] == old._iso(deadline))
        return work

    def _stage(self, context, values, row, consent, payload, association):
        profile = self.profile
        request = values["request"]
        metadata = old._review(request, consent, payload, association)
        family.require_open_from_population(context, metadata["provider_id"], metadata["provider_subject"])
        now, stamp = context.database_now, context.database_now.isoformat()
        for table, key in (("pending_oauth_credentials", {"id": row["id"]}), ("credentials", {"id": row["id"]}),
                ("credential_generations", {"credential_id": row["id"]})):
            profile.require(not context.exact(table, key)["present"])
        for item in context.present_rows("setup_sessions"):
            setup = shared._row(item, "setup population")
            if profile is setup_profile and setup["id"] == consent["setupBinding"]["sessionId"]:
                # The same actual context row was checked against the retained
                # started original before entering this method, then CASed.
                continue
            profile.require(setup.get("oauth_pending_credential_id") != row["id"]
                and setup.get("oauth_state_digest") not in {consent["stateSha256"], consent["stateSha256"][7:]})
        mutations, active, backlog = [], 0, 0
        for item in context.present_rows("pending_oauth_credentials"):
            pending = shared._row(item, "pending population")
            if pending["status"] == "pending" and exchange.timestamp(pending["expires_at"]) <= now:
                pending = {**pending, "status": "expired", "revocation_status": "pending", "revocation_error": None,
                    "revocation_next_attempt_at": stamp, "revocation_lease_owner": None, "revocation_lease_until": None, "updated_at": stamp}
                mutations.append(core.mutation(operation=self.operation, selected=item, row=pending))
            active += pending["status"] == "pending"
            backlog += pending["status"] in {"cancelled", "expired", "rejected"}
        profile.require(active < consent["limits"]["pendingCapacity"] and backlog < consent["limits"]["revocationCapacity"])
        # This is the normalized, separately measured final envelope, not a
        # false equality assertion against the earlier minimal issued capture.
        pending = {"id": row["id"], "requester_id": values["actor_id"], "name": consent["credentialName"], "kind": "oauth2",
            **request["tokenEnvelope"], "metadata": profile.canonical(metadata).decode("ascii"), "payload_digest": request["payloadDigest"],
            "review_json": profile.canonical(request["review"]).decode("ascii"), "target_credential_id": None, "target_credential_version": None,
            "status": "pending", "revocation_status": None, "revocation_error": None, "revocation_attempts": 0,
            "revocation_next_attempt_at": None, "revocation_lease_owner": None, "revocation_lease_until": None,
            "created_at": stamp, "expires_at": old._iso(consent["pendingExpiresAtEpochNs"]), "updated_at": stamp}
        activation.pending_original(pending)
        activate._google_collisions(context, pending, metadata)
        mutations.append(core.mutation(operation=self.operation, selected=context.exact("pending_oauth_credentials", {"id": row["id"]}), row=pending))
        return pending, mutations


KERNELS = MappingProxyType({operation: MeasuredExchangeKernel(operation) for operation in profile.OPERATIONS | setup_profile.OPERATIONS})
