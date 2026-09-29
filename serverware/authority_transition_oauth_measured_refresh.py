"""Measured refresh storage transitions; no provider I/O or plaintext keys.

The actual verifier and planner admit each native proof before these kernels.
Protected ciphertext capture is distinct from replacement admission. Recovery
can process a known retained capture, never reserve another provider contact.
"""
from dataclasses import dataclass
from types import MappingProxyType

from serverware import authority_oauth_measured_refresh as profile
from serverware import authority_oauth_refresh as refresh
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_inventory as inventory
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_provider_retirement as provider_retirement
from serverware import authority_oauth_retirement_succession_current as succession
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_oauth_refresh as common
from serverware import authority_credential_currentness as currentness
from serverware import authority_transition_credential_currentness as currentness_kernel


def _values(operation, arguments):
    return profile.arguments(operation, arguments, typed=True)


def _custody_public(row):
    return {"id": row["id"], "status": row["status"], "rowSha256": profile.sha256(profile.row_original(row)),
        "recoveryRequestDigest": row["recovery_request_digest"], "recoveryExpiresAtEpochNs": row["recovery_expires_at_epoch_ns"]}


def _envelopes_key(request, expected):
    for name in ("reservedIssuedEnvelope", "reservedSupersededEnvelope", "rawResponseEnvelope", "issuedMaterialEnvelope",
            "replacementEnvelope", "supersededEnvelope"):
        if request.get(name) is not None:
            profile.require(request[name]["secret_kek_id"] == expected)


def _heads(context, values, *, historical=False):
    return common._heads(context, values, require_live_enrollment=not historical)


def _retained(context, values, credential, generation, payload, selected, custody_selected):
    row = shared._row(selected, "measured refresh reservation")
    custody = shared._row(custody_selected, "measured refresh custody")
    refresh.row_original(row); profile.row_original(custody)
    request = values["request"]
    item_id = refresh.refresh_id(values["credential_id"], request["expectedVersion"])
    profile.require(row["id"] == custody["id"] == item_id
        and row["credential_id"] == custody["credential_id"] == credential["id"]
        and row["credential_version"] == custody["credential_version"] == request["expectedVersion"]
        and row["provider_id"] == payload["providerId"]
        and row["enrollment_original"] == custody["enrollment_original"] == values["enrollment_original"]
        and row["credential_original_json"].encode("ascii") == refresh.credential_original(credential)
        and row["generation_original_json"].encode("ascii") == refresh.generation_original(generation)
        and row["limits_json"] == profile.canonical(request["limits"]).decode("ascii")
        and row["issued_work_id"] == refresh.artifact_id(item_id, "issued")
        and row["superseded_work_id"] == (refresh.artifact_id(item_id, "superseded") if payload["providerId"] == "x" else None))
    _, root = currentness_kernel.require_root(context, credential["id"], request["expectedVersion"])
    _, barrier, _ = currentness_kernel._barrier(context, root, root["barrier_id"])
    currentness_kernel.require_consumed_refresh_barrier(context, credential["id"], request["expectedVersion"],
        barrier["original_sha256"], claim_request_digest=row["claim_request_digest"])
    return row, custody, barrier


@dataclass(frozen=True, slots=True)
class MeasuredRefreshKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = _values(self.operation, arguments)
        request = values["request"]
        provider = enrollment.enrollment_document(refresh.enrollment_bytes(values["enrollment_original"]))["payload"]["providerId"]
        queries = [shared._query(operation=self.operation, name="credential", table="credentials", key={"id": values["credential_id"]}),
            provider_retirement.query(self.operation, provider),
            shared._query(operation=self.operation, name="generation", table="credential_generations", key={"credential_id": values["credential_id"]})]
        queries.append(succession.query(self.operation, provider))
        if self.operation == profile.OP_INSPECT:
            queries.extend(succession.inspection_queries(self.operation, values["credential_id"]))
        else:
            queries.extend(succession.association_queries(self.operation, values["credential_id"], request["expectedVersion"]))
        if self.operation == profile.OP_INSPECT and request["recoveryVersion"] is not None:
            item_id = refresh.refresh_id(values["credential_id"], request["recoveryVersion"])
            for name, table in (("refresh", refresh.TABLE), ("custody", profile.TABLE)):
                queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": item_id}))
        if self.operation != profile.OP_INSPECT:
            item_id = refresh.refresh_id(values["credential_id"], request["expectedVersion"])
            for name, table in (("refresh", refresh.TABLE), ("custody", profile.TABLE)):
                queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": item_id},
                    require_absence=self.operation == profile.OP_CLAIM))
            queries.extend(currentness_kernel.effect_queries(self.operation, values["credential_id"], request["expectedVersion"],
                next_root=self.operation in {profile.OP_COMMIT, profile.OP_RECOVER}))
            provider = enrollment.enrollment_document(refresh.enrollment_bytes(values["enrollment_original"]))["payload"]["providerId"]
            for purpose in ("issued", "superseded") if provider == "x" else ("issued",):
                queries.append(shared._query(operation=self.operation, name=purpose, table="oauth_revocation_work",
                    key={"id": refresh.artifact_id(item_id, purpose)}, require_absence=self.operation == profile.OP_CLAIM))
        if self.operation == profile.OP_CLAIM:
            for table in inventory.tables_for(self.operation):
                queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table),
                    table=table, predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.maximum_rows(table) + 1,
                    proof_primitive="bounded-limit-plus-one", work_units=inventory.maximum_rows(table) + 1))
        else:
            queries.extend(family.population_queries(self.operation))
        queries.append(shared._audit_query(self.operation, request_digest))
        return family.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        values = _values(self.operation, context.arguments)
        request = values["request"]
        stamp, now = context.database_now.isoformat(), shared._database_epoch_ns(context.database_now)
        statement = values["evidence"]["statement"]
        profile.require(statement["issuedAtEpochNs"] <= now < statement["expiresAtEpochNs"])
        mutations = []
        if self.operation == profile.OP_INSPECT:
            profile.require(request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"])
            if request["recoveryVersion"] is not None:
                succession.require_observation(context, values["enrollment_original"])
                item_id = refresh.refresh_id(values["credential_id"], request["recoveryVersion"])
                row = shared._row(context.exact(refresh.TABLE, {"id": item_id}), "recovery inspection reservation")
                custody = shared._row(context.exact(profile.TABLE, {"id": item_id}), "recovery inspection custody")
                refresh.row_original(row); profile.row_original(custody)
                profile.require(row["id"] == custody["id"] == item_id and row["status"] in {"retained", "committed"}
                    and custody["status"] in {"captured", "committed"} and custody["capture_request_json"] is not None
                    and row["enrollment_original"] == custody["enrollment_original"] == values["enrollment_original"])
                result_payload = {"mode": "recovery", "refreshId": item_id, "credentialVersion": request["recoveryVersion"],
                    "custodyRowSha256": profile.sha256(profile.row_original(custody)),
                    "captureInputSha256": profile.sha256(custody["capture_request_json"].encode("ascii")),
                    "committed": custody["status"] == "committed"}
            else:
                current = shared._row(context.exact("credentials", {"id": values["credential_id"]}), "measured inspection credential")
                effective = {**values, "request": {**request, "expectedVersion": current["credential_version"]}}
                _, credential, _, generation, metadata, application = _heads(context, effective)
                succession.require_current(context, credential, values["enrollment_original"])
                result_payload = {"mode": "refresh", "credentialOriginal": refresh.credential_original(credential).decode("ascii"),
                    "generationOriginal": refresh.generation_original(generation).decode("ascii"),
                    "enrollmentOriginal": values["enrollment_original"], "applicationMaterialSha256": request["applicationMaterialSha256"],
                    "due": metadata["expires_at_epoch_ms"] * 1_000_000 <= now + request["limits"]["dueWithinSeconds"] * 1_000_000_000,
                    "refreshId": refresh.refresh_id(credential["id"], credential["credential_version"])}
        else:
            item_id = refresh.refresh_id(values["credential_id"], request["expectedVersion"])
            selected = context.exact(refresh.TABLE, {"id": item_id})
            custody_selected = context.exact(profile.TABLE, {"id": item_id})
            existing = None if not custody_selected["present"] else shared._row(custody_selected, "measured custody")
            if self.operation == profile.OP_RECOVER and existing is not None and existing["status"] == "committed":
                succession.require_observation(context, values["enrollment_original"])
                result_payload = self._completed(context, values, selected, existing)
            else:
                historical = self.operation == profile.OP_RECOVER or self.operation == profile.OP_COMMIT and request["recoveryRequestDigest"] is not None
                credential_selected, credential, generation_selected, generation, metadata, application = _heads(context, values, historical=historical)
                succession.require_current(context, credential, values["enrollment_original"])
                assignment = values["assignment_original"]
                profile.require(credential["secret_kek_id"] == assignment["secretKekId"])
                _envelopes_key(request, assignment["secretKekId"])
                if self.operation == profile.OP_CLAIM:
                    row, custody, effects = self._claim(context, values, credential, generation, metadata, application, selected, custody_selected)
                    mutations.extend(effects)
                else:
                    row, custody, barrier = _retained(context, values, credential, generation, application, selected, custody_selected)
                    issued_selected, issued = common._work(context, row["issued_work_id"], profile.ISSUED_SOURCE, application["providerId"], row["created_at"])
                    if self.operation == profile.OP_RECOVER:
                        profile.require(custody["status"] == "captured" and row["status"] == "retained"
                            and request["custodyRowSha256"] == profile.sha256(profile.row_original(custody))
                            and request["captureInputSha256"] == profile.sha256(custody["capture_request_json"].encode("ascii"))
                            and custody["recovery_request_digest"] is None
                            and request["issuedAtEpochNs"] <= now < request["expiresAtEpochNs"]
                            and row["raw_response_envelope_json"] is not None)
                        custody = {**custody, "recovery_request_digest": context.request_digest,
                            "recovery_expires_at_epoch_ns": request["expiresAtEpochNs"],
                            "recovery_owner_nonce_sha256": request["ownerNonceSha256"],
                            "recovery_evidence_original_json": profile.canonical(values["evidence"]).decode("ascii"), "updated_at": stamp}
                    else:
                        profile.require(request["refreshRowSha256"] == refresh.row_digest(row))
                        if not historical:
                            profile.require(custody["assignment_original_json"] == profile.canonical(assignment).decode("ascii")
                                and row["issued_at_epoch_ns"] <= now < row["retention_expires_at_epoch_ns"]
                                and row["owner_nonce_sha256"] == profile.sha256(refresh._nonce(request["ownerNonce"]))
                                and custody["recovery_request_digest"] is None)
                        else:
                            recovered = common._json(custody["recovery_evidence_original_json"], "recovery original")["statement"]
                            profile.require(custody["recovery_request_digest"] == request["recoveryRequestDigest"]
                                and now < custody["recovery_expires_at_epoch_ns"]
                                and custody["recovery_owner_nonce_sha256"] == profile.sha256(refresh._nonce(request["ownerNonce"]))
                                and all(statement[name] == recovered[name] for name in ("holderId", "bootId", "keyId", "instanceId", "enrollmentSha256")))
                        if self.operation == profile.OP_CAPTURE:
                            profile.require(row["status"] == "claimed" and custody["status"] == "claimed"
                                and row["raw_response_envelope_json"] is None and custody["capture_request_json"] is None
                                and issued["status"] == "refresh_in_flight"
                                and row["issued_at_epoch_ns"] <= request["receivedAtEpochNs"] <= now)
                            token = request["issuedMaterialEnvelope"]
                            row = {**row, "status": "retained", "received_at_epoch_ns": request["receivedAtEpochNs"],
                                "raw_response_sha256": request["rawResponseSha256"], "raw_response_envelope_json": profile.canonical(request["rawResponseEnvelope"]).decode("ascii"),
                                "issued_material_sha256": request["issuedMaterialSha256"],
                                "issued_material_envelope_json": None if token is None else profile.canonical(token).decode("ascii"), "updated_at": stamp}
                            custody = {**custody, "status": "captured", "capture_request_json": profile.canonical(request).decode("ascii"),
                                "capture_evidence_original_json": profile.canonical(values["evidence"]).decode("ascii"), "updated_at": stamp}
                            mutations.append(core.mutation(operation=self.operation, selected=issued_selected,
                                row={**issued, **({} if token is None else token), "status": "refresh_issued_unavailable" if token is None else "held", "updated_at": stamp}))
                        else:
                            profile.require(self.operation == profile.OP_COMMIT and row["status"] == "retained" and custody["status"] == "captured"
                                and row["raw_response_envelope_json"] is not None and row["issued_material_envelope_json"] is not None
                                and issued["status"] == "held"
                                and all(issued[name] == common._json(row["issued_material_envelope_json"], "issued ciphertext")[name] for name in refresh.ENVELOPE_FIELDS))
                            common._replacement_metadata(metadata, request["replacementMetadata"], row["received_at_epoch_ns"], now)
                            next_row = {**credential, **request["replacementEnvelope"], "metadata": profile.canonical(request["replacementMetadata"]).decode("ascii"), "updated_at": stamp}
                            refresh.credential_original(next_row)
                            mutations.extend(succession.propagate(context, credential, next_row, values["enrollment_original"]))
                            next_selected = context.exact(currentness.ROOT_TABLE, {"id": currentness.root_id(credential["id"], request["expectedVersion"] + 1)})
                            profile.require(not next_selected["present"])
                            mutations.extend((core.mutation(operation=self.operation, selected=credential_selected, row=next_row),
                                core.mutation(operation=self.operation, selected=generation_selected,
                                    row={**generation, "last_version": request["expectedVersion"] + 1, "updated_at": stamp}),
                                core.mutation(operation=self.operation, selected=next_selected,
                                    row=currentness.new_root(credential["id"], request["expectedVersion"] + 1, context.request_digest, stamp, barrier["original_sha256"])),
                                core.delete_mutation(operation=self.operation, selected=issued_selected)))
                            if row["superseded_work_id"] is None:
                                profile.require(request["supersededEnvelope"] is None)
                            else:
                                retired_selected, retired = common._work(context, row["superseded_work_id"], profile.SUPERSEDED_SOURCE, application["providerId"], row["created_at"])
                                profile.require(retired["status"] == "refresh_superseded_reserved")
                                if request["supersededEnvelope"] is None:
                                    mutations.append(core.delete_mutation(operation=self.operation, selected=retired_selected))
                                else:
                                    mutations.append(core.mutation(operation=self.operation, selected=retired_selected,
                                        row={**retired, **request["supersededEnvelope"], "status": "held", "updated_at": stamp}))
                            row = {**row, "status": "committed", "replacement_secret_sha256": request["replacementSecretSha256"],
                                "replacement_credential_sha256": profile.sha256(refresh.credential_original(next_row)),
                                "superseded_material_sha256": request["supersededMaterialSha256"], "updated_at": stamp}
                            custody = {**custody, "status": "committed", "commit_request_json": profile.canonical(request).decode("ascii"),
                                "commit_evidence_original_json": profile.canonical(values["evidence"]).decode("ascii"), "updated_at": stamp}
                refresh.row_original(row); profile.row_original(custody)
                if self.operation != profile.OP_RECOVER:
                    mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
                mutations.append(core.mutation(operation=self.operation, selected=custody_selected, row=custody))
                result_payload = {"refresh": common._public(row), "custody": _custody_public(custody)}
                if self.operation == profile.OP_RECOVER:
                    result_payload.update(status="recovery-admitted", credentialOriginal=row["credential_original_json"],
                        generationOriginal=row["generation_original_json"], claimRequest=common._json(custody["claim_request_json"], "claim"),
                        captureRequest=common._json(custody["capture_request_json"], "capture"))
                elif self.operation == profile.OP_COMMIT:
                    result_payload.update(credentialSha256=row["replacement_credential_sha256"], credentialVersion=request["expectedVersion"] + 1)
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="measured_policy", actor_id=statement["holderId"], event={"schema": "serverware.oauthMeasuredRefreshAudit/v1",
                "operation": self.operation, "requestDigest": context.request_digest, "credentialId": values["credential_id"],
                "nativeEvidenceSha256": profile.sha256(profile.canonical(values["evidence"])), "resultSha256": profile.sha256(profile.canonical(result_payload))})
        profile.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations) + audit, result={"ok": True, "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False, "payload": result_payload}, work_units=2048)

    def _claim(self, context, values, credential, generation, metadata, application, selected, custody_selected):
        request = values["request"]
        now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
        item_id = refresh.refresh_id(credential["id"], request["expectedVersion"])
        issued_id = refresh.artifact_id(item_id, "issued")
        retired_id = refresh.artifact_id(item_id, "superseded") if application["providerId"] == "x" else None
        profile.require(not selected["present"] and not custody_selected["present"] and request["expectedVersion"] < 2**63 - 1
            and len(context.present_rows(refresh.TABLE)) < inventory.MAX_ROWS and len(context.present_rows(profile.TABLE)) < inventory.MAX_ROWS
            and not any(shared._row(item, "refresh population")["credential_id"] == credential["id"]
                and shared._row(item, "refresh population")["status"] != "committed" for item in context.present_rows(refresh.TABLE))
            and len(context.present_rows("oauth_revocation_work")) + (2 if retired_id else 1) <= request["limits"]["revocationCapacity"]
            and profile.sha256(refresh.credential_original(credential)) == request["credentialRowSha256"]
            and profile.sha256(refresh.generation_original(generation)) == request["generationRowSha256"]
            and application["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now < request["contactExpiresAtEpochNs"]
            and request["retentionExpiresAtEpochNs"] <= application["expiresAtEpochNs"]
            and metadata["expires_at_epoch_ms"] * 1_000_000 <= now + request["limits"]["dueWithinSeconds"] * 1_000_000_000
            and (metadata.get("refresh_token_expires_at_epoch_ms") is None or now < metadata["refresh_token_expires_at_epoch_ms"] * 1_000_000)
            and (request["reservedSupersededEnvelope"] is not None) == (retired_id is not None))
        effects = list(currentness_kernel.consume_barrier(context, credential["id"], request["expectedVersion"], request["currentnessBarrierSha256"]))
        row = {name: None for name in refresh.ROW_FIELDS}
        row.update(id=item_id, credential_id=credential["id"], credential_version=request["expectedVersion"], provider_id=application["providerId"],
            enrollment_original=values["enrollment_original"], credential_original_json=refresh.credential_original(credential).decode("ascii"),
            generation_original_json=refresh.generation_original(generation).decode("ascii"), limits_json=profile.canonical(request["limits"]).decode("ascii"),
            claim_request_digest=context.request_digest, owner_nonce_sha256=request["ownerNonceSha256"], status="claimed", contact_request_sha256=request["contactRequestSha256"],
            issued_work_id=issued_id, superseded_work_id=retired_id, issued_at_epoch_ns=request["issuedAtEpochNs"],
            contact_expires_at_epoch_ns=request["contactExpiresAtEpochNs"], retention_expires_at_epoch_ns=request["retentionExpiresAtEpochNs"], created_at=stamp, updated_at=stamp)
        custody = {name: None for name in profile.ROW_FIELDS}
        custody.update(id=item_id, credential_id=credential["id"], credential_version=request["expectedVersion"], enrollment_original=values["enrollment_original"],
            assignment_original_json=profile.canonical(values["assignment_original"]).decode("ascii"),
            claim_evidence_original_json=profile.canonical(values["evidence"]).decode("ascii"), claim_request_json=profile.canonical(request).decode("ascii"),
            status="claimed", created_at=stamp, updated_at=stamp)
        for work_id, source, envelope, status in ((issued_id, profile.ISSUED_SOURCE, request["reservedIssuedEnvelope"], "refresh_in_flight"),
                (retired_id, profile.SUPERSEDED_SOURCE, request["reservedSupersededEnvelope"], "refresh_superseded_reserved")):
            if work_id is not None:
                work_selected = context.exact("oauth_revocation_work", {"id": work_id})
                profile.require(not work_selected["present"])
                effects.append(core.mutation(operation=self.operation, selected=work_selected,
                    row=common._new_work(work_id, application["providerId"], source, envelope, stamp, status)))
        return row, custody, effects

    def _completed(self, context, values, selected, custody):
        row = shared._row(selected, "completed measured refresh")
        refresh.row_original(row); profile.row_original(custody)
        request = values["request"]
        credential = shared._row(context.exact("credentials", {"id": values["credential_id"]}), "completed credential")
        generation = shared._row(context.exact("credential_generations", {"credential_id": values["credential_id"]}), "completed generation")
        profile.require(row["status"] == "committed" and row["id"] == custody["id"] == refresh.refresh_id(values["credential_id"], request["expectedVersion"])
            and row["credential_id"] == custody["credential_id"] == values["credential_id"]
            and row["credential_version"] == custody["credential_version"] == request["expectedVersion"]
            and row["enrollment_original"] == custody["enrollment_original"] == values["enrollment_original"]
            and request["custodyRowSha256"] == profile.sha256(profile.row_original(custody))
            and request["captureInputSha256"] == profile.sha256(custody["capture_request_json"].encode("ascii"))
            and request["issuedAtEpochNs"] <= shared._database_epoch_ns(context.database_now) < request["expiresAtEpochNs"]
            and profile.sha256(refresh.credential_original(credential)) == row["replacement_credential_sha256"]
            and credential["credential_version"] == generation["last_version"] == request["expectedVersion"] + 1
            and generation["credential_id"] == credential["id"] == values["credential_id"])
        return {"status": "observed-complete", "refresh": common._public(row), "custody": _custody_public(custody),
            "credentialSha256": row["replacement_credential_sha256"], "credentialVersion": credential["credential_version"]}


KERNELS = MappingProxyType({operation: MeasuredRefreshKernel(operation) for operation in profile.OPERATIONS})
