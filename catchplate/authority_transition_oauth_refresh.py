"""Due-only refresh claim, issued-original retention and atomic generation commit.

Pure metadata kernels never call a provider, decrypt a token, revoke a grant,
renew an existing lease authorization or accept a provider-success Boolean.
"""
from dataclasses import dataclass
from types import MappingProxyType

from catchplate import authority_oauth_activation_policy as enrollment
from catchplate import authority_oauth_inventory as inventory
from catchplate import authority_oauth_refresh as profile
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_credential_currentness as currentness
from catchplate import authority_transition_credential_currentness as currentness_kernel
from catchplate import authority_oauth_family_retirement as family_retirement
from catchplate import authority_oauth_provider_retirement as provider_retirement
from catchplate import authority_oauth_retirement_succession_current as succession

_HANDLERS = {name: "catchplate_policy_authority_" + name.replace(".", "_") for name in profile.OPERATIONS}
_MUTABLE_METADATA = frozenset({"refreshable", "token_type", "scopes", "expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms"})


def _values(operation, arguments):
    try:
        return profile.arguments(operation, arguments, typed=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise core.TransitionKernelError("OAuth refresh originals are not exact") from exc


def _json(value, label):
    return shared._canonical_stored_mapping(value, label)


def _public(row):
    return {"id": row["id"], "credentialId": row["credential_id"], "expectedVersion": row["credential_version"],
        "status": row["status"], "rowSha256": profile.row_digest(row),
        "contactExpiresAtEpochNs": row["contact_expires_at_epoch_ns"], "retentionExpiresAtEpochNs": row["retention_expires_at_epoch_ns"]}


def _heads(context, values, *, require_live_enrollment=True):
    credential_selected = context.exact("credentials", {"id": values["credential_id"]})
    generation_selected = context.exact("credential_generations", {"credential_id": values["credential_id"]})
    credential = shared._row(credential_selected, "current OAuth credential")
    generation = shared._row(generation_selected, "current OAuth generation")
    profile.credential_original(credential)
    profile.generation_original(generation)
    version = values["request"]["expectedVersion"]
    if (credential["id"] != values["credential_id"] or credential["credential_version"] != version
            or generation["credential_id"] != credential["id"] or generation["last_version"] != version
            or credential["kind"] != "oauth2" or credential["lifecycle_status"] != "active"
            or credential["revocation_error"] is not None or credential["revocation_requested_at"] is not None):
        raise core.TransitionKernelError("OAuth refresh current credential/generation is fenced or changed")
    profile.envelope({name: credential[name] for name in profile.ENVELOPE_FIELDS}, version)
    raw = profile.enrollment_bytes(values["enrollment_original"])
    payload = enrollment.enrollment_document(raw)["payload"]
    now = shared._database_epoch_ns(context.database_now)
    if require_live_enrollment and not payload["issuedAtEpochNs"] <= now < payload["expiresAtEpochNs"]:
        raise core.TransitionKernelError("OAuth refresh original application interval expired")
    metadata = _json(credential["metadata"], "current OAuth metadata")
    if (metadata.get("oauth") is not True or metadata.get("provider_identity_verified") is not True
            or metadata.get("provider_id") != payload["providerId"] or metadata.get("refreshable") is not True
            or profile.canonical(metadata.get("oauth_application_owner")) != profile.canonical(enrollment.association(raw))
            or metadata.get("token_type") != "Bearer"):
        raise core.TransitionKernelError("OAuth refresh original application/account binding differs")
    for name in ("provider_subject", "provider_account"):
        profile.text(metadata.get(name), 512)
    scopes = metadata.get("scopes")
    if (type(scopes) is not list or not 1 <= len(scopes) <= 128 or any(type(item) is not str for item in scopes)
            or len(set(scopes)) != len(scopes)):
        raise core.TransitionKernelError("OAuth refresh original scopes are not exact")
    for scope in scopes:
        profile.text(scope, 1024)
    for name in ("setup_session_id", "setupSessionId", "reconnect", "reconnect_credential_id", "reconnect_credential_version"):
        if name in metadata:
            raise core.TransitionKernelError("OAuth setup/reconnect needs its own complete controlled transition")
    if payload["providerId"] == "google" and metadata.get("oauth_client_id") != payload["clientId"]:
        raise core.TransitionKernelError("Google OAuth original client differs")
    if payload["providerId"] == "x":
        profile.text(metadata.get("x_app_id"), 512)
    expiry = metadata.get("expires_at_epoch_ms")
    refresh_expiry = metadata.get("refresh_token_expires_at_epoch_ms")
    if (type(expiry) is not int or not 1 <= expiry <= (2**63 - 1) // 1_000_000
            or refresh_expiry is not None and (type(refresh_expiry) is not int
                or not 1 <= refresh_expiry <= (2**63 - 1) // 1_000_000)):
        raise core.TransitionKernelError("OAuth refresh original expiry is invalid")
    return credential_selected, credential, generation_selected, generation, metadata, payload


def _new_work(item_id, provider, source, envelope, now, status):
    return {"id": item_id, "provider_id": provider, "actor_id": "oauth-refresh", "source": source, **envelope,
        "status": status, "attempts": 0, "last_error": None, "next_attempt_at": now,
        "lease_owner": None, "lease_until": None, "created_at": now, "updated_at": now}


def _work(context, item_id, source, provider, created):
    selected = context.exact("oauth_revocation_work", {"id": item_id})
    row = shared._row(selected, "refresh retained work")
    if (row["id"] != item_id or row["source"] != source or row["provider_id"] != provider
            or row["actor_id"] != "oauth-refresh" or row["created_at"] != created or row["attempts"] != 0
            or any(row[name] is not None for name in ("last_error", "lease_owner", "lease_until"))):
        raise core.TransitionKernelError("OAuth refresh retention reservation changed")
    profile.envelope({name: row[name] for name in profile.ENVELOPE_FIELDS}, 1)
    return selected, row


def _replacement_metadata(old, new, received_ns, now_ns):
    if (profile.canonical({key: value for key, value in old.items() if key not in _MUTABLE_METADATA})
            != profile.canonical({key: value for key, value in new.items() if key not in _MUTABLE_METADATA})
            or new.get("refreshable") is not True or new.get("token_type") != "Bearer"
            or new.get("scopes") != sorted(old["scopes"])):
        raise core.TransitionKernelError("OAuth refresh changed immutable identity, application or scopes")
    expiry = new.get("expires_at_epoch_ms")
    maximum = received_ns // 1_000_000 + profile.MAX_TOKEN_LIFETIME_SECONDS * 1000
    if type(expiry) is not int or not now_ns // 1_000_000 < expiry <= maximum:
        raise core.TransitionKernelError("OAuth replacement lifetime exceeds its retained response origin")
    if "refresh_token_expires_at_epoch_ms" in old and "refresh_token_expires_at_epoch_ms" not in new:
        raise core.TransitionKernelError("OAuth refresh cannot discard original refresh-token expiry")
    if "refresh_token_expires_at_epoch_ms" in new:
        refresh = new["refresh_token_expires_at_epoch_ms"]
        if type(refresh) is not int or not now_ns // 1_000_000 < refresh <= maximum:
            raise core.TransitionKernelError("OAuth replacement refresh-token lifetime is invalid")


@dataclass(frozen=True, slots=True)
class OAuthRefreshKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return _HANDLERS[self.operation]

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        values = _values(self.operation, arguments)
        item_id = profile.refresh_id(values["credential_id"], values["request"]["expectedVersion"])
        payload = enrollment.enrollment_document(profile.enrollment_bytes(values["enrollment_original"]))["payload"]
        queries = [shared._query(operation=self.operation, name="credential", table="credentials", key={"id": values["credential_id"]}),
            provider_retirement.query(self.operation, payload["providerId"]),
            shared._query(operation=self.operation, name="generation", table="credential_generations", key={"credential_id": values["credential_id"]}),
            shared._query(operation=self.operation, name="refresh", table=profile.TABLE, key={"id": item_id}, require_absence=self.operation == profile.OP_CLAIM)]
        queries.extend(currentness_kernel.effect_queries(self.operation, values["credential_id"], values["request"]["expectedVersion"],
            next_root=self.operation == profile.OP_COMMIT))
        queries.append(succession.query(self.operation, payload["providerId"]))
        queries.extend(succession.association_queries(self.operation, values["credential_id"], values["request"]["expectedVersion"]))
        for purpose in ("issued", "superseded") if payload["providerId"] == "x" else ("issued",):
            queries.append(shared._query(operation=self.operation, name=purpose, table="oauth_revocation_work",
                key={"id": profile.artifact_id(item_id, purpose)}, require_absence=self.operation == profile.OP_CLAIM))
        if self.operation == profile.OP_CLAIM:
            queries.extend(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table), table=table,
                predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.maximum_rows(table) + 1,
                proof_primitive="bounded-limit-plus-one", work_units=inventory.maximum_rows(table) + 1, page_size=inventory.maximum_rows(table)) for table in inventory.tables_for(self.operation))
        else:
            queries.extend(family_retirement.population_queries(self.operation))
        queries.append(shared._audit_query(self.operation, request_digest))
        return family_retirement.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        values = _values(self.operation, context.arguments)
        request = values["request"]
        now_s, now_ns = context.database_now.isoformat(), shared._database_epoch_ns(context.database_now)
        credential_selected, credential, generation_selected, generation, metadata, payload = _heads(context, values)
        succession.require_current(context, credential, values["enrollment_original"])
        item_id = profile.refresh_id(credential["id"], request["expectedVersion"])
        selected = context.exact(profile.TABLE, {"id": item_id})
        issued_id = profile.artifact_id(item_id, "issued")
        superseded_id = profile.artifact_id(item_id, "superseded") if payload["providerId"] == "x" else None
        mutations = []
        if self.operation == profile.OP_CLAIM:
            mutations.extend(currentness_kernel.consume_barrier(context, credential["id"], request["expectedVersion"], request["currentnessBarrierSha256"]))
            population = context.present_rows(profile.TABLE)
            if (selected["present"] or len(population) >= inventory.MAX_ROWS
                    or any(shared._row(item, "refresh population")["credential_id"] == credential["id"]
                        and shared._row(item, "refresh population")["status"] != "committed" for item in population)
                    or len(context.present_rows("oauth_revocation_work")) + (2 if superseded_id else 1) > request["limits"]["revocationCapacity"]
                    or profile.sha256(profile.credential_original(credential)) != request["credentialRowSha256"]
                    or profile.sha256(profile.generation_original(generation)) != request["generationRowSha256"]
                    or not payload["issuedAtEpochNs"] <= request["issuedAtEpochNs"] <= now_ns < request["contactExpiresAtEpochNs"]
                    or request["retentionExpiresAtEpochNs"] > payload["expiresAtEpochNs"]
                    or metadata["expires_at_epoch_ms"] * 1_000_000 > now_ns + request["limits"]["dueWithinSeconds"] * 1_000_000_000
                    or metadata.get("refresh_token_expires_at_epoch_ms") is not None and metadata["refresh_token_expires_at_epoch_ms"] * 1_000_000 <= now_ns
                    or (request["reservedSupersededEnvelope"] is not None) != (superseded_id is not None)):
                raise core.TransitionKernelError("OAuth refresh is not due, unchanged, unfenced and fully capacity-reserved")
            row = {name: None for name in profile.ROW_FIELDS}
            row.update(id=item_id, credential_id=credential["id"], credential_version=request["expectedVersion"], provider_id=payload["providerId"],
                enrollment_original=values["enrollment_original"], credential_original_json=profile.credential_original(credential).decode("ascii"),
                generation_original_json=profile.generation_original(generation).decode("ascii"), limits_json=profile.canonical(request["limits"]).decode("ascii"),
                claim_request_digest=context.request_digest, owner_nonce_sha256=request["ownerNonceSha256"], status="claimed",
                contact_request_sha256=request["contactRequestSha256"], issued_work_id=issued_id, superseded_work_id=superseded_id,
                issued_at_epoch_ns=request["issuedAtEpochNs"], contact_expires_at_epoch_ns=request["contactExpiresAtEpochNs"],
                retention_expires_at_epoch_ns=request["retentionExpiresAtEpochNs"], created_at=now_s, updated_at=now_s)
            for work_id, source, envelope, status in ((issued_id, profile.ISSUED_SOURCE, request["reservedIssuedEnvelope"], "refresh_in_flight"),
                    (superseded_id, profile.SUPERSEDED_SOURCE, request["reservedSupersededEnvelope"], "refresh_superseded_reserved")):
                if work_id is not None:
                    work_selected = context.exact("oauth_revocation_work", {"id": work_id})
                    if work_selected["present"]:
                        raise core.TransitionKernelError("OAuth refresh reservation identity was already consumed")
                    mutations.append(core.mutation(operation=self.operation, selected=work_selected,
                        row=_new_work(work_id, payload["providerId"], source, envelope, now_s, status)))
        else:
            row = shared._row(selected, "refresh original")
            profile.row_original(row)
            _, original_root = currentness_kernel.require_root(context, credential["id"], request["expectedVersion"])
            _, original_barrier, _ = currentness_kernel._barrier(context, original_root, original_root["barrier_id"])
            currentness_kernel.require_consumed_refresh_barrier(context, credential["id"], request["expectedVersion"],
                original_barrier["original_sha256"], claim_request_digest=row["claim_request_digest"])
            if (profile.row_digest(row) != request["refreshRowSha256"] or row["credential_id"] != credential["id"]
                    or row["credential_version"] != request["expectedVersion"] or row["provider_id"] != payload["providerId"]
                    or row["enrollment_original"] != values["enrollment_original"] or row["limits_json"] != profile.canonical(request["limits"]).decode("ascii")
                    or row["credential_original_json"].encode("ascii") != profile.credential_original(credential)
                    or row["generation_original_json"].encode("ascii") != profile.generation_original(generation)
                    or row["owner_nonce_sha256"] != profile.sha256(profile._nonce(request["ownerNonce"]))
                    or row["issued_work_id"] != issued_id or row["superseded_work_id"] != superseded_id
                    or not row["issued_at_epoch_ns"] <= now_ns < row["retention_expires_at_epoch_ns"]):
                raise core.TransitionKernelError("OAuth refresh original owner, heads, policy or lifetime changed")
            issued_selected, issued = _work(context, issued_id, profile.ISSUED_SOURCE, payload["providerId"], row["created_at"])
            if self.operation == profile.OP_RETAIN:
                if (row["status"] != "claimed" or row["raw_response_envelope_json"] is not None or issued["status"] != "refresh_in_flight"
                        or not row["issued_at_epoch_ns"] <= request["receivedAtEpochNs"] <= now_ns):
                    raise core.TransitionKernelError("OAuth refresh original response was already retained or outside its window")
                token = request["issuedMaterialEnvelope"]
                row = {**row, "status": "retained", "received_at_epoch_ns": request["receivedAtEpochNs"],
                    "raw_response_sha256": request["rawResponseSha256"], "raw_response_envelope_json": profile.canonical(request["rawResponseEnvelope"]).decode("ascii"),
                    "issued_material_sha256": request["issuedMaterialSha256"],
                    "issued_material_envelope_json": None if token is None else profile.canonical(token).decode("ascii"), "updated_at": now_s}
                issued = {**issued, **({} if token is None else token), "status": "refresh_issued_unavailable" if token is None else "held", "updated_at": now_s}
                mutations.append(core.mutation(operation=self.operation, selected=issued_selected, row=issued))
            else:
                if (row["status"] != "retained" or row["raw_response_envelope_json"] is None or row["issued_material_envelope_json"] is None
                        or issued["status"] != "held" or any(issued[name] != _json(row["issued_material_envelope_json"], "issued material")[name] for name in profile.ENVELOPE_FIELDS)
                        or superseded_id is None and request["supersededEnvelope"] is not None):
                    raise core.TransitionKernelError("OAuth refresh commit lacks its exact issued original or source-specific retirement")
                _replacement_metadata(metadata, request["replacementMetadata"], row["received_at_epoch_ns"], now_ns)
                next_row = {**credential, **request["replacementEnvelope"], "metadata": profile.canonical(request["replacementMetadata"]).decode("ascii"), "updated_at": now_s}
                profile.credential_original(next_row)
                mutations.extend(succession.propagate(context, credential, next_row, values["enrollment_original"]))
                next_root_selected = context.exact(currentness.ROOT_TABLE, {"id": currentness.root_id(credential["id"], request["expectedVersion"] + 1)})
                profile.require(next_root_selected["present"] is False)
                mutations.extend((core.mutation(operation=self.operation, selected=credential_selected, row=next_row),
                    core.mutation(operation=self.operation, selected=generation_selected,
                        row={**generation, "last_version": request["expectedVersion"] + 1, "updated_at": now_s}),
                    core.mutation(operation=self.operation, selected=next_root_selected,
                        row=currentness.new_root(credential["id"], request["expectedVersion"] + 1, context.request_digest,
                            now_s, original_barrier["original_sha256"])),
                    core.delete_mutation(operation=self.operation, selected=issued_selected)))
                if superseded_id is not None:
                    superseded_selected, superseded = _work(context, superseded_id, profile.SUPERSEDED_SOURCE, payload["providerId"], row["created_at"])
                    if superseded["status"] != "refresh_superseded_reserved":
                        raise core.TransitionKernelError("OAuth refresh superseded reservation changed")
                    if request["supersededEnvelope"] is None:
                        mutations.append(core.delete_mutation(operation=self.operation, selected=superseded_selected))
                    else:
                        mutations.append(core.mutation(operation=self.operation, selected=superseded_selected,
                            row={**superseded, **request["supersededEnvelope"], "status": "held", "updated_at": now_s}))
                row = {**row, "status": "committed", "replacement_secret_sha256": request["replacementSecretSha256"],
                    "replacement_credential_sha256": profile.sha256(profile.credential_original(next_row)),
                    "superseded_material_sha256": request["supersededMaterialSha256"], "updated_at": now_s}
        profile.row_original(row)
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=self.operation,
            actor_type="automatic_policy", actor_id="oauth-refresh", event={"schema": "catchplate.oauthRefreshAudit/v1",
                "operation": self.operation, "requestDigest": context.request_digest, "refresh": _public(row),
                "claimRequestDigest": row["claim_request_digest"], "enrollmentSha256": profile.sha256(profile.enrollment_bytes(values["enrollment_original"]))})
        if replay:
            raise core.TransitionKernelError("OAuth refresh audit identity was already used")
        result = {"ok": True, "refresh": _public(row), "operation": self.operation, "requestDigest": context.request_digest,
            "auditEventDigest": audit_digest, "idempotentReplay": False}
        if self.operation == profile.OP_COMMIT:
            result["credential"] = {name: (request["replacementMetadata"] if name == "metadata" else value) for name, value in next_row.items()
                if name not in {"encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext"}}
        return core.KernelTransition(mutations=tuple(mutations) + audit, result=result, work_units=1024)


KERNELS = MappingProxyType({operation: OAuthRefreshKernel(operation) for operation in profile.OPERATIONS})
