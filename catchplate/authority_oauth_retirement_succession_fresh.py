"""One fresh same-account issue and a separately approved new generation.

The caller is the protected succession kernel after its actual complete
material/contact closure. Neither a candidate nor an observed receipt clears
an old fence, restarts a provider contact, or substitutes for this transition.
"""
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as rows
from catchplate import authority_oauth_retirement_succession_lineages as lineages
from catchplate import authority_oauth_retirement_succession_inventory as inventory
from catchplate import authority_oauth_retirement_succession_approvals as approvals
from catchplate import authority_oauth_refresh as refresh
from catchplate import authority_oauth_exchange as exchange
from catchplate import authority_credential_currentness as current
from catchplate import authority_transition_credential_currentness as currentness
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_oauth_activation as approval_public


def _same_native(actual, prepared):
    for name in ("holderId", "bootId", "keyId", "controlPlaneResponseSigningKeyId", "deploymentId", "instanceId", "policyHash",
            "dataPlaneBinarySha256", "enrollmentSha256", "callbackOrigin", "portalOrigin", "ingressLeafCertificateSha256",
            "ingressLeafSpkiSha256", "authorizationSha256", "scopeRowSha256"):
        p.require(actual[name] == prepared[name], "the actual native succession owner changed")
    p.require(actual["materialId"] is None and prepared["materialId"] is None)


def _candidate(values, grant, scope, target, closure, now):
    request = values["request"]; metadata, review = request["metadata"], request["review"]
    before = inventory.metadata(target)
    variable = {"scopes", "expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms", "token_type", "refreshable", "provider_identity_verified"}
    p.require({key: value for key, value in metadata.items() if key not in variable} ==
        {key: value for key, value in before.items() if key not in variable}
        and metadata.get("provider_id") == grant["providerId"] and metadata.get("provider_subject") == grant["providerSubject"]
        and metadata.get("provider_account") == grant["providerAccount"] and metadata.get("scopes") == grant["scopes"]
        and metadata.get("provider_identity_verified") is True and metadata.get("refreshable") is True
        and metadata.get("token_type") == "Bearer" and type(metadata.get("expires_at_epoch_ms")) is int
        and metadata["expires_at_epoch_ms"] * 1_000_000 > now)
    if "refresh_token_expires_at_epoch_ms" in metadata:
        p.require(type(metadata["refresh_token_expires_at_epoch_ms"]) is int and metadata["refresh_token_expires_at_epoch_ms"] * 1_000_000 > now)
    scope_sha = p.sha256(rows.scope_original(scope))
    wanted_review = {"credential_type": "oauth2", "provider": grant["providerId"], "provider_subject": grant["providerSubject"],
        "provider_account": grant["providerAccount"], "scopes": grant["scopes"], "credential_name": target["name"],
        "metadata_keys": sorted(metadata), "expires_at_epoch_ms": metadata["expires_at_epoch_ms"],
        "oauth_application_owner": metadata["oauth_application_owner"], "succession_credential_id": grant["credentialId"],
        "succession_credential_version": grant["credentialVersion"], "succession_scope_sha256": scope_sha,
        "succession_material_closure_sha256": closure}
    if grant["providerId"] == "x":
        wanted_review["x_app_id"] = grant["clientId"]
    p.require(review == wanted_review)
    authorization_sha = p.sha256(p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES))
    wanted = p.sha256(p.canonical({"action": p.ACTION, "authorizationSha256": authorization_sha,
        "review": review, "encrypted_token_source_sha256": request["tokenSecretSha256"]}))
    p.require(request["payloadDigest"] == wanted)
    candidate = {"apiVersion": "catchplate.oauthRetiredScopeSuccessionCandidate/v1", "authorizationSha256": authorization_sha,
        "scopeSha256": scope_sha, "materialClosureSha256": closure, "credentialId": grant["credentialId"],
        "previousVersion": grant["credentialVersion"], "exchangeId": grant["authorizationId"],
        "tokenSecretSha256": request["tokenSecretSha256"], "tokenEnvelope": request["tokenEnvelope"], "metadata": metadata,
        "review": review, "payloadDigest": wanted, "createdAtEpochNs": now, "expiresAtEpochNs": grant["pendingExpiresAtEpochNs"]}
    rows.candidate_original(candidate, grant)
    return candidate


def _native(context, values, grant, scope, journal, target, exchanged, custody, closure):
    operation, request = context.operation, values["request"]
    now, stamp = shared._database_epoch_ns(context.database_now), context.database_now.isoformat()
    selected = context.exact(p.TABLE, {"id": grant["authorizationId"]})
    exchange_selected = context.exact(exchange.TABLE, {"id": grant["authorizationId"]})
    p.require(operation in p.FRESH_OPERATIONS and journal["status"] == "fenced")
    candidate = None
    if operation == p.OP_PREPARE:
        p.require(custody is None and not selected["present"] and not exchange_selected["present"]
            and len(context.present_rows(exchange.TABLE)) < p.MAX_HISTORY
            and lineages.epoch(scope["created_at"]) <= request["issuedAtEpochNs"] <= now < grant["contactExpiresAtEpochNs"]
            and request["metadata"] == inventory.metadata(target) and request["credentialName"] == target["name"])
        for item in context.present_rows(exchange.TABLE):
            prior = shared._row(item, "complete prior exchange original"); exchange.row_original(prior)
            p.require(rows.stored(prior["consent_json"])["stateSha256"] != request["stateSha256"])
        exchanged = {"id": grant["authorizationId"], "provider_id": grant["providerId"], "requester_id": grant["requesterId"],
            "enrollment_original": values["enrollment_original"], "credential_policy_json": journal["credential_policy_json"],
            "consent_json": p.canonical(request).decode("ascii"), "status": "prepared", **{name: None for name in exchange.NULLABLE},
            "created_at": stamp, "updated_at": stamp}
        custody = {name: None for name in rows.CUSTODY_FIELDS}
        custody.update(id=grant["authorizationId"], prepare_request_digest=context.request_digest,
            preparation_arguments_json=p.canonical(values).decode("ascii"), status="prepared", created_at=stamp, updated_at=stamp)
    else:
        p.require(custody is not None and exchanged is not None and custody["recovery_request_digest"] is None)
        preparation = p.arguments(p.OP_PREPARE, rows.stored(custody["preparation_arguments_json"], p.MAX_ARGUMENT_BYTES))
        p.require(preparation["authorization_original"] == values["authorization_original"]
            and preparation["request"] == rows.stored(exchanged["consent_json"])
            and preparation["credential_policy"] == values["credential_policy"]
            and preparation["assignment_original"] == values["assignment_original"]
            and exchanged["enrollment_original"] == values["enrollment_original"]
            and request["exchangeRowSha256"] == exchange.row_digest(exchanged))
        _same_native(values["native_evidence"]["statement"], preparation["native_evidence"]["statement"])
        p.require(now < grant["contactExpiresAtEpochNs" if operation in {p.OP_CLAIM, p.OP_CANCEL} else "retentionExpiresAtEpochNs"])
        if operation in {p.OP_CAPTURE, p.OP_STAGE}:
            p.require(p.sha256(p.decoded(request["ownerNonce"], 32, 32)) == custody["owner_nonce_sha256"])
        if operation == p.OP_CLAIM:
            p.require(custody["status"] == exchanged["status"] == "prepared" and all(exchanged[name] is None for name in exchange.NULLABLE))
            exchanged = {**exchanged, "status": "claimed", "claim_request_digest": context.request_digest,
                "code_sha256": request["codeSha256"], "contact_request_sha256": request["contactRequestSha256"], "updated_at": stamp}
            custody = {**custody, "status": "claimed", "claim_arguments_json": p.canonical(values).decode("ascii"),
                "owner_nonce_sha256": request["ownerNonceSha256"], "updated_at": stamp}
        elif operation == p.OP_CANCEL:
            p.require(custody["status"] == exchanged["status"] == "prepared" and all(exchanged[name] is None for name in exchange.NULLABLE))
            custody = {**custody, "status": "cancelled", "cancel_arguments_json": p.canonical(values).decode("ascii"), "updated_at": stamp}
        elif operation == p.OP_CAPTURE:
            p.require(custody["status"] == exchanged["status"] == "claimed" and custody["capture_arguments_json"] is None
                and preparation["request"]["issuedAtEpochNs"] <= request["receivedAtEpochNs"] <= now
                and request["receivedAtEpochNs"] < grant["contactExpiresAtEpochNs"])
            exchanged = {**exchanged, "status": "retained", "raw_response_sha256": request["rawResponseSha256"],
                "raw_response_envelope_json": p.canonical(request["rawResponseEnvelope"]).decode("ascii"),
                "token_secret_sha256": request["issuedMaterialSha256"],
                "token_envelope_json": None if request["issuedMaterialEnvelope"] is None else p.canonical(request["issuedMaterialEnvelope"]).decode("ascii"),
                "updated_at": stamp}
            custody = {**custody, "status": "captured", "capture_arguments_json": p.canonical(values).decode("ascii"),
                "received_at_epoch_ns": request["receivedAtEpochNs"], "updated_at": stamp}
        else:
            p.require(operation == p.OP_STAGE and request["recoveryRequestDigest"] is None
                and custody["status"] == "captured" and exchanged["status"] == "retained"
                and exchanged["token_envelope_json"] is not None and exchanged["raw_response_envelope_json"] is not None
                and now < grant["pendingExpiresAtEpochNs"])
            candidate = _candidate(values, grant, scope, target, closure, now)
            exchanged = {**exchanged, "status": "staged", "updated_at": stamp}
            custody = {**custody, "status": "staged", "stage_arguments_json": p.canonical(values).decode("ascii"),
                "candidate_original_json": rows.candidate_original(candidate, grant).decode("ascii"), "updated_at": stamp}
    exchange.row_original(exchanged); rows.custody_original(custody)
    return exchanged, custody, candidate, (core.mutation(operation=operation, selected=exchange_selected, row=exchanged),
        core.mutation(operation=operation, selected=selected, row=custody))


def _association(context, grant, scope, credential, target, predecessor):
    selected = context.exact(p.ASSOCIATION_TABLE, {"id": p.association_id(target["id"], target["credential_version"])})
    previous_sha = None
    if selected["present"]:
        previous = shared._row(selected, "actual previous successor association"); rows.association_original(previous)
        p.require(scope["previous_head_json"] is not None)
        head = rows.stored(scope["previous_head_json"], 8192); rows.head_original(head)
        _, root = currentness.require_root(context, target["id"], target["credential_version"])
        p.require(previous["credential_id"] == target["id"] and previous["credential_version"] == target["credential_version"]
            and previous["scope_id"] == head["scope_id"] and previous["scope_sha256"] == head["scope_sha256"]
            and previous["provider_id"] == grant["providerId"] and previous["provider_subject"] == grant["providerSubject"]
            and previous["enrollment_sha256"] == grant["enrollmentSha256"] and previous["root_origin_request_digest"] == root["origin_request_digest"])
        previous_sha = p.sha256(rows.association_original(previous))
    row = {"id": p.association_id(target["id"], target["credential_version"] + 1), "credential_id": target["id"],
        "credential_version": target["credential_version"] + 1, "scope_id": scope["id"], "scope_sha256": p.sha256(rows.scope_original(scope)),
        "provider_id": grant["providerId"], "provider_subject": grant["providerSubject"], "enrollment_sha256": grant["enrollmentSha256"],
        "credential_sha256": p.sha256(refresh.credential_original(credential)), "root_origin_request_digest": context.request_digest,
        "previous_association_sha256": previous_sha, "created_at": context.database_now.isoformat()}
    rows.association_original(row); p.digest(predecessor)
    return row


def transition(context, values, grant, scope, journal, target, exchanged, custody, closure):
    operation = context.operation; p.digest(closure)
    if operation in p.FRESH_OPERATIONS:
        exchanged, custody, candidate, effects = _native(context, values, grant, scope, journal, target, exchanged, custody, closure)
        return exchanged, custody, candidate, None, effects, {}
    now = shared._database_epoch_ns(context.database_now); stamp = context.database_now.isoformat()
    p.require(operation in {p.OP_REQUEST, p.OP_DECIDE, p.OP_ACTIVATE} and journal["status"] == "fenced"
        and custody is not None and custody["status"] == "staged" and exchanged is not None and exchanged["status"] == "staged"
        and now < grant["pendingExpiresAtEpochNs"])
    candidate = rows.stored(custody["candidate_original_json"], p.MAX_CANDIDATE_BYTES)
    raw_candidate = rows.candidate_original(candidate, grant)
    p.require(raw_candidate.decode("ascii") == custody["candidate_original_json"]
        and values["request"]["candidateSha256"] == p.sha256(raw_candidate)
        and candidate["authorizationSha256"] == journal["authorization_sha256"]
        and candidate["scopeSha256"] == p.sha256(rows.scope_original(scope)) and candidate["materialClosureSha256"] == closure)
    staged = p.arguments(p.OP_STAGE, rows.stored(custody["stage_arguments_json"], p.MAX_ARGUMENT_BYTES))
    p.require(rows.candidate_original(_candidate(staged, grant, scope, target, closure, candidate["createdAtEpochNs"]), grant) == raw_candidate)
    approval, _, effects = approvals.transition(context, values, grant, journal=journal)
    association = None
    if operation == p.OP_ACTIVATE:
        p.require(candidate["metadata"]["expires_at_epoch_ms"] * 1_000_000 > now)
        if "refresh_token_expires_at_epoch_ms" in candidate["metadata"]:
            p.require(candidate["metadata"]["refresh_token_expires_at_epoch_ms"] * 1_000_000 > now)
        target_selected = context.exact("credentials", {"id": target["id"]})
        head_selected = context.exact("credential_generations", {"credential_id": target["id"]})
        head = shared._row(head_selected, "actual still-fenced predecessor generation")
        p.require(head["last_version"] == target["credential_version"] < 2**63 - 1)
        next_selected = context.exact(current.ROOT_TABLE, {"id": current.root_id(target["id"], target["credential_version"] + 1)})
        association_selected = context.exact(p.ASSOCIATION_TABLE, {"id": p.association_id(target["id"], target["credential_version"] + 1)})
        p.require(not next_selected["present"] and not association_selected["present"])
        credential = {**target, **candidate["tokenEnvelope"], "metadata": p.canonical(candidate["metadata"]).decode("ascii"),
            "lifecycle_status": "active", "revocation_error": None, "revocation_requested_at": None, "updated_at": stamp}
        refresh.credential_original(credential)
        predecessor = next(item["barrierSha256"] for item in rows.array(scope["currentness_barriers_json"], 65536)
            if item["credentialId"] == target["id"])
        association = _association(context, grant, scope, credential, target, predecessor)
        effects.extend((core.mutation(operation=operation, selected=target_selected, row=credential),
            core.mutation(operation=operation, selected=head_selected, row={**head, "last_version": head["last_version"] + 1, "updated_at": stamp}),
            core.mutation(operation=operation, selected=next_selected,
                row=current.new_root(target["id"], target["credential_version"] + 1, context.request_digest, stamp, predecessor)),
            core.mutation(operation=operation, selected=association_selected, row=association)))
        custody = {**custody, "status": "committed", "commit_request_digest": context.request_digest,
            "committed_credential_json": refresh.credential_original(credential).decode("ascii"),
            "predecessor_original_json": refresh.credential_original(target).decode("ascii"), "updated_at": stamp}
        rows.custody_original(custody)
        effects.append(core.mutation(operation=operation, selected=context.exact(p.TABLE, {"id": grant["authorizationId"]}), row=custody))
    return exchanged, custody, candidate, association, tuple(effects), {"approval": approval_public._public(approval)}
