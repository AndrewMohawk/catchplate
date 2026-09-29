"""One-shot enrolled consent, contact claim, original retention and staging.

Pure metadata transitions: no provider call, decryption, retry, cleanup success
or provider-authorship assertion. Complete populations are authenticated by the
real planner; the executor revalidates the same roots under its writer fence.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from serverware import authority_oauth_activation as activation
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_exchange as profile
from serverware import authority_oauth_inventory as inventory
from serverware import authority_oauth_family_retirement as family
from serverware import authority_oauth_provider_retirement as provider_retirement
from serverware import authority_oauth_retirement_succession_current as succession
from serverware import authority_transition_core as core
from serverware import authority_transition_oauth_activation as activation_kernel
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion

_WORK_SOURCE = "enrolled-oauth-exchange/v1"
_WORK_FIELDS = frozenset({"id", "provider_id", "actor_id", "source", "encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at", "status", "attempts", "last_error", "next_attempt_at", "lease_owner", "lease_until", "created_at", "updated_at"})
_HANDLERS = {profile.OP_PREPARE: "serverware_policy_authority_oauth_exchange_prepare",
    profile.OP_CLAIM: "serverware_policy_authority_oauth_exchange_claim",
    profile.OP_RETAIN: "serverware_policy_authority_oauth_exchange_retain",
    profile.OP_STAGE: "serverware_policy_authority_oauth_pending_stage"}


def _values(operation, arguments):
    try:
        return profile.arguments(operation, arguments, typed=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise core.TransitionKernelError("OAuth exchange arguments are not closed") from exc


def _json(value, label):
    return shared._canonical_stored_mapping(value, label)


def _iso(epoch_ns):
    # SQL timestamps retain exact original microseconds without floating-point
    # conversion; discarding the final ns can only shorten the original window.
    seconds, remainder = divmod(epoch_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=remainder // 1000).isoformat()


def _public(row):
    consent = _json(row["consent_json"], "OAuth consent original")
    return {"id": row["id"], "status": row["status"], "rowSha256": profile.row_digest(row),
        **{name: consent[name] for name in ("contactExpiresAtEpochNs", "retentionExpiresAtEpochNs", "pendingExpiresAtEpochNs")}}


def _pending_public(row):
    names = ("id", "requester_id", "name", "kind", "payload_digest", "target_credential_id", "target_credential_version",
        "status", "revocation_status", "revocation_error", "revocation_attempts", "revocation_next_attempt_at", "created_at", "expires_at", "updated_at")
    return {**{name: row[name] for name in names}, "review": _json(row["review_json"], "OAuth pending review")}


def _enrollment(values, now_ns):
    raw = profile.enrollment_bytes(values["enrollment_original"])
    payload = enrollment.enrollment_document(raw)["payload"]
    if not payload["issuedAtEpochNs"] <= now_ns < payload["expiresAtEpochNs"]:
        raise core.TransitionKernelError("OAuth enrollment interval is no longer current")
    # The verifier and planner independently verified this original signature
    # with their actual measured, separately provisioned enrollment root.
    return payload, enrollment.association(raw)


def _work(context, row, consent):
    selected = context.exact("oauth_revocation_work", {"id": row["id"]})
    work = shared._row(selected, "OAuth retained revocation work")
    if (set(work) != _WORK_FIELDS or work["id"] != row["id"] or work["provider_id"] != row["provider_id"]
            or work["actor_id"] != row["requester_id"] or work["source"] != _WORK_SOURCE
            or work["credential_version"] != 1 or type(work["credential_version"]) is not int
            or work["attempts"] != 0 or type(work["attempts"]) is not int
            or any(work[name] is not None for name in ("last_error", "lease_owner", "lease_until"))
            or work["created_at"] != row["created_at"]):
        raise core.TransitionKernelError("OAuth exchange work association changed")
    expected = consent["reservedEnvelope"] if row["token_envelope_json"] is None else _json(row["token_envelope_json"], "OAuth retained token envelope")
    if any(work[name] != expected[name] or type(work[name]) is not type(expected[name]) for name in profile.ENVELOPE_FIELDS):
        raise core.TransitionKernelError("OAuth retained work ciphertext differs from the exact original")
    statuses = {"prepared": "reserved", "claimed": "exchange_in_flight", "retained": "held" if row["token_envelope_json"] is not None else "issuance_uncertain_unreported"}
    deadline = consent["contactExpiresAtEpochNs"] if row["status"] == "prepared" else consent["retentionExpiresAtEpochNs"]
    if work["status"] != statuses.get(row["status"]) or work["next_attempt_at"] != _iso(deadline):
        raise core.TransitionKernelError("OAuth work stage or original expiry differs")
    return selected, work


def _retained(context, values, payload, association, now_ns):
    request = values["request"]
    selected = context.exact(profile.TABLE, {"id": values["resource_id"]})
    row = shared._row(selected, "OAuth exchange original")
    if (profile.row_digest(row) != request["exchangeRowSha256"] or row["id"] != request["exchangeId"]
            or row["requester_id"] != values["actor_id"] or row["provider_id"] != payload["providerId"]
            or row["enrollment_original"] != values["enrollment_original"]
            or row["credential_policy_json"] != profile.canonical(values["credential_policy"]).decode("ascii")):
        raise core.TransitionKernelError("OAuth callback does not match its retained consent original")
    consent = profile.request_binding(profile.OP_PREPARE, _json(row["consent_json"], "OAuth consent original"))
    if (consent["exchangeId"] != row["id"] or consent["enrollmentSha256"] != association["enrollmentSha256"]
            or consent["providerId"] != payload["providerId"] or consent["redirectUri"] != payload["redirectUri"]
            or consent["pendingExpiresAtEpochNs"] > payload["expiresAtEpochNs"]
            or consent["issuedAtEpochNs"] < payload["issuedAtEpochNs"]
            or request["limits"] != consent["limits"]
            or consent["metadata"].get("oauth_application_owner") != association
            or not request["state"].startswith(row["id"].replace("-", "") + "_")
            or not hmac.compare_digest(profile.sha256(request["state"].encode("ascii")), consent["stateSha256"])
            or not hmac.compare_digest(profile.sha256(request["browserNonce"].encode("ascii")), consent["browserNonceSha256"])):
        raise core.TransitionKernelError("OAuth callback possession or original application binding differs")
    end = consent["contactExpiresAtEpochNs"] if context.operation == profile.OP_CLAIM else consent["retentionExpiresAtEpochNs"]
    if not consent["issuedAtEpochNs"] <= now_ns < end:
        raise core.TransitionKernelError("OAuth original contact or retention window expired")
    return selected, row, consent


def _review(request, consent, payload, association):
    metadata, review = request["metadata"], request["review"]
    required = {"credential_type", "provider", "provider_subject", "provider_account", "scopes", "credential_name", "metadata_keys", "expires_at_epoch_ms", "oauth_application_owner"}
    optional = {"x_app_id", "reconnect_credential_id", "reconnect_credential_version"}
    if (not required <= set(review) <= required | optional or review["credential_type"] != "oauth2"
            or review["provider"] != payload["providerId"] or review["credential_name"] != consent["credentialName"]
            or review["oauth_application_owner"] != association or metadata.get("oauth_application_owner") != association
            or metadata.get("oauth") is not True or metadata.get("provider_identity_verified") is not True
            or metadata.get("provider_id") != payload["providerId"] or review["metadata_keys"] != sorted(metadata)
            or review["expires_at_epoch_ms"] != metadata.get("expires_at_epoch_ms")
            or review.get("reconnect_credential_id") is not None or review.get("reconnect_credential_version") is not None):
        raise core.TransitionKernelError("OAuth stage review/application binding differs")
    for name in ("provider_subject", "provider_account"):
        profile.text(metadata.get(name), 512)
        if review[name] != metadata[name]:
            raise core.TransitionKernelError("OAuth stage provider account review differs")
    scopes = review["scopes"]
    if (type(scopes) is not list or not scopes or len(scopes) > 128
            or any(type(scope) is not str for scope in scopes) or len(set(scopes)) != len(scopes)
            or scopes != metadata.get("scopes") or not set(scopes) <= set(consent["scopes"])):
        raise core.TransitionKernelError("OAuth stage granted scopes differ from consent")
    if payload["providerId"] == "google" and (metadata.get("oauth_client_id") != payload["clientId"] or "x_app_id" in review):
        raise core.TransitionKernelError("OAuth stage Google client differs from enrollment")
    if payload["providerId"] == "x" and (type(review.get("x_app_id")) is not str or review["x_app_id"] != metadata.get("x_app_id")):
        raise core.TransitionKernelError("OAuth stage X application identity differs")
    expected = profile.sha256(profile.canonical({"action": activation.ACTION, "review": review,
        "encrypted_token_source_sha256": request["tokenSecretSha256"]}))
    if request["payloadDigest"] != expected:
        raise core.TransitionKernelError("OAuth activation payload does not bind the retained token source and review")
    return metadata


@dataclass(frozen=True, slots=True)
class OAuthExchangeKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return _HANDLERS[self.operation]

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, *, arguments, database_now, request_digest):
        if self.operation == profile.OP_PREPARE:
            raise core.TransitionKernelError("OAuth consent requires genuinely verified requester assertion")
        return self._queries(arguments, request_digest, None)

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        if self.operation != profile.OP_PREPARE:
            raise core.TransitionKernelError("OAuth callback is not a new assertion ceremony")
        return self._queries(arguments, request_digest, evidence)

    def _queries(self, arguments, request_digest, evidence):
        values = _values(self.operation, arguments)
        item_id = values["resource_id"]
        provider = enrollment.enrollment_document(activation.enrollment_bytes(values["enrollment_original"]))["payload"]["providerId"]
        queries = [shared._query(operation=self.operation, name="exchange", table=profile.TABLE, key={"id": item_id}, require_absence=self.operation == profile.OP_PREPARE),
            provider_retirement.query(self.operation, provider),
            shared._query(operation=self.operation, name="work", table="oauth_revocation_work", key={"id": item_id}, require_absence=self.operation == profile.OP_PREPARE),
            shared._role_query(self.operation, "actor_role", values["actor_id"])]
        if self.operation in succession.GUARDED_OPERATIONS:
            queries.append(succession.query(self.operation, provider))
        if self.operation == profile.OP_PREPARE:
            for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"), ("assertion_challenge", "webauthn_challenges", "challengeId")):
                core.require_text(evidence.get(field), field, maximum_bytes=1024)
                queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
            queries.extend(assertion._trust_queries(self.operation, work=None))
        if self.operation in {profile.OP_PREPARE, profile.OP_STAGE}:
            queries.extend(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table), table=table,
                predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.maximum_rows(table) + 1,
                proof_primitive="bounded-limit-plus-one", work_units=inventory.maximum_rows(table) + 1) for table in inventory.tables_for(self.operation))
        if self.operation == profile.OP_STAGE:
            queries.extend((shared._query(operation=self.operation, name="new_pending", table="pending_oauth_credentials", key={"id": item_id}, require_absence=True),
                shared._query(operation=self.operation, name="new_credential", table="credentials", key={"id": item_id}, require_absence=True),
                shared._query(operation=self.operation, name="new_generation", table="credential_generations", key={"credential_id": item_id}, require_absence=True)))
        queries.append(shared._audit_query(self.operation, request_digest))
        return family.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        values = _values(self.operation, context.arguments)
        request, actor = values["request"], values["actor_id"]
        now = context.database_now.astimezone(timezone.utc)
        now_s, now_ns = now.isoformat(), shared._database_epoch_ns(now)
        payload, association = _enrollment(values, now_ns)
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, payload["providerId"])
        if self.operation != profile.OP_RETAIN:
            provider_retirement.require_open(context, payload["providerId"])
        shared._require_role(context, subject_id=actor, required_role="credential_owner")
        mutations = []
        pending = None
        if self.operation == profile.OP_PREPARE:
            consent = request
            if (consent["providerId"] != payload["providerId"] or consent["redirectUri"] != payload["redirectUri"]
                    or consent["metadata"].get("oauth_application_owner") != association
                    or not payload["issuedAtEpochNs"] <= consent["issuedAtEpochNs"] <= now_ns < consent["contactExpiresAtEpochNs"]
                    or now_ns - consent["issuedAtEpochNs"] > 30_000_000_000
                    or consent["pendingExpiresAtEpochNs"] > payload["expiresAtEpochNs"]):
                raise core.TransitionKernelError("OAuth consent original scope or interval differs")
            for field in ("setup_session_id", "setupSessionId", "reconnect", "reconnect_credential_id", "reconnect_credential_version"):
                if field in consent["metadata"]:
                    raise core.TransitionKernelError("OAuth setup/reconnect requires its own complete controlled transition before contact")
            exchanges = context.present_rows(profile.TABLE)
            work_population = context.present_rows("oauth_revocation_work")
            pending_population = context.present_rows("pending_oauth_credentials")
            active_pending = pending_backlog = 0
            for item in pending_population:
                previous = shared._row(item, "pending OAuth row")
                live = previous["status"] == "pending" and profile.timestamp(previous["expires_at"]) > now
                active_pending += live
                pending_backlog += (previous["status"] in {"cancelled", "expired", "rejected"}
                    or previous["status"] == "pending" and not live)
            # Outstanding enrolled work already reserves a future pending slot.
            # Uncertain/retain-only work keeps that reservation until a separate
            # genuine cleanup operation exists; it is never treated as absent.
            outstanding = sum(shared._row(item, "OAuth work population")["source"] == _WORK_SOURCE
                for item in work_population)
            if (len(exchanges) >= inventory.MAX_ROWS or len(work_population) >= consent["limits"]["revocationCapacity"]
                    or active_pending + outstanding >= consent["limits"]["pendingCapacity"]
                    or pending_backlog >= consent["limits"]["revocationCapacity"]):
                raise core.TransitionKernelError("OAuth preparation has no protected state, pending or revocation capacity")
            for item in exchanges:
                prior = shared._row(item, "OAuth exchange population")
                prior_consent = _json(prior["consent_json"], "OAuth prior consent")
                if prior_consent["stateSha256"] == consent["stateSha256"]:
                    raise core.TransitionKernelError("OAuth state commitment was already reserved")
            evidence = context.verified_webauthn_evidence
            if evidence is None:
                raise core.TransitionKernelError("OAuth consent assertion was not independently verified")
            credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "requester authenticator")
            activation_kernel._hardware(credential, values["credential_policy"])
            if (evidence["rpId"] != values["credential_policy"]["rpId"]
                    or evidence["origin"] not in values["credential_policy"]["origins"]
                    or evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] > values["credential_policy"]["maxAssertionAgeSeconds"] * 1_000_000_000):
                raise core.TransitionKernelError("OAuth consent current physical policy differs")
            mutations.extend(assertion._assertion_mutations(context, {"actor_id": actor}))
            selected = context.exact(profile.TABLE, {"id": values["resource_id"]})
            work_selected = context.exact("oauth_revocation_work", {"id": values["resource_id"]})
            if selected["present"] or work_selected["present"]:
                raise core.TransitionKernelError("OAuth exchange identity was already used")
            row = {"id": values["resource_id"], "provider_id": payload["providerId"], "requester_id": actor,
                "enrollment_original": values["enrollment_original"], "credential_policy_json": profile.canonical(values["credential_policy"]).decode("ascii"),
                "consent_json": profile.canonical(consent).decode("ascii"), "status": "prepared",
                **{name: None for name in profile.NULLABLE}, "created_at": now_s, "updated_at": now_s}
            work = {"id": row["id"], "provider_id": row["provider_id"], "actor_id": actor, "source": _WORK_SOURCE,
                **consent["reservedEnvelope"], "status": "reserved", "attempts": 0, "last_error": None,
                "next_attempt_at": _iso(consent["contactExpiresAtEpochNs"]), "lease_owner": None, "lease_until": None,
                "created_at": now_s, "updated_at": now_s}
        else:
            selected, row, consent = _retained(context, values, payload, association, now_ns)
            expected = {profile.OP_CLAIM: "prepared", profile.OP_RETAIN: "claimed", profile.OP_STAGE: "retained"}[self.operation]
            if row["status"] != expected:
                raise core.TransitionKernelError("OAuth exchange stage is already used or uncertain; no replay")
            work_selected, work = _work(context, row, consent)
            if self.operation == profile.OP_CLAIM:
                if any(row[name] is not None for name in profile.NULLABLE):
                    raise core.TransitionKernelError("OAuth contact original is not unclaimed")
                row = {**row, "status": "claimed", "claim_request_digest": context.request_digest,
                    "code_sha256": request["codeSha256"], "contact_request_sha256": request["contactRequestSha256"], "updated_at": now_s}
                work = {**work, "status": "exchange_in_flight", "next_attempt_at": _iso(consent["retentionExpiresAtEpochNs"]), "updated_at": now_s}
            elif self.operation == profile.OP_RETAIN:
                for name in ("claim_request_digest", "code_sha256", "contact_request_sha256"):
                    profile.digest(row[name])
                if any(row[name] is not None for name in ("raw_response_sha256", "raw_response_envelope_json", "token_secret_sha256", "token_envelope_json")):
                    raise core.TransitionKernelError("OAuth issued response was already retained")
                token = request["tokenEnvelope"]
                row = {**row, "status": "retained", "raw_response_sha256": request["rawResponseSha256"],
                    "raw_response_envelope_json": profile.canonical(request["rawResponseEnvelope"]).decode("ascii"),
                    "token_secret_sha256": request["tokenSecretSha256"], "token_envelope_json": None if token is None else profile.canonical(token).decode("ascii"), "updated_at": now_s}
                work = {**work, **({} if token is None else token), "status": "issuance_uncertain_unreported" if token is None else "held", "updated_at": now_s}
            else:
                if (row["token_envelope_json"] is None or row["raw_response_envelope_json"] is None
                        or row["token_secret_sha256"] != request["tokenSecretSha256"]
                        or now_ns >= consent["pendingExpiresAtEpochNs"]):
                    raise core.TransitionKernelError("OAuth staging lacks exact retained material or original lifetime")
                profile.digest(row["raw_response_sha256"])
                metadata = _review(request, consent, payload, association)
                family.require_open_from_population(context, metadata["provider_id"], metadata["provider_subject"])
                for table, key in (("pending_oauth_credentials", {"id": row["id"]}), ("credentials", {"id": row["id"]}), ("credential_generations", {"credential_id": row["id"]})):
                    if context.exact(table, key)["present"]:
                        raise core.TransitionKernelError("OAuth pending identity or credential generation already exists")
                for item in context.present_rows("setup_sessions"):
                    setup = shared._row(item, "OAuth setup population")
                    if setup.get("oauth_pending_credential_id") == row["id"] or setup.get("oauth_state_digest") in {consent["stateSha256"], consent["stateSha256"][7:]}:
                        raise core.TransitionKernelError("OAuth state requires its separately atomic setup transition")
                pending_count = backlog = 0
                for item in context.present_rows("pending_oauth_credentials"):
                    prior = shared._row(item, "OAuth pending population")
                    if prior["status"] == "pending" and profile.timestamp(prior["expires_at"]) <= now:
                        prior = {**prior, "status": "expired", "revocation_status": "pending", "revocation_error": None,
                            "revocation_next_attempt_at": now_s, "revocation_lease_owner": None, "revocation_lease_until": None, "updated_at": now_s}
                        mutations.append(core.mutation(operation=self.operation, selected=item, row=prior))
                    pending_count += prior["status"] == "pending"
                    backlog += prior["status"] in {"cancelled", "expired", "rejected"}
                if pending_count >= consent["limits"]["pendingCapacity"] or backlog >= consent["limits"]["revocationCapacity"]:
                    raise core.TransitionKernelError("OAuth pending or retained revocation backlog is full")
                token = _json(row["token_envelope_json"], "OAuth retained final token envelope")
                pending = {"id": row["id"], "requester_id": actor, "name": consent["credentialName"], "kind": "oauth2", **token,
                    "metadata": profile.canonical(metadata).decode("ascii"), "payload_digest": request["payloadDigest"],
                    "review_json": profile.canonical(request["review"]).decode("ascii"), "target_credential_id": None, "target_credential_version": None,
                    "status": "pending", "revocation_status": None, "revocation_error": None, "revocation_attempts": 0,
                    "revocation_next_attempt_at": None, "revocation_lease_owner": None, "revocation_lease_until": None,
                    "created_at": now_s, "expires_at": _iso(consent["pendingExpiresAtEpochNs"]), "updated_at": now_s}
                activation.pending_original(pending)
                activation_kernel._google_collisions(context, pending, metadata)
                mutations.append(core.mutation(operation=self.operation, selected=context.exact("pending_oauth_credentials", {"id": row["id"]}), row=pending))
                row = {**row, "status": "staged", "updated_at": now_s}
        profile.row_original(row)
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        if self.operation == profile.OP_STAGE:
            mutations.append(core.delete_mutation(operation=self.operation, selected=work_selected))
        else:
            mutations.append(core.mutation(operation=self.operation, selected=work_selected, row=work))
        # Never emit state, browser nonce, PKCE, ciphertext or raw provider body.
        audit, audit_digest, replay = shared._audit_mutations(context,
            event_type="credential.oauth.exchange." + self.operation.split(".")[-1],
            actor_type="admin" if self.operation == profile.OP_PREPARE else "oauth_exchange", actor_id=actor,
            event={"schema": "serverware.oauthExchangeAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "exchangeId": row["id"], "exchangeRowSha256": profile.row_digest(row),
                "enrollmentSha256": association["enrollmentSha256"], "status": row["status"]})
        if replay:
            raise core.TransitionKernelError("OAuth exchange audit original already used")
        result = {"ok": True, "exchange": _public(row), "operation": self.operation,
            "requestDigest": context.request_digest, "auditEventDigest": audit_digest, "idempotentReplay": False}
        if pending is not None:
            result["pending"] = _pending_public(pending)
        return core.KernelTransition(mutations=tuple(mutations) + audit, result=result, work_units=1024)


KERNELS = MappingProxyType({operation: OAuthExchangeKernel(operation) for operation in profile.OPERATIONS})
