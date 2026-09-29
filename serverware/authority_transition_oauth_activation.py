"""Atomic new-credential OAuth activation with purpose-bound physical approval.

No decryption, provider request, reconnect, setup session or standalone consume.
The actual planner authenticates original enrollment and complete populations
before this pure computation; the controlled executor fences the same roots.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType

from serverware import authority_oauth_activation as profile
from serverware import authority_oauth_setup as setup_profile
from serverware import authority_oauth_measured_setup as measured_setup
from serverware import authority_transition_oauth_setup_rows as setup_rows
from serverware import authority_oauth_activation_policy as enrollment
from serverware import authority_oauth_inventory as inventory
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_credential_currentness as currentness
from serverware import authority_transition_credential_currentness as currentness_kernel
from serverware import authority_oauth_family_retirement as family_retirement
from serverware import authority_oauth_provider_retirement as provider_retirement
from serverware import authority_oauth_retirement_succession_current as succession

_PROVENANCE = frozenset({"schema", "requestDigest", "requestEvidenceDigest", "credentialPolicy", "decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest"})
_CREDENTIAL_COPY = ("id", "name", "kind", "encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at", "metadata")


def _values(operation, arguments):
    try:
        return _contract(operation).arguments(operation, arguments, typed=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise core.TransitionKernelError("OAuth activation arguments are not closed") from exc


def _contract(operation):
    if operation in {setup_profile.OP_REQUEST, setup_profile.OP_DECIDE, setup_profile.OP_ACTIVATE}:
        return setup_profile
    if operation in profile.OPERATIONS:
        return profile
    raise core.TransitionKernelError("OAuth activation operation is not selected")


def _setup_pending(context, values, pending, enrollment_payload):
    bound = values["request"]["setupBinding"]
    _, row = setup_rows.current(context, bound, phase="oauth_verified", actor=pending["requester_id"])
    custody = shared._row(context.exact(measured_setup.TABLE, {"id": pending["id"]}), "actual measured Setup custody")
    measured_setup.row_original(custody)
    initial = setup_rows._original(custody["setup_initial_json"])
    final = setup_rows._original(custody["setup_final_json"])
    preparation = measured_setup.arguments(measured_setup.OP_PREPARE,
        shared._canonical_stored_mapping(custody["preparation_arguments_json"], "actual Setup preparation"))
    setup_profile.require(custody["status"] == "staged" and row == final and row["revision"] == 2
        and row["oauth_pending_credential_id"] == pending["id"] and row["oauth_provider"] == enrollment_payload["providerId"]
        and row["credential_id"] is None and row["credential_version"] is None
        and row["owner_id"] == initial["owner_id"] == preparation["actor_id"] == pending["requester_id"]
        and row["current_assignee_id"] == initial["current_assignee_id"]
        and row["id"] == initial["id"] and row["expires_at"] == initial["expires_at"]
        and setup_profile.row_binding(initial) == preparation["request"]["setupBinding"]
        and preparation["enrollment_original"] == values["enrollment_original"]
        and custody["pending_original_json"] == profile.pending_original(pending).decode("ascii"),
        "Setup activation does not consume the exact genuine staged association")
    return row


def _time(value):
    if type(value) is not str:
        raise core.TransitionKernelError("OAuth timestamp is not an original SQL string")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise core.TransitionKernelError("OAuth timestamp is not UTC")
    return result


def _approval_id(operation, values, digest):
    return values["approval_id"] or core.deterministic_uuid(operation=operation, request_digest=digest, purpose="oauth-activation-approval")


def _public(row):
    return {**shared._control_public(row), "request": json.loads(row["request_json"])}


def _pending(context, values):
    selected = context.exact("pending_oauth_credentials", {"id": values["resource_id"]})
    row = shared._row(selected, "pending OAuth credential")
    if (profile.pending_digest(row) != values["request"]["pendingRowSha256"]
            or row["id"] != values["resource_id"] or row["payload_digest"] != values["payload_digest"]
            or row["status"] != "pending" or row["kind"] != "oauth2" or row["credential_version"] != 1
            or row["target_credential_id"] is not None or row["target_credential_version"] is not None
            or row["revocation_status"] is not None or row["revocation_attempts"] != 0
            or any(row[name] is not None for name in ("revocation_error", "revocation_next_attempt_at", "revocation_lease_owner", "revocation_lease_until"))
            or _time(row["expires_at"]) <= context.database_now):
        raise core.TransitionKernelError("OAuth pending original changed, expired, or requires unsupported reconnect/revocation")
    raw = profile.enrollment_bytes(values["enrollment_original"])
    payload = enrollment.enrollment_document(raw)["payload"]
    now_ns = shared._database_epoch_ns(context.database_now)
    if not payload["issuedAtEpochNs"] <= now_ns < payload["expiresAtEpochNs"]:
        raise core.TransitionKernelError("OAuth enrollment original interval expired")
    association = enrollment.association(raw)
    metadata = shared._canonical_stored_mapping(row["metadata"], "pending metadata")
    review = shared._canonical_stored_mapping(row["review_json"], "pending review")
    provider = payload["providerId"]
    required = {"credential_type", "provider", "provider_subject", "provider_account", "scopes", "credential_name", "metadata_keys", "expires_at_epoch_ms", "oauth_application_owner"}
    optional = {"x_app_id", "reconnect_credential_id", "reconnect_credential_version"}
    if (not required <= set(review) <= required | optional
            or metadata.get("oauth_application_owner") != association or review.get("oauth_application_owner") != association
            or metadata.get("oauth") is not True or metadata.get("provider_identity_verified") is not True
            or metadata.get("provider_id") != provider or review["provider"] != provider
            or review["credential_type"] != row["kind"] or review["credential_name"] != row["name"]
            or review["provider_subject"] != metadata.get("provider_subject")
            or review["provider_account"] != metadata.get("provider_account")
            or review["metadata_keys"] != sorted(metadata)
            or review["expires_at_epoch_ms"] != metadata.get("expires_at_epoch_ms")
            or review.get("reconnect_credential_id") is not None or review.get("reconnect_credential_version") is not None):
        raise core.TransitionKernelError("OAuth pending review/application association differs")
    for name in ("provider_subject", "provider_account"):
        core.require_text(metadata.get(name), name, maximum_bytes=512)
    scopes = review["scopes"]
    if (type(scopes) is not list or not scopes or len(scopes) > 128 or any(type(scope) is not str or not scope or len(scope) > 1024 for scope in scopes)
            or len(scopes) != len(set(scopes)) or scopes != metadata.get("scopes")):
        raise core.TransitionKernelError("OAuth review scopes differ")
    if provider == "google" and metadata.get("oauth_client_id") != payload["clientId"]:
        raise core.TransitionKernelError("Google OAuth client enrollment differs")
    if provider == "x" and (type(review.get("x_app_id")) is not str or review["x_app_id"] != metadata.get("x_app_id")):
        raise core.TransitionKernelError("X application identity differs")
    if provider != "x" and "x_app_id" in review:
        raise core.TransitionKernelError("OAuth review has another provider's application identity")
    return selected, row, metadata, payload


def _google_collisions(context, pending, metadata):
    if metadata["provider_id"] != "google":
        return
    for table in ("credentials", "pending_oauth_credentials"):
        population = context.present_rows(table)
        if len(population) > inventory.MAX_ROWS:
            raise core.TransitionKernelError("OAuth complete-population capacity exceeded")
        for selected in population:
            row = shared._row(selected, "OAuth population")
            if table == "pending_oauth_credentials" and row["id"] == pending["id"]:
                continue
            other = shared._canonical_stored_mapping(row["metadata"], "OAuth population metadata")
            if other.get("provider_id") != "google":
                continue
            if other.get("oauth") is not True or other.get("provider_identity_verified") is not True:
                raise core.TransitionKernelError("stored Google OAuth identity is malformed")
            core.require_text(other.get("provider_subject"), "Google subject", maximum_bytes=512)
            client = other.get("oauth_client_id")
            if client is not None:
                core.require_text(client, "Google client", maximum_bytes=2048)
            if other["provider_subject"] == metadata["provider_subject"] and (client is None or client == metadata["oauth_client_id"]):
                raise core.TransitionKernelError("Google OAuth grant family collides with an existing local original")


def _hardware(credential, policy):
    classes = {credential.get("authenticator_class")}
    if "yubikey" in classes:
        classes.add("hardware")
    if (credential.get("revoked_at") is not None or not classes.intersection(policy["allowedAuthenticatorClasses"])
            or not classes.intersection({"hardware", "yubikey"}) or credential.get("attestation_trusted") not in (True, 1)
            or not credential.get("attestation_leaf_sha256") or not credential.get("attestation_root_sha256")):
        raise core.TransitionKernelError("OAuth physical authenticator policy differs")


@dataclass(frozen=True, slots=True)
class OAuthActivationKernel:
    operation: str
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        if _contract(self.operation) is setup_profile:
            return "serverware_policy_authority_" + self.operation.replace(".", "_").replace("-", "_")
        return "serverware_policy_authority_oauth_" + ({profile.OP_REQUEST: "activation_approval_request", profile.OP_DECIDE: "activation_approval_decide", profile.OP_ACTIVATE: "pending_activate"}[self.operation])

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("OAuth activation requires genuinely verified assertion originals")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        profile = _contract(self.operation)
        values = _values(self.operation, arguments)
        item_id = _approval_id(self.operation, values, request_digest)
        provider = enrollment.enrollment_document(profile.enrollment_bytes(values["enrollment_original"]))["payload"]["providerId"]
        queries = [shared._query(operation=self.operation, name="approval", table="control_plane_approvals", key={"id": item_id}),
            provider_retirement.query(self.operation, provider),
            shared._role_query(self.operation, "actor_role", values["actor_id"]),
            shared._query(operation=self.operation, name="pending", table="pending_oauth_credentials", key={"id": values["resource_id"]})]
        if self.operation in succession.GUARDED_OPERATIONS:
            queries.append(succession.query(self.operation, provider))
        if self.operation == profile.OP_REQUEST:
            queries.append(shared._aggregate_query(self.operation, "approval_capacity", "control-plane-approvals", "global"))
        else:
            other = "requester_id" if self.operation == profile.OP_DECIDE else "approved_by"
            queries.append(shared._role_query(self.operation, "other_role", core.SelectedRowFieldReference("control_plane_approvals", {"id": item_id}, other)))
        for name, table, field in (("assertion_credential", "webauthn_credentials", "credentialRecordId"), ("assertion_challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(shared._query(operation=self.operation, name=name, table=table, key={"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        if profile is setup_profile:
            queries.extend((shared._query(operation=self.operation, name="setup", table="setup_sessions",
                key={"id": values["request"]["setupBinding"]["sessionId"]}),
                shared._query(operation=self.operation, name="setup_custody", table=measured_setup.TABLE, key={"id": values["resource_id"]})))
            if self.operation == profile.OP_ACTIVATE:
                queries.extend(setup_rows.event_queries(self.operation, values["request"]["setupBinding"]["sessionId"], 3))
        if self.operation == profile.OP_ACTIVATE:
            queries.append(currentness_kernel.root_query(self.operation, values["resource_id"], 1, absent=True))
            queries.extend((shared._query(operation=self.operation, name="new_credential", table="credentials", key={"id": values["resource_id"]}, require_absence=True),
                shared._query(operation=self.operation, name="new_generation", table="credential_generations", key={"credential_id": values["resource_id"]}, require_absence=True),
                shared._query(operation=self.operation, name="approver_credential", table="webauthn_credentials", key={"id": core.SelectedRowFieldReference("control_plane_approvals", {"id": item_id}, "approver_webauthn_credential_id")})))
            # Completeness is NOT inferred from these observations. The actual
            # planner must reconstruct all four entire roots before this kernel.
            queries.extend(core.BoundedQuery(query_id=core.query_program_id(self.operation, "complete_population", table), table=table,
                predicates=(), order_by=(core.QueryOrder("id"),), maximum_rows=inventory.maximum_rows(table) + 1,
                proof_primitive="bounded-limit-plus-one", work_units=inventory.maximum_rows(table) + 1) for table in inventory.TABLES)
        queries.append(shared._audit_query(self.operation, request_digest))
        return family_retirement.order_populations(self.operation, tuple(queries))

    def transition(self, context):
        profile = _contract(self.operation)
        values = _values(self.operation, context.arguments)
        pending_selected, pending, metadata, original_enrollment = _pending(context, values)
        if self.operation in succession.GUARDED_OPERATIONS:
            succession.require_unassigned(context, original_enrollment["providerId"])
        provider_retirement.require_open(context, original_enrollment["providerId"])
        setup_before = _setup_pending(context, values, pending, original_enrollment) if profile is setup_profile else None
        setup_after = setup_updates = None
        item_id = _approval_id(self.operation, values, context.request_digest)
        actor, now = values["actor_id"], context.database_now.astimezone(timezone.utc)
        now_s = now.isoformat()
        shared._require_role(context, subject_id=actor, required_role="credential_owner")
        evidence = context.verified_webauthn_evidence
        if evidence is None:
            raise core.TransitionKernelError("OAuth activation assertion was not independently verified")
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "assertion credential")
        policy = values["credential_policy"]
        _hardware(credential, policy)
        if (evidence["rpId"] != policy["rpId"] or evidence["origin"] not in policy["origins"]
                or evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] > policy["maxAssertionAgeSeconds"] * 1_000_000_000):
            raise core.TransitionKernelError("OAuth assertion current policy differs")
        mutations = list(assertion._assertion_mutations(context, {"actor_id": actor}))
        selected = context.exact("control_plane_approvals", {"id": item_id})
        if self.operation == profile.OP_REQUEST:
            if selected.get("present") is not False or pending["requester_id"] != actor:
                raise core.TransitionKernelError("OAuth request is not a fresh pending-owner request")
            expiry_ns = min(shared._database_epoch_ns(now + timedelta(seconds=300)), original_enrollment["expiresAtEpochNs"], shared._database_epoch_ns(_time(pending["expires_at"])))
            if setup_before is not None:
                expiry_ns = min(expiry_ns, setup_profile.epoch(setup_before["expires_at"]))
            expires = datetime.fromtimestamp(expiry_ns // 1_000_000_000, timezone.utc)
            if expires <= now:
                raise core.TransitionKernelError("OAuth approval has no remaining original lifetime")
            provenance = {"schema": profile.PROVENANCE_SCHEMA, "requestDigest": context.request_digest,
                "requestEvidenceDigest": evidence["verifiedAssertionReceiptDigest"], "credentialPolicy": policy,
                "decisionDigest": None, "decisionEvidenceDigest": None, "consumptionDigest": None, "consumptionEvidenceDigest": None}
            row = {"id": item_id, "action": profile.ACTION, "resource_id": values["resource_id"], "payload_digest": values["payload_digest"],
                "requester_id": actor, "request_json": profile.canonical(values["request"]).decode("ascii"), "status": "pending",
                "requested_at": now_s, "expires_at": expires.isoformat(), "approved_by": None, "approved_at": None,
                "consumed_by": None, "consumed_at": None, "decision_note": None, "approver_webauthn_credential_id": None,
                "approval_authn": profile.canonical(provenance).decode("ascii")}
            mutations.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global", live_delta=1,
                active_delta=1, next_sequence_delta=1, minimum_expiry_epoch_ns=shared._database_epoch_ns(expires)))
        else:
            row = shared._row(selected, "OAuth activation approval")
            provenance = shared._canonical_stored_mapping(row["approval_authn"], "OAuth approval provenance")
            if (set(provenance) != _PROVENANCE or provenance["schema"] != profile.PROVENANCE_SCHEMA
                    or provenance["credentialPolicy"] != policy or row["action"] != profile.ACTION
                    or row["resource_id"] != values["resource_id"] or row["payload_digest"] != values["payload_digest"]
                    or row["request_json"] != profile.canonical(values["request"]).decode("ascii")
                    or row["requester_id"] != pending["requester_id"] or _time(row["expires_at"]) <= now
                    or row["decision_note"] is not None):
                raise core.TransitionKernelError("OAuth approval original binding or provenance differs")
            for field in ("requestDigest", "requestEvidenceDigest"):
                profile.digest(provenance[field])
            if self.operation == profile.OP_DECIDE:
                shared._require_role(context, subject_id=row["requester_id"], required_role="credential_owner")
                if (row["status"] != "pending" or row["requester_id"] == actor or row["approved_by"] is not None
                        or any(provenance[name] is not None for name in ("decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest"))):
                    raise core.TransitionKernelError("OAuth decision is not fresh and distinct-person")
                provenance = {**provenance, "decisionDigest": context.request_digest, "decisionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
                row = {**row, "status": "approved", "approved_by": actor, "approved_at": now_s, "approver_webauthn_credential_id": evidence["credentialRecordId"]}
            else:
                if (row["status"] != "approved" or row["requester_id"] != actor or row["approved_by"] in (None, actor)
                        or row["consumed_by"] is not None or row["consumed_at"] is not None
                        or provenance["consumptionDigest"] is not None or provenance["consumptionEvidenceDigest"] is not None):
                    raise core.TransitionKernelError("OAuth activation is not an unused distinct-person approval")
                for field in ("decisionDigest", "decisionEvidenceDigest"):
                    profile.digest(provenance[field])
                shared._require_role(context, subject_id=row["approved_by"], required_role="credential_owner")
                approver = shared._row(context.exact("webauthn_credentials", {"id": row["approver_webauthn_credential_id"]}), "approver credential")
                _hardware(approver, policy)
                publications = context.present_rows("webauthn_trust_publications")
                if len(publications) != 1:
                    raise core.TransitionKernelError("OAuth current trust publication is ambiguous")
                publication = shared._row(publications[0], "trust publication")
                withdrawn = json.loads(publication["withdrawn_credential_ids_json"])
                if (approver["user_id"] != row["approved_by"] or approver.get("attestation_trust_bundle_digest") != publication["bundle_digest"]
                        or approver.get("attestation_trust_bundle_sequence") != publication["sequence"]
                        or type(withdrawn) is not list or approver["id"] in withdrawn or approver["credential_id"] in withdrawn):
                    raise core.TransitionKernelError("OAuth approver current physical trust differs")
                _google_collisions(context, pending, metadata)
                family_retirement.require_open_from_population(context, metadata["provider_id"], metadata["provider_subject"])
                if any(shared._row(item, "setup session").get("oauth_pending_credential_id") == pending["id"]
                        and (setup_before is None or item["row"]["id"] != setup_before["id"])
                        for item in context.present_rows("setup_sessions")):
                    raise core.TransitionKernelError("OAuth pending credential requires a separate atomic setup transition")
                new_selected = context.exact("credentials", {"id": pending["id"]})
                generation = context.exact("credential_generations", {"credential_id": pending["id"]})
                currentness_selected = context.exact(currentness.ROOT_TABLE, {"id": currentness.root_id(pending["id"], 1)})
                if new_selected["present"] or generation["present"] or currentness_selected["present"]:
                    raise core.TransitionKernelError("OAuth new credential identity or generation already exists")
                new_row = {name: pending[name] for name in _CREDENTIAL_COPY}
                new_row.update(lifecycle_status="active", revocation_error=None, revocation_requested_at=None, created_at=now_s, updated_at=now_s)
                mutations.extend((core.mutation(operation=self.operation, selected=new_selected, row=new_row),
                    core.mutation(operation=self.operation, selected=generation, row={"credential_id": pending["id"], "last_version": 1, "updated_at": now_s}),
                    core.mutation(operation=self.operation, selected=currentness_selected,
                        row=currentness.new_root(pending["id"], 1, context.request_digest, now_s)),
                    core.delete_mutation(operation=self.operation, selected=pending_selected)))
                if setup_before is not None:
                    setup_after, setup_updates = setup_rows.next_row(context, setup_before, transition="bind_credential", credential_id=pending["id"])
                provenance = {**provenance, "consumptionDigest": context.request_digest, "consumptionEvidenceDigest": evidence["verifiedAssertionReceiptDigest"]}
                row = {**row, "status": "consumed", "consumed_by": actor, "consumed_at": now_s}
            row = {**row, "approval_authn": profile.canonical(provenance).decode("ascii")}
        mutations.append(core.mutation(operation=self.operation, selected=selected, row=row))
        audit, audit_digest, replay = shared._audit_mutations(context, event_type=("credential.oauth.setup." if profile is setup_profile else "credential.oauth.activation.") + self.operation.split(".")[-1],
            actor_type="admin", actor_id=actor, event={"schema": "serverware.oauthSetupActivationAudit/v1" if profile is setup_profile else "serverware.oauthActivationAudit/v1", "operation": self.operation,
                "requestDigest": context.request_digest, "approvalId": item_id, "actorId": actor, "request": values["request"], "provenance": provenance,
                **({"setupPostSha256": setup_profile.sha256(setup_profile.row_original(setup_after))} if setup_after is not None else {})})
        if replay:
            raise core.TransitionKernelError("OAuth activation audit identity was already used")
        result = {"ok": True, "approval": _public(row), "operation": self.operation, "requestDigest": context.request_digest,
            "auditEventDigest": audit_digest, "idempotentReplay": False}
        if setup_before is not None:
            result["setupOriginal"] = setup_profile.row_original(setup_after or setup_before).decode("ascii")
        if setup_after is not None:
            mutations.extend(setup_rows.mutations(context, setup_before, setup_after, transition="bind_credential", actor=actor,
                updates=setup_updates, audit_digest=audit_digest, provider=original_enrollment["providerId"],
                enrollment_sha256=values["request"]["enrollmentSha256"]))
            result["setupEventId"] = setup_profile.event_id(setup_after["id"], 4)
            result["auditState"] = "controlled_pending"
        if self.operation == profile.OP_ACTIVATE:
            result["credential"] = {name: (metadata if name == "metadata" else value) for name, value in new_row.items()
                if name not in {"encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext"}}
        return core.KernelTransition(mutations=tuple(mutations) + audit, result=result, work_units=256)


KERNELS = MappingProxyType({operation: OAuthActivationKernel(operation) for operation in profile.OPERATIONS | {setup_profile.OP_REQUEST, setup_profile.OP_DECIDE, setup_profile.OP_ACTIVATE}})
