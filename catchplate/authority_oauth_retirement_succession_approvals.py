"""Genuine requester/distinct-approver ceremonies for two separate effects."""
from datetime import timedelta
from catchplate import authority_oauth_retirement_succession as p
from catchplate import authority_oauth_retirement_succession_records as records
from catchplate import authority_oauth_retirement_succession_queries as queries
from catchplate import authority_oauth_retirement_succession_lineages as lineages
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_oauth_activation as hardware
from catchplate.authority_transition_oauth_reconnect import _hardware as admit_hardware

PROVENANCE_FIELDS = frozenset({"schema", "requestDigest", "requestEvidenceDigest", "credentialPolicy", "decisionDigest",
    "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest", "consumptionMethod"})


def review(operation, grant, values):
    initial = operation in {p.OP_AUTHORIZE, p.OP_AUTHORIZE_DECIDE, p.OP_FENCE}
    return {"purpose": "scope-fence" if initial else "activate-generation",
        "authorizationSha256": p.sha256(p.decoded(values["authorization_original"], p.MAX_GRANT_BYTES)),
        "candidateSha256": None if initial else values["request"]["candidateSha256"]}


def _live_hardware(context, record_id, actor, policy):
    credential = shared._row(context.exact("webauthn_credentials", {"id": record_id}), "still admitted physical hardware")
    hardware._hardware(credential, policy)
    publications = context.present_rows("webauthn_trust_publications"); p.require(len(publications) == 1)
    publication = shared._row(publications[0], "current physical trust publication")
    withdrawn = records.array(publication["withdrawn_credential_ids_json"], 1024 * 1024)
    p.require(credential["user_id"] == actor and credential.get("attestation_trust_bundle_digest") == publication["bundle_digest"]
        and credential.get("attestation_trust_bundle_sequence") == publication["sequence"]
        and credential["id"] not in withdrawn and credential["credential_id"] not in withdrawn)


def transition(context, values, grant, *, journal=None):
    operation, actor, now = context.operation, values["actor_id"], context.database_now
    p.require(operation in p.ASSERTION_OPERATIONS | {p.OP_FENCE})
    evidence, effects = (None, []) if operation == p.OP_FENCE else admit_hardware(context, values)
    item = queries.approval_id(operation, values, context.request_digest)
    selected = context.exact("control_plane_approvals", {"id": item})
    binding = review(operation, grant, values); binding_raw = p.canonical(binding).decode("ascii")
    deadline = grant["admissionExpiresAtEpochNs"] if binding["purpose"] == "scope-fence" else grant["pendingExpiresAtEpochNs"]
    if operation in {p.OP_AUTHORIZE, p.OP_REQUEST}:
        p.require(not selected["present"] and actor == grant["requesterId"] and evidence is not None)
        expires = min(now + timedelta(seconds=300), p.issuance.legacy.timestamp(lineages.iso(deadline)))
        p.require(expires > now)
        provenance = {"schema": p.PROVENANCE_SCHEMA, "requestDigest": context.request_digest,
            "requestEvidenceDigest": evidence["verifiedAssertionReceiptDigest"], "credentialPolicy": values["credential_policy"],
            "decisionDigest": None, "decisionEvidenceDigest": None, "consumptionDigest": None,
            "consumptionEvidenceDigest": None, "consumptionMethod": None}
        row = {"id": item, "action": p.ACTION, "resource_id": grant["authorizationId"], "payload_digest": p.sha256(binding_raw.encode("ascii")),
            "requester_id": actor, "request_json": binding_raw, "status": "pending", "requested_at": now.isoformat(),
            "expires_at": expires.isoformat(), "approved_by": None, "approved_at": None, "consumed_by": None, "consumed_at": None,
            "decision_note": None, "approver_webauthn_credential_id": None, "approval_authn": p.canonical(provenance).decode("ascii")}
        effects.append(shared._aggregate_update(context, kind="control-plane-approvals", partition="global", live_delta=1,
            active_delta=1, next_sequence_delta=1, minimum_expiry_epoch_ns=shared._database_epoch_ns(expires)))
    else:
        row = shared._row(selected, "actual purpose-bound succession approval")
        provenance = records.stored(row["approval_authn"], 16384)
        p.require(set(provenance) == PROVENANCE_FIELDS and provenance["schema"] == p.PROVENANCE_SCHEMA
            and provenance["credentialPolicy"] == values["credential_policy"] and row["action"] == p.ACTION
            and row["resource_id"] == grant["authorizationId"] and row["payload_digest"] == p.sha256(binding_raw.encode("ascii"))
            and row["request_json"] == binding_raw and row["requester_id"] == grant["requesterId"]
            and lineages.epoch(row["expires_at"]) > shared._database_epoch_ns(now) and row["decision_note"] is None)
        for name in ("requestDigest", "requestEvidenceDigest"):
            p.digest(provenance[name])
        if operation in {p.OP_AUTHORIZE_DECIDE, p.OP_DECIDE}:
            p.require(evidence is not None and row["status"] == "pending" and actor != row["requester_id"]
                and row["approved_by"] is None and all(provenance[name] is None for name in
                    ("decisionDigest", "decisionEvidenceDigest", "consumptionDigest", "consumptionEvidenceDigest", "consumptionMethod")))
            shared._require_role(context, subject_id=row["requester_id"], required_role="credential_owner")
            provenance.update(decisionDigest=context.request_digest, decisionEvidenceDigest=evidence["verifiedAssertionReceiptDigest"])
            row = {**row, "status": "approved", "approved_by": actor, "approved_at": now.isoformat(), "approver_webauthn_credential_id": evidence["credentialRecordId"]}
        else:
            p.require(operation in {p.OP_FENCE, p.OP_ACTIVATE} and row["status"] == "approved" and row["requester_id"] == actor
                and row["approved_by"] not in {None, actor} and row["consumed_by"] is None and row["consumed_at"] is None
                and provenance["consumptionDigest"] is None and provenance["consumptionEvidenceDigest"] is None
                and provenance["consumptionMethod"] is None)
            for name in ("decisionDigest", "decisionEvidenceDigest"):
                p.digest(provenance[name])
            shared._require_role(context, subject_id=row["approved_by"], required_role="credential_owner")
            _live_hardware(context, row["approver_webauthn_credential_id"], row["approved_by"], values["credential_policy"])
            if operation == p.OP_FENCE:
                p.require(journal is not None and journal["approval_id"] == item
                    and lineages.epoch(journal["requester_evidence_expires_at"]) > shared._database_epoch_ns(now))
                _live_hardware(context, journal["requester_credential_id"], actor, values["credential_policy"])
                consumed_evidence, method = provenance["requestEvidenceDigest"], "retained-requester-and-distinct-approver"
            else:
                p.require(evidence is not None)
                consumed_evidence, method = evidence["verifiedAssertionReceiptDigest"], "fresh-requester-and-distinct-approver"
            provenance.update(consumptionDigest=context.request_digest, consumptionEvidenceDigest=consumed_evidence, consumptionMethod=method)
            row = {**row, "status": "consumed", "consumed_by": actor, "consumed_at": now.isoformat()}
        row["approval_authn"] = p.canonical(provenance).decode("ascii")
    effects.append(core.mutation(operation=operation, selected=selected, row=row))
    return row, evidence, effects
