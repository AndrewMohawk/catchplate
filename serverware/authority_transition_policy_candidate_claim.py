"""One actual typed pre-contact generation claim; no native contact here."""
from dataclasses import dataclass
from datetime import timezone

from serverware import authority_policy_candidate as profile
from serverware import authority_transition_policy_candidate_context as originals
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware


@dataclass(frozen=True, slots=True)
class GenerationClaimKernel:
    operation: str = profile.OP_CLAIM
    permits_empty_mutation: bool = False

    @property
    def handler(self):
        return "serverware_policy_authority_policy_candidate_generation_claim"

    @property
    def program_id(self):
        return core.transition_program_id(self.operation, self.handler)

    def queries(self, **kwargs):
        raise core.TransitionKernelError("candidate claim requires current original publisher hardware evidence")

    def queries_with_evidence(self, *, arguments, database_now, request_digest, evidence):
        del database_now
        values = profile.arguments(self.operation, arguments, typed=True)
        bound = values["request"]["context"]
        request = profile.management_original(values["request"]["managementRequestOriginal"])
        queries = list(originals.queries(self.operation, bound, request))
        queries.extend(originals.populations(self.operation))
        queries.extend((originals.exact(self.operation, "claim", profile.TABLE, {"request_id": request["requestId"]}, absence=True),
            shared._role_query(self.operation, "publisher", values["actor_id"]), shared._audit_query(self.operation, request_digest)))
        for name, table, field in (("hardware", "webauthn_credentials", "credentialRecordId"),
                ("challenge", "webauthn_challenges", "challengeId")):
            core.require_text(evidence.get(field), field, maximum_bytes=1024)
            queries.append(originals.exact(self.operation, name, table, {"id": evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation, work=None))
        return tuple(queries)

    def transition(self, context):
        values = profile.arguments(self.operation, context.arguments, typed=True)
        held = values["request"]
        request = profile.management_original(held["managementRequestOriginal"])
        bound, actor = held["context"], values["actor_id"]
        now = shared._database_epoch_ns(context.database_now)
        profile.require(held["issuedAtEpochNs"] <= now < held["expiresAtEpochNs"])
        shared._require_role(context, subject_id=actor, required_role="policy_publisher")
        evidence = context.verified_webauthn_evidence
        profile.require(evidence is not None)
        credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}), "actual candidate publisher")
        hardware._hardware(credential, values["credential_policy"])
        profile.require(evidence["rpId"] == values["credential_policy"]["rpId"]
            and evidence["origin"] in values["credential_policy"]["origins"]
            and evidence["expiresAtEpochNs"] - evidence["verifiedAtEpochNs"] <= values["credential_policy"]["maxAssertionAgeSeconds"] * 1_000_000_000)
        selected = context.exact(profile.TABLE, {"request_id": request["requestId"]})
        profile.require(not selected["present"])
        population = originals.population(context, profile.TABLE)
        profile.require(len(population) < 32, "candidate claim history capacity is full; no automatic pruning")
        for previous in population:
            profile.row_original(previous)
            profile.require(previous["replay_id"] != request["replayId"]
                and previous["management_handoff_id"] != request["managementHandoffId"], "candidate native identity has already been claimed")
        pending = sum(previous["publication_envelope_digest"] is None for previous in population)
        profile.require(len(originals.population(context, "policy_authority_evidence_verifications")) + 2 * (pending + 1) <= 32
            and len(originals.population(context, "policy_shadow_generation_publications")) + pending + 1 <= 32,
            "candidate retained claims have exhausted publication capacity; uncertainty is not released by expiry")
        actual = originals.original_context(context, bound, request)
        profile.require(held["expiresAtEpochNs"] <= min(actual["handoff"]["expires_at_epoch_ns"],
            actual["assignment"]["expires_at_epoch_ns"], actual["key"]["not_after_epoch_ns"]))
        identity = profile.generation_identity(actor=actor, bound=bound, request=request, originals=actual)
        from serverware import db
        replay = "replay:" + db._policy_authority_domain_digest(
            b"serverware.policyShadowGenerationReplayIdentity/v1", profile.canonical(identity)).removeprefix("sha256:")
        profile.require(request["replayId"] == replay)
        # HMAC handoff identity is created by the real retained CP transport
        # owner, never by this public computation. Its exact original is bound
        # here and independently authenticated by the actual native receiver.
        row = {"request_id": request["requestId"], "replay_id": replay,
            "management_handoff_id": request["managementHandoffId"], "actor_id": actor,
            "configuration_digest": values["control_plane_configuration_digest"], "context_json": profile.canonical(bound).decode("ascii"),
            "management_request_json": held["managementRequestOriginal"], "request_identity_digest": identity["requestIdentitySha256"],
            "payload_digest": profile.sha256(held["managementRequestOriginal"].encode("ascii")), "request_digest": context.request_digest,
            "issued_at_epoch_ns": held["issuedAtEpochNs"], "expires_at_epoch_ns": held["expiresAtEpochNs"],
            "created_at": context.database_now.astimezone(timezone.utc).isoformat(), "publication_envelope_digest": None}
        raw = profile.row_original(row)
        audit, audit_digest, replayed = shared._audit_mutations(context, event_type="policy.candidate.generation-claim",
            actor_type="admin", actor_id=actor, event={"schema": "serverware.policyCandidateClaimAudit/v1",
                "requestDigest": context.request_digest, "claimSha256": profile.sha256(raw), "requestId": request["requestId"],
                "payloadDigest": row["payload_digest"], "context": bound})
        profile.require(not replayed)
        return core.KernelTransition(mutations=(core.mutation(operation=self.operation, selected=selected, row=row),)
            + tuple(assertion._assertion_mutations(context, {"actor_id": actor})) + audit,
            result={"ok": True, "operation": self.operation, "requestDigest": context.request_digest,
                "auditEventDigest": audit_digest, "idempotentReplay": False, "claimOriginal": raw.decode("ascii")}, work_units=1024)
