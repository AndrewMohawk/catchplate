"""Exact assigned runtime handoff and retained generation revalidation.

Only public independently signed originals enter this module. The state owner
provides authenticated rows, not a SQL connection or an asserted verifier DTO.
"""
from catchplate import authority_policy_canary as profile
from catchplate.authority_transition_policy_canary_state import exact


def envelope_receipt(state, kind, original, binding, *, previous=None):
    item = {"original_" + name: original[name] for name in ("envelope_json", "envelope_digest", "payload_json", "payload_digest")}
    item.update({name: original[name] for name in ("signature_algorithm", "signing_key_id", "signature", "signature_digest")})
    if previous is not None:
        item["verification_receipt_digest"] = previous
    return state.static(kind, item, "original", binding, historical=previous is not None)


def verify_handoff(state, item, *, stored=None, current=True):
    from catchplate import db
    parsed = db._policy_shadow_runtime_attestation_handoff_components(item["runtime_attestation_json"])
    handoff, role, evidence = (parsed[name] for name in ("handoff", "role_record", "evidence"))
    context = state.runtime_context(item)
    attestation = state.one("policy_runtime_attestations", attestation_receipt_envelope_digest=context["attestation_receipt_envelope_digest"])
    key = state.one("policy_runtime_role_keys", assignment_envelope_digest=context["assignment_envelope_digest"],
        member_ordinal=context["member_ordinal"], role="shadow")
    artifact = state.one("policy_candidate_artifacts", artifact_envelope_digest=context["artifact_envelope_digest"])
    state.static("runtime_attestation", attestation, "attestation_receipt",
        db._candidate_authority_signed_record(attestation, current_prefix="attestation_receipt"), historical=True)
    profile.require(parsed["receipt"]["envelope_json"] == attestation["attestation_receipt_envelope_json"]
        and parsed["receipt"]["payload_json"] == attestation["attestation_receipt_payload_json"])
    load = db.loads(context["load_receipt_payload_json"], None)
    profile.require(type(load) is dict and type(load.get("runtimeIdentity")) is dict)
    runtime_identity = profile.sha256(profile.canonical(load["runtimeIdentity"]))
    expected = {"candidateId": item["candidate_id"], "canaryId": item["canary_id"], "instanceId": item["instance_id"],
        "bootIdSha256": item["boot_id"], "runtimeIdentitySha256": runtime_identity,
        "assignmentSha256": context["assignment_envelope_digest"], "assignmentPayloadSha256": context["assignment_payload_digest"],
        "assignmentRevision": context["assignment_revision"], "loadReceiptSha256": context["load_receipt_envelope_digest"],
        "loadReceiptPayloadSha256": context["load_receipt_payload_digest"], "fleetId": context["fleet_id"],
        "fleetMembershipRevision": context["membership_revision"], "membershipRootSha256": context["membership_root_digest"],
        "memberOrdinal": context["member_ordinal"], "memberId": context["member_id"], "runtimeExecutableSha256": context["runtime_digest"],
        "shadowSigningKeyId": key["signing_key_id"], "shadowSigningKeySpkiSha256": key["public_key_digest"],
        "teeMeasurementSha256": attestation["tee_measurement_digest"]}
    chain = db._policy_shadow_generation_rust_domain_digest(b"catchplate.policyShadowRuntimeAttestationEvidenceChain/v1", [
        "catchplate.policyShadowRuntimeAttestationHandoff/v2", handoff["receiptId"], handoff["receiptRevision"],
        handoff["receiptSha256"], handoff["receiptPayloadSha256"], handoff["roleAuthorizationId"], handoff["roleAuthorizationRevision"],
        handoff["roleAuthorizationSha256"], handoff["roleAuthorizationPayloadSha256"], evidence,
        context["assignment_payload_digest"], context["load_receipt_payload_digest"], runtime_identity, role["attestationPolicySha256"]])
    profile.require(artifact["candidate_id"] == item["candidate_id"] and all(role[name] == value for name, value in expected.items())
        and evidence["evidenceSha256"] == attestation["tee_evidence_digest"] and evidence["evidenceType"] == attestation["tee_platform"]
        and handoff["chainSha256"] == chain and key["attestation_receipt_envelope_digest"] == handoff["receiptSha256"],
        "runtime handoff does not bind its actual assigned member, key and attestation")
    if current:
        profile.require(parsed["receipt_issued_at_epoch_ns"] <= state.now < parsed["receipt_expires_at_epoch_ns"]
            and parsed["role_issued_at_epoch_ns"] <= state.now < parsed["role_expires_at_epoch_ns"])
    checked = envelope_receipt(state, "shadow_role_authorization", parsed["role_authorization"], role,
        previous=None if stored is None else stored["role_authorization_verification_receipt_digest"])
    row = {name: item[name] for name in ("canary_id", "instance_id", "boot_id", "candidate_id")}
    row.update({name: context[name] for name in ("assignment_envelope_digest", "assignment_payload_digest", "assignment_revision",
        "load_receipt_envelope_digest", "load_receipt_payload_digest")})
    row.update(runtime_attestation_handoff_digest=parsed["handoff_digest"], runtime_attestation_handoff_json=parsed["handoff_json"],
        receipt_id=handoff["receiptId"], receipt_revision=handoff["receiptRevision"], receipt_envelope_digest=handoff["receiptSha256"],
        receipt_payload_digest=handoff["receiptPayloadSha256"], role_authorization_id=handoff["roleAuthorizationId"],
        role_authorization_revision=handoff["roleAuthorizationRevision"], role_authorization_evidence_kind="shadow_role_authorization",
        role_authorization_record_binding_digest=checked["record_binding_digest"],
        role_authorization_verification_receipt_digest=checked["verification_receipt_digest"],
        attestation_evidence_id=evidence["evidenceId"], attestation_evidence_revision=evidence["evidenceRevision"],
        attestation_evidence_type=evidence["evidenceType"], attestation_evidence_digest=evidence["evidenceSha256"],
        attestation_evidence_json=parsed["evidence_json"], attestation_chain_digest=chain, runtime_identity_digest=runtime_identity,
        shadow_role_key_authorization_digest=key["authorization_digest"], tee_measurement_digest=attestation["tee_measurement_digest"],
        issued_at_epoch_ns=parsed["role_issued_at_epoch_ns"],
        expires_at_epoch_ns=min(parsed["role_expires_at_epoch_ns"], parsed["receipt_expires_at_epoch_ns"]))
    for field in ("envelope_digest", "payload_digest", "envelope_json", "payload_json", "signature_algorithm", "signing_key_id", "signature", "signature_digest"):
        row["role_authorization_" + field] = parsed["role_authorization"][field]
    for name, source in (("runtime_executable_digest", "runtimeExecutableSha256"), ("runtime_release_digest", "runtimeReleaseSha256"),
            ("runtime_config_digest", "runtimeConfigSha256"), ("runtime_policy_digest", "runtimePolicySha256"),
            ("attestation_policy_digest", "attestationPolicySha256"), ("attestation_trust_checkpoint_digest", "attestationTrustCheckpointSha256"),
            ("attestation_revocation_generation", "revocationGeneration"), ("attestation_revocation_root_digest", "revocationRootSha256"),
            ("shadow_signing_key_id", "shadowSigningKeyId"), ("shadow_signing_key_spki_digest", "shadowSigningKeySpkiSha256")):
        row[name] = role[source]
    if stored is not None:
        exact(row, stored, tuple(row))
    return row, parsed, attestation, key


def handoff(state, value):
    from catchplate import db
    item = db._candidate_authority_record("controlled runtime handoff", value,
        ("canary_id", "instance_id", "boot_id", "candidate_id", "runtime_attestation_json", "actor_id"))
    for name in ("canary_id", "instance_id", "candidate_id"):
        profile.text(item[name], 256)
    profile.text(item["actor_id"], 1024); profile.digest(item["boot_id"])
    row, parsed, _, _ = verify_handoff(state, item)
    previous = [held for held in state.rows("policy_shadow_runtime_attestation_handoffs")
        if any(held[name] == row[name] for name in ("canary_id", "runtime_attestation_handoff_digest", "role_authorization_envelope_digest"))]
    if previous:
        profile.require(len(previous) == 1)
        verify_handoff(state, item, stored=previous[0])
        return previous[0]
    row["created_transition_digest"] = state.transition(event_type="policy.shadow_runtime_attestation_handoff.staged",
        entity_kind="shadow_runtime_attestation_handoff", entity_id=row["runtime_attestation_handoff_digest"],
        entity_revision=row["role_authorization_revision"], state_digest=row["runtime_attestation_handoff_digest"],
        previous_state_digest=row["load_receipt_payload_digest"], actor_id=item["actor_id"],
        evidence={"attestationChainSha256": row["attestation_chain_digest"], "receiptSha256": row["receipt_envelope_digest"],
            "roleAuthorizationSha256": row["role_authorization_envelope_digest"]}, created_at_epoch_ns=row["issued_at_epoch_ns"])
    profile.require(set(row) == set(db._POLICY_SHADOW_RUNTIME_ATTESTATION_HANDOFF_COLUMNS))
    state.put("policy_shadow_runtime_attestation_handoffs", row)
    return row


def generation(state, stored):
    """Recheck the committed publication and both independent signature receipts."""
    from catchplate import db
    from catchplate.authority_transition_policy_candidate_publication import evidence_inputs
    request_json, request_digest = db._candidate_authority_json("retained management request", stored["management_request_json"],
        stored["request_payload_digest"], maximum=8 * 1024 * 1024)
    request = db.loads(request_json, None)
    projected = dict(stored)
    parsed = db._policy_shadow_generation_evidence(projected)
    profile.require(type(request) is dict and set(request) == db._POLICY_SHADOW_GENERATION_REQUEST_FIELDS
        and request["apiVersion"] == "catchplate.policyShadowGenerationInstall/v2"
        and request["requestId"] == stored["request_id"] and request["replayId"] == stored["replay_id"]
        and request["managementHandoffId"] == stored["management_handoff_id"] and request_digest == stored["request_payload_digest"]
        and request["runtimeAttestation"] == parsed["startup_attestation"]
        and all(type(request[name]) is dict for name in ("assignment", "loadReceipt", "activePolicyBundle", "candidatePolicyBundle"))
        and profile.sha256(profile.canonical(request["activePolicyBundle"])) == stored["active_policy_bundle_digest"]
        and profile.sha256(profile.canonical(request["candidatePolicyBundle"])) == stored["candidate_policy_bundle_digest"])
    identities = db.derive_policy_shadow_generation_request_identities(request_id=stored["request_id"], actor_id=stored["management_actor_id"],
        **{name: stored[name] for name in ("candidate_id", "canary_id", "instance_id", "boot_id", "assignment_envelope_digest",
            "load_receipt_envelope_digest", "active_policy_hash", "active_policy_bundle_digest", "candidate_policy_hash", "candidate_policy_bundle_digest")},
        runtime_attestation_chain_digest=stored["attestation_chain_digest"],
        request_identity_digest=profile.sha256(profile.canonical({name: value for name, value in request.items()
            if name not in {"replayId", "managementHandoffId"}})))
    custody, ingress = db._policy_shadow_generation_high_water_digests(stored)
    profile.require(identities["replay_id"] == stored["replay_id"] and identities["management_handoff_id"] == stored["management_handoff_id"]
        and custody == stored["custody_high_water_digest"] and ingress == stored["ingress_high_water_digest"]
        and all(stored[name] == projected[name] for name in db._POLICY_SHADOW_GENERATION_DERIVED_COLUMNS
            if name not in {"rust_attestation_verification_receipt_digest", "runtime_attestation_verifier_record_binding_digest"}))
    held = state.one("policy_shadow_runtime_attestation_handoffs", **{name: stored[name] for name in ("canary_id", "instance_id", "boot_id")})
    handoff_row, original, attestation, key = verify_handoff(state,
        {**{name: stored[name] for name in ("canary_id", "instance_id", "boot_id", "candidate_id")},
            "runtime_attestation_json": held["runtime_attestation_handoff_json"]}, stored=held, current=False)
    profile.require(request["runtimeAttestation"] == original["handoff"] and stored["attestation_chain_digest"] == handoff_row["attestation_chain_digest"]
        and stored["runtime_attestation_verification_receipt_digest"] == attestation["verification_receipt_digest"]
        and stored["runtime_attestation_verification_envelope_digest"] == parsed["inner"]["envelope_digest"]
        and stored["attestation_role_authorization_digest"] == held["role_authorization_envelope_digest"])
    verified = []
    for inputs, receipt in zip(evidence_inputs(stored, parsed),
            (stored["rust_attestation_verification_receipt_digest"], stored["verification_receipt_digest"])):
        verified.append(envelope_receipt(state, inputs["evidence_kind"], inputs, inputs["record_binding"], previous=receipt))
    inner, outer = verified
    trusted = state.one("policy_authority_trusted_keys", evidence_kind="generation_publication", signing_key_id=stored["signing_key_id"],
        signature_domain="catchplate.policyShadowGenerationPublication/v2")
    head = state.one("policy_authority_trusted_key_heads", evidence_kind="generation_publication")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    spki = []
    for original_key in (key, trusted):
        public = Ed25519PublicKey.from_public_bytes(db._candidate_authority_b64url("generation key", original_key["public_key_base64url"], expected_bytes=32))
        spki.append(profile.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
    profile.require(trusted["key_revision"] == head["head_key_revision"] and trusted["signing_key_id"] == head["head_signing_key_id"]
        and trusted["public_key_digest"] == head["head_public_key_digest"]
        and stored["signing_key_id"] == key["signing_key_id"] == key["public_key_digest"] == spki[0]
        == trusted["signing_key_id"] == trusted["public_key_digest"] == spki[1] == outer["public_key_digest"]
        and not state.matching("policy_runtime_role_key_revocations", assignment_envelope_digest=stored["assignment_envelope_digest"],
            member_ordinal=stored["member_ordinal"], role="shadow", public_key_digest=key["public_key_digest"]))
    profile.require(inner["record_binding_digest"] == stored["runtime_attestation_verifier_record_binding_digest"]
        and outer["public_key_digest"] == key["public_key_digest"] and stored["signing_key_id"] == key["signing_key_id"]
        and key["authorization_digest"] == held["shadow_role_key_authorization_digest"]
        and outer["issued_at_epoch_ns"] == parsed["evidence"]["issuedAtUnixNanos"]
        and outer["expires_at_epoch_ns"] == parsed["evidence"]["expiresAtUnixNanos"])
