"""Historical/current signature admission from authenticated transaction rows.

No receipt or key supplied by an HTTP caller is an authority. Historical heads
are selected from the complete authenticated key history as of the retained
verification time. They do not become the current head or renew any interval.
"""
from serverware import authority_policy_candidate as profile
from serverware import authority_policy_candidate_evidence as signatures
from serverware import authority_transition_policy_candidate_context as originals
from serverware import authority_transition_quota as shared


def historical(context, *, receipt_digest, **evidence):
    receipts = [row for row in originals.population(context, "policy_authority_evidence_verifications")
        if row["verification_receipt_digest"] == receipt_digest]
    profile.require(len(receipts) == 1, "retained candidate verification original is absent")
    receipt = receipts[0]
    now = shared._database_epoch_ns(context.database_now)
    verified = receipt["verified_at_epoch_ns"]
    profile.require(type(verified) is int and 0 < verified <= now and verified >= receipt["issued_at_epoch_ns"])
    keys = [row for row in originals.population(context, "policy_authority_trusted_keys")
        if row["evidence_kind"] == evidence["evidence_kind"] and row["installed_at_epoch_ns"] <= verified]
    profile.require(bool(keys), "historical candidate key history is absent")
    key = max(keys, key=lambda row: row["key_revision"])
    profile.require(key["key_revision"] == receipt["trusted_key_revision"]
        and key["installed_at_epoch_ns"] == receipt["trusted_key_installed_at_epoch_ns"]
        and key["signing_key_id"] == evidence["signing_key_id"])
    revoked = originals.population(context, "policy_authority_trusted_key_revocations")
    profile.require(not any(row["evidence_kind"] == evidence["evidence_kind"]
        and row["signing_key_id"] == evidence["signing_key_id"] for row in revoked),
        "historical candidate signing key is now revoked")
    sequence = max((row["revocation_sequence"] for row in revoked if row["revoked_at_epoch_ns"] <= verified), default=0)
    # This is the actual historical head computed above, not an asserted current
    # head. The shared pure verifier recomputes every signature/receipt byte.
    head = {"evidence_kind": key["evidence_kind"], "head_key_revision": key["key_revision"],
        "head_signing_key_id": key["signing_key_id"], "head_public_key_digest": key["public_key_digest"]}
    recomputed = signatures.verify_static_original(**evidence, key=key, key_head=head, revocation=None,
        revocation_sequence=sequence, verified_at_epoch_ns=verified)
    profile.require(recomputed == receipt, "historical candidate receipt or original changed")
    return receipt


def stored_static(context, *, kind, row, prefix):
    from serverware import db
    return historical(context, evidence_kind=kind, receipt_digest=row["verification_receipt_digest"],
        envelope_json=row[prefix + "_envelope_json"], envelope_digest=row[prefix + "_envelope_digest"],
        payload_json=row[prefix + "_payload_json"], payload_digest=row[prefix + "_payload_digest"],
        signature_algorithm=row["signature_algorithm"], signing_key_id=row["signing_key_id"],
        signature=row["signature"], signature_digest=row["signature_digest"],
        record_binding=db._candidate_authority_signed_record(row, current_prefix=prefix))


def current(context, *, expected_key, expected_head, expected_sequence, **evidence):
    key_rows = [row for row in originals.population(context, "policy_authority_trusted_keys")
        if row["evidence_kind"] == evidence["evidence_kind"] and row["key_revision"] == expected_key["key_revision"]]
    profile.require(len(key_rows) == 1 and key_rows[0] == expected_key, "candidate key prestate changed")
    head = shared._row(context.exact("policy_authority_trusted_key_heads", {
        "evidence_kind": evidence["evidence_kind"]}), "current candidate signing head")
    profile.require(head == expected_head, "candidate head prestate changed")
    revocations = originals.population(context, "policy_authority_trusted_key_revocations")
    sequence = max((row["revocation_sequence"] for row in revocations), default=0)
    profile.require(sequence == expected_sequence)
    revoked = next((row for row in revocations if row["evidence_kind"] == evidence["evidence_kind"]
        and row["signing_key_id"] == evidence["signing_key_id"]), None)
    computed = signatures.verify_static_original(**evidence, key=key_rows[0], key_head=head, revocation=revoked,
        revocation_sequence=sequence, verified_at_epoch_ns=shared._database_epoch_ns(context.database_now))
    existing = [row for row in originals.population(context, "policy_authority_evidence_verifications")
        if row["signature_digest"] == computed["signature_digest"] and row["record_binding_digest"] == computed["record_binding_digest"]]
    profile.require(len(existing) <= 1)
    if existing:
        profile.require(all(existing[0][field] == value for field, value in computed.items()
            if field not in {"verification_receipt_digest", "verified_at_epoch_ns"}), "candidate evidence identity was reused")
        return existing[0], None
    from serverware import authority_transition_core as core
    selected = context.exact("policy_authority_evidence_verifications", {
        "verification_receipt_digest": computed["verification_receipt_digest"]})
    profile.require(not selected["present"])
    return computed, core.mutation(operation=context.operation, selected=selected, row=computed)
