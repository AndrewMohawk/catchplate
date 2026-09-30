"""New openings retained atomically in the existing authenticated batch journal.

No old custody/ingress head is synthesized. Complete before-roots cover every
prior batch: another request ID cannot re-admit a receipt or skip an opening.
"""
from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_native_opening as opening
from serverware import authority_transition_policy_canary_handoff as handoff
from serverware import authority_transition_policy_canary_custody as custody
from serverware.authority_transition_policy_canary_state import exact


def retained(state, value):
    from serverware import db
    context = state.runtime_context(value)
    exact(value, context, ("assignment_envelope_digest", "assignment_payload_digest", "load_receipt_envelope_digest"))
    custody.observing(state, value)
    assignment = state.one("policy_canary_assignments", canary_id=value["canary_id"])
    # Current signature verification over the complete retained payload and
    # its actual protected projection, not reconstruction of the initial intake.
    state.static("canary_assignment", assignment, "assignment",
        db._candidate_authority_signed_record(assignment, current_prefix="assignment"), persist=False)
    load = state.one("policy_canary_load_receipts", canary_id=value["canary_id"], instance_id=value["instance_id"], boot_id=value["boot_id"])
    # Reverify its genuine direct original under the currently assigned key.
    # This is not a reconstructed historical verification receipt.
    state.runtime("load_receipt", load, "load_receipt", db._candidate_authority_signed_record(load, current_prefix="load_receipt"), persist=False)
    publication = state.one("policy_shadow_generation_publications", canary_id=value["canary_id"],
        instance_id=value["instance_id"], boot_id=value["boot_id"],
        generation_publication_envelope_digest=value["publication_envelope_digest"])
    handoff.generation(state, publication)
    assignment_payload = db.loads(assignment["assignment_payload_json"], None)
    load_payload = db.loads(load["load_receipt_payload_json"], None)
    return context, assignment_payload, load_payload, publication


def apply(state, value):
    profile.require(type(value) is dict and set(value) == opening.FIELDS and value["apiVersion"] == opening.SCHEMA)
    context, assignment_payload, load_payload, publication = retained(state, value)
    result = opening.verify(value, assignment=assignment_payload, load=load_payload, context=context, publication=publication, now=state.now)
    state.charge(512 + len(assignment_payload["authorityKeyIndependence"]["bindings"]))
    key = value["opening_receipt"]["signing_key_spki_sha256"]
    profile.require(not any(row["assignment_envelope_digest"] == context["assignment_envelope_digest"]
        and row["public_key_digest"] == key for row in state.rows("policy_runtime_role_key_revocations")))
    prior = []
    for row in state.rows(profile.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        # Authenticated protected rows, not caller snapshots. The planner proves
        # completeness. Preserve each original batch and its actual commit result.
        profile.row_original(row)
        batch = profile.batch(row["batch_original"])
        state.charge(len(batch["events"]) + 1)
        for event in batch["events"]:
            record = event["record"]
            if event["kind"] == "custody" and record.get("apiVersion") == opening.SCHEMA:
                receipt = record["opening_receipt"]
                if receipt["generation_id"] == result["generationId"]:
                    profile.require(record["assignment_envelope_digest"] == value["assignment_envelope_digest"]
                        and record["publication_envelope_digest"] == value["publication_envelope_digest"])
                    prior.append(receipt["ingress_sequence"])
    profile.require(len(prior) == len(set(prior)) and sorted(prior) == list(range(
        load_payload["ingressRangeStartSequence"], load_payload["ingressRangeStartSequence"] + len(prior))))
    expected = load_payload["ingressRangeStartSequence"] if not prior else max(prior) + 1
    profile.require(result["ingressSequence"] == expected, "opening is repeated, skipped, or from an unresolved predecessor")
    return result
