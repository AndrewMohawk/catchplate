"""Runtime originals consume real protected opening/terminal associations."""
from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_native_opening as opening
from serverware import authority_policy_canary_native_runtime as runtime
from serverware import authority_transition_policy_canary_native_opening as predecessor
from serverware import authority_policy_canary_native_observation_originals as observations


def apply(state, value, kind):
    response = type(value) is dict and value.get("apiVersion") == runtime.RESPONSE_SCHEMA
    profile.require(type(value) is dict and set(value) == (runtime.RESPONSE_FIELDS if response else runtime.FIELDS)
        and value["apiVersion"] == (runtime.RESPONSE_SCHEMA if response else runtime.SCHEMA))
    context, assignment, load, publication = predecessor.retained(state, value)
    receipt = value["receipt"]
    profile.require(type(receipt) is dict and set(receipt) == opening.RECEIPT_FIELDS)
    prior_openings, prior_terminals, prior_candidates, prior_responses = [], [], [], []
    for row in state.rows(profile.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        profile.row_original(row)
        batch = profile.batch(row["batch_original"])
        state.charge(len(batch["events"]) + 1)
        for event in batch["events"]:
            record = event["record"]
            marker = record.get("apiVersion")
            if event["kind"] == "custody" and marker in opening.SCHEMAS:
                original, selected = record["opening_receipt"], prior_openings
            elif marker == runtime.SCHEMA and event["kind"] in {"active-decision", "shadow-observation"}:
                original = record["receipt"]
                selected = prior_terminals if event["kind"] == "active-decision" else prior_candidates
            elif marker == runtime.RESPONSE_SCHEMA and event["kind"] == "shadow-observation":
                original, selected = record["receipt"], prior_responses
            else:
                continue
            if (original["generation_id"], original["ingress_sequence"]) != (receipt["generation_id"], receipt["ingress_sequence"]):
                continue
            profile.require(all(record[name] == value[name] for name in ("assignment_envelope_digest", "assignment_payload_digest",
                "load_receipt_envelope_digest", "publication_envelope_digest")))
            selected.append(record)
    profile.require(len(prior_openings) == 1 and not prior_responses and len(prior_candidates) == (1 if response else 0),
        "runtime original is duplicated or lacks its definite opening/request observation")
    profile.require(len(prior_terminals) == (0 if kind == "active-decision" else 1),
        "terminal is duplicated or candidate lacks its exact consumed terminal")
    result = runtime.verify(value, kind=kind, assignment=assignment, context=context, publication=publication,
        opening_record=prior_openings[0], terminal_record=prior_terminals[0] if prior_terminals else None, now=state.now,
        request_record=prior_candidates[0] if prior_candidates else None)
    if observations.decoded(receipt).get("domain") == observations.EVENT_V2:
        actual = [item["receipt"] for item in prior_terminals + prior_candidates] + [receipt]
        observations.validate_protected_originals(state, value, actual, publication, load)
    state.charge(512 + len(assignment["authorityKeyIndependence"]["bindings"]))
    key = receipt["signing_key_spki_sha256"]
    profile.require(not any(row["assignment_envelope_digest"] == context["assignment_envelope_digest"]
        and row["public_key_digest"] == key for row in state.rows("policy_runtime_role_key_revocations")))
    # Existing batch original/result + protected delivery consume are committed
    # together by the enclosing intake. No legacy decision/ingress/head rows,
    # checkpoint or readiness statement is fabricated from this carrier.
    return result
