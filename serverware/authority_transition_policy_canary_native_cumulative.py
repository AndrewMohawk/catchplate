"""Exact cumulative successor over protected originals and current authority."""
from serverware import authority_policy_canary as profile
from serverware import authority_policy_canary_native_cumulative as cumulative
from serverware import authority_policy_canary_native_checkpoint as interval
from serverware import authority_transition_policy_canary_native_opening as predecessor
from serverware import authority_policy_canary_native_observation_originals as observations


def apply(state, value):
    from serverware import authority_transition_policy_canary_native_heartbeat as heartbeat
    profile.require(type(value) is dict and set(value) == cumulative.FIELDS and value["apiVersion"] == cumulative.SCHEMA)
    context, assignment, load, publication = predecessor.retained(state, value)
    originals = value["accounting"]["originals"]
    profile.require(type(originals) is list and 1 <= len(originals) <= 64)
    # Charge every actual inner-key inventory/signature/chain operation before
    # doing it; large assignment inventories may exhaust the unchanged bound.
    state.charge(512 + len(originals) * (32 + len(assignment["authorityKeyIndependence"]["bindings"])))
    heartbeat.validate_checkpoint_heartbeat(state, value["heartbeat"])
    result = cumulative.verify(value, assignment=assignment, load=load, context=context, publication=publication, now=state.now)
    observations.validate_protected_originals(state, value, originals, publication, load, assignment=assignment, context=context)
    revoked = state.rows("policy_runtime_role_key_revocations")
    used = {receipt["signing_key_spki_sha256"] for receipt in originals}
    profile.require(not any(row["assignment_envelope_digest"] == context["assignment_envelope_digest"]
        and row["public_key_digest"] in used for row in revoked))
    prior, intervals = [], []
    for row in state.rows(profile.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        profile.row_original(row)
        batch = profile.batch(row["batch_original"])
        completed = profile.result(profile.document(row["result_original"].encode("ascii"), profile.MAX_RESULT))
        state.charge(len(batch["events"]) + 1)
        for event, outcome in zip(batch["events"], completed["results"]):
            record = event["record"]
            if event["kind"] != "checkpoint" or record.get("apiVersion") not in {cumulative.SCHEMA, interval.SCHEMA}:
                continue
            generation = record["accounting"]["generationId"] if record["apiVersion"] == cumulative.SCHEMA else record["receipt"]["generation_id"]
            if generation != result["generationId"]:
                continue
            profile.require(all(record[name] == value[name] for name in ("assignment_envelope_digest", "assignment_payload_digest",
                "load_receipt_envelope_digest", "publication_envelope_digest")))
            stored = profile.document(outcome["storedOriginal"].encode("ascii"), profile.MAX_RESULT)
            profile.require(stored["recordSha256"] == profile.sha256(profile.canonical(record)) and stored["generationId"] == generation)
            if record["apiVersion"] == cumulative.SCHEMA:
                profile.require(stored["coverage"] == "complete-native-prefix-not-readiness")
                prior.append(record)
            elif record["receipt"]["signed_receipt_sha256"] == value["interval_receipt_sha256"]:
                profile.require(stored["coverage"] == "contiguous-spool-interval")
                intervals.append(record)
    profile.require(len(intervals) == 1, "cumulative checkpoint has no unique consumed compaction original")
    accounting = value["accounting"]
    for reference in intervals[0]["ordered_range"]["receipts"]:
        offset = reference["eventOrdinal"] - accounting["baselineEventOrdinal"] - 1
        profile.require(0 <= offset < len(originals))
        original = originals[offset]
        profile.require(reference["signedReceiptSha256"] == original["signed_receipt_sha256"]
            and reference["eventSha256"] == original["event_sha256"]
            and reference["resultingHeadSha256"] == original["resulting_head_sha256"])
    profile.require(intervals[0]["receipt"]["trusted_observed_at_unix_nanos"] <= accounting["observedAtUnixNanos"])
    prior.sort(key=lambda item: item["checkpoint_sequence"])
    previous = None
    for sequence, record in enumerate(prior, 1):
        profile.require(record["checkpoint_sequence"] == sequence and record["previous_checkpoint_sha256"] == previous)
        previous = profile.sha256(profile.canonical(record))
    profile.require(value["checkpoint_sequence"] == len(prior) + 1 and value["previous_checkpoint_sha256"] == previous,
        "cumulative identity cannot reset, replay or bypass a protected predecessor")
    if prior:
        old = prior[-1]["accounting"]
        profile.require(accounting["lastEventOrdinal"] > old["lastEventOrdinal"]
            and accounting["observedAtUnixNanos"] >= old["observedAtUnixNanos"]
            and profile.canonical(originals[:old["originalCount"]]) == profile.canonical(old["originals"]),
            "cumulative successor must extend every exact previous signed original")
    return result
