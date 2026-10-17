"""Current protected lineage and nonoverlapping exact compaction intervals."""
from catchplate import authority_policy_canary as profile
from catchplate import authority_policy_canary_native_checkpoint as checkpoint
from catchplate import authority_policy_canary_native_opening as opening
from catchplate import authority_policy_canary_native_runtime as runtime
from catchplate import authority_transition_policy_canary_native_opening as predecessor


def apply(state, value):
    profile.require(type(value) is dict and set(value) == checkpoint.FIELDS and value["apiVersion"] == checkpoint.SCHEMA)
    context, assignment, load, publication = predecessor.retained(state, value)
    result = checkpoint.verify(value, assignment=assignment, context=context, publication=publication, now=state.now)
    receipt, covered = value["receipt"], value["ordered_range"]["receipts"]
    state.charge(512 + len(assignment["authorityKeyIndependence"]["bindings"]) + len(covered))
    profile.require(not any(row["assignment_envelope_digest"] == context["assignment_envelope_digest"]
        and row["public_key_digest"] == receipt["signing_key_spki_sha256"] for row in state.rows("policy_runtime_role_key_revocations")))
    prior, matched = [], set()
    by_ordinal = {row["eventOrdinal"]: row for row in covered}
    for row in state.rows(profile.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        profile.row_original(row)
        batch = profile.batch(row["batch_original"])
        state.charge(len(batch["events"]) + 1)
        for event in batch["events"]:
            record = event["record"]
            marker = record.get("apiVersion")
            if marker == checkpoint.SCHEMA and event["kind"] == "checkpoint":
                original, is_checkpoint = record["receipt"], True
            elif marker in opening.SCHEMAS and event["kind"] == "custody":
                original, is_checkpoint = record["opening_receipt"], False
            elif marker in {runtime.SCHEMA, runtime.RESPONSE_SCHEMA} and event["kind"] in {"active-decision", "shadow-observation"}:
                original, is_checkpoint = record["receipt"], False
            else:
                continue
            if original["generation_id"] != receipt["generation_id"]:
                continue
            profile.require(all(record[name] == value[name] for name in ("assignment_envelope_digest", "assignment_payload_digest",
                "load_receipt_envelope_digest", "publication_envelope_digest")))
            if is_checkpoint:
                prior.append(record)
                continue
            reference = by_ordinal.get(original["event_ordinal"])
            if reference is None:
                continue
            expected = {"eventOrdinal": original["event_ordinal"], "eventSha256": original["event_sha256"],
                "canonicalEventLength": len(original["canonical_event_bytes"]),
                "canonicalEventSha256": profile.sha256(bytes(original["canonical_event_bytes"])),
                "predecessorEventOrdinal": original["predecessor_event_ordinal"], "predecessorHeadSha256": original["predecessor_head_sha256"],
                "resultingHeadSha256": original["resulting_head_sha256"], "signedReceiptSha256": original["signed_receipt_sha256"],
                "retrievalIdSha256": original["retrieval_id_sha256"], "retrievalProofSha256": original["retrieval_proof_sha256"]}
            profile.require(profile.canonical(reference) == profile.canonical(expected)
                and original["trusted_observed_at_unix_nanos"] <= receipt["trusted_observed_at_unix_nanos"]
                and original["event_ordinal"] not in matched, "checkpoint differs from a protected observation original")
            matched.add(original["event_ordinal"])
    # Every interval must join genuine already-consumed runtime evidence.
    # Unexported event types remain commitments, not invented observations.
    profile.require(bool(matched), "checkpoint has no protected runtime observation in its interval")
    prior.sort(key=lambda row: row["receipt"]["compacted_first_event_ordinal"])
    baseline = load["authoritativeLedgerEventOrdinal"]
    profile.require(type(baseline) is int and 0 <= baseline < 9_223_372_036_854_775_807)
    expected_first, previous = baseline + 1, None
    for record in prior:
        old = record["receipt"]
        profile.require(old["compacted_first_event_ordinal"] == expected_first)
        expected_first = old["compacted_last_event_ordinal"] + 1
        previous = record
    profile.require(receipt["compacted_first_event_ordinal"] == expected_first,
        "checkpoint repeats, overlaps or skips a prior protected interval")
    if previous is not None:
        profile.require(covered[0]["predecessorHeadSha256"] == previous["ordered_range"]["receipts"][-1]["resultingHeadSha256"]
            and receipt["trusted_observed_at_unix_nanos"] >= previous["receipt"]["trusted_observed_at_unix_nanos"])
    else:
        profile.require(covered[0]["predecessorHeadSha256"] == load["authoritativeLedgerHeadSha256"],
            "first checkpoint must extend the genuine protected load baseline")
    # The enclosing kernel atomically retains this complete original/result,
    # audit and exact delivery consume. Never create legacy checkpoint/readiness.
    return result
