"""Native heartbeat facts in the existing protected complete batch journal."""
from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_finalization_policy as heartbeat
from serverware import authority_policy_canary_native_opening as opening
from serverware import authority_transition_policy_canary_native_opening as retained


def _scope(state, value):
    s = heartbeat.record(value)
    context, assignment, load, publication = retained.retained(state, value)
    p.require(s["generationId"] == publication["generation_id_digest"]
        and s["runtimeIdentitySha256"] == p.sha256(p.canonical(load["runtimeIdentity"]))
        and s["baselineEventOrdinal"] == load["authoritativeLedgerEventOrdinal"]
        and s["baselineHeadSha256"] == load["authoritativeLedgerHeadSha256"]
        and assignment["observationWindow"]["startsAtUnixNanos"] <= s["observedAtUnixNanos"] < assignment["observationWindow"]["sealDeadlineUnixNanos"]
        and s["issuedAtEpochNs"] <= state.now < s["expiresAtEpochNs"] <= min(assignment["expiresAtUnixNanos"],
            load["expiresAtUnixNanos"], assignment["observationWindow"]["sealDeadlineUnixNanos"]))
    if s["seal"] is not None:
        p.require(s["seal"]["windowEndsAtUnixNanos"] == assignment["observationWindow"]["endsAtUnixNanos"]
            and s["seal"]["sealDeadlineUnixNanos"] == assignment["observationWindow"]["sealDeadlineUnixNanos"])
    # Actual native purpose is independently reverified from current signed
    # configuration at BOTH verifier/planner admission, not this returned dict.
    state.charge(64)
    return s, load, (context, assignment, load, publication)


def heartbeat_originals(state, value):
    found = []
    for row in state.rows(p.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        p.row_original(row)
        batch = p.batch(row["batch_original"])
        completion = p.document(row["result_original"].encode("ascii"), p.MAX_RESULT)
        p.result(completion)
        p.require(completion["accepted"] == len(batch["events"]) == len(completion["results"]))
        for event, stored in zip(batch["events"], completion["results"]):
            record = event["record"]
            if event["kind"] == "custody" and record.get("apiVersion") == heartbeat.RECORD:
                s = heartbeat.record(record)
                if s["generationId"] == value["evidence"]["statement"]["generationId"]:
                    digest = p.sha256(p.canonical(record))
                    p.require(stored["kind"] == "custody" and stored["recordSha256"] == digest)
                    observation = p.document(stored["storedOriginal"].encode("ascii"), 65536)
                    p.require(observation == heartbeat_result(record))
                    found.append(record)
        state.charge(len(batch["events"]) + 1)
    p.require(len(found) <= 32)
    return found


def heartbeat_result(value):
    s = heartbeat.record(value)
    return {"apiVersion": heartbeat.RECORD, "coverage": "native-finalization-heartbeat-only", "recordSha256": p.sha256(p.canonical(value)),
        "generationId": s["generationId"], "heartbeatSequence": s["heartbeatSequence"], "eventOrdinal": s["eventOrdinal"],
        "headSha256": s["headSha256"], "observedAtUnixNanos": s["observedAtUnixNanos"], "okForAction": False}


def apply_heartbeat(state, value):
    s, load, retained_scope = _scope(state, value)
    prior = sorted(heartbeat_originals(state, value), key=lambda item: item["evidence"]["statement"]["heartbeatSequence"])
    previous = s["generationId"]
    observed = max(load["issuedAtUnixNanos"], load["loadedAtUnixNanos"], retained_scope[1]["observationWindow"]["startsAtUnixNanos"])
    ordinal, head = s["baselineEventOrdinal"], s["baselineHeadSha256"]
    for sequence, record in enumerate(prior, 1):
        old = heartbeat.record(record)
        p.require(old["seal"] is None and old["heartbeatSequence"] == sequence and old["previousHeartbeatSha256"] == previous
            and old["observedAtUnixNanos"] >= observed and old["eventOrdinal"] >= ordinal
            and (old["eventOrdinal"] != ordinal or old["headSha256"] == head)
            and all(record[name] == value[name] for name in heartbeat.RECORD_FIELDS - {"apiVersion", "evidence"}))
        previous, observed, ordinal, head = p.sha256(p.canonical(record)), old["observedAtUnixNanos"], old["eventOrdinal"], old["headSha256"]
    p.require(s["heartbeatSequence"] == len(prior) + 1 and s["previousHeartbeatSha256"] == previous
        and 0 < s["observedAtUnixNanos"] - observed <= 60_000_000_000
        and s["eventOrdinal"] >= ordinal and (s["eventOrdinal"] != ordinal or s["headSha256"] == head))
    openings = []
    for row in state.rows(p.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        p.row_original(row)
        for event in p.batch(row["batch_original"])["events"]:
            record = event["record"]
            if event["kind"] == "custody" and record.get("apiVersion") in opening.SCHEMAS:
                receipt = record["opening_receipt"]
                if receipt["generation_id"] == s["generationId"] and receipt["event_ordinal"] <= s["eventOrdinal"]:
                    p.require(receipt["event_ordinal"] > s["baselineEventOrdinal"])
                    openings.append(receipt)
    latest = max(openings, key=lambda item: item["ingress_sequence"], default=None)
    p.require(s["lastIngressSequence"] == (None if latest is None else latest["ingress_sequence"])
        and s["openingReceiptSha256"] == (None if latest is None else latest["signed_receipt_sha256"]))
    return heartbeat_result(value)


def validate_checkpoint_heartbeat(state, record):
    """Current scope plus exact prior committed original/result, no status DTO.

    Caller must embed this original in the closed cumulative record; actual
    verifier/planner re-admits the new heartbeat purpose before this transition.
    """
    _, load, scope = _scope(state, record)
    prior = sorted(heartbeat_originals(state, record), key=lambda item: item["evidence"]["statement"]["heartbeatSequence"])
    matches = [item for item in prior if p.canonical(item) == p.canonical(record)]
    p.require(len(matches) == 1, "checkpoint heartbeat was not definitely consumed")
    p.require(record["evidence"]["statement"]["heartbeatSequence"] == max(
        item["evidence"]["statement"]["heartbeatSequence"] for item in prior), "checkpoint cannot use a superseded heartbeat")
    previous = record["evidence"]["statement"]["generationId"]
    observed = max(load["issuedAtUnixNanos"], load["loadedAtUnixNanos"], scope[1]["observationWindow"]["startsAtUnixNanos"])
    ordinal, head = load["authoritativeLedgerEventOrdinal"], load["authoritativeLedgerHeadSha256"]
    for sequence, item in enumerate(prior, 1):
        old = heartbeat.record(item)
        p.require(old["heartbeatSequence"] == sequence and old["previousHeartbeatSha256"] == previous
            and 0 < old["observedAtUnixNanos"] - observed <= 60_000_000_000
            and old["eventOrdinal"] >= ordinal and (old["eventOrdinal"] != ordinal or old["headSha256"] == head)
            and (old["seal"] is None or sequence == len(prior))
            and all(item[name] == record[name] for name in heartbeat.RECORD_FIELDS - {"apiVersion", "evidence"}))
        previous, observed, ordinal, head = p.sha256(p.canonical(item)), old["observedAtUnixNanos"], old["eventOrdinal"], old["headSha256"]
    return heartbeat_result(record)


def checkpoints(state, value):
    from serverware import authority_policy_canary_native_final_cumulative as cumulative
    found = []
    for row in state.rows(p.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        p.row_original(row)
        batch = p.batch(row["batch_original"])
        completion = p.result(p.document(row["result_original"].encode("ascii"), p.MAX_RESULT))
        for event, outcome in zip(batch["events"], completion["results"]):
            record = event["record"]
            if event["kind"] == "checkpoint" and record.get("apiVersion") == cumulative.SCHEMA:
                if record["accounting"]["generationId"] == value["accounting"]["generationId"]:
                    p.require(all(record[name] == value[name] for name in ("assignment_envelope_digest", "assignment_payload_digest",
                        "load_receipt_envelope_digest", "publication_envelope_digest")))
                    stored = p.document(outcome["storedOriginal"].encode("ascii"), p.MAX_RESULT)
                    p.require(outcome["kind"] == "checkpoint" and outcome["recordSha256"] == p.sha256(p.canonical(record))
                        and stored["recordSha256"] == outcome["recordSha256"] and stored["generationId"] == record["accounting"]["generationId"]
                        and stored["coverage"] == ("complete-native-final-seal" if record["seal"] is not None else "complete-native-finalization-prefix"))
                    found.append(record)
        state.charge(len(batch["events"]) + 1)
    return sorted(found, key=lambda record: record["checkpoint_sequence"])


def _checkpoint(state, value, *, existing=False, include_observations=False):
    from serverware import authority_policy_canary_native_final_cumulative as cumulative
    from serverware import authority_policy_canary_native_checkpoint as interval
    p.require(type(value) is dict and set(value) == cumulative.FIELDS and value["apiVersion"] == cumulative.SCHEMA)
    context, assignment, load, publication = retained.retained(state, value)
    originals = value["accounting"]["originals"]
    p.require(type(originals) is list and 0 <= len(originals) <= 64)
    state.charge(512 + len(originals) * (32 + len(assignment["authorityKeyIndependence"]["bindings"])))
    validate_checkpoint_heartbeat(state, value["heartbeat"])
    computed = cumulative.verify(value, assignment=assignment, load=load, context=context, publication=publication, now=state.now)
    from serverware import authority_policy_canary_native_observation_originals as observations
    admitted_observations = observations.validate_protected_originals(state, value, originals, publication, load)
    used = {receipt["signing_key_spki_sha256"] for receipt in originals}
    p.require(not any(row["assignment_envelope_digest"] == context["assignment_envelope_digest"]
        and row["public_key_digest"] in used for row in state.rows("policy_runtime_role_key_revocations")))
    prior = checkpoints(state, value)
    matches = [record for record in prior if p.canonical(record) == p.canonical(value)]
    if existing:
        p.require(len(matches) == 1 and prior[-1] == matches[0], "readiness needs exact latest consumed checkpoint")
    else:
        p.require(not matches, "final checkpoint cannot replay")
        prior.append(value)
    previous, old = None, None
    for sequence, record in enumerate(prior, 1):
        p.require(record["checkpoint_sequence"] == sequence and record["previous_checkpoint_sha256"] == previous)
        accounting = record["accounting"]
        if old is not None:
            p.require(old["seal"] is None and accounting["lastEventOrdinal"] >= old["accounting"]["lastEventOrdinal"]
                and accounting["observedAtUnixNanos"] > old["accounting"]["observedAtUnixNanos"]
                and p.canonical(accounting["originals"][:old["accounting"]["originalCount"]]) == p.canonical(old["accounting"]["originals"]),
                "final cumulative history cannot reopen, skip a prefix, replay idle time or bypass uncertainty")
        previous, old = p.sha256(p.canonical(record)), record
    # A consumed interval is optional only when no such interval has been
    # produced. The complete signed originals are mandatory in both cases.
    intervals = []
    for row in state.rows(p.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        p.row_original(row)
        batch = p.batch(row["batch_original"])
        completion = p.result(p.document(row["result_original"].encode("ascii"), p.MAX_RESULT))
        for event, outcome in zip(batch["events"], completion["results"]):
            item = event["record"]
            if event["kind"] == "checkpoint" and item.get("apiVersion") == interval.SCHEMA and item["receipt"]["generation_id"] == computed["generationId"]:
                stored = p.document(outcome["storedOriginal"].encode("ascii"), p.MAX_RESULT)
                p.require(stored["coverage"] == "contiguous-spool-interval"
                    and stored["recordSha256"] == p.sha256(p.canonical(item)))
                intervals.append(item)
        state.charge(len(batch["events"]) + 1)
    if value["interval_receipt_sha256"] is None:
        p.require(not intervals)
    else:
        selected = [item for item in intervals if item["receipt"]["signed_receipt_sha256"] == value["interval_receipt_sha256"]]
        p.require(len(selected) == 1)
        selected = selected[0]
        for reference in selected["ordered_range"]["receipts"]:
            offset = reference["eventOrdinal"] - value["accounting"]["baselineEventOrdinal"] - 1
            p.require(0 <= offset < len(originals))
            original = originals[offset]
            p.require(reference["signedReceiptSha256"] == original["signed_receipt_sha256"]
                and reference["eventSha256"] == original["event_sha256"] and reference["resultingHeadSha256"] == original["resulting_head_sha256"])
        p.require(selected["receipt"]["trusted_observed_at_unix_nanos"] <= value["accounting"]["observedAtUnixNanos"])
    scope = {"context": context, "assignment": assignment, "load": load, "publication": publication,
        "accounting": value["accounting"], "seal": value["seal"]}
    if include_observations:
        scope["observations"] = admitted_observations
    return computed, scope


def apply_checkpoint(state, value):
    return _checkpoint(state, value)[0]


def validate_readiness_checkpoint(state, record, *, include_observations=False):
    """Current protected scope and exact latest consumed final original.

    Actual verifier AND planner must also re-admit the nested finalization
    purpose against their independently signed CURRENT configuration. This
    helper never turns prior acceptance, a SELECT, or a caller DTO into that
    permission. No new expiry, contact, checkpoint or activation is created.
    """
    p.require(record.get("seal") is not None)
    return _checkpoint(state, record, existing=True, include_observations=include_observations)[1]


def require_unsealed(state, value, generation):
    from serverware import authority_policy_canary_native_final_cumulative as cumulative
    for row in state.rows(p.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        p.row_original(row)
        for event in p.batch(row["batch_original"])["events"]:
            record = event["record"]
            p.require(not (event["kind"] == "checkpoint" and record.get("apiVersion") == cumulative.SCHEMA
                and record["accounting"]["generationId"] == generation and record["seal"] is not None),
                "closed native generation cannot append after its final seal")
