"""Native heartbeat facts in the existing protected complete batch journal."""
from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_heartbeat_policy as heartbeat
from serverware import authority_policy_canary_native_opening as opening
from serverware import authority_transition_policy_canary_native_opening as retained


def _scope(state, value):
    s = heartbeat.record(value)
    context, assignment, load, publication = retained.retained(state, value)
    p.require(s["generationId"] == publication["generation_id_digest"]
        and s["runtimeIdentitySha256"] == p.sha256(p.canonical(load["runtimeIdentity"]))
        and s["baselineEventOrdinal"] == load["authoritativeLedgerEventOrdinal"]
        and s["baselineHeadSha256"] == load["authoritativeLedgerHeadSha256"]
        and assignment["observationWindow"]["startsAtUnixNanos"] <= s["observedAtUnixNanos"] < assignment["observationWindow"]["endsAtUnixNanos"]
        and s["issuedAtEpochNs"] <= state.now < s["expiresAtEpochNs"] <= assignment["expiresAtUnixNanos"])
    # Actual native purpose is independently reverified from current signed
    # configuration at BOTH verifier/planner admission, not this returned dict.
    state.charge(64)
    return s, load


def originals(state, value):
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
                    p.require(observation == result(record))
                    found.append(record)
        state.charge(len(batch["events"]) + 1)
    p.require(len(found) <= 32)
    return found


def result(value):
    s = heartbeat.record(value)
    return {"apiVersion": heartbeat.RECORD, "coverage": "native-heartbeat-only", "recordSha256": p.sha256(p.canonical(value)),
        "generationId": s["generationId"], "heartbeatSequence": s["heartbeatSequence"], "eventOrdinal": s["eventOrdinal"],
        "headSha256": s["headSha256"], "observedAtUnixNanos": s["observedAtUnixNanos"], "okForAction": False}


def apply(state, value):
    s, load = _scope(state, value)
    prior = sorted(originals(state, value), key=lambda item: item["evidence"]["statement"]["heartbeatSequence"])
    previous = s["generationId"]
    observed = max(load["issuedAtUnixNanos"], load["loadedAtUnixNanos"])
    ordinal, head = s["baselineEventOrdinal"], s["baselineHeadSha256"]
    for sequence, record in enumerate(prior, 1):
        old = heartbeat.record(record)
        p.require(old["heartbeatSequence"] == sequence and old["previousHeartbeatSha256"] == previous
            and old["observedAtUnixNanos"] >= observed and old["eventOrdinal"] >= ordinal
            and (old["eventOrdinal"] != ordinal or old["headSha256"] == head)
            and all(record[name] == value[name] for name in heartbeat.RECORD_FIELDS - {"apiVersion", "evidence"}))
        previous, observed, ordinal, head = p.sha256(p.canonical(record)), old["observedAtUnixNanos"], old["eventOrdinal"], old["headSha256"]
    p.require(s["heartbeatSequence"] == len(prior) + 1 and s["previousHeartbeatSha256"] == previous
        and 0 <= s["observedAtUnixNanos"] - observed <= 60_000_000_000
        and s["eventOrdinal"] >= ordinal and (s["eventOrdinal"] != ordinal or s["headSha256"] == head))
    openings = []
    for row in state.rows(p.TABLE):
        if any(row[name] != value[name] for name in ("canary_id", "instance_id", "boot_id")):
            continue
        p.row_original(row)
        for event in p.batch(row["batch_original"])["events"]:
            record = event["record"]
            if event["kind"] == "custody" and record.get("apiVersion") == opening.SCHEMA:
                receipt = record["opening_receipt"]
                if receipt["generation_id"] == s["generationId"] and receipt["event_ordinal"] <= s["eventOrdinal"]:
                    p.require(receipt["event_ordinal"] > s["baselineEventOrdinal"])
                    openings.append(receipt)
    latest = max(openings, key=lambda item: item["ingress_sequence"], default=None)
    p.require(s["lastIngressSequence"] == (None if latest is None else latest["ingress_sequence"])
        and s["openingReceiptSha256"] == (None if latest is None else latest["signed_receipt_sha256"]))
    return result(value)


def validate_checkpoint_heartbeat(state, record):
    """Current scope plus exact prior committed original/result, no status DTO.

    Caller must embed this original in the closed cumulative record; actual
    verifier/planner re-admits the new heartbeat purpose before this transition.
    """
    _scope(state, record)
    prior = originals(state, record)
    matches = [item for item in prior if p.canonical(item) == p.canonical(record)]
    p.require(len(matches) == 1, "checkpoint heartbeat was not definitely consumed")
    p.require(record["evidence"]["statement"]["heartbeatSequence"] == max(
        item["evidence"]["statement"]["heartbeatSequence"] for item in prior), "checkpoint cannot use a superseded heartbeat")
    return result(record)
