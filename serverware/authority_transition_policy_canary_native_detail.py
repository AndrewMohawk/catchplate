"""Derive a complete native ingress census from freshly admitted originals.

Only the fixed readiness transition calls this helper, immediately after the
finalization owner re-admits the consumed checkpoint under current authority.
Its data is not a verification token, Fleet signature or activation permission.
"""
from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_native_observation_originals as originals
from serverware import authority_policy_canary_native_observation_semantics as semantics

PROFILE = "serverware.nativePolicyObservationResult/v1"
_TERMINAL = frozenset({"active-pre-dispatch-terminal", "response-terminal-appended"})
_UNREADY = frozenset({"failure", "cleanup-quarantined", "unsupported-required-ingress"})


def _one(events, label):
    selected = [(event, receipt) for event, receipt in events if event["event"] == label]
    p.require(len(selected) == 1, "native detail requires one actual " + label + " original")
    return selected[0]


def readiness_observations(state, record, compiler, *, admitted):
    from serverware import db
    # This keyword is an internal source-to-source join, never a wire field.
    # Do not independently re-run the same full signature admission here.
    p.require(admitted["accounting"] == record["accounting"] and admitted["seal"] == record["seal"]
        and admitted["seal"] is not None and semantics.RESULT_PROFILE == PROFILE)
    accounting = admitted["accounting"]
    detailed = admitted["observations"]
    analysis = db.loads(compiler["analysis_payload_json"], None)
    admissions, events_by_ingress = {}, {}
    for receipt in accounting["originals"]:
        event = originals.decoded(receipt)
        sequence = receipt["ingress_sequence"]
        if type(event) is list:
            p.require(sequence not in admissions, "native ingress repeats its opening")
            admissions[sequence] = (event, receipt)
            events_by_ingress[sequence] = []
        else:
            p.require(sequence in admissions and event["event"] not in _UNREADY,
                "native detail cannot omit an unsuccessful or unopened ingress")
            events_by_ingress[sequence].append((event, receipt))
    p.require(0 < len(admissions) == accounting["counters"]["admitted"] <= 64)
    first = admitted["assignment"]["observationWindow"]["firstIngressSequence"]
    p.require(list(admissions) == list(range(first, first + len(admissions))))
    results, evaluated = [], set()
    for sequence, (opening, opening_receipt) in admissions.items():
        events = events_by_ingress[sequence]
        terminal_receipt = request_receipt = response_receipt = None
        request_original = response_original = None
        if opening[3]["decision"] == "excluded-by-assignment":
            event, _ = _one(events, "sampled-out")
            p.require(len(events) == 1 and sequence not in detailed
                and event["responseFactsSha256"] == opening_receipt["request_commitment_sha256"],
                "sampling exclusion needs its actual signed matching exclusion event")
            result = {"status": "excluded", "reason": "deterministic-assignment-sampling"}
            facts = {"state": "unavailable", "reason": "deterministic-assignment-sampling"}
        else:
            p.require(opening[3]["decision"] == "included" and sequence in detailed
                and not any(event["event"] in {"sampled-out", "transport-excluded"} for event, _ in events),
                "included ingress lacks its actual detailed evaluation")
            terminals = [(event, receipt) for event, receipt in events if event["event"] in _TERMINAL]
            p.require(len(terminals) == 1, "native ingress requires its unique actual enforcement terminal")
            terminal, terminal_receipt = terminals[0]
            request, request_receipt = _one(events, "candidate-evaluated")
            p.require(detailed[sequence]["request"] == (request, request_receipt))
            request_original = request["observationOriginal"]
            dispatched = terminal["event"] == "response-terminal-appended"
            if dispatched:
                response, response_receipt = _one(events, "response-evaluated")
                p.require(detailed[sequence]["response"] == (response, response_receipt))
                response_original = response["observationOriginal"]
            else:
                p.require(detailed[sequence]["response"] is None
                    and not any(event["event"] == "response-evaluated" for event, _ in events))
            pilot = analysis["pilotRestrictions"]
            state.charge(64 + 4 * len(analysis["authorityAnalysis"]["expansionCells"])
                + 8 * (len(pilot.get("principalSha256s", [])) + len(pilot.get("routeSha256s", []))))
            result = semantics.evaluated(request_original, response_original,
                terminal_receipt=terminal_receipt, request_receipt=request_receipt,
                response_receipt=response_receipt, assignment=admitted["assignment"],
                compiler_payload=analysis, publication=admitted["publication"])
            facts = {"state": "captured", "capturedAtUnixNanos": request_original["factsCapturedAtUnixNanos"],
                "requestCommitmentSha256": opening_receipt["request_commitment_sha256"]}
            evaluated.add(sequence)
        derived = {"apiVersion": PROFILE, "generationId": accounting["generationId"],
            "ingressSequence": sequence, "openingReceiptSha256": opening_receipt["signed_receipt_sha256"],
            "ingressReceiptSha256s": [receipt["signed_receipt_sha256"] for _, receipt in events],
            "terminalReceiptSha256": None if terminal_receipt is None else terminal_receipt["signed_receipt_sha256"],
            "requestReceiptSha256": None if request_receipt is None else request_receipt["signed_receipt_sha256"],
            "responseReceiptSha256": None if response_receipt is None else response_receipt["signed_receipt_sha256"],
            "requestOriginalSha256": None if request_original is None else p.sha256(p.canonical(request_original)),
            "responseOriginalSha256": None if response_original is None else p.sha256(p.canonical(response_original)),
            "compilerAnalysisSha256": compiler["analysis_envelope_digest"],
            "factsState": facts, "result": result}
        results.append({"ingressSequence": sequence, "recordSha256": p.sha256(p.canonical(derived)),
            "factsState": facts, "result": result})
    p.require(evaluated == set(detailed), "native census cannot omit or add detailed observations")
    state.charge(32 + 16 * len(results))
    return tuple(results)
