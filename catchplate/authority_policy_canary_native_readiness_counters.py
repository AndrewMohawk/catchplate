"""Exhaustive native readiness arithmetic; these pure functions confer no trust.

The transition obtains every result from the fixed detailed-original verifier.
No aggregate, histogram, comparable flag or expansion cell count is accepted as
an input. Old Fleet signatures and their verification paths remain unchanged.
"""
from catchplate import authority_policy_canary as p
from catchplate import authority_transition_policy_canary_shadow as semantics

MAX_OBSERVATIONS = 64
_CELL = ("cellSha256", "authorityExpansion", "routeSha256", "operation",
    "compiledSemanticProfileSha256", "requestAuthorityClass", "activeOutcome", "candidateOutcome")
_RESPONSE_EXPANSIONS = frozenset({"response-field-exposure-added", "response-validation-relaxed", "response-filter-reduced"})
_EXPANDING = {("deny", "permit"): "activeDenyCandidatePermit",
    ("deny", "conditional"): "activeDenyCandidateConditional",
    ("conditional", "permit"): "activeConditionalCandidatePermit",
    ("indeterminate", "permit"): "activeIndeterminateCandidatePermit",
    ("indeterminate", "conditional"): "activeIndeterminateCandidateConditional"}
_UNSAFE = ("dropped", "errors", "unavailableEvidence", "unapprovedActiveIndeterminate",
    "candidateIndeterminate", "responseNoncomparable", "responseValidationDivergence", "responseValidatorUnavailable")


def _json(item, field, value):
    original = p.canonical(value).decode("ascii")
    item[field + "_json"], item[field + "_digest"] = original, p.sha256(original.encode("ascii"))


def projection(result, contract, compiler):
    """Check the complete semantic projection again, after provenance admission."""
    from catchplate import db
    p.require(type(result) is dict and "status" in result)
    status = result["status"]
    p.require(status in {"evaluated", "dropped", "error", "excluded", "transport-excluded"})
    item = {"observation_status": status, "active_outcome": "indeterminate", "candidate_outcome": "indeterminate",
        "candidate_dispatch_commitment_digest": None, "drop_reason": None, "error_reason": None}
    active = {"final_active_outcome": "indeterminate", "upstream_dispatch_authorized": 0,
        "active_dispatch_commitment_digest": None}
    values = {"authority_binding": None, "expansion_cells": [], "pilot_membership": None,
        "response_obligation": None, "response_comparison": None,
        "latency_samples": {name: None for name in db._POLICY_AUTHORITY_LATENCY_SAMPLE_FIELDS.values()}}
    if status == "evaluated":
        p.require(set(result) == {"status", "pureActiveEvaluation", "finalActiveEnforcement", "candidateEvaluation",
            "authorityBinding", "derivedExpansion", "pilotMembership", "responseObligation", "responseComparison", "latencySamples"})
        pure, final, candidate = (result[name] for name in ("pureActiveEvaluation", "finalActiveEnforcement", "candidateEvaluation"))
        p.require(all(type(value) is dict for value in (pure, final, candidate)))
        p.require(pure["outcome"] in db._POLICY_AUTHORITY_OUTCOMES and candidate["outcome"] in db._POLICY_AUTHORITY_OUTCOMES
            and final["finalOutcome"] in {"allow", "deny", "conditional", "error"} and type(final["upstreamDispatchAuthorized"]) is bool
            and candidate["evaluationPurpose"] == "candidate-shadow"
            and candidate["effectCapabilitiesAvailable"] is False and candidate["effectIntentsExecuted"] is False)
        item.update(active_outcome=pure["outcome"], candidate_outcome=candidate["outcome"],
            candidate_dispatch_commitment_digest=p.digest(candidate["dispatchCommitmentSha256"]))
        active.update(final_active_outcome=final["finalOutcome"], upstream_dispatch_authorized=int(final["upstreamDispatchAuthorized"]),
            active_dispatch_commitment_digest=p.digest(pure["dispatchCommitmentSha256"]))
        expansion = result["derivedExpansion"]
        p.require(type(expansion) is dict and set(expansion) == {"cells", "cellsRootSha256"})
        cells = db._policy_authority_semantic_expansion_cells("native observed cells", expansion["cells"], maximum=128, allow_empty=True)
        p.require(expansion["cellsRootSha256"] == db._policy_shadow_merkle_root([(n, cell["cellSha256"]) for n, cell in enumerate(cells, 1)]))
        values.update(authority_binding=result["authorityBinding"], expansion_cells=cells, pilot_membership=result["pilotMembership"],
            response_obligation=result["responseObligation"], response_comparison=result["responseComparison"], latency_samples=result["latencySamples"])
        p.require(type(result["latencySamples"]) is dict
            and result["latencySamples"].get("activeEvaluationNanos") == pure["evaluationNanos"]
            and result["latencySamples"].get("candidateEvaluationNanos") == candidate["evaluationNanos"])
    elif status in {"dropped", "error"}:
        p.require(set(result) == {"status", "reason", "unavailableMarkerSha256", "latencySamples"})
        p.digest(result["unavailableMarkerSha256"])
        item["drop_reason" if status == "dropped" else "error_reason"] = result["reason"]
        values["latency_samples"] = result["latencySamples"]
    elif status == "excluded":
        p.require(result == {"status": "excluded", "reason": "deterministic-assignment-sampling"})
    else:
        p.require(result == {"status": "transport-excluded"})
    for name, value in values.items():
        _json(item, name, value)
    binding, cells, obligation, comparison = semantics.components(item)
    semantics.native_compiler_scope(item, contract, compiler, binding, cells, obligation, comparison, active)
    return item, binding, cells, obligation, comparison


def aggregate(observations, contract, compiler):
    """One independently checked result for every real admitted ingress."""
    from catchplate import db
    p.require(type(observations) is tuple and 1 <= len(observations) <= MAX_OBSERVATIONS)
    value = db._empty_policy_authority_aggregate()
    inc = db._policy_authority_increment
    for observation in observations:
        p.require(type(observation) is dict and set(observation) == {"ingressSequence", "recordSha256", "factsState", "result"})
        p.epoch(observation["ingressSequence"]); p.digest(observation["recordSha256"])
        facts = observation["factsState"]
        p.require(type(facts) is dict and facts.get("state") in {"captured", "unavailable"})
        item, binding, cells, obligation, comparison = projection(observation["result"], contract, compiler)
        totals, status = value["totals"], item["observation_status"]
        inc(totals, "ingressAdmitted")
        inc(totals, {"evaluated": "evaluated", "dropped": "dropped", "error": "errors", "excluded": "excluded",
            "transport-excluded": "excluded"}[status])
        # The source-fixed census owner has already joined these two excluded
        # statuses to the genuine signed opening/sampling and exclusion event.
        # Deliberately not capturing facts is not missing required evidence.
        if facts["state"] == "unavailable" and status not in {"excluded", "transport-excluded"}:
            inc(totals, "unavailableEvidence")
        if status == "evaluated":
            active, candidate = item["active_outcome"], item["candidate_outcome"]
            inc(value["semanticMatrix"], active + ":" + candidate)
            if active == "indeterminate":
                inc(totals, "activeIndeterminate")
                if not cells:
                    inc(totals, "unapprovedActiveIndeterminate")
            if candidate == "indeterminate":
                inc(totals, "candidateIndeterminate")
            if (active, candidate) in _EXPANDING:
                inc(totals, _EXPANDING[(active, candidate)])
            response = comparison["classification"]
            inc(value["responseClasses"], response); inc(value["responseCaptureModes"], comparison["captureMode"])
            if response.startswith("comparable-"):
                inc(totals, "comparableResponses")
            elif response.startswith("not-comparable-"):
                inc(totals, "responseNoncomparable")
            if response == "comparable-validation-divergence":
                inc(totals, "responseValidationDivergence")
            if response == "not-comparable-candidate-validator-unavailable":
                inc(totals, "responseValidatorUnavailable")
            if cells:
                inc(totals, "authorityExpansionObservations")
                if binding["requestAuthorityClass"] == "write":
                    inc(totals, "authorityExpansionWriteObservations")
            for cell in cells:
                entry = value["expansionCells"].setdefault(cell["cellSha256"], {**{name: cell[name] for name in _CELL},
                    "requestCount": 0, "writeRequestCount": 0, "responseCount": 0, "writeResponseCount": 0})
                p.require(all(entry[name] == cell[name] for name in _CELL))
                inc(entry, "requestCount")
                if cell["requestAuthorityClass"] == "write":
                    inc(entry, "writeRequestCount")
                if response.startswith("comparable-"):
                    inc(entry, "responseCount")
                    if cell["requestAuthorityClass"] == "write":
                        inc(entry, "writeResponseCount")
            if obligation is not None:
                route = value["responseRouteCoverage"].setdefault(obligation["routeSha256"], {
                    "routeSha256": obligation["routeSha256"], "obligationRootSha256": obligation["obligationRootSha256"],
                    "comparableResponses": 0, "validationDivergences": 0, "validatorUnavailable": 0, "noncomparable": 0})
                p.require(route["obligationRootSha256"] == obligation["obligationRootSha256"])
                if response.startswith("comparable-"):
                    inc(route, "comparableResponses")
                if response == "comparable-validation-divergence":
                    inc(route, "validationDivergences")
                elif response == "not-comparable-candidate-validator-unavailable":
                    inc(route, "validatorUnavailable")
                elif response.startswith("not-comparable-"):
                    inc(route, "noncomparable")
        elif status in {"dropped", "error"}:
            inc(value["dropReasons" if status == "dropped" else "errorReasons"],
                item["drop_reason" if status == "dropped" else "error_reason"])
        samples = db.loads(item["latency_samples_json"], None)
        for series, field in db._POLICY_AUTHORITY_LATENCY_SAMPLE_FIELDS.items():
            sample = samples[field]
            if sample is not None:
                histogram = value["latencyHistograms"][series]
                bucket = db._policy_authority_latency_bucket_index(sample)
                histogram["buckets"][bucket] += 1
                inc(histogram, "total")
    return db._policy_authority_direct_cumulative_counters(value)


def merge(counters):
    """Checked component-wise sum without trusting a supplied fleet aggregate."""
    p.require(type(counters) is list and 1 <= len(counters) <= 32)
    def add(left, right):
        if type(left) is int:
            p.require(type(right) is int and 0 <= right <= 2**63 - 1 and 0 <= left <= 2**63 - 1 - right)
            return left + right
        p.require(type(left) is dict and type(right) is dict and set(left) == set(right))
        return {name: add(left[name], right[name]) for name in left}
    merged = {name: counters[0][name] for name in counters[0] if name not in {"expansionCells", "responseRouteCoverage"}}
    for item in counters[1:]:
        merged = add(merged, {name: item[name] for name in merged})
    for field, identity, static in (("expansionCells", "cellSha256", _CELL),
            ("responseRouteCoverage", "routeSha256", ("routeSha256", "obligationRootSha256"))):
        entries = {}
        for item in counters:
            for row in item[field]:
                previous = entries.get(row[identity])
                if previous is None:
                    entries[row[identity]] = dict(row)
                else:
                    p.require(set(previous) == set(row) and all(previous[name] == row[name] for name in static))
                    entries[row[identity]] = {name: row[name] if name in static else add(previous[name], row[name]) for name in row}
        merged[field] = [entries[key] for key in sorted(entries)]
    return merged


def requirements(counters, assignment, analysis, pilot, *, member, duration):
    """Same safety conditions as the legacy full readiness profile."""
    from catchplate import db
    totals, thresholds = counters["totals"], assignment["readinessThresholds"]
    p.require(not any(totals[name] for name in _UNSAFE), "native readiness contains incomplete or unsafe observations")
    p.require(totals["ingressAdmitted"] == totals["evaluated"] + totals["dropped"] + totals["errors"] + totals["excluded"])
    suffix = "PerMember" if member else ""
    for total, minimum in (("ingressAdmitted", "minimumIngressRequests"), ("evaluated", "minimumEvaluatedObservations"),
            ("comparableResponses", "minimumComparableResponses")):
        p.require(totals[total] >= thresholds[minimum + suffix], "native readiness threshold is unmet")
    cells = analysis["expansionCells"]
    actual = counters["expansionCells"]
    if analysis["mode"] == "no-expansion":
        p.require(pilot == {"mode": "not-applicable"} and not cells and not actual
            and not any(totals[name] for name in tuple(_EXPANDING.values()) + ("authorityExpansionObservations", "authorityExpansionWriteObservations")))
    else:
        from catchplate import authority_policy_canary_native_pilot as inventory
        inventory.validate(pilot)
        p.require(analysis["mode"] == "approved-expansion" and pilot["mode"] == inventory.MODE and pilot["cells"] == cells
            and len(actual) == len(cells) and 0 < totals["authorityExpansionObservations"] <= pilot["maximumRequests"]
            and totals["authorityExpansionWriteObservations"] <= pilot["maximumWriteRequests"] and duration <= pilot["maximumDurationNanos"])
        for observed, authorized in zip(actual, cells, strict=True):
            p.require(all(observed[name] == authorized[name] for name in _CELL)
                and 0 < observed["requestCount"] <= authorized["maximumRequests"]
                and observed["writeRequestCount"] <= authorized["maximumWriteRequests"]
                and observed["responseCount"] <= observed["requestCount"]
                and observed["writeResponseCount"] <= min(observed["writeRequestCount"], observed["responseCount"])
                and (authorized["authorityExpansion"] not in _RESPONSE_EXPANSIONS or observed["responseCount"] > 0)
                and authorized["pilotPrincipalSetRootSha256"] == pilot["principalSetRootSha256"]
                and authorized["pilotRouteSetRootSha256"] == pilot["routeSetRootSha256"])
            p.require((observed["writeRequestCount"], observed["writeResponseCount"]) ==
                ((0, 0) if observed["requestAuthorityClass"] == "read" else (observed["requestCount"], observed["responseCount"])))
    routes = {row["routeSha256"]: row for row in counters["responseRouteCoverage"]}
    obligations = assignment["responseValidationObligations"]
    p.require(len(routes) == len(counters["responseRouteCoverage"]) == len(obligations))
    for obligation in obligations:
        route = routes.get(obligation["routeSha256"])
        selected = [cell for cell in cells if cell["routeSha256"] == obligation["routeSha256"]]
        comparable = not selected or any(cell["authorityExpansion"] in _RESPONSE_EXPANSIONS for cell in selected)
        p.require(route is not None and route["obligationRootSha256"] == obligation["obligationRootSha256"]
            and not any(route[name] for name in ("validationDivergences", "validatorUnavailable", "noncomparable"))
            and (not comparable or route["comparableResponses"] >= (1 if member else obligation["minimumComparableResponses"])),
            "native response obligation coverage is incomplete")
    rates = {}
    for series, maximum, name in (("candidateEvaluation", "maximumCandidateEvaluationP99Nanos", "candidateEvaluationP99Nanos"),
            ("shadowTotal", "maximumShadowTotalP99Nanos", "shadowTotalP99Nanos")):
        value = db._policy_authority_latency_p99(series, counters["latencyHistograms"][series])
        p.require(value is not None and (member or value <= thresholds[maximum]), "native latency evidence is missing or over threshold")
        rates[name] = value
    return rates
