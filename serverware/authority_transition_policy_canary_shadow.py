"""Typed shadow evidence with exact independent ingress/active predecessors."""
from serverware import authority_policy_canary as profile
from serverware import authority_transition_policy_canary_custody as custody
from serverware.authority_transition_policy_canary_membership import record, integers
from serverware.authority_transition_policy_canary_state import exact, apply_verification


def decoded(item, prefix, maximum=1024 * 1024):
    from serverware import db
    original, _ = db._candidate_authority_json(prefix, item[prefix + "_json"], item[prefix + "_digest"], maximum=maximum)
    return db.loads(original, None)


def components(item):
    from serverware import db
    binding_value = decoded(item, "authority_binding")
    binding = None if binding_value is None else db._policy_authority_observed_binding("observed binding", binding_value)
    cells = db._policy_authority_semantic_expansion_cells("observed expansion", decoded(item, "expansion_cells", db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES), maximum=128, allow_empty=True)
    pilot = db._policy_authority_pilot_membership("observed pilot", decoded(item, "pilot_membership"), authority_binding=binding, expansion_cells=cells)
    obligation = db._policy_authority_response_obligation("observed response obligation", decoded(item, "response_obligation"))
    comparison = decoded(item, "response_comparison", db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES)
    latency = db._candidate_authority_strict_object("latency samples", decoded(item, "latency_samples"),
        frozenset(db._POLICY_AUTHORITY_LATENCY_SAMPLE_FIELDS.values()))
    samples = {series: latency[field] for series, field in db._POLICY_AUTHORITY_LATENCY_SAMPLE_FIELDS.items()}
    for sample in samples.values():
        if sample is not None:
            db._candidate_authority_int("latency", sample)
    evaluated = item["observation_status"] == "evaluated"
    if evaluated:
        profile.require(binding is not None and comparison is not None and item["candidate_dispatch_commitment_digest"] is not None
            and all(samples[series] is not None for series in ("factsCapture", "activeEvaluation", "candidateEvaluation", "shadowTotal"))
            and all(sample is None or sample <= samples["shadowTotal"] for sample in samples.values()))
        for cell in cells:
            profile.require(all(cell[name] == binding[name] for name in ("routeSha256", "operation", "compiledSemanticProfileSha256", "requestAuthorityClass"))
                and cell["activeOutcome"] == item["active_outcome"] and cell["candidateOutcome"] == item["candidate_outcome"])
        profile.require(obligation is None or obligation["routeSha256"] == binding["routeSha256"])
    else:
        profile.require(binding is None and not cells and pilot is None and obligation is None and comparison is None
            and item["candidate_dispatch_commitment_digest"] is None and item["candidate_outcome"] == "indeterminate")
    if item["observation_status"] in {"excluded", "transport-excluded"}:
        profile.require(all(sample is None for sample in samples.values()))
    elif item["observation_status"] in {"dropped", "error"}:
        profile.require(all(sample is None for sample in samples.values()) if samples["shadowTotal"] is None
            else all(sample is None or sample <= samples["shadowTotal"] for sample in samples.values()))
    for name, status, reasons in (("drop_reason", "dropped", db._POLICY_AUTHORITY_DROP_REASONS),
            ("error_reason", "error", db._POLICY_AUTHORITY_ERROR_REASONS)):
        profile.require((item[name] is not None) == (item["observation_status"] == status))
        if item[name] is not None:
            profile.text(item[name], 1024); profile.require(item[name] in reasons)
    for name, source in (("route_id", "routeSha256"), ("operation_class", "operation"), ("request_authority_class", "requestAuthorityClass")):
        item[name] = None if binding is None else binding[source]
    item["response_obligation_route_id"] = None if obligation is None else obligation["routeSha256"]
    item["response_obligation_root_digest"] = None if obligation is None else obligation["obligationRootSha256"]
    return binding, cells, obligation, comparison


def direct_result(item, ingress, active):
    from serverware import db
    payload = custody.wire(item, "shadow_observation")
    for prefix, nested, stored in (("ingress", "ingressEvidence", ingress), ("active_decision", "activeDecision", active)):
        original = db._policy_shadow_direct_envelope_components(nested, payload[nested])
        profile.require(payload[nested + "Sha256"] == item[prefix + "_envelope_digest"]
            and all(original[name] == stored[prefix + "_" + name] for name in ("envelope_digest", "payload_digest", "envelope_json", "payload_json")))
    result = payload["result"]
    profile.require(type(result) is dict and "status" in result)
    status = result["status"]
    if status == "evaluated":
        profile.require(set(result) == {"status", "pureActiveEvaluation", "finalActiveEnforcement", "candidateEvaluation", "authorityBinding",
            "derivedExpansion", "pilotMembership", "responseObligation", "responseComparison", "latencySamples"}
            and item["observation_status"] == "evaluated")
        active_result, final, candidate = (result[name] for name in ("pureActiveEvaluation", "finalActiveEnforcement", "candidateEvaluation"))
        profile.require(all(type(value) is dict for value in (active_result, final, candidate)))
        expansion = db._candidate_authority_strict_object("direct expansion", result["derivedExpansion"], frozenset({"cells", "cellsRootSha256"}))
        cells = db._policy_authority_semantic_expansion_cells("direct expansion cells", expansion["cells"],
            maximum=db._POLICY_AUTHORITY_MAX_EXPANSION_CELLS, allow_empty=True)
        profile.require(active_result.get("outcome") == item["active_outcome"] and candidate.get("outcome") == item["candidate_outcome"]
            and active_result.get("dispatchCommitmentSha256") == active["active_dispatch_commitment_digest"]
            and candidate.get("dispatchCommitmentSha256") == item["candidate_dispatch_commitment_digest"]
            and final.get("finalOutcome") == active["final_active_outcome"] and type(final.get("upstreamDispatchAuthorized")) is bool
            and int(final["upstreamDispatchAuthorized"]) == active["upstream_dispatch_authorized"]
            and expansion["cellsRootSha256"] == db._policy_shadow_merkle_root([(index, cell["cellSha256"]) for index, cell in enumerate(cells, 1)]))
        for source, target, value in (("authorityBinding", "authority_binding", result["authorityBinding"]),
                ("derivedExpansion", "expansion_cells", cells), ("pilotMembership", "pilot_membership", result["pilotMembership"]),
                ("responseObligation", "response_obligation", result["responseObligation"]),
                ("responseComparison", "response_comparison", result["responseComparison"]), ("latencySamples", "latency_samples", result["latencySamples"])):
            profile.require(profile.canonical(value).decode("ascii") == item[target + "_json"], "shadow direct result projection changed: " + source)
    elif status in {"dropped", "error"}:
        profile.require(set(result) == {"status", "reason", "unavailableMarkerSha256", "latencySamples"}
            and status == item["observation_status"] and result["reason"] == item["drop_reason" if status == "dropped" else "error_reason"]
            and profile.canonical(result["latencySamples"]).decode("ascii") == item["latency_samples_json"])
    elif status == "excluded":
        profile.require(set(result) == {"status", "reason"} and result["reason"] == "deterministic-assignment-sampling" and item["observation_status"] == status)
    else:
        profile.require(status == "transport-excluded" and set(result) == {"status"} and item["observation_status"] == status)


def compiler_scope(item, contract, compiler, binding, cells, obligation, comparison, active):
    from serverware import db
    return _compiler_scope(item, contract, compiler, binding, cells, obligation, comparison, active,
        db._policy_authority_response_comparison, _legacy_pilot)


def native_compiler_scope(item, contract, compiler, binding, cells, obligation, comparison, active):
    from serverware import authority_policy_canary_native_comparison as native
    return _compiler_scope(item, contract, compiler, binding, cells, obligation, comparison, active,
        native.validate, native.pilot_profile)


def _legacy_pilot(value, analysis_mode, cells):
    from serverware import db
    pilot = db._candidate_authority_strict_object("compiler pilot", value,
        frozenset({"mode"}) if analysis_mode == "no-expansion" else frozenset({"mode", "principalSetRootSha256", "routeSetRootSha256",
            "maximumRequests", "maximumDurationNanos", "maximumWriteRequests", "cells"}))
    profile.require(pilot == {"mode": "not-applicable"} if analysis_mode == "no-expansion" else
        pilot["mode"] == "constrained" and pilot["cells"] == cells)


def _compiler_scope(item, contract, compiler, binding, cells, obligation, comparison, active, comparison_validator, pilot_validator):
    from serverware import db
    for original, name, digest_name in ((contract, "expected_snapshots_json", "expected_snapshots_digest"),
            (contract, "response_obligations_json", "response_obligations_json_digest"),
            (compiler, "expansion_cells_json", "expansion_cells_digest"), (compiler, "pilot_restrictions_json", "pilot_restrictions_digest")):
        db._candidate_authority_json(name, original[name], original[digest_name], maximum=db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES)
    snapshots = db._candidate_authority_strict_object("assigned snapshots", db.loads(contract["expected_snapshots_json"], None),
        frozenset({"active", "candidate", "requestFactsSchemaSha256"}))
    profile.require(type(snapshots["active"]) is dict and type(snapshots["candidate"]) is dict)
    entries = db.loads(compiler["expansion_cells_json"], None)
    profile.require(type(entries) is list)
    authorized, previous = {}, ""
    for entry in entries:
        cell = db._policy_authority_semantic_expansion_cell("compiler expansion", entry)
        digest = cell["cellSha256"]
        profile.require(digest > previous and cell["routeAuthorityRootSha256"] == compiler["route_authority_root_digest"]
            and cell["operationAuthorityRootSha256"] == compiler["operation_authority_root_digest"])
        previous, authorized[digest] = digest, cell
    expanding = item["observation_status"] == "evaluated" and (item["active_outcome"], item["candidate_outcome"]) in db._POLICY_AUTHORITY_EXPANDING_TRANSITIONS
    if compiler["analysis_mode"] == "no-expansion":
        profile.require(not cells and not authorized and not expanding)
    else:
        profile.require(compiler["analysis_mode"] == "approved-expansion" and (not expanding or cells)
            and all(authorized.get(cell["cellSha256"]) == cell for cell in cells))
    expected = [] if binding is None else [authorized[digest] for digest in sorted(authorized)
        if all(authorized[digest][name] == binding[name] for name in ("routeSha256", "operation", "compiledSemanticProfileSha256", "requestAuthorityClass"))
        and authorized[digest]["activeOutcome"] == item["active_outcome"] and authorized[digest]["candidateOutcome"] == item["candidate_outcome"]]
    profile.require(cells == expected, "shadow expansion is not the exact compiler-derived set")
    obligations = db.loads(contract["response_obligations_json"], None)
    profile.require(type(obligations) is list)
    by_route = {value["routeSha256"]: value for value in obligations}
    assigned = None if binding is None else by_route.get(binding["routeSha256"])
    profile.require((obligation is None if assigned is None else obligation is not None and obligation["obligationRootSha256"] == assigned["obligationRootSha256"]))
    if item["observation_status"] == "evaluated":
        comparison = comparison_validator("observed comparison", comparison, obligation=obligation,
            active_snapshot_digest=snapshots["active"]["compiledSnapshotSha256"], candidate_snapshot_digest=snapshots["candidate"]["compiledSnapshotSha256"],
            final_active_outcome=active["final_active_outcome"], upstream_dispatch_authorized=active["upstream_dispatch_authorized"],
            active_dispatch_commitment_digest=active["active_dispatch_commitment_digest"],
            candidate_dispatch_commitment_digest=item["candidate_dispatch_commitment_digest"], candidate_outcome=item["candidate_outcome"])
        item["response_comparison_class"], item["response_capture_mode"] = comparison["classification"], comparison["captureMode"]
    else:
        item["response_comparison_class"] = item["response_capture_mode"] = None
    pilot_validator(db.loads(compiler["pilot_restrictions_json"], None), compiler["analysis_mode"],
        [authorized[digest] for digest in sorted(authorized)])


def shadow(state, value):
    from serverware import db
    item = record(value, db._POLICY_CANARY_SHADOW_OBSERVATION_FIELDS)
    profile.text(item.pop("actor_id"), 1024)
    integers(item, ("assignment_revision", "membership_revision", "member_ordinal", "observation_sequence", "ingress_sequence"))
    profile.require(item["observation_status"] in {"evaluated", "dropped", "error", "excluded", "transport-excluded"}
        and item["active_outcome"] in db._POLICY_AUTHORITY_OUTCOMES and item["candidate_outcome"] in db._POLICY_AUTHORITY_OUTCOMES)
    binding, cells, obligation, comparison = components(item)
    context = state.runtime_context(item)
    exact(item, context, custody.RUNTIME)
    custody.observing(state, item)
    ingress = state.one("policy_canary_ingress_observations", **custody.identity(item, custody.INSTANCE + ("ingress_sequence",)))
    active = state.one("policy_canary_active_decisions", **custody.identity(item, custody.INSTANCE + ("ingress_sequence",)))
    compiler = state.one("policy_compiler_authority_analyses", analysis_envelope_digest=item["compiler_analysis_envelope_digest"],
        analysis_payload_digest=item["compiler_analysis_payload_digest"])
    exact(item, ingress, ("ingress_envelope_digest", "ingress_payload_digest", "custody_evidence_envelope_digest", "custody_verification_receipt_digest"))
    exact(item, active, ("active_decision_envelope_digest", "active_decision_payload_digest", "custody_evidence_envelope_digest", "custody_verification_receipt_digest", "active_outcome"))
    exact(item, compiler, ("assignment_envelope_digest", "assignment_payload_digest", "canary_id"))
    profile.require(item["observation_status"] == ingress["accounting_outcome"]
        and (item["observation_status"] == "evaluated") == (active["decision_status"] == "evaluated"))
    previous_rows = state.matching("policy_canary_shadow_observations", **custody.identity(item, custody.INSTANCE))
    previous = max(previous_rows, key=lambda row: row["observation_sequence"]) if previous_rows else None
    first = db._candidate_authority_int("first shadow ingress", custody.observation_window(context)["firstIngressSequence"], minimum=1)
    profile.require(item["observation_sequence"] == (1 if previous is None else previous["observation_sequence"] + 1)
        and item["ingress_sequence"] == (first if previous is None else previous["ingress_sequence"] + 1)
        and item["previous_observation_envelope_digest"] == (None if previous is None else previous["shadow_observation_envelope_digest"]))
    if previous is not None:
        previous_ingress = state.one("policy_canary_ingress_observations", ingress_envelope_digest=previous["ingress_envelope_digest"],
            ingress_payload_digest=previous["ingress_payload_digest"])
        profile.require(ingress["observed_at_epoch_ns"] >= previous_ingress["observed_at_epoch_ns"])
    direct_result(item, ingress, active)
    if ingress["request_commitment_digest"] is not None:
        profile.require(all(ingress[name] is not None for name in custody.CUSTODY_REFERENCE)
            and ingress["custody_generation_id_digest"] == active["generation_id_digest"]
            and ingress["custody_request_commitment_digest"] == ingress["request_commitment_digest"])
        held = state.one("policy_canary_custody_evidence", custody_evidence_envelope_digest=ingress["custody_evidence_envelope_digest"],
            verification_receipt_digest=ingress["custody_verification_receipt_digest"])
        profile.require(held["generation_id_digest"] == active["generation_id_digest"] and held["request_commitment_digest"] == ingress["request_commitment_digest"]
            and held["request_binding_digest"] == ingress["custody_request_binding_digest"] and held["opening_spill_receipt_digest"] == ingress["custody_opening_spill_receipt_digest"])
        custody.reverify(state, held, current=False)
    else:
        profile.require(all(ingress[name] is None for name in custody.CUSTODY_REFERENCE))
    compiler_scope(item, context, compiler, binding, cells, obligation, comparison, active)
    apply_verification(item, state.runtime("shadow_observation", item, "shadow_observation",
        db._candidate_authority_signed_record(item, current_prefix="shadow_observation")), interval=True)
    profile.require(compiler["issued_at_epoch_ns"] <= item["issued_at_epoch_ns"] and item["expires_at_epoch_ns"] <= compiler["expires_at_epoch_ns"])
    state.put("policy_canary_shadow_observations", item)
    return item
