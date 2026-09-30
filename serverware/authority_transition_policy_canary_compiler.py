"""Actual independently signed compiler authority, not an intake ready flag."""
from serverware import authority_policy_canary as profile
from serverware.authority_transition_policy_canary_membership import record, integers
from serverware.authority_transition_policy_canary_state import exact, apply_verification
from serverware import authority_policy_canary_native_pilot as native_pilot


def compiler_analysis(state, value):
    from serverware import db
    item = record(value, db._POLICY_COMPILER_AUTHORITY_ANALYSIS_FIELDS)
    actor = db._candidate_authority_text("compiler actor", item.pop("actor_id"), maximum=1024)
    integers(item, ("assignment_revision", "required_approval_quorum"))
    profile.require(item["required_approval_quorum"] <= 2 and actor == item["signing_key_id"])
    db._candidate_authority_json("compiler cells", item["expansion_cells_json"], item["expansion_cells_digest"],
        maximum=db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES)
    db._candidate_authority_json("compiler pilot", item["pilot_restrictions_json"], item["pilot_restrictions_digest"])
    cells = db.loads(item["expansion_cells_json"], None)
    profile.require(type(cells) is list and len(cells) <= db._POLICY_AUTHORITY_MAX_EXPANSION_CELLS)
    normalized, previous, maximum_requests, maximum_writes = [], "", 0, 0
    for index, entry in enumerate(cells):
        state.charge(1)
        cell = db._policy_authority_semantic_expansion_cell("compiler cell " + str(index), entry)
        profile.require(cell["cellSha256"] > previous and cell["routeAuthorityRootSha256"] == item["route_authority_root_digest"]
            and cell["operationAuthorityRootSha256"] == item["operation_authority_root_digest"])
        previous = cell["cellSha256"]
        maximum_requests += cell["maximumRequests"]
        if cell["requestAuthorityClass"] == "write":
            maximum_writes += cell["maximumWriteRequests"]
        normalized.append(cell)
    pilot = db.loads(item["pilot_restrictions_json"], None)
    profile.require(type(pilot) is dict)
    if item["analysis_mode"] == "no-expansion":
        profile.require(item["approval_mode"] == "none" and item["required_approval_quorum"] == 1
            and not cells and pilot == {"mode": "not-applicable"})
    else:
        native = pilot.get("mode") == native_pilot.MODE
        profile.require(item["analysis_mode"] == "approved-expansion" and set(pilot) == (native_pilot.FIELDS if native else {
            "mode", "principalSetRootSha256", "routeSetRootSha256", "maximumRequests", "maximumDurationNanos", "maximumWriteRequests", "cells"}))
        if native:
            native_pilot.validate(pilot)
        profile.digest(pilot["principalSetRootSha256"]); profile.digest(pilot["routeSetRootSha256"])
        db._candidate_authority_int("pilot requests", pilot["maximumRequests"], minimum=1)
        db._candidate_authority_int("pilot duration", pilot["maximumDurationNanos"], minimum=1)
        db._candidate_authority_int("pilot writes", pilot["maximumWriteRequests"])
        quorum = {"two-person-hardware-webauthn": 2, "single-person-hardware-webauthn": 1}.get(item["approval_mode"], 0)
        profile.require(bool(cells) and pilot["mode"] == (native_pilot.MODE if native else "constrained") and pilot["cells"] == normalized
            and quorum == item["required_approval_quorum"] and pilot["maximumRequests"] <= maximum_requests
            and pilot["maximumWriteRequests"] <= min(maximum_writes, pilot["maximumRequests"]))
    assignment = state.one("policy_canary_assignments", assignment_envelope_digest=item["assignment_envelope_digest"])
    exact(item, assignment, ("assignment_payload_digest", "assignment_revision", "canary_id", "artifact_envelope_digest",
        "artifact_payload_digest", "compiler_digest", "compiler_config_digest", "policy_schema_digest", "semantic_model_digest", "response_obligations_digest"))
    verified = state.static("compiler_analysis", item, "analysis", db._candidate_authority_signed_record(item, current_prefix="analysis"))
    apply_verification(item, verified, interval=True)
    if pilot.get("mode") == native_pilot.MODE:
        native_pilot.admit(state, item, assignment)
    payload = db.loads(item["analysis_payload_json"], None)
    profile.require(payload["expectedLoadedSnapshots"] == db.loads(assignment["expected_snapshots_json"], None)
        and payload["responseValidationObligationsRootSha256"] == assignment["response_obligations_digest"])
    state.put("policy_compiler_authority_analyses", item)
    # A complete v2 map is checked against real published load originals,
    # even when the signed analysis has no expansion cells. Earlier analysis
    # intake is not load proof; later detailed intake repeats this exact join.
    from serverware import authority_transition_policy_canary_route_authority as routes
    for publication in state.matching("policy_shadow_generation_publications", canary_id=item["canary_id"],
            assignment_envelope_digest=item["assignment_envelope_digest"]):
        management = db.loads(publication["management_request_json"], None)
        if any(management[lane + "PolicyBundle"].get("apiVersion") == routes.classifier.BUNDLE for lane in ("active", "candidate")):
            routes.retained_pair(state, {"canary_id": publication["canary_id"], "instance_id": publication["instance_id"],
                "boot_id": publication["boot_id"], "publication_envelope_digest": publication["generation_publication_envelope_digest"]})
    return item
