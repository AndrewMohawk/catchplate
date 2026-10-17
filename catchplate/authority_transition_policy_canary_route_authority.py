"""Independent protected-original join for the complete native v2 classifier.

The installed getter proves local compilation only. This receiver selects the
actual protected generation and currently authorized signed compiler analysis,
then recomputes the complete map even when expansionCells is empty.
"""
from catchplate import authority_policy_canary as profile
from catchplate import policy_route_authority as classifier
from catchplate import authority_transition_policy_canary_handoff as handoff
from catchplate.authority_transition_policy_canary_state import exact


def retained_pair(state, record):
    from catchplate import db
    from catchplate.policy_bundle import policy_hash
    context = state.runtime_context(record)
    publication = state.one("policy_shadow_generation_publications", canary_id=record["canary_id"],
        instance_id=record["instance_id"], boot_id=record["boot_id"],
        generation_publication_envelope_digest=record["publication_envelope_digest"])
    exact(publication, context, ("assignment_envelope_digest", "assignment_payload_digest",
        "load_receipt_envelope_digest", "load_receipt_payload_digest"))
    handoff.generation(state, publication)
    management = db.loads(publication["management_request_json"], None)
    pair = {}
    for lane in ("active", "candidate"):
        raw = management[lane + "PolicyBundle"]
        profile.require(raw.get("apiVersion") == classifier.BUNDLE,
            "full native authority observations require explicit v2 in both installed lanes")
        # Full signed originals were admitted by the controlled claim and actual
        # native install, then committed by the separately verified publication.
        # Recompute, never treat its digest as decoded semantic facts.
        profile.require(policy_hash(raw) == publication[lane + "_policy_hash"]
            and profile.sha256(profile.canonical(raw)) == publication[lane + "_policy_bundle_digest"])
        state.charge(1 + (len(profile.canonical(raw)) + 255) // 256)
        pair[lane] = classifier.admit(raw)
        state.charge(1 + len(pair[lane]["mapping"]["profiles"]))
    compiler = state.one("policy_compiler_authority_analyses", canary_id=record["canary_id"],
        assignment_envelope_digest=context["assignment_envelope_digest"])
    exact(compiler, context, ("assignment_payload_digest", "assignment_revision", "artifact_envelope_digest",
        "artifact_payload_digest", "compiler_digest", "compiler_config_digest", "policy_schema_digest",
        "semantic_model_digest", "response_obligations_digest"))
    state.static("compiler_analysis", compiler, "analysis",
        db._candidate_authority_signed_record(compiler, current_prefix="analysis"), persist=False)
    analysis = db.loads(compiler["analysis_payload_json"], None)
    profile.require(analysis["expectedLoadedSnapshots"] == db.loads(context["expected_snapshots_json"], None))
    roots = classifier.analysis_roots(pair["active"], pair["candidate"])
    for source, target in (("routeAuthorityRootSha256", "route_authority_root_digest"),
            ("operationAuthorityRootSha256", "operation_authority_root_digest")):
        profile.require(roots[source] == compiler[target] == analysis[source],
            "compiler analysis does not authorize the complete installed classifier mapping")
    # Expansion profiles must use genuine entries too; no first-cell fallback.
    cells = db.loads(compiler["expansion_cells_json"], None)
    profile.require(type(cells) is list)
    for value in cells:
        state.charge(1)
        cell = db._policy_authority_semantic_expansion_cell("complete classifier expansion", value)
        classifier.binding_entry(pair["candidate"], cell)
        profile.require(cell["routeAuthorityRootSha256"] == roots["routeAuthorityRootSha256"]
            and cell["operationAuthorityRootSha256"] == roots["operationAuthorityRootSha256"])
    return {**pair, "analysis": compiler}


def require_binding(pair, lane, binding):
    profile.require(lane in {"active", "candidate"})
    entry = classifier.binding_entry(pair[lane], binding)
    profile.require(binding["principalSha256"] in entry["profile"]["principalSha256s"],
        "observed principal is outside actual signed route membership")
    return entry
