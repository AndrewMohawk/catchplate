"""Closed original-row acquisition for the shared checkpoint/readiness folds.

This is not a SQL adapter. It exposes no execute/cursor/connection API and has
no table or predicate supplied by HTTP. The kernel repeats these reads over
complete-root-authenticated before rows plus its own ordered mutations. The
same pure preflight may address queries, but has no commit authority.
"""
from serverware import authority_policy_canary as profile
from serverware import authority_transition_policy_canary_custody as custody
from serverware.authority_transition_policy_canary_state import State, exact


def owner(state, connection=None):
    profile.require(state is None or (type(state) is State and connection is None), "invalid controlled canary read owner")
    return state


def runtime_values(state, connection, **arguments):
    from serverware import db
    owner(state, connection)
    if state is None:
        return dict(db._verify_policy_runtime_evidence(connection, **arguments).values)
    item = {"original_" + name: arguments[name] for name in ("envelope_json", "envelope_digest", "payload_json", "payload_digest")}
    item.update({name: arguments[name] for name in ("signature_algorithm", "signing_key_id", "signature", "signature_digest",
        "assignment_envelope_digest", "member_ordinal", "canary_id", "fleet_id", "membership_revision", "instance_id", "boot_id")})
    return state.runtime(arguments["evidence_kind"], item, "original", arguments["record_binding"])


def apply_values(item, receipt):
    for name in ("evidence_kind", "record_binding_digest", "verification_receipt_digest"):
        item[name] = receipt[name]


def static_values(state, connection, **arguments):
    from serverware import db
    from serverware import authority_transition_policy_canary_handoff as handoffs
    owner(state, connection)
    if state is None:
        return dict(db._verify_policy_authority_evidence(connection, **arguments).values)
    return handoffs.envelope_receipt(state, arguments["evidence_kind"], arguments, arguments["record_binding"])


def static_row(state, connection, *, evidence_kind, item, current_prefix):
    from serverware import db
    owner(state, connection)
    if state is None:
        return db._reverify_policy_static_evidence(connection, evidence_kind=evidence_kind, item=item, current_prefix=current_prefix)
    return state.static(evidence_kind, item, current_prefix, db._candidate_authority_signed_record(item, current_prefix=current_prefix))


def assignment(state, canary_id):
    assigned = state.one("policy_canary_assignments", canary_id=canary_id)
    canary = state.one("policy_canaries", canary_id=canary_id)
    return {**assigned, "expected_instance_count": canary["expected_instance_count"]}


def instance(state, item):
    identity = custody.identity(item, custody.INSTANCE)
    return {**state.one("policy_canary_instances", **identity), **state.one("policy_canary_load_receipts", **identity)}


def checkpoint(state, item, sequence):
    identity = {**custody.identity(item, custody.INSTANCE), "checkpoint_sequence": sequence}
    return {**state.one("policy_canary_checkpoints", **identity), **state.one("policy_canary_checkpoint_aggregates", **identity)}


def sealed_rows(state, canary_id):
    rows = []
    for instance_row in state.matching("policy_canary_instances", canary_id=canary_id):
        identity = custody.identity(instance_row, custody.INSTANCE)
        instance_head = state.one("policy_canary_instance_heads", **identity)
        head = state.one("policy_canary_checkpoint_heads", **identity)
        final = state.one("policy_canary_checkpoints", **identity, checkpoint_sequence=head["checkpoint_sequence"])
        aggregate_row = state.one("policy_canary_checkpoint_aggregates", **identity, checkpoint_sequence=head["checkpoint_sequence"])
        exact(head, final, ("checkpoint_envelope_digest", "checkpoint_payload_digest"))
        exact(final, aggregate_row, ("checkpoint_envelope_digest", "checkpoint_payload_digest"))
        rows.append({**instance_row, **instance_head, **head, **final, **aggregate_row,
            "status": instance_head["status"], "sealed": head["sealed"], "aggregate_sealed": aggregate_row["sealed"],
            "head_revision": instance_head["head_revision"], "head_state_digest": instance_head["head_state_digest"]})
    state.charge(len(rows) * 64)
    return sorted(rows, key=lambda row: row["member_ordinal"])


def transition(state, connection, **arguments):
    from serverware import db
    owner(state, connection)
    return db._stage_policy_authority_transition(connection, **arguments) if state is None else state.transition(**arguments)


def recompute(state, connection, **arguments):
    from serverware import db
    owner(state, connection)
    return db._recompute_policy_canary_checkpoint_aggregate(connection, **arguments) if state is None else aggregate(state, **arguments)


def joined_observations(state, item, end):
    identity = custody.identity(item, custody.INSTANCE)
    shadows = sorted((row for row in state.matching("policy_canary_shadow_observations", **identity)
        if row["observation_sequence"] <= end), key=lambda row: row["observation_sequence"])
    profile.require(len(shadows) <= end)
    joined = []
    for shadow in shadows:
        ingress = state.one("policy_canary_ingress_observations", **identity, ingress_sequence=shadow["ingress_sequence"])
        active = state.one("policy_canary_active_decisions", **identity, ingress_sequence=shadow["ingress_sequence"])
        exact(shadow, ingress, ("ingress_envelope_digest", "ingress_payload_digest"))
        exact(shadow, active, ("active_decision_envelope_digest", "active_decision_payload_digest"))
        # SQL's explicit aliases preserve each independent custody reference.
        joined.append({**shadow, **ingress, **active, "active_outcome": shadow["active_outcome"],
            "independently_active_outcome": active["active_outcome"],
            "custody_evidence_envelope_digest": ingress["custody_evidence_envelope_digest"],
            "custody_verification_receipt_digest": ingress["custody_verification_receipt_digest"],
            "active_custody_evidence_envelope_digest": active["custody_evidence_envelope_digest"],
            "active_custody_verification_receipt_digest": active["custody_verification_receipt_digest"],
            "shadow_custody_evidence_envelope_digest": shadow["custody_evidence_envelope_digest"],
            "shadow_custody_verification_receipt_digest": shadow["custody_verification_receipt_digest"]})
    return joined


def aggregate(state, *, canary_id, instance_id, boot_id, sequence_end, checkpoint_assertions=None, historical=False):
    from serverware import db
    owner(state)
    profile.require(type(state) is State)
    db._candidate_authority_int("controlled prefix end", sequence_end, minimum=1, maximum=profile.MAX_ROWS)
    assertions = dict(checkpoint_assertions or {})
    profile.require(all(type(boundary) is int and 1 <= boundary <= sequence_end for boundary in assertions))
    assigned = assignment(state, canary_id)
    compiler = state.one("policy_compiler_authority_analyses", assignment_envelope_digest=assigned["assignment_envelope_digest"],
        assignment_payload_digest=assigned["assignment_payload_digest"])
    contract = {**assigned, **compiler}
    for name, digest_name in (("expected_snapshots_json", "expected_snapshots_digest"),
            ("response_obligations_json", "response_obligations_json_digest"), ("observation_window_json", "observation_window_digest"),
            ("expansion_cells_json", "expansion_cells_digest"), ("pilot_restrictions_json", "pilot_restrictions_digest")):
        db._candidate_authority_json(name, contract[name], contract[digest_name], maximum=db._POLICY_AUTHORITY_MAX_CANONICAL_AGGREGATE_BYTES)
    snapshots = db._candidate_authority_strict_object("checkpoint snapshots", db.loads(contract["expected_snapshots_json"], None),
        frozenset({"active", "candidate", "requestFactsSchemaSha256"}))
    window = custody.observation_window(contract)
    first = db._candidate_authority_int("checkpoint first ingress", window["firstIngressSequence"], minimum=1)
    obligations = db.loads(contract["response_obligations_json"], None)
    entries = db.loads(contract["expansion_cells_json"], None)
    profile.require(type(obligations) is list and type(entries) is list)
    authorized, previous = {}, ""
    for entry in entries:
        cell = db._policy_authority_semantic_expansion_cell("checkpoint compiler expansion", entry)
        digest = cell["cellSha256"]
        profile.require(digest > previous and cell["routeAuthorityRootSha256"] == contract["route_authority_root_digest"]
            and cell["operationAuthorityRootSha256"] == contract["operation_authority_root_digest"])
        previous, authorized[digest] = digest, cell
    identity = {"canary_id": canary_id, "instance_id": instance_id, "boot_id": boot_id}
    lanes, total_bytes = {}, 0
    for lane, table, column, prefix, start, end in (
            ("ingress", "policy_canary_ingress_observations", "ingress_sequence", "ingress", first, first + sequence_end - 1),
            ("active", "policy_canary_active_decisions", "ingress_sequence", "active_decision", first, first + sequence_end - 1),
            ("shadow", "policy_canary_shadow_observations", "observation_sequence", "shadow_observation", 1, sequence_end)):
        rows = [row for row in state.matching(table, **identity) if start <= row[column] <= end]
        keyed = {row[column]: row for row in rows}
        profile.require(len(rows) == sequence_end and len(keyed) == len(rows) and set(keyed) == set(range(start, end + 1)),
            "controlled checkpoint lane is not the exact contiguous assigned prefix")
        total_bytes += sum(len(row[prefix + "_envelope_json"].encode("utf-8")) for row in rows)
        lanes[lane] = keyed
    profile.require(total_bytes <= db._POLICY_AUTHORITY_MAX_VERIFIED_EVIDENCE_BYTES
        and sequence_end * db._POLICY_AUTHORITY_VERIFICATION_WORK_UNITS_PER_OBSERVATION <= db._POLICY_AUTHORITY_MAX_VERIFICATION_WORK_UNITS)
    held_custody = [row for row in state.matching("policy_canary_custody_evidence", **identity) if first <= row["ingress_sequence"] < first + sequence_end]
    by_ingress = {row["ingress_sequence"]: row for row in held_custody}
    profile.require(len(held_custody) <= sequence_end and len(by_ingress) == len(held_custody))
    state.charge(sequence_end * db._POLICY_AUTHORITY_VERIFICATION_WORK_UNITS_PER_OBSERVATION)
    return db._fold_policy_canary_checkpoint_originals(None, sequence_end=sequence_end, assertions=assertions, historical=historical,
        contract=contract, snapshots=snapshots, observation_window=window, first_ingress_sequence=first,
        obligation_by_route={value["routeSha256"]: value for value in obligations}, authorized_cells=authorized, lane_gaps=0,
        custody_by_ingress=by_ingress, runtime_lane_records=lanes, rows=joined_observations(state, identity, sequence_end), _controlled_state=state)
