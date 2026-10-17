"""Closed supplemental helper ceremonies, without approval or owner claims.

Three explicit role selections complement the already approved primary. Every
result retains the existing initial checkpoint/anchor wire and signatures;
assembly has no publication pin. Public validation never creates currentness,
process evidence, signing material or an independently approved input.
"""
from __future__ import annotations

import copy

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_ordinary_initial_authority as issuer
from catchplate import native_pilot_ordinary_initial_profile as initial

p = generation.p
POLICY_API = "catchplate.nativePilotSupervisorHelperInitialPolicy/v1"
MAX_POLICY = 4096
HELPER = generation.ROLES[-1]
SLOTS = (1, 2, 3)


def _row(initial_policy):
    from catchplate import native_pilot_supervisor_initial_history as primary

    p.fields(initial_policy, ("apiVersion", "services"))
    p.require(initial_policy["apiVersion"] == primary.POLICY_API)
    rows = p.fields(initial_policy["services"], generation.ROLES)
    row = p.fields(rows[HELPER], primary.ROLE_FIELDS)
    p.require(row["endpointRole"] in initial.HELPER_ENDPOINT_ROLES and row["validity"] == primary.VALIDITY)
    primary._keys(row["authorities"])
    for name in primary.GENERATIONS + ("revocationGenerationHighWater",):
        p.integer(row[name], maximum=p.MAX_U64)
    for name in ("deploymentGenerationSha256", "revocationRootSha256"):
        p.digest(row[name])
    return row


def validate_policy(fragment, *, initial_policy) -> dict:
    """Validate explicit ordered role selection; not delegation provenance."""
    row = _row(initial_policy)
    p.fields(fragment, ("apiVersion", "supplementalEndpointRoles"))
    p.require(fragment["apiVersion"] == POLICY_API and len(p.canonical(fragment)) <= MAX_POLICY)
    roles = fragment["supplementalEndpointRoles"]
    p.require(type(roles) is list and roles == [role for role in initial.HELPER_ENDPOINT_ROLES
        if role != row["endpointRole"]])
    return copy.deepcopy(fragment)


def _facts(state, payload, authorities, *, endpoint_role, row):
    from catchplate import native_pilot_supervisor_initial_history as primary

    p.require(state["serviceRole"] == HELPER and payload["endpointRole"] == endpoint_role
        and payload["validFromBoottime"]["absoluteBoottimeNanos"] == p.ns(state["issuedAtBoottimeNs"])
        and payload["validUntilBoottime"]["absoluteBoottimeNanos"] == p.ns(state["lifetimeDeadlineBoottimeNs"]))
    primary._same(authorities, row["authorities"])
    for name in primary.GENERATIONS + ("deploymentGenerationSha256",):
        p.require(state[name] == row[name])
    for name in ("revocationGenerationHighWater", "revocationRootSha256"):
        p.require(payload[name] == row[name])


def checked_result(slot, operation, input_raw, result, *, fragment, initial_policy) -> bytes:
    """Authenticate an existing result against its explicit supplemental slot."""
    from catchplate import native_pilot_supervisor_initial_history as primary

    checked = validate_policy(fragment, initial_policy=initial_policy)
    p.require(type(slot) is int and slot in SLOTS and operation in issuer.OPERATIONS)
    _, state, _, payload, authorities, _ = primary._result_context(HELPER, operation, input_raw)
    _facts(state, payload, authorities, endpoint_role=checked["supplementalEndpointRoles"][slot - 1],
        row=_row(initial_policy))
    raw = primary._checked_result(HELPER, operation, input_raw, result, published=False)
    if operation == "assemble":
        p.require(len(raw) <= initial.MAX_HELPER_HISTORY)
    return raw


def authenticate_histories(primary_raw, supplementary_by_slot, *, fragment, initial_policy) -> dict:
    """Return four authenticated literal wrappers; never synthesize a member."""
    checked = validate_policy(fragment, initial_policy=initial_policy)
    row = _row(initial_policy)
    p.require(type(supplementary_by_slot) is dict
        and all(type(slot) is int for slot in supplementary_by_slot)
        and set(supplementary_by_slot) == set(SLOTS))
    selected = {row["endpointRole"]: primary_raw}
    for slot in SLOTS:
        selected[checked["supplementalEndpointRoles"][slot - 1]] = supplementary_by_slot[slot]
    p.require(all(type(raw) is bytes and 0 < len(raw) <= initial.MAX_HELPER_HISTORY for raw in selected.values()))
    contexts = initial.helper_histories(primary_raw,
        {role: selected[role].decode("ascii") for role in initial.HELPER_ENDPOINT_ROLES},
        root_pin={name: row["authorities"]["root"][name] for name in ("keyId", "keySpkiSha256")})
    for endpoint_role, context in contexts.items():
        _facts(context["state"], context["checkpoint"]["payload"],
            {"root": context["history"]["rootAuthority"], "checkpoint": context["epoch"]["checkpointAuthority"],
                "service": context["epoch"]["serviceSigningKey"]}, endpoint_role=endpoint_role, row=row)
    return {role: contexts[role]["original"] for role in initial.HELPER_ENDPOINT_ROLES}
