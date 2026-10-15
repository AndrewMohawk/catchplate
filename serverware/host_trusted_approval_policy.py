"""Pure signed-policy vocabulary for explicitly host-trusted approvals.

Validation is not approval enforcement. Only the owning Rust request path may
consume an approval; Python forwarding rejects these routes before custody.
"""
from __future__ import annotations

TYPE = "hostTrustedApproval"
SCHEMA = "serverware.hostTrustedApprovalPolicy/v1"
FIELDS = frozenset({"type", "schema", "pendingTtlSeconds", "approvalTtlSeconds"})
ADAPTERS = frozenset({"generic.rest", "gmail.read.v1", "npm.metadata.v1",
    "npm.install.v1", "npm.publish.v1", "x.app_read.v1", "x.post.v1", "alchemy.rpc_read.v1"})
DURABLE_CONSTRAINTS = frozenset({"slidingWindowLimit", "weightedBudget", "traversalBudget", "responseBinding"})


def validate(value):
    if (not isinstance(value, dict) or set(value) != FIELDS or value.get("type") != TYPE
            or value.get("schema") != SCHEMA
            or type(value.get("pendingTtlSeconds")) is not int
            or not 30 <= value["pendingTtlSeconds"] <= 3600
            or type(value.get("approvalTtlSeconds")) is not int
            or not 1 <= value["approvalTtlSeconds"] <= 300):
        raise ValueError("host-trusted approval requires its exact bounded policy fields")


def provider_constraints(constraints):
    """Remove only one validated marker for unchanged pure provider checks."""
    result, seen = [], False
    for value in constraints:
        if isinstance(value, dict) and value.get("type") == TYPE:
            validate(value)
            if seen:
                raise ValueError("one host-trusted approval policy is allowed per route")
            seen = True
        else:
            result.append(value)
    return tuple(result)


def validate_route(*, adapter, credential_ref, jit, constraints, response_observation=False):
    normal = provider_constraints(constraints)
    if len(normal) == len(constraints):
        return
    if (adapter not in ADAPTERS or not credential_ref or jit.get("required") is True
            or response_observation
            or any(row.get("type") in DURABLE_CONSTRAINTS
                or (row.get("type") == "rateLimit" and row.get("store", "local") == "shared")
                for row in normal)):
        raise ValueError("host-trusted approval cannot compose with native, durable or unbound authority")
