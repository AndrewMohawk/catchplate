"""Source-owned complete-index query intent, not range evidence or authority.

The first admitted declaration family is the unregistered explicit revocation
candidate's five roles. Its arguments and cutoff are supplied intent/time, not
authenticated facts. Binding proves neither a complete index population nor a
current root, trusted clock, SQL result, authorized operation or working kernel.
The planner must reject this distinct query kind until its real proof producer
and evidence admission exist. Legacy QueryProgram/v1 is not changed here.

This module may be imported by authority_contract. It deliberately imports no
core, operation registry, query reader, database or verification-result types.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from serverware import authority_index_projection as projection


QUERY_SCHEMA = "serverware.policyAuthorityCompleteIndexQuery/v1"
ROLE_SCHEMA = "serverware.policyAuthorityCompleteIndexQueryRole/v1"
PROOF_PRIMITIVE = "authenticated-complete-index-range"
OPERATION = "webauthn.credential.revoke"
CASCADE_MAX = 32
MAX_ARGUMENT_FIELDS = 64
MAX_SOURCE_ID_BYTES = 1024
_I64_MIN, _I64_MAX = -(2**63), 2**63 - 1
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class CompleteQueryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Role:
    name: str
    table: str
    index_id: str
    hint_field: str
    shared_group: str
    status: str | None = None

    @property
    def selector_names(self) -> tuple[str, ...]:
        if self.name == "global_registration_challenges":
            return ("expires_after_us",)
        return (("credential_record_id", "status") if self.status is not None
                else ("credential_record_id",))


_ROLES = (
    _Role("sessions_pending_webauthn", "oidc_browser_sessions", "webauthn_session_credential_status",
          "oidc_session_ids", "oidc_sessions", "pending_webauthn"),
    _Role("sessions_active", "oidc_browser_sessions", "webauthn_session_credential_status",
          "oidc_session_ids", "oidc_sessions", "active"),
    _Role("grants", "approval_grants", "webauthn_grant_approver_active",
          "approval_grant_ids", "approval_grants"),
    _Role("approvals", "control_plane_approvals", "webauthn_control_approval_approved",
          "control_plane_approval_ids", "control_plane_approvals"),
    _Role("global_registration_challenges", "webauthn_challenges", "webauthn_registration_unused_global",
          "registration_challenge_ids", "registration_challenges"),
)
ROLES = tuple(role.name for role in _ROLES)
_HINT_FIELDS = ("oidc_session_ids", "approval_grant_ids",
                "control_plane_approval_ids", "registration_challenge_ids")


def _operation(value: Any) -> None:
    if type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii():
        raise CompleteQueryError("complete query operation is not a bounded exact identity")


def _role(operation: str, role: Any) -> _Role:
    _operation(operation)
    if operation != OPERATION or type(role) is not str or not 1 <= len(role) <= 128:
        raise CompleteQueryError("complete query role is not declared for its operation")
    for candidate in _ROLES:
        if role == candidate.name:
            return candidate
    raise CompleteQueryError("complete query role is not declared for its operation")


def _source_id(value: Any) -> str:
    # Preserve the candidate's source-ID admission, not just the looser index
    # codec's 4096-byte text ceiling. Never coerce numbers, null or subclasses.
    if (type(value) is not str or not 1 <= len(value) <= MAX_SOURCE_ID_BYTES
            or value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CompleteQueryError("complete query source ID is invalid")
    try:
        if len(value.encode("utf-8")) > MAX_SOURCE_ID_BYTES:
            raise CompleteQueryError("complete query source ID exceeds its UTF-8 bound")
    except UnicodeError as exc:
        raise CompleteQueryError("complete query source ID is not valid UTF-8") from exc
    return value


def _cutoff(value: Any) -> int:
    if type(value) is not int or not _I64_MIN <= value <= _I64_MAX:
        raise CompleteQueryError("complete query cutoff is not an exact signed int64")
    return value


def cutoff_microseconds(value: datetime) -> int:
    """Convert supplied aware time exactly; no clock is read or authenticated."""
    if type(value) is not datetime or value.tzinfo is None:
        raise CompleteQueryError("complete query time is not an exact aware datetime")
    try:
        if value.utcoffset() is None:
            raise CompleteQueryError("complete query time is not aware")
        elapsed = value.astimezone(timezone.utc) - _EPOCH
        return _cutoff((elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds)
    except (OverflowError, ValueError, TypeError) as exc:
        if isinstance(exc, CompleteQueryError):
            raise
        raise CompleteQueryError("complete query time cannot be converted exactly") from exc


@dataclass(frozen=True, slots=True)
class CompleteIndexQuery:
    """Immutable bound declaration data; construction grants no completeness.

    Source-derived properties cannot be supplied as arbitrary profile, table,
    filter, ordering, continuation or proof fields. A consumer must additionally
    rebind the stored values to its actual arguments/cutoff with validate_bindings.
    """

    operation: str
    role: str
    selector_items: tuple[tuple[str, str | int], ...]
    maximum_rows: int

    def __post_init__(self) -> None:
        declared = _role(self.operation, self.role)
        if (type(self.selector_items) is not tuple or len(self.selector_items) != len(declared.selector_names)
                or type(self.maximum_rows) is not int or not 1 <= self.maximum_rows <= CASCADE_MAX):
            raise CompleteQueryError("complete query selector inventory or row bound is invalid")
        for item, name in zip(self.selector_items, declared.selector_names):
            if type(item) is not tuple or len(item) != 2 or type(item[0]) is not str or item[0] != name:
                raise CompleteQueryError("complete query selector fields are not source ordered and closed")
            value = item[1]
            if name == "expires_after_us":
                _cutoff(value)
            elif name == "status":
                if type(value) is not str or value != declared.status:
                    raise CompleteQueryError("complete query status differs from its source role")
            else:
                _source_id(value)
        try:
            profile = projection.profile_for(declared.index_id)
            if profile.table != declared.table:
                raise CompleteQueryError("complete query role and projection table differ")
            projection.snapshot_selector(declared.index_id, dict(self.selector_items))
        except projection.IndexProjectionError as exc:
            raise CompleteQueryError("complete query selector differs from its fixed projection") from exc

    @property
    def query_id(self) -> str:
        return f"serverware.policyAuthorityQuery/{self.operation}/{self.role}/{self.table}/v1"

    @property
    def table(self) -> str:
        return _role(self.operation, self.role).table

    @property
    def index_id(self) -> str:
        return _role(self.operation, self.role).index_id

    @property
    def projection_digest(self) -> str:
        return projection.profile_for(self.index_id).projection_digest

    @property
    def proof_primitive(self) -> str:
        return PROOF_PRIMITIVE

    @property
    def work_units(self) -> int:
        return 1

    @property
    def shared_group(self) -> str:
        return _role(self.operation, self.role).shared_group

    @property
    def shared_maximum_rows(self) -> int:
        return CASCADE_MAX

    def selector(self) -> dict[str, str | int]:
        return dict(self.selector_items)

    def contract_value(self) -> dict[str, Any]:
        return {
            "schema": QUERY_SCHEMA, "operation": self.operation, "role": self.role,
            "queryId": self.query_id, "table": self.table, "indexId": self.index_id,
            "projectionDigest": self.projection_digest, "selector": self.selector(),
            "maximumRows": self.maximum_rows, "proofPrimitive": PROOF_PRIMITIVE,
            "workUnits": 1, "overflowDisposition": "fail-closed",
            "order": "fixed-index-key", "sharedBudget": {
                "group": self.shared_group, "maximumRows": CASCADE_MAX,
                "measure": "distinct-primary-address-union",
            },
        }


def snapshot_query(query: CompleteIndexQuery) -> CompleteIndexQuery:
    """Return a fresh revalidated declaration, never a verified result token."""
    if type(query) is not CompleteIndexQuery:
        raise CompleteQueryError("complete query has an unexpected exact type")
    try:
        return CompleteIndexQuery(query.operation, query.role, query.selector_items, query.maximum_rows)
    except AttributeError as exc:
        raise CompleteQueryError("complete query is incomplete") from exc


def _binding_inputs(arguments: Any, cutoff_us: Any) -> tuple[str, dict[str, int], int]:
    # Only referenced primitive fields are inspected. This is deliberately not
    # a second full business-intent validator and does not retain its audit data.
    if type(arguments) is not dict or len(arguments) > MAX_ARGUMENT_FIELDS:
        raise CompleteQueryError("complete query arguments are not a bounded exact dictionary")
    if type(arguments.get("source")) is not str or arguments["source"] != "explicit":
        raise CompleteQueryError("complete query roles require explicit revocation")
    record_id = _source_id(arguments.get("record_id"))
    sizes = {}
    for name in _HINT_FIELDS:
        supplied = arguments.get(name)
        if type(supplied) is not list or len(supplied) > CASCADE_MAX:
            raise CompleteQueryError("complete query hint inventory exceeds its source bound")
        owned = tuple(_source_id(item) for item in supplied)
        if owned != tuple(sorted(set(owned))):
            raise CompleteQueryError("complete query hints are not sorted and unique")
        sizes[name] = len(owned)
    return record_id, sizes, _cutoff(cutoff_us)


def _bind(operation: str, declared: _Role, inputs: tuple[str, dict[str, int], int]) -> CompleteIndexQuery:
    record_id, sizes, cutoff_us = inputs
    if declared.name == "global_registration_challenges":
        selector = (("expires_after_us", cutoff_us),)
    elif declared.status is not None:
        selector = (("credential_record_id", record_id), ("status", declared.status))
    else:
        selector = (("credential_record_id", record_id),)
    return CompleteIndexQuery(operation, declared.name, selector, max(1, sizes[declared.hint_field]))


def bind_query(operation: str, role: str, *, arguments: Any, cutoff_us: int) -> CompleteIndexQuery:
    """Derive a fixed role from supplied intent/time, not caller index claims."""
    declared = _role(operation, role)
    return _bind(operation, declared, _binding_inputs(arguments, cutoff_us))


def validate_bindings(operation: str, complete_queries: tuple[CompleteIndexQuery, ...], *,
                      arguments: Any, cutoff_us: int) -> tuple[CompleteIndexQuery, ...]:
    """Require all five exact roles and rederive bindings from actual inputs.

    Hint lengths are only fail-closed overflow allowances. They do not prove a
    result count or authorize omission. Future evidence admission must also
    enforce each shared union ceiling and the existing operation-wide bounds.
    """
    _operation(operation)
    if operation != OPERATION or type(complete_queries) is not tuple or len(complete_queries) != len(_ROLES):
        raise CompleteQueryError("complete query role inventory is not exact for its operation")
    inputs = _binding_inputs(arguments, cutoff_us)
    owned = tuple(snapshot_query(query) for query in complete_queries)
    if {query.role for query in owned} != set(ROLES):
        raise CompleteQueryError("complete query roles are missing, extra or duplicated")
    for query in owned:
        if query != _bind(operation, _role(operation, query.role), inputs):
            raise CompleteQueryError("complete query binding differs from supplied intent or cutoff")
    return owned


def role_manifest(operation: str) -> list[dict[str, Any]]:
    """Fresh fixed declarations for source commitment, not runtime activation."""
    _operation(operation)
    if operation != OPERATION:
        return []
    result = []
    for declared in _ROLES:
        profile = projection.profile_for(declared.index_id)
        sources = ({"expires_after_us": "supplied-cutoff-microseconds"}
                   if declared.name == "global_registration_challenges" else
                   {"credential_record_id": "arguments.record_id"})
        if declared.status is not None:
            sources["status"] = {"constant": declared.status}
        result.append({
            "schema": ROLE_SCHEMA, "querySchema": QUERY_SCHEMA,
            "operation": operation, "role": declared.name,
            "queryId": f"serverware.policyAuthorityQuery/{operation}/{declared.name}/{declared.table}/v1",
            "table": declared.table, "indexId": declared.index_id,
            "projectionDigest": profile.projection_digest, "selectorSources": sources,
            "requiredSource": {"arguments.source": "explicit"},
            "rowBound": {"rule": "max(1,length-of-hint-list)", "hintField": declared.hint_field,
                         "maximum": CASCADE_MAX},
            "sharedBudget": {"group": declared.shared_group, "maximumRows": CASCADE_MAX,
                             "measure": "distinct-primary-address-union"},
            "proofPrimitive": PROOF_PRIMITIVE, "workUnits": 1,
            "order": "fixed-index-key", "overflowDisposition": "fail-closed",
        })
    return result
