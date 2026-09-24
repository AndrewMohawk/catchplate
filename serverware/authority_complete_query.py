"""Source-owned complete-index query intent, not range evidence or authority.

The explicit-revocation family retains its six roles unchanged. Successor
registration has two unconditional roles and two additional OIDC-first-
enrollment roles. Arguments and cutoff are supplied intent/time, not facts.
Binding proves neither a complete index population nor a current root, trusted
clock, SQL result, authorized operation or working kernel. Actual proof and
operation admission remain mandatory. Legacy QueryProgram/v1 is unchanged.

This module may be imported by authority_contract. It deliberately imports no
core, operation registry, query reader, database or verification-result types.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from serverware import authority_index_projection as projection
from serverware.authority_query_read_work import _ValidationWork


QUERY_SCHEMA = "serverware.policyAuthorityCompleteIndexQuery/v1"
ROLE_SCHEMA = "serverware.policyAuthorityCompleteIndexQueryRole/v1"
PROOF_PRIMITIVE = "authenticated-complete-index-range"
OPERATION = "webauthn.credential.revoke"
REGISTRATION_OPERATION = "webauthn.registration.finalize"
CASCADE_MAX = 32
MAX_ARGUMENT_FIELDS = 64
MAX_SOURCE_ID_BYTES = 1024
_I64_MIN, _I64_MAX = -(2**63), 2**63 - 1
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_REGISTRATION_MODES = frozenset({"bootstrap-token", "development-bootstrap",
    "existing-webauthn", "oidc-session-first-enrollment"})
_BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class CompleteQueryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Role:
    name: str
    table: str
    index_id: str
    hint_field: str | None
    shared_group: str
    status: str | None = None

    @property
    def selector_names(self) -> tuple[str, ...]:
        if self.name == "credential_id_history":
            return ("credential_id",)
        if self.name == "user_credential_history":
            return ("user_id",)
        if self.name == "user_registration_challenges":
            return ("user_id", "expires_after_us")
        if self.name == "pending_trust_publications":
            return ("status",)
        if self.name == "global_registration_challenges":
            return ("expires_after_us",)
        return (("credential_record_id", "status") if self.status is not None
                else ("credential_record_id",))

    @property
    def maximum_rows(self) -> int:
        if self.name == "user_registration_challenges":
            return 1 + CASCADE_MAX
        return 1 if self.hint_field is None else CASCADE_MAX


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
    _Role("pending_trust_publications", "webauthn_trust_publications", "webauthn_publication_status",
          None, "pending_trust_publications", "pending"),
)
ROLES = tuple(role.name for role in _ROLES)
_REGISTRATION_ROLES = (
    _Role("credential_id_history", "webauthn_credentials", "webauthn_credential_id",
          None, "credential_id_history"),
    _Role("pending_trust_publications", "webauthn_trust_publications", "webauthn_publication_status",
          None, "pending_trust_publications", "pending"),
    _Role("user_credential_history", "webauthn_credentials", "webauthn_credential_user_history",
          None, "user_credential_history"),
    _Role("user_registration_challenges", "webauthn_challenges", "webauthn_registration_unused_user",
          "sibling_challenge_ids", "user_registration_challenges"),
)
REGISTRATION_BASE_ROLES = ("credential_id_history", "pending_trust_publications")
REGISTRATION_ROLES = REGISTRATION_BASE_ROLES + ("user_credential_history", "user_registration_challenges")
_HINT_FIELDS = ("oidc_session_ids", "approval_grant_ids",
                "control_plane_approval_ids", "registration_challenge_ids")


def _operation(value: Any) -> None:
    if type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii():
        raise CompleteQueryError("complete query operation is not a bounded exact identity")


def _role(operation: str, role: Any) -> _Role:
    _operation(operation)
    if operation not in (OPERATION, REGISTRATION_OPERATION) or type(role) is not str or not 1 <= len(role) <= 128:
        raise CompleteQueryError("complete query role is not declared for its operation")
    for candidate in (_ROLES if operation == OPERATION else _REGISTRATION_ROLES):
        if role == candidate.name:
            return candidate
    raise CompleteQueryError("complete query role is not declared for its operation")


def _source_id(value: Any, *, work: _ValidationWork | None = None) -> str:
    # Preserve the candidate's source-ID admission, not just the looser index
    # codec's 4096-byte text ceiling. Never coerce numbers, null or subclasses.
    if (type(value) is not str or not 1 <= len(value) <= MAX_SOURCE_ID_BYTES
            or value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise CompleteQueryError("complete query source ID is invalid")
    if work is not None:
        work.prepare_utf8(value)
    try:
        if len(value.encode("utf-8")) > MAX_SOURCE_ID_BYTES:
            raise CompleteQueryError("complete query source ID exceeds its UTF-8 bound")
    except UnicodeError as exc:
        raise CompleteQueryError("complete query source ID is not valid UTF-8") from exc
    return value


def _registration_id(value: Any, *, credential: bool = False,
                     work: _ValidationWork | None = None) -> str:
    """Registration uses its actual ceremony/index bounds, not revoke's 1KiB.

    The credential encoding is canonical unpadded raw1..1024 base64url. Its
    alphabet, length and unused-tail-bit checks need no decoded allocation.
    User/challenge/session identifiers retain exact UTF-8 without trimming.
    """
    maximum = 1366 if credential else 4096
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise CompleteQueryError("registration query identifier is not bounded exact text")
    if work is not None:
        work.prepare_utf8(value)
    try:
        if len(value.encode("utf-8")) > maximum or "\x00" in value:
            raise CompleteQueryError("registration query identifier exceeds its UTF-8 bound")
    except UnicodeError as exc:
        raise CompleteQueryError("registration query identifier is not valid UTF-8") from exc
    if credential:
        if work is not None:
            work.prepare_scan(value)
        remainder = len(value) % 4
        if (not 1 <= len(value) * 3 // 4 <= 1024 or remainder == 1
                or any(character not in _BASE64URL for character in value)
                or (remainder == 2 and _BASE64URL.index(value[-1]) % 16 != 0)
                or (remainder == 3 and _BASE64URL.index(value[-1]) % 4 != 0)):
            raise CompleteQueryError("registration credential query encoding is not canonical raw1..1024")
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
                or type(self.maximum_rows) is not int or not 1 <= self.maximum_rows <= declared.maximum_rows):
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
            elif self.operation == REGISTRATION_OPERATION:
                _registration_id(value, credential=name == "credential_id")
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
        return _role(self.operation, self.role).maximum_rows

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
                "group": self.shared_group, "maximumRows": self.shared_maximum_rows,
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


def _binding_inputs(
    arguments: Any, cutoff_us: Any, *, work: _ValidationWork | None = None,
) -> tuple[str, dict[str, int], int]:
    # Only referenced primitive fields are inspected. This is deliberately not
    # a second full business-intent validator and does not retain its audit data.
    if type(arguments) is not dict or len(arguments) > MAX_ARGUMENT_FIELDS:
        raise CompleteQueryError("complete query arguments are not a bounded exact dictionary")
    if type(arguments.get("source")) is not str or arguments["source"] != "explicit":
        raise CompleteQueryError("complete query roles require explicit revocation")
    record_id = _source_id(arguments.get("record_id"), work=work)
    sizes = {}
    for name in _HINT_FIELDS:
        supplied = arguments.get(name)
        if type(supplied) is not list or len(supplied) > CASCADE_MAX:
            raise CompleteQueryError("complete query hint inventory exceeds its source bound")
        if work is not None:
            work.prepare_copy(supplied)
        owned = tuple(_source_id(item, work=work) for item in supplied)
        if work is not None:
            # Conservative full-list units for the set, sorted list, and final
            # tuple. The separately prepared comparison never refunds a
            # shortcut or an input containing duplicate values.
            for _ in range(3):
                work.prepare_copy(owned)
        ordered = tuple(sorted(set(owned)))
        if work is not None:
            work.prepare_comparison(owned, ordered)
        if owned != ordered:
            raise CompleteQueryError("complete query hints are not sorted and unique")
        sizes[name] = len(owned)
    return record_id, sizes, _cutoff(cutoff_us)


def _registration_object(value: Any, label: str) -> dict:
    if (type(value) is not dict or len(value) > MAX_ARGUMENT_FIELDS
            or any(type(name) is not str or len(name) > 64 for name in value)):
        raise CompleteQueryError(f"registration query {label} is not a bounded exact object")
    return value


def _registration_binding_inputs(arguments: Any, cutoff_us: Any, *,
        work: _ValidationWork | None = None) -> tuple[str, str, bool, int, int]:
    """Own only referenced bounded scalars; full semantic admission is separate."""
    arguments = _registration_object(arguments, "arguments")
    if "oidc_session_id" not in arguments:
        raise CompleteQueryError("registration query requires its explicit nullable OIDC scope")
    intent = _registration_object(arguments.get("semantic_intent"), "intent")
    credential = _registration_object(arguments.get("credential"), "credential")
    operation, mode = intent.get("operation"), intent.get("authorizationMode")
    if (type(operation) is not str or operation != REGISTRATION_OPERATION
            or type(mode) is not str or len(mode) > 64 or mode not in _REGISTRATION_MODES):
        raise CompleteQueryError("registration query operation or enrollment mode is not source declared")
    credential_id = _registration_id(credential.get("credential_id"), credential=True, work=work)
    user_id = _registration_id(credential.get("user_id"), work=work)
    intent_user = _registration_id(intent.get("userId"), work=work)
    challenge_id = _registration_id(intent.get("challengeId"), work=work)
    if work is not None:
        work.prepare_comparison(user_id, intent_user)
    if user_id != intent_user:
        raise CompleteQueryError("registration query user differs from its semantic intent")
    supplied = arguments.get("sibling_challenge_ids")
    if type(supplied) is not list or len(supplied) > CASCADE_MAX:
        raise CompleteQueryError("registration sibling query inventory exceeds its source bound")
    if work is not None:
        work.prepare_copy(supplied)
    siblings = tuple(_registration_id(item, work=work) for item in supplied)
    if work is not None:
        for _ in range(3):
            work.prepare_copy(siblings)
    ordered = tuple(sorted(set(siblings)))
    if work is not None:
        work.prepare_comparison(siblings, ordered)
        work.prepare_scan(siblings)
        work.prepare_scan(challenge_id)
    if siblings != ordered or challenge_id in siblings:
        raise CompleteQueryError("registration sibling hints are not sorted unique other challenges")
    oidc = mode == "oidc-session-first-enrollment"
    session_id = arguments.get("oidc_session_id")
    if oidc:
        _registration_id(session_id, work=work)
    elif session_id is not None or siblings:
        raise CompleteQueryError("ordinary registration cannot supply OIDC or sibling query scope")
    return credential_id, user_id, oidc, len(siblings), _cutoff(cutoff_us)


def family_roles(operation: str, *, arguments: Any) -> tuple[str, ...]:
    """Fixed role names derived from actual mode, not a caller-selected family.

    This is bounded mode metadata only: no encoding, hashing, hint sorting or
    full argument admission. Actual scope/user/sibling/credential checks remain
    mandatory in binding and rebinding before SQL or proof verification. The
    unchanged revocation family's existing validator still checks its inputs.
    """
    _operation(operation)
    if operation == OPERATION:
        return ROLES
    if operation == REGISTRATION_OPERATION:
        arguments = _registration_object(arguments, "arguments")
        intent = _registration_object(arguments.get("semantic_intent"), "intent")
        declared_operation, mode = intent.get("operation"), intent.get("authorizationMode")
        if (type(declared_operation) is not str or declared_operation != REGISTRATION_OPERATION
                or type(mode) is not str or len(mode) > 64 or mode not in _REGISTRATION_MODES):
            raise CompleteQueryError("registration query family mode is not source declared")
        return REGISTRATION_ROLES if mode == "oidc-session-first-enrollment" else REGISTRATION_BASE_ROLES
    raise CompleteQueryError("complete query operation has no source family")


def family_limits(operation: str, *, arguments: Any) -> dict[str, int]:
    """Ordinary source bounds, with no hash, new allowance or authority token.

    Batch context accounting is 66 + 4*query_count + 2*head_count + 1 for the
    existing constructor/anchor schedule: revocation remains exactly 101 hashes.
    The fixed outside-prefix bound must be added by the actual frontier owner.
    """
    roles = family_roles(operation, arguments=arguments)
    if operation == OPERATION:
        return {"query_count": 6, "head_count": 5, "max_frontier_rows": CASCADE_MAX}
    count = len(roles)
    return {"query_count": count, "head_count": count,
        "max_frontier_rows": 1 + CASCADE_MAX if count == 4 else 1}


def _prepare_constructor_work(
    index_id: str, selector_items: tuple[tuple[str, str | int], ...],
    work: _ValidationWork,
) -> None:
    """Prepare one real constructor without constructing a second selector.

    The actual pair graph conservatively bounds both selector dictionary
    copies. Text is encoded once by the projection codec and, for source IDs,
    once more by the declaration's stricter source-ID guard.
    """
    for name, value in selector_items:
        if type(value) is str:
            work.prepare_utf8(value)
            if name != "status":
                work.prepare_utf8(value)
            if index_id == "webauthn_credential_id" and name == "credential_id":
                work.prepare_scan(value)
    work.prepare_copy(selector_items)
    work.prepare_copy(selector_items)
    descriptor = projection._definition(index_id).document()
    work.prepare_encoding(descriptor, ensure_ascii=False)
    work.charge(hashes=1)


def _bind(
    operation: str, declared: _Role, inputs: tuple[str, dict[str, int], int],
    *, work: _ValidationWork | None = None,
) -> CompleteIndexQuery:
    record_id, sizes, cutoff_us = inputs
    if declared.name == "pending_trust_publications":
        selector = (("status", "pending"),)
    elif declared.name == "global_registration_challenges":
        selector = (("expires_after_us", cutoff_us),)
    elif declared.status is not None:
        selector = (("credential_record_id", record_id), ("status", declared.status))
    else:
        selector = (("credential_record_id", record_id),)
    if work is not None:
        _prepare_constructor_work(declared.index_id, selector, work)
    maximum = 1 if declared.hint_field is None else max(1, sizes[declared.hint_field])
    return CompleteIndexQuery(operation, declared.name, selector, maximum)


def _bind_registration(declared: _Role, inputs: tuple[str, str, bool, int, int], *,
        work: _ValidationWork | None = None) -> CompleteIndexQuery:
    credential_id, user_id, oidc, sibling_count, cutoff_us = inputs
    if declared.name not in (REGISTRATION_ROLES if oidc else REGISTRATION_BASE_ROLES):
        raise CompleteQueryError("registration query role is not enabled for its actual enrollment mode")
    if declared.name == "credential_id_history":
        selector = (("credential_id", credential_id),)
    elif declared.name == "pending_trust_publications":
        selector = (("status", "pending"),)
    elif declared.name == "user_credential_history":
        selector = (("user_id", user_id),)
    else:
        selector = (("user_id", user_id), ("expires_after_us", cutoff_us))
    if work is not None:
        _prepare_constructor_work(declared.index_id, selector, work)
    maximum = 1 + sibling_count if declared.name == "user_registration_challenges" else 1
    return CompleteIndexQuery(REGISTRATION_OPERATION, declared.name, selector, maximum)


def bind_query(operation: str, role: str, *, arguments: Any, cutoff_us: int) -> CompleteIndexQuery:
    """Derive a fixed role from supplied intent/time, not caller index claims."""
    declared = _role(operation, role)
    if operation == REGISTRATION_OPERATION:
        return _bind_registration(declared, _registration_binding_inputs(arguments, cutoff_us))
    return _bind(operation, declared, _binding_inputs(arguments, cutoff_us))


def _bind_query(
    operation: str, role: str, *, arguments: Any, cutoff_us: int,
    work: _ValidationWork,
) -> CompleteIndexQuery:
    """Private metered route through the same binding and constructor body."""
    declared = _role(operation, role)
    if operation == REGISTRATION_OPERATION:
        return _bind_registration(declared,
            _registration_binding_inputs(arguments, cutoff_us, work=work), work=work)
    return _bind(operation, declared, _binding_inputs(arguments, cutoff_us, work=work), work=work)


def validate_bindings(operation: str, complete_queries: tuple[CompleteIndexQuery, ...], *,
                      arguments: Any, cutoff_us: int) -> tuple[CompleteIndexQuery, ...]:
    """Require the exact family roles and rederive bindings from actual inputs.

    Hint lengths are only fail-closed overflow allowances. They do not prove a
    result count or authorize omission. Future evidence admission must also
    enforce each shared union ceiling and the existing operation-wide bounds.
    """
    _operation(operation)
    if operation == REGISTRATION_OPERATION:
        inputs = _registration_binding_inputs(arguments, cutoff_us)
        roles = REGISTRATION_ROLES if inputs[2] else REGISTRATION_BASE_ROLES
        if type(complete_queries) is not tuple or len(complete_queries) != len(roles):
            raise CompleteQueryError("registration complete query inventory differs from its actual mode")
        owned = tuple(snapshot_query(query) for query in complete_queries)
        if tuple(query.role for query in owned) != roles:
            raise CompleteQueryError("registration complete roles are missing, duplicated or out of source order")
        for query in owned:
            if query != _bind_registration(_role(operation, query.role), inputs):
                raise CompleteQueryError("registration complete query differs from its supplied intent or cutoff")
        return owned
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
    if operation == REGISTRATION_OPERATION:
        return _registration_role_manifest()
    if operation != OPERATION:
        return []
    result = []
    for declared in _ROLES:
        profile = projection.profile_for(declared.index_id)
        sources = ({} if declared.hint_field is None else
                   {"expires_after_us": "supplied-cutoff-microseconds"}
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
            "rowBound": ({"rule": "constant", "maximum": 1} if declared.hint_field is None else
                         {"rule": "max(1,length-of-hint-list)", "hintField": declared.hint_field,
                          "maximum": CASCADE_MAX}),
            "sharedBudget": {"group": declared.shared_group, "maximumRows": declared.maximum_rows,
                             "measure": "distinct-primary-address-union"},
            "proofPrimitive": PROOF_PRIMITIVE, "workUnits": 1,
            "order": "fixed-index-key", "overflowDisposition": "fail-closed",
        })
    return result


def _registration_role_manifest() -> list[dict[str, Any]]:
    """Commit all possible roles and their exact source mode conditions."""
    result = []
    for declared in _REGISTRATION_ROLES:
        profile = projection.profile_for(declared.index_id)
        if declared.name == "credential_id_history":
            sources = {"credential_id": "arguments.credential.credential_id"}
        elif declared.name == "pending_trust_publications":
            sources = {"status": {"constant": "pending"}}
        else:
            sources = {"user_id": "arguments.credential.user_id"}
            if declared.name == "user_registration_challenges":
                sources["expires_after_us"] = "supplied-cutoff-microseconds"
        oidc_only = declared.name not in REGISTRATION_BASE_ROLES
        modes = (["oidc-session-first-enrollment"] if oidc_only else sorted(_REGISTRATION_MODES))
        result.append({
            "schema": ROLE_SCHEMA, "querySchema": QUERY_SCHEMA,
            "operation": REGISTRATION_OPERATION, "role": declared.name,
            "queryId": f"serverware.policyAuthorityQuery/{REGISTRATION_OPERATION}/{declared.name}/{declared.table}/v1",
            "table": declared.table, "indexId": declared.index_id,
            "projectionDigest": profile.projection_digest, "selectorSources": sources,
            "requiredSource": {"arguments.semantic_intent.operation": REGISTRATION_OPERATION,
                "arguments.semantic_intent.authorizationMode": {"oneOf": modes}},
            "modeBinding": {"oidcSession": "nonempty-iff-oidc-first-enrollment",
                "siblingHints": "empty-unless-oidc/sorted-unique/excludes-selected-challenge",
                "userJoin": "arguments.credential.user_id=arguments.semantic_intent.userId"},
            "rowBound": ({"rule": "constant", "maximum": 1} if declared.hint_field is None else
                {"rule": "1+length-of-hint-list", "hintField": declared.hint_field, "maximum": 1 + CASCADE_MAX}),
            "sharedBudget": {"group": declared.shared_group, "maximumRows": declared.maximum_rows,
                "measure": "distinct-primary-address-union"},
            "proofPrimitive": PROOF_PRIMITIVE, "workUnits": 1,
            "order": "fixed-index-key", "overflowDisposition": "fail-closed",
        })
    return result
