"""Source-owned complete-index query intent, not range evidence or authority.

The explicit-revocation family retains its six roles unchanged. Successor
registration has two unconditional roles and two additional OIDC-first-
enrollment roles. OIDC activation has seven fixed equality ranges. Trust staging
has five fixed ranges and four dependent ranges per declared withdrawal, all
under one unchanged 192-row closure.
Arguments and cutoff are supplied intent/time, not facts.
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
STAGE_OPERATION = "webauthn.trust.stage"
ACTIVATION_OPERATION = "oidc.session.activate"
STAGE_MAX_ROWS = 192
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
    row_ceiling: int | None = None

    @property
    def selector_names(self) -> tuple[str, ...]:
        if self.name in _ACTIVATION_SELECTORS:
            return (_ACTIVATION_SELECTORS[self.name][0],)
        if self.name == "live_trusted_credentials":
            return ()
        if self.name == "candidate_bundle_history":
            return ("bundle_digest",)
        if self.name == "candidate_or_newer_publications":
            return ("minimum_rollback_epoch", "minimum_sequence")
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
        if self.row_ceiling is not None:
            return self.row_ceiling
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
_ACTIVATION_SELECTORS = {
    "session_new_token": ("token_digest", "new_token_digest"),
    "delivery_session": ("session_id", "session_id"),
    "delivery_old_token": ("old_token_digest", "old_token_digest"),
    "delivery_new_token": ("new_token_digest", "new_token_digest"),
    "delivery_assertion": ("assertion_digest", "assertion_digest"),
    "delivery_challenge": ("challenge_id", "challenge_id"),
}
_ACTIVATION_ARGUMENT_FIELDS = frozenset({
    "session_id", "user_id", "credential_id", "credential_record_id", "challenge_id",
    "old_token_digest", "new_token_digest", "assertion_digest",
    "delivery_ttl_seconds", "businessIntent",
})
_ACTIVATION_ROLES = (
    _Role("session_new_token", "oidc_browser_sessions", "oidc_session_token_digest",
          None, "activation_session_new_token"),
    *tuple(_Role(name, "oidc_session_activation_deliveries",
                 "oidc_activation_delivery_" + selector, None, "activation_" + name)
           for name, (selector, _) in _ACTIVATION_SELECTORS.items()
           if name != "session_new_token"),
    _Role("pending_trust_publications", "webauthn_trust_publications",
          "webauthn_publication_status", None, "activation_pending_trust", "pending"),
)
ACTIVATION_ROLES = tuple(role.name for role in _ACTIVATION_ROLES)
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
_STAGE_BASE_ROLES = (
    _Role("live_trusted_credentials", "webauthn_credentials", "webauthn_credential_live_trust",
          "live_credential_ids", "stage_live_credentials", row_ceiling=STAGE_MAX_ROWS),
    _Role("global_registration_challenges", "webauthn_challenges", "webauthn_registration_unused_global",
          "registration_challenge_ids", "stage_registration_challenges", row_ceiling=STAGE_MAX_ROWS),
    _Role("pending_trust_publications", "webauthn_trust_publications", "webauthn_publication_status",
          None, "stage_pending_publications", "pending"),
    _Role("candidate_bundle_history", "webauthn_trust_publications", "webauthn_publication_bundle_digest",
          None, "stage_candidate_bundle"),
    _Role("candidate_or_newer_publications", "webauthn_trust_publications", "webauthn_publication_generation",
          None, "stage_candidate_generation"),
)
STAGE_BASE_ROLES = tuple(role.name for role in _STAGE_BASE_ROLES)
STAGE_WITHDRAWAL_ROLES = ("sessions_pending_webauthn", "sessions_active", "grants", "approvals")
_STAGE_HINT_FIELDS = frozenset({"live_credential_ids", "registration_challenge_ids", "withdrawals"})
_STAGE_WITHDRAWAL_FIELDS = frozenset({"credential_record_id", "oidc_session_ids",
    "approval_grant_ids", "control_plane_approval_ids"})
_HINT_FIELDS = ("oidc_session_ids", "approval_grant_ids",
                "control_plane_approval_ids", "registration_challenge_ids")


def _operation(value: Any) -> None:
    if type(value) is not str or not 1 <= len(value) <= 128 or not value.isascii():
        raise CompleteQueryError("complete query operation is not a bounded exact identity")


def _role(operation: str, role: Any) -> _Role:
    _operation(operation)
    if operation not in (OPERATION, REGISTRATION_OPERATION, STAGE_OPERATION, ACTIVATION_OPERATION) or type(role) is not str or not 1 <= len(role) <= 128:
        raise CompleteQueryError("complete query role is not declared for its operation")
    if operation == ACTIVATION_OPERATION:
        for candidate in _ACTIVATION_ROLES:
            if role == candidate.name:
                return candidate
        raise CompleteQueryError("activation complete role is not source declared")
    if operation == STAGE_OPERATION:
        for candidate in _STAGE_BASE_ROLES:
            if role == candidate.name:
                return candidate
        ordinal, suffix = _stage_role_parts(role)
        source = _ROLES[STAGE_WITHDRAWAL_ROLES.index(suffix)]
        group = "oidc_sessions" if suffix in STAGE_WITHDRAWAL_ROLES[:2] else source.shared_group
        return _Role(role, source.table, source.index_id, source.hint_field,
            f"stage_withdrawal_{ordinal:03d}_{group}", source.status, STAGE_MAX_ROWS)
    for candidate in (_ROLES if operation == OPERATION else _REGISTRATION_ROLES):
        if role == candidate.name:
            return candidate
    raise CompleteQueryError("complete query role is not declared for its operation")


def _stage_role_parts(role: str) -> tuple[int, str]:
    """Closed source ordinal metadata; actual argument membership is rebound."""
    if (type(role) is not str or not 16 <= len(role) <= 128
            or role[:11] != "withdrawal_" or role[14:15] != "_"
            or len(role[11:14]) != 3 or any(char not in "0123456789" for char in role[11:14])
            or role[15:] not in STAGE_WITHDRAWAL_ROLES):
        raise CompleteQueryError("trust-stage dependent role is not source declared")
    ordinal = int(role[11:14])
    if ordinal >= STAGE_MAX_ROWS:
        raise CompleteQueryError("trust-stage dependent ordinal exceeds the source bound")
    return ordinal, role[15:]


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
            elif self.operation == STAGE_OPERATION and name in ("minimum_rollback_epoch", "minimum_sequence"):
                _stage_integer(value, minimum=1 if name == "minimum_sequence" else 0)
            elif self.operation == STAGE_OPERATION and name == "bundle_digest":
                _source_id(value)
                _stage_digest(value)
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


def _stage_object(value: Any, label: str, *, fields: frozenset[str] | None = None) -> dict:
    if (type(value) is not dict or len(value) > MAX_ARGUMENT_FIELDS
            or any(type(name) is not str or len(name) > 64 for name in value)
            or fields is not None and set(value) != fields):
        raise CompleteQueryError(f"trust-stage query {label} is not a closed bounded object")
    return value


def _stage_integer(value: Any, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value <= _I64_MAX:
        raise CompleteQueryError("trust-stage generation selector is not source bounded")
    return value


def _stage_digest(value: Any, *, work: _ValidationWork | None = None) -> str:
    if work is not None and type(value) is str and len(value) == 71:
        work.prepare_scan(value)
    if (type(value) is not str or len(value) != 71 or value[:7] != "sha256:"
            or any(char not in "0123456789abcdef" for char in value[7:])):
        raise CompleteQueryError("trust-stage candidate bundle digest is not canonical")
    return value


def _stage_withdrawal_count(arguments: Any) -> int:
    """Hash/encoding-free family metadata, not full hint or scope admission."""
    arguments = _stage_object(arguments, "arguments")
    hints = _stage_object(arguments.get("query_hints"), "hints", fields=_STAGE_HINT_FIELDS)
    withdrawals = hints["withdrawals"]
    if (type(withdrawals) is not list or len(withdrawals) > STAGE_MAX_ROWS
            or len(STAGE_BASE_ROLES) + len(STAGE_WITHDRAWAL_ROLES) * len(withdrawals) > STAGE_MAX_ROWS):
        raise CompleteQueryError("trust-stage query count exceeds the whole-operation bound")
    return len(withdrawals)


def _stage_family_roles(count: int) -> tuple[str, ...]:
    return STAGE_BASE_ROLES + tuple(f"withdrawal_{ordinal:03d}_{suffix}"
        for ordinal in range(count) for suffix in STAGE_WITHDRAWAL_ROLES)


def _stage_ids(value: Any, *, work: _ValidationWork | None = None) -> tuple[str, ...]:
    if type(value) is not list or len(value) > STAGE_MAX_ROWS:
        raise CompleteQueryError("trust-stage query hint list exceeds the shared bound")
    if work is not None:
        work.prepare_copy(value)
    owned = tuple(_source_id(item, work=work) for item in value)
    if work is not None:
        for _ in range(3):
            work.prepare_copy(owned)
    ordered = tuple(sorted(set(owned)))
    if work is not None:
        work.prepare_comparison(owned, ordered)
    if owned != ordered:
        raise CompleteQueryError("trust-stage query hints are not sorted unique source IDs")
    return owned


def _stage_binding_inputs(arguments: Any, cutoff_us: Any, *, work: _ValidationWork | None = None):
    """Own referenced scalar/list inputs; hints never prove any population.

    One aggregate hint bound counts live credentials, challenges and all
    dependent hints. Withdrawn credentials must already occur in the live
    hints. The actual complete/scaffold program separately retains its existing
    conservative sum(maximum_rows) cap, including both session-status maxima.
    """
    count = _stage_withdrawal_count(arguments)
    hints = arguments["query_hints"]
    bundle = _stage_digest(arguments.get("bundle_digest"), work=work)
    epoch = _stage_integer(arguments.get("rollback_epoch"), minimum=0)
    sequence = _stage_integer(arguments.get("sequence"), minimum=1)
    live = _stage_ids(hints["live_credential_ids"], work=work)
    challenges = _stage_ids(hints["registration_challenge_ids"], work=work)
    withdrawn = _stage_ids(arguments.get("withdrawn_credential_ids"), work=work)
    if len(withdrawn) != count:
        raise CompleteQueryError("trust-stage withdrawal hints differ from the declared withdrawal count")
    if work is not None:
        work.prepare_copy(live)
    live_set = set(live)
    if work is not None:
        work.prepare_scan(withdrawn)
    if any(identifier not in live_set for identifier in withdrawn):
        raise CompleteQueryError("trust-stage withdrawals escape the live credential hints")
    total = len(live) + len(challenges)
    if total > STAGE_MAX_ROWS:
        raise CompleteQueryError("trust-stage hints exceed the whole-operation row bound")
    if work is not None:
        work.prepare_copy(hints["withdrawals"])
    withdrawals = []
    for ordinal, raw in enumerate(hints["withdrawals"]):
        item = _stage_object(raw, "withdrawal", fields=_STAGE_WITHDRAWAL_FIELDS)
        identifier = _source_id(item["credential_record_id"], work=work)
        if work is not None:
            work.prepare_comparison(identifier, withdrawn[ordinal])
        if identifier != withdrawn[ordinal]:
            raise CompleteQueryError("trust-stage withdrawal records are not the exact sorted declared IDs")
        sizes = {}
        for name in _HINT_FIELDS[:3]:
            ids = _stage_ids(item[name], work=work)
            if len(ids) > STAGE_MAX_ROWS - total:
                raise CompleteQueryError("trust-stage dependent hints exceed the aggregate row bound")
            total += len(ids)
            sizes[name] = len(ids)
        withdrawals.append((identifier, sizes))
    if work is not None:
        work.prepare_copy(withdrawals)
    return bundle, epoch, sequence, len(live), len(challenges), tuple(withdrawals), _cutoff(cutoff_us)


def family_roles(operation: str, *, arguments: Any) -> tuple[str, ...]:
    """Fixed names from actual mode/count, not a caller-selected role family.

    This is bounded mode/count metadata only: no encoding, hashing, hint sorting or
    full argument admission. Actual scope/user/sibling/credential checks remain
    mandatory in binding and rebinding before SQL or proof verification. The
    unchanged revocation family's existing validator still checks its inputs.
    """
    _operation(operation)
    if operation == ACTIVATION_OPERATION:
        return ACTIVATION_ROLES
    if operation == OPERATION:
        return ROLES
    if operation == STAGE_OPERATION:
        return _stage_family_roles(_stage_withdrawal_count(arguments))
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
    if operation == ACTIVATION_OPERATION:
        return {"query_count": 7, "head_count": 7, "max_frontier_rows": 1}
    if operation == OPERATION:
        return {"query_count": 6, "head_count": 5, "max_frontier_rows": CASCADE_MAX}
    if operation == STAGE_OPERATION:
        return {"query_count": len(roles), "head_count": 5 if len(roles) == 5 else 8,
            "max_frontier_rows": STAGE_MAX_ROWS}
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
            if index_id == "webauthn_publication_bundle_digest" and name == "bundle_digest":
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


def _bind_stage(declared: _Role, inputs, *, work: _ValidationWork | None = None) -> CompleteIndexQuery:
    bundle, epoch, sequence, live_count, challenge_count, withdrawals, cutoff_us = inputs
    maximum = 1
    if declared.name == "live_trusted_credentials":
        selector = ()
        maximum = max(1, live_count)
    elif declared.name == "global_registration_challenges":
        selector = (("expires_after_us", cutoff_us),)
        maximum = max(1, challenge_count)
    elif declared.name == "pending_trust_publications":
        selector = (("status", "pending"),)
    elif declared.name == "candidate_bundle_history":
        selector = (("bundle_digest", bundle),)
    elif declared.name == "candidate_or_newer_publications":
        selector = (("minimum_rollback_epoch", epoch), ("minimum_sequence", sequence))
    else:
        ordinal, _ = _stage_role_parts(declared.name)
        if ordinal >= len(withdrawals):
            raise CompleteQueryError("trust-stage dependent role has no actual withdrawal")
        identifier, sizes = withdrawals[ordinal]
        selector = (("credential_record_id", identifier),)
        if declared.status is not None:
            selector += (("status", declared.status),)
        maximum = max(1, sizes[declared.hint_field])
    if work is not None:
        _prepare_constructor_work(declared.index_id, selector, work)
    return CompleteIndexQuery(STAGE_OPERATION, declared.name, selector, maximum)


def _activation_binding_inputs(arguments: Any, cutoff_us: Any, *,
                               work: _ValidationWork | None = None) -> dict[str, Any]:
    """Fixed scalar intent only; businessIntent and assertion admission are separate."""
    _cutoff(cutoff_us)
    if (type(arguments) is not dict or len(arguments) != len(_ACTIVATION_ARGUMENT_FIELDS)
            or set(arguments) != _ACTIVATION_ARGUMENT_FIELDS
            or type(arguments["businessIntent"]) is not dict):
        raise CompleteQueryError("activation query arguments are not source closed")
    values = {}
    for name in ("session_id", "user_id", "credential_record_id", "challenge_id"):
        value = _source_id(arguments[name], work=work)
        if name == "session_id":
            if work is not None:
                work.prepare_utf8(value)
            if len(value.encode("utf-8")) > 128:
                raise CompleteQueryError("activation session identifier exceeds its bound")
        values[name] = value
    values["credential_id"] = _registration_id(arguments["credential_id"], credential=True, work=work)
    for name in ("old_token_digest", "new_token_digest", "assertion_digest"):
        values[name] = _stage_digest(arguments[name], work=work)
    ttl = arguments["delivery_ttl_seconds"]
    if type(ttl) is not int or not 5 <= ttl <= 60:
        raise CompleteQueryError("activation delivery lifetime is outside its source bound")
    values["delivery_ttl_seconds"] = ttl
    return values


def _bind_activation(declared: _Role, inputs: dict[str, Any], *,
                     work: _ValidationWork | None = None) -> CompleteIndexQuery:
    if declared.name == "pending_trust_publications":
        selector = (("status", "pending"),)
    else:
        name, argument = _ACTIVATION_SELECTORS[declared.name]
        selector = ((name, inputs[argument]),)
    if work is not None:
        _prepare_constructor_work(declared.index_id, selector, work)
    return CompleteIndexQuery(ACTIVATION_OPERATION, declared.name, selector, 1)


def bind_query(operation: str, role: str, *, arguments: Any, cutoff_us: int) -> CompleteIndexQuery:
    """Derive a fixed role from supplied intent/time, not caller index claims."""
    declared = _role(operation, role)
    if operation == ACTIVATION_OPERATION:
        return _bind_activation(declared, _activation_binding_inputs(arguments, cutoff_us))
    if operation == STAGE_OPERATION:
        return _bind_stage(declared, _stage_binding_inputs(arguments, cutoff_us))
    if operation == REGISTRATION_OPERATION:
        return _bind_registration(declared, _registration_binding_inputs(arguments, cutoff_us))
    return _bind(operation, declared, _binding_inputs(arguments, cutoff_us))


def _bind_query(
    operation: str, role: str, *, arguments: Any, cutoff_us: int,
    work: _ValidationWork,
) -> CompleteIndexQuery:
    """Private metered route through the same binding and constructor body."""
    declared = _role(operation, role)
    if operation == ACTIVATION_OPERATION:
        return _bind_activation(declared,
            _activation_binding_inputs(arguments, cutoff_us, work=work), work=work)
    if operation == STAGE_OPERATION:
        return _bind_stage(declared, _stage_binding_inputs(arguments, cutoff_us, work=work), work=work)
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
    if operation == ACTIVATION_OPERATION:
        inputs = _activation_binding_inputs(arguments, cutoff_us)
        if type(complete_queries) is not tuple or len(complete_queries) != len(ACTIVATION_ROLES):
            raise CompleteQueryError("activation complete query inventory is not exact")
        owned = tuple(snapshot_query(query) for query in complete_queries)
        if tuple(query.role for query in owned) != ACTIVATION_ROLES:
            raise CompleteQueryError("activation complete roles are missing, duplicated or out of order")
        for query in owned:
            if query != _bind_activation(_role(operation, query.role), inputs):
                raise CompleteQueryError("activation complete query differs from its original arguments")
        return owned
    if operation == STAGE_OPERATION:
        inputs = _stage_binding_inputs(arguments, cutoff_us)
        roles = _stage_family_roles(len(inputs[5]))
        if type(complete_queries) is not tuple or len(complete_queries) != len(roles):
            raise CompleteQueryError("trust-stage complete query inventory differs from actual withdrawals")
        owned = tuple(snapshot_query(query) for query in complete_queries)
        if tuple(query.role for query in owned) != roles:
            raise CompleteQueryError("trust-stage complete roles are missing, duplicated or out of source order")
        for query in owned:
            if query != _bind_stage(_role(operation, query.role), inputs):
                raise CompleteQueryError("trust-stage complete query differs from its actual intent or cutoff")
        return owned
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
    if operation == ACTIVATION_OPERATION:
        return _activation_role_manifest()
    if operation == STAGE_OPERATION:
        return _stage_role_manifest()
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


def _activation_role_manifest() -> list[dict[str, Any]]:
    result = []
    for declared in _ACTIVATION_ROLES:
        profile = projection.profile_for(declared.index_id)
        if declared.name == "pending_trust_publications":
            sources = {"status": {"constant": "pending"}}
        else:
            selector, argument = _ACTIVATION_SELECTORS[declared.name]
            sources = {selector: "arguments." + argument}
        result.append({
            "schema": ROLE_SCHEMA, "querySchema": QUERY_SCHEMA,
            "operation": ACTIVATION_OPERATION, "role": declared.name,
            "queryId": f"serverware.policyAuthorityQuery/{ACTIVATION_OPERATION}/{declared.name}/{declared.table}/v1",
            "table": declared.table, "indexId": declared.index_id,
            "projectionDigest": profile.projection_digest, "selectorSources": sources,
            "rowBound": {"rule": "constant", "maximum": 1},
            "sharedBudget": {"group": declared.shared_group, "maximumRows": 1,
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


def _stage_role_manifest() -> list[dict[str, Any]]:
    """Five literals plus four closed ordinal templates, not an open DSL.

    Runtime roles are expanded only from actual sorted withdrawal records.
    Hint admission, exact rebinding, conservative complete/scaffold row sums
    and actual distinct-address union checks remain independently mandatory.
    """
    result = []
    for declared in _STAGE_BASE_ROLES:
        if declared.name == "live_trusted_credentials":
            sources = {}
        elif declared.name == "global_registration_challenges":
            sources = {"expires_after_us": "supplied-cutoff-microseconds"}
        elif declared.name == "pending_trust_publications":
            sources = {"status": {"constant": "pending"}}
        elif declared.name == "candidate_bundle_history":
            sources = {"bundle_digest": "arguments.bundle_digest"}
        else:
            sources = {"minimum_rollback_epoch": "arguments.rollback_epoch",
                "minimum_sequence": "arguments.sequence"}
        result.append({
            "schema": ROLE_SCHEMA, "querySchema": QUERY_SCHEMA,
            "operation": STAGE_OPERATION, "role": declared.name,
            "queryId": f"serverware.policyAuthorityQuery/{STAGE_OPERATION}/{declared.name}/{declared.table}/v1",
            "table": declared.table, "indexId": declared.index_id,
            "projectionDigest": projection.profile_for(declared.index_id).projection_digest,
            "selectorSources": sources, "requiredSource": {"queryHintsRequired": True},
            "rowBound": ({"rule": "constant", "maximum": 1} if declared.hint_field is None else
                {"rule": "max(1,length-of-hint-list)",
                 "hintField": "arguments.query_hints." + declared.hint_field, "maximum": STAGE_MAX_ROWS}),
            "sharedBudget": {"group": declared.shared_group, "maximumRows": declared.maximum_rows,
                "measure": "distinct-primary-address-union"},
            "proofPrimitive": PROOF_PRIMITIVE, "workUnits": 1,
            "order": "fixed-index-key", "overflowDisposition": "fail-closed",
        })
    for suffix in STAGE_WITHDRAWAL_ROLES:
        declared = _role(STAGE_OPERATION, "withdrawal_000_" + suffix)
        pattern = "withdrawal_{ordinal:03d}_" + suffix
        sources = {"credential_record_id": "arguments.query_hints.withdrawals[ordinal].credential_record_id"}
        if declared.status is not None:
            sources["status"] = {"constant": declared.status}
        result.append({
            "schema": ROLE_SCHEMA, "querySchema": QUERY_SCHEMA,
            "operation": STAGE_OPERATION, "rolePattern": pattern,
            "queryIdPattern": f"serverware.policyAuthorityQuery/{STAGE_OPERATION}/{pattern}/{declared.table}/v1",
            "ordinal": {"minimum": 0, "maximum": STAGE_MAX_ROWS - 1, "width": 3,
                "source": "arguments.query_hints.withdrawals", "order": "credential_record_id-ascending-unique"},
            "table": declared.table, "indexId": declared.index_id,
            "projectionDigest": projection.profile_for(declared.index_id).projection_digest,
            "selectorSources": sources,
            "requiredSource": {"withdrawals": "exact-sorted-match-arguments.withdrawn_credential_ids",
                "withdrawnCredentials": "subset-of-live_credential_ids"},
            "rowBound": {"rule": "max(1,length-of-hint-list)", "maximum": STAGE_MAX_ROWS,
                "hintField": "arguments.query_hints.withdrawals[ordinal]." + declared.hint_field},
            "sharedBudget": {"groupPattern": declared.shared_group.replace("000", "{ordinal:03d}", 1),
                "maximumRows": STAGE_MAX_ROWS, "measure": "distinct-primary-address-union"},
            "proofPrimitive": PROOF_PRIMITIVE, "workUnits": 1,
            "order": "fixed-index-key", "overflowDisposition": "fail-closed",
        })
    # Repeated source metadata is deliberately fixed-size: no argument graph,
    # input-dependent role expansion or proof work is performed by a manifest.
    for item in result:
        item["hintAdmission"] = {"fields": sorted(_STAGE_HINT_FIELDS),
            "withdrawalFields": sorted(_STAGE_WITHDRAWAL_FIELDS),
            "ids": "exact-sorted-unique/source-UTF8-1024/no-controls-or-surrounding-whitespace",
            "withdrawalJoin": "exact-sorted-match-arguments.withdrawn_credential_ids/subset-of-live_credential_ids"}
        item["operationWideBudget"] = {"maximumRows": STAGE_MAX_ROWS,
            "maximumQueryCount": STAGE_MAX_ROWS,
            "hintMeasure": "live+registration+all-dependent-list-lengths",
            "declarationMeasure": "sum(maximum_rows)-including-both-session-statuses-and-scaffold",
            "resultMeasure": "distinct-primary-address-union-including-scaffold",
            "overflowDisposition": "reject-entire-operation"}
    return result
