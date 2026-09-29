from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_audit_capacity
from serverware.authority_audit_trace import (
    AuditTraceBudget,
    AuditTraceError,
    MAX_PLAN_TRACE_ENTRIES,
    audit_capacity_scan_key,
)
from serverware import authority_contract
from serverware import authority_publication_approval as publication_approval
from serverware import authority_public_revocation_approval as public_revocation_approval
from serverware import authority_oauth_activation as oauth_activation
from serverware import authority_oauth_exchange as oauth_exchange
from serverware import authority_oauth_measured_exchange as oauth_measured_exchange
from serverware import authority_oauth_inventory
from serverware import authority_policy_candidate as policy_candidate
from serverware import authority_policy_candidate_inventory
from serverware import authority_policy_canary
from serverware import authority_policy_canary_tables
from serverware import authority_policy_canary_delivery
from serverware import authority_policy_canary_delivery_policy
from serverware import authority_complete_query
from serverware import authority_complete_acquisition
from serverware import authority_complete_query_batch
from serverware import authority_complete_read_write
from serverware.authority_index_contract import IndexRangeError
from serverware import authority_index_trace
from serverware import authority_index_heads
from serverware import authority_index_reader
from serverware import authority_index_mutation_reader
from serverware import authority_indexed_mutation
from serverware import authority_index_projection
from serverware import authority_primary_contract
from serverware import authority_query_reads
from serverware.authority_query_read_work import (
    _ValidationWork, QueryReadValidationLimits, QueryReadValidationMetrics, QueryReadWorkError,
)
# Preserve the existing planner names as direct re-exports of the actual
# registry-free computation bodies. Public request admission remains below.
from serverware.authority_request_commitment import (
    AuthorityPlannerError,
    _authorization_arguments,
    _business_intent,
    _request_different,
    _typed_request_digest,
    canonical_bytes,
    framed_digest,
    operation_id,
)
from serverware import authority_query_staging
from serverware import authority_radix_proof
from serverware import authority_root_transition
from serverware import authority_revocation_semantics
from serverware import authority_revocation_proof_bundle
from serverware import authority_revocation_plan
from serverware import authority_revocation_plan_production
from serverware import authority_revocation_observed
from serverware import authority_revocation_retention
from serverware import authority_transition_core
from serverware import authority_transition_registry
from serverware import authority_transition_webauthn
from serverware import authority_transition_webauthn_registration
from serverware import authority_transition_webauthn_trust_stage
from serverware import authority_transition_webauthn_completion
from serverware import authority_webauthn_assertion
from serverware import authority_webauthn_trust_candidate
from serverware.config import (
    WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX,
    WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX,
    WEBAUTHN_CHALLENGE_MAX_RETAINED,
    WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS,
    WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS,
    WEBAUTHN_CHALLENGE_USER_LIVE_MAX,
    WEBAUTHN_CHALLENGE_USER_RATE_MAX,
)


PLANNER_REQUEST_SCHEMA = "serverware.policyAuthorityPlannerRequest/v1"
PLANNER_RESPONSE_SCHEMA = "serverware.policyAuthorityPlannerResponse/v3"
MEASURED_PLAN_SCHEMA = "serverware.policyAuthorityMeasuredPlan/v3"
SIGNED_MEASURED_PLAN_SCHEMA = (
    "serverware.signedPolicyAuthorityMeasuredPlan/v3"
)
PLANNER_PERSIST_REQUEST_SCHEMA = (
    "serverware.policyAuthorityPlannerPersistRequest/v1"
)
PLANNER_PERSIST_RECEIPT_SCHEMA = (
    "serverware.policyAuthorityPlannerPersistReceipt/v1"
)
PLANNER_REPLAY_RECEIPT_SCHEMA = (
    "serverware.policyAuthorityPlannerReplayReceipt/v1"
)
EXECUTION_RESERVATION_RECEIPT_SCHEMA = (
    "serverware.policyAuthorityExecutionReservationReceipt/v1"
)
PLANNER_TRACE_SCHEMA = "serverware.policyAuthorityPlannerTrace/v1"
PLANNER_PROGRAM_SCHEMA = "serverware.policyAuthorityPlannerProgram/v1"
BUSINESS_INTENT_SCHEMA = authority_contract.BUSINESS_INTENT_SCHEMA
_EVIDENCE_ADMISSION_READ_OPERATIONS = frozenset({
    "webauthn.registration.evidence.admit",
    "webauthn.trust.installation.admit",
})
WEBAUTHN_CHALLENGE_SELECTOR_OVERFLOW_LIMIT = (
    authority_contract.MAX_QUERY_PROOFS
)
WEBAUTHN_CHALLENGE_PLANNING_SCAN_MAX = (
    WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX
    + WEBAUTHN_CHALLENGE_MAX_RETAINED
)
WEBAUTHN_CHALLENGE_OPERATIONS = (
    authority_transition_registry.WEBAUTHN_CHALLENGE_OPERATIONS
)
WEBAUTHN_CHALLENGE_ROW_FIELDS = frozenset(
    {
        "id",
        "challenge",
        "challenge_type",
        "user_id",
        "scope_key",
        "approval_request_id",
        "payload_json",
        "expires_at",
        "used_at",
        "created_at",
    }
)
AUTHORITATIVE_INPUT_FIELDS = frozenset(
    {
        "authorityRootSetBeforeDigest",
        "authoritySnapshotDigest",
        "attestationReceiptDigest",
        "authorizationProjection",
        "authorizationProjectionDigest",
        "expectedResult",
        "expectedResultDigest",
        "generationDigest",
        "generationSequence",
        "identityDigest",
        "launchIdentityCertificate",
        "measurementDigest",
        "mutationPlan",
        "mutationPlanDigest",
        "plannerAttestationReceiptDigest",
        "plannerIdentity",
        "plannerMeasurementDigest",
        "plannerSessionIdentityDigest",
        "publicationReceiptSha256",
        "queryMultiproofs",
        "queryProofs",
        "rootTransition",
        "rootTransitionDigest",
        "selectedBusinessRows",
        "selectedBusinessRowsDigest",
        "sessionIdentityDigest",
        "transactionResult",
        "runtimeAttestationReceiptSha256",
        "verifierAttestationReceiptDigest",
        "verifierIdentity",
        "verifierMeasurementDigest",
        "verifierSessionIdentityDigest",
        "workUnits",
    }
)
AUTHORITATIVE_NORMALIZED_FIELDS = frozenset(
    {
        "attestation",
        "identity",
        "multiproof",
        "multiproofs",
        "mutation",
        "mutations",
        "result",
        "root",
        "roots",
        "selectedrow",
        "selectedrows",
        "transactionresult",
    }
)
AUTHORITATIVE_NORMALIZED_MARKERS = (
    "attestation",
    "authorityroot",
    "expectedresult",
    "identitydigest",
    "launchidentity",
    "measurementdigest",
    "multiproof",
    "mutationplan",
    "publicationreceipt",
    "rootset",
    "runtimeattestation",
    "selectedbusinessrow",
    "selectedrow",
)


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def decode_base64url(
    value: object,
    *,
    label: str,
    size: int | None = None,
) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or any(
            character
            not in (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789-_"
            )
            for character in value
        )
    ):
        raise AuthorityPlannerError(
            f"{label} is not canonical base64url"
        )
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * ((4 - len(value) % 4) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise AuthorityPlannerError(
            f"{label} is not canonical base64url"
        ) from exc
    encoded = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if encoded != value or size is not None and len(decoded) != size:
        raise AuthorityPlannerError(
            f"{label} is not canonical base64url"
        )
    return decoded


def typed_request_digest(request: Mapping[str, Any]) -> str:
    # Computing a source-declared digest is not permission to plan it. Keep
    # the public registration gate here, before the shared computation body.
    if request.get("operation") not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS:
        raise AuthorityPlannerError("typed planner request is not closed")
    return _typed_request_digest(request, work=None)


def _require_digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AuthorityPlannerError(f"{label} is not a canonical digest")
    return value


def _require_utc_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorityPlannerError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise AuthorityPlannerError(
            f"{label} is not a UTC timestamp"
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat() != value
    ):
        raise AuthorityPlannerError(f"{label} is not a UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _epoch_nanoseconds(value: datetime) -> int:
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _webauthn_public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    if set(row) != WEBAUTHN_CHALLENGE_ROW_FIELDS:
        raise AuthorityPlannerError(
            "WebAuthn challenge row is not closed"
        )
    try:
        payload = json.loads(str(row["payload_json"]))
    except json.JSONDecodeError as exc:
        raise AuthorityPlannerError(
            "WebAuthn challenge payload JSON is invalid"
        ) from exc
    public = dict(row)
    public.pop("payload_json")
    public["payload"] = payload
    return public


def _selected_business_row(
    *,
    table: str,
    key: Mapping[str, Any],
    row: Mapping[str, Any] | None,
    contract_selector: str | None = None,
) -> dict[str, Any]:
    key_value = dict(key)
    return {
        "table": table,
        "key": key_value,
        "keyDigest": framed_digest(
            "serverware.policyAuthorityBusinessKey/v1",
            table.encode("utf-8"),
            canonical_bytes(key_value),
        ),
        "present": row is not None,
        "row": None if row is None else dict(row),
        "contractSelector": contract_selector,
    }


def _planned_business_mutation(
    *,
    operation: str,
    selected: Mapping[str, Any],
    row: Mapping[str, Any],
) -> dict[str, Any]:
    mutation = "UPDATE" if selected["present"] else "INSERT"
    templates = [
        template
        for template
        in authority_contract.operation_spec(operation)[
            "mutationTemplates"
        ]
        if (
            template["table"] == selected["table"]
            and template["mutation"] == mutation
        )
    ]
    if len(templates) != 1:
        raise AuthorityPlannerError(
            "typed planning mutation template is not unique"
        )
    return {
        "templateId": templates[0]["templateId"],
        "operation": mutation,
        "table": selected["table"],
        "key": dict(selected["key"]),
        "keyDigest": selected["keyDigest"],
        "expectedRow":
            dict(selected["row"]) if selected["present"] else None,
        "row": dict(row),
    }


def reject_authoritative_input(value: Any, *, path: str = "input") -> None:
    if isinstance(value, list):
        for index, item in enumerate(value):
            reject_authoritative_input(item, path=f"{path}[{index}]")
        return
    if not isinstance(value, Mapping):
        return
    forbidden = AUTHORITATIVE_INPUT_FIELDS.intersection(value)
    normalized_forbidden = {
        str(key)
        for key in value
        if (
            (
                normalized := "".join(
                    character.lower()
                    for character in str(key)
                    if character.isalnum()
                )
            )
            in AUTHORITATIVE_NORMALIZED_FIELDS
            or any(
                marker in normalized
                for marker in AUTHORITATIVE_NORMALIZED_MARKERS
            )
        )
    }
    if forbidden or normalized_forbidden:
        raise AuthorityPlannerError(
            f"{path} contains caller-authored authority fields"
        )
    for key, item in value.items():
        reject_authoritative_input(item, path=f"{path}.{key}")


def reject_typed_authoritative_input(operation: str, value: Mapping[str, Any]) -> None:
    if operation in oauth_measured_exchange.OPERATIONS:
        oauth_measured_exchange.arguments(operation, value, typed=True)
        evidence = dict(value["native_evidence"])
        evidence["nativeKeyEvidence"] = {name: item for name, item in evidence["nativeKeyEvidence"].items()
            if name != "attestationDocumentB64"}
        reject_authoritative_input({**value, "native_evidence": evidence})
    elif operation.startswith("oauth.measured-refresh.") or operation.startswith("oauth.measured-refresh-cleanup.") or operation.startswith("oauth.measured-pending-retirement.") or operation.startswith("oauth.measured-capture-retirement."):
        if operation.startswith("oauth.measured-capture-retirement."):
            from serverware import authority_oauth_measured_capture_retirement as measured
        elif operation.startswith("oauth.measured-pending-retirement."):
            from serverware import authority_oauth_measured_pending_retirement as measured
        elif operation.startswith("oauth.measured-refresh-cleanup."):
            from serverware import authority_oauth_measured_cleanup as measured
        else:
            from serverware import authority_oauth_measured_refresh as measured
        measured.arguments(operation, value, typed=True)
        # This exact field is a bounded original COSE byte string, not an
        # attestation verdict. Both actual authority roles independently verify
        # it. Keep every other input under the unchanged authority-name guard.
        evidence = dict(value["evidence"])
        evidence["nativeKeyEvidence"] = {name: item for name, item in evidence["nativeKeyEvidence"].items()
            if name != "attestationDocumentB64"}
        reject_authoritative_input({**value, "evidence": evidence})
    else:
        reject_authoritative_input(value)


@dataclass(frozen=True, slots=True)
class PlannerIdentity:
    database_role: str
    tls_client_dn: str
    tls_client_serial: str
    tls_issuer_dn: str
    session_identity_digest: str
    measurement_digest: str
    attestation_receipt_digest: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PlannerIdentity":
        required = {
            "databaseRole",
            "tlsClientDn",
            "tlsClientSerial",
            "tlsIssuerDn",
            "sessionIdentityDigest",
            "measurementDigest",
            "attestationReceiptDigest",
        }
        if (
            set(value) != required
            or any(
                not isinstance(value[field], str) or not value[field]
                for field in (
                    "databaseRole",
                    "tlsClientDn",
                    "tlsClientSerial",
                    "tlsIssuerDn",
                )
            )
        ):
            raise AuthorityPlannerError("planner identity is not closed")
        for field in (
            "sessionIdentityDigest",
            "measurementDigest",
            "attestationReceiptDigest",
        ):
            _require_digest(value[field], f"planner {field}")
        return cls(
            database_role=value["databaseRole"],
            tls_client_dn=value["tlsClientDn"],
            tls_client_serial=value["tlsClientSerial"],
            tls_issuer_dn=value["tlsIssuerDn"],
            session_identity_digest=value["sessionIdentityDigest"],
            measurement_digest=value["measurementDigest"],
            attestation_receipt_digest=value["attestationReceiptDigest"],
        )


@dataclass(frozen=True, slots=True)
class PlannedTransition:
    selected_business_rows: tuple[dict[str, Any], ...]
    mutation_plan: tuple[dict[str, Any], ...]
    result: Any
    work_units: int = 1


@dataclass(frozen=True, slots=True)
class PlanningState:
    database_now: datetime | None = None
    webauthn_admission: Mapping[str, int] | None = None
    query_work_units: int = 0
    verified_webauthn_evidence: Mapping[str, Any] | None = None
    query_program: tuple[authority_transition_core.Query, ...] = ()
    query_reads: tuple[authority_query_reads.QueryRead, ...] = ()
    complete_query_evidence: authority_complete_acquisition.CompleteAcquisitionEvidence | None = None
    rbac_primary_inputs: tuple | None = None
    retirement_succession_primary_roots: tuple | None = None
    canary_delivery_admission: Any = None


@dataclass(frozen=True, slots=True)
class _RevocationAcquisition:
    """Invocation-owned raw observations, not a signed plan or commit token."""

    request: dict[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    state: PlanningState
    kernel: authority_transition_core.KernelTransition
    mutations: tuple[dict[str, Any], ...]
    work_units: int
    write_evidence: authority_index_mutation_reader.AcquiredIndexedMutation
    trace: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _RegistrationAcquisition:
    """Actual registration observations, not a signed plan or commit token."""

    request: dict[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    state: PlanningState
    kernel: authority_transition_core.KernelTransition
    mutations: tuple[dict[str, Any], ...]
    work_units: int
    write_evidence: authority_index_mutation_reader.AcquiredIndexedMutation
    trace: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _TrustStageAcquisition:
    """Actual aggregate-stage observations, never publication authority."""

    request: dict[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    state: PlanningState
    kernel: authority_transition_core.KernelTransition
    mutations: tuple[dict[str, Any], ...]
    work_units: int
    write_evidence: authority_index_mutation_reader.AcquiredIndexedMutation
    trace: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class _TrustCompletionAcquisition:
    """Actual completion observations, not installation or commit authority."""

    request: dict[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    state: PlanningState
    kernel: authority_transition_core.KernelTransition
    mutations: tuple[dict[str, Any], ...]
    work_units: int
    write_evidence: authority_index_mutation_reader.AcquiredIndexedMutation
    trace: tuple[dict[str, Any], ...]
    business_before_roots: tuple[dict[str, Any], ...]
    authorization_before_roots: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    counted_before_heads: tuple[authority_index_heads.CapturedIndexHead, ...]


@dataclass(frozen=True, slots=True)
class _ProducedRevocationPlan:
    """Original signed/context bytes and cutoff, not persistence authority."""

    signed: authority_revocation_plan_production._ProducedPlan
    database_now: datetime
    metrics: QueryReadValidationMetrics
    evaluation_context_bytes: bytes


@dataclass(frozen=True, slots=True)
class _ProducedObservedRevocationPlan:
    """Original output plus detached independent expectations, never authority."""

    signed: authority_revocation_plan_production._ProducedPlan
    database_now: datetime
    metrics: QueryReadValidationMetrics
    evaluation_context_bytes: bytes
    expected_context: dict[str, Any]


class PlanningProgram(Protocol):
    def __call__(
        self,
        *,
        operation: str,
        handler: str,
        request: Mapping[str, Any],
        manifest: tuple[dict[str, Any], ...],
        selected_rows: tuple[dict[str, Any], ...],
        state: PlanningState,
    ) -> PlannedTransition:
        ...


def _query_trace_key(
    operation: str, query: authority_transition_core.BoundedQuery,
) -> dict[str, str] | None:
    query_id = authority_transition_core.query_program_id(
        operation, authority_audit_capacity.QUERY_NAME, authority_audit_capacity.AGGREGATE_TABLE,
    )
    if query.query_id != query_id:
        return None
    expected = authority_transition_core.BoundedQuery(
        query_id=query_id,
        table=authority_audit_capacity.AGGREGATE_TABLE,
        predicates=(authority_transition_core.QueryPredicate(
            "aggregate_id", "eq", authority_audit_capacity.AGGREGATE_ID,
        ),),
        order_by=(authority_transition_core.QueryOrder("aggregate_id"),),
        maximum_rows=1,
        absent_key={"aggregate_id": authority_audit_capacity.AGGREGATE_ID},
    )
    if (not authority_contract.operation_spec(operation)["globalAuditCapacity"]
            or query != expected):
        raise AuthorityPlannerError("global audit capacity trace query is not source owned")
    return audit_capacity_scan_key()


class PlannerTrace:
    def __init__(self, *, operation: str, _complete_queries: bool = False,
                 _counted_writes: bool = False) -> None:
        if (type(_complete_queries) is not bool
                or _complete_queries and operation not in (authority_complete_query.OPERATION,
                    authority_complete_query.REGISTRATION_OPERATION, authority_complete_query.STAGE_OPERATION,
                    authority_complete_query.ACTIVATION_OPERATION, authority_complete_query.DELIVERY_OPERATION)
                or type(_counted_writes) is not bool
                or _counted_writes and (operation != authority_transition_webauthn_completion.OPERATION
                                       or _complete_queries)):
            raise AuthorityPlannerError("complete trace scope is not source admitted")
        spec = authority_contract.operation_spec(operation)
        self.operation = operation
        self._complete_queries = _complete_queries
        self._counted_writes = _counted_writes
        self.business_reads = frozenset(
            set(spec["businessReads"]) | set(spec["businessWrites"])
        )
        self.selection_reads = frozenset(
            set(self.business_reads) | set(spec["authorizationReads"])
        )
        self.business_writes = frozenset(spec["businessWrites"])
        self.allowed_reads = frozenset(
            set(self.business_reads)
            | set(spec["authorizationReads"])
            | set(spec["frameworkPreconditions"])
            | set(spec["frameworkWrites"])
            | ({authority_index_heads.HEAD_TABLE, authority_index_reader.LEAF_TABLE,
                authority_index_reader.NODE_TABLE} if _complete_queries or _counted_writes else set())
        )
        self.allowed_writes = frozenset(
            set(spec["businessWrites"]) | set(spec["frameworkWrites"])
        )
        self._entries: list[dict[str, Any]] = []
        self._budget = AuditTraceBudget(operation)

    def read(self, table: str, key: Mapping[str, Any] | None) -> None:
        if table not in self.allowed_reads:
            raise AuthorityPlannerError(
                "planner read escaped the generated operation manifest"
            )
        if (table in {authority_index_heads.HEAD_TABLE, authority_index_reader.LEAF_TABLE,
                      authority_index_reader.NODE_TABLE}
                or isinstance(key, Mapping) and key.get("profile") == authority_index_trace.PRIMARY_READ_PROFILE):
            if not self._complete_queries and not self._counted_writes:
                raise AuthorityPlannerError("complete trace profile has no current planner admission")
            try:
                if (type(key) is dict
                        and key.get("profile") == authority_index_trace.MUTATION_READ_PROFILE):
                    authority_index_trace.validate_mutation_read_trace(self.operation, table, key)
                elif self._counted_writes:
                    if table != authority_index_heads.HEAD_TABLE:
                        raise AuthorityPlannerError("completion trace cannot admit complete-range reads")
                    authority_index_heads.validate_head_trace_key(
                        self.operation, key, include_write_heads=True)
                else:
                    authority_index_trace.validate_complete_read_trace(self.operation, table, key)
            except (authority_index_trace.IndexTraceError, authority_index_heads.IndexHeadReadError) as exc:
                raise AuthorityPlannerError("complete trace read is not source closed") from exc
        self._append("read", table, key)

    def write(self, table: str, key: Mapping[str, Any]) -> None:
        if table not in self.allowed_writes:
            raise AuthorityPlannerError(
                "planner write escaped the generated operation manifest"
            )
        self._append("write", table, key)

    def _append(
        self,
        access: str,
        table: str,
        key: Mapping[str, Any] | None,
    ) -> None:
        if len(self._entries) >= MAX_PLAN_TRACE_ENTRIES:
            raise AuthorityPlannerError("planner trace bound was exceeded")
        entry = {
            "ordinal": len(self._entries),
            "access": access,
            "table": table,
            "key": None if key is None else dict(key),
        }
        try:
            self._budget.append(entry)
        except AuditTraceError as exc:
            raise AuthorityPlannerError(str(exc)) from exc
        self._entries.append(entry)

    def close(
        self,
        *,
        selected_rows: tuple[dict[str, Any], ...],
        mutation_plan: tuple[dict[str, Any], ...],
    ) -> tuple[dict[str, Any], ...]:
        for selected in selected_rows:
            table = str(selected["table"])
            if table not in self.selection_reads:
                raise AuthorityPlannerError(
                    "selected row escaped the generated selection manifest"
                )
            if not isinstance(selected.get("key"), Mapping):
                raise AuthorityPlannerError(
                    "selected row key is not exact"
                )
        for mutation in mutation_plan:
            table = str(mutation["table"])
            if table not in self.business_writes:
                raise AuthorityPlannerError(
                    "planned mutation escaped the generated business writes"
                )
            if not isinstance(mutation.get("key"), Mapping):
                raise AuthorityPlannerError(
                    "planned mutation key is not exact"
                )
        try:
            self._budget.close(mutation_plan)
        except AuditTraceError as exc:
            raise AuthorityPlannerError(str(exc)) from exc
        return tuple(dict(entry) for entry in self._entries)


@dataclass(frozen=True, slots=True)
class TypedTransitionPlanningProgram:
    operation: str
    handler: str
    kernel: authority_transition_core.TransitionKernel

    def read_inputs(
        self,
        cursor: Any,
        *,
        request: Mapping[str, Any],
        manifest: tuple[dict[str, Any], ...],
        trace: PlannerTrace,
        query_sources: authority_query_staging.StagedQueryProofs,
        query_work: _ValidationWork,
        complete_acquisition: authority_complete_acquisition._CompleteQueryAcquisition | None = None,
        verified_webauthn_evidence: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
        if (
            self.operation not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
            or self.kernel.operation != self.operation
            or self.kernel.handler != self.handler
            or self.kernel.program_id
                != authority_contract.transition_program_id(self.operation)
            or type(query_work) is not _ValidationWork
        ):
            raise AuthorityPlannerError(
                "typed transition query identity changed"
            )
        database_now = _read_database_now(cursor)
        arguments = request.get("arguments")
        if not isinstance(arguments, Mapping):
            raise AuthorityPlannerError(
                "typed transition arguments are not closed"
            )
        _business_intent(request, operation=self.operation)
        try:
            if self.operation in ({authority_webauthn_assertion.OPERATION} | publication_approval.assertion_operations() | oauth_activation.ASSERTION_OPERATIONS | oauth_exchange.ASSERTION_OPERATIONS | oauth_measured_exchange.ASSERTION_OPERATIONS | public_revocation_approval.ASSERTION_OPERATIONS):
                query_program = getattr(self.kernel, "queries_with_evidence", None)
                if not callable(query_program) or verified_webauthn_evidence is None:
                    raise AuthorityPlannerError(
                        "revocation planning requires pinned verified assertion evidence"
                    )
                proposed_queries = query_program(
                    arguments=arguments,
                    database_now=database_now,
                    request_digest=str(request["requestDigest"]),
                    evidence=verified_webauthn_evidence,
                )
            else:
                if verified_webauthn_evidence is not None:
                    raise AuthorityPlannerError(
                        "assertion planning hook is outside its exact operation"
                    )
                proposed_queries = self.kernel.queries(
                    arguments=arguments,
                    database_now=database_now,
                    request_digest=str(request["requestDigest"]),
                )
            if (type(proposed_queries) is not tuple
                    or len(proposed_queries) > authority_contract.operation_spec(self.operation)["maximumBusinessQueryRows"]):
                raise AuthorityPlannerError("typed query inventory exceeds its source bound")
            if authority_complete_query.role_manifest(self.operation):
                bound_queries = iter(authority_complete_query.validate_bindings(
                    self.operation,
                    tuple(query for query in proposed_queries
                          if type(query) is authority_complete_query.CompleteIndexQuery),
                    arguments=arguments,
                    cutoff_us=authority_complete_query.cutoff_microseconds(database_now),
                ))
                proposed_queries = tuple(
                    next(bound_queries) if type(query) is authority_complete_query.CompleteIndexQuery else query
                    for query in proposed_queries
                )
            queries = authority_audit_capacity.add_capacity_query(
                self.operation,
                proposed_queries,
            )
            selected, queries, query_reads = _read_bounded_transition_rows(
                cursor,
                operation=self.operation,
                request=request,
                queries=queries,
                manifest=manifest,
                trace=trace,
                query_sources=query_sources,
                query_work=query_work,
                complete_acquisition=complete_acquisition,
            )
        except (authority_transition_core.TransitionKernelError,
                authority_complete_query.CompleteQueryError,
                authority_query_reads.QueryReadError,
                authority_complete_acquisition.CompleteAcquisitionError,
                authority_complete_query_batch.CompleteQueryBatchError,
                IndexRangeError,
                QueryReadWorkError,
                authority_query_staging.QueryStagingError) as exc:
            raise AuthorityPlannerError(
                "typed transition query program denied the request"
            ) from exc
        return selected, PlanningState(
            database_now=database_now,
            query_work_units=sum(query.work_units for query in queries),
            verified_webauthn_evidence=verified_webauthn_evidence,
            query_program=queries,
            query_reads=query_reads,
            complete_query_evidence=(None if complete_acquisition is None
                                     else complete_acquisition.retained_evidence()),
        )

    def _read_revocation_inputs(
        self,
        cursor: Any,
        *,
        request: dict[str, Any],
        manifest: tuple[dict[str, Any], ...],
        trace: PlannerTrace,
        query_work: _ValidationWork,
        business_before_roots: Any,
        authorization_before_roots: Any,
        verified_webauthn_evidence: Mapping[str, Any],
    ) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
        """Standalone private read facade; no physical ledger is exported."""
        if type(query_work) is not _ValidationWork:
            raise AuthorityPlannerError("private revocation read identity changed")
        acquisition = authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
        return self._read_revocation_inputs_with_acquisition(
            cursor, request=request, manifest=manifest, trace=trace, query_work=query_work,
            business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots,
            verified_webauthn_evidence=verified_webauthn_evidence, acquisition=acquisition,
        )

    def _read_revocation_inputs_with_acquisition(
        self,
        cursor: Any,
        *,
        request: dict[str, Any],
        manifest: tuple[dict[str, Any], ...],
        trace: PlannerTrace,
        query_work: _ValidationWork,
        business_before_roots: Any,
        authorization_before_roots: Any,
        verified_webauthn_evidence: Mapping[str, Any],
        acquisition: authority_index_reader._ReadAcquisitionBudget,
    ) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
        """Acquire the real private revocation read phase in one transaction.

        The transaction owner supplies observed primary roots and independently
        verified assertion evidence. This entry neither authenticates that
        provenance nor opens public request/registry/v3 admission. It owns the
        input graphs before driver callbacks, reads the database clock once,
        and derives its own complete source program, staging and collector.
        Query bookkeeping, generation, collection and evidence copies share
        the supplied meter. Staged proof/stamp work and primary proof SQL keep
        their existing separate bounds; this is not a whole-plan work claim.
        """
        operation = authority_transition_webauthn.OPERATION
        kernel = self.kernel

        def require_identity() -> None:
            if (type(query_work) is not _ValidationWork
                    or type(kernel) is not authority_transition_webauthn.WebAuthnCredentialRevokeKernel
                    or self.kernel is not kernel
                    or any(type(value) is not str for value in
                           (self.operation, self.handler, kernel.operation,
                            kernel.handler, kernel.program_id))
                    or self.operation != operation
                    or self.handler != kernel.handler
                    or kernel.operation != operation
                    or kernel.handler != "revoke_webauthn_credential"
                    or kernel.program_id != authority_contract.transition_program_id(operation)
                    or type(trace) is not PlannerTrace
                    or type(trace.operation) is not str or trace.operation != operation
                    or trace._complete_queries is not True):
                raise AuthorityPlannerError("private revocation read identity changed")

        if type(acquisition) is not authority_index_reader._ReadAcquisitionBudget:
            raise AuthorityPlannerError("private revocation read physical ledger type changed")
        try:
            with acquisition.read_phase(cursor, trace, query_work):
                require_identity()
                acquisition.require_idle(cursor, trace, query_work)
                if (type(request) is not dict or type(manifest) is not tuple
                        or type(verified_webauthn_evidence) not in (dict, MappingProxyType)):
                    raise AuthorityPlannerError("private revocation read inputs are not exact owned-value types")
                from serverware import authority_public_webauthn_revocation as public_revocation
                fields = (public_revocation.FIELDS if public_revocation.is_public(verified_webauthn_evidence)
                    else authority_webauthn_assertion.EVIDENCE_FIELDS)
                if (len(verified_webauthn_evidence) != len(fields)
                        or any(type(name) is not str or len(name) > 128
                               for name in verified_webauthn_evidence)
                        or set(verified_webauthn_evidence) != fields):
                    raise AuthorityPlannerError("private revocation assertion fields changed")
                # The real verifier returns an exact MappingProxyType. Accept its
                # raw fixed-field data without a general Mapping coercion or any
                # inference that a freely constructible proxy proves a signature.
                # Pair scaffolding is source-fixed; reserve the full pair graph
                # before the actual shallow dictionary projection, then own it in
                # the same context copy as every other input before callbacks.
                evidence_items = tuple((name, verified_webauthn_evidence[name])
                                       for name in sorted(fields))
                query_work.prepare_copy(evidence_items)
                evidence_projection = dict(evidence_items)
                owned = authority_query_reads._CopyBudget(query_work).copy({
                    "request": request, "manifest": manifest,
                    "evidence": evidence_projection,
                    "businessBeforeRoots": business_before_roots,
                    "authorizationBeforeRoots": authorization_before_roots,
                })
                actual_request = owned["request"]
                if (actual_request.get("operation") != operation
                        or actual_request.get("handler") != kernel.handler
                        or type(actual_request.get("arguments")) is not dict):
                    raise AuthorityPlannerError("private revocation request identity changed")
                request_digest = _require_digest(actual_request.get("requestDigest"),
                                                 "private revocation request digest")
                database_now = _read_database_now_on_work(cursor, query_work)
                acquisition.require_idle(cursor, trace, query_work)
                require_identity()
                cutoff_us = authority_complete_query.cutoff_microseconds(database_now)
                queries = authority_transition_webauthn._revocation_query_program(
                    arguments=actual_request["arguments"], cutoff_us=cutoff_us,
                    request_digest=request_digest, evidence=owned["evidence"], work=query_work,
                )
                collector = authority_complete_acquisition._CompleteQueryAcquisition(
                    cursor, operation=operation, arguments=actual_request["arguments"],
                    cutoff_us=cutoff_us,
                    queries=tuple(query for query in queries
                                  if type(query) is authority_complete_query.CompleteIndexQuery),
                    business_before_roots=owned["businessBeforeRoots"],
                    authorization_before_roots=owned["authorizationBeforeRoots"],
                    trace=trace, work=query_work, acquisition=acquisition,
                )
                staging = authority_query_staging.StagedQueryProofs(
                    operation=operation, business_before_roots=owned["businessBeforeRoots"],
                    authorization_before_roots=owned["authorizationBeforeRoots"],
                    query_work=query_work,
                )
                selected, queries, query_reads = _read_bounded_transition_rows(
                    cursor, operation=operation, request=actual_request, queries=queries,
                    manifest=owned["manifest"], trace=trace, query_sources=staging,
                    query_work=query_work, complete_acquisition=collector,
                )
                evidence = collector.retained_evidence()
                acquisition.require_idle(cursor, trace, query_work)
                require_identity()
                return selected, PlanningState(
                    database_now=database_now,
                    query_work_units=sum(query.work_units for query in queries),
                    verified_webauthn_evidence=owned["evidence"],
                    query_program=queries, query_reads=query_reads,
                    complete_query_evidence=evidence,
                )
        except (authority_transition_core.TransitionKernelError,
                authority_complete_query.CompleteQueryError,
                authority_query_reads.QueryReadError,
                authority_complete_acquisition.CompleteAcquisitionError,
                authority_complete_query_batch.CompleteQueryBatchError,
                IndexRangeError, QueryReadWorkError,
                authority_query_staging.QueryStagingError) as exc:
            acquisition.failed = True
            raise AuthorityPlannerError("private revocation read phase denied the request") from exc
        except BaseException:
            acquisition.failed = True
            raise

    def _acquire_revocation_transition(
        self, cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
        business_before_roots: Any, authorization_before_roots: Any,
        evidence: dict[str, Any], verifier_identity: dict[str, Any],
        verifier_public_key: Ed25519PublicKey, capability_id: str,
        now_epoch_ns: int, deadline_epoch_ns: int, maximum_age_ns: int,
        query_work: _ValidationWork, trace: PlannerTrace | None = None,
    ) -> _RevocationAcquisition:
        """Acquire genuine read/effect/write observations on one transaction.

        This private producer genuinely binds the owned request and pinned
        assertion before SQL, then uses the original database cutoff for the
        real kernel/capacity effects and write-proof acquisition. Independent
        key/capability/current-root/time authority and ownership of a read-only
        MVCC transaction are caller prerequisites, not established here.

        One live physical ledger covers counted heads, ranges, exact member
        fetches and write frontiers. Clock, ordinary and primary-proof SQL keep
        their separate existing bounds. Work shares the supplied meter with
        explicit staged-proof/stamp, trace and allocation exclusions; this is
        neither whole-plan resource accounting nor signed-v4 activation.
        No successful effects/proof object is accepted as an input.
        The configured owner may supply its actual metadata-read trace; the
        standalone facade creates one. Neither form grants public admission.
        """
        if type(query_work) is not _ValidationWork:
            raise AuthorityPlannerError("private revocation producer requires an exact shared meter")
        operation = authority_transition_webauthn.OPERATION
        if trace is None:
            trace = PlannerTrace(operation=operation, _complete_queries=True)
        if (type(trace) is not PlannerTrace or type(trace.operation) is not str
                or trace.operation != operation or trace._complete_queries is not True):
            raise AuthorityPlannerError("private revocation producer trace identity changed")
        acquisition = authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
        try:
            if (type(request) is not dict or type(manifest) is not tuple
                    or type(evidence) is not dict or type(verifier_identity) is not dict):
                raise AuthorityPlannerError("private revocation producer context is not exact raw data")
            # Retain this joint capture across both cryptographic and driver
            # callbacks; never return to mutable caller arguments after reads.
            owned = authority_query_reads._CopyBudget(query_work).copy({
                "request": request, "manifest": manifest, "evidence": evidence,
                "verifierIdentity": verifier_identity, "capabilityId": capability_id,
                "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
                "maximumAgeNs": maximum_age_ns,
                "businessBeforeRoots": business_before_roots,
                "authorizationBeforeRoots": authorization_before_roots,
            })
            actual_request = owned["request"]
            if actual_request.get("operation") != operation:
                raise AuthorityPlannerError("private revocation producer request operation changed")
            request_digest = _typed_request_digest(actual_request, work=query_work)
            claimed_request = _require_digest(actual_request["requestDigest"], "producer request digest")
            if _request_different(request_digest, claimed_request, work=query_work):
                raise AuthorityPlannerError("private revocation producer request digest changed")
            query_work.prepare_utf8(operation)
            query_work.prepare_utf8(request_digest)
            query_work.charge(hashes=1)
            actual_operation_id = operation_id(operation, request_digest)
            claimed_operation = _require_digest(actual_request["operationId"], "producer operation id")
            if _request_different(actual_operation_id, claimed_operation, work=query_work):
                raise AuthorityPlannerError("private revocation producer operation id changed")
            verified, _signature_attempts = authority_revocation_semantics._verify_evidence(
                owned["evidence"], operation_id=actual_operation_id, request_digest=request_digest,
                capability_id=owned["capabilityId"], verifier_identity=owned["verifierIdentity"],
                verifier_public_key=verifier_public_key, now_epoch_ns=owned["nowEpochNs"],
                deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=owned["maximumAgeNs"],
                work=query_work,
            )
            # These are actual root-table reads on this transaction and trace,
            # including the separately charged global audit-capacity root.
            # A caller's expected root vector cannot substitute for that SQL
            # observation or synthesize the framework marker required at close.
            observed_business, observed_authorization, _ = _read_root_set(
                cursor, operation=operation, manifest=owned["manifest"],
                trace=trace, work=query_work, deadline_epoch_ns=owned["deadlineEpochNs"])
            authority_revocation_semantics._canonical_equal(
                (observed_business, observed_authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]),
                work=query_work, label="private producer database roots differ from independent expectations")
            selected, state = self._read_revocation_inputs_with_acquisition(
                cursor, request=actual_request, manifest=owned["manifest"], trace=trace,
                query_work=query_work, business_before_roots=observed_business,
                authorization_before_roots=observed_authorization,
                verified_webauthn_evidence=verified, acquisition=acquisition,
            )
            kernel, finalized, work_units, _, _ = authority_revocation_semantics._derive_revocation_effects(
                arguments=actual_request["arguments"], selected_rows=selected,
                query_program=state.query_program, query_reads=state.query_reads,
                database_now=state.database_now, request_digest=request_digest,
                verified_webauthn_evidence=state.verified_webauthn_evidence, work=query_work,
            )
            mutations = authority_revocation_semantics._ordered_mutations(finalized, work=query_work)
            retained = state.complete_query_evidence
            if retained is None:
                raise AuthorityPlannerError("private revocation producer lost original read evidence")
            # Fixed source metadata only. The write engine independently
            # requires every profile of every genuinely changed source table.
            write_ids = {name for item in mutations
                         for name in authority_index_projection.index_ids_for_table(item["table"])}
            heads = tuple(authority_indexed_mutation.IndexedMutationHead(
                item.index_id, item.index_revision, item.index_root)
                for item in retained.heads if item.index_id in write_ids)
            limits = authority_complete_read_write._write_limits(
                authority_contract.operation_spec(operation),
                authority_complete_query_batch._SharedLedger(query_work),
            )
            writer = authority_index_mutation_reader._AcquisitionBudget(
                shared_acquisition=acquisition, work=query_work)
            write_evidence = authority_index_mutation_reader._acquire_indexed_primary_batch(
                cursor, table_contracts=authority_primary_contract.primary_table_contracts(operation),
                business_before_roots=authority_complete_query_batch._roots(retained.business_before_roots),
                authorization_before_roots=authority_complete_query_batch._roots(retained.authorization_before_roots),
                selected_rows=selected, before_proofs=retained.before_proofs, mutations=mutations,
                index_before_heads=heads, limits=limits, trace=trace, acquisition_budget=writer,
            )
            acquisition.require_idle(cursor, trace, query_work)
            for mutation in mutations:
                trace.write(mutation["table"], mutation["key"])
            closed_trace = trace.close(selected_rows=selected, mutation_plan=mutations)
            return _RevocationAcquisition(actual_request, selected, state, kernel,
                mutations, work_units, write_evidence, closed_trace)
        except BaseException:
            acquisition.failed = True
            raise

    def _produce_revocation_plan(
        self, cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
        evidence: dict[str, Any], context: dict[str, Any],
        verifier_public_key: Ed25519PublicKey, planner_private_key: Ed25519PrivateKey,
        planner_public_key: Ed25519PublicKey, query_work: _ValidationWork,
        trace: PlannerTrace | None = None,
    ) -> _ProducedRevocationPlan:
        """Preserved exact-context API and accounting through the genuine body."""
        return self._produce_revocation_plan_on_work(cursor, request=request, manifest=manifest,
            evidence=evidence, context=context, verifier_public_key=verifier_public_key,
            planner_private_key=planner_private_key, planner_public_key=planner_public_key,
            query_work=query_work, trace=trace)

    def _produce_observed_revocation_plan(
        self, cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
        evidence: dict[str, Any], context: dict[str, Any], root_inventory,
        verifier_public_key: Ed25519PublicKey, planner_private_key: Ed25519PrivateKey,
        planner_public_key: Ed25519PublicKey, query_work: _ValidationWork,
        trace: PlannerTrace | None = None,
    ) -> _ProducedObservedRevocationPlan:
        """Acquire all observed commitments before projecting actual-write roots.

        The fourteen-field context omits expectedBefore. The independent full
        inventory is ordinary reader data, not an acquisition/proof success
        token. Its auxiliary source metadata is not asserted to be present in
        the planner's compact root vectors. No public admission changes here.
        """
        if root_inventory is None:
            raise AuthorityPlannerError("observed production requires the full independent inventory")
        return self._produce_revocation_plan_on_work(cursor, request=request, manifest=manifest,
            evidence=evidence, context=context, verifier_public_key=verifier_public_key,
            planner_private_key=planner_private_key, planner_public_key=planner_public_key,
            query_work=query_work, trace=trace, root_inventory=root_inventory)

    def _produce_revocation_plan_on_work(
        self, cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
        evidence: dict[str, Any], context: dict[str, Any],
        verifier_public_key: Ed25519PublicKey, planner_private_key: Ed25519PrivateKey,
        planner_public_key: Ed25519PublicKey, query_work: _ValidationWork,
        trace: PlannerTrace | None = None, root_inventory=None,
    ) -> _ProducedRevocationPlan | _ProducedObservedRevocationPlan:
        """Privately acquire, package and sign the genuine revoke-only v4 plan.

        The cursor belongs to a caller-owned read-only MVCC transaction. Key
        enrollment, planner/database identity, current roots, reservation and
        clock provenance are preceding independent admission requirements.
        This method does not open public routes, registry or durable execution.

        Capture all caller graphs together before callbacks. Acquire real
        reads/effects/write proofs internally, then normalize and replay those
        raw graphs under the same remaining work for the compact proof's exact
        phase metrics. Repeated proof work is charged, not replaced by an
        acquisition success token. The output retains the original signed
        envelope/context bytes and database cutoff; it authorizes no commit or replay.
        A supplied private trace retains the configured owner's real manifest
        reads instead of resetting their trace budget before acquisition.
        """
        if (type(query_work) is not _ValidationWork
                or type(request) is not dict or type(manifest) is not tuple
                or type(evidence) is not dict or type(context) is not dict
                or not isinstance(verifier_public_key, Ed25519PublicKey)
                or not isinstance(planner_private_key, Ed25519PrivateKey)
                or not isinstance(planner_public_key, Ed25519PublicKey)):
            raise AuthorityPlannerError("private revocation production context has unexpected types")
        try:
            independent_inventory = (None if root_inventory is None else
                authority_revocation_observed._capture_root_inventory(root_inventory, work=query_work))
            owned = authority_query_reads._CopyBudget(query_work).copy({
                "request": request, "manifest": manifest, "evidence": evidence, "context": context,
            })
            actual_request, actual_context = owned["request"], owned["context"]
            if independent_inventory is None:
                authority_revocation_plan_production._validate_context(actual_context, query_work)
            else:
                authority_revocation_observed._validate_partial_context(actual_context, query_work)
            # Bind the externally reserved transaction before any SQL. The
            # genuine acquisition below independently recomputes the request
            # and operation commitments before its clock or driver callbacks.
            operation_identifier = _require_digest(actual_request.get("operationId"), "producer operation id")
            request_digest = _require_digest(actual_request.get("requestDigest"), "producer request digest")
            transaction_id = authority_revocation_plan._frame(
                "serverware.policyAuthorityPlannerTransaction/v1",
                tuple(authority_revocation_plan._ascii(value, query_work) for value in (
                    operation_identifier, request_digest, actual_context["expectedCapabilityId"])), query_work)
            authority_revocation_semantics._canonical_equal(transaction_id,
                actual_context["expectedPlannerTransactionId"], work=query_work,
                label="private producer transaction differs from independent reservation")
            expected_before = (actual_context["expectedBefore"] if independent_inventory is None else
                authority_revocation_observed._inventory_before(independent_inventory))
            acquired = self._acquire_revocation_transition(cursor,
                request=actual_request, manifest=owned["manifest"], evidence=owned["evidence"],
                business_before_roots=expected_before["businessBeforeRoots"],
                authorization_before_roots=expected_before["authorizationBeforeRoots"],
                verifier_identity=actual_context["expectedVerifierIdentity"],
                verifier_public_key=verifier_public_key,
                capability_id=actual_context["expectedCapabilityId"],
                now_epoch_ns=actual_context["nowEpochNs"],
                deadline_epoch_ns=actual_context["deadlineEpochNs"],
                maximum_age_ns=actual_context["maximumAssertionAgeNs"], query_work=query_work,
                trace=trace,
            )
            raw, state = acquired.state.complete_query_evidence, acquired.state
            if raw is None or type(state.database_now) is not datetime:
                raise AuthorityPlannerError("private producer lost its original complete evidence")
            queries = tuple(query for query in state.query_program
                            if type(query) is authority_complete_query.CompleteIndexQuery)
            if independent_inventory is not None:
                # Compare ALL nine commitments before deriving any subset.
                # The selector names come only from this genuine acquisition's
                # queries, effects and actual write-proof inventories.
                actual_context = authority_revocation_observed._project_expected_context(
                    actual_context, independent_inventory, acquired_before={
                        "businessBeforeRoots": list(raw.business_before_roots),
                        "authorizationBeforeRoots": list(raw.authorization_before_roots),
                        "indexBeforeHeads": [{"indexId": item.index_id,
                            "indexRevision": item.index_revision, "rootDigest": item.index_root.digest,
                            "leafCount": item.index_root.count} for item in raw.heads]},
                    query_roles=tuple(query.role for query in queries),
                    mutated_tables=tuple(mutation["table"] for mutation in acquired.mutations),
                    write_index_ids=tuple(head.index_id for head in acquired.write_evidence.result.before_heads),
                    work=query_work)
                expected_before = actual_context["expectedBefore"]
            # The collector captures all nine potential heads. Packaging needs
            # only the exact six-role read/ACTUAL write union, not unused heads.
            index_ids = {query.index_id for query in queries} | {
                head.index_id for head in acquired.write_evidence.result.before_heads}
            heads = tuple(authority_complete_read_write.CompleteReadWriteHead(
                item.index_id, item.index_revision, item.index_root)
                for item in raw.heads if item.index_id in index_ids)
            observed_before = {
                "businessBeforeRoots": raw.business_before_roots,
                "authorizationBeforeRoots": raw.authorization_before_roots,
                "indexBeforeHeads": [{"indexId": head.index_id, "indexRevision": head.index_revision,
                    "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}
                    for head in heads],
            }
            authority_revocation_semantics._canonical_equal(observed_before, expected_before,
                work=query_work, label="private producer roots differ from independent expectations")
            verified_evidence = state.verified_webauthn_evidence
            if type(verified_evidence) is not dict:
                raise AuthorityPlannerError("private producer lost its owned verified assertion")
            packaged = authority_revocation_proof_bundle._derive_on_work(
                work=query_work, operation=authority_transition_webauthn.OPERATION,
                arguments=acquired.request["arguments"], cutoff_us=raw.cutoff_us,
                request_digest=acquired.request["requestDigest"],
                assertion_binding=authority_revocation_semantics._evidence_binding(verified_evidence),
                query_reads=state.query_reads, queries=queries,
                business_before_roots=raw.business_before_roots,
                authorization_before_roots=raw.authorization_before_roots,
                selected_rows=acquired.selected_rows, before_proofs=raw.before_proofs,
                mutations=acquired.mutations, counted_before_heads=heads,
                query_frontiers=raw.frontiers,
                write_frontiers=tuple(authority_complete_read_write.CompleteWriteFrontier(
                    item.index_id, item.frontier) for item in acquired.write_evidence.index_inputs),
            )
            if authority_complete_query.cutoff_microseconds(state.database_now) != raw.cutoff_us:
                raise AuthorityPlannerError("private producer context lost its original acquisition cutoff")
            evaluation_context_bytes = authority_revocation_retention._encode_context_on_work(
                actual_context, database_now=state.database_now, work=query_work)
            # The signer payload may retain identity subgraphs from its input.
            # The returned expectations must not alias those mutable graphs.
            independent_context = (None if independent_inventory is None else
                authority_query_reads._CopyBudget(query_work).copy(actual_context))
            signed = authority_revocation_plan_production._build_and_sign(
                request=acquired.request, selected_rows=acquired.selected_rows,
                mutations=acquired.mutations, before_proofs=raw.before_proofs,
                trace=acquired.trace, evidence=verified_evidence, result=acquired.kernel.result,
                work_units=acquired.work_units, bundle=packaged.bundle,
                transition=packaged.transition, transition_digest=packaged.retained.transition_digest,
                context=actual_context, planner_private_key=planner_private_key,
                planner_public_key=planner_public_key, work=query_work,
            )
            if independent_context is not None:
                return _ProducedObservedRevocationPlan(signed, state.database_now, query_work.metrics,
                    evaluation_context_bytes, independent_context)
            return _ProducedRevocationPlan(signed, state.database_now, query_work.metrics,
                evaluation_context_bytes)
        except (AttributeError, KeyError, TypeError, ValueError, OverflowError,
                RecursionError, InvalidSignature, authority_transition_core.TransitionKernelError) as exc:
            if isinstance(exc, AuthorityPlannerError):
                raise
            raise AuthorityPlannerError("private signed revocation production failed") from exc

    def __call__(
        self,
        *,
        operation: str,
        handler: str,
        request: Mapping[str, Any],
        manifest: tuple[dict[str, Any], ...],
        selected_rows: tuple[dict[str, Any], ...],
        state: PlanningState,
    ) -> PlannedTransition:
        del manifest
        if state.complete_query_evidence is not None:
            raise AuthorityPlannerError("complete planning requires the successor retained-evidence protocol")
        if (
            operation not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
            or operation != self.operation
            or handler != self.handler
            or self.kernel.operation != operation
            or self.kernel.handler != handler
            or self.kernel.program_id
                != authority_contract.transition_program_id(operation)
            or state.database_now is None
            or (operation in ({authority_webauthn_assertion.OPERATION} | publication_approval.assertion_operations() | oauth_activation.ASSERTION_OPERATIONS | oauth_exchange.ASSERTION_OPERATIONS | oauth_measured_exchange.ASSERTION_OPERATIONS | public_revocation_approval.ASSERTION_OPERATIONS))
                != (state.verified_webauthn_evidence is not None)
        ):
            raise AuthorityPlannerError(
                "typed transition program identity changed"
            )
        arguments = request.get("arguments")
        if not isinstance(arguments, Mapping):
            raise AuthorityPlannerError(
                "typed transition arguments are not closed"
            )
        _business_intent(request, operation=operation)
        try:
            context = authority_transition_core.KernelContext(
                operation=operation,
                arguments=arguments,
                selected_rows=selected_rows,
                database_now=state.database_now,
                request_digest=str(request["requestDigest"]),
                verified_webauthn_evidence=state.verified_webauthn_evidence,
                query_reads=state.query_reads,
                rbac_primary_inputs=state.rbac_primary_inputs,
                retirement_succession_primary_roots=state.retirement_succession_primary_roots,
                canary_delivery_admission=state.canary_delivery_admission,
            )
            transition = self.kernel.transition(context)
        except authority_transition_core.TransitionKernelError as exc:
            raise AuthorityPlannerError(
                "typed transition kernel denied the request"
            ) from exc
        if not isinstance(
            transition, authority_transition_core.KernelTransition
        ):
            raise AuthorityPlannerError(
                "typed transition kernel returned the wrong type"
            )
        if not isinstance(transition.mutations, tuple):
            raise AuthorityPlannerError(
                "typed transition kernel exceeded its operation manifest"
            )
        try:
            finalized_mutations = authority_audit_capacity.finalize_capacity(
                context, transition.mutations,
            )
            total_work_units = authority_audit_capacity.transition_work_units(
                operation=operation,
                query_work_units=state.query_work_units,
                kernel_work_units=transition.work_units,
                mutations=finalized_mutations,
            )
            authority_audit_capacity.validate_transition_work_units(
                operation=operation,
                work_units=total_work_units,
                mutations=finalized_mutations,
            )
        except authority_transition_core.TransitionKernelError as exc:
            raise AuthorityPlannerError(
                "typed transition global audit capacity denied the request"
            ) from exc
        spec = authority_contract.operation_spec(operation)
        if (
            len(finalized_mutations) > int(spec["maximumMutations"])
            or not isinstance(total_work_units, int)
            or isinstance(total_work_units, bool)
            or not 1
                <= total_work_units
                <= int(spec["maximumWorkUnits"])
            or any(
                not isinstance(entry, Mapping)
                or set(entry)
                    != {
                        "templateId",
                        "operation",
                        "table",
                        "key",
                        "keyDigest",
                        "expectedRow",
                        "row",
                    }
                for entry in finalized_mutations
            )
        ):
            raise AuthorityPlannerError(
                "typed transition kernel exceeded its operation manifest"
            )
        if (
            not finalized_mutations
            and not self.kernel.permits_empty_mutation
        ):
            raise AuthorityPlannerError(
                "typed transition kernel returned an undeclared no-op"
            )
        mutations = tuple(
            sorted(
                (dict(entry) for entry in finalized_mutations),
                key=lambda entry: (
                    entry["table"],
                    entry["keyDigest"],
                    entry["operation"],
                ),
            )
        )
        return PlannedTransition(
            selected_business_rows=selected_rows,
            mutation_plan=mutations,
            result=transition.result,
            work_units=total_work_units,
        )


@dataclass(frozen=True, slots=True)
class WebAuthnChallengePlanningProgram:
    operation: str
    handler: str

    def __call__(
        self,
        *,
        operation: str,
        handler: str,
        request: Mapping[str, Any],
        manifest: tuple[dict[str, Any], ...],
        selected_rows: tuple[dict[str, Any], ...],
        state: PlanningState,
    ) -> PlannedTransition:
        if (
            operation != self.operation
            or handler != self.handler
            or operation not in WEBAUTHN_CHALLENGE_OPERATIONS
            or state.database_now is None
            or {
                entry["table"] for entry in manifest
                if entry["table"] == "webauthn_challenges"
            }
                != {"webauthn_challenges"}
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge planning state changed"
            )
        arguments = request.get("arguments")
        if not isinstance(arguments, Mapping):
            raise AuthorityPlannerError(
                "WebAuthn challenge arguments are not closed"
            )
        if operation == "webauthn.challenge.create":
            return self._create(
                arguments=arguments,
                selected_rows=selected_rows,
                state=state,
            )
        if operation == "webauthn.challenge.claim":
            return self._claim(
                arguments=arguments,
                selected_rows=selected_rows,
                state=state,
            )
        return self._consume(
            arguments=arguments,
            selected_rows=selected_rows,
            state=state,
        )

    def _create(
        self,
        *,
        arguments: Mapping[str, Any],
        selected_rows: tuple[dict[str, Any], ...],
        state: PlanningState,
    ) -> PlannedTransition:
        required = {
            "challenge_id",
            "challenge",
            "challenge_type",
            "user_id",
            "payload",
            "approval_request_id",
            "scope_key",
            "ttl_seconds",
            "created_at",
            "expires_at",
            "businessIntent",
        }
        challenge_id = arguments.get("challenge_id")
        challenge = arguments.get("challenge")
        challenge_type = arguments.get("challenge_type")
        user_id = arguments.get("user_id")
        payload = arguments.get("payload")
        approval_request_id = arguments.get("approval_request_id")
        scope_key = arguments.get("scope_key")
        ttl_seconds = arguments.get("ttl_seconds")
        created_at_value = arguments.get("created_at")
        expires_at_value = arguments.get("expires_at")
        if (
            set(arguments) != required
            or not isinstance(challenge_id, str)
            or not challenge_id
            or not isinstance(challenge, str)
            or not 32 <= len(challenge) <= 128
            or any(
                character
                not in (
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz"
                    "0123456789-_"
                )
                for character in challenge
            )
            or not isinstance(challenge_type, str)
            or not 1 <= len(challenge_type) <= 64
            or not isinstance(user_id, str)
            or not 1 <= len(user_id.encode("utf-8")) <= 512
            or not isinstance(payload, Mapping)
            or not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 30 <= ttl_seconds <= 300
            or (
                approval_request_id is not None
                and not isinstance(approval_request_id, str)
            )
            or (
                scope_key is not None
                and (
                    not isinstance(scope_key, str)
                    or not 1 <= len(scope_key.encode("utf-8")) <= 512
                )
            )
            or len(canonical_bytes(payload)) > 64 * 1024
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge creation arguments are invalid"
            )
        _business_intent(
            {"arguments": arguments},
            operation=self.operation,
        )
        created_at = _require_utc_timestamp(
            created_at_value,
            "WebAuthn challenge created_at",
        )
        expires_at = _require_utc_timestamp(
            expires_at_value,
            "WebAuthn challenge expires_at",
        )
        expected_row = {
            "id": challenge_id,
            "challenge": challenge,
            "challenge_type": challenge_type,
            "user_id": user_id,
            "scope_key": scope_key,
            "approval_request_id": approval_request_id,
            "payload_json": canonical_bytes(payload).decode("ascii"),
            "expires_at": expires_at_value,
            "used_at": None,
            "created_at": created_at_value,
        }
        if (
            set(expected_row) != WEBAUTHN_CHALLENGE_ROW_FIELDS
            or expires_at - created_at
                != timedelta(seconds=ttl_seconds)
            or created_at > state.database_now
            or expires_at <= state.database_now
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge creation binding changed"
            )
        if payload.get("schema") == (
            "serverware.policyAuthorityWebAuthnChallenge/v1"
        ):
            operation_identifier = payload.get("operationId")
            issued_at_epoch_ns = payload.get("issuedAtEpochNs")
            expires_at_epoch_ns = payload.get("expiresAtEpochNs")
            if (
                set(payload)
                != {
                    "schema",
                    "operationId",
                    "rpId",
                    "origin",
                    "issuedAtEpochNs",
                    "expiresAtEpochNs",
                    "credentialId",
                }
                or not isinstance(operation_identifier, str)
                or _require_digest(
                    operation_identifier,
                    "WebAuthn target operation ID",
                )
                    != operation_identifier
                or scope_key != operation_identifier
                or challenge_type != "policy_authority"
                or expected_row["id"]
                    != framed_digest(
                        "serverware."
                        "policyAuthorityWebAuthnChallengeId/v1",
                        operation_identifier.encode("ascii"),
                        challenge.encode("ascii"),
                    )
                or not isinstance(issued_at_epoch_ns, int)
                or isinstance(issued_at_epoch_ns, bool)
                or not isinstance(expires_at_epoch_ns, int)
                or isinstance(expires_at_epoch_ns, bool)
                or expires_at_epoch_ns - issued_at_epoch_ns
                    != ttl_seconds * 1_000_000_000
                or _epoch_nanoseconds(created_at) != issued_at_epoch_ns
                or _epoch_nanoseconds(expires_at)
                    != expires_at_epoch_ns
            ):
                raise AuthorityPlannerError(
                    "policy-authority challenge binding changed"
                )
        target = next(
            (
                selected
                for selected in selected_rows
                if selected["key"] == {"id": expected_row["id"]}
            ),
            None,
        )
        if target is None or target["present"]:
            raise AuthorityPlannerError(
                "WebAuthn challenge identity is already present"
            )
        replacements = tuple(
            selected
            for selected in selected_rows
            if selected is not target
        )
        if (
            state.webauthn_admission is None
            or state.webauthn_admission.get("replacementCount")
                != len(replacements)
            or any(
                not selected["present"]
                or selected["row"]["challenge_type"]
                    != challenge_type
                or selected["row"]["user_id"] != user_id
                or selected["row"]["scope_key"] != scope_key
                or selected["row"]["used_at"] is not None
                for selected in replacements
            )
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge replacement set changed"
            )
        mutations = [
            _planned_business_mutation(
                operation=self.operation,
                selected=selected,
                row={
                    **selected["row"],
                    "used_at": state.database_now.isoformat(),
                },
            )
            for selected in replacements
        ]
        mutations.append(
            _planned_business_mutation(
                operation=self.operation,
                selected=target,
                row=expected_row,
            )
        )
        mutations.sort(
            key=lambda entry: (
                entry["table"],
                entry["keyDigest"],
                entry["operation"],
            )
        )
        return PlannedTransition(
            selected_business_rows=selected_rows,
            mutation_plan=tuple(mutations),
            result=_webauthn_public_row(expected_row),
        )

    def _claim(
        self,
        *,
        arguments: Mapping[str, Any],
        selected_rows: tuple[dict[str, Any], ...],
        state: PlanningState,
    ) -> PlannedTransition:
        required = {
            "challenge",
            "challenge_type",
            "user_id",
            "approval_request_id",
            "businessIntent",
        }
        approval_request_id = arguments.get("approval_request_id")
        if (
            set(arguments) != required
            or not isinstance(arguments.get("challenge"), str)
            or not isinstance(arguments.get("challenge_type"), str)
            or not isinstance(arguments.get("user_id"), str)
            or (
                approval_request_id is not None
                and not isinstance(approval_request_id, str)
            )
            or len(selected_rows) > 1
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge claim arguments are invalid"
            )
        selected = selected_rows[0] if selected_rows else None
        eligible = (
            selected is not None
            and selected["present"]
            and selected["row"]["challenge"] == arguments["challenge"]
            and selected["row"]["challenge_type"]
                == arguments["challenge_type"]
            and selected["row"]["user_id"] == arguments["user_id"]
            and selected["row"]["approval_request_id"]
                == approval_request_id
            and selected["row"]["used_at"] is None
            and _require_utc_timestamp(
                selected["row"]["expires_at"],
                "claimed challenge expiry",
            )
                > state.database_now
        )
        mutations: tuple[dict[str, Any], ...] = ()
        result = None
        if eligible and selected is not None:
            claimed_row = {
                **selected["row"],
                "used_at": state.database_now.isoformat(),
            }
            mutations = (
                _planned_business_mutation(
                    operation=self.operation,
                    selected=selected,
                    row=claimed_row,
                ),
            )
            result = _webauthn_public_row(claimed_row)
        _business_intent(
            {"arguments": arguments},
            operation=self.operation,
        )
        return PlannedTransition(
            selected_business_rows=selected_rows,
            mutation_plan=mutations,
            result=result,
        )

    def _consume(
        self,
        *,
        arguments: Mapping[str, Any],
        selected_rows: tuple[dict[str, Any], ...],
        state: PlanningState,
    ) -> PlannedTransition:
        if (
            set(arguments) != {"challenge_id", "businessIntent"}
            or not isinstance(arguments.get("challenge_id"), str)
            or not arguments["challenge_id"]
            or len(selected_rows) != 1
            or selected_rows[0]["key"]
                != {"id": arguments["challenge_id"]}
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge consumption arguments are invalid"
            )
        selected = selected_rows[0]
        mutations: tuple[dict[str, Any], ...] = ()
        if selected["present"] and selected["row"]["used_at"] is None:
            mutations = (
                _planned_business_mutation(
                    operation=self.operation,
                    selected=selected,
                    row={
                        **selected["row"],
                        "used_at": state.database_now.isoformat(),
                    },
                ),
            )
        _business_intent(
            {"arguments": arguments},
            operation=self.operation,
        )
        return PlannedTransition(
            selected_business_rows=selected_rows,
            mutation_plan=mutations,
            result=None,
        )


PLANNING_PROGRAMS: Mapping[str, PlanningProgram] = MappingProxyType(
    {
        operation: WebAuthnChallengePlanningProgram(
            operation=operation,
            handler=authority_contract.OPERATION_REGISTRY[
                operation
            ].handler,
        )
        for operation in sorted(WEBAUTHN_CHALLENGE_OPERATIONS)
    }
    | {
        operation: TypedTransitionPlanningProgram(
            operation=operation,
            handler=kernel.handler,
            kernel=kernel,
        )
        for operation, kernel
        in sorted(authority_transition_registry.KERNELS.items())
    }
)

if set(PLANNING_PROGRAMS) != set(authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS):
    raise RuntimeError("legacy measured planner program inventory is not source exact")


def _validate_database_identity(
    cursor: Any,
    identity: PlannerIdentity,
) -> None:
    row = cursor.execute(
        "SELECT current_user AS role, ssl.ssl, ssl.client_dn, "
        "ssl.client_serial::text AS client_serial, ssl.issuer_dn, "
        "role_record.rolsuper, role_record.rolcreaterole, "
        "role_record.rolcreatedb, role_record.rolreplication, "
        "role_record.rolbypassrls, "
        "pg_catalog.has_schema_privilege("
        "current_user, 'serverware_metadata', 'CREATE') AS schema_create, "
        "pg_catalog.has_database_privilege("
        "current_user, pg_catalog.current_database(), 'CREATE') "
        "AS database_create, "
        "pg_catalog.has_database_privilege("
        "current_user, pg_catalog.current_database(), 'TEMPORARY') "
        "AS database_temporary "
        "FROM pg_catalog.pg_stat_ssl AS ssl "
        "JOIN pg_catalog.pg_roles AS role_record "
        "ON role_record.oid = current_user::pg_catalog.regrole::oid "
        "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
    ).fetchone()
    if (
        row is None
        or row["role"] != identity.database_role
        or not bool(row["ssl"])
        or row["client_dn"] != identity.tls_client_dn
        or row["client_serial"] != identity.tls_client_serial
        or row["issuer_dn"] != identity.tls_issuer_dn
        or any(
            bool(row[field])
            for field in (
                "rolsuper",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
                "schema_create",
                "database_create",
                "database_temporary",
            )
        )
    ):
        raise AuthorityPlannerError(
            "planner PostgreSQL identity is not exact"
        )
    mutation = cursor.execute(
        "SELECT 1 FROM pg_catalog.pg_class AS relation "
        "JOIN pg_catalog.pg_namespace AS namespace "
        "ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = 'serverware_metadata' "
        "AND relation.relkind IN ('r', 'p', 'S') "
        "AND ((relation.relkind IN ('r', 'p') AND "
        "pg_catalog.has_table_privilege(current_user, relation.oid, "
        "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')) "
        "OR (relation.relkind = 'S' AND "
        "pg_catalog.has_sequence_privilege("
        "current_user, relation.oid, 'USAGE,UPDATE'))) LIMIT 1"
    ).fetchone()
    if mutation is not None:
        raise AuthorityPlannerError(
            "read-only planner credential has mutation authority"
        )


def _load_manifest(
    cursor: Any,
    *,
    operation: str,
    trace: PlannerTrace,
) -> tuple[tuple[dict[str, Any], ...], str]:
    trace.read(
        "policy_authority_query_dependency_manifests",
        {"operation": operation},
    )
    spec = authority_contract.operation_spec(operation)
    expected_count = len(set(spec["businessReads"]) | set(spec["businessWrites"]))
    rows = cursor.execute(
        "SELECT ordinal, predicate_id, table_name, handler_digest, "
        "key_columns_json, write_access, selector_paths_json, proof_kind, "
        "maximum_rows, entry_digest, manifest_digest, index_contract, "
        "predicate_kind, selector_source, exact_absence, source_revision "
        "FROM serverware_metadata."
        "policy_authority_query_dependency_manifests "
        "WHERE operation = %s ORDER BY ordinal LIMIT %s",
        (operation, expected_count + 1),
    ).fetchall()
    try:
        manifest = authority_primary_contract.validate_planner_manifest_rows(
            operation, rows, authorization=False,
        )
    except ValueError as exc:
        raise AuthorityPlannerError("planner query manifest differs from measured source") from exc
    return manifest, authority_primary_contract.source_query_manifest_digest()


def _load_authorization_manifest(
    cursor: Any,
    *,
    operation: str,
    trace: PlannerTrace,
) -> tuple[dict[str, Any], ...]:
    trace.read(
        "policy_authority_authorization_dependency_manifests",
        {"operation": operation},
    )
    expected_count = len(authority_contract.operation_spec(operation)["authorizationReads"])
    rows = cursor.execute(
        "SELECT ordinal, table_name, key_columns_json, predicate_kind, "
        "exact_absence, entry_digest, manifest_digest, source_revision "
        "FROM serverware_metadata."
        "policy_authority_authorization_dependency_manifests "
        "WHERE operation = %s ORDER BY ordinal LIMIT %s",
        (operation, expected_count + 1),
    ).fetchall()
    try:
        return authority_primary_contract.validate_planner_manifest_rows(
            operation, rows, authorization=True,
        )
    except ValueError as exc:
        raise AuthorityPlannerError("authorization dependency differs from measured source") from exc


def _read_root_set(
    cursor: Any,
    *,
    operation: str,
    manifest: tuple[dict[str, Any], ...],
    trace: PlannerTrace,
    deadline_epoch_ns: int,
    deadline_monotonic_ns: int | None = None,
    work: _ValidationWork | None = None,
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
    str,
]:
    # The legacy caller retains its existing accounting. The private v4 path
    # owns each exact scalar row before later driver callbacks, and pays the
    # real canonical root-set commitment on its existing remaining work.
    ledger = authority_complete_query_batch._SharedLedger(work) if work is not None else None
    spec = authority_contract.operation_spec(operation)
    manifest_tables = {entry["table"] for entry in manifest}
    business_tables = set(spec["businessReads"]) | set(
        spec["businessWrites"]
    )
    authorization_tables = set(spec["authorizationReads"])
    if (
        not business_tables <= manifest_tables
        or not authorization_tables <= manifest_tables
    ):
        raise AuthorityPlannerError(
            "authenticated root classes escaped the generated manifest"
        )

    def callback(function, *arguments):
        if work is None:
            return function(*arguments)
        authority_complete_query_batch._SharedLedger(work)
        limits, metrics = work.limits, work.metrics
        values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
        try:
            return function(*arguments)
        finally:
            authority_complete_query_batch._SharedLedger(work)
            if (work.limits is not limits or work.metrics != metrics
                    or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != values):
                raise AuthorityPlannerError("planner root callback changed its shared work")

    def read_roots(tables: set[str]) -> tuple[dict[str, Any], ...]:
        roots: list[dict[str, Any]] = []
        for table in sorted(tables):
            callback(lambda: trace.read(
                "policy_authority_authenticated_table_roots",
                {"tableName": table},
            ))
            result = callback(lambda: cursor.execute(
                "SELECT root_revision, root_digest, leaf_count "
                "FROM serverware_metadata."
                "policy_authority_authenticated_table_roots "
                "WHERE table_name = %s",
                (table,),
            ))
            row = callback(lambda: result.fetchone())
            if row is None:
                raise AuthorityPlannerError(
                    f"planner authenticated root is absent for {table}"
                )
            if work is not None:
                if (type(row) is not dict or len(row) != 3
                        or any(type(name) is not str or len(name) > 32 for name in row)
                        or set(row) != {"root_revision", "root_digest", "leaf_count"}):
                    raise AuthorityPlannerError("planner authenticated root row is not closed")
                authority_revocation_plan.contract._integer(row["root_revision"])
                authority_revocation_plan.contract._integer(row["leaf_count"])
                authority_revocation_plan.contract._digest(row["root_digest"])
            root = {
                "table": table,
                "rootRevision": row["root_revision"],
                "rootDigest": row["root_digest"],
                "leafCount": row["leaf_count"],
            }
            roots.append(authority_query_reads._CopyBudget(work).copy(root)
                         if work is not None else root)
        return tuple(roots)

    business_roots = read_roots(business_tables)
    authorization_roots = read_roots(authorization_tables)
    from serverware import control_plane_rbac_currentness as rbac_currentness
    callback(lambda: rbac_currentness.require_roots(tuple(business_roots) + tuple(authorization_roots), cursor=cursor,
        deadline_epoch_ns=deadline_epoch_ns, deadline_ns=deadline_monotonic_ns))
    if {
        entry["table"] for entry in business_roots
    } & {
        entry["table"] for entry in authorization_roots
    }:
        raise AuthorityPlannerError(
            "business and authorization roots overlap"
        )
    return (
        business_roots,
        authorization_roots,
        authority_revocation_plan._json_digest(
            "serverware.policyAuthorityRootSet/v1", business_roots, ledger,
        ) if ledger is not None else framed_digest(
            "serverware.policyAuthorityRootSet/v1",
            canonical_bytes(list(business_roots)),
        ),
    )


def _selector_keys(
    *,
    operation: str,
    request: Mapping[str, Any],
    manifest: tuple[dict[str, Any], ...],
) -> tuple[tuple[str, dict[str, Any], str | None], ...]:
    extracted = authority_contract.extract_selectors(operation, request)
    by_table = {entry["table"]: entry for entry in manifest}
    selected: dict[
        tuple[str, bytes],
        tuple[str, dict[str, Any], str | None],
    ] = {}
    for table, values in sorted(extracted.items()):
        entry = by_table.get(table)
        if entry is None or len(entry["keyColumns"]) != 1:
            raise AuthorityPlannerError(
                "contract selector cannot be mapped to an exact primary key"
            )
        column = entry["keyColumns"][0]
        for value in values:
            key = {column: value}
            identity = (table, canonical_bytes(key))
            if identity in selected:
                raise AuthorityPlannerError(
                    "contract selector produced a duplicate exact key"
                )
            selected[identity] = (
                table,
                key,
                value,
            )
    _business_intent(request, operation=operation)
    return tuple(
        selected[identity] for identity in sorted(selected)
    )


def _read_selected_rows(
    cursor: Any,
    *,
    operation: str,
    request: Mapping[str, Any],
    manifest: tuple[dict[str, Any], ...],
    trace: PlannerTrace,
) -> tuple[dict[str, Any], ...]:
    selected: list[dict[str, Any]] = []
    for table, key, selector in _selector_keys(
        operation=operation,
        request=request,
        manifest=manifest,
    ):
        entry = next(item for item in manifest if item["table"] == table)
        columns = entry["keyColumns"]
        predicate = " AND ".join(
            f"target.{column} IS NOT DISTINCT FROM %s" for column in columns
        )
        trace.read(table, key)
        row = cursor.execute(
            f"SELECT pg_catalog.to_jsonb(target) AS row_value "
            f"FROM serverware_metadata.{table} AS target "
            f"WHERE {predicate}",
            tuple(key[column] for column in columns),
        ).fetchone()
        row_value = None if row is None else row["row_value"]
        key_digest = framed_digest(
            "serverware.policyAuthorityBusinessKey/v1",
            table.encode("utf-8"),
            canonical_bytes(key),
        )
        selected.append(
            {
                "table": table,
                "key": key,
                "keyDigest": key_digest,
                "present": row_value is not None,
                "row": row_value,
                "contractSelector": selector,
            }
        )
    return tuple(
        sorted(
            selected,
            key=lambda entry: (entry["table"], entry["keyDigest"]),
        )
    )


def _read_database_now(cursor: Any) -> datetime:
    row = cursor.execute(
        "SELECT pg_catalog.clock_timestamp() AS database_now"
    ).fetchone()
    database_now = row["database_now"] if row is not None else None
    if not isinstance(database_now, datetime):
        raise AuthorityPlannerError(
            "planner database clock returned an invalid value"
        )
    if database_now.tzinfo is None:
        database_now = database_now.replace(tzinfo=timezone.utc)
    return database_now.astimezone(timezone.utc)


def _read_database_now_on_work(cursor: Any, work: _ValidationWork) -> datetime:
    """Keep the original meter intact across the separately bounded clock SQL.

    Driver and database work remain outside H/B/N accounting. A callback,
    including one that fails, cannot replenish or replace the shared allowance.
    This does not authenticate the clock or own its transaction snapshot.
    """
    authority_complete_query_batch._SharedLedger(work)
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    try:
        return _read_database_now(cursor)
    finally:
        authority_complete_query_batch._SharedLedger(work)
        if (work.limits is not limits or work.metrics != metrics
                or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != values):
            raise AuthorityPlannerError("planner database clock callback changed its shared work")


def _acquire_registration_transition_on_work(
    cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
    business_before_roots: Any, authorization_before_roots: Any,
    expected_counted_heads: tuple[dict[str, Any], ...],
    evidence_public_key: Ed25519PublicKey, expected_signer_identity: dict[str, Any],
    expected_signer_spki_digest: str, expected_rp_id: str, expected_origin: str,
    now_epoch_ns: int, deadline_epoch_ns: int, maximum_age_ns: int,
    maximum_clock_skew_ns: int, query_work: _ValidationWork,
    trace: PlannerTrace | None = None,
) -> _RegistrationAcquisition:
    """Compose actual registration reads, custody consumption and write proofs.

    The private owner must independently admit the request, configured signer,
    RP/origin, current primary/counted root vectors and clock/deadline, and own a read-only MVCC
    transaction. This function does not provide those permissions, persist new
    evidence, sign a plan, reserve execution, or bypass the registry/public gate.
    It accepts raw roots/rows only through actual SQL and proof acquisition,
    never an input successful-proof or business-effect object.

    One physical ledger covers counted reads and mutation-frontier acquisition;
    one work meter covers the real query/crypto/kernel/capacity/write engines.
    Ordinary and primary-proof SQL, staged stamps and driver/native internals
    retain their existing separate bounds. Results are observations, not a
    whole-operation CPU claim or an independently authenticated root transition.
    """
    registration = authority_transition_webauthn_registration
    operation = registration.OPERATION
    if type(query_work) is not _ValidationWork:
        raise AuthorityPlannerError("registration acquisition requires the actual shared meter")
    if trace is None:
        trace = PlannerTrace(operation=operation, _complete_queries=True)
    if (type(trace) is not PlannerTrace or type(trace.operation) is not str
            or trace.operation != operation or trace._complete_queries is not True):
        raise AuthorityPlannerError("registration acquisition trace identity changed")
    acquisition = authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
    try:
        if (type(request) is not dict or type(manifest) is not tuple
                or type(expected_counted_heads) is not tuple
                or not 1 <= len(expected_counted_heads) <= authority_index_heads.MAX_HEADS
                or type(expected_signer_identity) is not dict):
            raise AuthorityPlannerError("registration acquisition requires exact raw inputs")
        # Detach all variable inputs before any key or database callback.
        owned = authority_query_reads._CopyBudget(query_work).copy({
            "request": request, "manifest": manifest,
            "businessBeforeRoots": business_before_roots,
            "authorizationBeforeRoots": authorization_before_roots,
            "expectedCountedHeads": expected_counted_heads,
            "signerIdentity": expected_signer_identity,
            "signerSpkiDigest": expected_signer_spki_digest,
            "rpId": expected_rp_id, "origin": expected_origin,
            "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
            "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns,
        })
        actual_request = owned["request"]
        if (actual_request.get("operation") != operation
                or actual_request.get("handler") != "finalize_webauthn_registration"
                or type(actual_request.get("arguments")) is not dict):
            raise AuthorityPlannerError("registration acquisition request identity changed")
        registration._integer(owned["nowEpochNs"], "independent current time", 1)
        registration._integer(owned["deadlineEpochNs"], "independent deadline", 1)
        registration._integer(owned["maximumAgeNs"], "maximum age", 1,
                              authority_contract.VERIFIER_RESPONSE_MAX_AGE_NS)
        registration._integer(owned["maximumClockSkewNs"], "clock skew", 0,
                              authority_contract.VERIFIER_MAX_CLOCK_SKEW_NS)
        if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
            raise AuthorityPlannerError("registration acquisition deadline has expired")
        request_digest = _typed_request_digest(actual_request, work=query_work)
        claimed_request = _require_digest(actual_request.get("requestDigest"), "registration request digest")
        if _request_different(request_digest, claimed_request, work=query_work):
            raise AuthorityPlannerError("registration acquisition request digest changed")
        query_work.prepare_utf8(operation)
        query_work.prepare_utf8(request_digest)
        query_work.charge(hashes=1)
        expected_operation = operation_id(operation, request_digest)
        if _request_different(expected_operation, actual_request.get("operationId"), work=query_work):
            raise AuthorityPlannerError("registration acquisition operation id changed")
        with acquisition.read_phase(cursor, trace, query_work):
            observed_business, observed_authorization, _ = _read_root_set(
                cursor, operation=operation, manifest=owned["manifest"], trace=trace, work=query_work,
                deadline_epoch_ns=owned["deadlineEpochNs"])
            authority_revocation_semantics._canonical_equal(
                (observed_business, observed_authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]),
                work=query_work, label="registration database roots differ from independent expectations")
            database_now = _read_database_now_on_work(cursor, query_work)
            database_now_ns = registration._now(database_now)
            if (abs(database_now_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]
                    or database_now_ns >= owned["deadlineEpochNs"]):
                raise AuthorityPlannerError("registration database cutoff differs from admitted time/deadline")
            queries = registration._query_recipe_on_work(arguments=actual_request["arguments"],
                database_now=database_now, request_digest=request_digest, work=query_work)
            # The common finalizer genuinely reconstructs these declarations.
            authority_transition_webauthn._prepare_complete_copies(queries, query_work)
            authority_transition_webauthn._prepare_complete_copies(queries, query_work)
            queries = authority_audit_capacity.add_capacity_query(operation, queries)
            collector = authority_complete_acquisition._CompleteQueryAcquisition(
                cursor, operation=operation, arguments=actual_request["arguments"],
                cutoff_us=authority_complete_query.cutoff_microseconds(database_now),
                queries=tuple(query for query in queries
                              if type(query) is authority_complete_query.CompleteIndexQuery),
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                trace=trace, work=query_work, acquisition=acquisition, include_write_heads=True)
            staging = authority_query_staging.StagedQueryProofs(operation=operation,
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                query_work=query_work)
            selected, queries, records = _read_bounded_transition_rows(cursor,
                operation=operation, request=actual_request, queries=queries, manifest=owned["manifest"],
                trace=trace, query_sources=staging, query_work=query_work, complete_acquisition=collector)
            retained = collector.retained_evidence()
            actual_heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}
                for head in retained.heads)
            authority_revocation_semantics._canonical_equal(actual_heads, owned["expectedCountedHeads"],
                work=query_work, label="registration counted heads differ from independent expectations")
            acquisition.require_idle(cursor, trace, query_work)
        context = authority_transition_core.KernelContext(operation, actual_request["arguments"],
            selected, database_now, request_digest, query_reads=records)
        kernel = registration._kernel_transition_on_work(context,
            evidence_public_key=evidence_public_key, expected_signer_identity=owned["signerIdentity"],
            expected_signer_spki_digest=owned["signerSpkiDigest"], expected_rp_id=owned["rpId"],
            expected_origin=owned["origin"], maximum_age_ns=owned["maximumAgeNs"],
            maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=query_work)
        finalized = authority_audit_capacity._finalize_capacity(context, kernel.mutations, work=query_work)
        work_units = authority_audit_capacity.transition_work_units(operation=operation,
            query_work_units=sum(query.work_units for query in queries),
            kernel_work_units=kernel.work_units, mutations=finalized)
        authority_audit_capacity.validate_transition_work_units(operation, work_units, finalized)
        query_work.prepare_copy(finalized)
        ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
        query_work.prepare_copy(ordered)
        mutations = tuple(ordered)
        write_ids = {name for item in mutations
                     for name in authority_index_projection.index_ids_for_table(item["table"])}
        heads = tuple(authority_indexed_mutation.IndexedMutationHead(
            item.index_id, item.index_revision, item.index_root)
            for item in retained.heads if item.index_id in write_ids)
        limits = authority_complete_read_write._write_limits(authority_contract.operation_spec(operation),
            authority_complete_query_batch._SharedLedger(query_work))
        writer = authority_index_mutation_reader._AcquisitionBudget(
            shared_acquisition=acquisition, work=query_work)
        write_evidence = authority_index_mutation_reader._acquire_indexed_primary_batch(
            cursor, table_contracts=authority_primary_contract.primary_table_contracts(operation),
            business_before_roots=authority_complete_query_batch._roots(retained.business_before_roots),
            authorization_before_roots=authority_complete_query_batch._roots(retained.authorization_before_roots),
            selected_rows=selected, before_proofs=retained.before_proofs, mutations=mutations,
            index_before_heads=heads, limits=limits, trace=trace, acquisition_budget=writer)
        acquisition.require_idle(cursor, trace, query_work)
        for mutation in mutations:
            trace.write(mutation["table"], mutation["key"])
        closed_trace = trace.close(selected_rows=selected, mutation_plan=mutations)
        state = PlanningState(database_now=database_now,
            query_work_units=sum(query.work_units for query in queries), query_program=queries,
            query_reads=records, complete_query_evidence=retained)
        return _RegistrationAcquisition(actual_request, selected, state, kernel,
            mutations, work_units, write_evidence, closed_trace)
    except BaseException:
        acquisition.failed = True
        raise


def _acquire_trust_stage_transition_on_work(
    cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
    business_before_roots: Any, authorization_before_roots: Any,
    expected_counted_heads: tuple[dict[str, Any], ...],
    assertion_evidence: dict[str, Any], verifier_identity: dict[str, Any],
    verifier_public_key: Ed25519PublicKey, capability_id: str,
    candidate_bundle_bytes: bytes, candidate_verification_context: Any,
    expected_candidate_signing_key_id: str, development_enabled: bool,
    require_approval: bool, require_approver_webauthn: bool,
    now_epoch_ns: int, deadline_epoch_ns: int, maximum_age_ns: int,
    maximum_clock_skew_ns: int, query_work: _ValidationWork,
    trace: PlannerTrace | None = None,
) -> _TrustStageAcquisition:
    """Join genuine assertion, aggregate reads, merged effects and write proofs.

    Independent request/capability admission, candidate signing-key and schema
    configuration, current root vectors/time and read-only MVCC ownership
    remain caller prerequisites. The original candidate bundle and actual
    pinned assertion receipt are genuinely verified here before any SQL;
    candidate root policy is derived, never supplied as a successful proof DTO.
    This private acquisition neither signs/persists a plan nor executes a stage,
    activates a registry, installs trust files or establishes a terminal witness.
    """
    stage = authority_transition_webauthn_trust_stage
    operation = stage.OPERATION
    if type(query_work) is not _ValidationWork:
        raise AuthorityPlannerError("trust stage acquisition requires the actual shared meter")
    if trace is None:
        trace = PlannerTrace(operation=operation, _complete_queries=True)
    if (type(trace) is not PlannerTrace or trace.operation != operation
            or trace._complete_queries is not True):
        raise AuthorityPlannerError("trust stage acquisition trace identity changed")
    acquisition = authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
    try:
        if (type(request) is not dict or type(manifest) is not tuple
                or type(assertion_evidence) is not dict or type(verifier_identity) is not dict
                or type(expected_counted_heads) is not tuple
                or not 1 <= len(expected_counted_heads) <= authority_index_heads.MAX_HEADS
                or type(candidate_bundle_bytes) is not bytes
                or type(candidate_verification_context) is not
                    authority_webauthn_trust_candidate.bundle_core.TrustVerificationContext
                or any(type(value) is not bool for value in (
                    development_enabled, require_approval, require_approver_webauthn))):
            raise AuthorityPlannerError("trust stage acquisition inputs are not exact source values")
        copier = authority_query_reads._CopyBudget(query_work)
        owned = copier.copy({"request": request, "manifest": manifest,
            "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
            "expectedCountedHeads": expected_counted_heads, "assertion": assertion_evidence,
            "verifierIdentity": verifier_identity, "capabilityId": capability_id,
            "nowEpochNs": now_epoch_ns, "deadlineEpochNs": deadline_epoch_ns,
            "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns,
            "candidateSigningKeyId": expected_candidate_signing_key_id})
        actual_request = owned["request"]
        if (actual_request.get("operation") != operation
                or actual_request.get("handler") != "stage_webauthn_trust_publication"
                or type(actual_request.get("arguments")) is not dict):
            raise AuthorityPlannerError("trust stage acquisition request identity changed")
        registration = authority_transition_webauthn_registration
        for name in ("nowEpochNs", "deadlineEpochNs"):
            registration._integer(owned[name], name, 1)
        registration._integer(owned["maximumAgeNs"], "maximum age", 1,
                              authority_contract.VERIFIER_RESPONSE_MAX_AGE_NS)
        registration._integer(owned["maximumClockSkewNs"], "clock skew", 0,
                              authority_contract.VERIFIER_MAX_CLOCK_SKEW_NS)
        if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
            raise AuthorityPlannerError("trust stage acquisition deadline has expired")
        if registration._now(candidate_verification_context.verified_at) != owned["nowEpochNs"]:
            raise AuthorityPlannerError("candidate verification time differs from independently admitted time")
        candidate_arguments, held_roots = authority_webauthn_trust_candidate._admit_on_work(
            arguments=actual_request["arguments"], bundle_bytes=candidate_bundle_bytes,
            verification_context=candidate_verification_context,
            expected_signing_key_id=owned["candidateSigningKeyId"], work=query_work)
        # The genuine candidate worker joins every original argument field;
        # its detached result cannot substitute a different typed request.
        authority_revocation_semantics._canonical_equal(candidate_arguments, actual_request["arguments"],
            work=query_work, label="candidate admission changed the held request arguments")
        actual_request["arguments"] = candidate_arguments
        request_digest = _typed_request_digest(actual_request, work=query_work)
        if _request_different(request_digest, actual_request.get("requestDigest"), work=query_work):
            raise AuthorityPlannerError("trust stage acquisition request digest changed")
        query_work.prepare_utf8(operation)
        query_work.prepare_utf8(request_digest)
        query_work.charge(hashes=1)
        actual_operation_id = operation_id(operation, request_digest)
        if _request_different(actual_operation_id, actual_request.get("operationId"), work=query_work):
            raise AuthorityPlannerError("trust stage acquisition operation id changed")
        verified = authority_webauthn_assertion._verify_stage_assertion_evidence(
            owned["assertion"], operation_id=actual_operation_id, request_digest=request_digest,
            capability_id=owned["capabilityId"], verifier_identity=owned["verifierIdentity"],
            verifier_public_key=verifier_public_key, now_epoch_ns=owned["nowEpochNs"],
            deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=owned["maximumAgeNs"],
            work=authority_webauthn_assertion._ReceiptWork(query_work))
        query_work.prepare_copy(owned["assertion"])
        verified = dict(verified)
        with acquisition.read_phase(cursor, trace, query_work):
            observed_business, observed_authorization, _ = _read_root_set(
                cursor, operation=operation, manifest=owned["manifest"], trace=trace, work=query_work,
                deadline_epoch_ns=owned["deadlineEpochNs"])
            authority_revocation_semantics._canonical_equal(
                (observed_business, observed_authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]), work=query_work,
                label="trust stage database roots differ from independent expectations")
            database_now = _read_database_now_on_work(cursor, query_work)
            database_now_ns = registration._now(database_now)
            if (abs(database_now_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]
                    or not verified["verifiedAtEpochNs"] <= database_now_ns < verified["expiresAtEpochNs"]
                    or database_now_ns >= owned["deadlineEpochNs"]):
                raise AuthorityPlannerError("trust stage cutoff differs from live admitted assertion/time")
            authority_webauthn_trust_candidate._require_valid_at_on_work(
                arguments=actual_request["arguments"], verified_at=database_now, work=query_work)
            queries = stage._query_recipe_on_work(arguments=actual_request["arguments"],
                database_now=database_now, request_digest=request_digest,
                verified_webauthn_evidence=verified, work=query_work)
            authority_transition_webauthn._prepare_complete_copies(queries, query_work)
            authority_transition_webauthn._prepare_complete_copies(queries, query_work)
            queries = authority_audit_capacity.add_capacity_query(operation, queries)
            collector = authority_complete_acquisition._CompleteQueryAcquisition(cursor,
                operation=operation, arguments=actual_request["arguments"],
                cutoff_us=authority_complete_query.cutoff_microseconds(database_now),
                queries=tuple(query for query in queries
                              if type(query) is authority_complete_query.CompleteIndexQuery),
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                trace=trace, work=query_work, acquisition=acquisition, include_write_heads=True)
            staging = authority_query_staging.StagedQueryProofs(operation=operation,
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                query_work=query_work)
            selected, queries, records = _read_bounded_transition_rows(cursor, operation=operation,
                request=actual_request, queries=queries, manifest=owned["manifest"], trace=trace,
                query_sources=staging, query_work=query_work, complete_acquisition=collector)
            retained = collector.retained_evidence()
            actual_heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}
                for head in retained.heads)
            authority_revocation_semantics._canonical_equal(actual_heads, owned["expectedCountedHeads"],
                work=query_work, label="trust stage counted heads differ from independent expectations")
            acquisition.require_idle(cursor, trace, query_work)
        context = authority_transition_core.KernelContext(operation, actual_request["arguments"],
            selected, database_now, request_digest, verified, query_reads=records)
        kernel = stage._kernel_transition_on_work(context, candidate_roots=held_roots,
            development_enabled=development_enabled, require_approval=require_approval,
            require_approver_webauthn=require_approver_webauthn, work=query_work)
        finalized = authority_audit_capacity._finalize_capacity(context, kernel.mutations, work=query_work)
        work_units = authority_audit_capacity.transition_work_units(operation=operation,
            query_work_units=sum(query.work_units for query in queries),
            kernel_work_units=kernel.work_units, mutations=finalized)
        authority_audit_capacity.validate_transition_work_units(operation, work_units, finalized)
        mutations = authority_revocation_semantics._ordered_mutations(finalized, work=query_work)
        write_ids = {name for item in mutations
                     for name in authority_index_projection.index_ids_for_table(item["table"])}
        heads = tuple(authority_indexed_mutation.IndexedMutationHead(
            item.index_id, item.index_revision, item.index_root)
            for item in retained.heads if item.index_id in write_ids)
        limits = authority_complete_read_write._write_limits(authority_contract.operation_spec(operation),
            authority_complete_query_batch._SharedLedger(query_work))
        writer = authority_index_mutation_reader._AcquisitionBudget(shared_acquisition=acquisition, work=query_work)
        write_evidence = authority_index_mutation_reader._acquire_indexed_primary_batch(cursor,
            table_contracts=authority_primary_contract.primary_table_contracts(operation),
            business_before_roots=authority_complete_query_batch._roots(retained.business_before_roots),
            authorization_before_roots=authority_complete_query_batch._roots(retained.authorization_before_roots),
            selected_rows=selected, before_proofs=retained.before_proofs, mutations=mutations,
            index_before_heads=heads, limits=limits, trace=trace, acquisition_budget=writer)
        acquisition.require_idle(cursor, trace, query_work)
        for mutation in mutations:
            trace.write(mutation["table"], mutation["key"])
        closed_trace = trace.close(selected_rows=selected, mutation_plan=mutations)
        state = PlanningState(database_now=database_now,
            query_work_units=sum(query.work_units for query in queries), verified_webauthn_evidence=verified,
            query_program=queries, query_reads=records, complete_query_evidence=retained)
        return _TrustStageAcquisition(actual_request, selected, state, kernel,
            mutations, work_units, write_evidence, closed_trace)
    except BaseException:
        acquisition.failed = True
        raise


def _completion_read_callback_on_work(work: _ValidationWork, call: Callable[[], Any]) -> Any:
    """Guard separately bounded driver/proof calls, not assign them H/B/N cost."""
    authority_complete_query_batch._SharedLedger(work)
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    try:
        return call()
    finally:
        authority_complete_query_batch._SharedLedger(work)
        if (work.limits is not limits or work.metrics != metrics
                or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != values):
            raise AuthorityPlannerError("completion read callback changed its shared work")


def _acquire_trust_completion_transition_on_work(
    cursor: Any, *, request: dict[str, Any], manifest: tuple[dict[str, Any], ...],
    business_before_roots: Any, authorization_before_roots: Any,
    expected_counted_heads: tuple[dict[str, Any], ...],
    installation_envelope_bytes: bytes, installed_bundle_bytes: bytes, installed_state_bytes: bytes,
    installation_target_digest: str, expected_committed_stage: dict[str, Any],
    installer_public_key: Ed25519PublicKey, expected_installer_identity: dict[str, Any],
    expected_installer_spki_digest: str, now_epoch_ns: int, deadline_epoch_ns: int,
    maximum_age_ns: int, maximum_clock_skew_ns: int, query_work: _ValidationWork,
    trace: PlannerTrace | None = None,
) -> _TrustCompletionAcquisition:
    """Acquire and authenticate exact completion inputs before deriving effects.

    Request admission, current primary/count heads, committed-stage authority,
    installed-original provenance, installer configuration and the read-only
    MVCC owner are independent caller prerequisites. Four real business PK
    queries and the common capacity query are not a complete-range family.
    Their existing SQL/proof bounds remain separate from the shared counted
    head/write physical ledger; genuine primary verification, evidence
    consumption and final write evaluation use the same cumulative work.
    Nothing here signs, persists, executes, installs files or admits a registry.
    """
    completion = authority_transition_webauthn_completion
    operation = completion.OPERATION
    if type(query_work) is not _ValidationWork:
        raise AuthorityPlannerError("trust completion requires the actual shared meter")
    if trace is None:
        trace = PlannerTrace(operation=operation, _counted_writes=True)
    if (type(trace) is not PlannerTrace or trace.operation != operation
            or trace._counted_writes is not True or trace._complete_queries is not False):
        raise AuthorityPlannerError("trust completion trace identity changed")
    acquisition = authority_index_reader._ReadAcquisitionBudget(cursor, trace, work=query_work)
    try:
        if (type(request) is not dict or type(manifest) is not tuple
                or type(expected_counted_heads) is not tuple or len(expected_counted_heads) != 3
                or type(expected_committed_stage) is not dict or type(expected_installer_identity) is not dict
                or not isinstance(installer_public_key, Ed25519PublicKey)):
            raise AuthorityPlannerError("trust completion inputs are not exact source values")
        for raw, maximum in (
                (installation_envelope_bytes, completion.evidence.MAX_EVIDENCE_BYTES),
                (installed_bundle_bytes, completion.bundle_core.MAX_INSTALLATION_BYTES),
                (installed_state_bytes, completion.bundle_core.MAX_STATE_BYTES)):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise AuthorityPlannerError("trust completion requires bounded immutable originals")
        owned = authority_query_reads._CopyBudget(query_work).copy({
            "request": request, "manifest": manifest,
            "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
            "expectedCountedHeads": expected_counted_heads, "committedStage": expected_committed_stage,
            "installerIdentity": expected_installer_identity, "installerSpkiDigest": expected_installer_spki_digest,
            "installationTargetDigest": installation_target_digest, "nowEpochNs": now_epoch_ns,
            "deadlineEpochNs": deadline_epoch_ns, "maximumAgeNs": maximum_age_ns,
            "maximumClockSkewNs": maximum_clock_skew_ns})
        actual_request = owned["request"]
        if (actual_request.get("operation") != operation
                or actual_request.get("handler") != "complete_webauthn_trust_publication"
                or type(actual_request.get("arguments")) is not dict):
            raise AuthorityPlannerError("trust completion request identity changed")
        arguments = actual_request["arguments"]
        completion._object(arguments, completion._ARGUMENT_FIELDS, "completion arguments")
        completion._object(owned["committedStage"], completion._STAGE_FIELDS, "committed stage")
        registration = authority_transition_webauthn_registration
        for name in ("nowEpochNs", "deadlineEpochNs"):
            registration._integer(owned[name], name, 1)
        registration._integer(owned["maximumAgeNs"], "maximum age", 1,
                              authority_contract.VERIFIER_RESPONSE_MAX_AGE_NS)
        registration._integer(owned["maximumClockSkewNs"], "clock skew", 0,
                              authority_contract.VERIFIER_MAX_CLOCK_SKEW_NS)
        if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
            raise AuthorityPlannerError("trust completion acquisition deadline has expired")
        authority_transition_core.require_digest(owned["installationTargetDigest"], "installation target")
        authority_transition_core.require_digest(owned["installerSpkiDigest"], "installer SPKI")
        request_digest = _typed_request_digest(actual_request, work=query_work)
        if _request_different(request_digest, actual_request.get("requestDigest"), work=query_work):
            raise AuthorityPlannerError("trust completion request digest changed")
        query_work.prepare_utf8(operation)
        query_work.prepare_utf8(request_digest)
        query_work.charge(hashes=1)
        actual_operation_id = operation_id(operation, request_digest)
        if _request_different(actual_operation_id, actual_request.get("operationId"), work=query_work):
            raise AuthorityPlannerError("trust completion operation id changed")
        queries = completion.completion_queries(publication_id=arguments["publication_id"],
            verification_evidence_digest=arguments["verification_evidence_digest"],
            request_digest=request_digest, work=query_work)
        queries = authority_audit_capacity.add_capacity_query(operation, queries)
        with acquisition.read_phase(cursor, trace, query_work):
            observed_business, observed_authorization, _ = _read_root_set(
                cursor, operation=operation, manifest=owned["manifest"], trace=trace, work=query_work,
                deadline_epoch_ns=owned["deadlineEpochNs"])
            authority_revocation_semantics._canonical_equal(
                (observed_business, observed_authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]), work=query_work,
                label="trust completion database roots differ from independent expectations")
            database_now = _read_database_now_on_work(cursor, query_work)
            database_now_ns = registration._now(database_now)
            if (abs(database_now_ns - owned["nowEpochNs"]) > owned["maximumClockSkewNs"]
                    or database_now_ns >= owned["deadlineEpochNs"]):
                raise AuthorityPlannerError("trust completion cutoff differs from admitted live time")
            captured_heads = authority_index_heads.read_operation_index_heads(cursor,
                operation=operation, trace=trace, work=query_work, acquisition=acquisition,
                include_write_heads=True)
            actual_heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}
                for head in captured_heads)
            authority_revocation_semantics._canonical_equal(actual_heads, owned["expectedCountedHeads"],
                work=query_work, label="trust completion counted heads differ from independent expectations")
            staging = authority_query_staging.StagedQueryProofs(operation=operation,
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                query_work=query_work)
            selected, queries, records = _read_bounded_transition_rows(cursor, operation=operation,
                request=actual_request, queries=queries, manifest=owned["manifest"], trace=trace,
                query_sources=staging, query_work=query_work)
            pending = staging.unproved_rows(selected)
            before_proofs = _completion_read_callback_on_work(query_work,
                lambda: _derive_multiproofs(cursor, selected_rows=pending,
                    roots=observed_business + observed_authorization, trace=trace))
            before_proofs = staging.merge_proofs(selected_rows=selected, remaining_proofs=before_proofs)
            # Assembly is not authentication. Run the actual primary engine,
            # clamp its child to remaining work, then use only its owned rows.
            ledger = authority_complete_query_batch._SharedLedger(query_work)
            ledger.charge(hashes=authority_contract.TREE_DEPTH + 2)
            primary_business = authority_complete_query_batch._roots(observed_business)
            primary_authorization = authority_complete_query_batch._roots(observed_authorization)
            spec = authority_contract.operation_spec(operation)
            memberships = authority_complete_query_batch.primary.evaluate_primary_radix_memberships(
                table_contracts=authority_primary_contract.primary_table_contracts(operation),
                business_before_roots=primary_business, authorization_before_roots=primary_authorization,
                selected_rows=selected, before_proofs=before_proofs,
                limits=authority_complete_query_batch._primary_limits(spec, spec["maximumQueryRows"], ledger))
            metrics = memberships.result.metrics
            ledger.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
            if (memberships.result.business_after_roots != primary_business
                    or memberships.result.authorization_after_roots != primary_authorization
                    or metrics.mutations != 0 or metrics.recomputed_ancestors != 0):
                raise AuthorityPlannerError("trust completion membership proof changed its before roots")
            selected, before_proofs = memberships.selected_rows, memberships.before_proofs
            authority_audit_capacity._validate_capacity_transition(operation=operation,
                selected_rows=selected, mutations=(), work=query_work)
            _, records = authority_query_reads._validate_query_reads(operation,
                queries=queries, query_reads=records, selected_rows=selected, work=query_work)
            acquisition.require_idle(cursor, trace, query_work)
        context = authority_transition_core.KernelContext(operation, arguments, selected,
            database_now, request_digest, query_reads=records)
        kernel = completion._kernel_transition_on_work(context,
            installation_envelope_bytes=installation_envelope_bytes,
            installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
            installation_target_digest=owned["installationTargetDigest"],
            expected_committed_stage=owned["committedStage"], installer_public_key=installer_public_key,
            expected_installer_identity=owned["installerIdentity"],
            expected_installer_spki_digest=owned["installerSpkiDigest"],
            maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"],
            work=query_work)
        finalized = authority_audit_capacity._finalize_capacity(context, kernel.mutations, work=query_work)
        work_units = authority_audit_capacity.transition_work_units(operation=operation,
            query_work_units=sum(query.work_units for query in queries),
            kernel_work_units=kernel.work_units, mutations=finalized)
        authority_audit_capacity.validate_transition_work_units(operation, work_units, finalized)
        query_work.prepare_copy(finalized)
        ordered = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
        query_work.prepare_copy(ordered)
        mutations = tuple(ordered)
        heads = tuple(authority_indexed_mutation.IndexedMutationHead(
            item.index_id, item.index_revision, item.index_root) for item in captured_heads)
        limits = authority_complete_read_write._write_limits(spec,
            authority_complete_query_batch._SharedLedger(query_work))
        writer = authority_index_mutation_reader._AcquisitionBudget(shared_acquisition=acquisition, work=query_work)
        write_evidence = authority_index_mutation_reader._acquire_indexed_primary_batch(cursor,
            table_contracts=authority_primary_contract.primary_table_contracts(operation),
            business_before_roots=primary_business, authorization_before_roots=primary_authorization,
            selected_rows=selected, before_proofs=before_proofs, mutations=mutations,
            index_before_heads=heads, limits=limits, trace=trace, acquisition_budget=writer)
        acquisition.require_idle(cursor, trace, query_work)
        for mutation in mutations:
            trace.write(mutation["table"], mutation["key"])
        closed_trace = trace.close(selected_rows=selected, mutation_plan=mutations)
        state = PlanningState(database_now=database_now,
            query_work_units=sum(query.work_units for query in queries), query_program=queries, query_reads=records)
        return _TrustCompletionAcquisition(actual_request, selected, state, kernel,
            mutations, work_units, write_evidence, closed_trace,
            observed_business, observed_authorization, before_proofs, captured_heads)
    except BaseException:
        acquisition.failed = True
        raise


def _read_bounded_transition_rows(
    cursor: Any,
    *,
    operation: str,
    request: Mapping[str, Any] | None,
    queries: tuple[authority_transition_core.Query, ...],
    manifest: tuple[dict[str, Any], ...],
    trace: PlannerTrace,
    query_sources: authority_query_staging.StagedQueryProofs,
    query_work: _ValidationWork,
    complete_acquisition: authority_complete_acquisition._CompleteQueryAcquisition | None = None,
) -> tuple[tuple[dict[str, Any], ...],
           tuple[authority_transition_core.Query, ...],
           tuple[authority_query_reads.QueryRead, ...]]:
    # Retain query identity and empty results separately from the deduplicated
    # row union. This records SQL observations, not predicate completeness.
    if (operation in _EVIDENCE_ADMISSION_READ_OPERATIONS
            and (type(trace) is not PlannerTrace or trace.operation != operation
                 or trace._complete_queries is not False or trace._counted_writes is not False)):
        raise AuthorityPlannerError("evidence admission requires its ordinary source trace")
    query_sources._require_query_work(query_work)
    queries = authority_query_reads._snapshot_queries(operation, queries, work=query_work)
    from serverware import authority_oauth_family_query_group as family_group
    family_acquisition = family_group.Acquisition(operation, queries)
    # Reject the whole inventory before even the first business/proof read.
    # A complete declaration must never fall through to ordinary SQL LIMIT+1.
    # The earlier database-clock read is not independent time authority.
    has_complete = any(type(query) is authority_complete_query.CompleteIndexQuery for query in queries)
    if request is None and (
            operation != "webauthn.registration.evidence.admit"
            or authority_contract.operation_spec(operation)["selectors"]
            or has_complete or complete_acquisition is not None):
        raise AuthorityPlannerError("request-free reads are outside the fixed registration source subset")
    if has_complete:
        # Only the private successor acquisition worker may enter this branch.
        # No current public v3 producer constructs or passes it, and v3 payload
        # admission still has no representation for its raw evidence.
        if type(complete_acquisition) is not authority_complete_acquisition._CompleteQueryAcquisition:
            raise AuthorityPlannerError("complete index query acquisition is not available")
        complete_acquisition.begin(cursor, operation=operation, arguments=request.get("arguments"),
            queries=queries, trace=trace, work=query_work)
    elif complete_acquisition is not None:
        raise AuthorityPlannerError("complete acquisition is outside its source query family")
    manifest_by_table = {
        str(entry["table"]): entry for entry in manifest
    }
    # The fixed registration source worker regenerates and proves its own
    # three/four PK recipe before any evidence envelope or typed request exists.
    # It has no source request selectors; every ordinary request path remains
    # subject to the existing selector extraction.
    extracted = {} if request is None else authority_contract.extract_selectors(operation, request)
    selected: dict[tuple[str, bytes], dict[str, Any]] = {}
    query_reads: list[authority_query_reads.QueryRead] = []

    for query in queries:
        family_acquisition.before(query)
        manifest_entry = manifest_by_table.get(query.table)
        if manifest_entry is None:
            raise AuthorityPlannerError(
                "typed transition query table is outside the manifest"
            )
        key_columns = tuple(manifest_entry["keyColumns"])
        if (
            not key_columns
            or key_columns != authority_primary_contract.PRIMARY_KEY_COLUMNS.get(query.table)
            or any(
                not isinstance(column, str) or not column
                for column in key_columns
            )
        ):
            raise AuthorityPlannerError(
                "typed transition query has no exact primary key"
            )
        # A deferred value may influence this SQL only after its source row's
        # actual primary proof has been verified against this transaction's
        # captured roots. This does not establish their independent currentness.
        staged_rows = query_sources.authenticate_references(
            cursor, query=query, query_reads=tuple(query_reads),
            selected_rows=tuple(selected.values()), trace=trace,
        )
        selected = {
            (entry["table"], canonical_bytes(entry["key"])): entry
            for entry in staged_rows
        }
        resolved_query = authority_query_reads._resolve_query(
            operation, query, prior_reads=tuple(query_reads),
            selected_rows=tuple(selected.values()), work=query_work,
        )
        is_complete = type(query) is authority_complete_query.CompleteIndexQuery
        if is_complete:
            rows = tuple({"row_value": row} for row in complete_acquisition.read_rows(resolved_query))
        else:
            clauses: list[str] = []
            parameters: list[Any] = []
            for predicate in resolved_query.predicates:
                if predicate.operator == "is-null":
                    clauses.append(f"target.{predicate.column} IS NULL")
                elif predicate.operator == "not-null":
                    clauses.append(f"target.{predicate.column} IS NOT NULL")
                else:
                    sql_operator = {
                        "eq": "IS NOT DISTINCT FROM", "ne": "IS DISTINCT FROM",
                        "lt": "<", "lte": "<=", "gt": ">", "gte": ">=",
                    }[predicate.operator]
                    clauses.append(f"target.{predicate.column} {sql_operator} %s")
                    parameters.append(predicate.value)
            ordering = ", ".join(
                f"target.{item.column} " + ("DESC" if item.descending else "ASC")
                for item in resolved_query.order_by)
            if (operation == authority_transition_webauthn_completion.OPERATION and trace._counted_writes
                    or operation in (authority_transition_webauthn_registration.OPERATION,
                        authority_transition_webauthn_trust_stage.OPERATION) and trace._complete_queries
                    or operation in _EVIDENCE_ADMISSION_READ_OPERATIONS):
                # Keep the successors' separately bounded ordinary SQL calls
                # from changing the original proof/kernel allowance on either
                # success or failure. Complete-range reads still use their
                # real collector; no trace permission is widened here.
                _completion_read_callback_on_work(query_work,
                    lambda: trace.read(query.table, _query_trace_key(operation, query)))
                result = _completion_read_callback_on_work(query_work, lambda: cursor.execute(
                    "SELECT pg_catalog.to_jsonb(target) AS row_value "
                    f"FROM serverware_metadata.{query.table} AS target "
                    + ("WHERE " + " AND ".join(clauses) + " " if clauses else "")
                    + f"ORDER BY {ordering} LIMIT %s", (*parameters, query.maximum_rows + 1)))
                rows = _completion_read_callback_on_work(query_work, lambda: result.fetchall())
            else:
                trace.read(query.table, _query_trace_key(operation, query))
                rows = cursor.execute(
                    "SELECT pg_catalog.to_jsonb(target) AS row_value "
                    f"FROM serverware_metadata.{query.table} AS target "
                    + ("WHERE " + " AND ".join(clauses) + " " if clauses else "")
                    + f"ORDER BY {ordering} LIMIT %s",
                    (*parameters, query.maximum_rows + 1),
                ).fetchall()
            if len(rows) > query.maximum_rows:
                raise AuthorityPlannerError("typed transition query exceeded its manifest bound")
            if query.require_absence and rows:
                raise AuthorityPlannerError("typed transition exact-absence query found a row")
        # This is the actual metered SQL result, before source-reference or
        # final primary proof construction, not a caller supplied population.
        family_acquisition.record(query, len(rows))
        if operation in {"oauth.measured-pending-retirement.inspect", "oauth.measured-pending-retirement.claim",
                "oauth.measured-pending-retirement.contact", "oauth.measured-pending-retirement.finish", "oauth.measured-pending-retirement.recover"}:
            from serverware import authority_transition_oauth_measured_pending_retirement as pending_retirement
            pending_retirement.check_acquired_credentials(operation, request["arguments"], query, rows)
        query_rows = tuple(
            row["row_value"] for row in rows
        )
        resolved_absent_key = None if is_complete else resolved_query.absent_key
        if resolved_absent_key is not None and not query_rows:
            query_rows = (None,)
        ordered_selected = []
        for row_value in query_rows:
            if row_value is None:
                key = dict(resolved_absent_key or {})
            elif isinstance(row_value, Mapping):
                key = {
                    column: row_value[column]
                    for column in key_columns
                    if column in row_value
                }
            else:
                raise AuthorityPlannerError(
                    "typed transition query returned an invalid row"
                )
            if set(key) != set(key_columns):
                raise AuthorityPlannerError(
                    "typed transition query row has no exact primary key"
                )
            if is_complete:
                query_work.prepare_encoding(key)
            identity = (query.table, canonical_bytes(key))
            contract_selector = None
            if len(key_columns) == 1:
                candidate = str(key[key_columns[0]])
                if candidate in extracted.get(query.table, ()):
                    contract_selector = candidate
            if is_complete:
                query_work.prepare_copy(key)
                query_work.prepare_encoding(key)
                query_work.prepare_copy(row_value)
                query_work.prepare_utf8(query.table)
                query_work.charge(hashes=1, input_bytes=16)
            entry = _selected_business_row(
                table=query.table,
                key=key,
                row=row_value,
                contract_selector=contract_selector,
            )
            previous = selected.get(identity)
            if is_complete and previous is not None:
                query_work.prepare_encoding(previous)
                query_work.prepare_encoding(entry)
            if previous is not None and canonical_bytes(previous) != canonical_bytes(entry):
                raise AuthorityPlannerError(
                    "typed transition queries disagree on one row"
                )
            # Keep a previously verified owned snapshot on an equal overlap.
            # Replacing it with a later raw SQL dictionary would discard that
            # ownership boundary even though its current bytes compare equal.
            if previous is not None:
                entry = previous
            selected[identity] = entry
            ordered_selected.append(entry)
            trace.read(query.table, key)
        query_read = authority_query_reads._capture_query_read(
            operation, query, resolved_query=resolved_query,
            ordered_selected_rows=tuple(ordered_selected), returned_row_count=len(rows),
            work=query_work,
        )
        authority_query_reads._validate_read_budget(
            operation, query_reads=(*query_reads, query_read), work=query_work,
        )
        query_reads.append(query_read)
    family_acquisition.finish()
    selected_rows = tuple(
        sorted(
            selected.values(),
            key=lambda entry: (entry["table"], entry["keyDigest"]),
        )
    )
    _, checked_reads = authority_query_reads._validate_query_reads(
        operation, queries=queries, query_reads=tuple(query_reads), selected_rows=selected_rows,
        work=query_work,
    )
    if complete_acquisition is not None:
        complete_acquisition.finish_reads()
        pending = query_sources.unproved_rows(selected_rows)
        proof_roots = complete_acquisition.roots_for_proofs()
        if operation in (authority_transition_webauthn_registration.OPERATION,
                authority_transition_webauthn_trust_stage.OPERATION):
            # Root ownership above legitimately charges this work. The actual
            # separately bounded proof callback must leave it unchanged.
            proofs = _completion_read_callback_on_work(query_work,
                lambda: _derive_multiproofs(cursor, selected_rows=pending,
                    roots=proof_roots, trace=trace))
        else:
            proofs = _derive_multiproofs(cursor, selected_rows=pending,
                roots=proof_roots, trace=trace)
        proofs = query_sources.merge_proofs(selected_rows=selected_rows, remaining_proofs=proofs)
        verified = complete_acquisition.verify(selected_rows=selected_rows, before_proofs=proofs)
        selected_rows = verified.selected_rows
        # Recheck actual observations against the genuine engine's owned rows,
        # with the same allowance, before returning to any planning program.
        _, checked_reads = authority_query_reads._validate_query_reads(
            operation, queries=queries, query_reads=checked_reads, selected_rows=selected_rows,
            work=query_work)
    return selected_rows, queries, checked_reads


def _query_webauthn_challenge_rows(
    cursor: Any,
    *,
    predicate: str,
    parameters: tuple[Any, ...],
    maximum_rows: int,
    trace: PlannerTrace,
) -> tuple[dict[str, Any], ...]:
    if (
        not isinstance(maximum_rows, int)
        or isinstance(maximum_rows, bool)
        or not 1
            <= maximum_rows
            < WEBAUTHN_CHALLENGE_SELECTOR_OVERFLOW_LIMIT
    ):
        raise AuthorityPlannerError(
            "WebAuthn challenge selector limit is invalid"
        )
    trace.read("webauthn_challenges", None)
    rows = cursor.execute(
        "SELECT pg_catalog.to_jsonb(target) AS row_value "
        "FROM serverware_metadata.webauthn_challenges AS target "
        f"WHERE {predicate} ORDER BY target.id LIMIT %s",
        (*parameters, maximum_rows + 1),
    ).fetchall()
    if len(rows) > maximum_rows:
        raise AuthorityPlannerError(
            "WebAuthn challenge selector exceeds its proof bound"
        )
    selected: list[dict[str, Any]] = []
    for result in rows:
        row = result["row_value"]
        if (
            not isinstance(row, Mapping)
            or set(row) != WEBAUTHN_CHALLENGE_ROW_FIELDS
            or not isinstance(row.get("id"), str)
            or not row["id"]
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge query returned an invalid row"
            )
        key = {"id": row["id"]}
        trace.read("webauthn_challenges", key)
        selected.append(
            _selected_business_row(
                table="webauthn_challenges",
                key=key,
                row=row,
            )
        )
    return tuple(selected)


def _read_webauthn_challenge_planning_inputs(
    cursor: Any,
    *,
    operation: str,
    request: Mapping[str, Any],
    trace: PlannerTrace,
) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
    now_row = cursor.execute(
        "SELECT pg_catalog.clock_timestamp() AS database_now"
    ).fetchone()
    database_now = (
        now_row["database_now"] if now_row is not None else None
    )
    if not isinstance(database_now, datetime):
        raise AuthorityPlannerError(
            "planner database clock returned an invalid value"
        )
    if database_now.tzinfo is None:
        database_now = database_now.replace(tzinfo=timezone.utc)
    database_now = database_now.astimezone(timezone.utc)
    arguments = request.get("arguments")
    if not isinstance(arguments, Mapping):
        raise AuthorityPlannerError(
            "WebAuthn challenge arguments are not closed"
        )
    if operation == "webauthn.challenge.create":
        _business_intent(request, operation=operation)
        item_id = arguments.get("challenge_id")
        challenge = arguments.get("challenge")
        user_id = arguments.get("user_id")
        challenge_type = arguments.get("challenge_type")
        scope_key = arguments.get("scope_key")
        if not all(
            isinstance(value, str) and value
            for value in (
                item_id,
                challenge,
                user_id,
                challenge_type,
            )
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge creation identity is invalid"
            )
        trace.read("webauthn_challenges", None)
        bounded_count = cursor.execute(
            "SELECT COUNT(*) AS row_count FROM ("
            "SELECT 1 FROM serverware_metadata.webauthn_challenges "
            "ORDER BY id LIMIT %s"
            ") AS bounded_webauthn_challenges",
            (WEBAUTHN_CHALLENGE_PLANNING_SCAN_MAX + 1,),
        ).fetchone()
        if (
            bounded_count is None
            or int(bounded_count["row_count"])
                > WEBAUTHN_CHALLENGE_PLANNING_SCAN_MAX
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge terminal scan exceeds its bound"
            )
        collisions = _query_webauthn_challenge_rows(
            cursor,
            predicate=(
                "target.id = %s OR target.challenge = %s"
            ),
            parameters=(item_id, challenge),
            maximum_rows=1,
            trace=trace,
        )
        if collisions:
            raise AuthorityPlannerError(
                "WebAuthn challenge identity is already present"
            )
        target_key = {"id": item_id}
        trace.read("webauthn_challenges", target_key)
        selected = [
            _selected_business_row(
                table="webauthn_challenges",
                key=target_key,
                row=None,
            )
        ]
        replacements: tuple[dict[str, Any], ...] = ()
        if scope_key is not None:
            replacements = _query_webauthn_challenge_rows(
                cursor,
                predicate=(
                    "target.challenge_type = %s "
                    "AND target.user_id = %s "
                    "AND target.scope_key = %s "
                    "AND target.used_at IS NULL"
                ),
                parameters=(
                    challenge_type,
                    user_id,
                    scope_key,
                ),
                maximum_rows=(
                    WEBAUTHN_CHALLENGE_SELECTOR_OVERFLOW_LIMIT - 1
                ),
                trace=trace,
            )
            selected.extend(replacements)
        rate_start = database_now - timedelta(
            seconds=WEBAUTHN_CHALLENGE_RATE_WINDOW_SECONDS
        )
        terminal_cutoff = database_now - timedelta(
            seconds=WEBAUTHN_CHALLENGE_TERMINAL_RETENTION_SECONDS
        )
        live_replacements = sum(
            1
            for selected_replacement in replacements
            if _require_utc_timestamp(
                selected_replacement["row"]["expires_at"],
                "replacement challenge expiry",
            )
            > database_now
        )
        retained_replacements = sum(
            1
            for selected_replacement in replacements
            if selected_replacement["row"]["challenge_type"]
                != "recovery-registration"
            and _require_utc_timestamp(
                selected_replacement["row"]["expires_at"],
                "replacement challenge expiry",
            )
                > database_now
        )
        counts = cursor.execute(
            "WITH normalized AS ("
            "SELECT target.*, "
            "CASE WHEN target.used_at IS NULL "
            "AND CAST(target.expires_at AS timestamptz) <= %s "
            "THEN %s ELSE CAST(target.used_at AS timestamptz) END "
            "AS effective_used_at, "
            "(target.challenge_type = 'recovery-registration') "
            "AS recovery_retained "
            "FROM serverware_metadata.webauthn_challenges AS target"
            "), old_survivors AS ("
            "SELECT normalized.*, "
            "(normalized.effective_used_at IS NOT NULL "
            "AND normalized.effective_used_at <= %s "
            "AND NOT normalized.recovery_retained) AS old_deleted "
            "FROM normalized"
            "), ranked_terminal AS ("
            "SELECT old_survivors.id, "
            "ROW_NUMBER() OVER (ORDER BY "
            "old_survivors.effective_used_at DESC, "
            "old_survivors.id DESC) AS ordinal "
            "FROM old_survivors "
            "WHERE NOT old_survivors.old_deleted "
            "AND NOT old_survivors.recovery_retained "
            "AND old_survivors.effective_used_at IS NOT NULL"
            "), survivors AS ("
            "SELECT old_survivors.* FROM old_survivors "
            "LEFT JOIN ranked_terminal "
            "ON ranked_terminal.id = old_survivors.id "
            "WHERE NOT old_survivors.old_deleted "
            "AND (ranked_terminal.ordinal IS NULL "
            "OR ranked_terminal.ordinal <= %s)"
            ") SELECT "
            "COUNT(*) FILTER (WHERE survivors.user_id = %s "
            "AND CAST(survivors.created_at AS timestamptz) > %s) "
            "AS user_recent, "
            "COUNT(*) FILTER (WHERE "
            "CAST(survivors.created_at AS timestamptz) > %s) "
            "AS global_recent, "
            "COUNT(*) FILTER (WHERE "
            "survivors.effective_used_at IS NULL) "
            "AS global_live, "
            "COUNT(*) FILTER (WHERE survivors.user_id = %s "
            "AND survivors.effective_used_at IS NULL) "
            "AS user_live, "
            "COUNT(*) FILTER (WHERE "
            "survivors.effective_used_at IS NOT NULL "
            "AND NOT survivors.recovery_retained) "
            "AS retained "
            "FROM survivors",
            (
                database_now,
                database_now,
                terminal_cutoff,
                WEBAUTHN_CHALLENGE_MAX_RETAINED - 1,
                user_id,
                rate_start,
                rate_start,
                user_id,
            ),
        ).fetchone()
        if counts is None:
            raise AuthorityPlannerError(
                "WebAuthn challenge admission state is absent"
            )
        admission = {
            "userRecent": int(counts["user_recent"]),
            "globalRecent": int(counts["global_recent"]),
            "globalLive": int(counts["global_live"]),
            "userLive": int(counts["user_live"]),
            "retained": int(counts["retained"]),
            "replacementCount": len(replacements),
            "liveReplacementCount": live_replacements,
            "retainedReplacementCount": retained_replacements,
        }
        if (
            admission["userRecent"]
                >= WEBAUTHN_CHALLENGE_USER_RATE_MAX
            or admission["globalRecent"]
                >= WEBAUTHN_CHALLENGE_GLOBAL_RATE_MAX
            or admission["globalLive"]
                - admission["liveReplacementCount"]
                >= WEBAUTHN_CHALLENGE_GLOBAL_LIVE_MAX
            or admission["userLive"]
                - admission["liveReplacementCount"]
                >= WEBAUTHN_CHALLENGE_USER_LIVE_MAX
            or admission["retained"]
                + admission["retainedReplacementCount"]
                >= WEBAUTHN_CHALLENGE_MAX_RETAINED
        ):
            raise AuthorityPlannerError(
                "WebAuthn challenge admission limit reached"
            )
        selected.sort(
            key=lambda entry: (entry["table"], entry["keyDigest"])
        )
        return (
            tuple(selected),
            PlanningState(
                database_now=database_now,
                webauthn_admission=admission,
            ),
        )
    if operation == "webauthn.challenge.claim":
        challenge = arguments.get("challenge")
        if not isinstance(challenge, str) or not challenge:
            raise AuthorityPlannerError(
                "WebAuthn challenge claim identity is invalid"
            )
        selected = _query_webauthn_challenge_rows(
            cursor,
            predicate="target.challenge = %s",
            parameters=(challenge,),
            maximum_rows=1,
            trace=trace,
        )
        if len(selected) > 1:
            raise AuthorityPlannerError(
                "WebAuthn challenge identity is not unique"
            )
        return selected, PlanningState(database_now=database_now)
    challenge_id = arguments.get("challenge_id")
    if not isinstance(challenge_id, str) or not challenge_id:
        raise AuthorityPlannerError(
            "WebAuthn challenge consumption identity is invalid"
        )
    selected = _query_webauthn_challenge_rows(
        cursor,
        predicate="target.id = %s",
        parameters=(challenge_id,),
        maximum_rows=1,
        trace=trace,
    )
    if len(selected) > 1:
        raise AuthorityPlannerError(
            "WebAuthn challenge identity is not unique"
        )
    if not selected:
        key = {"id": challenge_id}
        trace.read("webauthn_challenges", key)
        selected = (
            _selected_business_row(
                table="webauthn_challenges",
                key=key,
                row=None,
            ),
        )
    return selected, PlanningState(database_now=database_now)


def _read_planning_inputs(
    cursor: Any,
    *,
    operation: str,
    request: Mapping[str, Any],
    manifest: tuple[dict[str, Any], ...],
    trace: PlannerTrace,
    program: PlanningProgram,
    query_sources: authority_query_staging.StagedQueryProofs | None = None,
    query_work: _ValidationWork | None = None,
    verified_webauthn_evidence: Mapping[str, Any] | None = None,
) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
    if operation not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS:
        raise AuthorityPlannerError("successor planning cannot enter the legacy read dispatcher")
    if operation in WEBAUTHN_CHALLENGE_OPERATIONS:
        return _read_webauthn_challenge_planning_inputs(
            cursor,
            operation=operation,
            request=request,
            trace=trace,
        )
    if isinstance(program, TypedTransitionPlanningProgram):
        if type(query_sources) is not authority_query_staging.StagedQueryProofs:
            raise AuthorityPlannerError("typed query proof context is unavailable")
        return program.read_inputs(
            cursor,
            request=request,
            manifest=manifest,
            trace=trace,
            query_sources=query_sources,
            query_work=query_work,
            verified_webauthn_evidence=verified_webauthn_evidence,
        )
    return (
        _read_selected_rows(
            cursor,
            operation=operation,
            request=request,
            manifest=manifest,
            trace=trace,
        ),
        PlanningState(),
    )


def _authorization_projection(
    *,
    operation: str,
    operation_identifier: str,
    request_digest: str,
    capability_id: str,
    planner_transaction_id: str,
    roots: tuple[dict[str, Any], ...],
    selected_rows: tuple[dict[str, Any], ...],
    approver_policy_digest: str | None,
    assertion_evidence_digest: str | None,
    verifier_identity: Mapping[str, str],
    created_at_epoch_ns: int,
    expires_at_epoch_ns: int,
) -> dict[str, Any]:
    spec = authority_contract.operation_spec(operation)
    if tuple(entry["table"] for entry in roots) != tuple(sorted(spec["authorizationReads"])):
        raise AuthorityPlannerError("authorization root inventory differs from source contract")
    try:
        source_rows = authority_root_transition.derive_authorization_sources(
            operation=operation, selected_rows=selected_rows,
        )
    except ValueError as exc:
        raise AuthorityPlannerError("authorization query coverage is incomplete") from exc
    return {
        "plannerTransactionId": planner_transaction_id,
        "operation": operation,
        "operationId": operation_identifier,
        "requestDigest": request_digest,
        "capabilityId": capability_id,
        "authorizationReads": list(spec["authorizationReads"]),
        "sourceRows": source_rows,
        "sourceHighWaterDigest": framed_digest(
            "serverware.policyAuthorityAuthorizationRootSet/v1",
            canonical_bytes(list(roots)),
        ),
        "approverPolicyDigest": approver_policy_digest,
        "assertionEvidenceDigest": assertion_evidence_digest,
        "verifierSessionIdentityDigest":
            verifier_identity["sessionIdentityDigest"],
        "verifierMeasurementDigest":
            verifier_identity["measurementDigest"],
        "verifierAttestationReceiptDigest":
            verifier_identity["attestationReceiptDigest"],
        "createdAtEpochNs": created_at_epoch_ns,
        "expiresAtEpochNs": expires_at_epoch_ns,
    }


def _empty_digest(depth: int) -> str:
    try:
        return authority_radix_proof.empty_digest(depth)
    except authority_radix_proof.RadixProofError as exc:
        raise AuthorityPlannerError(str(exc)) from exc


def _derive_multiproofs(
    cursor: Any,
    *,
    selected_rows: tuple[dict[str, Any], ...],
    roots: tuple[dict[str, Any], ...],
    trace: PlannerTrace,
) -> tuple[dict[str, Any], ...]:
    # The final inventory may include one separately budgeted global counter.
    # Individual business query/proof limits remain source-contract checked.
    if (not isinstance(selected_rows, tuple)
            or len(selected_rows) > authority_contract.MAX_PLAN_QUERY_ROWS
            or any(not isinstance(item, Mapping) for item in selected_rows)):
        raise AuthorityPlannerError("planner final proof inventory exceeds its bound")
    # The framework counter retains its exact contiguous singleton proof trace.
    # All other selections use source-bounded physical child-vector batches;
    # reconstructed v3 proofs and evaluator work accounting do not change.
    counter_rows = tuple(item for item in selected_rows if (
        item.get("table") == authority_audit_capacity.AGGREGATE_TABLE
        and item.get("key") == {"aggregate_id": authority_audit_capacity.AGGREGATE_ID}
    ))
    business_rows = tuple(item for item in selected_rows if not (
        item.get("table") == authority_audit_capacity.AGGREGATE_TABLE
        and item.get("key") == {"aggregate_id": authority_audit_capacity.AGGREGATE_ID}
    ))
    participates = authority_contract.operation_spec(trace.operation)["globalAuditCapacity"]
    if (len(counter_rows) != int(participates)
            or len(business_rows) > authority_contract.MAX_QUERY_PROOFS):
        raise AuthorityPlannerError("planner proof business/framework inventory is not exact")
    try:
        counter_proofs = authority_radix_proof.derive_multiproofs(
            cursor, selected_rows=counter_rows, roots=roots, trace=trace,
        )
        business_proofs = authority_radix_proof.derive_multiproofs_batched(
            cursor, selected_rows=business_rows, roots=roots, trace=trace,
        )
        return tuple(sorted((*counter_proofs, *business_proofs),
                            key=lambda entry: (entry["table"], entry["keyDigest"])))
    except (
        authority_radix_proof.RadixProofError,
        authority_transition_core.TransitionKernelError,
    ) as exc:
        raise AuthorityPlannerError(str(exc)) from exc


def _reconstruct_multiproof_root(
    proof: Mapping[str, Any],
    *,
    selected: Mapping[str, Any],
) -> str:
    try:
        return authority_radix_proof.reconstruct_multiproof_root(proof, selected=selected)
    except (
        authority_radix_proof.RadixProofError,
        authority_transition_core.TransitionKernelError,
    ) as exc:
        raise AuthorityPlannerError(str(exc)) from exc


def _validate_webauthn_evidence_envelope(
    evidence: Mapping[str, Any],
    *,
    operation: str,
    operation_identifier: str,
    request_digest: str,
    capability_id: str,
    verifier_identity: Mapping[str, Any],
) -> None:
    required = {
        "operation",
        "operationId",
        "requestDigest",
        "capabilityId",
        "challengeId",
        "challengeDigest",
        "clientChallengeDigest",
        "credentialRecordId",
        "credentialId",
        "credentialPolicyDigest",
        "authenticatorDataBase64url",
        "authenticatorDataDigest",
        "clientDataJSONBase64url",
        "clientDataJSONDigest",
        "signatureBase64url",
        "signatureDigest",
        "rpId",
        "rpIdHashDigest",
        "origin",
        "flags",
        "userPresent",
        "userVerified",
        "priorCounter",
        "counter",
        "trustHighWaterDigest",
        "metadataPublicationSequence",
        "verifierSessionIdentityDigest",
        "verifierMeasurementDigest",
        "verifierAttestationReceiptDigest",
        "verifiedAssertionReceiptDigest",
        "verifierSignatureBase64url",
        "verifierSignatureDigest",
        "verifiedAtEpochNs",
        "expiresAtEpochNs",
    }
    unsigned = dict(evidence)
    signature = decode_base64url(
        unsigned.pop("verifierSignatureBase64url", None),
        label="WebAuthn verifier signature",
        size=64,
    )
    signature_digest = unsigned.pop("verifierSignatureDigest", None)
    receipt_digest = unsigned.pop(
        "verifiedAssertionReceiptDigest",
        None,
    )
    if (
        set(evidence) != required
        or evidence.get("operation") != operation
        or evidence.get("operationId") != operation_identifier
        or evidence.get("requestDigest") != request_digest
        or evidence.get("capabilityId") != capability_id
        or evidence.get("verifierSessionIdentityDigest")
            != verifier_identity.get("sessionIdentityDigest")
        or evidence.get("verifierMeasurementDigest")
            != verifier_identity.get("measurementDigest")
        or evidence.get("verifierAttestationReceiptDigest")
            != verifier_identity.get("attestationReceiptDigest")
        or receipt_digest
            != framed_digest(
                "serverware."
                "policyAuthorityVerifiedWebAuthnAssertionReceipt/v1",
                canonical_bytes(unsigned),
            )
        or signature_digest != sha256(signature)
        or evidence.get("userPresent") is not True
        or evidence.get("userVerified") is not True
    ):
        raise AuthorityPlannerError(
            "WebAuthn pinned verifier envelope is not exact"
        )


def validate_planner_request(request: Mapping[str, Any]) -> None:
    required = {
        "schema",
        "plannerTransactionId",
        "operation",
        "operationId",
        "requestDigest",
        "capabilityId",
        "typedRequest",
        "approverPolicyDigest",
        "webauthnEvidence",
        "verifierIdentity",
        "queryManifestDigest",
        "deadlineMonotonicNs",
        "deadlineEpochNs",
        "fence",
        "reservedAtEpochNs",
    }
    typed_request = request.get("typedRequest")
    verifier_identity = request.get("verifierIdentity")
    if (
        set(request) != required
        or request.get("schema") != PLANNER_REQUEST_SCHEMA
        or not isinstance(typed_request, dict)
        or not isinstance(verifier_identity, dict)
        or request.get("operation")
            not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
        or typed_request.get("operation") != request.get("operation")
        or typed_request_digest(typed_request)
            != request.get("requestDigest")
        or request.get("operationId")
            != operation_id(
                str(request.get("operation")),
                str(request.get("requestDigest")),
            )
        or typed_request.get("operationId")
            != request.get("operationId")
        or typed_request.get("requestDigest")
            != request.get("requestDigest")
        or request.get("plannerTransactionId")
            != framed_digest(
                "serverware.policyAuthorityPlannerTransaction/v1",
                str(request.get("operationId")).encode("ascii"),
                str(request.get("requestDigest")).encode("ascii"),
                str(request.get("capabilityId")).encode("ascii"),
            )
        or set(verifier_identity)
            != {
                "sessionIdentityDigest",
                "measurementDigest",
                "attestationReceiptDigest",
            }
        or any(
            not isinstance(request.get(field), int)
            or isinstance(request.get(field), bool)
            for field in (
                "deadlineMonotonicNs",
                "deadlineEpochNs",
                "fence",
                "reservedAtEpochNs",
            )
        )
        or request["fence"] < 1
        or time.monotonic_ns() >= request["deadlineMonotonicNs"]
    ):
        raise AuthorityPlannerError("planner request is not closed")
    for field in (
        "plannerTransactionId",
        "requestDigest",
        "capabilityId",
        "queryManifestDigest",
    ):
        _require_digest(request[field], f"planner {field}")
    for field in verifier_identity:
        _require_digest(
            verifier_identity[field],
            f"planner verifier {field}",
        )
    if request["approverPolicyDigest"] is not None:
        _require_digest(
            request["approverPolicyDigest"],
            "planner approver policy digest",
        )
    evidence = request["webauthnEvidence"]
    spec = authority_contract.operation_spec(str(request["operation"]))
    if isinstance(evidence, Mapping):
        _validate_webauthn_evidence_envelope(
            evidence,
            operation=str(request["operation"]),
            operation_identifier=str(request["operationId"]),
            request_digest=str(request["requestDigest"]),
            capability_id=str(request["capabilityId"]),
            verifier_identity=verifier_identity,
        )
    elif evidence is not None or bool(spec["assertionRequired"]):
        raise AuthorityPlannerError(
            "planner WebAuthn evidence requirement changed"
        )
    reject_typed_authoritative_input(str(request["operation"]), typed_request)


def measured_plan_signature_message(payload: Mapping[str, Any]) -> bytes:
    return framed_digest(
        SIGNED_MEASURED_PLAN_SCHEMA,
        canonical_bytes(dict(payload)),
    ).encode("ascii")


def validate_measured_plan_payload(
    payload: Mapping[str, Any],
    *,
    expected_identity: PlannerIdentity,
) -> None:
    required = {
        "schema",
        "measuredPlan",
        "typedRequest",
        "selectedBusinessRows",
        "mutationPlan",
        "queryMultiproofs",
        "queryMultiproofsDigest",
        "plannerTrace",
        "plannerTraceDigest",
        "authorizationProjection",
        "webauthnEvidence",
        "expectedResult",
        "expectedResultDigest",
        "plannerIdentity",
        "rootTransition",
    }
    plan_fields = {
        "schema",
        "plannerTransactionId",
        "operation",
        "operationId",
        "requestDigest",
        "capabilityId",
        "sourceRevision",
        "authoritySchemaVersion",
        "operationContractDigest",
        "operationManifestDigest",
        "handlerContractDigest",
        "queryManifestDigest",
        "selectedBusinessRowsDigest",
        "mutationPlanDigest",
        "workUnits",
        "authorityRootSetBeforeDigest",
        "authorizationProjectionDigest",
        "authoritySnapshotDigest",
        "rootTransitionDigest",
        "deadlineMonotonicNs",
        "deadlineEpochNs",
        "fence",
    }
    expected_identity_value = {
        "sessionIdentityDigest":
            expected_identity.session_identity_digest,
        "measurementDigest": expected_identity.measurement_digest,
        "attestationReceiptDigest":
            expected_identity.attestation_receipt_digest,
    }
    measured_plan = payload.get("measuredPlan")
    typed_request = payload.get("typedRequest")
    selected = payload.get("selectedBusinessRows")
    mutations = payload.get("mutationPlan")
    multiproofs = payload.get("queryMultiproofs")
    trace = payload.get("plannerTrace")
    projection = payload.get("authorizationProjection")
    evidence = payload.get("webauthnEvidence")
    if (
        set(payload) != required
        or payload.get("schema") != PLANNER_RESPONSE_SCHEMA
        or not isinstance(measured_plan, Mapping)
        or set(measured_plan) != plan_fields
        or measured_plan.get("schema") != MEASURED_PLAN_SCHEMA
        or not isinstance(typed_request, Mapping)
        or not isinstance(selected, list)
        or not isinstance(mutations, list)
        or not isinstance(multiproofs, list)
        or not isinstance(trace, Mapping)
        or not isinstance(projection, Mapping)
        or evidence is not None and not isinstance(evidence, Mapping)
        or not isinstance(measured_plan.get("workUnits"), int)
        or isinstance(measured_plan.get("workUnits"), bool)
        or not 1
            <= measured_plan["workUnits"]
            <= authority_contract.MAX_PLAN_WORK_UNITS
        or payload.get("plannerIdentity") != expected_identity_value
    ):
        raise AuthorityPlannerError(
            "measured-plan payload is not closed"
        )
    operation = measured_plan["operation"]
    if operation not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS:
        raise AuthorityPlannerError(
            "measured-plan operation has no exact transition program"
        )
    spec = authority_contract.operation_spec(operation)
    request_digest = typed_request_digest(typed_request)
    if (
        measured_plan["workUnits"] > int(spec["maximumWorkUnits"])
        or measured_plan["operationContractDigest"]
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or measured_plan["sourceRevision"]
            != authority_contract.SOURCE_REVISION
        or measured_plan["authoritySchemaVersion"]
            != authority_contract.SCHEMA_VERSION
        or measured_plan["operationManifestDigest"]
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or measured_plan["handlerContractDigest"]
            != authority_contract.handler_contract_digest(operation)
        or measured_plan["queryManifestDigest"]
            != authority_primary_contract.source_query_manifest_digest()
        or typed_request.get("operation") != operation
        or typed_request.get("requestDigest") != request_digest
        or measured_plan["requestDigest"] != request_digest
        or measured_plan["operationId"]
            != operation_id(operation, request_digest)
        or typed_request.get("operationId")
            != measured_plan["operationId"]
        or measured_plan["plannerTransactionId"]
            != framed_digest(
                "serverware.policyAuthorityPlannerTransaction/v1",
                measured_plan["operationId"].encode("ascii"),
                request_digest.encode("ascii"),
                measured_plan["capabilityId"].encode("ascii"),
            )
        or time.monotonic_ns()
            >= measured_plan["deadlineMonotonicNs"]
        or measured_plan["deadlineEpochNs"] <= time.time_ns()
        or measured_plan["fence"] < 1
    ):
        raise AuthorityPlannerError(
            "measured-plan identity or deadline binding changed"
        )
    for field in (
        "plannerTransactionId",
        "requestDigest",
        "capabilityId",
        "operationContractDigest",
        "operationManifestDigest",
        "handlerContractDigest",
        "queryManifestDigest",
        "selectedBusinessRowsDigest",
        "mutationPlanDigest",
        "authorityRootSetBeforeDigest",
        "authorizationProjectionDigest",
        "authoritySnapshotDigest",
        "rootTransitionDigest",
    ):
        _require_digest(
            measured_plan[field],
            f"measured plan {field}",
        )
    reject_typed_authoritative_input(operation, typed_request)
    try:
        authority_audit_capacity.validate_capacity_transition(
            operation=operation, selected_rows=selected, mutations=mutations,
        )
        authority_audit_capacity.validate_transition_work_units(
            operation=operation,
            work_units=measured_plan["workUnits"],
            mutations=mutations,
        )
    except authority_transition_core.TransitionKernelError as exc:
        raise AuthorityPlannerError(
            "measured-plan global audit capacity changed"
        ) from exc
    try:
        root_transition = authority_root_transition.verify_primary_root_transition(
            operation=operation, value=payload["rootTransition"],
            selected_rows=selected, before_proofs=multiproofs, mutations=mutations,
        )
        authorization_sources = authority_root_transition.derive_authorization_sources(
            operation=operation, selected_rows=selected,
        )
    except ValueError as exc:
        raise AuthorityPlannerError("measured-plan primary root transition changed") from exc
    if (
        measured_plan["rootTransitionDigest"]
            != authority_root_transition.primary_root_transition_digest(root_transition)
        or canonical_bytes(projection.get("sourceRows")) != canonical_bytes(authorization_sources)
        or projection.get("sourceHighWaterDigest") != framed_digest(
            "serverware.policyAuthorityAuthorizationRootSet/v1",
            canonical_bytes(root_transition["authorizationBeforeRoots"]),
        )
        or projection.get("authorizationReads") != list(spec["authorizationReads"])
        or measured_plan["authorityRootSetBeforeDigest"]
            != framed_digest("serverware.policyAuthorityRootSet/v1",
                             canonical_bytes(root_transition["businessBeforeRoots"]))
        or measured_plan["authoritySnapshotDigest"] != framed_digest(
            "serverware.policyAuthoritySnapshot/v3",
            operation.encode("ascii"), measured_plan["operationId"].encode("ascii"),
            request_digest.encode("ascii"), measured_plan["queryManifestDigest"].encode("ascii"),
            measured_plan["authorityRootSetBeforeDigest"].encode("ascii"),
            measured_plan["authorizationProjectionDigest"].encode("ascii"),
            measured_plan["selectedBusinessRowsDigest"].encode("ascii"),
            measured_plan["mutationPlanDigest"].encode("ascii"),
            measured_plan["rootTransitionDigest"].encode("ascii"),
        )
    ):
        raise AuthorityPlannerError("measured-plan primary root snapshot binding changed")
    if (
        measured_plan["selectedBusinessRowsDigest"]
            != framed_digest(
                "serverware.policyAuthoritySelectedBusinessRows/v1",
                canonical_bytes(selected),
            )
        or measured_plan["mutationPlanDigest"]
            != framed_digest(
                "serverware.policyAuthorityMutationPlan/v3",
                canonical_bytes(mutations),
            )
        or payload["queryMultiproofsDigest"]
            != framed_digest(
                "serverware.policyAuthorityRadixMultiproofSet/v3",
                canonical_bytes(multiproofs),
            )
        or payload["plannerTraceDigest"]
            != framed_digest(
                PLANNER_TRACE_SCHEMA,
                canonical_bytes(trace),
            )
    ):
        raise AuthorityPlannerError(
            "measured-plan derived set digest changed"
        )
    # verify_primary_root_transition already authenticates every proof digest,
    # unique selected address and before head, then computes the complete delta.
    # Do not add an unaccounted second per-proof reconstruction here.
    allowed_reads = (
        set(spec["businessReads"])
        | set(spec["businessWrites"])
        | set(spec["authorizationReads"])
        | set(spec["frameworkPreconditions"])
        | set(spec["frameworkWrites"])
    )
    allowed_writes = set(spec["businessWrites"])
    entries = trace.get("entries")
    if (
        set(trace) != {"schema", "operation", "entries"}
        or trace.get("schema") != PLANNER_TRACE_SCHEMA
        or trace.get("operation") != operation
        or not isinstance(entries, list)
        or len(entries) > MAX_PLAN_TRACE_ENTRIES
        or any(
            not isinstance(entry, Mapping)
            or set(entry) != {"ordinal", "access", "table", "key"}
            or entry["ordinal"] != ordinal
            or entry["access"] not in {"read", "write"}
            or (
                entry["access"] == "read"
                and entry["table"] not in allowed_reads
            )
            or (
                entry["access"] == "write"
                and entry["table"] not in allowed_writes
            )
            or (
                entry["key"] is not None
                and not isinstance(entry["key"], Mapping)
            )
            or entry["access"] == "write"
                and not isinstance(entry["key"], Mapping)
            for ordinal, entry in enumerate(entries)
        )
    ):
        raise AuthorityPlannerError(
            "measured-plan trace escaped its generated manifest"
        )
    try:
        trace_budget = AuditTraceBudget(operation)
        for entry in entries:
            trace_budget.append(entry)
        trace_budget.close(mutations)
    except AuditTraceError as exc:
        raise AuthorityPlannerError(str(exc)) from exc
    expected_write_trace = [
        {
            "access": "write",
            "table": mutation["table"],
            "key": mutation["key"],
        }
        for mutation in mutations
    ]
    write_trace_start = len(entries) - len(expected_write_trace)
    actual_write_trace = [
        {
            "access": entry["access"],
            "table": entry["table"],
            "key": entry["key"],
        }
        for entry in entries[write_trace_start:]
    ]
    dependency_read_identities = {
        (
            entry["table"],
            canonical_bytes(entry["key"]),
        )
        for entry in entries[:write_trace_start]
        if entry["access"] == "read"
        and entry["table"]
            in (set(spec["businessReads"]) | set(spec["businessWrites"])
                | set(spec["authorizationReads"]))
        and isinstance(entry["key"], Mapping)
    }
    expected_read_identities = {
        (
            entry["table"],
            canonical_bytes(entry["key"]),
        )
        for entry in selected
    }
    if (
        write_trace_start < 0
        or any(
            entry["access"] != "read"
            for entry in entries[:write_trace_start]
        )
        or actual_write_trace != expected_write_trace
        or not expected_read_identities <= dependency_read_identities
    ):
        raise AuthorityPlannerError(
            "measured-plan trace is not mechanically derived"
        )
    evidence_digest = (
        framed_digest(
            "serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
            canonical_bytes(evidence),
        )
        if isinstance(evidence, Mapping)
        else None
    )
    if isinstance(evidence, Mapping):
        _validate_webauthn_evidence_envelope(
            evidence,
            operation=str(operation),
            operation_identifier=str(measured_plan["operationId"]),
            request_digest=str(request_digest),
            capability_id=str(measured_plan["capabilityId"]),
            verifier_identity={
                "sessionIdentityDigest":
                    projection.get(
                        "verifierSessionIdentityDigest"
                    ),
                "measurementDigest":
                    projection.get("verifierMeasurementDigest"),
                "attestationReceiptDigest":
                    projection.get(
                        "verifierAttestationReceiptDigest"
                    ),
            },
        )
    if (
        bool(spec["assertionRequired"])
            != isinstance(evidence, Mapping)
        or projection.get("plannerTransactionId")
            != measured_plan["plannerTransactionId"]
        or projection.get("operation") != operation
        or projection.get("operationId")
            != measured_plan["operationId"]
        or projection.get("requestDigest") != request_digest
        or projection.get("capabilityId")
            != measured_plan["capabilityId"]
        or projection.get("assertionEvidenceDigest")
            != evidence_digest
        or measured_plan["authorizationProjectionDigest"]
            != framed_digest(
                "serverware.policyAuthorityAuthorizationProjection/v1",
                canonical_bytes(projection),
            )
    ):
        raise AuthorityPlannerError(
            "measured-plan authorization projection changed"
        )


class MeasuredPlanner:
    def __init__(
        self,
        *,
        read_dsn: str,
        identity: PlannerIdentity,
        connect_timeout_seconds: int,
        enabled_operations: tuple[str, ...],
        programs: Mapping[str, PlanningProgram] = PLANNING_PROGRAMS,
        verifier_public_key: Ed25519PublicKey | None = None,
        verifier_identity: Mapping[str, str] | None = None,
        maximum_assertion_age_ns: int | None = None,
        canary_delivery_admission=None,
    ) -> None:
        if (
            not read_dsn
            or connect_timeout_seconds < 1
            or tuple(sorted(set(enabled_operations))) != enabled_operations
            or set(enabled_operations)
                - set(authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS)
            or set(enabled_operations) - set(programs)
            or set(programs)
                - set(authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS)
        ):
            raise AuthorityPlannerError(
                "read-only planner configuration is invalid"
            )
        self.read_dsn = read_dsn
        self.identity = identity
        self.connect_timeout_seconds = connect_timeout_seconds
        self.enabled_operations = frozenset(enabled_operations)
        self.programs = dict(programs)
        if ({authority_webauthn_assertion.OPERATION} | publication_approval.assertion_operations() | oauth_activation.ASSERTION_OPERATIONS | oauth_exchange.ASSERTION_OPERATIONS | oauth_measured_exchange.ASSERTION_OPERATIONS | public_revocation_approval.ASSERTION_OPERATIONS) & self.enabled_operations:
            if (
                not isinstance(verifier_public_key, Ed25519PublicKey)
                or not isinstance(verifier_identity, Mapping)
                or set(verifier_identity) != authority_webauthn_assertion.IDENTITY_FIELDS
                or type(maximum_assertion_age_ns) is not int
                or maximum_assertion_age_ns < 1
            ):
                raise AuthorityPlannerError(
                    "revocation planner verifier pin is unavailable"
                )
            for value in verifier_identity.values():
                _require_digest(value, "revocation verifier identity")
        self.verifier_public_key = verifier_public_key
        self.verifier_identity = (
            MappingProxyType(dict(verifier_identity))
            if verifier_identity is not None else None
        )
        self.maximum_assertion_age_ns = maximum_assertion_age_ns
        if self.enabled_operations & authority_policy_canary_delivery.OPERATIONS:
            if type(canary_delivery_admission) is not authority_policy_canary_delivery_policy._Admission:
                raise AuthorityPlannerError("canary delivery planner lacks its actual configuration owner")
            canary_delivery_admission.check()
        elif canary_delivery_admission is not None:
            raise AuthorityPlannerError("canary delivery configuration cannot be supplied to another planner")
        self.canary_delivery_admission = canary_delivery_admission

    def verify_assertion_evidence(
        self, request: Mapping[str, Any]
    ) -> Mapping[str, Any] | None:
        verified_webauthn_evidence = None
        if request.get("operation") in (publication_approval.assertion_operations() | oauth_activation.ASSERTION_OPERATIONS | oauth_exchange.ASSERTION_OPERATIONS | oauth_measured_exchange.ASSERTION_OPERATIONS | public_revocation_approval.ASSERTION_OPERATIONS):
            # Independently pinned receipt verification precedes any proof SQL;
            # current hardware/trust/actor and raw challenge joins are repeated
            # by the purpose kernel over genuine selected originals.
            return authority_webauthn_assertion._verify_operation_assertion_evidence(
                request["webauthnEvidence"], operation=request["operation"],
                operation_id=request["operationId"], request_digest=request["requestDigest"],
                capability_id=request["capabilityId"], verifier_identity=self.verifier_identity,
                verifier_public_key=self.verifier_public_key, now_epoch_ns=time.time_ns(),
                deadline_epoch_ns=request["deadlineEpochNs"], maximum_age_ns=self.maximum_assertion_age_ns,
                work=None)
        if request.get("operation") == authority_webauthn_assertion.OPERATION:
            # Independently authenticate the exact evidence before opening the
            # planner transaction or deriving any selectors or mutations.
            try:
                verified_webauthn_evidence = (
                    authority_webauthn_assertion.verify_revoke_assertion_evidence(
                        request["webauthnEvidence"],
                        operation_id=str(request["operationId"]),
                        request_digest=str(request["requestDigest"]),
                        capability_id=str(request["capabilityId"]),
                        verifier_identity=self.verifier_identity,
                        verifier_public_key=self.verifier_public_key,
                        now_epoch_ns=time.time_ns(),
                        deadline_epoch_ns=int(request["deadlineEpochNs"]),
                        maximum_age_ns=self.maximum_assertion_age_ns,
                    )
                )
            except authority_webauthn_assertion.AssertionEvidenceError as exc:
                raise AuthorityPlannerError(
                    "revocation planner assertion verification failed"
                ) from exc
        return verified_webauthn_evidence

    def derive(self, request: Mapping[str, Any]) -> dict[str, Any]:
        validate_planner_request(request)
        operation = str(request["operation"])
        spec = authority_contract.operation_spec(operation)
        if operation not in self.enabled_operations:
            raise AuthorityPlannerError(
                "operation is not enabled for the measured planner"
            )
        verified_webauthn_evidence = self.verify_assertion_evidence(request)
        import psycopg
        from psycopg.rows import dict_row

        trace = PlannerTrace(operation=operation)
        # One invocation-private ledger for the actual typed-query bookkeeping
        # path. This does not meter SQL, primary proofs, kernels or whole-plan
        # execution, and is never serialized or replaced between phases.
        bookkeeping = authority_contract.PLANNER_QUERY_BOOKKEEPING_CONTRACT
        query_work = (
            _ValidationWork(QueryReadValidationLimits(
                max_hashes=bookkeeping["maxHashes"],
                max_input_bytes=bookkeeping["maxInputBytes"],
                max_json_nodes=bookkeeping["maxJsonNodes"],
            ))
            if isinstance(self.programs[operation], TypedTransitionPlanningProgram)
            else None
        )
        with psycopg.connect(
            self.read_dsn,
            row_factory=dict_row,
            connect_timeout=self.connect_timeout_seconds,
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE "
                        "READ ONLY DEFERRABLE"
                    )
                    _validate_database_identity(cursor, self.identity)
                    manifest, manifest_digest = _load_manifest(
                        cursor,
                        operation=operation,
                        trace=trace,
                    )
                    authorization_manifest = (
                        _load_authorization_manifest(
                            cursor,
                            operation=operation,
                            trace=trace,
                        )
                    )
                    selection_manifest = (
                        tuple(manifest)
                        + tuple(authorization_manifest)
                    )
                    if manifest_digest != request["queryManifestDigest"]:
                        raise AuthorityPlannerError(
                            "planner query manifest generation changed"
                        )
                    (
                        roots,
                        authorization_roots,
                        root_set_digest,
                    ) = _read_root_set(
                        cursor,
                        operation=operation,
                        manifest=selection_manifest,
                        trace=trace,
                        deadline_epoch_ns=request["deadlineEpochNs"],
                        deadline_monotonic_ns=request["deadlineMonotonicNs"],
                    )
                    try:
                        query_sources = (
                            authority_query_staging.StagedQueryProofs(
                                operation=operation, business_before_roots=roots,
                                authorization_before_roots=authorization_roots,
                                query_work=query_work,
                            )
                            if isinstance(self.programs[operation], TypedTransitionPlanningProgram)
                            else None
                        )
                    except authority_query_staging.QueryStagingError as exc:
                        raise AuthorityPlannerError("typed query proof context is invalid") from exc
                    selected, planning_state = _read_planning_inputs(
                        cursor,
                        operation=operation,
                        request=request["typedRequest"],
                        manifest=selection_manifest,
                        trace=trace,
                        program=self.programs[operation],
                        query_sources=query_sources,
                        query_work=query_work,
                        verified_webauthn_evidence=verified_webauthn_evidence,
                    )
                    try:
                        unproved_selected = (
                            selected if query_sources is None
                            else query_sources.unproved_rows(selected)
                        )
                        multiproofs = _derive_multiproofs(
                            cursor,
                            selected_rows=unproved_selected,
                            roots=tuple(roots) + tuple(authorization_roots),
                            trace=trace,
                        )
                        if query_sources is not None:
                            multiproofs = query_sources.merge_proofs(
                                selected_rows=selected, remaining_proofs=multiproofs,
                            )
                        # Kernels receive the actual verifier's owned snapshot.
                        # Typed deferred sources were verified before their SQL
                        # use, but completeness/currentness remain separate.
                        verified_inputs = authority_root_transition.verify_primary_plan_inputs(
                            operation=operation, business_before_roots=roots,
                            authorization_before_roots=authorization_roots,
                            selected_rows=selected, before_proofs=multiproofs,
                        )
                        selected = verified_inputs.selected_rows
                        multiproofs = verified_inputs.before_proofs
                        if operation in policy_candidate.OPERATIONS:
                            authority_policy_candidate_inventory.require_complete_populations(
                                selected_rows=selected, before_roots=tuple(roots) + tuple(authorization_roots),
                                work=query_work, deadline_ns=request["deadlineMonotonicNs"], operation=operation)
                        if operation == authority_policy_canary.OP_INTAKE:
                            authority_policy_canary_tables.require_complete_populations(
                                selected_rows=selected, before_roots=tuple(roots) + tuple(authorization_roots),
                                work=query_work, deadline_ns=request["deadlineMonotonicNs"], operation=operation)
                        if operation == "rbac.binding.mutate":
                            planning_state = replace(planning_state,
                                rbac_primary_inputs=(tuple(roots), tuple(authorization_roots), tuple(multiproofs)))
                        from serverware import authority_oauth_retirement_succession as succession
                        from serverware import authority_oauth_retirement_succession_snapshots as succession_snapshots
                        if operation in succession_snapshots.ROOT_OPERATIONS:
                            planning_state = replace(planning_state,
                                retirement_succession_primary_roots=tuple(roots) + tuple(authorization_roots))
                            if operation in succession.SNAPSHOT_OPERATIONS:
                                authority_oauth_inventory.require_complete_populations(
                                    selected_rows=selected, before_roots=tuple(roots) + tuple(authorization_roots),
                                    work=query_work, deadline_ns=request["deadlineMonotonicNs"], operation=operation)
                            else:
                                succession_snapshots.validate_fence_inputs(selected_rows=selected,
                                    before_roots=tuple(roots) + tuple(authorization_roots), work=query_work,
                                    deadline_ns=request["deadlineMonotonicNs"])
                        if operation in authority_policy_canary_delivery.OPERATIONS:
                            self.canary_delivery_admission.verify(operation, request["typedRequest"]["arguments"],
                                int(planning_state.database_now.timestamp()) * 1_000_000_000 + planning_state.database_now.microsecond * 1000)
                            planning_state = replace(planning_state, canary_delivery_admission=self.canary_delivery_admission)
                        if operation in {oauth_activation.OP_ACTIVATE, oauth_exchange.OP_PREPARE, oauth_exchange.OP_STAGE,
                                oauth_measured_exchange.OP_PREPARE, oauth_measured_exchange.OP_STAGE,
                                "oauth.setup.create", "oauth.setup.activate", "oauth.measured-setup.prepare", "oauth.measured-setup.stage",
                                "oauth.reconnect.authorize", "oauth.reconnect.fence", "oauth.measured-reconnect.prepare",
                                succession.OP_AUTHORIZE, succession.OP_PREPARE,
                                "oauth.refresh.claim", "oauth.refresh.retain", "oauth.refresh.commit",
                                "oauth.measured-refresh.inspect", "oauth.measured-refresh.claim", "oauth.measured-refresh.capture",
                                "oauth.measured-refresh.commit", "oauth.measured-refresh.recover",
                                "oauth.measured-refresh-cleanup.inspect", "oauth.measured-refresh-cleanup.claim", "oauth.measured-refresh-cleanup.contact",
                                "oauth.measured-refresh-cleanup.finish", "oauth.measured-refresh-cleanup.recover",
                                "oauth.measured-pending-retirement.inspect", "oauth.measured-pending-retirement.claim", "oauth.measured-pending-retirement.contact",
                                "oauth.measured-pending-retirement.finish", "oauth.measured-pending-retirement.recover",
                                "oauth.measured-capture-retirement.inspect", "oauth.measured-capture-retirement.claim",
                                "credential.currentness.challenge", "credential.currentness.register", "credential.currentness.quiesce", "credential.currentness.admit",
                                "oauth.refresh-cleanup.claim", "oauth.refresh-cleanup.contact", "oauth.refresh-cleanup.finish"}:
                            authority_oauth_inventory.require_complete_populations(
                                selected_rows=selected, before_roots=tuple(roots) + tuple(authorization_roots),
                                work=query_work, deadline_ns=request["deadlineMonotonicNs"], operation=operation,
                            )
                        if isinstance(self.programs[operation], TypedTransitionPlanningProgram):
                            planning_state = replace(
                                planning_state,
                                query_reads=authority_query_reads._validate_query_reads(
                                    operation, queries=planning_state.query_program,
                                    query_reads=planning_state.query_reads, selected_rows=selected,
                                    work=query_work,
                                )[1],
                            )
                    except (authority_root_transition.PrimaryRadixMutationError,
                            authority_query_reads.QueryReadError,
                            QueryReadWorkError,
                            authority_query_staging.QueryStagingError) as exc:
                        raise AuthorityPlannerError(
                            "planner before-kernel input verification failed"
                        ) from exc
                    transition = self.programs[operation](
                        operation=operation,
                        handler=str(
                            authority_contract.operation_spec(operation)[
                                "handler"
                            ]
                        ),
                        request=request["typedRequest"],
                        manifest=selection_manifest,
                        selected_rows=selected,
                        state=planning_state,
                    )
                    if not isinstance(transition, PlannedTransition):
                        raise AuthorityPlannerError(
                            "measured planner returned the wrong type"
                        )
                    if transition.selected_business_rows != selected:
                        raise AuthorityPlannerError(
                            "planning program changed the "
                            "contract-selected rows"
                        )
                    selected = transition.selected_business_rows
                    mutations = transition.mutation_plan
                    try:
                        authority_audit_capacity.validate_capacity_transition(
                            operation=operation,
                            selected_rows=selected,
                            mutations=mutations,
                        )
                        authority_audit_capacity.validate_transition_work_units(
                            operation=operation,
                            work_units=transition.work_units,
                            mutations=mutations,
                        )
                    except authority_transition_core.TransitionKernelError as exc:
                        raise AuthorityPlannerError(
                            "planner final global audit capacity changed"
                        ) from exc
        if (
            len(selected) > int(spec["maximumQueryRows"])
            or len(mutations) > int(spec["maximumMutations"])
            or not isinstance(transition.work_units, int)
            or isinstance(transition.work_units, bool)
            or not 1
                <= transition.work_units
                <= int(spec["maximumWorkUnits"])
            or any(not isinstance(value, dict) for value in selected)
            or any(not isinstance(value, dict) for value in mutations)
        ):
            raise AuthorityPlannerError("measured plan exceeds its bound")
        for mutation in mutations:
            trace.write(str(mutation["table"]), mutation["key"])
        closed_trace = trace.close(
            selected_rows=selected,
            mutation_plan=mutations,
        )
        selected_value = list(selected)
        mutation_value = list(mutations)
        proof_value = list(multiproofs)
        try:
            root_transition = authority_root_transition.derive_primary_root_transition(
                operation=operation, business_before_roots=roots,
                authorization_before_roots=authorization_roots,
                selected_rows=selected_value, before_proofs=proof_value, mutations=mutation_value,
            )
            root_transition_digest = authority_root_transition.primary_root_transition_digest(root_transition)
        except ValueError as exc:
            raise AuthorityPlannerError("planner primary root transition failed") from exc
        trace_value = {
            "schema": PLANNER_TRACE_SCHEMA,
            "operation": operation,
            "entries": list(closed_trace),
        }
        selected_digest = framed_digest(
            "serverware.policyAuthoritySelectedBusinessRows/v1",
            canonical_bytes(selected_value),
        )
        mutation_digest = framed_digest(
            "serverware.policyAuthorityMutationPlan/v3",
            canonical_bytes(mutation_value),
        )
        multiproof_digest = framed_digest(
            "serverware.policyAuthorityRadixMultiproofSet/v3",
            canonical_bytes(proof_value),
        )
        trace_digest = framed_digest(
            PLANNER_TRACE_SCHEMA,
            canonical_bytes(trace_value),
        )
        result_bytes = canonical_bytes(transition.result)
        from serverware import db

        expected_result_digest = db.compute_authority_v9_result_digest(
            result_bytes
        )
        evidence = (
            dict(verified_webauthn_evidence)
            if verified_webauthn_evidence is not None
            else request["webauthnEvidence"]
        )
        spec = authority_contract.operation_spec(operation)
        if bool(spec["assertionRequired"]) != isinstance(evidence, dict):
            raise AuthorityPlannerError(
                "planner WebAuthn evidence requirement changed"
            )
        evidence_digest = (
            framed_digest(
                "serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
                canonical_bytes(evidence),
            )
            if isinstance(evidence, dict)
            else None
        )
        created_at = int(request["reservedAtEpochNs"])
        expires_at = int(request["deadlineEpochNs"])
        projection = _authorization_projection(
            operation=operation,
            operation_identifier=request["operationId"],
            request_digest=request["requestDigest"],
            capability_id=request["capabilityId"],
            planner_transaction_id=request["plannerTransactionId"],
            roots=authorization_roots,
            selected_rows=selected,
            approver_policy_digest=request["approverPolicyDigest"],
            assertion_evidence_digest=evidence_digest,
            verifier_identity=request["verifierIdentity"],
            created_at_epoch_ns=created_at,
            expires_at_epoch_ns=expires_at,
        )
        projection_digest = framed_digest(
            "serverware.policyAuthorityAuthorizationProjection/v1",
            canonical_bytes(projection),
        )
        snapshot_digest = db.compute_authority_v9_snapshot_digest(
            operation=operation,
            operation_id=request["operationId"],
            request_digest=request["requestDigest"],
            query_manifest_digest=manifest_digest,
            authority_root_set_before_digest=root_set_digest,
            authorization_projection_digest=projection_digest,
            selected_business_rows_digest=selected_digest,
            mutation_plan_digest=mutation_digest,
            root_transition_digest=root_transition_digest,
        )
        measured_plan = {
            "schema": MEASURED_PLAN_SCHEMA,
            "plannerTransactionId": request["plannerTransactionId"],
            "operation": operation,
            "operationId": request["operationId"],
            "requestDigest": request["requestDigest"],
            "capabilityId": request["capabilityId"],
            "sourceRevision": authority_contract.SOURCE_REVISION,
            "authoritySchemaVersion": authority_contract.SCHEMA_VERSION,
            "operationContractDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "operationManifestDigest":
                authority_contract.OPERATION_MANIFEST_DIGEST,
            "handlerContractDigest":
                authority_contract.handler_contract_digest(operation),
            "queryManifestDigest": manifest_digest,
            "selectedBusinessRowsDigest": selected_digest,
            "mutationPlanDigest": mutation_digest,
            "workUnits": transition.work_units,
            "authorityRootSetBeforeDigest": root_set_digest,
            "authorizationProjectionDigest": projection_digest,
            "authoritySnapshotDigest": snapshot_digest,
            "rootTransitionDigest": root_transition_digest,
            "deadlineMonotonicNs": request["deadlineMonotonicNs"],
            "deadlineEpochNs": request["deadlineEpochNs"],
            "fence": request["fence"],
        }
        payload = {
            "schema": PLANNER_RESPONSE_SCHEMA,
            "measuredPlan": measured_plan,
            "typedRequest": dict(request["typedRequest"]),
            "selectedBusinessRows": selected_value,
            "mutationPlan": mutation_value,
            "queryMultiproofs": proof_value,
            "rootTransition": root_transition,
            "queryMultiproofsDigest": multiproof_digest,
            "plannerTrace": trace_value,
            "plannerTraceDigest": trace_digest,
            "authorizationProjection": projection,
            "webauthnEvidence": evidence,
            "expectedResult": transition.result,
            "expectedResultDigest": expected_result_digest,
            "plannerIdentity": {
                "sessionIdentityDigest":
                    self.identity.session_identity_digest,
                "measurementDigest": self.identity.measurement_digest,
                "attestationReceiptDigest":
                    self.identity.attestation_receipt_digest,
            },
        }
        if time.monotonic_ns() >= request["deadlineMonotonicNs"]:
            raise AuthorityPlannerError(
                "measured planner crossed its absolute deadline"
            )
        validate_measured_plan_payload(
            payload,
            expected_identity=self.identity,
        )
        return payload


class PlannerPersistence:
    def __init__(
        self,
        *,
        persistence_dsn: str,
        connect_timeout_seconds: int,
        planner_public_key_verify: Callable[[bytes, bytes], None],
        expected_planner_identity: PlannerIdentity,
    ) -> None:
        if (
            not persistence_dsn
            or connect_timeout_seconds < 1
            or not callable(planner_public_key_verify)
        ):
            raise AuthorityPlannerError(
                "planner persistence configuration is invalid"
            )
        self.persistence_dsn = persistence_dsn
        self.connect_timeout_seconds = connect_timeout_seconds
        self.verify = planner_public_key_verify
        self.expected_identity = expected_planner_identity

    def persist(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        if (
            set(envelope)
            != {"schema", "payload", "signatureBase64Url"}
            or envelope.get("schema") != SIGNED_MEASURED_PLAN_SCHEMA
            or not isinstance(envelope.get("payload"), dict)
        ):
            raise AuthorityPlannerError(
                "signed measured-plan envelope is not closed"
            )
        payload = dict(envelope["payload"])
        signature = decode_base64url(
            envelope["signatureBase64Url"],
            label="measured-plan signature",
            size=64,
        )
        self.verify(signature, measured_plan_signature_message(payload))
        validate_measured_plan_payload(
            payload,
            expected_identity=self.expected_identity,
        )
        measured_plan = payload["measuredPlan"]
        import psycopg
        from psycopg.rows import dict_row
        from serverware import db

        if (
            payload["expectedResultDigest"]
            != db.compute_authority_v9_result_digest(
                canonical_bytes(payload["expectedResult"])
            )
            or measured_plan["authoritySnapshotDigest"]
                != db.compute_authority_v9_snapshot_digest(
                    operation=measured_plan["operation"],
                    operation_id=measured_plan["operationId"],
                    request_digest=measured_plan["requestDigest"],
                    query_manifest_digest=measured_plan[
                        "queryManifestDigest"
                    ],
                    authority_root_set_before_digest=measured_plan[
                        "authorityRootSetBeforeDigest"
                    ],
                    authorization_projection_digest=measured_plan[
                        "authorizationProjectionDigest"
                    ],
                    selected_business_rows_digest=measured_plan[
                        "selectedBusinessRowsDigest"
                    ],
                    mutation_plan_digest=measured_plan[
                        "mutationPlanDigest"
                    ],
                    root_transition_digest=measured_plan[
                        "rootTransitionDigest"
                    ],
                )
        ):
            raise AuthorityPlannerError(
                "measured-plan result or snapshot binding changed"
            )
        with psycopg.connect(
            self.persistence_dsn,
            row_factory=dict_row,
            connect_timeout=self.connect_timeout_seconds,
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
                    )
                facade = db.PostgresMetadataConnection(connection)
                evidence = payload["webauthnEvidence"]
                evidence_digest = None
                if isinstance(evidence, dict):
                    evidence_digest = db.persist_webauthn_assertion_evidence(
                        evidence=evidence,
                        connection=facade,
                    )
                projection = payload["authorizationProjection"]
                if (
                    not isinstance(projection, dict)
                    or projection.get("assertionEvidenceDigest")
                        != evidence_digest
                ):
                    raise AuthorityPlannerError(
                        "authorization projection evidence changed"
                    )
                projection_digest = db.persist_authorization_projection(
                    projection=projection,
                    connection=facade,
                )
                if (
                    projection_digest
                    != measured_plan["authorizationProjectionDigest"]
                ):
                    raise AuthorityPlannerError(
                        "authorization projection digest changed"
                    )
                db.reserve_authority_planner_transaction(
                    planner_transaction_id=measured_plan[
                        "plannerTransactionId"
                    ],
                    operation=measured_plan["operation"],
                    operation_id=measured_plan["operationId"],
                    request_digest=measured_plan["requestDigest"],
                    request=payload["typedRequest"],
                    capability_id=measured_plan["capabilityId"],
                    query_manifest_digest=measured_plan[
                        "queryManifestDigest"
                    ],
                    selected_business_rows=payload[
                        "selectedBusinessRows"
                    ],
                    mutation_plan=payload["mutationPlan"],
                    work_units=measured_plan["workUnits"],
                    authority_root_set_before_digest=measured_plan[
                        "authorityRootSetBeforeDigest"
                    ],
                    planner_session_identity_digest=(
                        self.expected_identity.session_identity_digest
                    ),
                    planner_measurement_digest=(
                        self.expected_identity.measurement_digest
                    ),
                    planner_attestation_receipt_digest=(
                        self.expected_identity.attestation_receipt_digest
                    ),
                    deadline_monotonic_ns=measured_plan[
                        "deadlineMonotonicNs"
                    ],
                    deadline_epoch_ns=measured_plan["deadlineEpochNs"],
                    fence=measured_plan["fence"],
                    reserved_at_epoch_ns=projection[
                        "createdAtEpochNs"
                    ],
                    connection=facade,
                )
                db.complete_authority_planner_transaction(
                    planner_transaction_id=measured_plan[
                        "plannerTransactionId"
                    ],
                    authorization_projection_digest=projection_digest,
                    exact_plan_bytes=canonical_bytes(payload),
                    planned_at_epoch_ns=time.time_ns(),
                    connection=facade,
                )
        return {
            "schema": PLANNER_PERSIST_RECEIPT_SCHEMA,
            "plannerTransactionId":
                measured_plan["plannerTransactionId"],
            "authorizationProjectionDigest": projection_digest,
            "authoritySnapshotDigest":
                measured_plan["authoritySnapshotDigest"],
            "expectedResultDigest": payload["expectedResultDigest"],
            "plannerTraceDigest": payload["plannerTraceDigest"],
            "queryMultiproofsDigest":
                payload["queryMultiproofsDigest"],
        }


class ExecutionEnvelopePersistence:
    def __init__(
        self,
        *,
        persistence_dsn: str,
        connect_timeout_seconds: int,
    ) -> None:
        if not persistence_dsn or connect_timeout_seconds < 1:
            raise AuthorityPlannerError(
                "execution reservation writer configuration is invalid"
            )
        self.persistence_dsn = persistence_dsn
        self.connect_timeout_seconds = connect_timeout_seconds

    def reserve(self, request: Mapping[str, Any]) -> dict[str, Any]:
        required = {
            "envelopeId",
            "parentEnvelopeId",
            "operation",
            "operationId",
            "requestDigest",
            "capabilityId",
            "plannerTransactionId",
            "authorizationProjectionDigest",
            "exactRequestBase64Url",
            "deadlineMonotonicNs",
            "deadlineEpochNs",
            "fence",
            "reservedAtEpochNs",
        }
        if (
            set(request) != required
            or request.get("operation")
                not in authority_transition_registry.LEGACY_PLANNABLE_OPERATIONS
            or request.get("parentEnvelopeId")
                != request.get("plannerTransactionId")
            or any(
                not isinstance(request.get(field), int)
                or isinstance(request.get(field), bool)
                for field in (
                    "deadlineMonotonicNs",
                    "deadlineEpochNs",
                    "fence",
                    "reservedAtEpochNs",
                )
            )
            or request["fence"] < 1
            or time.monotonic_ns() >= request["deadlineMonotonicNs"]
        ):
            raise AuthorityPlannerError(
                "execution reservation request is not closed"
            )
        for field in (
            "envelopeId",
            "parentEnvelopeId",
            "operationId",
            "requestDigest",
            "capabilityId",
            "plannerTransactionId",
            "authorizationProjectionDigest",
        ):
            _require_digest(
                request[field],
                f"execution reservation {field}",
            )
        exact_request = decode_base64url(
            request["exactRequestBase64Url"],
            label="exact execution request",
        )
        try:
            typed_request = json.loads(exact_request)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorityPlannerError(
                "exact execution request is not JSON"
            ) from exc
        if (
            not isinstance(typed_request, dict)
            or canonical_bytes(typed_request) != exact_request
            or typed_request_digest(typed_request)
                != request["requestDigest"]
            or typed_request.get("operationId")
                != request["operationId"]
        ):
            raise AuthorityPlannerError(
                "exact execution request binding changed"
            )
        import psycopg
        from psycopg.rows import dict_row
        from serverware import db

        with psycopg.connect(
            self.persistence_dsn,
            row_factory=dict_row,
            connect_timeout=self.connect_timeout_seconds,
            options="-c search_path=pg_catalog",
        ) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
                    )
                facade = db.PostgresMetadataConnection(connection)
                row = db.reserve_authority_execution_envelope(
                    envelope_id=request["envelopeId"],
                    parent_envelope_id=request["parentEnvelopeId"],
                    operation=request["operation"],
                    operation_id=request["operationId"],
                    request_digest=request["requestDigest"],
                    capability_id=request["capabilityId"],
                    planner_transaction_id=request[
                        "plannerTransactionId"
                    ],
                    authorization_projection_digest=request[
                        "authorizationProjectionDigest"
                    ],
                    exact_request_bytes=exact_request,
                    deadline_monotonic_ns=request[
                        "deadlineMonotonicNs"
                    ],
                    deadline_epoch_ns=request["deadlineEpochNs"],
                    fence=request["fence"],
                    reserved_at_epoch_ns=request[
                        "reservedAtEpochNs"
                    ],
                    connection=facade,
                )
        if row.get("status") != "reserved":
            raise AuthorityPlannerError(
                "execution reservation is already terminal"
            )
        return {
            "schema": EXECUTION_RESERVATION_RECEIPT_SCHEMA,
            "envelopeId": request["envelopeId"],
            "plannerTransactionId":
                request["plannerTransactionId"],
            "requestDigest": request["requestDigest"],
            "exactRequestBytesDigest": sha256(exact_request),
            "deadlineMonotonicNs": request["deadlineMonotonicNs"],
            "fence": request["fence"],
            "status": "reserved",
        }


def exact_response_bytes(response: Mapping[str, Any]) -> bytes:
    value = canonical_bytes(dict(response))
    if len(value) > authority_contract.MAX_RESULT_BYTES:
        raise AuthorityPlannerError("planner response exceeds its bound")
    return value


def decode_exact_response(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * ((4 - len(value) % 4) % 4)
        )
    except (ValueError, TypeError) as exc:
        raise AuthorityPlannerError(
            "stored planner response is not base64url"
        ) from exc
    return decoded
