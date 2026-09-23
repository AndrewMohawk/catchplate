from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_audit_capacity
from serverware.authority_audit_trace import (
    AuditTraceBudget,
    AuditTraceError,
    MAX_PLAN_TRACE_ENTRIES,
    audit_capacity_scan_key,
)
from serverware import authority_contract
from serverware import authority_complete_query
from serverware import authority_primary_contract
from serverware import authority_query_reads
from serverware import authority_query_staging
from serverware import authority_radix_proof
from serverware import authority_root_transition
from serverware import authority_transition_core
from serverware import authority_transition_registry
from serverware import authority_webauthn_assertion
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


class AuthorityPlannerError(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def framed_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(encoded_domain)
    digest.update(b"\x00")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


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


def operation_id(operation: str, request_digest: str) -> str:
    return framed_digest(
        "serverware.policyAuthorityOperation/v2",
        operation.encode("utf-8"),
        request_digest.encode("utf-8"),
    )


def _authorization_arguments(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    excluded = {
        "authn",
        "authn_evidence",
        "webauthn_authorization",
        "challenge_id",
    }
    return {
        key: value
        for key, value in sorted(arguments.items())
        if key not in excluded
    }


def typed_request_digest(request: Mapping[str, Any]) -> str:
    required = {
        "schema",
        "operation",
        "operationId",
        "requestDigest",
        "handler",
        "operationManifestDigest",
        "arguments",
    }
    operation = request.get("operation")
    if (
        set(request) != required
        or request.get("schema")
            != "serverware.policyAuthorityV9Request/v1"
        or operation
            not in authority_transition_registry.PLANNABLE_OPERATIONS
        or request.get("handler")
            != authority_contract.operation_spec(str(operation))["handler"]
        or request.get("operationManifestDigest")
            != authority_contract.OPERATION_MANIFEST_DIGEST
        or not isinstance(request.get("arguments"), Mapping)
    ):
        raise AuthorityPlannerError(
            "typed planner request is not closed"
        )
    _business_intent(request, operation=str(operation))
    return framed_digest(
        "serverware.policyAuthorityV9Request/v1",
        canonical_bytes(
            {
                "schema":
                    "serverware.policyAuthorityV9Authorization/v1",
                "operation": operation,
                "handler": request["handler"],
                "operationManifestDigest":
                    authority_contract.OPERATION_MANIFEST_DIGEST,
                "arguments": _authorization_arguments(
                    request["arguments"]
                ),
            }
        ),
    )


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
    def __init__(self, *, operation: str) -> None:
        spec = authority_contract.operation_spec(operation)
        self.operation = operation
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


def _business_intent(
    request: Mapping[str, Any],
    *,
    operation: str,
) -> Mapping[str, Any]:
    arguments = request.get("arguments")
    intent = (
        arguments.get("businessIntent")
        if isinstance(arguments, Mapping)
        else None
    )
    caller_arguments = (
        {
            key: value
            for key, value in sorted(arguments.items())
            if key != "businessIntent"
        }
        if isinstance(arguments, Mapping)
        else None
    )
    spec = authority_contract.operation_spec(operation)
    if (
        not isinstance(intent, Mapping)
        or set(intent)
            != {
                "schema",
                "operation",
                "planningAdapterId",
                "arguments",
            }
        or intent.get("schema") != BUSINESS_INTENT_SCHEMA
        or intent.get("operation") != operation
        or intent.get("planningAdapterId")
            != spec["planningAdapterId"]
        or not isinstance(intent.get("arguments"), Mapping)
        or caller_arguments is None
    ):
        raise AuthorityPlannerError(
            "typed operation business intent is not closed"
        )
    try:
        expected = authority_contract.synthesize_business_intent(
            operation,
            caller_arguments,
        )
    except ValueError as exc:
        raise AuthorityPlannerError(
            "typed operation business intent cannot be synthesized"
        ) from exc
    if (
        dict(intent) != expected
        or dict(intent["arguments"]) != expected["arguments"]
    ):
        raise AuthorityPlannerError(
            "typed operation business intent differs from the registry"
        )
    return intent


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
        verified_webauthn_evidence: Mapping[str, Any] | None = None,
    ) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
        if (
            self.kernel.operation != self.operation
            or self.kernel.handler != self.handler
            or self.kernel.program_id
                != authority_contract.transition_program_id(self.operation)
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
            if self.operation == authority_webauthn_assertion.OPERATION:
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
            )
        except (authority_transition_core.TransitionKernelError,
                authority_complete_query.CompleteQueryError,
                authority_query_reads.QueryReadError,
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
        )

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
        if (
            operation != self.operation
            or handler != self.handler
            or self.kernel.operation != operation
            or self.kernel.handler != handler
            or self.kernel.program_id
                != authority_contract.transition_program_id(operation)
            or state.database_now is None
            or (operation == authority_webauthn_assertion.OPERATION)
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
) -> tuple[
    tuple[dict[str, Any], ...],
    tuple[dict[str, Any], ...],
    str,
]:
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

    def read_roots(tables: set[str]) -> tuple[dict[str, Any], ...]:
        roots: list[dict[str, Any]] = []
        for table in sorted(tables):
            trace.read(
                "policy_authority_authenticated_table_roots",
                {"tableName": table},
            )
            row = cursor.execute(
                "SELECT root_revision, root_digest, leaf_count "
                "FROM serverware_metadata."
                "policy_authority_authenticated_table_roots "
                "WHERE table_name = %s",
                (table,),
            ).fetchone()
            if row is None:
                raise AuthorityPlannerError(
                    f"planner authenticated root is absent for {table}"
                )
            roots.append(
                {
                    "table": table,
                    "rootRevision": row["root_revision"],
                    "rootDigest": row["root_digest"],
                    "leafCount": row["leaf_count"],
                }
            )
        return tuple(roots)

    business_roots = read_roots(business_tables)
    authorization_roots = read_roots(authorization_tables)
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
        framed_digest(
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


def _read_bounded_transition_rows(
    cursor: Any,
    *,
    operation: str,
    request: Mapping[str, Any],
    queries: tuple[authority_transition_core.Query, ...],
    manifest: tuple[dict[str, Any], ...],
    trace: PlannerTrace,
    query_sources: authority_query_staging.StagedQueryProofs,
) -> tuple[tuple[dict[str, Any], ...],
           tuple[authority_transition_core.Query, ...],
           tuple[authority_query_reads.QueryRead, ...]]:
    # Retain query identity and empty results separately from the deduplicated
    # row union. This records SQL observations, not predicate completeness.
    queries = authority_query_reads.snapshot_queries(operation, queries)
    # Reject the whole inventory before even the first business/proof read.
    # A complete declaration must never fall through to ordinary SQL LIMIT+1.
    # The earlier database-clock read is not independent time authority.
    if any(type(query) is authority_complete_query.CompleteIndexQuery for query in queries):
        raise AuthorityPlannerError("complete index query acquisition is not available")
    manifest_by_table = {
        str(entry["table"]): entry for entry in manifest
    }
    extracted = authority_contract.extract_selectors(operation, request)
    selected: dict[tuple[str, bytes], dict[str, Any]] = {}
    query_reads: list[authority_query_reads.QueryRead] = []

    for query in queries:
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
        resolved_query = authority_query_reads.resolve_query(
            operation, query, prior_reads=tuple(query_reads),
            selected_rows=tuple(selected.values()),
        )
        clauses: list[str] = []
        parameters: list[Any] = []
        for predicate in resolved_query.predicates:
            if predicate.operator == "is-null":
                clauses.append(
                    f"target.{predicate.column} IS NULL"
                )
            elif predicate.operator == "not-null":
                clauses.append(
                    f"target.{predicate.column} IS NOT NULL"
                )
            else:
                sql_operator = {
                    "eq": "IS NOT DISTINCT FROM",
                    "ne": "IS DISTINCT FROM",
                    "lt": "<",
                    "lte": "<=",
                    "gt": ">",
                    "gte": ">=",
                }[predicate.operator]
                clauses.append(
                    f"target.{predicate.column} {sql_operator} %s"
                )
                parameters.append(predicate.value)
        order = resolved_query.order_by
        ordering = ", ".join(
            f"target.{item.column} "
            + ("DESC" if item.descending else "ASC")
            for item in order
        )
        trace.read(query.table, _query_trace_key(operation, query))
        rows = cursor.execute(
            "SELECT pg_catalog.to_jsonb(target) AS row_value "
            f"FROM serverware_metadata.{query.table} AS target "
            + ("WHERE " + " AND ".join(clauses) + " " if clauses else "")
            + f"ORDER BY {ordering} LIMIT %s",
            (*parameters, query.maximum_rows + 1),
        ).fetchall()
        if len(rows) > query.maximum_rows:
            raise AuthorityPlannerError(
                "typed transition query exceeded its manifest bound"
            )
        if query.require_absence and rows:
            raise AuthorityPlannerError(
                "typed transition exact-absence query found a row"
            )
        query_rows = tuple(
            row["row_value"] for row in rows
        )
        resolved_absent_key = resolved_query.absent_key
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
            identity = (query.table, canonical_bytes(key))
            contract_selector = None
            if len(key_columns) == 1:
                candidate = str(key[key_columns[0]])
                if candidate in extracted.get(query.table, ()):
                    contract_selector = candidate
            entry = _selected_business_row(
                table=query.table,
                key=key,
                row=row_value,
                contract_selector=contract_selector,
            )
            previous = selected.get(identity)
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
        query_read = authority_query_reads.capture_query_read(
            operation, query, resolved_query=resolved_query,
            ordered_selected_rows=tuple(ordered_selected), returned_row_count=len(rows),
        )
        authority_query_reads.validate_read_budget(
            operation, query_reads=(*query_reads, query_read),
        )
        query_reads.append(query_read)
    selected_rows = tuple(
        sorted(
            selected.values(),
            key=lambda entry: (entry["table"], entry["keyDigest"]),
        )
    )
    return selected_rows, queries, authority_query_reads.validate_query_reads(
        operation, queries=queries, query_reads=tuple(query_reads), selected_rows=selected_rows,
    )


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
    verified_webauthn_evidence: Mapping[str, Any] | None = None,
) -> tuple[tuple[dict[str, Any], ...], PlanningState]:
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
            not in authority_transition_registry.PLANNABLE_OPERATIONS
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
    reject_authoritative_input(typed_request)


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
    if operation not in authority_transition_registry.PLANNABLE_OPERATIONS:
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
    reject_authoritative_input(typed_request)
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
    ) -> None:
        if (
            not read_dsn
            or connect_timeout_seconds < 1
            or tuple(sorted(set(enabled_operations))) != enabled_operations
            or set(enabled_operations)
                - set(authority_transition_registry.PLANNABLE_OPERATIONS)
            or set(enabled_operations) - set(programs)
            or set(programs)
                - set(authority_transition_registry.PLANNABLE_OPERATIONS)
        ):
            raise AuthorityPlannerError(
                "read-only planner configuration is invalid"
            )
        self.read_dsn = read_dsn
        self.identity = identity
        self.connect_timeout_seconds = connect_timeout_seconds
        self.enabled_operations = frozenset(enabled_operations)
        self.programs = dict(programs)
        if authority_webauthn_assertion.OPERATION in self.enabled_operations:
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

    def verify_assertion_evidence(
        self, request: Mapping[str, Any]
    ) -> Mapping[str, Any] | None:
        verified_webauthn_evidence = None
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
                    )
                    try:
                        query_sources = (
                            authority_query_staging.StagedQueryProofs(
                                operation=operation, business_before_roots=roots,
                                authorization_before_roots=authorization_roots,
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
                        if isinstance(self.programs[operation], TypedTransitionPlanningProgram):
                            planning_state = replace(
                                planning_state,
                                query_reads=authority_query_reads.validate_query_reads(
                                    operation, queries=planning_state.query_program,
                                    query_reads=planning_state.query_reads, selected_rows=selected,
                                ),
                            )
                    except (authority_root_transition.PrimaryRadixMutationError,
                            authority_query_reads.QueryReadError,
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
                not in authority_contract.OPERATION_REGISTRY
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
