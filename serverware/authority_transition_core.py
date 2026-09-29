from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from serverware import authority_contract
from serverware import authority_complete_query
from serverware import authority_query_reads
from serverware.authority_query_read_work import _ValidationWork


QUERY_PROGRAM_SCHEMA = "serverware.policyAuthorityQueryProgram/v1"
TRANSITION_PROGRAM_SCHEMA = "serverware.policyAuthorityTransitionProgram/v1"
MAX_QUERY_PREDICATES = 32
MAX_QUERY_ORDER_COLUMNS = 8
MAX_ARGUMENT_DEPTH = 16
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_QUERY_OPERATORS = frozenset(
    {"eq", "ne", "lt", "lte", "gt", "gte", "is-null", "not-null"}
)
_SIGNED_BIGINT_MAX = 2**63 - 1
_DECISION_GATE_PUBLICATION_BINDING_FIELDS = frozenset(
    {
        "publicationRequestId",
        "replayId",
        "generationId",
        "predecessorGenerationDigest",
        "generationEpoch",
        "generationTombstoneEpoch",
        "assignmentEnvelopeDigest",
        "assignmentPayloadDigest",
        "assignmentRevision",
        "loadReceiptEnvelopeDigest",
        "loadReceiptPayloadDigest",
        "custodyPreparationReceiptDigest",
        "custodyPublicationReceiptDigest",
        "activationPublicationReceiptDigest",
        "ingressEvidenceChainDigest",
        "ingressHighWaterDigest",
        "ingressRangeStartSequence",
        "ingressRangeEndSequence",
        "ingressRangePredecessorHeadDigest",
        "activationMode",
        "activePolicyDigest",
        "activePolicySequence",
        "activeRollbackEpoch",
        "activeCompiledSnapshotDigest",
        "candidatePolicyDigest",
        "candidatePolicySequence",
        "candidateRollbackEpoch",
        "candidateCompiledSnapshotDigest",
        "publicationRevision",
        "policyHighWaterBeforeDigest",
        "policyHighWaterAfterDigest",
        "readinessCoreDigest",
        "authorityKeyIndependenceDigest",
        "activationTransactionDigest",
        "runtimeExecutableDigest",
        "runtimeReleaseAttestationDigest",
        "runtimePolicyAttestationDigest",
        "runtimeConfigAttestationDigest",
        "runtimeTeeEvidenceDigest",
        "runtimeTeeMeasurementDigest",
        "runtimeAttestationReceiptDigest",
        "runtimeEvidenceChainDigest",
        "bootIdDigest",
        "instanceId",
        "trustCheckpointDigest",
        "trustRevocationGeneration",
        "trustRevocationRootDigest",
        "persistenceReceiptDigest",
        "retrievalIdDigest",
        "retrievalProofDigest",
        "authoritativeLedgerEventOrdinal",
        "authoritativeLedgerHeadDigest",
        "authoritativeSpoolRootDigest",
    }
)
_DECISION_GATE_PUBLICATION_STATEMENT_FIELDS = (
    _DECISION_GATE_PUBLICATION_BINDING_FIELDS
    | {
        "schema",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
        "generationPublicationEnvelope",
        "generationPublicationEnvelopeDigest",
        "activationPublicationEnvelope",
        "activationPublicationEnvelopeDigest",
        "runtimeAttestationVerifierEnvelope",
        "runtimeAttestationVerifierEnvelopeDigest",
        "evidenceChainDigest",
    }
)
_DECISION_GATE_PUBLICATION_ENVELOPE_FIELDS = frozenset(
    {
        "apiVersion",
        "kind",
        "canonicalProfile",
        "signatureDomain",
        "payload",
        "payloadSha256",
        "signatureAlgorithm",
        "signingKeyId",
        "signingKeySpkiSha256",
        "signature",
    }
)
_GENERATION_PUBLICATION_PAYLOAD_FIELDS = frozenset(
    {
        "schemaVersion",
        "signatureDomain",
        "signatureAlgorithm",
        "canonicalizationProfile",
        "status",
        "request",
        "preparationEnvelopeSha256",
        "generation",
        "custody",
        "runtime",
        "trust",
        "attestationChain",
        "externalRecordSha256",
        "durableCommitReceiptSha256",
        "notBeforeUnixNanos",
        "issuedAtUnixNanos",
        "expiresAtUnixNanos",
    }
)
_PUBLICATION_REQUEST_FIELDS = frozenset(
    {
        "requestId",
        "replayId",
        "managementHandoffId",
        "managementHandoffSha256",
        "requestSha256",
    }
)
_PUBLICATION_SNAPSHOT_FIELDS = frozenset(
    {
        "policySha256",
        "policySequence",
        "rollbackEpoch",
        "compiledSnapshotSha256",
        "compiledBehaviorSha256",
        "runtimeSnapshotEpoch",
        "policyTrustGeneration",
    }
)
_PUBLICATION_GENERATION_FIELDS = frozenset(
    {
        "generationId",
        "generationEpoch",
        "generationTombstoneEpoch",
        "assignmentEnvelopeSha256",
        "assignmentPayloadSha256",
        "assignmentRevision",
        "loadReceiptEnvelopeSha256",
        "loadReceiptPayloadSha256",
        "runtimeBootIdSha256",
        "active",
        "candidate",
        "requestCommitmentKeyEpoch",
        "requestFactsSchemaSha256",
        "ingressRangeStartSequence",
        "ingressRangePredecessorHeadSha256",
        "observationIntervalSha256",
        "responseValidationObligationsRootSha256",
        "signedPublicationRevision",
    }
)
_PUBLICATION_CUSTODY_FIELDS = frozenset(
    {
        "custodyConfigurationSha256",
        "preparationReceiptSha256",
        "publicationReceiptSha256",
        "publicationRevision",
        "publicationReconciliationReceiptSha256",
        "authoritativeLedgerEventOrdinal",
        "authoritativeLedgerHeadSha256",
        "authoritativeSpoolRootSha256",
    }
)
_PUBLICATION_RUNTIME_FIELDS = frozenset(
    {
        "decisionGateExecutableSha256",
        "decisionGateRuntimeMeasurementSha256",
        "releaseProvenanceSha256",
        "runtimeConfigurationSha256",
        "runtimePolicySha256",
        "imageSignaturesSha256",
        "generationTrustManifestSha256",
        "policyCompilerBinarySha256",
        "policyCompilerConfigurationSha256",
        "policySchemaSha256",
        "adapterSchemaSha256",
        "policySemanticModelSha256",
        "policyPlanSchemaSha256",
        "requestFactsSchemaSha256",
        "runtimeAttestationVerifierExecutableSha256",
        "publicationHandoffExecutableSha256",
        "activePolicySigningKeyId",
        "runtimeInstanceId",
        "runtimeIdentitySha256",
        "runtimeBootIdSha256",
        "runtimeTeeMeasurementSha256",
    }
)
_PUBLICATION_TRUST_FIELDS = frozenset(
    {
        "trustCheckpointSha256",
        "revocationGeneration",
        "revocationRootSha256",
        "runtimeAttestationPolicySha256",
        "runtimeAttestationVerifierSigningKeyId",
        "runtimeAttestationVerifierSigningKeySpkiSha256",
        "publicationSigningKeyId",
        "publicationSigningKeySpkiSha256",
        "publicationReplayStoreSha256",
        "replayStoreRevision",
    }
)
_PUBLICATION_ATTESTATION_CHAIN_FIELDS = frozenset(
    {
        "startupAttestation",
        "runtimeAttestationVerification",
        "runtimeAttestationVerificationEnvelopeSha256",
        "attestationMode",
        "hardwareAttested",
    }
)
_RUNTIME_ATTESTATION_EVIDENCE_FIELDS = frozenset(
    {
        "apiVersion",
        "evidenceId",
        "evidenceRevision",
        "evidenceType",
        "evidenceSha256",
        "evidence",
    }
)
_RUNTIME_ATTESTATION_HANDOFF_FIELDS = frozenset(
    {
        "apiVersion",
        "receiptId",
        "receiptRevision",
        "receipt",
        "receiptSha256",
        "receiptPayloadSha256",
        "roleAuthorizationId",
        "roleAuthorizationRevision",
        "roleAuthorization",
        "roleAuthorizationSha256",
        "roleAuthorizationPayloadSha256",
        "evidence",
        "chainSha256",
    }
)
_PHYSICAL_WEBAUTHN_BINDING_FIELDS = frozenset(
    {
        "operation",
        "operationId",
        "requestDigest",
        "credentialRecordId",
        "credentialIdDigest",
        "grantId",
        "actorId",
        "ceremonyId",
        "challengeDigest",
        "authenticatorDataDigest",
        "clientDataDigest",
        "assertionSignatureDigest",
        "priorCounter",
        "newCounter",
        "trustGeneration",
        "trustRootDigest",
    }
)
_PHYSICAL_WEBAUTHN_STATEMENT_FIELDS = (
    _PHYSICAL_WEBAUTHN_BINDING_FIELDS
    | {
        "schema",
        "userPresent",
        "userVerified",
        "hardwareBacked",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
        "signatureDomain",
        "signatureAlgorithm",
        "signingKeyId",
        "signingKeySpkiSha256",
        "signedEvidenceDigest",
    }
)
_ACTIVATION_PUBLICATION_PAYLOAD_FIELDS = frozenset(
    {
        "assignmentEnvelopeDigest",
        "assignmentPayloadDigest",
        "assignmentRevision",
        "readinessCoreDigest",
        "authorityKeyIndependenceDigest",
        "activationTransactionDigest",
        "replacedPolicyDigest",
        "replacedPolicySequence",
        "replacedRollbackEpoch",
        "publishedPolicyDigest",
        "publishedPolicySequence",
        "publishedRollbackEpoch",
        "replacedPublicationRevision",
        "publishedPublicationRevision",
        "trustedObservedAtEpochNs",
        "trustedTimeCheckpointDigest",
        "persistenceReceiptDigest",
        "retrievalIdDigest",
        "retrievalProofDigest",
        "signingKeyId",
        "signingKeySpkiSha256",
        "signature",
        "signedReceiptDigest",
    }
)
_RUNTIME_ATTESTATION_PAYLOAD_FIELDS = frozenset(
    {
        "schemaVersion",
        "status",
        "attestationPolicySha256",
        "verifierExecutableSha256",
        "attestationMode",
        "hardwareAttested",
        "assignmentPayloadSha256",
        "loadReceiptPayloadSha256",
        "runtimeIdentitySha256",
        "runtimeAttestationReceiptSha256",
        "runtimeAttestationPayloadSha256",
        "roleAuthorizationSha256",
        "roleAuthorizationPayloadSha256",
        "attestationEvidenceId",
        "attestationEvidenceRevision",
        "teeEvidenceSha256",
        "teeMeasurementSha256",
        "runtimeExecutableSha256",
        "runtimeReleaseSha256",
        "runtimeConfigSha256",
        "runtimePolicySha256",
        "shadowSigningKeyId",
        "shadowSigningKeySpkiSha256",
        "trustCheckpointSha256",
        "revocationGeneration",
        "revocationRootSha256",
        "evidenceChainSha256",
        "trustedNowUnixNanos",
        "maximumAgeNanos",
        "issuedAtUnixNanos",
        "expiresAtUnixNanos",
    }
)


class TransitionKernelError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class QueryPredicate:
    column: str
    operator: str
    value: Any = None

    def __post_init__(self) -> None:
        if (
            not _IDENTIFIER.fullmatch(self.column)
            or self.operator not in _QUERY_OPERATORS
            or self.operator in {"is-null", "not-null"}
            and self.value is not None
        ):
            raise TransitionKernelError(
                "authority query predicate is not closed"
            )


@dataclass(frozen=True, slots=True)
class QueryOrder:
    column: str
    descending: bool = False

    def __post_init__(self) -> None:
        if (
            not _IDENTIFIER.fullmatch(self.column)
            or not isinstance(self.descending, bool)
        ):
            raise TransitionKernelError(
                "authority query ordering is not closed"
            )


@dataclass(frozen=True, slots=True)
class SelectedRowFieldReference:
    table: str
    key: Mapping[str, Any]
    column: str

    def __post_init__(self) -> None:
        if (
            not _IDENTIFIER.fullmatch(self.table)
            or not isinstance(self.key, Mapping)
            or not self.key
            or any(
                not _IDENTIFIER.fullmatch(str(column))
                for column in self.key
            )
            or not _IDENTIFIER.fullmatch(self.column)
        ):
            raise TransitionKernelError(
                "authority selected-row field reference is not closed"
            )
        canonical_bytes(dict(self.key))

    def contract_value(self) -> dict[str, Any]:
        return {
            "schema": "serverware.policyAuthoritySelectedRowField/v1",
            "table": self.table,
            "key": dict(self.key),
            "column": self.column,
        }


@dataclass(frozen=True, slots=True)
class BoundedQuery:
    query_id: str
    table: str
    predicates: tuple[QueryPredicate, ...]
    order_by: tuple[QueryOrder, ...]
    maximum_rows: int
    absent_key: Mapping[str, Any] | None = None
    require_absence: bool = False
    proof_primitive: str = "primary-key-row"
    work_units: int = 1
    exact_page: bool = False
    page_size: int | None = None
    continuation_token_digest: str | None = None
    secondary_index_name: str | None = None

    def __post_init__(self) -> None:
        exact_absence_predicates = {
            predicate.column: predicate.value
            for predicate in self.predicates
            if predicate.operator == "eq"
        }
        if (
            not isinstance(self.query_id, str)
            or not self.query_id.startswith(
                "serverware.policyAuthorityQuery/"
            )
            or not _IDENTIFIER.fullmatch(self.table)
            or not isinstance(self.predicates, tuple)
            or any(
                not isinstance(predicate, QueryPredicate)
                for predicate in self.predicates
            )
            or not isinstance(self.order_by, tuple)
            or any(
                not isinstance(item, QueryOrder)
                for item in self.order_by
            )
            or not isinstance(self.maximum_rows, int)
            or isinstance(self.maximum_rows, bool)
            or not (
                0 < self.maximum_rows
                <= authority_contract.MAX_QUERY_PROOFS
            )
            or len(self.predicates) > MAX_QUERY_PREDICATES
            or len(self.order_by) > MAX_QUERY_ORDER_COLUMNS
            or len({item.column for item in self.order_by})
                != len(self.order_by)
            or (
                self.absent_key is not None
                and (
                    not isinstance(self.absent_key, Mapping)
                    or not self.absent_key
                    or self.maximum_rows != 1
                    or exact_absence_predicates != dict(self.absent_key)
                    or len(exact_absence_predicates)
                        != len(self.predicates)
                    or any(
                        not _IDENTIFIER.fullmatch(str(column))
                        for column in self.absent_key
                    )
                )
            )
            or not isinstance(self.require_absence, bool)
            or (
                self.require_absence
                and self.absent_key is None
            )
            or self.proof_primitive not in authority_contract.PROOF_PRIMITIVES
            or self.proof_primitive == authority_complete_query.PROOF_PRIMITIVE
            or not isinstance(self.work_units, int)
            or isinstance(self.work_units, bool)
            or not 1 <= self.work_units <= authority_contract.MAX_WORK_UNITS
            or not isinstance(self.exact_page, bool)
            or self.exact_page
                and self.proof_primitive != "ordered-exact-page"
            or (
                self.proof_primitive == "bounded-limit-plus-one"
                and (
                    not isinstance(self.page_size, int)
                    or isinstance(self.page_size, bool)
                    or not 1 <= self.page_size < self.maximum_rows
                    or self.maximum_rows != self.page_size + 1
                    or (
                        self.continuation_token_digest is not None
                        and require_digest(
                            self.continuation_token_digest,
                            "bounded query continuation token",
                        )
                            != self.continuation_token_digest
                    )
                )
            )
            or (
                self.proof_primitive != "bounded-limit-plus-one"
                and (
                    self.page_size is not None
                    or self.continuation_token_digest is not None
                )
            )
            or (
                self.proof_primitive == "authenticated-secondary-index"
                and (
                    not isinstance(self.secondary_index_name, str)
                    or not _IDENTIFIER.fullmatch(
                        self.secondary_index_name
                    )
                )
            )
            or (
                self.proof_primitive != "authenticated-secondary-index"
                and self.secondary_index_name is not None
            )
        ):
            raise TransitionKernelError(
                "authority bounded query is not closed"
            )

    def contract_value(self) -> dict[str, Any]:
        return {
            "schema": QUERY_PROGRAM_SCHEMA,
            "queryId": self.query_id,
            "table": self.table,
            "predicates": [
                {
                    "column": predicate.column,
                    "operator": predicate.operator,
                    "value": (
                        predicate.value.contract_value()
                        if isinstance(
                            predicate.value,
                            SelectedRowFieldReference,
                        )
                        else predicate.value
                    ),
                }
                for predicate in self.predicates
            ],
            "orderBy": [
                {
                    "column": item.column,
                    "descending": item.descending,
                }
                for item in self.order_by
            ],
            "maximumRows": self.maximum_rows,
            "overflowDisposition": "fail-closed",
            "absentKey": (
                None if self.absent_key is None
                else {
                    column: (
                        value.contract_value()
                        if isinstance(value, SelectedRowFieldReference)
                        else value
                    )
                    for column, value in self.absent_key.items()
                }
            ),
            "requireAbsence": self.require_absence,
            "proofPrimitive": self.proof_primitive,
            "workUnits": self.work_units,
            "exactPage": self.exact_page,
            "pageSize": self.page_size,
            "continuationTokenDigest": self.continuation_token_digest,
            "secondaryIndexName": self.secondary_index_name,
        }


# Complete index declarations deliberately have no SQL-predicate/page fields.
# The legacy BoundedQuery wire projection above remains byte-for-byte v1.
Query = BoundedQuery | authority_complete_query.CompleteIndexQuery


@dataclass(frozen=True, slots=True)
class KernelTransition:
    mutations: tuple[dict[str, Any], ...]
    result: Any
    work_units: int = 1

    def __post_init__(self) -> None:
        if (
            not isinstance(self.mutations, tuple)
            or any(
                not isinstance(entry, Mapping)
                for entry in self.mutations
            )
            or not isinstance(self.work_units, int)
            or isinstance(self.work_units, bool)
            or not 1 <= self.work_units <= authority_contract.MAX_WORK_UNITS
        ):
            raise TransitionKernelError(
                "authority transition result is not bounded"
            )
        canonical_bytes(self.result)


@dataclass(frozen=True, slots=True)
class KernelContext:
    operation: str
    arguments: Mapping[str, Any]
    selected_rows: tuple[dict[str, Any], ...]
    database_now: datetime
    request_digest: str
    verified_webauthn_evidence: Mapping[str, Any] | None = None
    query_reads: tuple[authority_query_reads.QueryRead, ...] = ()
    # Only the RBAC source program receives these actual admitted originals;
    # they are not arguments or an independently current authority token.
    rbac_primary_inputs: tuple | None = None

    def observed_query_rows(self, *, query_id: str) -> tuple[dict[str, Any], ...]:
        """Return the retained ordered SQL observation, not completeness proof.

        Global selector metadata is preserved. Neither an empty result nor this
        accessor supplies indexed range, checkpoint or currentness authority.
        """
        try:
            return authority_query_reads.query_rows(
                self.operation, query_reads=self.query_reads,
                selected_rows=self.selected_rows, query_id=query_id,
            )
        except authority_query_reads.QueryReadError as exc:
            raise TransitionKernelError("retained query observation is invalid") from exc

    def rows(self, table: str) -> tuple[dict[str, Any], ...]:
        return tuple(
            selected
            for selected in self.selected_rows
            if selected.get("table") == table
        )

    def present_rows(self, table: str) -> tuple[dict[str, Any], ...]:
        return tuple(
            selected
            for selected in self.rows(table)
            if selected.get("present") is True
        )

    def limit_plus_one_rows(
        self,
        *,
        table: str,
        page_size: int,
        order_columns: tuple[str, ...],
    ) -> tuple[tuple[dict[str, Any], ...], str | None]:
        _require_manifest_primitive(
            self.operation,
            "bounded-limit-plus-one",
        )
        page_size = require_integer(
            page_size,
            "bounded page size",
            minimum=1,
            maximum=authority_contract.MAX_QUERY_PROOFS - 1,
        )
        if (
            not isinstance(order_columns, tuple)
            or not order_columns
            or len(set(order_columns)) != len(order_columns)
            or any(
                not isinstance(column, str)
                or not _IDENTIFIER.fullmatch(column)
                for column in order_columns
            )
        ):
            raise TransitionKernelError(
                "bounded page ordering is not closed"
            )
        rows = self.present_rows(table)
        if len(rows) > page_size + 1:
            raise TransitionKernelError(
                "bounded page escaped its limit-plus-one proof"
            )
        for selected in rows:
            row = selected.get("row")
            if (
                not isinstance(row, Mapping)
                or any(column not in row for column in order_columns)
            ):
                raise TransitionKernelError(
                    "bounded page row has no exact ordering value"
                )
        ordered = tuple(
            sorted(
                rows,
                key=lambda selected: canonical_bytes(
                    {
                        "order": [
                            selected["row"][column]
                            for column in order_columns
                        ],
                        "keyDigest": selected["keyDigest"],
                    }
                ),
            )
        )
        page = ordered[:page_size]
        continuation = (
            None
            if len(ordered) <= page_size
            else framed_digest(
                "serverware.policyAuthorityContinuation/v1",
                self.operation.encode("ascii"),
                table.encode("ascii"),
                self.request_digest.encode("ascii"),
                canonical_bytes(
                    {
                        "order": [
                            ordered[page_size]["row"][column]
                            for column in order_columns
                        ],
                        "key": ordered[page_size]["key"],
                        "keyDigest": ordered[page_size]["keyDigest"],
                    }
                ),
            )
        )
        return page, continuation

    def secondary_index_head(
        self,
        *,
        index_id: str,
        relation_name: str,
        index_name: str,
        key_columns: tuple[str, ...],
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "authenticated-secondary-index",
        )
        require_text(
            index_id,
            "secondary index identity",
            maximum_bytes=256,
        )
        if (
            not _IDENTIFIER.fullmatch(relation_name)
            or not _IDENTIFIER.fullmatch(index_name)
            or not isinstance(key_columns, tuple)
            or not key_columns
            or len(set(key_columns)) != len(key_columns)
            or any(
                not isinstance(column, str)
                or not _IDENTIFIER.fullmatch(column)
                for column in key_columns
            )
        ):
            raise TransitionKernelError(
                "secondary index contract is not closed"
            )
        selected = self.exact(
            "policy_authority_secondary_index_heads",
            {"index_id": index_id},
        )
        row = _selected_row(selected, "secondary index head")
        key_columns_json = canonical_bytes(
            list(key_columns)
        ).decode("ascii")
        high_water_key_json = row.get("high_water_key_json")
        high_water_key_digest = row.get("high_water_key_digest")
        if (
            row.get("relation_name") != relation_name
            or row.get("index_name") != index_name
            or row.get("key_columns_json") != key_columns_json
            or row.get("key_columns_digest")
                != framed_digest(
                    "serverware.policyAuthoritySecondaryIndexColumns/v1",
                    key_columns_json.encode("ascii"),
                )
            or require_digest(
                row.get("root_digest"),
                "secondary index root",
            )
                != row.get("root_digest")
            or not isinstance(row.get("revision"), int)
            or isinstance(row.get("revision"), bool)
            or row.get("revision") < 1
            or not isinstance(row.get("row_count"), int)
            or isinstance(row.get("row_count"), bool)
            or row.get("row_count") < 0
            or (
                high_water_key_json is None
                and high_water_key_digest is not None
            )
            or (
                high_water_key_json is not None
                and (
                    _canonical_json_text(
                        high_water_key_json,
                        "secondary index high-water key",
                    )
                    is None
                    or require_digest(
                        high_water_key_digest,
                        "secondary index high-water key digest",
                    )
                        != framed_digest(
                            (
                                "serverware."
                                "policyAuthoritySecondaryIndexHighWater/v1"
                            ),
                            high_water_key_json.encode("ascii"),
                        )
                )
            )
            or not isinstance(row.get("updated_at_epoch_ns"), int)
            or isinstance(row.get("updated_at_epoch_ns"), bool)
            or not 0
                <= row["updated_at_epoch_ns"]
                <= _epoch_nanoseconds(self.database_now)
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
        ):
            raise TransitionKernelError(
                "secondary index head is not authoritative"
            )
        return row

    def continuation(
        self,
        *,
        continuation_digest: str,
        operation_id: str,
        page_kind: str,
        status: str = "pending",
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "bounded-limit-plus-one",
        )
        require_digest(
            continuation_digest,
            "continuation digest",
        )
        require_text(
            operation_id,
            "continuation operation identity",
            maximum_bytes=256,
        )
        require_text(
            page_kind,
            "continuation page kind",
            maximum_bytes=128,
        )
        if status not in {"pending", "completed", "cancelled"}:
            raise TransitionKernelError(
                "continuation status is not closed"
            )
        selected = self.exact(
            "policy_authority_continuations",
            {"continuation_digest": continuation_digest},
        )
        row = _selected_row(selected, "continuation")
        if (
            row.get("operation") != self.operation
            or row.get("operation_id") != operation_id
            or row.get("request_digest") != self.request_digest
            or row.get("page_kind") != page_kind
            or row.get("status") != status
            or not isinstance(row.get("page_ordinal"), int)
            or isinstance(row.get("page_ordinal"), bool)
            or row.get("page_ordinal") < 1
            or require_digest(
                row.get("source_root_digest"),
                "continuation source root",
            )
                != row.get("source_root_digest")
            or not isinstance(row.get("source_revision_number"), int)
            or isinstance(row.get("source_revision_number"), bool)
            or row.get("source_revision_number") < 1
            or _canonical_json_text(
                row.get("next_key_json"),
                "continuation next key",
                require_mapping=True,
            )
                is None
            or require_digest(
                row.get("next_key_digest"),
                "continuation next key digest",
            )
                != framed_digest(
                    "serverware.policyAuthorityContinuationKey/v1",
                    row["next_key_json"].encode("ascii"),
                )
            or require_digest(
                row.get("accumulated_state_digest"),
                "continuation accumulated state",
            )
                != row.get("accumulated_state_digest")
            or not isinstance(row.get("created_at_epoch_ns"), int)
            or isinstance(row.get("created_at_epoch_ns"), bool)
            or not isinstance(row.get("expires_at_epoch_ns"), int)
            or isinstance(row.get("expires_at_epoch_ns"), bool)
            or not row["created_at_epoch_ns"]
                <= _epoch_nanoseconds(self.database_now)
                < row["expires_at_epoch_ns"]
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
        ):
            raise TransitionKernelError(
                "continuation is not currently authoritative"
            )
        return row

    def exact(
        self,
        table: str,
        key: Mapping[str, Any],
    ) -> dict[str, Any]:
        return self._exact(table, key, work=None)

    def _exact(
        self, table: str, key: Mapping[str, Any], *, work: _ValidationWork | None,
    ) -> dict[str, Any]:
        if work is not None:
            if type(work) is not _ValidationWork:
                raise TransitionKernelError("authority exact selection requires the shared work meter")
            work.prepare_copy(self.selected_rows)
        candidates = self.rows(table)
        if work is not None:
            work.prepare_copy(candidates)

        def matches_key(selected: Mapping[str, Any]) -> bool:
            if work is not None:
                # dict(key) is genuinely constructed for every candidate,
                # including nonmatches; do not hoist it or change == dispatch.
                work.prepare_copy(key)
                work.prepare_comparison(selected.get("key"), key)
            return selected.get("key") == dict(key)

        matches = tuple(
            selected
            for selected in candidates
            if matches_key(selected)
        )
        if len(matches) != 1:
            raise TransitionKernelError(
                "authority transition exact row is absent or ambiguous"
            )
        return matches[0]

    def _evidence(
        self,
        *,
        evidence_type: str,
        evidence_digest: str,
        binding_digest: str,
        expected_status: str,
        consumed_operation_id: str | None,
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "external-evidence-receipt",
        )
        if evidence_type not in authority_contract.operation_spec(
            self.operation
        )["externalEvidenceTypes"]:
            raise TransitionKernelError(
                "external evidence type escaped the operation manifest"
            )
        require_text(
            evidence_type,
            "external evidence type",
            maximum_bytes=128,
        )
        require_digest(evidence_digest, "external evidence digest")
        require_digest(binding_digest, "external evidence binding digest")
        selected = self.exact(
            "policy_authority_external_evidence_receipts",
            {"evidence_digest": evidence_digest},
        )
        row = _selected_row(selected, "external evidence")
        statement = _canonical_json_text(
            row.get("statement_json"),
            "external evidence statement",
            require_mapping=True,
        )
        statement_digest = framed_digest(
            "serverware.policyAuthorityExternalEvidenceStatement/v1",
            canonical_bytes(statement),
        )
        signature_algorithm = require_text(
            row.get("signature_algorithm"),
            "external evidence signature algorithm",
            maximum_bytes=128,
        )
        signature_base64url = _require_base64url(
            row.get("signature_base64url"),
            "external evidence signature",
            maximum_bytes=4 * 1024 * 1024,
        )
        signature_digest = framed_digest(
            "serverware.policyAuthorityExternalEvidenceSignature/v1",
            signature_algorithm.encode("utf-8"),
            signature_base64url.encode("ascii"),
        )
        verified_at_epoch_ns = row.get("verified_at_epoch_ns")
        expires_at_epoch_ns = row.get("expires_at_epoch_ns")
        receipt_material = {
            "schema":
                "serverware.policyAuthorityExternalEvidenceReceipt/v1",
            "bindingDigest": binding_digest,
            "evidenceType": evidence_type,
            "expiresAtEpochNs": expires_at_epoch_ns,
            "signatureAlgorithm": signature_algorithm,
            "signatureDigest": signature_digest,
            "sourceRevision": authority_contract.SOURCE_REVISION,
            "statementDigest": statement_digest,
            "verifiedAtEpochNs": verified_at_epoch_ns,
            "verifierAttestationReceiptDigest":
                row.get("verifier_attestation_receipt_digest"),
            "verifierIdentityDigest":
                row.get("verifier_identity_digest"),
            "verifierMeasurementDigest":
                row.get("verifier_measurement_digest"),
        }
        if (
            row.get("evidence_type") != evidence_type
            or row.get("binding_digest") != binding_digest
            or signature_algorithm != "Ed25519"
            or row.get("statement_digest") != statement_digest
            or row.get("signature_digest") != signature_digest
            or require_digest(
                row.get("verifier_identity_digest"),
                "external evidence verifier identity",
            )
                != row.get("verifier_identity_digest")
            or require_digest(
                row.get("verifier_measurement_digest"),
                "external evidence verifier measurement",
            )
                != row.get("verifier_measurement_digest")
            or require_digest(
                row.get("verifier_attestation_receipt_digest"),
                "external evidence verifier attestation",
            )
                != row.get("verifier_attestation_receipt_digest")
            or evidence_digest
                != framed_digest(
                    "serverware.policyAuthorityExternalEvidenceReceipt/v1",
                    canonical_bytes(receipt_material),
                )
            or row.get("status") != expected_status
            or not isinstance(verified_at_epoch_ns, int)
            or isinstance(verified_at_epoch_ns, bool)
            or not isinstance(expires_at_epoch_ns, int)
            or isinstance(expires_at_epoch_ns, bool)
            or not verified_at_epoch_ns
                <= _epoch_nanoseconds(self.database_now)
                < expires_at_epoch_ns
            or (
                expected_status == "verified"
                and (
                    row.get("consumed_operation_id") is not None
                    or row.get("consumed_at_epoch_ns") is not None
                )
            )
            or (
                expected_status == "consumed"
                and (
                    row.get("consumed_operation_id")
                        != consumed_operation_id
                    or not isinstance(
                        row.get("consumed_at_epoch_ns"),
                        int,
                    )
                    or isinstance(
                        row.get("consumed_at_epoch_ns"),
                        bool,
                    )
                    or not verified_at_epoch_ns
                        <= row.get("consumed_at_epoch_ns")
                        <= _epoch_nanoseconds(self.database_now)
                )
            )
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
        ):
            raise TransitionKernelError(
                "external evidence receipt is not currently authoritative"
            )
        return row

    def evidence(
        self,
        *,
        evidence_type: str,
        evidence_digest: str,
        binding_digest: str,
    ) -> dict[str, Any]:
        return self._evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
            expected_status="verified",
            consumed_operation_id=None,
        )

    def consumed_evidence(
        self,
        *,
        evidence_type: str,
        evidence_digest: str,
        binding_digest: str,
        consumed_operation_id: str,
    ) -> dict[str, Any]:
        require_text(
            consumed_operation_id,
            "external evidence consuming operation",
            maximum_bytes=256,
        )
        return self._evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
            expected_status="consumed",
            consumed_operation_id=consumed_operation_id,
        )

    def consume_evidence(
        self,
        *,
        evidence_type: str,
        evidence_digest: str,
        binding_digest: str,
        operation_id: str,
    ) -> dict[str, Any]:
        row = self.evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
        )
        require_text(
            operation_id,
            "external evidence consuming operation",
            maximum_bytes=256,
        )
        selected = self.exact(
            "policy_authority_external_evidence_receipts",
            {"evidence_digest": evidence_digest},
        )
        return mutation(
            operation=self.operation,
            selected=selected,
            row={
                **row,
                "status": "consumed",
                "consumed_operation_id": operation_id,
                "consumed_at_epoch_ns":
                    _epoch_nanoseconds(self.database_now),
            },
        )

    def decision_gate_publication_evidence(
        self,
        *,
        evidence_digest: str,
        expected_binding: Mapping[str, Any],
        consumed_operation_id: str | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(expected_binding, Mapping)
            or set(expected_binding)
                != _DECISION_GATE_PUBLICATION_BINDING_FIELDS
        ):
            raise TransitionKernelError(
                "decision-gate publication binding is not exact"
            )
        binding = dict(expected_binding)
        binding_digest = framed_digest(
            "serverware.policyAuthorityDecisionGatePublicationBinding/v1",
            canonical_bytes(binding),
        )
        row = (
            self.evidence(
                evidence_type="decision-gate-publication-chain/v1",
                evidence_digest=evidence_digest,
                binding_digest=binding_digest,
            )
            if consumed_operation_id is None
            else self.consumed_evidence(
                evidence_type="decision-gate-publication-chain/v1",
                evidence_digest=evidence_digest,
                binding_digest=binding_digest,
                consumed_operation_id=consumed_operation_id,
            )
        )
        statement = _canonical_json_text(
            row.get("statement_json"),
            "decision-gate publication statement",
            require_mapping=True,
        )
        if (
            set(statement)
                != _DECISION_GATE_PUBLICATION_STATEMENT_FIELDS
            or statement.get("schema")
                != (
                    "serverware."
                    "policyAuthorityDecisionGatePublicationChain/v1"
                )
            or any(
                statement.get(field) != value
                for field, value in binding.items()
            )
        ):
            raise TransitionKernelError(
                "decision-gate publication statement diverged"
            )
        for field in (
            "generationId",
            "predecessorGenerationDigest",
            "assignmentEnvelopeDigest",
            "assignmentPayloadDigest",
            "loadReceiptEnvelopeDigest",
            "loadReceiptPayloadDigest",
            "custodyPreparationReceiptDigest",
            "custodyPublicationReceiptDigest",
            "activationPublicationReceiptDigest",
            "ingressEvidenceChainDigest",
            "ingressHighWaterDigest",
            "ingressRangePredecessorHeadDigest",
            "activePolicyDigest",
            "activeCompiledSnapshotDigest",
            "candidatePolicyDigest",
            "candidateCompiledSnapshotDigest",
            "policyHighWaterBeforeDigest",
            "policyHighWaterAfterDigest",
            "readinessCoreDigest",
            "authorityKeyIndependenceDigest",
            "activationTransactionDigest",
            "runtimeExecutableDigest",
            "runtimeReleaseAttestationDigest",
            "runtimePolicyAttestationDigest",
            "runtimeConfigAttestationDigest",
            "runtimeTeeEvidenceDigest",
            "runtimeTeeMeasurementDigest",
            "runtimeAttestationReceiptDigest",
            "runtimeEvidenceChainDigest",
            "bootIdDigest",
            "trustCheckpointDigest",
            "trustRevocationRootDigest",
            "persistenceReceiptDigest",
            "retrievalIdDigest",
            "retrievalProofDigest",
            "authoritativeLedgerHeadDigest",
            "authoritativeSpoolRootDigest",
            "generationPublicationEnvelopeDigest",
            "activationPublicationEnvelopeDigest",
            "runtimeAttestationVerifierEnvelopeDigest",
            "evidenceChainDigest",
        ):
            require_digest(
                statement.get(field),
                f"decision-gate publication {field}",
            )
        for field in (
            "generationEpoch",
            "generationTombstoneEpoch",
            "assignmentRevision",
            "ingressRangeStartSequence",
            "ingressRangeEndSequence",
            "activePolicySequence",
            "candidatePolicySequence",
            "publicationRevision",
            "trustRevocationGeneration",
            "authoritativeLedgerEventOrdinal",
        ):
            require_integer(
                statement.get(field),
                f"decision-gate publication {field}",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
        for field in (
            "activeRollbackEpoch",
            "candidateRollbackEpoch",
            "issuedAtEpochNs",
        ):
            require_integer(
                statement.get(field),
                f"decision-gate publication {field}",
                minimum=0,
                maximum=_SIGNED_BIGINT_MAX,
            )
        expires_at_epoch_ns = require_integer(
            statement.get("expiresAtEpochNs"),
            "decision-gate publication expiry",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        issued_at_epoch_ns = int(statement["issuedAtEpochNs"])
        require_text(
            statement.get("publicationRequestId"),
            "decision-gate publication request identity",
            maximum_bytes=256,
        )
        require_text(
            statement.get("replayId"),
            "decision-gate publication replay identity",
            maximum_bytes=256,
        )
        require_text(
            statement.get("instanceId"),
            "decision-gate publication instance identity",
            maximum_bytes=256,
        )
        activation_mode = statement.get("activationMode")
        if (
            activation_mode not in {"forward", "authorized-rollback"}
            or activation_mode == "forward"
            and (
                statement["candidatePolicySequence"]
                    <= statement["activePolicySequence"]
                or statement["candidateRollbackEpoch"]
                    != statement["activeRollbackEpoch"]
            )
            or activation_mode == "authorized-rollback"
            and statement["candidateRollbackEpoch"]
                <= statement["activeRollbackEpoch"]
            or statement["generationTombstoneEpoch"]
                > statement["generationEpoch"]
            or statement["ingressRangeEndSequence"]
                < statement["ingressRangeStartSequence"]
            or not issued_at_epoch_ns
                <= int(row["verified_at_epoch_ns"])
                <= _epoch_nanoseconds(self.database_now)
                < expires_at_epoch_ns
            or int(row["expires_at_epoch_ns"]) > expires_at_epoch_ns
        ):
            raise TransitionKernelError(
                "decision-gate publication bounds are invalid"
            )
        generation, generation_envelope_digest = (
            _validate_signed_envelope(
                statement.get("generationPublicationEnvelope"),
                label="decision-gate generation publication",
                api_version=(
                    "serverware."
                    "policyShadowGenerationPublication/v2"
                ),
                kind="PolicyShadowGenerationPublication",
                signing_domain=(
                    "serverware."
                    "policyShadowGenerationPublication/v2"
                ),
                payload_fields=
                    _GENERATION_PUBLICATION_PAYLOAD_FIELDS,
            )
        )
        activation, activation_envelope_digest = (
            _validate_activation_publication_receipt(
                statement.get("activationPublicationEnvelope")
            )
        )
        runtime, runtime_envelope_digest = _validate_signed_envelope(
            statement.get("runtimeAttestationVerifierEnvelope"),
            label="decision-gate runtime attestation verifier",
            api_version=(
                "serverware."
                "policyShadowRuntimeAttestationVerification/v2"
            ),
            kind="PolicyShadowRuntimeAttestationVerification",
            signing_domain=(
                "serverware."
                "policyShadowRuntimeAttestationVerification/v2"
            ),
            payload_fields=_RUNTIME_ATTESTATION_PAYLOAD_FIELDS,
        )
        (
            publication_request,
            publication_generation,
            publication_custody,
            publication_runtime,
            publication_trust,
            publication_attestation,
        ) = _validate_generation_publication_payload(generation)
        embedded_runtime = publication_attestation[
            "runtimeAttestationVerification"
        ]
        if (
            canonical_bytes(embedded_runtime)
                != canonical_bytes(
                    statement.get("runtimeAttestationVerifierEnvelope")
                )
            or publication_attestation[
                "runtimeAttestationVerificationEnvelopeSha256"
            ] != runtime_envelope_digest
        ):
            raise TransitionKernelError(
                "embedded runtime attestation envelope diverged"
            )
        _validate_runtime_attestation_payload(runtime)
        if (
            publication_request.get("requestId")
                != statement["publicationRequestId"]
            or publication_request.get("replayId")
                != statement["replayId"]
            or publication_generation.get("generationId")
                != statement["generationId"]
            or publication_generation.get("generationEpoch")
                != statement["generationEpoch"]
            or publication_generation.get("generationTombstoneEpoch")
                != statement["generationTombstoneEpoch"]
            or publication_generation.get("assignmentEnvelopeSha256")
                != statement["assignmentEnvelopeDigest"]
            or publication_generation.get("assignmentPayloadSha256")
                != statement["assignmentPayloadDigest"]
            or publication_generation.get("assignmentRevision")
                != statement["assignmentRevision"]
            or publication_generation.get("loadReceiptEnvelopeSha256")
                != statement["loadReceiptEnvelopeDigest"]
            or publication_generation.get("loadReceiptPayloadSha256")
                != statement["loadReceiptPayloadDigest"]
            or publication_generation.get("runtimeBootIdSha256")
                != statement["bootIdDigest"]
            or publication_generation.get("ingressRangeStartSequence")
                != statement["ingressRangeStartSequence"]
            or publication_generation.get(
                "ingressRangePredecessorHeadSha256"
            ) != statement["ingressRangePredecessorHeadDigest"]
            or publication_generation.get("signedPublicationRevision")
                != statement["publicationRevision"]
            or publication_generation["active"].get("policySha256")
                != statement["activePolicyDigest"]
            or publication_generation["active"].get("policySequence")
                != statement["activePolicySequence"]
            or publication_generation["active"].get("rollbackEpoch")
                != statement["activeRollbackEpoch"]
            or publication_generation["active"].get(
                "compiledSnapshotSha256"
            ) != statement["activeCompiledSnapshotDigest"]
            or publication_generation["candidate"].get("policySha256")
                != statement["candidatePolicyDigest"]
            or publication_generation["candidate"].get("policySequence")
                != statement["candidatePolicySequence"]
            or publication_generation["candidate"].get("rollbackEpoch")
                != statement["candidateRollbackEpoch"]
            or publication_generation["candidate"].get(
                "compiledSnapshotSha256"
            ) != statement["candidateCompiledSnapshotDigest"]
            or publication_custody.get("publicationRevision")
                != statement["publicationRevision"]
            or publication_custody.get("preparationReceiptSha256")
                != statement["custodyPreparationReceiptDigest"]
            or publication_custody.get("publicationReceiptSha256")
                != statement["custodyPublicationReceiptDigest"]
            or publication_custody.get(
                "authoritativeLedgerEventOrdinal"
            )
                != statement["authoritativeLedgerEventOrdinal"]
            or publication_custody.get(
                "authoritativeLedgerHeadSha256"
            )
                != statement["authoritativeLedgerHeadDigest"]
            or publication_custody.get(
                "authoritativeSpoolRootSha256"
            )
                != statement["authoritativeSpoolRootDigest"]
            or publication_runtime.get("decisionGateExecutableSha256")
                != statement["runtimeExecutableDigest"]
            or publication_runtime.get("releaseProvenanceSha256")
                != statement["runtimeReleaseAttestationDigest"]
            or publication_runtime.get("runtimeConfigurationSha256")
                != statement["runtimeConfigAttestationDigest"]
            or publication_runtime.get("runtimePolicySha256")
                != statement["runtimePolicyAttestationDigest"]
            or publication_runtime.get("runtimeInstanceId")
                != statement["instanceId"]
            or publication_runtime.get("runtimeBootIdSha256")
                != statement["bootIdDigest"]
            or publication_runtime.get("runtimeTeeMeasurementSha256")
                != statement["runtimeTeeMeasurementDigest"]
            or publication_trust.get("trustCheckpointSha256")
                != statement["trustCheckpointDigest"]
            or publication_trust.get("revocationGeneration")
                != statement["trustRevocationGeneration"]
            or publication_trust.get("revocationRootSha256")
                != statement["trustRevocationRootDigest"]
            or activation.get("assignmentEnvelopeDigest")
                != statement["assignmentEnvelopeDigest"]
            or activation.get("assignmentPayloadDigest")
                != statement["assignmentPayloadDigest"]
            or activation.get("assignmentRevision")
                != statement["assignmentRevision"]
            or activation.get("readinessCoreDigest")
                != statement["readinessCoreDigest"]
            or activation.get("authorityKeyIndependenceDigest")
                != statement["authorityKeyIndependenceDigest"]
            or activation.get("activationTransactionDigest")
                != statement["activationTransactionDigest"]
            or activation.get("replacedPolicyDigest")
                != statement["activePolicyDigest"]
            or activation.get("replacedPolicySequence")
                != statement["activePolicySequence"]
            or activation.get("replacedRollbackEpoch")
                != statement["activeRollbackEpoch"]
            or activation.get("publishedPolicyDigest")
                != statement["candidatePolicyDigest"]
            or activation.get("publishedPolicySequence")
                != statement["candidatePolicySequence"]
            or activation.get("publishedRollbackEpoch")
                != statement["candidateRollbackEpoch"]
            or activation.get("publishedPublicationRevision")
                != statement["publicationRevision"]
            or activation.get("trustedTimeCheckpointDigest")
                != statement["trustCheckpointDigest"]
            or activation.get("persistenceReceiptDigest")
                != statement["persistenceReceiptDigest"]
            or activation.get("retrievalIdDigest")
                != statement["retrievalIdDigest"]
            or activation.get("retrievalProofDigest")
                != statement["retrievalProofDigest"]
            or activation.get("signedReceiptDigest")
                != statement["activationPublicationReceiptDigest"]
            or runtime.get("assignmentPayloadSha256")
                != statement["assignmentPayloadDigest"]
            or runtime.get("loadReceiptPayloadSha256")
                != statement["loadReceiptPayloadDigest"]
            or runtime.get("teeEvidenceSha256")
                != statement["runtimeTeeEvidenceDigest"]
            or runtime.get("teeMeasurementSha256")
                != statement["runtimeTeeMeasurementDigest"]
            or runtime.get("runtimeExecutableSha256")
                != statement["runtimeExecutableDigest"]
            or runtime.get("runtimeReleaseSha256")
                != statement["runtimeReleaseAttestationDigest"]
            or runtime.get("runtimeConfigSha256")
                != statement["runtimeConfigAttestationDigest"]
            or runtime.get("runtimePolicySha256")
                != statement["runtimePolicyAttestationDigest"]
            or runtime.get("runtimeAttestationReceiptSha256")
                != statement["runtimeAttestationReceiptDigest"]
            or runtime.get("evidenceChainSha256")
                != statement["runtimeEvidenceChainDigest"]
            or runtime.get("trustCheckpointSha256")
                != statement["trustCheckpointDigest"]
            or runtime.get("revocationGeneration")
                != statement["trustRevocationGeneration"]
            or runtime.get("revocationRootSha256")
                != statement["trustRevocationRootDigest"]
            or statement["generationPublicationEnvelopeDigest"]
                != generation_envelope_digest
            or statement["activationPublicationEnvelopeDigest"]
                != activation_envelope_digest
            or statement["runtimeAttestationVerifierEnvelopeDigest"]
                != runtime_envelope_digest
            or statement["evidenceChainDigest"]
                != framed_digest(
                    "serverware.policyAuthorityDecisionGateEvidenceChain/v1",
                    canonical_bytes(
                        {
                            **binding,
                            "expiresAtEpochNs": expires_at_epoch_ns,
                            "issuedAtEpochNs": issued_at_epoch_ns,
                        }
                    ),
                    generation_envelope_digest.encode("ascii"),
                    activation_envelope_digest.encode("ascii"),
                    runtime_envelope_digest.encode("ascii"),
                )
            or any(
                not issued_at_epoch_ns
                    <= payload["issuedAtUnixNanos"]
                    < payload["expiresAtUnixNanos"]
                    <= expires_at_epoch_ns
                for payload in (generation, runtime)
            )
            or not issued_at_epoch_ns
                <= activation["trustedObservedAtEpochNs"]
                < expires_at_epoch_ns
        ):
            raise TransitionKernelError(
                "decision-gate publication evidence chain diverged"
            )
        return row

    def consume_decision_gate_publication_evidence(
        self,
        *,
        evidence_digest: str,
        expected_binding: Mapping[str, Any],
        operation_id: str,
    ) -> dict[str, Any]:
        self.decision_gate_publication_evidence(
            evidence_digest=evidence_digest,
            expected_binding=expected_binding,
        )
        return self.consume_evidence(
            evidence_type="decision-gate-publication-chain/v1",
            evidence_digest=evidence_digest,
            binding_digest=framed_digest(
                (
                    "serverware."
                    "policyAuthorityDecisionGatePublicationBinding/v1"
                ),
                canonical_bytes(dict(expected_binding)),
            ),
            operation_id=operation_id,
        )

    def consumed_decision_gate_publication_evidence(
        self,
        *,
        evidence_digest: str,
        expected_binding: Mapping[str, Any],
        consumed_operation_id: str,
    ) -> dict[str, Any]:
        return self.decision_gate_publication_evidence(
            evidence_digest=evidence_digest,
            expected_binding=expected_binding,
            consumed_operation_id=consumed_operation_id,
        )

    def physical_webauthn_evidence(
        self,
        *,
        evidence_digest: str,
        expected_binding: Mapping[str, Any],
        consumed_operation_id: str | None = None,
    ) -> dict[str, Any]:
        if (
            not isinstance(expected_binding, Mapping)
            or set(expected_binding) != _PHYSICAL_WEBAUTHN_BINDING_FIELDS
        ):
            raise TransitionKernelError(
                "physical WebAuthn binding is not exact"
            )
        binding = dict(expected_binding)
        binding_digest = framed_digest(
            "serverware.policyAuthorityPhysicalWebAuthnBinding/v1",
            canonical_bytes(binding),
        )
        row = (
            self.evidence(
                evidence_type="webauthn-hardware-authorization/v1",
                evidence_digest=evidence_digest,
                binding_digest=binding_digest,
            )
            if consumed_operation_id is None
            else self.consumed_evidence(
                evidence_type="webauthn-hardware-authorization/v1",
                evidence_digest=evidence_digest,
                binding_digest=binding_digest,
                consumed_operation_id=consumed_operation_id,
            )
        )
        statement = _canonical_json_text(
            row.get("statement_json"),
            "physical WebAuthn statement",
            require_mapping=True,
        )
        if (
            set(statement) != _PHYSICAL_WEBAUTHN_STATEMENT_FIELDS
            or statement.get("schema")
                != "serverware.policyAuthorityPhysicalWebAuthn/v1"
            or any(
                statement.get(field) != value
                for field, value in binding.items()
            )
            or statement.get("userPresent") is not True
            or statement.get("userVerified") is not True
            or statement.get("hardwareBacked") is not True
            or statement.get("signatureDomain")
                != "serverware.policyAuthorityPhysicalWebAuthn/v1"
            or statement.get("signatureAlgorithm") != "Ed25519"
        ):
            raise TransitionKernelError(
                "physical WebAuthn statement diverged"
            )
        for field in (
            "requestDigest",
            "credentialIdDigest",
            "challengeDigest",
            "authenticatorDataDigest",
            "clientDataDigest",
            "assertionSignatureDigest",
            "trustRootDigest",
            "signingKeyId",
            "signingKeySpkiSha256",
            "signedEvidenceDigest",
        ):
            require_digest(
                statement.get(field),
                f"physical WebAuthn {field}",
            )
        for field in (
            "priorCounter",
            "newCounter",
            "trustGeneration",
            "issuedAtEpochNs",
            "expiresAtEpochNs",
        ):
            require_integer(
                statement.get(field),
                f"physical WebAuthn {field}",
                minimum=0,
                maximum=_SIGNED_BIGINT_MAX,
            )
        if (
            statement["newCounter"] <= statement["priorCounter"]
            or not statement["issuedAtEpochNs"]
                <= int(row["verified_at_epoch_ns"])
                <= _epoch_nanoseconds(self.database_now)
                < statement["expiresAtEpochNs"]
            or statement["signedEvidenceDigest"]
                != framed_digest(
                    "serverware.policyAuthorityPhysicalWebAuthn/v1",
                    canonical_bytes(
                        {
                            **binding,
                            "expiresAtEpochNs":
                                statement["expiresAtEpochNs"],
                            "hardwareBacked": True,
                            "issuedAtEpochNs":
                                statement["issuedAtEpochNs"],
                            "signatureAlgorithm": "Ed25519",
                            "signatureDomain":
                                statement["signatureDomain"],
                            "signingKeyId": statement["signingKeyId"],
                            "signingKeySpkiSha256":
                                statement["signingKeySpkiSha256"],
                            "userPresent": True,
                            "userVerified": True,
                        }
                    ),
                )
        ):
            raise TransitionKernelError(
                "physical WebAuthn evidence is stale or replayable"
            )
        return row

    def consume_physical_webauthn_evidence(
        self,
        *,
        evidence_digest: str,
        expected_binding: Mapping[str, Any],
        operation_id: str,
    ) -> dict[str, Any]:
        self.physical_webauthn_evidence(
            evidence_digest=evidence_digest,
            expected_binding=expected_binding,
        )
        return self.consume_evidence(
            evidence_type="webauthn-hardware-authorization/v1",
            evidence_digest=evidence_digest,
            binding_digest=framed_digest(
                "serverware.policyAuthorityPhysicalWebAuthnBinding/v1",
                canonical_bytes(dict(expected_binding)),
            ),
            operation_id=operation_id,
        )

    def opaque_value(
        self,
        *,
        value_kind: str,
        opaque_id: str,
        binding_digest: str,
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "opaque-value-receipt",
        )
        if value_kind not in authority_contract.operation_spec(
            self.operation
        )["opaqueValueKinds"]:
            raise TransitionKernelError(
                "opaque value kind escaped the operation manifest"
            )
        require_text(value_kind, "opaque value kind", maximum_bytes=128)
        require_text(opaque_id, "opaque value identity", maximum_bytes=256)
        require_digest(binding_digest, "opaque value binding digest")
        selected = self.exact(
            "policy_authority_opaque_values",
            {"opaque_id": opaque_id},
        )
        row = _selected_row(selected, "opaque value")
        algorithm = require_text(
            row.get("algorithm"),
            "opaque value algorithm",
            maximum_bytes=128,
        )
        key_id = require_text(
            row.get("key_id"),
            "opaque value key identity",
            maximum_bytes=256,
        )
        ciphertext_base64url = _require_base64url(
            row.get("ciphertext_base64url"),
            "opaque value ciphertext",
            maximum_bytes=4 * 1024 * 1024,
        )
        expires_at_epoch_ns = row.get("expires_at_epoch_ns")
        created_at_epoch_ns = row.get("created_at_epoch_ns")
        producer_evidence_digest = require_digest(
            row.get("producer_evidence_digest"),
            "opaque value producer evidence",
        )
        if (
            row.get("value_kind") != value_kind
            or row.get("binding_digest") != binding_digest
            or row.get("ciphertext_digest")
                != framed_digest(
                    "serverware.policyAuthorityOpaqueCiphertext/v1",
                    algorithm.encode("utf-8"),
                    key_id.encode("utf-8"),
                    ciphertext_base64url.encode("ascii"),
                )
            or row.get("status") != "active"
            or not isinstance(created_at_epoch_ns, int)
            or isinstance(created_at_epoch_ns, bool)
            or not 0
                <= created_at_epoch_ns
                <= _epoch_nanoseconds(self.database_now)
            or row.get("consumed_at_epoch_ns") is not None
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
            or (
                expires_at_epoch_ns is not None
                and (
                    not isinstance(expires_at_epoch_ns, int)
                    or isinstance(expires_at_epoch_ns, bool)
                    or expires_at_epoch_ns
                    <= _epoch_nanoseconds(self.database_now)
                )
            )
        ):
            raise TransitionKernelError(
                "opaque value receipt is not currently authoritative"
            )
        producer = self.evidence(
            evidence_type="key-custody-seal/v1",
            evidence_digest=producer_evidence_digest,
            binding_digest=binding_digest,
        )
        return row

    def sealed_value(
        self,
        *,
        sealed_value_id: str,
        value_kind: str,
        target_table: str,
        target_column: str,
        target_row_key_digest: str,
        purpose: str,
        plaintext_digest: str,
        request_id: str,
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "sealed-value-receipt",
        )
        for value, label, maximum in (
            (sealed_value_id, "sealed value identity", 256),
            (value_kind, "sealed value kind", 128),
            (purpose, "sealed value purpose", 256),
            (request_id, "sealed value request identity", 256),
        ):
            require_text(value, label, maximum_bytes=maximum)
        if (
            not _IDENTIFIER.fullmatch(target_table)
            or not _IDENTIFIER.fullmatch(target_column)
        ):
            raise TransitionKernelError(
                "sealed value target is not a closed identifier"
            )
        require_digest(
            target_row_key_digest,
            "sealed value target row key",
        )
        require_digest(plaintext_digest, "sealed value plaintext digest")
        selected = self.exact(
            "policy_authority_sealed_values",
            {"sealed_value_id": sealed_value_id},
        )
        row = _selected_row(selected, "sealed value")
        key_generation = require_integer(
            row.get("key_generation"),
            "sealed value key generation",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        algorithm = require_text(
            row.get("algorithm"),
            "sealed value algorithm",
            maximum_bytes=128,
        )
        key_id = require_text(
            row.get("key_id"),
            "sealed value key identity",
            maximum_bytes=256,
        )
        nonce = _require_base64url(
            row.get("nonce_base64url"),
            "sealed value nonce",
            maximum_bytes=1024,
        )
        ciphertext = _require_base64url(
            row.get("ciphertext_base64url"),
            "sealed value ciphertext",
            maximum_bytes=4 * 1024 * 1024,
        )
        issued_at = require_integer(
            row.get("issued_at_epoch_ns"),
            "sealed value issuance",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        expires_at = require_integer(
            row.get("expires_at_epoch_ns"),
            "sealed value expiry",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        binding = {
            "schema": "serverware.policyAuthoritySealedValueBinding/v1",
            "algorithm": algorithm,
            "ciphertextDigest": row.get("ciphertext_digest"),
            "keyGeneration": key_generation,
            "keyId": key_id,
            "nonceBase64url": nonce,
            "plaintextDigest": plaintext_digest,
            "purpose": purpose,
            "requestId": request_id,
            "sealedValueId": sealed_value_id,
            "targetColumn": target_column,
            "targetRowKeyDigest": target_row_key_digest,
            "targetTable": target_table,
            "valueKind": value_kind,
        }
        binding_digest = framed_digest(
            "serverware.policyAuthoritySealedValueBinding/v1",
            canonical_bytes(binding),
        )
        if (
            row.get("value_kind") != value_kind
            or row.get("target_table") != target_table
            or row.get("target_column") != target_column
            or row.get("target_row_key_digest")
                != target_row_key_digest
            or row.get("purpose") != purpose
            or row.get("plaintext_digest") != plaintext_digest
            or row.get("request_id") != request_id
            or row.get("binding_digest") != binding_digest
            or row.get("ciphertext_digest")
                != framed_digest(
                    "serverware.policyAuthoritySealedCiphertext/v1",
                    algorithm.encode("utf-8"),
                    key_id.encode("utf-8"),
                    str(key_generation).encode("ascii"),
                    nonce.encode("ascii"),
                    ciphertext.encode("ascii"),
                )
            or row.get("status") != "active"
            or row.get("consumed_at_epoch_ns") is not None
            or not issued_at
                <= _epoch_nanoseconds(self.database_now)
                < expires_at
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
        ):
            raise TransitionKernelError(
                "sealed value is not currently authoritative"
            )
        self.evidence(
            evidence_type="encryption-authority-seal/v1",
            evidence_digest=require_digest(
                row.get("producer_evidence_digest"),
                "sealed value producer evidence",
            ),
            binding_digest=binding_digest,
        )
        return row

    def consume_sealed_value(
        self,
        *,
        row: Mapping[str, Any],
    ) -> dict[str, Any]:
        if row.get("status") != "active":
            raise TransitionKernelError(
                "sealed value cannot be consumed twice"
            )
        selected = self.exact(
            "policy_authority_sealed_values",
            {"sealed_value_id": row.get("sealed_value_id")},
        )
        return mutation(
            operation=self.operation,
            selected=selected,
            row={
                **dict(row),
                "status": "consumed",
                "consumed_at_epoch_ns":
                    _epoch_nanoseconds(self.database_now),
            },
        )

    def bounded_aggregate(
        self,
        *,
        aggregate_id: str,
        aggregate_kind: str,
        partition_digest: str,
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "aggregate-high-water",
        )
        require_text(
            aggregate_id,
            "bounded aggregate identity",
            maximum_bytes=256,
        )
        require_text(
            aggregate_kind,
            "bounded aggregate kind",
            maximum_bytes=128,
        )
        require_digest(
            partition_digest,
            "bounded aggregate partition digest",
        )
        selected = self.exact(
            "policy_authority_bounded_aggregate_states",
            {"aggregate_id": aggregate_id},
        )
        row = _selected_row(selected, "bounded aggregate")
        reserved_units = _canonical_json_text(
            row.get("reserved_units_json"),
            "bounded aggregate reserved units",
            require_mapping=True,
        )
        committed_units = _canonical_json_text(
            row.get("committed_units_json"),
            "bounded aggregate committed units",
            require_mapping=True,
        )
        state_value = _canonical_json_text(
            row.get("state_json"),
            "bounded aggregate state",
            require_mapping=True,
        )
        capacity_limit = row.get("capacity_limit")
        minimum_expiry_epoch_ns = row.get("minimum_expiry_epoch_ns")
        work_page_id = row.get("work_page_id")
        if (
            aggregate_id != f"{aggregate_kind}:{partition_digest}"
            or row.get("aggregate_kind") != aggregate_kind
            or row.get("partition_digest") != partition_digest
            or not isinstance(row.get("revision"), int)
            or isinstance(row.get("revision"), bool)
            or row.get("revision") < 1
            or not isinstance(row.get("live_count"), int)
            or isinstance(row.get("live_count"), bool)
            or row.get("live_count") < 0
            or not isinstance(row.get("active_count"), int)
            or isinstance(row.get("active_count"), bool)
            or row.get("active_count") < 0
            or not isinstance(capacity_limit, int)
            or isinstance(capacity_limit, bool)
            or capacity_limit < 0
            or not 0
                <= row["active_count"]
                <= row["live_count"]
                <= capacity_limit
            or not isinstance(row.get("next_sequence"), int)
            or isinstance(row.get("next_sequence"), bool)
            or not 0 <= row["next_sequence"] <= _SIGNED_BIGINT_MAX
            or (
                minimum_expiry_epoch_ns is not None
                and (
                    not isinstance(minimum_expiry_epoch_ns, int)
                    or isinstance(minimum_expiry_epoch_ns, bool)
                    or minimum_expiry_epoch_ns < 0
                )
            )
            or require_digest(
                row.get("expiry_index_root_digest"),
                "bounded aggregate expiry root",
            )
                != row.get("expiry_index_root_digest")
            or (
                work_page_id is not None
                and (
                    not isinstance(work_page_id, str)
                    or not work_page_id
                    or len(work_page_id.encode("utf-8")) > 256
                )
            )
            or state_value
                != _aggregate_state_material(
                    row,
                    reserved_units=reserved_units,
                    committed_units=committed_units,
                )
            or require_digest(
                row.get("state_digest"),
                "bounded aggregate state digest",
            )
                != framed_digest(
                    "serverware.policyAuthorityAggregateState/v1",
                    canonical_bytes(state_value),
                )
            or not isinstance(row.get("updated_at_epoch_ns"), int)
            or isinstance(row.get("updated_at_epoch_ns"), bool)
            or not 0
                <= row["updated_at_epoch_ns"]
                <= _epoch_nanoseconds(self.database_now)
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
        ):
            raise TransitionKernelError(
                "bounded aggregate state is not authoritative"
            )
        return row

    def update_bounded_aggregate(
        self,
        *,
        aggregate_id: str,
        aggregate_kind: str,
        partition_digest: str,
        live_delta: int,
        active_delta: int,
        reserved_units: Mapping[str, Any],
        committed_units: Mapping[str, Any],
        next_sequence_delta: int,
        minimum_expiry_epoch_ns: int | None,
        expiry_index_root_digest: str,
        work_page_id: str | None,
    ) -> dict[str, Any]:
        live_delta = require_integer(
            live_delta,
            "bounded aggregate live delta",
            minimum=-authority_contract.MAX_MUTATIONS,
            maximum=authority_contract.MAX_MUTATIONS,
        )
        active_delta = require_integer(
            active_delta,
            "bounded aggregate active delta",
            minimum=-authority_contract.MAX_MUTATIONS,
            maximum=authority_contract.MAX_MUTATIONS,
        )
        if (
            not isinstance(reserved_units, Mapping)
            or not isinstance(committed_units, Mapping)
        ):
            raise TransitionKernelError(
                "bounded aggregate units are not exact maps"
            )
        reserved_units_json = canonical_bytes(
            dict(reserved_units)
        ).decode("ascii")
        committed_units_json = canonical_bytes(
            dict(committed_units)
        ).decode("ascii")
        if (
            len(reserved_units_json) > 4 * 1024 * 1024
            or len(committed_units_json) > 4 * 1024 * 1024
        ):
            raise TransitionKernelError(
                "bounded aggregate units exceed their bound"
            )
        next_sequence_delta = require_integer(
            next_sequence_delta,
            "bounded aggregate sequence delta",
            minimum=0,
            maximum=authority_contract.MAX_MUTATIONS,
        )
        if minimum_expiry_epoch_ns is not None:
            minimum_expiry_epoch_ns = require_integer(
                minimum_expiry_epoch_ns,
                "bounded aggregate minimum expiry",
                minimum=0,
                maximum=_SIGNED_BIGINT_MAX,
            )
        require_digest(
            expiry_index_root_digest,
            "bounded aggregate expiry root",
        )
        if work_page_id is not None:
            require_text(
                work_page_id,
                "bounded aggregate work page",
                maximum_bytes=256,
            )
        row = self.bounded_aggregate(
            aggregate_id=aggregate_id,
            aggregate_kind=aggregate_kind,
            partition_digest=partition_digest,
        )
        live_count = row["live_count"] + live_delta
        active_count = row["active_count"] + active_delta
        capacity_limit = row.get("capacity_limit")
        revision = row["revision"]
        next_sequence = row["next_sequence"] + next_sequence_delta
        if (
            not isinstance(capacity_limit, int)
            or isinstance(capacity_limit, bool)
            or capacity_limit < 0
            or not 0 <= active_count <= live_count <= capacity_limit
            or revision >= _SIGNED_BIGINT_MAX
            or next_sequence > _SIGNED_BIGINT_MAX
        ):
            raise TransitionKernelError(
                "bounded aggregate capacity transition is invalid"
            )
        next_row = {
            **row,
            "revision": revision + 1,
            "live_count": live_count,
            "active_count": active_count,
            "reserved_units_json": reserved_units_json,
            "committed_units_json": committed_units_json,
            "next_sequence": next_sequence,
            "minimum_expiry_epoch_ns": minimum_expiry_epoch_ns,
            "expiry_index_root_digest": expiry_index_root_digest,
            "work_page_id": work_page_id,
            "updated_at_epoch_ns":
                _epoch_nanoseconds(self.database_now),
        }
        state_value = _aggregate_state_material(
            next_row,
            reserved_units=dict(reserved_units),
            committed_units=dict(committed_units),
        )
        state_json = canonical_bytes(state_value).decode("ascii")
        state_digest = framed_digest(
            "serverware.policyAuthorityAggregateState/v1",
            canonical_bytes(state_value),
        )
        selected = self.exact(
            "policy_authority_bounded_aggregate_states",
            {"aggregate_id": aggregate_id},
        )
        return mutation(
            operation=self.operation,
            selected=selected,
            row={
                **next_row,
                "state_json": state_json,
                "state_digest": state_digest,
            },
        )

    def work_page(
        self,
        *,
        page_id: str,
        aggregate_id: str,
        page_kind: str,
    ) -> tuple[dict[str, Any], tuple[Mapping[str, Any], ...]]:
        _require_manifest_primitive(
            self.operation,
            "logical-expiry-tombstone",
        )
        require_text(page_id, "work page identity", maximum_bytes=256)
        require_text(
            aggregate_id,
            "work page aggregate identity",
            maximum_bytes=256,
        )
        require_text(page_kind, "work page kind", maximum_bytes=128)
        selected = self.exact(
            "policy_authority_work_pages",
            {"page_id": page_id},
        )
        row = _selected_row(selected, "work page")
        try:
            items = json.loads(str(row.get("items_json")))
        except (TypeError, ValueError) as exc:
            raise TransitionKernelError(
                "work page items are not canonical JSON"
            ) from exc
        complete_through_epoch_ns = row.get(
            "complete_through_epoch_ns"
        )
        continuation_page_id = row.get("continuation_page_id")
        created_at_epoch_ns = row.get("created_at_epoch_ns")
        if (
            not isinstance(complete_through_epoch_ns, int)
            or isinstance(complete_through_epoch_ns, bool)
            or complete_through_epoch_ns < 0
        ):
            raise TransitionKernelError(
                "work page completion bound is invalid"
            )
        allowed_tables = (
            set(authority_contract.operation_spec(self.operation)[
                "businessReads"
            ])
            | set(authority_contract.operation_spec(self.operation)[
                "businessWrites"
            ])
        ) - {
            "policy_authority_bounded_aggregate_states",
            "policy_authority_exact_pages",
            "policy_authority_external_evidence_receipts",
            "policy_authority_opaque_values",
            "policy_authority_tombstones",
            "policy_authority_work_pages",
        }
        if (
            row.get("aggregate_id") != aggregate_id
            or row.get("page_kind") != page_kind
            or row.get("status") != "pending"
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
            or not isinstance(row.get("item_count"), int)
            or isinstance(row.get("item_count"), bool)
            or not 0 <= row["item_count"] <= 64
            or not isinstance(items, list)
            or len(items) != row["item_count"]
            or any(
                not isinstance(item, Mapping)
                or set(item)
                    != {
                        "mutationOrdinal",
                        "table",
                        "key",
                        "keyDigest",
                        "rowDigest",
                        "expiresAtEpochNs",
                    }
                or item.get("table") not in allowed_tables
                or not isinstance(item.get("key"), Mapping)
                or not item.get("key")
                or require_digest(
                    item.get("keyDigest"),
                    "work page key digest",
                )
                    != framed_digest(
                        "serverware.policyAuthorityBusinessKey/v1",
                        str(item.get("table")).encode("utf-8"),
                        canonical_bytes(dict(item.get("key", {}))),
                    )
                or require_digest(
                    item.get("rowDigest"),
                    "work page row digest",
                )
                    != item.get("rowDigest")
                or not isinstance(item.get("mutationOrdinal"), int)
                or isinstance(item.get("mutationOrdinal"), bool)
                or not 1
                    <= item.get("mutationOrdinal")
                    <= row["item_count"]
                or not isinstance(item.get("expiresAtEpochNs"), int)
                or isinstance(item.get("expiresAtEpochNs"), bool)
                or not 0
                    <= item.get("expiresAtEpochNs")
                    <= complete_through_epoch_ns
                for item in items
            )
            or [
                item["mutationOrdinal"] for item in items
            ] != list(range(1, len(items) + 1))
            or len(
                {
                    (item["table"], item["keyDigest"])
                    for item in items
                }
            ) != len(items)
            or canonical_bytes(items).decode("ascii")
                != row.get("items_json")
            or require_digest(
                row.get("items_digest"),
                "work page items digest",
            )
                != framed_digest(
                    "serverware.policyAuthorityWorkPageItems/v1",
                    canonical_bytes(items),
                )
            or not isinstance(row.get("page_sequence"), int)
            or isinstance(row.get("page_sequence"), bool)
            or row.get("page_sequence") < 1
            or (
                continuation_page_id is not None
                and (
                    not isinstance(continuation_page_id, str)
                    or not continuation_page_id
                    or len(continuation_page_id.encode("utf-8")) > 256
                    or continuation_page_id == page_id
                )
            )
            or not isinstance(created_at_epoch_ns, int)
            or isinstance(created_at_epoch_ns, bool)
            or not 0
                <= created_at_epoch_ns
                <= _epoch_nanoseconds(self.database_now)
        ):
            raise TransitionKernelError(
                "work page is not currently authoritative"
            )
        return row, tuple(dict(item) for item in items)

    def consume_work_page(
        self,
        *,
        page_id: str,
        aggregate_id: str,
        page_kind: str,
        require_terminal: bool,
    ) -> tuple[dict[str, Any], tuple[Mapping[str, Any], ...]]:
        if not isinstance(require_terminal, bool):
            raise TransitionKernelError(
                "work page terminal requirement is not closed"
            )
        row, items = self.work_page(
            page_id=page_id,
            aggregate_id=aggregate_id,
            page_kind=page_kind,
        )
        if require_terminal and row.get("continuation_page_id") is not None:
            raise TransitionKernelError(
                "work page has an unconsumed continuation"
            )
        for item in items:
            selected = self.exact(
                str(item["table"]),
                dict(item["key"]),
            )
            source_row = _selected_row(
                selected,
                "work page source",
            )
            if item["rowDigest"] != framed_digest(
                "serverware.policyAuthorityDeletedRow/v1",
                canonical_bytes(source_row),
            ):
                raise TransitionKernelError(
                    "work page source row changed"
                )
        selected_page = self.exact(
            "policy_authority_work_pages",
            {"page_id": page_id},
        )
        return (
            mutation(
                operation=self.operation,
                selected=selected_page,
                row={
                    **row,
                    "status": "consumed",
                    "consumed_at_epoch_ns":
                        _epoch_nanoseconds(self.database_now),
                },
            ),
            items,
        )

    def exact_page_receipt(
        self,
        *,
        page_digest: str,
        relation_name: str,
        predicate_digest: str,
        ordering_digest: str,
        relation_root_digest: str,
        relation_revision: int,
        rows_digest: str,
        terminal: bool,
    ) -> dict[str, Any]:
        _require_manifest_primitive(
            self.operation,
            "ordered-exact-page",
        )
        require_digest(page_digest, "exact page digest")
        require_text(
            relation_name,
            "exact page relation",
            maximum_bytes=128,
        )
        require_digest(predicate_digest, "exact page predicate digest")
        require_digest(ordering_digest, "exact page ordering digest")
        require_digest(relation_root_digest, "exact page relation root")
        relation_revision = require_integer(
            relation_revision,
            "exact page relation revision",
            minimum=1,
            maximum=2**63 - 1,
        )
        require_digest(rows_digest, "exact page rows digest")
        if not isinstance(terminal, bool):
            raise TransitionKernelError(
                "exact page terminal state is not closed"
            )
        selected = self.exact(
            "policy_authority_exact_pages",
            {"page_digest": page_digest},
        )
        row = _selected_row(selected, "exact page")
        proof = _canonical_json_text(
            row.get("proof_json"),
            "exact page proof",
            require_mapping=True,
        )
        expected_proof_fields = {
            "schema",
            "relationName",
            "predicateDigest",
            "orderingDigest",
            "relationRootDigest",
            "relationRevision",
            "pageSequence",
            "rows",
            "proofNodes",
            "continuationPageDigest",
            "terminal",
        }
        rows = proof.get("rows")
        proof_nodes = proof.get("proofNodes")
        if (
            set(proof) != expected_proof_fields
            or proof.get("schema")
                != "serverware.policyAuthorityExactPageProof/v1"
            or not isinstance(rows, list)
            or not isinstance(proof_nodes, list)
            or len(proof_nodes) > authority_contract.MAX_PROOF_NODES
            or any(
                not isinstance(node, str)
                or require_digest(node, "exact page proof node") != node
                for node in proof_nodes
            )
            or any(
                not isinstance(item, Mapping)
                or set(item) != {"key", "keyDigest", "rowDigest"}
                or not isinstance(item.get("key"), Mapping)
                or require_digest(
                    item.get("keyDigest"),
                    "exact page key digest",
                )
                    != framed_digest(
                        "serverware.policyAuthorityBusinessKey/v1",
                        relation_name.encode("utf-8"),
                        canonical_bytes(dict(item.get("key", {}))),
                    )
                or require_digest(
                    item.get("rowDigest"),
                    "exact page row digest",
                )
                    != item.get("rowDigest")
                for item in rows
            )
        ):
            raise TransitionKernelError(
                "exact page proof is not closed"
            )
        expected_rows_digest = framed_digest(
            "serverware.policyAuthorityExactPageRows/v1",
            canonical_bytes(rows),
        )
        first_key_json = (
            None
            if not rows
            else canonical_bytes(dict(rows[0]["key"])).decode("ascii")
        )
        last_key_json = (
            None
            if not rows
            else canonical_bytes(dict(rows[-1]["key"])).decode("ascii")
        )
        continuation_page_digest = row.get(
            "continuation_page_digest"
        )
        created_at_epoch_ns = row.get("created_at_epoch_ns")
        expires_at_epoch_ns = row.get("expires_at_epoch_ns")
        proof_digest = framed_digest(
            "serverware.policyAuthorityExactPageProof/v1",
            canonical_bytes(proof),
        )
        page_material = {
            "schema": "serverware.policyAuthorityExactPage/v1",
            "relationName": relation_name,
            "predicateDigest": predicate_digest,
            "orderingDigest": ordering_digest,
            "relationRootDigest": relation_root_digest,
            "relationRevision": relation_revision,
            "pageSequence": row.get("page_sequence"),
            "rowCount": len(rows),
            "firstKeyJson": first_key_json,
            "lastKeyJson": last_key_json,
            "rowsDigest": expected_rows_digest,
            "continuationPageDigest": continuation_page_digest,
            "terminal": terminal,
            "proofDigest": proof_digest,
            "createdAtEpochNs": created_at_epoch_ns,
            "expiresAtEpochNs": expires_at_epoch_ns,
            "sourceRevision": authority_contract.SOURCE_REVISION,
        }
        if (
            row.get("relation_name") != relation_name
            or row.get("predicate_digest") != predicate_digest
            or row.get("ordering_digest") != ordering_digest
            or row.get("relation_root_digest") != relation_root_digest
            or row.get("relation_revision") != relation_revision
            or rows_digest != expected_rows_digest
            or row.get("rows_digest") != expected_rows_digest
            or row.get("terminal") != int(terminal)
            or isinstance(row.get("terminal"), bool)
            or not isinstance(row.get("row_count"), int)
            or isinstance(row.get("row_count"), bool)
            or row.get("row_count") != len(rows)
            or not 0 <= len(rows) <= 64
            or row.get("terminal") not in (0, 1)
            or not isinstance(row.get("page_sequence"), int)
            or isinstance(row.get("page_sequence"), bool)
            or row.get("page_sequence") < 1
            or row.get("first_key_json") != first_key_json
            or row.get("last_key_json") != last_key_json
            or (
                terminal
                and continuation_page_digest is not None
            )
            or (
                not terminal
                and require_digest(
                    continuation_page_digest,
                    "exact page continuation",
                )
                    != continuation_page_digest
            )
            or not isinstance(created_at_epoch_ns, int)
            or isinstance(created_at_epoch_ns, bool)
            or created_at_epoch_ns < 0
            or not isinstance(expires_at_epoch_ns, int)
            or isinstance(expires_at_epoch_ns, bool)
            or not created_at_epoch_ns
                < expires_at_epoch_ns
            or expires_at_epoch_ns
                <= _epoch_nanoseconds(self.database_now)
            or proof.get("relationName") != relation_name
            or proof.get("predicateDigest") != predicate_digest
            or proof.get("orderingDigest") != ordering_digest
            or proof.get("relationRootDigest") != relation_root_digest
            or proof.get("relationRevision") != relation_revision
            or proof.get("pageSequence") != row.get("page_sequence")
            or proof.get("continuationPageDigest")
                != continuation_page_digest
            or proof.get("terminal") is not terminal
            or row.get("proof_digest") != proof_digest
            or page_digest
                != framed_digest(
                    "serverware.policyAuthorityExactPage/v1",
                    canonical_bytes(page_material),
                )
            or row.get("source_revision")
                != authority_contract.SOURCE_REVISION
        ):
            raise TransitionKernelError(
                "exact page receipt is not currently authoritative"
            )
        return row


class TransitionKernel(Protocol):
    operation: str
    handler: str
    program_id: str
    permits_empty_mutation: bool

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[Query, ...]:
        ...

    def transition(self, context: KernelContext) -> KernelTransition:
        ...


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise TransitionKernelError(
            "authority transition value is not canonical JSON"
        ) from exc


def _canonical_json_text(
    value: Any,
    label: str,
    *,
    require_mapping: bool = False,
) -> Any:
    if not isinstance(value, str):
        raise TransitionKernelError(f"{label} is not canonical JSON")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise TransitionKernelError(
            f"{label} is not canonical JSON"
        ) from exc
    if (
        require_mapping and not isinstance(parsed, Mapping)
        or canonical_bytes(parsed).decode("ascii") != value
    ):
        raise TransitionKernelError(f"{label} is not canonical JSON")
    return parsed


def _require_base64url(
    value: Any,
    label: str,
    *,
    maximum_bytes: int,
) -> str:
    if (
        not isinstance(value, str)
        or not _BASE64URL.fullmatch(value)
        or len(value.encode("ascii")) > maximum_bytes
    ):
        raise TransitionKernelError(f"{label} is not canonical base64url")
    return value


def _sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _validate_signed_envelope(
    value: Any,
    *,
    label: str,
    api_version: str,
    kind: str,
    signing_domain: str,
    payload_fields: frozenset[str],
) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _DECISION_GATE_PUBLICATION_ENVELOPE_FIELDS
        or value.get("apiVersion") != api_version
        or value.get("kind") != kind
        or value.get("canonicalProfile")
            != "serverware.canonicalJson/ascii-integer-v1"
        or value.get("signatureDomain") != signing_domain
        or value.get("signatureAlgorithm") != "Ed25519"
        or not isinstance(value.get("payload"), Mapping)
        or set(value["payload"]) != payload_fields
    ):
        raise TransitionKernelError(f"{label} is not an exact envelope")
    payload = dict(value["payload"])
    signing_key_id = require_digest(
        value.get("signingKeyId"),
        f"{label} signing key",
    )
    signing_key_spki = require_digest(
        value.get("signingKeySpkiSha256"),
        f"{label} signing SPKI",
    )
    signature = _require_base64url(
        value.get("signature"),
        f"{label} signature",
        maximum_bytes=4096,
    )
    if value.get("payloadSha256") != _sha256_digest(
        canonical_bytes(payload)
    ):
        raise TransitionKernelError(f"{label} payload digest changed")
    envelope = dict(value)
    envelope_digest = _sha256_digest(canonical_bytes(envelope))
    framed_digest(
        "serverware.policyAuthoritySignedEnvelopeSignature/v1",
        signing_domain.encode("ascii"),
        signing_key_id.encode("ascii"),
        signing_key_spki.encode("ascii"),
        signature.encode("ascii"),
    )
    return payload, envelope_digest


def _validate_generation_publication_payload(
    payload: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    if (
        set(payload) != _GENERATION_PUBLICATION_PAYLOAD_FIELDS
        or payload.get("schemaVersion")
            != "serverware.policyShadowGenerationPublication/v2"
        or payload.get("signatureDomain")
            != "serverware.policyShadowGenerationPublication/v2"
        or payload.get("signatureAlgorithm") != "Ed25519"
        or payload.get("canonicalizationProfile")
            != "serverware.canonicalJson/ascii-integer-v1"
        or payload.get("status") != "published"
    ):
        raise TransitionKernelError(
            "generation publication payload is not exact"
        )
    nested_specs = (
        ("request", _PUBLICATION_REQUEST_FIELDS),
        ("generation", _PUBLICATION_GENERATION_FIELDS),
        ("custody", _PUBLICATION_CUSTODY_FIELDS),
        ("runtime", _PUBLICATION_RUNTIME_FIELDS),
        ("trust", _PUBLICATION_TRUST_FIELDS),
        ("attestationChain", _PUBLICATION_ATTESTATION_CHAIN_FIELDS),
    )
    nested: dict[str, dict[str, Any]] = {}
    for name, fields in nested_specs:
        value = payload.get(name)
        if not isinstance(value, Mapping) or set(value) != fields:
            raise TransitionKernelError(
                f"generation publication {name} is not exact"
            )
        nested[name] = dict(value)
    for snapshot_name in ("active", "candidate"):
        snapshot = nested["generation"].get(snapshot_name)
        if (
            not isinstance(snapshot, Mapping)
            or set(snapshot) != _PUBLICATION_SNAPSHOT_FIELDS
        ):
            raise TransitionKernelError(
                "generation publication snapshot is not exact"
            )
        nested["generation"][snapshot_name] = dict(snapshot)
    startup_attestation = nested["attestationChain"].get(
        "startupAttestation"
    )
    evidence = (
        startup_attestation.get("evidence")
        if isinstance(startup_attestation, Mapping)
        else None
    )
    verifier = nested["attestationChain"].get(
        "runtimeAttestationVerification"
    )
    if (
        not isinstance(startup_attestation, Mapping)
        or set(startup_attestation)
            != _RUNTIME_ATTESTATION_HANDOFF_FIELDS
        or not isinstance(startup_attestation.get("receipt"), Mapping)
        or not isinstance(
            startup_attestation.get("roleAuthorization"), Mapping
        )
        or not isinstance(evidence, Mapping)
        or set(evidence) != _RUNTIME_ATTESTATION_EVIDENCE_FIELDS
        or not isinstance(verifier, Mapping)
        or nested["attestationChain"].get("hardwareAttested") is not True
    ):
        raise TransitionKernelError(
            "generation publication attestation chain is not exact"
        )
    require_text(
        nested["request"].get("requestId"),
        "generation publication request identity",
        maximum_bytes=128,
    )
    require_text(
        nested["request"].get("replayId"),
        "generation publication replay identity",
        maximum_bytes=128,
    )
    require_text(
        nested["runtime"].get("runtimeInstanceId"),
        "generation publication runtime instance",
        maximum_bytes=256,
    )
    for container in (
        nested["request"],
        nested["generation"],
        nested["generation"]["active"],
        nested["generation"]["candidate"],
        nested["custody"],
        nested["runtime"],
        nested["trust"],
        dict(evidence),
    ):
        for field, value in container.items():
            if (
                field.endswith("Sha256")
                or field.endswith("KeyId")
                or field == "generationId"
            ):
                require_digest(
                    value,
                    f"generation publication {field}",
                )
            elif field.endswith(
                (
                    "Revision",
                    "Sequence",
                    "Ordinal",
                    "Generation",
                    "Epoch",
                )
            ):
                require_integer(
                    value,
                    f"generation publication {field}",
                    minimum=0,
                    maximum=_SIGNED_BIGINT_MAX,
                )
    for field in (
        "preparationEnvelopeSha256",
        "externalRecordSha256",
        "durableCommitReceiptSha256",
    ):
        require_digest(payload.get(field), f"generation publication {field}")
    not_before = require_integer(
        payload.get("notBeforeUnixNanos"),
        "generation publication not-before",
        minimum=0,
        maximum=_SIGNED_BIGINT_MAX,
    )
    issued_at = require_integer(
        payload.get("issuedAtUnixNanos"),
        "generation publication issuance",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    expires_at = require_integer(
        payload.get("expiresAtUnixNanos"),
        "generation publication expiry",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    if (
        not not_before <= issued_at < expires_at
        or nested["custody"]["publicationRevision"]
            != nested["generation"]["signedPublicationRevision"]
        or nested["runtime"]["runtimeBootIdSha256"]
            != nested["generation"]["runtimeBootIdSha256"]
        or nested["runtime"]["requestFactsSchemaSha256"]
            != nested["generation"]["requestFactsSchemaSha256"]
    ):
        raise TransitionKernelError(
            "generation publication internal binding diverged"
        )
    return (
        nested["request"],
        nested["generation"],
        nested["custody"],
        nested["runtime"],
        nested["trust"],
        nested["attestationChain"],
    )


def _validate_runtime_attestation_payload(
    payload: Mapping[str, Any],
) -> None:
    if (
        set(payload) != _RUNTIME_ATTESTATION_PAYLOAD_FIELDS
        or payload.get("schemaVersion")
            != (
                "serverware."
                "policyShadowRuntimeAttestationVerification/v2"
            )
        or payload.get("status") != "verified"
        or payload.get("hardwareAttested") is not True
    ):
        raise TransitionKernelError(
            "runtime attestation verifier payload is not exact"
        )
    for field, value in payload.items():
        if field.endswith("Sha256"):
            require_digest(value, f"runtime attestation {field}")
        elif field == "revocationGeneration":
            require_integer(
                value,
                "runtime attestation revocation generation",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
    trusted_now = require_integer(
        payload.get("trustedNowUnixNanos"),
        "runtime attestation trusted time",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    issued_at = require_integer(
        payload.get("issuedAtUnixNanos"),
        "runtime attestation issuance",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    expires_at = require_integer(
        payload.get("expiresAtUnixNanos"),
        "runtime attestation expiry",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    maximum_age = require_integer(
        payload.get("maximumAgeNanos"),
        "runtime attestation maximum age",
        minimum=1,
        maximum=15 * 60 * 1_000_000_000,
    )
    if (
        not issued_at <= trusted_now < expires_at
        or trusted_now - issued_at > maximum_age
        or expires_at - issued_at
            > 15 * 60 * 1_000_000_000
    ):
        raise TransitionKernelError(
            "runtime attestation validity diverged"
        )


def _validate_activation_publication_receipt(
    value: Any,
) -> tuple[dict[str, Any], str]:
    fields = (
        "assignmentSha256",
        "assignmentPayloadSha256",
        "assignmentRevision",
        "readinessCoreSha256",
        "authorityKeyIndependenceSha256",
        "transactionSha256",
        "replacedPolicySha256",
        "replacedPolicySequence",
        "replacedRollbackEpoch",
        "publishedPolicySha256",
        "publishedPolicySequence",
        "publishedRollbackEpoch",
        "replacedPublicationRevision",
        "publishedPublicationRevision",
        "trustedObservedAtUnixNanos",
        "trustedTimeCheckpointSha256",
        "persistenceReceiptSha256",
        "retrievalIdSha256",
        "retrievalProofSha256",
        "signingKeyId",
        "signingKeySpkiSha256",
        "signature",
        "signedReceiptSha256",
    )
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise TransitionKernelError(
            "activation publication receipt is not exact"
        )
    wire = dict(value)
    for field in fields:
        if field.endswith("Sha256") or field == "signingKeyId":
            require_digest(wire[field], f"activation publication {field}")
        elif field.endswith(
            ("Revision", "Sequence", "Epoch", "UnixNanos")
        ):
            require_integer(
                wire[field],
                f"activation publication {field}",
                minimum=1,
                maximum=_SIGNED_BIGINT_MAX,
            )
    signature = _require_base64url(
        wire.get("signature"),
        "activation publication signature",
        maximum_bytes=4096,
    )
    canonical_payload = canonical_bytes(
        [
            *[wire[field] for field in fields[:19]],
            "activation-publication",
            wire["signingKeyId"],
            wire["signingKeySpkiSha256"],
        ]
    )
    if wire["signedReceiptSha256"] != framed_digest(
        "serverware.policyActivationPublicationReceipt/v1",
        canonical_payload,
        signature.encode("ascii"),
    ):
        raise TransitionKernelError(
            "activation publication signed receipt digest diverged"
        )
    normalized = {
        "assignmentEnvelopeDigest": wire["assignmentSha256"],
        "assignmentPayloadDigest": wire["assignmentPayloadSha256"],
        "assignmentRevision": wire["assignmentRevision"],
        "readinessCoreDigest": wire["readinessCoreSha256"],
        "authorityKeyIndependenceDigest":
            wire["authorityKeyIndependenceSha256"],
        "activationTransactionDigest": wire["transactionSha256"],
        "replacedPolicyDigest": wire["replacedPolicySha256"],
        "replacedPolicySequence": wire["replacedPolicySequence"],
        "replacedRollbackEpoch": wire["replacedRollbackEpoch"],
        "publishedPolicyDigest": wire["publishedPolicySha256"],
        "publishedPolicySequence": wire["publishedPolicySequence"],
        "publishedRollbackEpoch": wire["publishedRollbackEpoch"],
        "replacedPublicationRevision":
            wire["replacedPublicationRevision"],
        "publishedPublicationRevision":
            wire["publishedPublicationRevision"],
        "trustedObservedAtEpochNs": wire["trustedObservedAtUnixNanos"],
        "trustedTimeCheckpointDigest":
            wire["trustedTimeCheckpointSha256"],
        "persistenceReceiptDigest": wire["persistenceReceiptSha256"],
        "retrievalIdDigest": wire["retrievalIdSha256"],
        "retrievalProofDigest": wire["retrievalProofSha256"],
        "signingKeyId": wire["signingKeyId"],
        "signingKeySpkiSha256": wire["signingKeySpkiSha256"],
        "signature": signature,
        "signedReceiptDigest": wire["signedReceiptSha256"],
    }
    if set(normalized) != _ACTIVATION_PUBLICATION_PAYLOAD_FIELDS:
        raise TransitionKernelError(
            "activation publication normalization diverged"
        )
    return normalized, _sha256_digest(canonical_bytes(wire))


def framed_digest(domain: str, *frames: bytes) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(encoded_domain)
    digest.update(b"\x00")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def deterministic_uuid(
    *,
    operation: str,
    request_digest: str,
    purpose: str,
) -> str:
    return _deterministic_uuid(
        operation=operation, request_digest=request_digest, purpose=purpose,
        work=None,
    )


def _deterministic_uuid(
    *,
    operation: str,
    request_digest: str,
    purpose: str,
    work: _ValidationWork | None,
) -> str:
    """Build the one source identity document, optionally preparing its work."""
    require_digest(request_digest, "authority transition request digest")
    if work is not None:
        work.prepare_utf8(purpose)
    require_text(purpose, "authority transition identity purpose")
    document = {
        "schema": "serverware.policyAuthorityDeterministicIdentity/v1",
        "operation": operation,
        "requestDigest": request_digest,
        "purpose": purpose,
    }
    if work is not None:
        work.prepare_encoding(document)
        work.charge(hashes=1)
    material = hashlib.sha256(canonical_bytes(document)).hexdigest()
    value = list(material[:32])
    value[12] = "5"
    value[16] = format((int(value[16], 16) & 0x3) | 0x8, "x")
    compact = "".join(value)
    return (
        compact[:8]
        + "-"
        + compact[8:12]
        + "-"
        + compact[12:16]
        + "-"
        + compact[16:20]
        + "-"
        + compact[20:]
    )


def require_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise TransitionKernelError(f"{label} is not a canonical digest")
    return value


def require_text(
    value: Any,
    label: str,
    *,
    maximum_bytes: int = 512,
    allow_empty: bool = False,
) -> str:
    if (
        not isinstance(value, str)
        or not allow_empty and not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum_bytes
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TransitionKernelError(f"{label} is invalid")
    return value


def require_integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise TransitionKernelError(f"{label} is outside its bound")
    return value


def checked_u64(value: Any, label: str) -> int:
    return require_integer(
        value,
        label,
        minimum=0,
        maximum=2**64 - 1,
    )


def checked_i64(value: Any, label: str) -> int:
    return require_integer(
        value,
        label,
        minimum=-(2**63),
        maximum=2**63 - 1,
    )


def checked_u64_add(left: Any, right: Any, label: str) -> int:
    left_value = checked_u64(left, f"{label} left operand")
    right_value = checked_u64(right, f"{label} right operand")
    result = left_value + right_value
    if result > 2**64 - 1:
        raise TransitionKernelError(f"{label} overflowed u64")
    return result


def checked_u64_sub(left: Any, right: Any, label: str) -> int:
    left_value = checked_u64(left, f"{label} left operand")
    right_value = checked_u64(right, f"{label} right operand")
    if right_value > left_value:
        raise TransitionKernelError(f"{label} underflowed u64")
    return left_value - right_value


def checked_i64_add(left: Any, right: Any, label: str) -> int:
    left_value = checked_i64(left, f"{label} left operand")
    right_value = checked_i64(right, f"{label} right operand")
    result = left_value + right_value
    if not -(2**63) <= result <= 2**63 - 1:
        raise TransitionKernelError(f"{label} overflowed i64")
    return result


def _epoch_nanoseconds(value: datetime) -> int:
    if value.tzinfo is None:
        raise TransitionKernelError(
            "authority transition database clock is not timezone-aware"
        )
    return int(value.timestamp() * 1_000_000_000)


def _selected_row(
    selected: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    row = selected.get("row")
    if selected.get("present") is not True or not isinstance(row, Mapping):
        raise TransitionKernelError(f"{label} row is absent")
    return dict(row)


def _aggregate_state_material(
    row: Mapping[str, Any],
    *,
    reserved_units: Mapping[str, Any],
    committed_units: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "serverware.policyAuthorityAggregateState/v1",
        "aggregateId": row.get("aggregate_id"),
        "aggregateKind": row.get("aggregate_kind"),
        "partitionDigest": row.get("partition_digest"),
        "revision": row.get("revision"),
        "liveCount": row.get("live_count"),
        "activeCount": row.get("active_count"),
        "capacityLimit": row.get("capacity_limit"),
        "reservedUnits": dict(reserved_units),
        "committedUnits": dict(committed_units),
        "nextSequence": row.get("next_sequence"),
        "minimumExpiryEpochNs": row.get("minimum_expiry_epoch_ns"),
        "expiryIndexRootDigest": row.get("expiry_index_root_digest"),
        "workPageId": row.get("work_page_id"),
    }


def _require_manifest_primitive(operation: str, primitive: str) -> None:
    try:
        declared = authority_contract.operation_spec(operation)[
            "proofPrimitives"
        ]
    except ValueError as exc:
        raise TransitionKernelError(
            "authority operation is outside the manifest"
        ) from exc
    if primitive not in declared:
        raise TransitionKernelError(
            "authority proof primitive escaped the operation manifest"
        )


def require_exact_arguments(
    arguments: Mapping[str, Any],
    fields: frozenset[str],
) -> None:
    if (
        not isinstance(arguments, Mapping)
        or set(arguments) != set(fields) | {"businessIntent"}
    ):
        raise TransitionKernelError(
            "authority transition arguments are not exact"
        )


def argument_path(
    arguments: Mapping[str, Any],
    *path: str,
) -> Any:
    if not path or len(path) > MAX_ARGUMENT_DEPTH:
        raise TransitionKernelError("authority argument path is invalid")
    value: Any = arguments
    for component in path:
        if (
            not isinstance(value, Mapping)
            or component not in value
        ):
            raise TransitionKernelError(
                "authority argument path is absent"
            )
        value = value[component]
    return value


def transition_program_id(operation: str, handler: str) -> str:
    spec = authority_contract.operation_spec(operation)
    if spec["handler"] != handler:
        raise TransitionKernelError(
            "authority transition handler identity changed"
        )
    return authority_contract.transition_program_id(operation)


def query_program_id(
    operation: str,
    name: str,
    table: str,
) -> str:
    if (
        not _IDENTIFIER.fullmatch(name)
        or not _IDENTIFIER.fullmatch(table)
    ):
        raise TransitionKernelError(
            "authority query program identity is invalid"
        )
    return (
        "serverware.policyAuthorityQuery/"
        f"{operation}/{name}/{table}/v1"
    )


def mutation(
    *,
    operation: str,
    selected: Mapping[str, Any],
    row: Mapping[str, Any],
) -> dict[str, Any]:
    mutation_kind = "UPDATE" if selected.get("present") is True else "INSERT"
    templates = tuple(
        template
        for template in authority_contract.operation_spec(operation)[
            "mutationTemplates"
        ]
        if (
            template["table"] == selected.get("table")
            and template["mutation"] == mutation_kind
        )
    )
    if (
        len(templates) != 1
        or not isinstance(selected.get("key"), Mapping)
        or not isinstance(selected.get("keyDigest"), str)
        or not isinstance(row, Mapping)
    ):
        raise TransitionKernelError(
            "authority transition mutation is outside its template"
        )
    return {
        "templateId": templates[0]["templateId"],
        "operation": mutation_kind,
        "table": selected["table"],
        "key": dict(selected["key"]),
        "keyDigest": selected["keyDigest"],
        "expectedRow": (
            dict(selected["row"]) if selected.get("present") is True else None
        ),
        "row": dict(row),
    }


def delete_mutation(
    *,
    operation: str,
    selected: Mapping[str, Any],
) -> dict[str, Any]:
    templates = tuple(
        template
        for template in authority_contract.operation_spec(operation)[
            "mutationTemplates"
        ]
        if (
            template["table"] == selected.get("table")
            and template["mutation"] == "DELETE"
        )
    )
    if (
        len(templates) != 1
        or selected.get("present") is not True
        or not isinstance(selected.get("key"), Mapping)
        or not isinstance(selected.get("keyDigest"), str)
        or not isinstance(selected.get("row"), Mapping)
    ):
        raise TransitionKernelError(
            "authority transition delete is outside its template"
        )
    return {
        "templateId": templates[0]["templateId"],
        "operation": "DELETE",
        "table": selected["table"],
        "key": dict(selected["key"]),
        "keyDigest": selected["keyDigest"],
        "expectedRow": dict(selected["row"]),
        "row": None,
    }


def delete_with_tombstone(
    *,
    operation: str,
    selected: Mapping[str, Any],
    tombstone_selected: Mapping[str, Any],
    tombstone_row: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _require_manifest_primitive(operation, "tombstone-row")
    if (
        selected.get("present") is not True
        or not isinstance(selected.get("row"), Mapping)
        or not isinstance(selected.get("key"), Mapping)
        or not isinstance(tombstone_row, Mapping)
        or tombstone_selected.get("table")
            != "policy_authority_tombstones"
        or tombstone_selected.get("present") is not False
        or tombstone_row.get("source_table") != selected.get("table")
        or tombstone_row.get("source_key_digest")
            != selected.get("keyDigest")
        or tombstone_row.get("source_key_json")
            != canonical_bytes(dict(selected.get("key", {}))).decode("ascii")
        or tombstone_row.get("source_row_digest")
            != framed_digest(
                "serverware.policyAuthorityDeletedRow/v1",
                canonical_bytes(dict(selected.get("row", {}))),
            )
        or tombstone_row.get("operation") != operation
        or require_digest(
            tombstone_row.get("request_digest"),
            "authority tombstone request digest",
        )
            != tombstone_row.get("request_digest")
        or tombstone_row.get("source_revision")
            != authority_contract.SOURCE_REVISION
    ):
        raise TransitionKernelError(
            "authority tombstone does not bind the deleted row"
        )
    return (
        mutation(
            operation=operation,
            selected=tombstone_selected,
            row=tombstone_row,
        ),
        delete_mutation(operation=operation, selected=selected),
    )


def close_queries(
    operation: str,
    queries: tuple[Query, ...],
) -> tuple[Query, ...]:
    spec = authority_contract.operation_spec(operation)
    if (type(queries) is not tuple
            or len(queries) > spec["maximumQueryRows"]
            or any(type(query) not in (BoundedQuery, authority_complete_query.CompleteIndexQuery)
                   for query in queries)):
        raise TransitionKernelError("authority query program has an unknown declaration kind")
    try:
        queries = tuple(
            authority_complete_query.snapshot_query(query)
            if type(query) is authority_complete_query.CompleteIndexQuery else query
            for query in queries
        )
    except authority_complete_query.CompleteQueryError as exc:
        raise TransitionKernelError("authority complete query declaration is invalid") from exc
    allowed = (
        set(spec["businessReads"])
        | set(spec["businessWrites"])
        | set(spec["authorizationReads"])
    )
    if (
        not isinstance(queries, tuple)
        or any(
            query.table not in allowed
            or (type(query) is BoundedQuery
                and query.proof_primitive == authority_complete_query.PROOF_PRIMITIVE)
            for query in queries
        )
        or any(
            not query.query_id.startswith(
                f"serverware.policyAuthorityQuery/{operation}/"
            )
            for query in queries
        )
        or len({query.query_id for query in queries}) != len(queries)
        or sum(query.maximum_rows for query in queries)
            > int(spec["maximumQueryRows"])
        or sum(query.work_units for query in queries)
            > int(spec["maximumWorkUnits"])
        or any(
            query.proof_primitive not in spec["proofPrimitives"]
            for query in queries
        )
    ):
        raise TransitionKernelError(
            "authority query program escaped its operation manifest"
        )
    return queries


EMPTY_KERNEL_REGISTRY: Mapping[str, TransitionKernel] = MappingProxyType({})
