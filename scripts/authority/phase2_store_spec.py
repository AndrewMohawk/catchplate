from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping

from serverware import authority_contract
from serverware import authority_audit_capacity as audit_capacity


PHASE2_STORE_SPEC_SCHEMA: Final[str] = (
    "serverware.policyAuthorityPhase2StoreSpec/v1"
)
PHASE2_BACKFILL_RECEIPT_SCHEMA: Final[str] = (
    "serverware.policyAuthorityPhase2BackfillReceipt/v1"
)
PHASE2_BACKFILL_MODE: Final[str] = (
    "offline-serializable-signed-exact"
)


PHASE2_TABLES: Final[tuple[str, ...]] = (
    "policy_authority_activation_evidence_bindings",
    "policy_authority_bounded_aggregate_states",
    "policy_authority_continuations",
    "policy_authority_exact_pages",
    "policy_authority_external_evidence_receipts",
    "policy_authority_opaque_values",
    "policy_authority_sealed_values",
    "policy_authority_secondary_index_heads",
    "policy_authority_tombstones",
    "policy_authority_work_pages",
)


AGGREGATE_BACKFILLS: Final[
    Mapping[str, Mapping[str, object]]
] = MappingProxyType(
    {
        "approval-request-capacity": MappingProxyType(
            {
                "sourceTables": ("approval_requests",),
                "liveStates": ("pending",),
                "groupKey": (),
                "expiryColumn": "expires_at",
                "capacitySource": "configuration",
            }
        ),
        "approval-review-receipt-capacity": MappingProxyType(
            {
                "sourceTables": ("approval_review_receipts",),
                "liveStates": ("unused-unexpired",),
                "groupKey": (),
                "expiryColumn": "expires_at",
                "capacitySource": "configuration",
            }
        ),
        "control-approval-head": MappingProxyType(
            {
                "sourceTables": ("control_plane_approvals",),
                "liveStates": ("pending", "approved"),
                "groupKey": (
                    "action",
                    "resource_id",
                    "payload_digest",
                ),
                "expiryColumn": "expires_at",
                "capacitySource": "configuration",
            }
        ),
        "credential-nonce-capacity": MappingProxyType(
            {
                "sourceTables": (
                    "credential_lease_nonces",
                    "credential_lease_replay_state",
                ),
                "liveStates": ("unexpired",),
                "groupKey": ("scope",),
                "expiryColumn": "expires_at_epoch_ms",
                "capacitySource": "configuration",
            }
        ),
        "durable-budget-high-water": MappingProxyType(
            {
                "sourceTables": (
                    "durable_budget_definitions",
                    "durable_budget_events",
                ),
                "liveStates": (
                    "reserved",
                    "dispatched",
                    "committed",
                ),
                "groupKey": ("budget_key",),
                "expiryColumn": "expires_at_epoch_ms",
                "capacitySource": "durable_budget_definitions.max_units",
            }
        ),
        # Declaration only: the integrated transition checker cannot establish
        # a populated baseline. No initializer or installation receipt is
        # implemented here, and neither legacy counter supplies this identity.
        audit_capacity.AGGREGATE_KIND: MappingProxyType(
            {
                "sourceTables": (audit_capacity.OUTBOX_TABLE,),
                "liveStates": ("pending", "claimed"),
                "groupKey": (),
                "expiryColumn": None,
                "capacitySource": "serverware.audit_outbox_contract.MAX_PENDING",
                "capacityLimit": audit_capacity.MAX_PENDING,
                "aggregateId": audit_capacity.AGGREGATE_ID,
                "partitionDigest": audit_capacity.PARTITION_DIGEST,
                "stateSchema": audit_capacity.STATE_SCHEMA,
                "activeCountRule": "equal-live-count",
                "reservedUnits": MappingProxyType({}),
                "committedUnits": MappingProxyType({}),
                "minimumExpiryEpochNs": None,
                "expiryIndexRootDigest": audit_capacity.EMPTY_EXPIRY_DIGEST,
                "workPageId": None,
                "maximumRowBytes": audit_capacity.MAX_COUNTER_BYTES,
                "initializerImplemented": False,
                "onlineActivationPermitted": False,
            }
        ),
        "traversal-chain-high-water": MappingProxyType(
            {
                "sourceTables": (
                    "traversal_budget_chains",
                    "traversal_budget_cursors",
                    "traversal_budget_page_reservations",
                ),
                "liveStates": (
                    "available",
                    "reserved",
                    "dispatched",
                ),
                "groupKey": ("chain_key",),
                "expiryColumn": "reservation_expires_at_epoch_ms",
                "capacitySource": "traversal_budget_chains",
            }
        ),
    }
)


EXTERNAL_EVIDENCE_TYPES: Final[tuple[str, ...]] = (
    "audit-inclusion/v1",
    "audit-ledger-append/v1",
    "credential-issuer/v1",
    "decision-gate-publication-chain/v1",
    "dispatcher-forwarding/v1",
    "encryption-authority-seal/v1",
    "key-custody-seal/v1",
    "policy-signature-verification/v1",
    "release-cancellation-authority/v1",
    "release-dispatch-authority/v1",
    "release-reconciliation-authority/v1",
    "release-reservation-authority/v1",
    "response-validation/v2",
    "webauthn-hardware-authorization/v1",
)


DECISION_GATE_PUBLICATION_BINDING_FIELDS: Final[tuple[str, ...]] = (
    "activationMode",
    "activationPublicationReceiptDigest",
    "activationTransactionDigest",
    "activeCompiledSnapshotDigest",
    "activePolicyDigest",
    "activePolicySequence",
    "activeRollbackEpoch",
    "assignmentEnvelopeDigest",
    "assignmentPayloadDigest",
    "assignmentRevision",
    "authoritativeLedgerEventOrdinal",
    "authoritativeLedgerHeadDigest",
    "authoritativeSpoolRootDigest",
    "authorityKeyIndependenceDigest",
    "bootIdDigest",
    "candidateCompiledSnapshotDigest",
    "candidatePolicyDigest",
    "candidatePolicySequence",
    "candidateRollbackEpoch",
    "custodyPreparationReceiptDigest",
    "custodyPublicationReceiptDigest",
    "generationEpoch",
    "generationId",
    "generationTombstoneEpoch",
    "ingressEvidenceChainDigest",
    "ingressHighWaterDigest",
    "ingressRangeEndSequence",
    "ingressRangePredecessorHeadDigest",
    "ingressRangeStartSequence",
    "instanceId",
    "loadReceiptEnvelopeDigest",
    "loadReceiptPayloadDigest",
    "persistenceReceiptDigest",
    "policyHighWaterAfterDigest",
    "policyHighWaterBeforeDigest",
    "predecessorGenerationDigest",
    "publicationRequestId",
    "publicationRevision",
    "readinessCoreDigest",
    "replayId",
    "retrievalIdDigest",
    "retrievalProofDigest",
    "runtimeAttestationReceiptDigest",
    "runtimeConfigAttestationDigest",
    "runtimeEvidenceChainDigest",
    "runtimeExecutableDigest",
    "runtimePolicyAttestationDigest",
    "runtimeReleaseAttestationDigest",
    "runtimeTeeEvidenceDigest",
    "runtimeTeeMeasurementDigest",
    "trustCheckpointDigest",
    "trustRevocationGeneration",
    "trustRevocationRootDigest",
)
DECISION_GATE_PUBLICATION_STATEMENT_FIELDS: Final[tuple[str, ...]] = (
    *DECISION_GATE_PUBLICATION_BINDING_FIELDS,
    "activationPublicationEnvelope",
    "activationPublicationEnvelopeDigest",
    "evidenceChainDigest",
    "expiresAtEpochNs",
    "generationPublicationEnvelope",
    "generationPublicationEnvelopeDigest",
    "issuedAtEpochNs",
    "runtimeAttestationVerifierEnvelope",
    "runtimeAttestationVerifierEnvelopeDigest",
    "schema",
)
EXTERNAL_EVIDENCE_STATEMENT_SCHEMAS: Final[
    Mapping[str, Mapping[str, object]]
] = MappingProxyType(
    {
        "decision-gate-publication-chain/v1": MappingProxyType(
            {
                "schema": (
                    "serverware."
                    "policyAuthorityDecisionGatePublicationChain/v1"
                ),
                "requiredFields":
                    DECISION_GATE_PUBLICATION_STATEMENT_FIELDS,
                "bindingFields":
                    DECISION_GATE_PUBLICATION_BINDING_FIELDS,
                "bindingDigestDomain": (
                    "serverware."
                    "policyAuthorityDecisionGatePublicationBinding/v1"
                ),
                "rustEnvelopeDomains": (
                    (
                        "serverware."
                        "policyShadowGenerationPublication/v2"
                    ),
                    (
                        "serverware."
                        "policyActivationPublicationReceipt/v1"
                    ),
                    (
                        "serverware."
                        "policyShadowRuntimeAttestationVerification/v2"
                    ),
                ),
                "canonicalEnvelopeRule": (
                    "the exact canonical Rust generation-publication v2 "
                    "envelope embeds the exact runtime-verifier v2 envelope; "
                    "the activation-publication custody wire carries its "
                    "Ed25519 key, SPKI, signature, and signed-receipt digest; "
                    "all canonical digests plus outer issuance and expiry "
                    "produce one evidence-chain digest"
                ),
                "lifecycleRule": (
                    "prepare consumes the verified evidence once; every later "
                    "activation stage must prove that same consumed digest and "
                    "operation identity from its preparation row"
                ),
                "callerAuthorityRule": (
                    "publicationReceiptSha256, runtimeAttestation, and all "
                    "caller-supplied publication or runtime-attestation "
                    "digests are non-authoritative and rejected"
                ),
            }
        ),
        "webauthn-hardware-authorization/v1": MappingProxyType(
            {
                "schema":
                    "serverware.policyAuthorityPhysicalWebAuthn/v1",
                "bindingFields": (
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
                ),
                "authorityRule": (
                    "one pinned measured verifier admits an Ed25519 receipt "
                    "only after user-presence, user-verification, hardware "
                    "backing, counter monotonicity, and current trust-root "
                    "verification; the business transaction consumes it once"
                ),
            }
        ),
    }
)


OPAQUE_VALUE_KINDS: Final[tuple[str, ...]] = (
    "approval-review-json/v1",
    "approval-secret-json/v1",
    "quota-operation-recovery/v1",
    "release-operation-context/v1",
)


PRIMITIVE_CONTRACTS: Final[
    Mapping[str, Mapping[str, object]]
] = MappingProxyType(
    {
        "aggregate-high-water": MappingProxyType(
            {
                "table": "policy_authority_bounded_aggregate_states",
                "identity": (
                    "aggregate_id is aggregate_kind, a colon, and the "
                    "canonical partition digest"
                ),
                "stateDigestDomain":
                    "serverware.policyAuthorityAggregateState/v1",
                "stateMaterialFields": (
                    "schema",
                    "aggregateId",
                    "aggregateKind",
                    "partitionDigest",
                    "revision",
                    "liveCount",
                    "activeCount",
                    "capacityLimit",
                    "reservedUnits",
                    "committedUnits",
                    "nextSequence",
                    "minimumExpiryEpochNs",
                    "expiryIndexRootDigest",
                    "workPageId",
                ),
                "updateRule": (
                    "one full-row CAS increments revision exactly once and "
                    "applies manifest-bounded count, unit, and sequence deltas; "
                    "aggregate_id must equal aggregate_kind plus a colon plus "
                    "the partition digest"
                ),
            }
        ),
        "bounded-limit-plus-one": MappingProxyType(
            {
                "table": "policy_authority_continuations",
                "selectionRule": (
                    "select at most the manifest page size plus one row in "
                    "one source-defined total order; the extra row commits a "
                    "request-bound continuation digest and is never mutated "
                    "by the current page"
                ),
                "completionRule": (
                    "the protected resource remains disabled until a terminal "
                    "page atomically marks the continuation completed"
                ),
            }
        ),
        "authenticated-secondary-index": MappingProxyType(
            {
                "table": "policy_authority_secondary_index_heads",
                "proofRule": (
                    "the index head binds the relation, fixed index name, key "
                    "columns, root, revision, row count, and high-water key; "
                    "absence and uniqueness are proved against that root"
                ),
            }
        ),
        "checked-arithmetic": MappingProxyType(
            {
                "rule": (
                    "every u64 or i64 add and subtract rejects overflow or "
                    "underflow before a mutation or result is constructed"
                ),
            }
        ),
        "ordered-exact-page": MappingProxyType(
            {
                "table": "policy_authority_exact_pages",
                "pageDigestDomain":
                    "serverware.policyAuthorityExactPage/v1",
                "rowsDigestDomain":
                    "serverware.policyAuthorityExactPageRows/v1",
                "proofDigestDomain":
                    "serverware.policyAuthorityExactPageProof/v1",
                "rowFields": ("key", "keyDigest", "rowDigest"),
                "proofRule": (
                    "the signed receipt binds relation root and revision, "
                    "predicate, ordering, every exact primary key and row "
                    "digest, continuation, and terminal completeness"
                ),
            }
        ),
        "logical-expiry-tombstone": MappingProxyType(
            {
                "table": "policy_authority_work_pages",
                "itemsDigestDomain":
                    "serverware.policyAuthorityWorkPageItems/v1",
                "itemFields": (
                    "mutationOrdinal",
                    "table",
                    "key",
                    "keyDigest",
                    "rowDigest",
                    "expiresAtEpochNs",
                ),
                "itemRule": (
                    "each item binds one source primary key, expected full-row "
                    "digest, expiry, and contiguous deterministic mutation "
                    "ordinal; consumption rechecks every selected source row"
                ),
                "completionRule": (
                    "a business result is forbidden while a consumed page "
                    "declares a continuation or omits any item at or before "
                    "complete_through_epoch_ns"
                ),
            }
        ),
        "tombstone-row": MappingProxyType(
            {
                "table": "policy_authority_tombstones",
                "sourceRowDigestDomain":
                    "serverware.policyAuthorityDeletedRow/v1",
                "mutationRule": (
                    "the tombstone INSERT and exact full-row CAS DELETE are "
                    "one SERIALIZABLE mutation plan"
                ),
            }
        ),
        "opaque-value-receipt": MappingProxyType(
            {
                "table": "policy_authority_opaque_values",
                "requiredProducerEvidenceType": "key-custody-seal/v1",
                "bindingRule": (
                    "the opaque row and verified producer receipt carry the "
                    "same operation-specific binding digest; algorithm, key "
                    "identity, canonical ciphertext, and ciphertext digest are "
                    "cross-checked before use"
                ),
            }
        ),
        "sealed-value-receipt": MappingProxyType(
            {
                "table": "policy_authority_sealed_values",
                "requiredProducerEvidenceType":
                    "encryption-authority-seal/v1",
                "bindingFields": (
                    "plaintextDigest",
                    "ciphertextDigest",
                    "targetTable",
                    "targetColumn",
                    "targetRowKeyDigest",
                    "purpose",
                    "keyGeneration",
                    "nonceBase64url",
                    "requestId",
                    "issuedAtEpochNs",
                    "expiresAtEpochNs",
                ),
                "keyRule": (
                    "kernels receive ciphertext and a pinned encryption "
                    "authority receipt, never a plaintext encryption key"
                ),
            }
        ),
        "external-evidence-receipt": MappingProxyType(
            {
                "table":
                    "policy_authority_external_evidence_receipts",
                "admissionRule": (
                    "only an attested measured verifier identity pinned by "
                    "the stage-zero contract may install a verified receipt; "
                    "statement, signature, verifier identity, binding, and "
                    "receipt digests are recomputed before use"
                ),
                "consumptionRule": (
                    "single-use evidence changes from verified to consumed "
                    "by exact full-row CAS in the business transaction; later "
                    "stages may only prove the same consumed identity"
                ),
            }
        ),
    }
)


REQUIRED_EXISTING_V9_SCHEMA_CHANGES: Final[
    tuple[Mapping[str, object], ...]
] = (
    MappingProxyType(
        {
            "object": "policy_authority_operation_mutation_templates",
            "change": (
                "replace the mutation CHECK with the exact INSERT, UPDATE, "
                "DELETE before/after matrix from authority_v9_schema_source"
            ),
            "onlineActivationPermitted": False,
        }
    ),
    MappingProxyType(
        {
            "object": "policy_authority_source_revision_constraints",
            "change": (
                "replace every prior source-revision constraint with the "
                "exact Phase 2 source revision"
            ),
            "onlineActivationPermitted": False,
        }
    ),
    MappingProxyType(
        {
            "object": "phase2_authenticated_relations",
            "change": (
                "install all Phase 2 tables, register their exact primary "
                "keys, and initialize authenticated roots from signed rows"
            ),
            "onlineActivationPermitted": False,
        }
    ),
    MappingProxyType(
        {
            "object": "policy_authority_planner_transactions.work_units",
            "change": (
                "add the non-null signed work-unit count and enforce the "
                "operation-specific maximum in reservation and execution"
            ),
            "onlineActivationPermitted": False,
        }
    ),
    MappingProxyType(
        {
            "object": "policy_shadow_generation_publications",
            "change": (
                "register the exact primary key and signed-row schema in the "
                "authenticated relation-root set; activation must prove its "
                "generation, publication revision, request and replay "
                "identities, assignment/load/custody/ingress bindings, runtime "
                "attestation chain, signing identity, and validity interval"
            ),
            "onlineActivationPermitted": False,
        }
    ),
    MappingProxyType(
        {
            "object": (
                "policy_authority_activation_evidence_bindings"
            ),
            "change": (
                "install the authenticated sidecar relation keyed by "
                "preparation_digest with non-null evidence, binding, "
                "generation-publication, activation-publication, runtime-"
                "verifier, chain, request, replay, revision, and consumed-"
                "operation identities; every identity is immutable and "
                "one-shot"
            ),
            "onlineActivationPermitted": False,
        }
    ),
    MappingProxyType(
        {
            "object": (
                "policy_activation_finalizations,"
                "policy_activation_aborts"
            ),
            "change": (
                "carry the preparation decision-gate evidence-chain digest "
                "and consumed operation identity through exact foreign keys; "
                "reject any finalization or abort whose evidence identity, "
                "generation, publication revision, or replay identity "
                "diverges from preparation"
            ),
            "onlineActivationPermitted": False,
        }
    ),
)


PHASE2_STORE_SPEC: Final[Mapping[str, object]] = MappingProxyType(
    {
        "schema": PHASE2_STORE_SPEC_SCHEMA,
        "sourceRevision": authority_contract.SOURCE_REVISION,
        "backfillMode": PHASE2_BACKFILL_MODE,
        "runtimeFullTableScansPermitted": False,
        "tables": PHASE2_TABLES,
        "requiredExistingV9SchemaChanges":
            REQUIRED_EXISTING_V9_SCHEMA_CHANGES,
        "aggregateBackfills": AGGREGATE_BACKFILLS,
        "primitiveContracts": PRIMITIVE_CONTRACTS,
        "externalEvidenceTypes": EXTERNAL_EVIDENCE_TYPES,
        "externalEvidenceStatementSchemas":
            EXTERNAL_EVIDENCE_STATEMENT_SCHEMAS,
        "opaqueValueKinds": OPAQUE_VALUE_KINDS,
        "receiptSchema": PHASE2_BACKFILL_RECEIPT_SCHEMA,
        "requiredReceiptBindings": (
            "sourceSchemaDigest",
            "sourceRootSetDigest",
            "sourceRowCountsDigest",
            "aggregateRowsDigest",
            "exactPageRowsDigest",
            "operationManifestDigest",
            "migrationMeasurementDigest",
            "migrationAttestationReceiptDigest",
            "completedAtEpochNs",
        ),
        "activationRule": (
            "no operation that declares an aggregate, exact-page, opaque, "
            "or external-evidence primitive may be enabled before the exact "
            "signed backfill receipt is installed and authenticated roots "
            "for every Phase 2 table are current"
        ),
        "policyActivationEvidenceRule": (
            "policy activation prepare, inclusion, finalize, and abort remain "
            "disabled until Rust emits the three canonically signed envelopes, "
            "an attested verifier admits the exact combined chain, and the "
            "durable preparation/finalization/abort schema persists one "
            "consumed evidence identity; plaintext publicationReceiptSha256 "
            "or caller runtimeAttestation material is never authoritative"
        ),
        "existingV9UpgradeRule": (
            "CREATE TABLE IF NOT EXISTS is not an in-place upgrade; an "
            "existing v9 installation must apply every required schema "
            "change and signed backfill while admission remains disabled"
        ),
    }
)
